// Olympus.exe: the one tray icon for the whole suite. It reads every guardian's status and
// alerts, shows pop-ups (held while you're gaming), keeps Janus and Ares running, owns the
// "check this link" hotkey, re-runs Athena's report card daily, and opens the dashboard.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Olympus.Hub
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "status" || first == "alerts" || first == "help" || first == "--help" || first == "/?";
            AppStart.Init(AppId.Olympus, !cli);
            if (cli)
            {
                Cli.Attach();
                return HubCli.Run(a);
            }
            if (a.Has("--snapshot")) return AppWindow.Run(args, null, () => new Dashboard(null));
            // The hub lives in your session, never elevated: an elevated start (say, from an installer)
            // only signals the running hub (its lock and signals are session-wide, an admin's aren't).
            if (a.Has("--exit") || Elevation.IsElevated)
            {
                Sync.Poke(a.Has("--exit") ? "hub.exit" : "hub.show");
                return 0;
            }
            Mutex m;
            if (!Sync.Claim("hub", out m))
            {
                if (a.Has("--exit")) Sync.Poke("hub.exit");
                else if (!a.Has("--tray")) Sync.Poke("hub.show");
                return 0;
            }
            using (m)
            {
                if (a.Has("--exit")) return 0;
                Application.Run(new HubApp(!a.Has("--tray")));
            }
            return 0;
        }
    }

    static class HubCli
    {
        const string Help =
            "Olympus security hub - commands:\n" +
            "  Olympus.exe              open the dashboard (starts the tray icon if needed)\n" +
            "  Olympus.exe --tray       start just the tray icon (used at sign-in)\n" +
            "  Olympus.exe --exit       close the tray icon\n" +
            "  Olympus.exe status       how every guardian is doing\n" +
            "  Olympus.exe alerts [N]   the newest N alerts you haven't dismissed (default 20)\n" +
            "From PowerShell, add | Out-String so the output waits for the command.";

        static string Word(string sev)
        {
            switch (sev) { case Sev.Critical: return "CRITICAL"; case Sev.Warning: return "warning"; case Sev.Notice: return "notice"; default: return "info"; }
        }

        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "status":
                {
                    var states = Overview.Collect();
                    var rows = new List<string[]> { new[] { "APP", "STATE", "SUMMARY", "REPORTED" } };
                    foreach (var s in states)
                        rows.Add(new[] { s.App.Name, s.State, s.Summary, s.App.Id == AppId.Aegis || s.Updated == DateTime.MinValue ? "-" : Fmt.Ago(s.Updated) });
                    Cli.Table(rows);
                    string text;
                    Overview.Overall(states, Inbox.Count(), out text);
                    Cli.Out("");
                    Cli.Out("Overall: " + text);
                    return 0;
                }
                case "alerts":
                {
                    int n;
                    if (!int.TryParse(a[1] ?? "20", out n) || n <= 0) n = 20;
                    var list = Inbox.Open(200).Take(n).ToList();
                    if (list.Count == 0) Cli.Out("No alerts.");
                    foreach (var al in list)
                        Cli.Out(Fmt.Local(al.TimeUtc).PadRight(18) + " " + (al.App ?? "").PadRight(9) + " " + Word(al.Severity).PadRight(9) + " " + al.Title);
                    return 0;
                }
                default:
                    Cli.Out(Help);
                    return 0;
            }
        }
    }

    sealed class HubApp : ApplicationContext
    {
        readonly NotifyIcon tray = new NotifyIcon();
        readonly ContextMenuStrip menu = new ContextMenuStrip();
        readonly Control invoker = new Control();
        readonly System.Windows.Forms.Timer fast = new System.Windows.Forms.Timer { Interval = 2000 };
        readonly System.Windows.Forms.Timer slow = new System.Windows.Forms.Timer { Interval = 15000 };
        readonly HubSettings settings = HubSettings.Load();
        readonly HotkeyWindow hotkey = new HotkeyWindow();
        readonly List<AlertInfo> pending = new List<AlertInfo>(), held = new List<AlertInfo>();
        readonly Dictionary<AppId, WatchInfo> watchers = new Dictionary<AppId, WatchInfo>();
        readonly Dictionary<Badge, Icon> icons = new Dictionary<Badge, Icon>();
        readonly DateTime started = DateTime.UtcNow;
        Dashboard dash;
        List<AppState> states = new List<AppState>();
        int openAlerts;
        bool collecting, wasPlaying;
        DateTime lastToast = DateTime.MinValue, lastAthena = DateTime.MinValue;
        AlertInfo toastAlert;
        ToolStripMenuItem quietItem, gameItem;
        string overallState = States.Off, overallText = "Starting…";

        // One tray icon per guardian while it runs, created up front in a fixed order so Windows
        // keeps each icon's place and "show on taskbar" choice between sign-ins. Aegis has its own.
        // (new guardians go at the end so the existing icons keep their places)
        static readonly AppId[] IconOrder = { AppId.Argus, AppId.Sibyl, AppId.Janus, AppId.Arachne, AppId.Athena, AppId.Cerberus, AppId.Ark, AppId.Ares, AppId.Atlas };
        readonly Dictionary<AppId, NotifyIcon> guardianIcons = new Dictionary<AppId, NotifyIcon>();
        readonly Dictionary<string, Icon> badgeIcons = new Dictionary<string, Icon>();
        string shownIcons = null;

        sealed class WatchInfo
        {
            public int Starts;
            public DateTime Since = DateTime.UtcNow;
            public bool GaveUp;
        }

        public List<AppState> AppStates { get { return states; } }
        public string OverallState { get { return overallState; } }
        public string OverallText { get { return overallText; } }
        public int OpenAlerts { get { return openAlerts; } }
        public event Action Changed;
        public event Action AlertsArrived;

        static int IconSize { get { return Math.Max(16, SystemInformation.SmallIconSize.Width); } }

        public HubApp(bool openDashboard)
        {
            invoker.CreateControl();
            BuildMenu();
            tray.Icon = IconFor(Badge.Off);
            tray.Text = "Olympus";
            tray.ContextMenuStrip = menu;
            tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowDashboard(); };
            tray.BalloonTipClicked += (s, e) => ToastClicked();
            tray.Visible = true;
            CreateGuardianIcons();

            ListenFor("hub.show", ShowDashboard);
            ListenFor("hub.exit", ExitThread);
            ListenFor(ArachneAlertReview.ChangedSignal, () =>
            {
                var dismissed = ArachneAlertReview.DismissedIds();
                pending.RemoveAll(a => a.App == "Arachne" && dismissed.Contains(a.Id));
                held.RemoveAll(a => a.App == "Arachne" && dismissed.Contains(a.Id));
                if (AlertsArrived != null) AlertsArrived();
                SlowTick();
            });
            PrimeOffsets();
            hotkey.Pressed += CheckClipboard;
            if (!hotkey.Register(settings.Hotkey)) Log.Warn("couldn't register the hotkey " + settings.Hotkey + " (another app may use it)");

            fast.Tick += (s, e) => FastTick();
            slow.Tick += (s, e) => SlowTick();
            fast.Start();
            slow.Start();
            SlowTick();
            Log.Info("hub started");
            if (openDashboard) ShowDashboard();
        }

        void ListenFor(string name, Action action)
        {
            var ev = Sync.Listen(name);
            var t = new Thread(() =>
            {
                while (ev.WaitOne())
                {
                    try { invoker.BeginInvoke(action); } catch (Exception) { return; }
                }
            }) { IsBackground = true };
            t.Start();
        }

        Icon IconFor(Badge b)
        {
            Icon ic;
            if (!icons.TryGetValue(b, out ic)) icons[b] = ic = IconArt.MakeIcon(AppId.Olympus, IconSize, b);
            return ic;
        }

        void BuildMenu()
        {
            var open = new ToolStripMenuItem("Open Olympus", IconArt.Draw(AppId.Olympus, Ui.S(16)), (s, e) => ShowDashboard());
            open.Font = new Font(menu.Font, FontStyle.Bold);
            menu.Items.Add(open);
            menu.Items.Add(new ToolStripSeparator());
            foreach (var app in AppInfo.Guardians)
            {
                var id = app.Id;
                menu.Items.Add(new ToolStripMenuItem(app.Name + "  —  " + app.Role, IconArt.Draw(app.Id, Ui.S(16)), (s, e) => Launch.Open(id, null)));
            }
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(new ToolStripMenuItem("Check a link or message  (" + settings.Hotkey + ")", null, (s, e) => CheckClipboard()));
            menu.Items.Add(new ToolStripMenuItem("Back up now", null, (s, e) => Launch.Command(AppId.Ark, "--backup-now")));
            menu.Items.Add(new ToolStripMenuItem("Scan for hijacks now", null, (s, e) => Launch.Command(AppId.Argus, "--scan-now")));
            menu.Items.Add(new ToolStripMenuItem("Free up space", null, (s, e) => Launch.Open(AppId.Atlas, "clean")));
            gameItem = new ToolStripMenuItem("Game mode", null, (s, e) => Launch.Command(AppId.Ares, "--toggle"));
            menu.Items.Add(gameItem);
            menu.Items.Add(new ToolStripSeparator());
            quietItem = new ToolStripMenuItem("Quiet pop-ups for 1 hour", null, (s, e) => { Inbox.SetQuiet(Inbox.Quiet ? (TimeSpan?)null : TimeSpan.FromHours(1)); UpdateIcon(); });
            menu.Items.Add(quietItem);
            menu.Items.Add(new ToolStripMenuItem("Exit", null, (s, e) => ExitThread()));
            menu.Opening += (s, e) =>
            {
                quietItem.Text = Inbox.Quiet ? "Pop-ups back on" : "Quiet pop-ups for 1 hour";
                gameItem.Checked = GameState.Playing;
            };
        }

        void CheckClipboard() { Launch.Command(AppId.Sibyl, "--clipboard"); }

        // ------------------------------------------------------------------ a tray icon per guardian

        Icon GuardianIcon(AppId id, Badge b)
        {
            string k = id + ":" + b;
            Icon ic;
            if (!badgeIcons.TryGetValue(k, out ic)) badgeIcons[k] = ic = IconArt.MakeIcon(id, IconSize, b);
            return ic;
        }

        IEnumerable<ToolStripItem> QuickActions(AppId id)
        {
            switch (id)
            {
                case AppId.Argus: yield return new ToolStripMenuItem("Scan now", null, (s, e) => Launch.Command(AppId.Argus, "--scan-now")); break;
                case AppId.Sibyl: yield return new ToolStripMenuItem("Check what I copied  (" + settings.Hotkey + ")", null, (s, e) => CheckClipboard()); break;
                case AppId.Athena: yield return new ToolStripMenuItem("Check again now", null, (s, e) => Launch.Command(AppId.Athena, "--report --quiet")); break;
                case AppId.Ark: yield return new ToolStripMenuItem("Back up now", null, (s, e) => Launch.Command(AppId.Ark, "--backup-now")); break;
                case AppId.Ares: yield return new ToolStripMenuItem("Game mode on/off", null, (s, e) => Launch.Command(AppId.Ares, "--toggle")); break;
                case AppId.Atlas:
                    yield return new ToolStripMenuItem("Clean up junk…", null, (s, e) => Launch.Open(AppId.Atlas, "clean"));
                    yield return new ToolStripMenuItem("Map drive C:", null, (s, e) => Launch.Open(AppId.Atlas, "map:C"));
                    break;
            }
        }

        void CreateGuardianIcons()
        {
            foreach (var id in IconOrder)
            {
                var app = AppInfo.Of(id);
                var ni = new NotifyIcon { Icon = GuardianIcon(id, Badge.Off), Text = app.Name, Visible = false };
                var m = new ContextMenuStrip();
                var open = new ToolStripMenuItem("Open " + app.Name, IconArt.Draw(id, Ui.S(16)), (s, e) => Launch.Open(id, null));
                open.Font = new Font(m.Font, FontStyle.Bold);
                m.Items.Add(open);
                foreach (var extra in QuickActions(id)) m.Items.Add(extra);
                m.Items.Add(new ToolStripSeparator());
                m.Items.Add(new ToolStripMenuItem("Hide this icon", null, (s, e) => HideIcon(id)));
                m.Items.Add(new ToolStripMenuItem("Open Olympus", IconArt.Draw(AppId.Olympus, Ui.S(16)), (s, e) => ShowDashboard()));
                ni.ContextMenuStrip = m;
                ni.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) Launch.Open(id, null); };
                guardianIcons[id] = ni;
            }
        }

        void HideIcon(AppId id)
        {
            var name = AppInfo.Of(id).Name;
            if (!settings.Hidden.Contains(name, StringComparer.OrdinalIgnoreCase)) settings.Hidden.Add(name);
            try { HubSettings.SaveHidden(settings.Hidden); } catch (Exception e) { Log.Error("saving hidden icons", e); }
            UpdateGuardianIcons();
            tray.ShowBalloonTip(5000, name + "'s tray icon is hidden", "Bring it back by removing " + name + " from hidden_icons in Olympus's settings (Settings on the dashboard).", ToolTipIcon.Info);
        }

        void UpdateGuardianIcons()
        {
            var shown = new List<string>();
            foreach (var st in states)
            {
                NotifyIcon ni;
                if (!guardianIcons.TryGetValue(st.App.Id, out ni)) continue;
                bool show = settings.GuardianIcons && st.Running && !settings.Hidden.Contains(st.App.Name, StringComparer.OrdinalIgnoreCase);
                if (show)
                {
                    string summary = st.App.Id == AppId.Sibyl && (st.Summary.StartsWith("Hasn't") || st.Summary.StartsWith("Ready")) ? "ready (" + settings.Hotkey + ")" : st.Summary;
                    ni.Icon = GuardianIcon(st.App.Id, Ui.StateBadge(st.State));
                    ni.Text = Fmt.Clip(st.App.Name + " — " + summary, 63);
                    shown.Add(st.App.Name);
                }
                if (ni.Visible != show) ni.Visible = show;
            }
            string now = string.Join(", ", shown);
            if (now != shownIcons)
            {
                shownIcons = now;
                Log.Info("tray icons: " + (now.Length == 0 ? "none" : now));
            }
            // Windows lists a new icon a few seconds after it first appears, so keep looking (cheap)
            if (settings.PinIcons) PinIcons();
        }

        // Windows 11 keeps each tray icon's "show on the taskbar" choice under
        // HKCU\Control Panel\NotifyIconSettings. Each of Olympus's icons is promoted once, the first
        // time Windows lists it; after that your own choice in Settings is left alone.
        void PinIcons()
        {
            try
            {
                var st = Inbox.State;
                int pinned = 0;
                using (var root = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Control Panel\NotifyIconSettings", true))
                {
                    if (root == null) return;
                    foreach (var name in root.GetSubKeyNames())
                    {
                        if (st.Pinned.Contains(name)) continue;
                        using (var k = root.OpenSubKey(name, true))
                        {
                            string exe = k == null ? null : k.GetValue("ExecutablePath") as string;
                            if (exe == null || !exe.EndsWith(@"\Olympus\Olympus.exe", StringComparison.OrdinalIgnoreCase)) continue;
                            k.SetValue("IsPromoted", 1, Microsoft.Win32.RegistryValueKind.DWord);
                            st.Pinned.Add(name);
                            pinned++;
                        }
                    }
                }
                if (pinned > 0) { Inbox.Save(); Log.Info("asked Windows to show " + pinned + " Olympus tray icons on the taskbar"); }
            }
            catch (Exception e) { Log.Warn("pinning tray icons: " + e.Message); }
        }

        public void ShowDashboard()
        {
            if (dash == null || dash.IsDisposed)
            {
                dash = new Dashboard(this);
                dash.Show();
            }
            else dash.BringUp();
        }

        // Start each alerts file where it ends now the first time; afterwards carry on where we left off,
        // so alerts raised while the hub wasn't running (say, at boot) still pop up.
        void PrimeOffsets()
        {
            var st = Inbox.State;
            foreach (var app in AppInfo.All)
                foreach (var dir in new[] { Suite.SharedDir(app.Id), Suite.UserDir(app.Id) })
                {
                    if (st.Offsets.ContainsKey(dir)) continue;
                    string f = Path.Combine(dir, AlertStore.FileName);
                    long len = 0;
                    try { if (File.Exists(f)) len = new FileInfo(f).Length; } catch (Exception) { }
                    st.Offsets[dir] = len;
                }
            Inbox.Save();
        }

        void FastTick()
        {
            var fresh = new List<AlertInfo>();
            var st = Inbox.State;
            bool moved = false;
            foreach (var app in AppInfo.All)
                foreach (var dir in new[] { Suite.SharedDir(app.Id), Suite.UserDir(app.Id) })
                {
                    long off;
                    st.Offsets.TryGetValue(dir, out off);
                    long before = off;
                    fresh.AddRange(AlertStore.Tail(dir, ref off));
                    if (off != before) { st.Offsets[dir] = off; moved = true; }
                }
            if (moved) Inbox.Save();
            if (fresh.Count > 0)
            {
                var dismissed = fresh.Any(a => a != null && a.App == "Arachne") ? ArachneAlertReview.DismissedIds() : null;
                foreach (var a in fresh)
                    if (a == null || a.App != "Arachne" || !dismissed.Contains(a.Id)) Route(a);
                if (AlertsArrived != null) AlertsArrived();
                SlowTick();
            }
            bool playing = GameState.Playing;
            if (wasPlaying && !playing && held.Count > 0) ShowHeld("While you played");
            else if (!playing && !Inbox.Quiet && held.Count > 0 && !wasPlaying) ShowHeld("While pop-ups were quiet");
            wasPlaying = playing;
            Flush();
        }

        void Route(AlertInfo a)
        {
            if (a == null || !settings.Toasts || Sev.Rank(a.Severity) < Sev.Rank(Sev.Warning)) return;
            bool hold = Inbox.Quiet || (settings.HoldWhileGaming && GameState.Playing && a.Severity != Sev.Critical);
            (hold ? held : pending).Add(a);
        }

        void Flush()
        {
            if (pending.Count == 0 || (DateTime.UtcNow - lastToast).TotalSeconds < 6) return;
            if (pending.Count == 1)
            {
                var a = pending[0];
                toastAlert = a;
                tray.ShowBalloonTip(10000, Fmt.Clip(a.App + ": " + a.Title, 63), Fmt.Clip(string.IsNullOrEmpty(a.Body) ? a.Title : a.Body, 250),
                    a.Severity == Sev.Critical ? ToolTipIcon.Error : ToolTipIcon.Warning);
            }
            else
            {
                toastAlert = null;
                var lines = pending.Take(3).Select(x => x.App + ": " + x.Title).ToList();
                if (pending.Count > 3) lines.Add("…and " + (pending.Count - 3) + " more");
                tray.ShowBalloonTip(10000, "Olympus: " + pending.Count + " new alerts", Fmt.Clip(string.Join("\n", lines), 250),
                    pending.Any(x => x.Severity == Sev.Critical) ? ToolTipIcon.Error : ToolTipIcon.Warning);
            }
            pending.Clear();
            lastToast = DateTime.UtcNow;
        }

        void ShowHeld(string when)
        {
            toastAlert = null;
            var lines = held.Take(3).Select(x => x.App + ": " + x.Title).ToList();
            if (held.Count > 3) lines.Add("…and " + (held.Count - 3) + " more");
            tray.ShowBalloonTip(10000, when + ": " + Fmt.Plural(held.Count, "alert"), Fmt.Clip(string.Join("\n", lines), 250), ToolTipIcon.Info);
            held.Clear();
            lastToast = DateTime.UtcNow;
        }

        void ToastClicked()
        {
            if (toastAlert != null)
            {
                var app = AppInfo.Find(toastAlert.App);
                if (app != null && app.Id != AppId.Olympus) { Launch.Open(app.Id, "alert:" + toastAlert.Id); return; }
            }
            ShowDashboard();
        }

        void SlowTick()
        {
            if (!collecting)
            {
                collecting = true;
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    List<AppState> got = null;
                    int open = 0;
                    try { got = Overview.Collect(); open = Inbox.Count(); }
                    catch (Exception e) { Log.Error("collecting states", e); }
                    try
                    {
                        invoker.BeginInvoke((Action)(() =>
                        {
                            collecting = false;
                            if (got == null) return;
                            states = got;
                            openAlerts = open;
                            UpdateIcon();
                            if (Changed != null) Changed();
                        }));
                    }
                    catch (Exception) { collecting = false; }
                });
            }
            if (settings.RunWatchers) Supervise();
            MaybeRunAthena();
        }

        void UpdateIcon()
        {
            string text;
            overallState = Overview.Overall(states, openAlerts, out text);
            overallText = text;
            var b = Ui.StateBadge(overallState);
            tray.Icon = IconFor(b);
            tray.Text = Fmt.Clip("Olympus — " + text + (Inbox.Quiet ? " (pop-ups quiet)" : ""), 63);
            UpdateGuardianIcons();
        }

        // Janus and Ares run in your session; start them if they're not running (but stop
        // trying for a while if one keeps stopping).
        void Supervise()
        {
            foreach (var app in AppInfo.All.Where(x => x.Watcher))
            {
                string exe = Suite.ExeOf(app.Id);
                if (!File.Exists(exe) || Proc.Running(exe)) continue;
                WatchInfo w;
                if (!watchers.TryGetValue(app.Id, out w)) watchers[app.Id] = w = new WatchInfo();
                if (DateTime.UtcNow - w.Since > TimeSpan.FromMinutes(30)) { w.Since = DateTime.UtcNow; w.Starts = 0; w.GaveUp = false; }
                if (w.GaveUp) continue;
                if (++w.Starts > 4)
                {
                    w.GaveUp = true;
                    Log.Warn(app.Name + " keeps stopping; leaving it off for 30 minutes");
                    continue;
                }
                Log.Info("starting " + app.Name + " --watch");
                Launch.Command(app.Id, "--watch");
            }
        }

        void MaybeRunAthena()
        {
            if (DateTime.UtcNow - started < TimeSpan.FromMinutes(3) || DateTime.UtcNow - lastAthena < TimeSpan.FromHours(1)) return;
            if (!File.Exists(Suite.ExeOf(AppId.Athena))) return;
            var s = J.Load<StatusInfo>(Path.Combine(Suite.UserDir(AppId.Athena), StatusStore.FileName));
            if (s != null && DateTime.UtcNow - s.UpdatedUtc < TimeSpan.FromHours(settings.AthenaHours)) return;
            lastAthena = DateTime.UtcNow;
            Launch.Command(AppId.Athena, "--report --quiet");
        }

        protected override void ExitThreadCore()
        {
            fast.Stop();
            slow.Stop();
            tray.Visible = false;
            tray.Dispose();
            foreach (var ni in guardianIcons.Values) { ni.Visible = false; ni.Dispose(); }
            hotkey.Dispose();
            Inbox.Save();
            if (dash != null && !dash.IsDisposed) dash.Close();
            Log.Info("hub stopped");
            base.ExitThreadCore();
        }
    }

    // Receives the global hotkey.
    sealed class HotkeyWindow : NativeWindow, IDisposable
    {
        public event Action Pressed;
        bool registered;
        public HotkeyWindow() { CreateHandle(new CreateParams()); }

        public bool Register(string spec)
        {
            uint mods, vk;
            if (!Parse(spec, out mods, out vk)) return false;
            registered = Native.RegisterHotKey(Handle, 1, mods | 0x4000 /* no repeat */, vk);
            return registered;
        }

        public static bool Parse(string spec, out uint mods, out uint vk)
        {
            mods = 0;
            vk = 0;
            if (string.IsNullOrWhiteSpace(spec)) return false;
            foreach (var part in spec.Split('+'))
            {
                string t = part.Trim().ToLowerInvariant();
                if (t == "ctrl" || t == "control") mods |= 2;
                else if (t == "alt") mods |= 1;
                else if (t == "shift") mods |= 4;
                else if (t == "win") mods |= 8;
                else
                {
                    Keys k;
                    if (!Enum.TryParse(part.Trim(), true, out k)) return false;
                    vk = (uint)k;
                }
            }
            return vk != 0 && mods != 0;
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == 0x0312 && Pressed != null) Pressed();
            base.WndProc(ref m);
        }

        public void Dispose()
        {
            if (registered) { try { Native.UnregisterHotKey(Handle, 1); } catch (Exception) { } }
            DestroyHandle();
        }
    }
}
