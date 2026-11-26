// What the hub knows: how each app is doing, the alert inbox (what's been dismissed, what's
// been toasted), hub settings, and opening an app or running one of its alert actions.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Hub
{
    sealed class AppState
    {
        public AppEntry Entry;
        public AppInfo App;      // the suite's own apps; null for registered ones
        public string State = States.Off, Summary = "", Detail = "";
        public DateTime Updated = DateTime.MinValue;
        public bool Present;
        public bool Running;     // on duty right now (reporting on time, or its program is open); Sibyl: ready through the hotkey
        public bool? Enabled;    // switched on (stays on after a restart); null when it can't be told
        public bool Held;        // a watcher you stopped by hand, left stopped until you start it or sign in again
        public bool Tray;        // Aegis: its tray icon is open

        public string Name { get { return Entry.Name; } }
        public bool Off { get { return Enabled == false; } }
        // drawn greyed: switched off and not running, or stopped by hand
        public bool Faded { get { return Held || (Off && !Running); } }
        public string RunWord
        {
            get
            {
                if (Entry.Kind == AppKind.Launcher) return "-";
                if (Entry.Kind == AppKind.OnDemand) return Off ? "no" : "ready";
                return Running ? "yes" : "no";
            }
        }
        public string OnWord
        {
            get
            {
                if (Entry.Kind == AppKind.Launcher) return "—";
                return Enabled == true ? "On" : Enabled == false ? "Off" : "?";
            }
        }
    }

    static class Overview
    {
        public static List<AppState> Collect()
        {
            var settings = HubSettings.Load();
            var held = Held.Read();
            var list = new List<AppState>();
            foreach (var e in AppRegistry.All())
            {
                AppState st;
                try
                {
                    if (e.Kind == AppKind.Aegis) st = Aegis();
                    else if (e.IsSuite) st = FromStatus(e.Info);
                    else st = Registered(e);
                    st.Entry = e;
                    if (e.IsSuite) Switched(st, settings, held);
                }
                catch (Exception x)
                {
                    st = new AppState { Entry = e, App = e.Info, State = States.Error, Summary = "Couldn't check: " + x.Message };
                }
                list.Add(st);
            }
            return list;
        }

        // Whether one of the suite's apps is switched on, and what that changes in its state line.
        static void Switched(AppState st, HubSettings settings, HashSet<string> held)
        {
            var e = st.Entry;
            switch (e.Kind)
            {
                case AppKind.Watcher:
                case AppKind.OnDemand:
                    st.Enabled = !settings.IsOff(e.Name);
                    st.Held = e.Kind == AppKind.Watcher && held.Contains(e.Name);
                    break;
                case AppKind.Periodic:
                case AppKind.Engine:
                    st.Enabled = Suite.Installed ? TaskControl.Enabled(e.Name) : null;
                    // a fresh report means its task is evidently running
                    if (st.Enabled == null && st.Running) st.Enabled = true;
                    break;
            }
            if (!st.Present) return;
            if (e.Kind == AppKind.OnDemand && st.Off) { st.State = States.Off; st.Summary = "Off: its hotkey is free"; st.Running = false; }
            else if (st.Off && !st.Running)
            {
                st.State = States.Off;
                if (st.Updated != DateTime.MinValue) st.Detail = "Last report " + Fmt.Ago(st.Updated) + ": " + st.Summary;
                st.Summary = "Off (switched off in Olympus)";
            }
            else if (st.Held && !st.Running)
            {
                st.State = States.Off;
                st.Summary = "Stopped until you start it again (or Olympus restarts)";
            }
        }

        // What's wrong with a service an app needs, or null when it's running (or none is named).
        public static string ServiceProblem(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            try
            {
                using (var sc = new System.ServiceProcess.ServiceController(name))
                {
                    var s = sc.Status;   // throws when there's no such service
                    return s == System.ServiceProcess.ServiceControllerStatus.Running ? null : "Running, but the " + name + " service is " + s.ToString().ToLowerInvariant();
                }
            }
            catch (InvalidOperationException) { return "Running, but the " + name + " service isn't installed"; }
            catch (Exception) { return null; }
        }

        // A registered program: open or not, switched on at sign-in or not, plus what it says itself.
        static AppState Registered(AppEntry e)
        {
            var st = new AppState { Entry = e };
            if (e.Kind == AppKind.Launcher)
            {
                st.Present = AppRegistry.Present(e);
                st.State = st.Present ? States.Ok : States.Error;
                st.Summary = st.Present ? "Ready: runs when you click Run" : "Not found";
                st.Detail = st.Present ? e.Blurb : "Couldn't find what it runs: " + e.Command;
                return st;
            }
            st.Present = File.Exists(e.Exe);
            if (!st.Present)
            {
                st.State = States.Error;
                st.Summary = "Not found";
                st.Detail = "Couldn't find " + e.Exe;
                return st;
            }
            try { st.Enabled = StartupEntry.State(e.RunName) == true; } catch (Exception) { st.Enabled = null; }
            st.Running = Proc.Running(e.Exe);
            st.Updated = DateTime.UtcNow;
            StatusInfo own = e.StatusPath == null ? null : J.Load<StatusInfo>(e.StatusPath);
            if (own != null && (DateTime.UtcNow - own.UpdatedUtc) > TimeSpan.FromMinutes(30)) own = null;
            if (st.Running)
            {
                st.State = own != null && !string.IsNullOrEmpty(own.State) ? own.State : States.Ok;
                st.Summary = own != null && !string.IsNullOrEmpty(own.Summary) ? own.Summary : "Running";
                if (st.Enabled == false) st.Summary += " · doesn't start at sign-in";
                st.Detail = own != null && !string.IsNullOrEmpty(own.Detail) ? own.Detail : (LogTail.Last(e.LogPath) ?? e.Blurb);
                string svc = ServiceProblem(e.Service);
                if (svc != null && States.Rank(st.State) < 2)
                {
                    st.State = States.Warn;
                    st.Summary = svc;
                }
            }
            else if (st.Enabled == true)
            {
                st.State = States.Warn;
                st.Summary = "Not running (it's set to start at sign-in)";
                st.Detail = LogTail.Last(e.LogPath) ?? e.Blurb;
            }
            else
            {
                st.State = States.Off;
                st.Summary = "Off";
                st.Detail = e.Blurb;
            }
            return st;
        }

        static long Num(Dictionary<string, string> f, string k)
        {
            string v;
            long n;
            return f.TryGetValue(k, out v) && long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : 0;
        }

        // Aegis is paused "until you turn it back on" when its pause runs out more than a year away.
        public static bool PausedForGood(Dictionary<string, string> f)
        {
            string state;
            if (!f.TryGetValue("state", out state) || state != "paused") return false;
            long until = Num(f, "until");
            return until > 0 && Clock.FromUnix(Math.Min(until, 253402300799L)) > DateTime.UtcNow.AddDays(365);
        }

        static AppState Aegis()
        {
            var st = new AppState { App = AppInfo.Of(AppId.Aegis), Updated = DateTime.UtcNow };
            string exe = AegisClient.Exe;
            st.Tray = exe != null && Proc.Running(exe);
            var f = AegisClient.Status();
            if (f.Count == 0)
            {
                st.Present = exe != null;
                st.State = st.Present ? States.Alert : States.Off;
                st.Summary = st.Present ? "Its engine isn't answering" : "Not installed";
                return st;
            }
            st.Present = true;
            st.Running = true;
            string state;
            f.TryGetValue("state", out state);
            long blocked = Num(f, "b"), lookups = Num(f, "q"), domains = Num(f, "domains");
            st.Enabled = !PausedForGood(f);
            if (st.Off) { st.State = States.Off; st.Summary = "Off: filtering paused until you enable it"; }
            else if (state == "paused") { st.State = States.Warn; st.Summary = "Paused"; }
            else if (!AegisClient.WindowsUsesAegis()) { st.State = States.Warn; st.Summary = "Windows isn't using it"; }
            else { st.State = States.Ok; st.Summary = "Filtering · " + blocked.ToString("N0") + " blocked today"; }
            st.Detail = st.Off ? "Windows still sends its lookups to Aegis, so DNS keeps working; nothing is blocked."
                : lookups.ToString("N0") + " lookups today · " + domains.ToString("N0") + " domains listed";
            if (!st.Tray) st.Detail += " · tray icon closed";
            return st;
        }

        // How long each guardian may go without reporting before the hub calls it stale.
        static TimeSpan MaxAge(AppId id)
        {
            switch (id)
            {
                case AppId.Argus: return TimeSpan.FromMinutes(30);
                case AppId.Ark: return TimeSpan.FromHours(3);
                case AppId.Cerberus: case AppId.Arachne: case AppId.Janus: case AppId.Ares: case AppId.Atlas: return TimeSpan.FromMinutes(20);
                case AppId.Athena: return TimeSpan.FromDays(3);
                default: return TimeSpan.Zero;
            }
        }

        static AppState FromStatus(AppInfo app)
        {
            var st = new AppState { App = app };
            string from;
            // Argus's status from the folder its findings are shown from (the installed engine's, once installed).
            var s = app.Id == AppId.Argus ? ArgusAlertReview.ReadDisplayStatus(out from) : StatusStore.Read(app.Id, out from);
            if (app.Id == AppId.Arachne) ArachneAlertReview.ApplyStatus(s, ArachneAlertReview.Open(200));
            if (app.Id == AppId.Argus) ArgusAlertReview.ApplyStatus(s, from);
            bool exe = File.Exists(Suite.ExeOf(app.Id));
            if (s == null)
            {
                st.Present = exe;
                st.State = States.Off;
                st.Summary = exe ? "Hasn't reported yet" : "Not installed";
                st.Running = exe && app.Id == AppId.Sibyl;
                return st;
            }
            st.Present = true;
            st.State = s.State ?? States.Off;
            st.Summary = s.Summary ?? "";
            st.Detail = s.Detail ?? "";
            st.Updated = s.UpdatedUtc;
            var max = MaxAge(app.Id);
            bool stale = max > TimeSpan.Zero && DateTime.UtcNow - st.Updated > max;
            st.Running = app.Id == AppId.Sibyl ? exe : !stale && st.State != States.Off;
            if (stale && st.State != States.Off)
            {
                st.State = States.Warn;
                st.Detail = "Last report " + Fmt.Ago(st.Updated) + ": " + st.Summary;
                st.Summary = "Not running (no report for " + Fmt.Duration(DateTime.UtcNow - st.Updated) + ")";
            }
            return st;
        }

        // The hub's one-line verdict. Apps you switched off or stopped by hand, and launchers, don't count.
        public static string Overall(List<AppState> states, int openAlerts, out string text)
        {
            var present = states.Where(s => s.Present && s.Entry.Kind != AppKind.Launcher && !s.Off && !s.Held).ToList();
            var bad = present.Where(s => States.Rank(s.State) == 3).ToList();
            var warnings = present.Where(s => s.State == States.Warn || (s.State == States.Off && s.Entry.Kind != AppKind.OnDemand)).ToList();
            if (present.Count == 0 && states.Any(s => s.Present && s.Entry.Kind != AppKind.Launcher))
            {
                text = "Every app is switched off";
                return openAlerts > 0 ? States.Warn : States.Off;
            }
            if (present.Count == 0) { text = "Nothing installed yet"; return States.Off; }
            if (bad.Count > 0)
            {
                text = bad.Count == 1 ? bad[0].Name + " needs attention" : bad.Count + " apps need attention";
                return States.Alert;
            }
            if (warnings.Count + openAlerts > 0)
            {
                var parts = new List<string>();
                if (openAlerts > 0) parts.Add(Fmt.Plural(openAlerts, "alert") + " to review");
                if (warnings.Count > 0) parts.Add(warnings.Count == 1 ? warnings[0].Name + " needs a look" : warnings.Count + " apps need a look");
                text = string.Join(" · ", parts);
                return States.Warn;
            }
            int off = states.Count(s => s.Present && s.Entry.Kind != AppKind.Launcher && (s.Off || s.Held));
            text = "All quiet · " + Fmt.Plural(present.Count, "app") + " on" + (off > 0 ? " · " + off + " off" : "");
            return States.Ok;
        }
    }

    // The hub's record of alerts: where it has read up to in each alerts file, and what you dismissed.
    sealed class InboxState
    {
        public Dictionary<string, long> Offsets = new Dictionary<string, long>();
        public List<string> Dismissed = new List<string>();
        public List<string> Pinned = new List<string>();   // tray-icon settings keys already promoted once
        public string QuietUntil;
    }

    static class Inbox
    {
        static readonly object gate = new object();
        static InboxState state;
        static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Olympus), "inbox.json"); } }

        public static InboxState State
        {
            get
            {
                lock (gate)
                {
                    if (state == null) state = J.Load<InboxState>(FilePath) ?? new InboxState();
                    if (state.Offsets == null) state.Offsets = new Dictionary<string, long>();
                    if (state.Dismissed == null) state.Dismissed = new List<string>();
                    if (state.Pinned == null) state.Pinned = new List<string>();
                    return state;
                }
            }
        }

        public static void Save()
        {
            lock (gate)
            {
                if (state == null) return;
                if (state.Dismissed.Count > 2000) state.Dismissed.RemoveRange(0, state.Dismissed.Count - 2000);
                try { J.Save(FilePath, state); } catch (Exception e) { Log.Error("saving the inbox", e); }
            }
        }

        // Alerts from every guardian, newest first, without the dismissed ones.
        public static List<AlertInfo> Open(int perApp)
        {
            var dismissed = AlertReview.DismissedIds();
            var resolved = ArgusAlertReview.ResolvedIds();
            var all = new List<AlertInfo>();
            foreach (var app in AppInfo.All)
            {
                var records = AlertStore.Recent(app.Id, int.MaxValue);
                all.AddRange(ArgusAlertReview.Remaining(records, resolved)
                    .Where(a => !string.IsNullOrEmpty(a.Id) && !dismissed.Contains(a.Id)).Take(perApp));
            }
            return all.OrderByDescending(a => a.Time, StringComparer.Ordinal).ToList();
        }

        // Warnings and worse from the last week that you haven't dismissed.
        public static int Count()
        {
            var since = Clock.Iso(DateTime.UtcNow.AddDays(-7));
            return Open(100).Count(a => Sev.Rank(a.Severity) >= 2 && string.CompareOrdinal(a.Time, since) > 0);
        }

        public static bool Quiet
        {
            get
            {
                var q = Clock.Parse(State.QuietUntil);
                return q > DateTime.UtcNow;
            }
        }
        public static void SetQuiet(TimeSpan? span)
        {
            State.QuietUntil = span.HasValue ? Clock.Iso(DateTime.UtcNow + span.Value) : null;
            Save();
        }
    }

    sealed class HubSettings
    {
        public string Hotkey = "Ctrl+Alt+L";
        public bool RunWatchers = true, Toasts = true, HoldWhileGaming = true, GuardianIcons = true, PinIcons = true;
        public int AthenaHours = 24;
        public List<string> Hidden = new List<string>();
        public List<string> Off = new List<string>();

        public bool IsOff(string name) { return Off.Contains(name, StringComparer.OrdinalIgnoreCase); }

        public const string Defaults =
            "; Olympus hub settings. Changes apply the next time Olympus starts (off_apps applies at once).\r\n\r\n" +
            "[hub]\r\n" +
            "; Check the link or message on the clipboard with Sibyl.\r\n" +
            "hotkey = Ctrl+Alt+L\r\n" +
            "; Keep Janus (downloads), Ares (game mode) and Atlas (drive space) running in the background.\r\n" +
            "run_watchers = true\r\n" +
            "; Apps you switched off on the dashboard's Apps tab (Janus, Ares, Atlas: the hub leaves them off; Sibyl: no hotkey).\r\n" +
            "off_apps =\r\n" +
            "; Pop-up notifications for new alerts (warnings and worse).\r\n" +
            "toasts = true\r\n" +
            "; Hold non-urgent pop-ups while a game is running; show a summary afterwards.\r\n" +
            "hold_while_gaming = true\r\n" +
            "; How often Athena re-grades your PC (hours).\r\n" +
            "athena_report_hours = 24\r\n" +
            "; A tray icon for each Olympus app while it's running, next to Olympus's own.\r\n" +
            "guardian_icons = true\r\n" +
            "; Apps whose tray icon you hid (right-click an icon > Hide this icon). Delete a name to bring it back.\r\n" +
            "hidden_icons =\r\n" +
            "; Ask Windows to show Olympus's icons on the taskbar instead of in the ^ overflow (once per icon; your later choice in Settings wins).\r\n" +
            "pin_icons = true\r\n";

        public static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Olympus), "olympus.ini"); } }

        public static HubSettings Load()
        {
            var ini = Ini.LoadOrCreate(FilePath, Defaults);
            return new HubSettings
            {
                Hotkey = ini.Get("hub", "hotkey", "Ctrl+Alt+L"),
                RunWatchers = ini.Bool("hub", "run_watchers", true),
                Toasts = ini.Bool("hub", "toasts", true),
                HoldWhileGaming = ini.Bool("hub", "hold_while_gaming", true),
                AthenaHours = Math.Max(1, ini.Int("hub", "athena_report_hours", 24)),
                GuardianIcons = ini.Bool("hub", "guardian_icons", true),
                PinIcons = ini.Bool("hub", "pin_icons", true),
                Hidden = ini.List("hub", "hidden_icons"),
                Off = ini.List("hub", "off_apps")
            };
        }

        // The settings text with hidden_icons set to the list (other lines and comments untouched).
        public static string WithHidden(string text, IEnumerable<string> hidden) { return WithList(text, "hidden_icons", hidden); }

        // The settings text with one [hub] list setting replaced (or added under [hub]).
        public static string WithList(string text, string key, IEnumerable<string> values)
        {
            string line = key + " = " + string.Join(", ", values);
            var existing = new System.Text.RegularExpressions.Regex(@"(?m)^[ \t]*" + System.Text.RegularExpressions.Regex.Escape(key) + @"[ \t]*=[^\r\n]*");
            if (existing.IsMatch(text)) return existing.Replace(text, line, 1);
            var hub = new System.Text.RegularExpressions.Regex(@"(?m)^\[hub\][ \t]*\r?$");
            if (hub.IsMatch(text)) return hub.Replace(text, "[hub]\r\n" + line, 1);
            return text.TrimEnd() + "\r\n\r\n[hub]\r\n" + line + "\r\n";
        }

        public static void SaveHidden(IEnumerable<string> hidden) { SaveList("hidden_icons", hidden); }

        // Adds or removes an app in off_apps.
        public static void SetOff(string name, bool off)
        {
            var now = Load().Off;
            now.RemoveAll(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (off) now.Add(name);
            SaveList("off_apps", now);
        }

        static readonly object saveGate = new object();
        static void SaveList(string key, IEnumerable<string> values)
        {
            lock (saveGate)
            {
                string text = File.Exists(FilePath) ? File.ReadAllText(FilePath) : Defaults;
                FileUtil.WriteAtomic(FilePath, WithList(text, key, values));
            }
        }
    }

    static class Launch
    {
        // Opens a guardian's window (Aegis: its own app).
        public static void Open(AppId id, string request)
        {
            try
            {
                if (id == AppId.Aegis)
                {
                    string aegis = AegisClient.Exe;
                    if (aegis != null) Proc.Start(aegis, "");
                    return;
                }
                string exe = Suite.ExeOf(id);
                if (!File.Exists(exe)) return;
                Proc.Start(exe, request == null ? "" : "--show " + Proc.Quote(request));
            }
            catch (Exception e) { Log.Error("opening " + id, e); }
        }

        public static void Command(AppId id, string args)
        {
            string exe = Suite.ExeOf(id);
            if (!File.Exists(exe)) return;
            try { Proc.Start(exe, args); } catch (Exception e) { Log.Error("starting " + id + " " + args, e); }
        }

        // Runs one of an alert's buttons. Returns a message to show, or null when all went well.
        public static string Action(AlertInfo a, AlertAction act)
        {
            if (a == null || act == null) return "This alert has an invalid action.";
            var app = AppInfo.Find(a.App);
            if (app == null) return "Unknown app " + a.App;
            try
            {
                bool installed = Suite.Installed;
                bool elevate;
                if (!CanRunAction(app.Id, act.Id, installed, out elevate)) return "This alert has an invalid action.";
                if (elevate && !installed) return "Install Olympus before running an administrator alert action.";
                var record = AlertStore.FindForAction(app.Id, a.Id, act.Id);
                if (record == null || record.Title != a.Title || record.Body != a.Body
                    || !record.Actions.Any(x => x != null && x.Id == act.Id && x.Label == act.Label))
                    return "This action no longer matches the saved alert.";

                string exe = installed && app.SystemEngine ? Path.Combine(Suite.InstallDir, app.Name + ".exe") : Suite.ExeOf(app.Id);
                if (!File.Exists(exe)) return "Couldn't find " + app.Name + " at " + exe;
                string args = "--action " + act.Id + " --alert " + a.Id;
                // Argus exits with 3 when a scan had already kept or replaced the finding behind the alert, and with 4
                // when Turn off found the entry registered differently from what the alert showed.
                const string handled = "Argus had already dealt with this change (a newer scan kept or replaced it), so nothing was changed.";
                const string changed = "That entry changed since Argus reported it, so nothing was changed. Argus's next scan shows it as it is now.";
                if (elevate)
                {
                    int r = Elevation.Run(exe, args, true);
                    if (r == -1) return "Cancelled: Windows asked for admin rights and the request was declined.";
                    if (r == 3 && app.Id == AppId.Argus) return handled;
                    if (r == 4 && app.Id == AppId.Argus) return changed;
                    return r == 0 ? null : app.Name + " couldn't do that (code " + r + "). See its log for details.";
                }
                string output;
                int code = Proc.Run(exe, args, out output, 120000);
                if (code == 3 && app.Id == AppId.Argus) return handled;
                if (code == 4 && app.Id == AppId.Argus) return changed;
                return code == 0 ? null : (output.Trim().Length > 0 ? output.Trim() : app.Name + " couldn't do that (code " + code + ").");
            }
            catch (Exception e) { return e.Message; }
        }

        static bool CanRunAction(AppId id, string action, bool installed, out bool elevate)
        {
            elevate = false;
            switch (id)
            {
                case AppId.Argus:
                    elevate = action == "disable" || (action == "accept" && installed);
                    return action == "accept" || action == "disable";
                case AppId.Arachne:
                    elevate = action == "allow";
                    return action == "kill" || action == "scan" || action == "allow";
                case AppId.Cerberus:
                    elevate = action == "block";
                    return action == "block";
                case AppId.Ark: return action == "retry";
                case AppId.Ares: return action == "kill" || action == "ignore";
                case AppId.Janus: return action == "delete" || action == "show";
                default: return false;
            }
        }
    }
}
