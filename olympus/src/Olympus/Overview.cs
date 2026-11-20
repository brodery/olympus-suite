// What the hub knows: how each guardian is doing, the alert inbox (what's been dismissed,
// what's been toasted), hub settings, and running a guardian or one of its alert actions.
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
        public AppInfo App;
        public string State = States.Off, Summary = "", Detail = "";
        public DateTime Updated = DateTime.MinValue;
        public bool Present;
        public bool Running;   // on duty right now (reporting on time); Sibyl: ready through the hotkey
    }

    static class Overview
    {
        public static List<AppState> Collect()
        {
            var list = new List<AppState>();
            foreach (var app in AppInfo.Guardians) list.Add(app.Id == AppId.Aegis ? Aegis() : FromStatus(app));
            return list;
        }

        static long Num(Dictionary<string, string> f, string k)
        {
            string v;
            long n;
            return f.TryGetValue(k, out v) && long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : 0;
        }

        static AppState Aegis()
        {
            var st = new AppState { App = AppInfo.Of(AppId.Aegis), Updated = DateTime.UtcNow };
            var f = AegisClient.Status();
            if (f.Count == 0)
            {
                st.Present = AegisClient.Exe != null;
                st.State = st.Present ? States.Alert : States.Off;
                st.Summary = st.Present ? "Its engine isn't answering" : "Not installed";
                return st;
            }
            st.Present = true;
            string state;
            f.TryGetValue("state", out state);
            long blocked = Num(f, "b"), lookups = Num(f, "q"), domains = Num(f, "domains");
            if (state == "paused") { st.State = States.Warn; st.Summary = "Paused"; }
            else if (!AegisClient.WindowsUsesAegis()) { st.State = States.Warn; st.Summary = "Windows isn't using it"; }
            else { st.State = States.Ok; st.Summary = "Filtering · " + blocked.ToString("N0") + " blocked today"; }
            st.Detail = lookups.ToString("N0") + " lookups today · " + domains.ToString("N0") + " domains listed";
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
            var s = StatusStore.Read(app.Id);
            if (app.Id == AppId.Arachne) ArachneAlertReview.ApplyStatus(s, ArachneAlertReview.Open(200));
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

        public static string Overall(List<AppState> states, int openAlerts, out string text)
        {
            var present = states.Where(s => s.Present).ToList();
            var bad = present.Where(s => States.Rank(s.State) == 3).ToList();
            var warnings = present.Where(s => s.State == States.Warn || (s.State == States.Off && s.App.Id != AppId.Sibyl)).ToList();
            if (present.Count == 0) { text = "Nothing installed yet"; return States.Off; }
            if (bad.Count > 0)
            {
                text = bad.Count == 1 ? bad[0].App.Name + " needs attention" : bad.Count + " guardians need attention";
                return States.Alert;
            }
            if (warnings.Count + openAlerts > 0)
            {
                var parts = new List<string>();
                if (openAlerts > 0) parts.Add(Fmt.Plural(openAlerts, "alert") + " to review");
                if (warnings.Count > 0) parts.Add(warnings.Count == 1 ? warnings[0].App.Name + " needs a look" : warnings.Count + " guardians need a look");
                text = string.Join(" · ", parts);
                return States.Warn;
            }
            text = "All quiet · " + Fmt.Plural(present.Count, "guardian") + " on watch";
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
            HashSet<string> dismissed;
            lock (gate) dismissed = new HashSet<string>(State.Dismissed);
            var all = new List<AlertInfo>();
            foreach (var app in AppInfo.All)
            {
                if (app.Id == AppId.Arachne) all.AddRange(ArachneAlertReview.Open(perApp));
                else if (app.Id == AppId.Argus) all.AddRange(ArgusAlertReview.Open(perApp));
                else all.AddRange(AlertStore.Recent(app.Id, perApp));
            }
            return all.Where(a => !dismissed.Contains(a.Id)).OrderByDescending(a => a.Time, StringComparer.Ordinal).ToList();
        }

        // Warnings and worse from the last week that you haven't dismissed.
        public static int Count()
        {
            var since = Clock.Iso(DateTime.UtcNow.AddDays(-7));
            return Open(100).Count(a => Sev.Rank(a.Severity) >= 2 && string.CompareOrdinal(a.Time, since) > 0);
        }

        public static void Dismiss(IEnumerable<string> ids)
        {
            lock (gate)
            {
                var st = State;
                foreach (var id in ids) if (!st.Dismissed.Contains(id)) st.Dismissed.Add(id);
            }
            Save();
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

        public const string Defaults =
            "; Olympus hub settings. Changes apply the next time Olympus starts.\r\n\r\n" +
            "[hub]\r\n" +
            "; Check the link or message on the clipboard with Sibyl.\r\n" +
            "hotkey = Ctrl+Alt+L\r\n" +
            "; Keep Janus (downloads), Ares (game mode) and Atlas (drive space) running in the background.\r\n" +
            "run_watchers = true\r\n" +
            "; Pop-up notifications for new alerts (warnings and worse).\r\n" +
            "toasts = true\r\n" +
            "; Hold non-urgent pop-ups while a game is running; show a summary afterwards.\r\n" +
            "hold_while_gaming = true\r\n" +
            "; How often Athena re-grades your PC (hours).\r\n" +
            "athena_report_hours = 24\r\n" +
            "; A tray icon for each guardian while it's running, next to Olympus's own.\r\n" +
            "guardian_icons = true\r\n" +
            "; Guardians whose tray icon you hid (right-click an icon > Hide this icon). Delete a name to bring it back.\r\n" +
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
                Hidden = ini.List("hub", "hidden_icons")
            };
        }

        // The settings text with hidden_icons set to the list (other lines and comments untouched).
        public static string WithHidden(string text, IEnumerable<string> hidden)
        {
            string line = "hidden_icons = " + string.Join(", ", hidden);
            var existing = new System.Text.RegularExpressions.Regex(@"(?m)^[ \t]*hidden_icons[ \t]*=.*$");
            if (existing.IsMatch(text)) return existing.Replace(text, line, 1);
            var hub = new System.Text.RegularExpressions.Regex(@"(?m)^\[hub\][ \t]*\r?$");
            if (hub.IsMatch(text)) return hub.Replace(text, "[hub]\r\n" + line, 1);
            return text.TrimEnd() + "\r\n\r\n[hub]\r\n" + line + "\r\n";
        }

        public static void SaveHidden(IEnumerable<string> hidden)
        {
            string text = File.Exists(FilePath) ? File.ReadAllText(FilePath) : Defaults;
            FileUtil.WriteAtomic(FilePath, WithHidden(text, hidden));
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
                if (elevate)
                {
                    int r = Elevation.Run(exe, args, true);
                    if (r == -1) return "Cancelled: Windows asked for admin rights and the request was declined.";
                    return r == 0 ? null : app.Name + " couldn't do that (code " + r + "). See its log for details.";
                }
                string output;
                int code = Proc.Run(exe, args, out output, 120000);
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
