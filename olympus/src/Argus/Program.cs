// Argus.exe: --scan (the 5-minute scheduled task, as SYSTEM), --scan-now (from the hub),
// alert actions, the command line, and the review window.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Argus
{
    static class Program
    {
        static bool IsCli(string a)
        {
            switch (a) { case "status": case "scan": case "pending": case "list": case "accept": case "help": case "--help": case "/?": return true; default: return false; }
        }

        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool headless = a.Has("--scan") || a.Has("--scan-now") || a.Has("--action") || IsCli(first);
            AppStart.Init(AppId.Argus, !headless);
            try
            {
                if (a.Has("--scan")) return Engine.Scan() == null ? 2 : 0;
                if (a.Has("--scan-now")) return ScanNow();
                if (a.Has("--action")) return Actions.Run(a.Opt("--action"), a.Opt("--alert"), a.Opt("--key"), a.Opt("--undo"), a.Opt("--alerts"), a.Opt("--digest"));
                if (IsCli(first)) { Cli.Attach(); return ArgusCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new ArgusWindow());
            }
            catch (Exception e)
            {
                Log.Error("Argus failed", e);
                if (headless) { Cli.Attach(); Cli.Out("Error: " + e.Message); }
                return 1;
            }
        }

        // Once installed, the SYSTEM task does the scan (it sees everything); before that, scan as you.
        public static int ScanNow()
        {
            if (Suite.Installed && !Elevation.IsElevated)
            {
                string o;
                int code = Proc.Run("schtasks.exe", "/run /tn \"\\Olympus\\Argus\"", out o, 20000);
                if (code == 0) return 0;
                Log.Warn("couldn't start the Argus task: " + o.Trim());
            }
            return Engine.Scan() == null ? 2 : 0;
        }
    }

    // Keep / turn off / undo, from an alert button, the window or the command line. Changing the
    // installed data (ProgramData) or the machine needs admin, so a non-elevated caller re-runs
    // Argus elevated for that one step.
    static class Actions
    {
        public static int Run(string action, string alertId, string key, string undoId)
        {
            return Run(action, alertId, key, undoId, null);
        }

        public static int Run(string action, string alertId, string key, string undoId, string alertList)
        {
            return Run(action, alertId, key, undoId, alertList, null);
        }

        // digest: Engine.ReviewDigest of the entry as the window showed it (or null): keep and turn off act only on
        // exactly that state.
        public static int Run(string action, string alertId, string key, string undoId, string alertList, string digest)
        {
            System.Threading.Mutex scan;
            if (!Sync.Claim("argus.scan", out scan)) return 2;
            using (scan)
            {
                try { return RunLocked(action, alertId, key, undoId, alertList, digest); }
                finally { scan.ReleaseMutex(); }
            }
        }

        // Exit code when the alert or row you acted on was already handled (a scan kept or replaced it).
        public const int Superseded = 3;
        // Exit code when the entry is no longer exactly as you reviewed it (saved or registered); nothing changed.
        public const int ChangedSinceReview = 4;

        static readonly System.Text.RegularExpressions.Regex DigestShape = new System.Text.RegularExpressions.Regex(@"\A[0-9a-fA-F]{64}\z");
        internal static bool ValidDigest(string digest) { return digest == null || DigestShape.IsMatch(digest); }

        static int RunLocked(string action, string alertId, string key, string undoId, string alertList, string digest)
        {
            if ((alertId != null && !ArgusAlertReview.IsAlertId(alertId)) || !ValidList(alertList) || !ValidDigest(digest))
            {
                Log.Warn(action + ": not a valid alert ID; nothing changed");
                return 1;
            }
            var data = ArgusData.Load(Suite.MyDir);
            if (!data.Readable)
            {
                Log.Warn(action + ": couldn't read " + string.Join(", ", data.Unreadable) + "; nothing changed");
                return 1;
            }
            var previous = ArgusAlertReview.PendingIds(data.Pending.Values);
            if (alertId != null)
            {
                string currentId;
                if (key != null)
                {
                    // From Argus's window: that row's finding must still be the open one (checked against the
                    // protected pending list, so it works even after the alert log has moved on).
                    if (!previous.TryGetValue(key, out currentId) || currentId != alertId)
                    {
                        Log.Info(action + ": the finding for " + key + " was already handled; nothing changed");
                        return Superseded;
                    }
                }
                else
                {
                    // From an alert in the hub: find its entry, which must still be the open finding.
                    var al = AlertStore.FindForAction(AppId.Argus, alertId, action);
                    string alertKey = al == null ? null : al.Get("key");
                    if (alertKey == null || !previous.TryGetValue(alertKey, out currentId) || currentId != alertId)
                    {
                        Log.Info(action + ": alert " + alertId + " is no longer the open finding; nothing changed");
                        return Superseded;
                    }
                    key = alertKey;
                }
            }
            switch (action)
            {
                case "accept":
                {
                    if (key == null) return 1;
                    if (!Engine.MatchesReview(Engine.Find(data, key), digest))
                    {
                        Log.Info("accept: " + key + " changed since it was reviewed; nothing changed");
                        return ChangedSinceReview;
                    }
                    string err = Engine.Accept(data, key);
                    if (err != null) { Log.Warn(err); return 1; }
                    break;
                }
                case "accept-all":
                    foreach (var k in data.Pending.Keys.ToList()) Engine.Accept(data, k);
                    break;
                case "accept-visible":
                    foreach (var finding in data.VisibleFindings()) Engine.Accept(data, finding.Key);
                    break;
                case "accept-listed":
                {
                    // Exactly the findings you saw listed (their alert IDs); any a scan has kept or replaced since
                    // are left alone.
                    var wanted = new HashSet<string>((alertList ?? "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);
                    var keys = previous.Where(kv => kv.Value != null && wanted.Contains(kv.Value)).Select(kv => kv.Key).ToList();
                    foreach (var k in keys) Engine.Accept(data, k);
                    if (keys.Count < wanted.Count) Log.Info("accept-listed: " + (wanted.Count - keys.Count) + " of the listed changes were already handled");
                    if (keys.Count == 0) return wanted.Count == 0 ? 1 : Superseded;
                    break;
                }
                case "disable":
                {
                    if (key == null) return 1;
                    var it = Engine.Find(data, key);
                    if (it == null || !Engine.CanTurnOff(it)) { Log.Warn("disable: " + key + " can't be turned off"); return 1; }
                    try { Engine.TurnOff(data, key, digest); }
                    catch (Engine.ChangedSinceReview)
                    {
                        Log.Info("disable: " + key + " changed since it was reviewed; nothing changed");
                        return ChangedSinceReview;
                    }
                    break;
                }
                case "undo":
                {
                    var u = data.Undo.FirstOrDefault(x => x.Id == undoId);
                    if (u == null) return 1;
                    Engine.Undo(data, u);
                    break;
                }
                default:
                    Log.Warn("unknown action " + action);
                    return 1;
            }
            // Your decision is saved first; if recording the closed alert IDs then fails, the hub may keep
            // showing an alert whose finding is gone, and acting on it just reports that it was handled. An Undo
            // is marked done only after the baseline it restored is saved (it can run again until then).
            data.Save(action == "undo");
            try { Engine.RecordClosedAlerts(data, previous); }
            catch (Exception e) { Log.Warn("recording closed alerts: " + e.Message); }
            Engine.RefreshStatus(data);
            Sync.Poke(AlertReview.ChangedSignal);
            return 0;
        }

        // A list of alert IDs ("id,id,..."), each exactly 16 hex digits, or no list at all.
        internal static bool ValidList(string alertList)
        {
            return alertList == null || alertList.Split(',').All(ArgusAlertReview.IsAlertId);
        }

        static bool Mine(string location)
        {
            if (string.IsNullOrEmpty(location)) return false;
            return location.StartsWith("HKU\\" + Suite.User.Sid + "\\", StringComparison.OrdinalIgnoreCase)
                || location.StartsWith(Suite.User.Profile + "\\", StringComparison.OrdinalIgnoreCase);
        }

        static bool NeedsAdmin(string action, string key, string undoId, ArgusData data)
        {
            if (Elevation.IsElevated) return false;
            if (Suite.Installed) return true;                       // the data lives in ProgramData
            if (action == "disable")
            {
                var it = key == null ? null : Engine.Find(data, key);
                return it == null || !(Mine(it.Location) || (it.Category == "startup" && Mine(it.X("file"))));
            }
            if (action == "undo")
            {
                var u = data.Undo.FirstOrDefault(x => x.Id == undoId);
                return u == null || !(Mine(u.D("location")) || Mine(u.D("file")));
            }
            return false;
        }

        // Returns null on success, else what went wrong. With alertId (a row on the To review tab), the
        // action only goes ahead while that exact finding is still the open one.
        public static string Do(string action, string key, string undoId)
        {
            return Do(action, key, undoId, null);
        }

        public static string Do(string action, string key, string undoId, string alertId)
        {
            return Do(action, key, undoId, alertId, null);
        }

        // alertList: for "accept-listed", the comma-separated alert IDs of the rows you saw.
        public static string Do(string action, string key, string undoId, string alertId, string alertList)
        {
            return Do(action, key, undoId, alertId, alertList, null);
        }

        // digest: Engine.ReviewDigest of the entry as you saw it, taken before any question (or null).
        public static string Do(string action, string key, string undoId, string alertId, string alertList, string digest)
        {
            const string handled = "Argus had already dealt with this change (a newer scan kept or replaced it), so nothing was changed. The list is up to date now.";
            const string changed = "That entry changed since Argus showed it to you, so nothing was changed. The list shows it as it is now (or will after the next scan, within 5 minutes).";
            // Only well-formed IDs and digests reach the command line of an elevated Argus.
            if ((alertId != null && !ArgusAlertReview.IsAlertId(alertId)) || !ValidList(alertList) || !ValidDigest(digest)) return "That change can't be identified, so nothing was changed.";
            var data = ArgusData.Load(Suite.MyDir);
            if (NeedsAdmin(action, key, undoId, data))
            {
                string args = "--action " + action + (key != null ? " --key " + Proc.Quote(key) : "") + (undoId != null ? " --undo " + undoId : "")
                            + (alertId != null ? " --alert " + alertId : "") + (alertList != null ? " --alerts " + alertList : "")
                            + (digest != null ? " --digest " + digest : "");
                int r = Elevation.Run(Suite.ExeOf(AppId.Argus), args, true);
                if (r == -1) return "Cancelled: Windows asked for admin rights and the request was declined.";
                if (r == Superseded) return handled;
                if (r == ChangedSinceReview) return changed;
                return r == 0 ? null : "That didn't work (code " + r + "); Argus's log has the details.";
            }
            try
            {
                int code = Run(action, alertId, key, undoId, alertList, digest);
                return code == 0 ? null : code == Superseded ? handled : code == ChangedSinceReview ? changed : "That didn't work; Argus's log has the details.";
            }
            catch (Exception e) { Log.Error(action + " " + key, e); return e.Message; }
        }
    }

    static class ArgusCli
    {
        const string Help =
            "Argus hijack watcher - commands:\n" +
            "  Argus.exe                 open the review window\n" +
            "  Argus.exe status          how things stand, entries per kind\n" +
            "  Argus.exe scan            scan now and compare with what you've accepted\n" +
            "  Argus.exe pending         changes waiting for review\n" +
            "  Argus.exe list [KIND]     everything Argus watches (kinds: run, task, service, driver, extension, ...)\n" +
            "  Argus.exe accept KEY|all  keep a change (or all of them)\n" +
            "  Argus.exe --scan          what the scheduled task runs every 5 minutes (as SYSTEM)\n" +
            "From PowerShell, add | Out-String so the output waits for the command.";

        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "status":
                {
                    string from;
                    var st = ArgusAlertReview.ReadDisplayStatus(out from);
                    var data = ArgusData.Load(from);
                    var visible = data.VisibleFindings();
                    if (!data.PendingReadable) Cli.Out("Argus: can't read the list of changes right now (" + string.Join(", ", data.Unreadable) + ")");
                    else if (st == null && visible.Count == 0) Cli.Out("Argus: hasn't scanned yet");
                    else
                    {
                        var shown = st ?? new StatusInfo { State = States.Ok, Summary = "" };
                        ArgusAlertReview.ApplyFindings(shown, visible);
                        Cli.Out("Argus: " + shown.State + " - " + shown.Summary);
                    }
                    if (st != null) Cli.Out("       " + st.Detail);
                    Cli.Out("Data: " + data.Dir);
                    Cli.Out("");
                    var rows = new List<string[]> { new[] { "KIND", "ENTRIES", "UNSIGNED", "TURNED OFF" } };
                    foreach (var g in data.Current.GroupBy(i => i.Category).OrderBy(g => g.Key))
                        rows.Add(new[] { Engine.Plural(g.Key), g.Count().ToString(), g.Count(i => i.Target != null && !i.Signed && !i.Missing).ToString(), g.Count(i => !i.Enabled).ToString() });
                    Cli.Table(rows);
                    return 0;
                }
                case "scan":
                {
                    var r = Engine.Scan();
                    if (r == null) { Cli.Out("A scan is already running."); return 2; }
                    Cli.Out((r.First ? "First scan: baseline of " : "Scanned ") + r.Entries.ToString("N0") + " entries in " + (int)r.Took.TotalSeconds + " s" +
                            (r.First ? "" : ": " + r.Fresh + " to review, " + r.Auto + " accepted automatically, " + r.Removed + " gone") + ".");
                    if (!Elevation.IsElevated) Cli.Out("(Not running as admin: some areas, like other accounts and WMI, aren't visible.)");
                    foreach (var p in r.Problems) Cli.Out("  couldn't read " + p);
                    return Pending();
                }
                case "pending": return Pending();
                case "list":
                {
                    var data = ArgusData.ForDisplay();
                    string kind = a[1];
                    foreach (var it in data.Current.Where(i => kind == null || i.Category.Equals(kind, StringComparison.OrdinalIgnoreCase)))
                        Cli.Out(it.Category.PadRight(11) + " " + Fmt.Clip(it.Name, 40).PadRight(41) + " " + it.SignedBy.PadRight(28) + " " + Fmt.Clip(it.Command, 90));
                    return 0;
                }
                case "accept":
                {
                    if (a[1] == null) { Cli.Out("accept KEY or accept all"); return 1; }
                    string err = a[1] == "all" ? Actions.Do("accept-all", null, null) : Actions.Do("accept", a.Rest(1), null);
                    Cli.Out(err ?? "Done.");
                    return err == null ? 0 : 1;
                }
                default:
                    Cli.Out(Help);
                    return 0;
            }
        }

        static int Pending()
        {
            var data = ArgusData.ForDisplay();
            var findings = data.VisibleFindings();
            if (findings.Count == 0) { Cli.Out("Nothing to review."); return 0; }
            foreach (var f in findings.OrderByDescending(x => Sev.Rank(x.Severity)))
            {
                Cli.Out("[" + f.Severity + "] " + f.Kind + " " + Engine.Noun(f.Now.Category) + ": " + f.Now.Name);
                if (!string.IsNullOrEmpty(f.Why)) Cli.Out("    why:  " + f.Why);
                Cli.Out("    runs: " + Fmt.Clip(f.Now.Command, 140));
                Cli.Out("    key:  " + f.Key);
            }
            return 0;
        }
    }
}
