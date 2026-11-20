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
                if (a.Has("--action")) return Actions.Run(a.Opt("--action"), a.Opt("--alert"), a.Opt("--key"), a.Opt("--undo"));
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
            if (key == null && alertId != null)
            {
                var al = AlertStore.FindForAction(AppId.Argus, alertId, action);
                if (al != null) key = al.Get("key");
            }
            var data = ArgusData.Load(Suite.MyDir);
            switch (action)
            {
                case "accept":
                {
                    if (key == null) return 1;
                    string err = Engine.Accept(data, key);
                    if (err != null) { Log.Warn(err); return 1; }
                    break;
                }
                case "accept-all":
                    foreach (var k in data.Pending.Keys.ToList()) Engine.Accept(data, k);
                    break;
                case "disable":
                    if (key == null) return 1;
                    Engine.TurnOff(data, key);
                    break;
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
            data.Save();
            Engine.RefreshStatus(data);
            return 0;
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

        // Returns null on success, else what went wrong.
        public static string Do(string action, string key, string undoId)
        {
            var data = ArgusData.Load(Suite.MyDir);
            if (NeedsAdmin(action, key, undoId, data))
            {
                string args = "--action " + action + (key != null ? " --key " + Proc.Quote(key) : "") + (undoId != null ? " --undo " + undoId : "");
                int r = Elevation.Run(Suite.ExeOf(AppId.Argus), args, true);
                if (r == -1) return "Cancelled: Windows asked for admin rights and the request was declined.";
                return r == 0 ? null : "That didn't work (code " + r + "); Argus's log has the details.";
            }
            try { return Run(action, null, key, undoId) == 0 ? null : "That didn't work; Argus's log has the details."; }
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
                    var st = StatusStore.Read(AppId.Argus);
                    Cli.Out("Argus: " + (st == null ? "hasn't scanned yet" : st.State + " - " + st.Summary));
                    if (st != null) Cli.Out("       " + st.Detail);
                    var data = ArgusData.ForDisplay();
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
            if (data.Pending.Count == 0) { Cli.Out("Nothing to review."); return 0; }
            foreach (var f in data.Pending.Values.OrderByDescending(x => Sev.Rank(x.Severity)))
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
