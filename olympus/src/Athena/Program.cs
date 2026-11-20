// Athena.exe: --report (runs the checks as you; the hub does this daily), --collect (the SYSTEM
// task's admin-only facts), fix actions, the command line, and the report-card window.
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Olympus.Athena
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "report" || first == "show" || first == "help" || first == "--help" || first == "/?";
            bool headless = cli || a.Has("--collect") || a.Has("--report") || a.Has("--action");
            AppStart.Init(AppId.Athena, !headless);
            try
            {
                if (a.Has("--collect")) return CollectNow();
                if (a.Has("--report")) { Reporter.Run(true, null); return 0; }
                if (a.Has("--action")) return Fixes.Run(a.Opt("--action"));
                if (cli) { Cli.Attach(); return AthenaCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new AthenaWindow());
            }
            catch (Exception e)
            {
                Log.Error("Athena failed", e);
                return 1;
            }
        }

        static int CollectNow()
        {
            var facts = Checks.Collect();
            J.Save(Path.Combine(Suite.MyDir, "admin-facts.json"), facts);
            Log.Info("admin facts collected" + (Elevation.IsElevated ? "" : " (not elevated: partial)"));
            return 0;
        }
    }

    static class Reporter
    {
        public static string ReportFile { get { return Path.Combine(Suite.UserDir(AppId.Athena), "report.json"); } }
        static readonly HashSet<string> Core = new HashSet<string> { "defender", "firewall", "aegis", "uac", "signatures", "smb1" };

        static int Rank(string s) { return s == "good" ? 0 : s == "warn" ? 1 : s == "bad" ? 2 : -1; }

        public static Report Run(bool network, Action<string> progress)
        {
            var prev = J.Load<Report>(ReportFile);
            StatusStore.Write(States.Busy, "Checking your PC…", null, null);
            var r = Checks.Run(prev, network, progress);
            J.Save(ReportFile, r);
            if (prev != null)
            {
                foreach (var c in r.Checks)
                {
                    var before = prev.Checks.FirstOrDefault(x => x.Id == c.Id);
                    if (before == null || Rank(c.State) < 0 || Rank(before.State) < 0 || Rank(c.State) <= Rank(before.State)) continue;
                    var a = AlertStore.New(c.State == "bad" && Core.Contains(c.Id) ? Sev.Critical : Sev.Warning, c.Name + ": " + (c.State == "bad" ? "needs fixing" : "slipped"), c.Detail + (c.Fix != null ? "\n" + c.Fix : ""), "regress:" + c.Id);
                    AlertStore.Raise(a);
                }
            }
            var issues = r.Checks.Where(c => c.State == "warn" || c.State == "bad").ToList();
            string summary = "Grade " + r.Grade + " (" + r.Percent + "%)" + (issues.Count > 0 ? " · " + Fmt.Plural(issues.Count, "thing") + " to improve" : " · nothing to fix");
            string detail = issues.Count == 0 ? "Checked " + DateTime.Now.ToString("MMM d, h:mm tt") : string.Join(", ", issues.OrderByDescending(c => Rank(c.State)).Take(4).Select(c => c.Name));
            StatusStore.Write(r.Grade == "A" || r.Grade == "B" ? States.Ok : r.Grade == "C" ? States.Warn : States.Alert, summary, detail, new Dictionary<string, object> { { "grade", r.Grade }, { "percent", r.Percent } });
            return r;
        }
    }

    // Fixes that change Defender settings: only ever run because you clicked them (elevated).
    static class Fixes
    {
        static int PowerShell(string command)
        {
            string o;
            int code = Proc.Run("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + command.Replace("\"", "\\\"") + "\"", out o, 120000);
            if (code != 0) Log.Warn("powershell: " + o.Trim());
            return code;
        }

        public static int Run(string action)
        {
            if (action == "asr-audit" || action == "asr-enforce")
            {
                if (!Elevation.IsElevated) return Elevation.Run(Suite.ExeOf(AppId.Athena), "--action " + action, true) == 0 ? 0 : 1;
                string err;
                var current = Asr.Current(out err);
                if (action == "asr-audit")
                {
                    var add = Asr.Recommended.Where(x => !current.ContainsKey(x[0])).ToList();
                    if (add.Count == 0) return 0;
                    int code = PowerShell("Add-MpPreference -AttackSurfaceReductionRules_Ids " + string.Join(",", add.Select(x => x[0])) + " -AttackSurfaceReductionRules_Actions " + string.Join(",", add.Select(x => "AuditMode")));
                    Log.Info("ASR: " + add.Count + " rules added in audit mode (exit " + code + ")");
                    if (code == 0)
                        AlertStore.Raise(AlertStore.New(Sev.Info, add.Count + " Defender rules are now in watch-only mode", "They only log what they would have blocked. In a week, Athena can turn on the ones that never got in your way.", "asr-audit"));
                    return code == 0 ? 0 : 1;
                }
                // enforce: audited rules that flagged nothing in the past week
                var hits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    var q = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, "*[System[(EventID=1122) and TimeCreated[timediff(@SystemTime) <= 604800000]]]");
                    using (var reader = new EventLogReader(q))
                    {
                        EventRecord e;
                        while ((e = reader.ReadEvent()) != null)
                            using (e)
                            {
                                var m = Regex.Match(e.ToXml(), @"<Data Name='ID'>\{?([0-9a-fA-F\-]{36})\}?</Data>");
                                if (m.Success) { int c; hits.TryGetValue(m.Groups[1].Value, out c); hits[m.Groups[1].Value] = c + 1; }
                            }
                    }
                }
                catch (Exception e) { Log.Warn("reading ASR events: " + e.Message); return 1; }
                var quiet = current.Where(kv => kv.Value == 2 && !hits.ContainsKey(kv.Key)).Select(kv => kv.Key).ToList();
                var noisy = current.Where(kv => kv.Value == 2 && hits.ContainsKey(kv.Key)).Select(kv => Asr.Recommended.Where(x => x[0].Equals(kv.Key, StringComparison.OrdinalIgnoreCase)).Select(x => x[1]).FirstOrDefault() ?? kv.Key).ToList();
                if (quiet.Count == 0) return 0;
                int rc = PowerShell("Add-MpPreference -AttackSurfaceReductionRules_Ids " + string.Join(",", quiet) + " -AttackSurfaceReductionRules_Actions " + string.Join(",", quiet.Select(x => "Enabled")));
                if (rc == 0)
                    AlertStore.Raise(AlertStore.New(Sev.Info, quiet.Count + " Defender rules switched on", noisy.Count == 0 ? "None of them flagged anything during the trial." : "Left in watch-only mode because they flagged programs this week: " + string.Join(", ", noisy) + ".", "asr-enforce"));
                return rc == 0 ? 0 : 1;
            }
            if (action != null && action.StartsWith("open:")) { Proc.Open(action.Substring(5)); return 0; }
            return 1;
        }
    }

    static class AthenaCli
    {
        static string Mark(string s) { return s == "good" ? "OK  " : s == "warn" ? "WARN" : s == "bad" ? "BAD " : s == "info" ? "info" : " ?  "; }

        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "report":
                {
                    var r = Reporter.Run(!a.Has("--no-network"), s => Console.Error.WriteLine("  checking " + s + "..."));
                    return Print(r);
                }
                case "show":
                {
                    var r = J.Load<Report>(Reporter.ReportFile);
                    if (r == null) { Cli.Out("No report yet: run Athena.exe report"); return 1; }
                    return Print(r);
                }
                default:
                    Cli.Out("Athena security report card - commands:\n  Athena.exe            open the report card\n  Athena.exe report     check everything now and print the report (add --no-network to skip the network scans)\n  Athena.exe show       print the last report\n  Athena.exe --collect  what the daily SYSTEM task runs (admin-only facts)\nFrom PowerShell, add | Out-String so the output waits for the command.");
                    return 0;
            }
        }

        static int Print(Report r)
        {
            Cli.Out("Grade " + r.Grade + " (" + r.Percent + "%), checked " + Fmt.Local(Clock.Parse(r.Time)));
            foreach (var g in r.Checks.GroupBy(c => c.Group))
            {
                Cli.Out("");
                Cli.Out(g.Key);
                foreach (var c in g)
                {
                    Cli.Out("  " + Mark(c.State) + " " + c.Name + ": " + c.Detail);
                    foreach (var i in c.Items.Take(12)) Cli.Out("         " + i);
                }
            }
            return 0;
        }
    }
}
