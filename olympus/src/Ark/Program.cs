// Ark.exe: --backup (the hourly scheduled task), --backup-now (from the hub or the window),
// the command line, alert actions, and the restore window.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Ark
{
    static class Program
    {
        static bool IsCli(string a)
        {
            switch (a) { case "status": case "list": case "backup": case "prune": case "help": case "--help": case "/?": return true; default: return false; }
        }

        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool headless = a.Has("--backup") || a.Has("--backup-now") || a.Has("--action") || IsCli(first);
            AppStart.Init(AppId.Ark, !headless);
            try
            {
                if (a.Has("--backup")) return Job.Run(false, null, null);
                if (a.Has("--backup-now")) return BackupNow();
                if (a.Has("--action")) return DoAction(a.Opt("--action"));
                if (IsCli(first)) { Cli.Attach(); return ArkCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new ArkWindow());
            }
            catch (Exception e)
            {
                Log.Error("Ark failed", e);
                if (headless) { Cli.Attach(); Cli.Out("Error: " + e.Message); }
                return 1;
            }
        }

        // From the hub or the window: once installed, the SYSTEM task does the work (your account
        // can only read the backup drive); the flag tells it to back up every set, not just due ones.
        public static int BackupNow()
        {
            if (Suite.Installed && !Elevation.IsElevated)
            {
                try { Directory.CreateDirectory(Path.GetDirectoryName(Job.ForceFlag)); File.WriteAllText(Job.ForceFlag, Clock.NowIso()); } catch (Exception) { }
                string output;
                int code = Proc.Run("schtasks.exe", "/run /tn \"\\Olympus\\Ark\"", out output, 20000);
                if (code == 0) return 0;
                Log.Warn("couldn't start the Ark task (" + code + "): " + output.Trim());
            }
            return Job.Run(true, null, null);
        }

        static int DoAction(string action)
        {
            switch (action)
            {
                case "retry":
                    Proc.Start(Suite.ExeOf(AppId.Ark), "--backup-now");
                    return 0;
                default:
                    Log.Warn("unknown action " + action);
                    return 1;
            }
        }
    }

    static class ArkCli
    {
        const string Help =
            "Ark versioned backups - commands:\n" +
            "  Ark.exe                    open the restore window\n" +
            "  Ark.exe status             last backup of every folder, and what's next\n" +
            "  Ark.exe list [SET]         the snapshots kept for each folder\n" +
            "  Ark.exe backup [SET]       back up now (every folder, or just SET), showing progress\n" +
            "  Ark.exe prune --dry-run    which old snapshots retention would remove\n" +
            "  Ark.exe --backup           what the hourly task runs (only folders that are due)\n" +
            "Settings: " + "ark.ini in ProgramData\\Olympus\\ark once installed (your profile before that).\n" +
            "From PowerShell, add | Out-String so the output waits for the command.";

        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "status": return Status();
                case "list": return List(a[1]);
                case "backup":
                {
                    string only = a[1] != null && !a[1].StartsWith("--") ? a[1] : null;
                    int r = Job.Run(true, only, s => Cli.Out("  " + s));
                    Status();
                    return r;
                }
                case "prune":
                {
                    var cfg = ArkConfig.Load();
                    foreach (var set in cfg.Sets)
                    {
                        string dir = Snapshots.SetDir(cfg.Target, set);
                        var del = Snapshots.PlanRetention(dir, cfg, DateTime.Now);
                        Cli.Out(set.Name + ": " + (del.Count == 0 ? "nothing to remove" : "would remove " + string.Join(", ", del)));
                    }
                    return 0;
                }
                default:
                    Cli.Out(Help);
                    return 0;
            }
        }

        static int Status()
        {
            var cfg = ArkConfig.LoadForDisplay();
            var st = StatusStore.Read(AppId.Ark);
            Cli.Out("Ark: " + (st == null ? "no backups yet" : st.State + " - " + st.Summary));
            if (st != null && !string.IsNullOrEmpty(st.Detail)) Cli.Out("     " + st.Detail);
            Cli.Out("Settings: " + cfg.FilePath);
            Cli.Out("");
            var state = ArkState.Load(File.Exists(ArkState.PathIn(Suite.SharedDir(AppId.Ark))) ? Suite.SharedDir(AppId.Ark) : Suite.UserDir(AppId.Ark));
            var rows = new List<string[]> { new[] { "FOLDER", "EVERY", "LAST COMPLETE", "FILES", "COPIED", "SNAPSHOTS", "SOURCE" } };
            foreach (var set in cfg.Sets)
            {
                var ss = state.For(set.Name);
                string dir = Snapshots.SetDir(cfg.Target, set);
                ss.RecoverLastSuccess(dir);
                int count = Snapshots.List(dir).Count;
                string warning = ss.LastError != null ? "  (failed: " + ss.LastError + ")" :
                    ss.LastErrors > 0 ? "  (incomplete with " + Fmt.Plural(ss.LastErrors, "error") + ")" : "";
                rows.Add(new[] { set.Name, Fmt.Duration(set.Every), ss.LastSuccess == null ? "never" : Fmt.Ago(Clock.Parse(ss.LastSuccess)),
                    ss.LastFiles.ToString("N0"), Fmt.Size(ss.LastCopiedBytes), count.ToString(), set.Path + warning });
            }
            Cli.Table(rows);
            return 0;
        }

        static int List(string only)
        {
            var cfg = ArkConfig.LoadForDisplay();
            foreach (var set in cfg.Sets)
            {
                if (only != null && !set.Name.Equals(only, StringComparison.OrdinalIgnoreCase)) continue;
                string dir = Snapshots.SetDir(cfg.Target, set);
                Cli.Out(set.Name + "  (" + dir + ")");
                foreach (var name in Snapshots.List(dir).AsEnumerable().Reverse())
                {
                    var s = Snapshots.Summary(dir, name);
                    Cli.Out("  " + name + (s == null ? "" : "   " + s.Files.ToString("N0") + " files, " + s.Copied + " copied (" + Fmt.Size(s.CopiedBytes) + ")" + (s.Errors > 0 ? ", " + s.Errors + " errors" : "")));
                }
            }
            return 0;
        }
    }
}
