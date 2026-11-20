// Atlas.exe: the window, --watch (drive space, kept running by the hub), the command line, and the
// two jobs it runs elevated when you ask (a complete scan, cleaning Windows' own folders).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Olympus.Atlas
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "status" || first == "scan" || first == "junk" || first == "clean" || first == "help" || first == "--help" || first == "/?";
            bool headless = cli || a.Has("--watch") || a.Has("--stop") || a.Has("--clean-admin") || a.Has("--map-admin");
            AppStart.Init(AppId.Atlas, !headless);
            try
            {
                if (a.Has("--watch")) return Watcher.Run();
                if (a.Has("--stop")) { Sync.Poke("atlas.stop"); return 0; }
                if (a.Has("--clean-admin")) return Elevated.Clean(a.Opt("--clean-admin"), a.Opt("--out"));
                if (a.Has("--map-admin")) return Elevated.Map(a.Opt("--map-admin"), a.Opt("--out"));
                if (cli) { Cli.Attach(); return AtlasCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new AtlasWindow());
            }
            catch (Exception e)
            {
                Log.Error("Atlas failed", e);
                return 1;
            }
        }
    }

    // What runs after a UAC prompt you accepted from Atlas's window.
    static class Elevated
    {
        // Results only go into Atlas's own folder.
        static bool Inside(string path, string dir)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try { return Path.GetFullPath(path).StartsWith(Path.GetFullPath(dir).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
            catch (Exception) { return false; }
        }

        public static int Clean(string ids, string outFile)
        {
            if (!Elevation.IsElevated) return 2;
            if (!Inside(outFile, Suite.UserDir(AppId.Atlas))) return 3;
            var want = new HashSet<string>((ids ?? "").Split(','), StringComparer.OrdinalIgnoreCase);
            var results = new List<CleanResult>();
            foreach (var it in Catalog.AdminItems().Where(i => want.Contains(i.Id)))   // only Atlas's built-in list, never a file
            {
                var r = Cleaner.Clean(it);
                History.Add(r);
                results.Add(r);
            }
            J.Save(outFile, results);
            return 0;
        }

        public static int Map(string root, string outFile)
        {
            if (!Elevation.IsElevated) return 2;
            if (!Inside(outFile, MapFile.Dir)) return 3;
            if (!Privilege.EnableBackup()) Log.Warn("couldn't turn on the backup privilege; some folders may stay unreadable");
            var m = new Scanner().Run(root);
            MapFile.Save(m, outFile);
            Log.Info("complete scan of " + m.RootPath + ": " + Fmt.Size(m.Root.Size) + " in " + m.Root.Files.ToString("N0") + " files, " + m.DeniedDirs + " folders unreadable, " + Fmt.Duration(m.Took));
            return 0;
        }
    }

    static class AtlasCli
    {
        const string Help =
            "Atlas disk space map - commands:\n" +
            "  Atlas.exe                    open the window\n" +
            "  Atlas.exe status             free space on each drive, junk to clean, saved maps\n" +
            "  Atlas.exe scan [PATH] [N]    map a drive or folder (default C:) and list the N biggest things (15)\n" +
            "  Atlas.exe junk               what the Clean up tab finds\n" +
            "  Atlas.exe clean ID,ID --yes  clean those items (IDs from \"junk\"; without --yes it only shows them)\n" +
            "  Atlas.exe --watch            watch drive space (the hub keeps this running)\n" +
            "  Atlas.exe --stop             stop the watcher\n" +
            "From PowerShell, add | Out-String so the output waits for the command.";

        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "status": return Status();
                case "scan": return Scan(a);
                case "junk": return Junk();
                case "clean": return Clean(a);
                default: Cli.Out(Help); return 0;
            }
        }

        static int Status()
        {
            var s = AtlasSettings.Load();
            var rows = new List<string[]> { new[] { "DRIVE", "LABEL", "FREE", "SIZE", "STATE", "MAPPED" } };
            foreach (var d in DriveWatch.Fixed(s, true))
            {
                int lv = DriveWatch.Level(d.Free, d.Total, 0, s.WarnPercent);
                string file = MapFile.PathFor(d.Root);
                rows.Add(new[] { d.Root, d.Label, Fmt.Size(d.Free), Fmt.Size(d.Total), lv == 2 ? "NEARLY FULL" : lv == 1 ? "getting full" : "ok",
                                 File.Exists(file) ? Fmt.Ago(File.GetLastWriteTimeUtc(file)) : "-" });
            }
            Cli.Table(rows);
            var junk = J.Load<JunkReport>(Watcher.JunkFile);
            if (junk != null) Cli.Out("Junk ticked by default: " + Fmt.Size(junk.Bytes) + " (measured " + Fmt.Ago(Clock.Parse(junk.Measured)) + ")");
            var st = StatusStore.Read(AppId.Atlas);
            if (st != null) Cli.Out("Watcher: " + st.Summary + " (reported " + Fmt.Ago(st.UpdatedUtc) + ")");
            return 0;
        }

        static int Scan(Args a)
        {
            string root = a[1] ?? @"C:\";
            int n;
            if (!int.TryParse(a[2] ?? "15", out n) || n <= 0) n = 15;
            var m = new Scanner().Run(root);
            try { MapFile.Save(m, MapFile.PathFor(m.RootPath)); } catch (Exception e) { Log.Error("saving the map", e); }
            Cli.Out(m.RootPath + ": " + Fmt.Size(m.Root.Size) + " in " + m.Root.Files.ToString("N0") + " files and " + m.Root.Dirs.ToString("N0") + " folders, mapped in " + Fmt.Duration(m.Took) +
                    (m.DeniedDirs > 0 ? "; " + m.DeniedDirs.ToString("N0") + " folders need admin" : "") + (m.Unseen > 0 ? "; " + Fmt.Size(m.Unseen) + " hidden from Atlas" : ""));
            Cli.Out("");
            Cli.Out("Biggest folders and files at the top:");
            if (m.Root.Kids != null)
                foreach (var k in m.Root.Kids.Take(n))
                    Cli.Out("  " + Fmt.Size(k.Size).PadLeft(9) + "  " + k.Name + (k.IsDir ? "\\" : ""));
            Cli.Out("");
            Cli.Out("Where the space is (folders spread over many things):");
            foreach (var h in Hotspots(m, n)) Cli.Out("  " + Fmt.Size(h.Size).PadLeft(9) + "  " + h.FullPath);
            Cli.Out("");
            Cli.Out("Biggest files:");
            foreach (var f in Files(m.Root).OrderByDescending(x => x.Size).Take(n)) Cli.Out("  " + Fmt.Size(f.Size).PadLeft(9) + "  " + f.FullPath);
            return 0;
        }

        public static IEnumerable<Node> Files(Node root)
        {
            var stack = new Stack<Node>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                var x = stack.Pop();
                if (x.Kids == null) continue;
                foreach (var k in x.Kids)
                {
                    if (k.IsDir) stack.Push(k);
                    else yield return k;
                }
            }
        }

        // Folders holding at least 1% of the total where no single thing inside holds most of it:
        // where the space actually sits.
        public static List<Node> Hotspots(MapInfo m, int n)
        {
            var found = new List<Node>();
            long floor = Math.Max(1, m.Root.Size / 100);
            var stack = new Stack<Node>();
            stack.Push(m.Root);
            while (stack.Count > 0)
            {
                var x = stack.Pop();
                if (x.Size < floor || x.Kids == null) continue;
                var big = x.Kids[0];
                if (big.Size * 10 >= x.Size * 6) { if (big.IsDir) stack.Push(big); continue; }
                found.Add(x);
                foreach (var k in x.Kids) if (k.IsDir && k.Size >= floor) stack.Push(k);
            }
            return found.Where(x => x != m.Root).OrderByDescending(x => x.Size).Take(n).ToList();
        }

        static int Junk()
        {
            var rows = new List<string[]> { new[] { "ID", "SIZE", "FILES", "TICKED", "WHAT" } };
            foreach (var it in Catalog.Load())
            {
                Cleaner.Measure(it);
                if (!it.Exists && !it.Admin) continue;
                rows.Add(new[] { it.Id, it.Unreadable ? "(admin)" : Fmt.Size(it.Bytes) + (it.Partial ? "+" : ""), it.Count.ToString("N0"), it.Default ? "yes" : "",
                                 it.Name + (it.Blocked != null ? " - " + it.Blocked : "") });
            }
            Cli.Table(rows);
            return 0;
        }

        static int Clean(Args a)
        {
            var ids = new HashSet<string>((a[1] ?? "").Split(','), StringComparer.OrdinalIgnoreCase);
            var list = Catalog.Load().Where(i => ids.Contains(i.Id)).ToList();
            if (list.Count == 0) { Cli.Out("No such items; \"Atlas.exe junk\" lists them."); return 1; }
            bool yes = a.Has("--yes");
            foreach (var it in list)
            {
                Cleaner.Measure(it);
                if (!yes) { Cli.Out("would clean " + it.Id + ": " + Fmt.Size(it.Bytes) + " in " + it.Count.ToString("N0") + " files (add --yes)"); continue; }
                if (it.Admin && !Elevation.IsElevated) { Cli.Out(it.Id + ": needs admin rights; skipped"); continue; }
                var r = Cleaner.Clean(it);
                History.Add(r);
                Cli.Out(it.Id + ": freed " + Fmt.Size(r.Freed) + " (" + r.Files.ToString("N0") + " files" + (r.Failed > 0 ? ", " + r.Failed + " in use" : "") + ")" + (r.Note != null ? " - " + r.Note : ""));
            }
            return 0;
        }
    }
}
