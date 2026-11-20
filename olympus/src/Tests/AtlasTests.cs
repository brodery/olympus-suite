// Tests for Atlas: the treemap layout, file kinds, drive-space levels, the scanner (on a temp folder:
// hard links count once, junctions aren't followed), saved maps, the cleanup list and cleaning
// (never through a junction), Steam's files, and the places Atlas refuses to touch.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using Olympus.Atlas;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class AtlasTests
    {
        public static void Run()
        {
            Layout();
            MapLayoutTest();
            KindsTest();
            Levels();
            ScanAndSave();
            CatalogTest();
            CleanTest();
            PermanentDeleteTest();
            SteamTest();
            SafetyTest();
        }

        static void Layout()
        {
            // the paper's example: 6,6,4,3,2,2,1 in a 6x4 rectangle (scaled up 100x)
            var sizes = new List<double> { 6, 6, 4, 3, 2, 2, 1 };
            var r = Squarify.Layout(sizes, new RectangleF(0, 0, 600, 400));
            T.True(Near(r[0], 0, 0, 300, 200) && Near(r[1], 0, 200, 300, 200), "treemap: first row is the two 6s on the left");
            T.True(Math.Abs(r[2].Width * r[2].Height - 40000) < 2 && r[2].Y < 0.5, "treemap: the 4 starts the next row at the top");
            double area = 0;
            for (int i = 0; i < r.Length; i++)
            {
                area += r[i].Width * r[i].Height;
                T.True(Math.Abs(r[i].Width * r[i].Height - sizes[i] * 10000) < 2, "treemap: block " + i + " has its share of the area");
                T.True(r[i].X >= -0.01 && r[i].Y >= -0.01 && r[i].Right <= 600.01 && r[i].Bottom <= 400.01, "treemap: block " + i + " stays inside");
                for (int j = 0; j < i; j++)
                {
                    var x = RectangleF.Intersect(r[i], r[j]);
                    T.True(x.Width * x.Height < 0.5, "treemap: blocks " + j + " and " + i + " don't overlap");
                }
            }
            T.True(Math.Abs(area - 240000) < 5, "treemap: the blocks fill the rectangle");
            T.Eq(0, Squarify.Layout(new List<double>(), new RectangleF(0, 0, 10, 10)).Length, "treemap: nothing to lay out");
            var zeros = Squarify.Layout(new List<double> { 5, 0 }, new RectangleF(0, 0, 10, 10));
            T.True(zeros[1].Width * zeros[1].Height == 0 && Math.Abs(zeros[0].Width * zeros[0].Height - 100) < 0.01, "treemap: an empty item gets no space");
        }

        static bool Near(RectangleF a, float x, float y, float w, float h)
        {
            return Math.Abs(a.X - x) < 0.5 && Math.Abs(a.Y - y) < 0.5 && Math.Abs(a.Width - w) < 0.5 && Math.Abs(a.Height - h) < 0.5;
        }

        const long MB = 1L << 20;

        // Little trees for the map layout tests; sizes and counts are filled in bottom-up.
        static Node TFile(string name, long size) { return new Node { Name = name, Kind = Kinds.Of(name), Size = size, Files = 1 }; }

        static Node TDir(string name, params Node[] kids)
        {
            var d = new Node { Name = name, Kind = Kinds.Folder };
            var list = kids.ToList();
            foreach (var k in list) k.Parent = d;
            list.Sort((a, b) => b.Size.CompareTo(a.Size));
            d.Kids = list.Count > 0 ? list.ToArray() : null;
            d.Size = list.Sum(k => k.Size);
            d.Files = list.Sum(k => k.Files);
            d.Dirs = list.Where(k => k.IsDir).Sum(k => 1 + k.Dirs);
            return d;
        }

        static Node Grow(Random rnd, string name, int depth)
        {
            var kids = new List<Node>();
            int n = rnd.Next(2, depth > 2 ? 8 : 40);
            for (int i = 0; i < n; i++)
            {
                if (depth < 4 && rnd.NextDouble() < 0.3) kids.Add(Grow(rnd, name + i, depth + 1));
                else kids.Add(TFile(name + "_" + i + (rnd.Next(3) == 0 ? ".pak" : ".bin"), (long)(Math.Pow(rnd.NextDouble(), 4) * 4000 * MB) + MB));
            }
            return TDir(name, kids.ToArray());
        }

        static MapLayout TestLayout() { return new MapLayout { MinArea = 121, MinOpen = 22, HeaderH = 17, Pad = 1.5f, HeaderMinW = 48 }; }

        static MapBlock Named(MapLayout l, string name) { return l.Blocks.FirstOrDefault(b => !b.Pseudo && b.Node.Name == name); }

        static void MapLayoutTest()
        {
            var L = TestLayout();

            // 400 files of 1 MB next to a 1000 MB one: each would get under 11x11 pixels
            var files = new List<Node> { TFile("big.bin", 1000 * MB) };
            for (int i = 0; i < 400; i++) files.Add(TFile("f" + i + ".txt", MB));
            var one = TDir(@"C:\t", files.ToArray());
            L.Build(new MapInfo { Root = one, RootPath = @"C:\t" }, one, new RectangleF(0, 0, 400, 300));
            var rest = L.Blocks.FirstOrDefault(b => b.Members != null);
            T.Eq(2, L.Blocks.Count, "map layout: tiny files fold into one block beside the big one");
            T.True(rest != null && rest.Count == 400 && rest.Files == 400 && rest.Size == 400 * MB && rest.Members.Count == 400, "map layout: the smaller-items block stands for all 400");
            var big = Named(L, "big.bin");
            T.True(big != null && L.At(new PointF(big.R.X + big.R.Width / 2, big.R.Y + big.R.Height / 2), 5) == big, "map layout: the block under a point");
            T.True(rest != null && L.Find(files[7]) == rest, "map layout: a file gathered into smaller items is found there");

            var sl = TDir("sl", TFile("big.bin", 1000 * MB), TFile("thin.bin", 4 * MB));
            L.Build(new MapInfo { Root = sl, RootPath = @"C:\sl" }, sl, new RectangleF(0, 0, 1000, 100));
            var thinB = Named(L, "thin.bin");
            T.True(thinB != null && thinB.R.Width < 6 && L.At(new PointF(thinB.R.X - 2, 50), 6) == thinB, "map layout: a sliver can be pointed at from just beside it");
            T.True(thinB != null && L.At(new PointF(thinB.R.X - 5, 50), 6) == Named(L, "big.bin"), "map layout: further away, its big neighbour wins");

            var lone = TDir("lone", TFile("big.bin", 1000 * MB), TFile("one.txt", MB));
            L.Build(new MapInfo { Root = lone, RootPath = @"C:\lone" }, lone, new RectangleF(0, 0, 400, 300));
            T.True(L.Blocks.Count == 2 && L.Blocks.All(b => b.Members == null), "map layout: a lone small file keeps its own block");

            // Program Files (x86) > Steam > steamapps > common, each nearly all of the one before
            var common = TDir("common", TDir("GameA", TFile("a.pak", 600 * MB), TFile("a2.pak", 300 * MB)),
                                        TDir("GameB", TFile("b.pak", 500 * MB), TFile("b2.pak", 100 * MB)));
            var pf = TDir("Program Files (x86)", TDir("Steam", TDir("steamapps", common, TFile("x.acf", MB)), TFile("steam.log", 5 * MB)), TFile("misc.dll", 8 * MB));
            var top = TDir("C:", pf, TFile("other.bin", 1500 * MB));
            L.Build(new MapInfo { Root = top, RootPath = @"C:\x" }, top, new RectangleF(0, 0, 1000, 600));
            var c = Named(L, "common");
            T.True(c != null && c.Header && c.Title == @"Program Files (x86)\Steam\steamapps\common", "map layout: a chain of one-folder folders shares one name strip");
            T.True(!Named(L, "Program Files (x86)").Header && !Named(L, "Steam").Header && !Named(L, "steamapps").Header, "map layout: the folders in the chain get no strip of their own");
            var a = Named(L, "GameA");
            T.True(a != null && a.Header && a.Title == "GameA" && a.Parent == c, "map layout: the folders inside keep their own strips");
            var apak = Named(L, "a.pak");
            T.True(apak != null && L.At(new PointF(apak.R.X + apak.R.Width / 2, apak.R.Y + apak.R.Height / 2), 5) == apak && apak.Parent == a, "map layout: the innermost block is the one under the pointer");

            var mods = TDir("mods", TFile("m.pak", MB), TFile("n.txt", MB / 4));
            var four = TDir("four", TFile("huge.bin", 999 * MB), mods);
            L.Build(new MapInfo { Root = four, RootPath = @"C:\four" }, four, new RectangleF(0, 0, 400, 300));
            var m = Named(L, "mods");
            T.True(m != null && m.Solid && m.Fill == Kinds.Game && !L.Blocks.Any(b => b.Parent == m), "map layout: a folder too small to open is drawn whole, in its main kind's colour");

            var many = TDir("many", Enumerable.Range(0, 60).Select(i => TFile("c" + i + ".pak", MB)).ToArray());
            var five = TDir("five", TFile("huge.bin", 900 * MB), many);
            L.Build(new MapInfo { Root = five, RootPath = @"C:\five" }, five, new RectangleF(0, 0, 400, 300));
            var mb = Named(L, "many");
            T.True(mb != null && mb.Solid && !L.Blocks.Any(b => b.Parent == mb), "map layout: a folder that would only show 'smaller items' is drawn whole");
            T.True(mb != null && L.Find(many.Kids[3]) == mb, "map layout: a file inside a folder drawn whole is found as that folder");

            // random trees: blocks stay inside their folder, never overlap, and at most one thing per
            // folder is smaller than the pointable minimum (a lone small item isn't folded)
            var rnd = new Random(7);
            bool inside = true, apart = true, pointable = true, filled = true;
            for (int round = 0; round < 6; round++)
            {
                var tree = Grow(rnd, "r" + round, 0);
                L.Build(new MapInfo { Root = tree, RootPath = @"C:\r" }, tree, new RectangleF(0, 0, 1000, 600));
                double topArea = 0;
                foreach (var g in L.Blocks.GroupBy(b => b.Parent))
                {
                    var kids = g.ToList();
                    if (g.Key == null) topArea = kids.Sum(b => (double)b.Area);
                    foreach (var b in kids)
                        if (g.Key != null && !RectangleF.Inflate(g.Key.R, 0.5f, 0.5f).Contains(b.R)) inside = false;
                    for (int i = 0; i < kids.Count; i++)
                        for (int j = 0; j < i; j++)
                        {
                            var x = RectangleF.Intersect(kids[i].R, kids[j].R);
                            if (x.Width * x.Height > 0.5f) apart = false;
                        }
                    if (kids.Count(b => !b.Pseudo && b.Area < L.MinArea * 0.99f) > 1) pointable = false;
                }
                if (Math.Abs(topArea - 600000) > 600) filled = false;
            }
            T.True(inside, "map layout: every block stays inside its folder");
            T.True(apart, "map layout: blocks in a folder never overlap");
            T.True(pointable, "map layout: at most one thing per folder is too small to point at");
            T.True(filled, "map layout: the top level fills the map");
        }

        static void KindsTest()
        {
            T.Eq(Kinds.Video, Kinds.Of("Clip.MP4"), "kinds: video, any case");
            T.Eq(Kinds.Exe, Kinds.Of("thing.dll"), "kinds: programs");
            T.Eq(Kinds.Game, Kinds.Of("pakchunk0-Windows.pak"), "kinds: game data");
            T.Eq(Kinds.Archive, Kinds.Of("backup.tar.gz"), "kinds: the last extension counts");
            T.Eq(Kinds.Other, Kinds.Of("README"), "kinds: no extension");
            T.Eq(Kinds.Other, Kinds.Of(".gitignore"), "kinds: a dot file has no extension");
            T.Eq(".pak", Kinds.Ext("A.PAK"), "kinds: extension in lower case");
            T.Eq("(none)", Kinds.Ext("Makefile"), "kinds: none");
        }

        static void Levels()
        {
            long gb = DriveWatch.GB, c = 1862 * gb, b = 224 * gb;
            T.Eq(100 * gb, DriveWatch.WarnBelow(c, 10), "space: a big drive warns at 100 GB, not 10%");
            T.Eq(b / 100 * 10, DriveWatch.WarnBelow(b, 10), "space: a smaller drive warns at 10%");
            T.Eq(10 * gb, DriveWatch.WarnBelow(60 * gb, 10), "space: never below 10 GB");
            T.Eq(25 * gb, DriveWatch.CriticalBelow(c), "space: nearly full at 25 GB on a big drive");
            T.Eq(2 * gb, DriveWatch.CriticalBelow(40 * gb), "space: nearly full never below 2 GB");
            T.Eq(0, DriveWatch.Level(545 * gb, c, 0, 10), "space: plenty of room");
            T.Eq(1, DriveWatch.Level(80 * gb, c, 0, 10), "space: getting full");
            T.Eq(2, DriveWatch.Level(20 * gb, c, 1, 10), "space: nearly full");
            T.Eq(1, DriveWatch.Level(105 * gb, c, 1, 10), "space: stays 'getting full' just above the line");
            T.Eq(0, DriveWatch.Level(111 * gb, c, 1, 10), "space: back to fine 10% above the line");
            T.Eq(2, DriveWatch.Level(26 * gb, c, 2, 10), "space: stays 'nearly full' just above its line");
            T.Eq(1, DriveWatch.Level(28 * gb, c, 2, 10), "space: then drops to 'getting full'");
            T.Eq(0, DriveWatch.Level(5 * gb, 0, 0, 10), "space: a drive of unknown size is left alone");
            var now = new DateTime(2026, 11, 19, 12, 0, 0, DateTimeKind.Utc);
            T.True(DriveWatch.ShouldAlert(1, 0, DateTime.MinValue, now), "space: alert when it gets full");
            T.True(!DriveWatch.ShouldAlert(1, 1, now.AddHours(-2), now), "space: not again two hours later");
            T.True(DriveWatch.ShouldAlert(1, 1, now.AddHours(-25), now), "space: again the next day");
            T.True(DriveWatch.ShouldAlert(2, 1, now.AddMinutes(-5), now), "space: at once when it gets worse");
            T.True(DriveWatch.ShouldAlert(2, 2, now.AddHours(-7), now), "space: nearly full repeats every 6 hours");
            T.True(!DriveWatch.ShouldAlert(0, 2, DateTime.MinValue, now), "space: no alert once there's room");
        }

        static string MakeJunction(string link, string target)
        {
            string output;
            Proc.Run("cmd.exe", "/c mklink /J \"" + link + "\" \"" + target + "\"", out output, 15000);
            return Directory.Exists(link) ? link : null;
        }

        static void ScanAndSave()
        {
            string d = T.TempDir("atlas-scan");
            try
            {
                Directory.CreateDirectory(Path.Combine(d, @"a\b"));
                Directory.CreateDirectory(Path.Combine(d, "c"));
                File.WriteAllBytes(Path.Combine(d, @"a\big.bin"), new byte[3 << 20]);
                File.WriteAllBytes(Path.Combine(d, @"a\b\mid.bin"), new byte[200 << 10]);
                File.WriteAllText(Path.Combine(d, @"c\tiny.txt"), "hi");
                var first = new Scanner().Run(d);
                long logical = (3 << 20) + (200 << 10);
                T.True(first.Root.Size >= logical && first.Root.Size < logical + 3 * 4096, "scan: size on disk adds up (" + first.Root.Size + ")");
                T.Eq(3L, first.Root.Files, "scan: three files");
                T.Eq(3, first.Root.Dirs, "scan: three folders");
                T.Eq("a", first.Root.Kids[0].Name, "scan: biggest folder first");
                T.True(first.Root.Kids[0].Kids.Any(k => k.Name == "big.bin" && !k.IsDir), "scan: a big file is kept by name");
                var c = first.Root.Kids.First(k => k.Name == "c");
                T.Eq(1, c.SmallCount, "scan: a tiny file is counted among the smaller files");
                T.True(first.Types.ContainsKey(".bin") && first.Types[".bin"].Count == 2, "scan: file types counted");

                // a hard link adds a file but no space; a junction isn't followed
                bool linked = Native.CreateHardLink(Path.Combine(d, @"c\link.bin"), Path.Combine(d, @"a\big.bin"), IntPtr.Zero);
                string j = MakeJunction(Path.Combine(d, "j"), Path.Combine(d, "a"));
                var second = new Scanner().Run(d);
                if (linked)
                {
                    T.Eq(4L, second.Root.Files, "scan: the hard link is a file");
                    T.Eq(first.Root.Size, second.Root.Size, "scan: a hard link's space counts once");
                    var cNode = second.Root.Kids.First(k => k.Name == "c");
                    T.True(cNode.Size < 4096 && second.Root.Kids[0].Name == "a", "scan: the link with the first path (a\\big.bin) keeps the space, every time");
                    for (int run = 0; run < 3; run++)
                    {
                        var again = new Scanner().Run(d, 8);
                        T.True(again.Root.Kids[0].Name == "a" && again.Root.Kids.First(k => k.Name == "c").Size < 4096, "scan: same answer on run " + (run + 2));
                    }
                }
                else T.True(false, "scan: couldn't make a hard link to test with");
                if (j != null)
                {
                    var jn = second.Root.Kids.FirstOrDefault(k => k.Name == "j");
                    T.True(jn != null && jn.Has(Node.Link) && jn.Size == 0 && jn.Kids == null, "scan: a junction is shown but not followed");
                }

                // saved and read back unchanged
                string file = Path.Combine(d, "test.map");
                MapFile.Save(second, file);
                var back = MapFile.Load(file);
                T.True(back != null, "map file: reads back");
                if (back != null)
                {
                    T.Eq(second.Root.Size, back.Root.Size, "map file: total");
                    T.Eq(second.Root.Files, back.Root.Files, "map file: files");
                    T.Eq(second.RootPath, back.RootPath, "map file: root");
                    T.Eq(string.Join(",", second.Root.Kids.Select(k => k.Name)), string.Join(",", back.Root.Kids.Select(k => k.Name)), "map file: same folders, same order");
                    var bigBack = back.Root.Kids[0].Kids.FirstOrDefault(k => k.Name == "big.bin");
                    T.True(bigBack != null && bigBack.FullPath == Path.Combine(d, @"a\big.bin") && bigBack.Kind == Kinds.Other, "map file: paths and kinds survive");
                    T.Eq(second.Types.Count, back.Types.Count, "map file: file types");
                }
                T.True(MapFile.Load(Path.Combine(d, @"c\tiny.txt")) == null, "map file: something else isn't a map");
                T.Eq(Path.Combine(MapFile.Dir, "C.map"), MapFile.PathFor("c:"), "map file: one per drive");
                T.Eq(@"C:\", Scanner.NormalizeRoot("C"), "scan: a bare drive letter is the drive");
                if (j != null) Directory.Delete(j);
            }
            finally { T.Cleanup(d); }
        }

        static void CatalogTest()
        {
            string ini =
                "[clean:temp]\nname = Temp files\nabout = x\npath = %TEMP%\nolder_than = 2d\ndefault = true\n\n" +
                "[clean:both]\nname = Two places\npath = C:\\one\npath = C:\\two\nhow = recycle\nwait_for = chrome, msedge.exe\nkeep = *.lock\n\n" +
                "[clean:sneaky]\nname = Wants admin\npath = %TEMP%\\x\nadmin = true\n\n" +
                "[clean:odd]\nname = Unknown method\npath = C:\\x\nhow = shred\n\n" +
                "[other]\nname = not a clean section\n";
            var items = Catalog.Parse(ini);
            T.Eq(3, items.Count, "catalog: clean sections with a known method");
            var temp = items[0];
            T.Eq("temp", temp.Id, "catalog: id");
            T.True(temp.Default && temp.OlderThan == TimeSpan.FromDays(2) && temp.Paths[0].IndexOf('%') < 0, "catalog: default, age, expanded path");
            var both = items[1];
            T.True(both.Paths.Count == 2 && both.How == "recycle" && both.WaitFor.Count == 2 && both.Keep[0] == "*.lock", "catalog: repeated paths and lists");
            T.True(!items[2].Admin, "catalog: a file can't ask for admin rights");
            T.True(Catalog.AdminItems().All(i => i.Admin) && Catalog.AdminItems().Any(i => i.Id == "win-temp"), "catalog: Windows' folders are built in");
            string shipped = Path.Combine(Path.GetDirectoryName(Suite.BinDir), @"src\Atlas\atlas.ini");
            if (File.Exists(shipped))
            {
                var real = Catalog.Parse(File.ReadAllText(shipped));
                T.True(real.Count >= 8 && real.Any(i => i.Id == "temp" && i.Default), "catalog: the shipped atlas.ini parses");
                T.True(real.All(i => i.Paths.All(p => Safety.Refuse(p) == null || p.IndexOf('*') >= 0)), "catalog: nothing in atlas.ini points at a protected place");
            }
        }

        static void Age(string path, int days)
        {
            var t = DateTime.UtcNow.AddDays(-days);
            File.SetCreationTimeUtc(path, t);
            File.SetLastWriteTimeUtc(path, t);
        }

        static void CleanTest()
        {
            string d = T.TempDir("atlas-clean");
            string keepDir = T.TempDir("atlas-precious");
            try
            {
                string old1 = Path.Combine(d, "old1.tmp"), fresh = Path.Combine(d, "new.tmp"), locked = Path.Combine(d, "busy.lock");
                Directory.CreateDirectory(Path.Combine(d, @"sub\deeper"));
                string old2 = Path.Combine(d, @"sub\deeper\old2.tmp");
                string precious = Path.Combine(keepDir, "keep.txt");
                foreach (var f in new[] { old1, fresh, locked, old2, precious }) File.WriteAllBytes(f, new byte[1000]);
                foreach (var f in new[] { old1, locked, old2, precious }) Age(f, 5);
                string j = MakeJunction(Path.Combine(d, "link"), keepDir);

                var it = new CleanItem { Id = "t", Name = "test", OlderThan = TimeSpan.FromDays(2), Keep = { "*.lock" } };
                it.Paths.Add(d);
                Cleaner.Measure(it);
                T.Eq(2L, it.Count, "clean: measures only old files, not kept ones or ones behind a junction");
                T.Eq(2000L, it.Bytes, "clean: their size");
                var r = Cleaner.Clean(it);
                T.Eq(2L, r.Files, "clean: deleted the two old files");
                T.True(!File.Exists(old1) && !File.Exists(old2), "clean: old files gone");
                T.True(File.Exists(fresh) && File.Exists(locked), "clean: new and kept files stay");
                T.True(File.Exists(precious), "clean: nothing deleted through a junction");
                T.True(Directory.Exists(d), "clean: the folder itself stays");
                T.True(!Directory.Exists(Path.Combine(d, "sub")), "clean: folders it emptied are removed");
                if (j != null) T.True(Directory.Exists(j), "clean: the junction itself is left alone");

                // a whole folder (Steam's leftover shader caches)
                string whole = Path.Combine(d, "whole");
                Directory.CreateDirectory(Path.Combine(whole, "x"));
                File.WriteAllBytes(Path.Combine(whole, @"x\a.bin"), new byte[500]);
                var w = new CleanItem { Id = "w", Name = "whole", WholeFolder = true };
                w.Paths.Add(whole);
                var wr = Cleaner.Clean(w);
                T.True(wr.Files == 1 && !Directory.Exists(whole), "clean: a whole-folder item removes the folder too");

                // places Atlas refuses, even from atlas.ini (checked without pointing a clean at them)
                var bad = new CleanItem { Id = "bad", Name = "bad" };
                string why = Cleaner.Refused(bad, new List<string> { Suite.User.Downloads });
                T.True(why != null && why.Contains("main folders"), "clean: refuses your Downloads folder as a whole");
                T.True(Cleaner.Refused(bad, new List<string> { Path.Combine(Suite.User.Downloads, "old-setup.exe") }) == null, "clean: but not a file inside it");
                var builtIn = Catalog.AdminItems()[0];
                T.True(Cleaner.Refused(builtIn, Cleaner.Places(builtIn)) == null, "clean: Windows' built-in folders are allowed for the built-in list");

                // a program that must be closed first
                var proc = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                var wait = new CleanItem { Id = "wait", Name = "wait" };
                wait.Paths.Add(d);
                wait.WaitFor.Add(proc + ".exe");
                T.True(Cleaner.BlockedBy(wait) != null, "clean: waits while the program runs");
                if (j != null) Directory.Delete(j);
            }
            finally
            {
                T.Cleanup(d);
                T.Cleanup(keepDir);
            }
        }

        static bool PermanentDeleteRefused(string path, bool isDirectory, DateTime modifiedUtc)
        {
            try { PermanentDelete.Remove(path, isDirectory, modifiedUtc); }
            catch (InvalidOperationException) { return true; }
            return false;
        }

        static void PermanentDeleteTest()
        {
            string root = T.TempDir("atlas-permanent-delete");
            string junction = null;
            try
            {
                string selected = Path.Combine(root, "selected.txt");
                string neighbor = Path.Combine(root, "neighbor.txt");
                File.WriteAllText(selected, "delete");
                File.WriteAllText(neighbor, "keep");
                DateTime recorded = File.GetLastWriteTimeUtc(selected);
                T.True(PermanentDeleteRefused(selected, true, DateTime.MinValue) && File.Exists(selected),
                    "permanent delete: stale directory entry cannot delete a file");
                File.SetLastWriteTimeUtc(selected, recorded.AddMinutes(-5));
                T.True(PermanentDeleteRefused(selected, false, recorded) && File.Exists(selected),
                    "permanent delete: a file changed since the scan stays");
                PermanentDelete.Remove(selected, false, File.GetLastWriteTimeUtc(selected));
                T.True(!File.Exists(selected) && File.Exists(neighbor), "permanent delete: removes only the selected file");

                string folder = Path.Combine(root, "folder");
                string nested = Path.Combine(folder, "nested");
                Directory.CreateDirectory(nested);
                File.WriteAllText(Path.Combine(nested, "child.txt"), "delete");
                T.True(PermanentDeleteRefused(folder, false, DateTime.MinValue) && Directory.Exists(nested),
                    "permanent delete: stale file entry cannot delete a folder");
                PermanentDelete.Remove(folder, true, DateTime.MinValue);
                T.True(!Directory.Exists(folder) && File.Exists(neighbor), "permanent delete: removes the selected folder and its contents");

                string outside = Path.Combine(root, "outside");
                Directory.CreateDirectory(outside);
                string precious = Path.Combine(outside, "precious.txt");
                File.WriteAllText(precious, "keep");
                string blocked = Path.Combine(root, "blocked");
                Directory.CreateDirectory(blocked);
                string ordinaryChild = Path.Combine(blocked, "legacy.txt");
                File.WriteAllText(ordinaryChild, "keep");
                junction = MakeJunction(Path.Combine(blocked, "junction"), outside);
                if (junction != null)
                {
                    T.True(PermanentDeleteRefused(Path.Combine(junction, "precious.txt"), false, DateTime.MinValue)
                            && File.Exists(precious),
                        "permanent delete: a path under a junction cannot reach its target");
                    T.True(PermanentDeleteRefused(blocked, true, DateTime.MinValue)
                            && File.Exists(ordinaryChild) && Directory.Exists(junction) && File.Exists(precious),
                        "permanent delete: refuses the whole folder before changing anything if it contains a junction");
                }
            }
            finally
            {
                if (junction != null && Directory.Exists(junction)
                    && (File.GetAttributes(junction) & FileAttributes.ReparsePoint) != 0)
                    Directory.Delete(junction);
                T.Cleanup(root);
            }
        }

        static void SteamTest()
        {
            string acf = "\"AppState\"\n{\n\t\"appid\"\t\t\"1144200\"\n\t\"name\"\t\t\"Ready or Not\"\n\t\"installdir\"\t\t\"Ready Or Not\"\n" +
                         "\t\"LastUpdated\"\t\t\"1792667290\"\n\t\"LastPlayed\"\t\t\"1787461909\"\n\t\"SizeOnDisk\"\t\t\"48794454093\"\n" +
                         "\t\"InstalledDepots\"\n\t{\n\t\t\"1144201\"\n\t\t{\n\t\t\t\"size\"\t\t\"1\"\n\t\t}\n\t}\n}\n";
            var g = Steam.ParseManifest(acf, @"D:\SteamLibrary");
            T.True(g != null && g.AppId == "1144200" && g.Name == "Ready or Not" && g.InstallDir == "Ready Or Not", "steam: manifest basics");
            T.True(g != null && g.SizeOnDisk == 48794454093L && g.LastPlayed == Clock.FromUnix(1787461909), "steam: size and last played");
            T.Eq(@"D:\SteamLibrary\steamapps\common\Ready Or Not", g == null ? null : g.Folder, "steam: install folder");
            T.True(Steam.ParseManifest("\"AppState\" { \"name\" \"x\" }", "C:\\") == null, "steam: a manifest without an install folder is skipped");
            string vdf = "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t}\n}\n";
            var libs = Steam.ParseLibraries(vdf);
            T.Eq(@"C:\Program Files (x86)\Steam|D:\SteamLibrary", string.Join("|", libs), "steam: library folders unescaped");
            var left = Steam.Leftovers(new[] { "Ready Or Not", "Rust", "Steam Controller Configs", "Steamworks Shared" }, new[] { "ready or not" });
            T.Eq("Rust", string.Join(",", left), "steam: leftovers skip installed games and Steam's own folders");
            var games = new List<SteamGame> { g };
            // when last played, from an account's localconfig.vdf (nested blocks, comments, escapes)
            string local = "\"UserLocalConfigStore\"\n{\n  // comment\n  \"Software\"\n  {\n    \"Valve\"\n    {\n      \"Steam\"\n      {\n" +
                           "        \"apps\"\n        {\n          \"1144200\"\n          {\n            \"cloud\" { \"last_sync\" \"1\" }\n            \"LastPlayed\"\t\"1800000000\"\n          }\n" +
                           "          \"999\"\n          {\n            \"LastPlayed\"\t\"0\"\n          }\n        }\n        \"path\" \"C:\\\\x\\\"y\"\n      }\n    }\n  }\n}\n";
            var doc = Vdf.Parse(local);
            T.Eq("C:\\x\"y", Vdf.Get(doc, "UserLocalConfigStore", "Software", "Valve", "Steam", "path") as string, "vdf: escapes");
            var played = new Dictionary<string, DateTime>();
            Steam.ReadLastPlayed(local, played);
            T.True(played.Count == 1 && played["1144200"] == Clock.FromUnix(1800000000), "steam: last played from localconfig (zero ignored)");
            Steam.MergeLastPlayed(games, played);
            T.Eq(Clock.FromUnix(1800000000), g.LastPlayed, "steam: the later date wins");
            Steam.MergeLastPlayed(games, new Dictionary<string, DateTime> { { "1144200", Clock.FromUnix(1700000000) } });
            T.Eq(Clock.FromUnix(1800000000), g.LastPlayed, "steam: an older date doesn't replace it");
            T.True(Steam.GameAt(@"D:\SteamLibrary\steamapps\common\Ready Or Not\Content\x.pak", games) == g, "steam: a file inside a game belongs to it");
            T.True(Steam.GameAt(@"D:\SteamLibrary\steamapps\common\Ready Or Not 2", games) == null, "steam: a similar name doesn't");
        }

        static void SafetyTest()
        {
            string profile = Suite.User.Profile;
            T.True(Safety.Refuse(@"C:\") != null, "safety: a whole drive");
            T.True(Safety.Refuse(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32")) != null, "safety: Windows");
            T.True(Safety.Refuse(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)) != null, "safety: Program Files itself");
            T.True(Safety.Refuse(profile) != null, "safety: your user folder");
            T.True(Safety.Refuse(Suite.User.Downloads) != null, "safety: your Downloads folder as a whole");
            T.True(Safety.Refuse(Path.Combine(Suite.User.Downloads, "setup.exe")) == null, "safety: a file in Downloads is fine");
            T.True(Safety.Refuse(Path.Combine(Safety.ArkRoot(), "C-Claude")) != null, "safety: Ark's backups");
            T.True(Safety.Refuse(@"D:\SteamLibrary\steamapps\common\Rust") == null, "safety: a leftover game folder is fine");
            T.True(Safety.Refuse(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Olympus", "Atlas.exe")) != null, "safety: Olympus itself");
            // a short (8.3) spelling of a protected folder is still that folder
            string tmp = Path.GetTempPath().TrimEnd('\\');
            string longTmp = FsNative.LongName(tmp);
            T.True(longTmp.IndexOf('~') < 0 || tmp.IndexOf('~') < 0, "long names: " + tmp + " -> " + longTmp);
            if (tmp.IndexOf('~') >= 0)
            {
                string shortProfile = tmp.Substring(0, tmp.IndexOf(@"\AppData", StringComparison.OrdinalIgnoreCase));
                T.True(Safety.Refuse(shortProfile) != null, "safety: the short spelling of your user folder is refused too");
                T.True(FsNative.LongName(tmp + @"\*\Cache").EndsWith(@"\*\Cache") && FsNative.LongName(tmp + @"\*\Cache").IndexOf('~') < 0, "long names: a pattern keeps its wildcard part");
            }
        }
    }
}
