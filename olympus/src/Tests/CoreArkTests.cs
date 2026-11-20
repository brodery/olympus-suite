// Tests for the shared core and Ark.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using Olympus.Ark;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class CoreTests
    {
        public static void Run()
        {
            var ini = Ini.Parse("; c\r\n[a]\r\nx = 1\r\nx = 2\r\nflag = yes\r\nlist = p, q; r\r\n[set:B c]\r\npath = C:\\x\r\nevery = 90m\r\n");
            T.Eq("2", ini.Get("a", "x", null), "ini: last repeat wins");
            T.Eq(2, ini.All("a", "x").Count, "ini: repeats kept");
            T.True(ini.Bool("a", "flag", false), "ini: yes is true");
            T.Eq(3, ini.List("a", "list").Count, "ini: list split on , and ;");
            T.Eq(TimeSpan.FromMinutes(90), ini.Span("set:B c", "every", TimeSpan.Zero), "ini: 90m");
            T.True(ini.Sections.Contains("set:B c"), "ini: section names keep spaces");
            TimeSpan t;
            T.True(Spans.TryParse("2d", out t) && t == TimeSpan.FromDays(2), "spans: 2d");
            T.True(Spans.TryParse("15", out t) && t == TimeSpan.FromMinutes(15), "spans: bare number = minutes");
            T.True(!Spans.TryParse("x", out t), "spans: garbage rejected");

            var parsed = J.Parse("{\"a\":{\"b\":[1,{\"c\":\"d\"}]},\"n\":5}");
            T.Eq("d", J.Str(parsed, "a.b.1.c"), "json: path into arrays");
            T.Eq(5L, J.Long(parsed, "n", 0), "json: number");
            T.True(J.Get(parsed, "a.zz.q") == null, "json: missing path is null");
            string pretty = J.Pretty(J.Write(new Dictionary<string, object> { { "s", "a,b{c}\"q\"" }, { "e", new object[0] } }));
            T.Eq("a,b{c}\"q\"", J.Str(J.Parse(pretty), "s"), "json: pretty keeps strings intact");

            T.Eq("1.5 KB", Fmt.Size(1536), "fmt: size");
            T.Eq("just now", Fmt.Ago(DateTime.UtcNow.AddSeconds(-5)), "fmt: just now");
            T.Eq("3 min ago", Fmt.Ago(DateTime.UtcNow.AddMinutes(-3)), "fmt: minutes");
            T.Eq("abc\u2026", Fmt.Clip("abcdef", 4), "fmt: clip");
            T.Eq(new DateTime(2026, 11, 18, 12, 0, 0, DateTimeKind.Utc), Clock.Parse("2026-11-18T12:00:00Z"), "clock: parse iso");

            var f = AegisClient.Fields("app=Aegis;ver=1.0.1;state=on;b=667");
            T.Eq("on", f["state"], "aegis fields");
            T.Eq("667", f["b"], "aegis fields: number");

            T.True(!NetTables.IsPublic(IPAddress.Parse("192.168.1.5")), "ip: lan is private");
            T.True(!NetTables.IsPublic(IPAddress.Parse("100.72.1.1")), "ip: cgnat is private");
            T.True(NetTables.IsPublic(IPAddress.Parse("9.9.9.9")), "ip: quad9 is public");
            T.True(!NetTables.IsPublic(IPAddress.Parse("fe80::1")), "ip: link-local v6");
            T.True(NetTables.IsPublic(IPAddress.Parse("2620:fe::fe")), "ip: public v6");
            T.True(!NetTables.IsPublic(IPAddress.Parse("::ffff:10.0.0.1")), "ip: mapped private");

            // alerts file tailing, including a rotation in between
            string dir = T.TempDir("alerts");
            try
            {
                string path = Path.Combine(dir, AlertStore.FileName);
                File.WriteAllText(path, J.Write(new AlertInfo { Id = "a1", Title = "one" }) + "\n" + J.Write(new AlertInfo { Id = "a2", Title = "two" }) + "\n{\"Id\":\"partial");
                long off = 0;
                var got = AlertStore.Tail(dir, ref off);
                T.Eq(2, got.Count, "tail: two complete lines, partial line left");
                File.AppendAllText(path, "\"}\n");
                got = AlertStore.Tail(dir, ref off);
                T.Eq(1, got.Count, "tail: partial line completed");
                T.Eq("partial", got[0].Id, "tail: completed line parsed");
                File.Move(path, Path.Combine(dir, AlertStore.OldName));
                File.AppendAllText(Path.Combine(dir, AlertStore.OldName), J.Write(new AlertInfo { Id = "a3" }) + "\n");
                File.WriteAllText(path, J.Write(new AlertInfo { Id = "a4" }) + "\n");
                got = AlertStore.Tail(dir, ref off);
                T.Eq("a3,a4", string.Join(",", got.Select(a => a.Id)), "tail: reads the rest of a rotated file, then the new one");
            }
            finally { T.Cleanup(dir); }

            string hubIni = "; settings\r\n[hub]\r\nhotkey = Ctrl+Alt+L\r\nhidden_icons =\r\ntoasts = true\r\n";
            string after = Olympus.Hub.HubSettings.WithHidden(hubIni, new[] { "Ark", "Ares" });
            T.True(after.Contains("hidden_icons = Ark, Ares") && after.Contains("; settings") && after.Contains("toasts = true"), "hidden icons: replaces the line, keeps the rest");
            T.Eq(2, Ini.Parse(after).List("hub", "hidden_icons").Count, "hidden icons: reads back");
            string noKey = Olympus.Hub.HubSettings.WithHidden("[hub]\r\nhotkey = Ctrl+Alt+L\r\n", new[] { "Argus" });
            T.Eq("Argus", Ini.Parse(noKey).Get("hub", "hidden_icons", null), "hidden icons: added under [hub]");
            string noHub = Olympus.Hub.HubSettings.WithHidden("; empty\r\n", new[] { "Sibyl" });
            T.Eq("Sibyl", Ini.Parse(noHub).Get("hub", "hidden_icons", null), "hidden icons: [hub] created when missing");

            uint mods, vk;
            T.True(Olympus.Hub.HotkeyWindow.Parse("Ctrl+Alt+L", out mods, out vk) && mods == 3 && vk == (uint)System.Windows.Forms.Keys.L, "hotkey: ctrl+alt+L");
            T.True(!Olympus.Hub.HotkeyWindow.Parse("L", out mods, out vk), "hotkey: needs a modifier");

            var sig = Signature.Check(Path.Combine(Environment.SystemDirectory, "notepad.exe"));
            T.True(sig.Signed && sig.Trusted, "signature: notepad is signed (" + sig.Describe() + ")");
            var kernel = Signature.Check(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
            T.True(kernel.Signed && kernel.IsMicrosoft, "signature: kernel32 signed by Microsoft (" + kernel.Describe() + ")");
            string unsigned = Path.Combine(T.TempDir("sig"), "x.exe");
            File.WriteAllBytes(unsigned, new byte[] { 0x4D, 0x5A, 0, 0 });
            T.True(!Signature.Check(unsigned).Signed, "signature: junk file is unsigned");
            T.Cleanup(Path.GetDirectoryName(unsigned));

            var listeners = NetTables.Tcp(true);
            T.True(listeners.Any(c => c.LocalPort == 135 || c.LocalPort == 445), "tcp table: sees Windows' own listeners");
        }
    }

    static class ArkTests
    {
        static void Write(string path, string text, DateTime when)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, text);
            File.SetLastWriteTimeUtc(path, when);
        }

        public static void Run()
        {
            var ex = Snapshots.Excluder(new[] { @"*\obj\*", "*.tmp" });
            T.True(ex(@"C:\x\obj\a.exe", false), "exclude: file under obj");
            T.True(ex(@"C:\x\obj", true), "exclude: the obj folder itself");
            T.True(ex(@"C:\x\a.tmp", false), "exclude: by name");
            T.True(!ex(@"C:\x\a.tmpx", false), "exclude: anchored");
            T.True(!ex(@"C:\x\object\a.cs", false), "exclude: obj isn't object");

            var now = new DateTime(2026, 11, 18, 15, 0, 0);
            Func<DateTime, string> N = d => d.ToString(Snapshots.StampFormat, CultureInfo.InvariantCulture);
            var names = new List<string>
            {
                N(now.AddMinutes(-5)), N(now.AddHours(-1)), N(now.AddHours(-47)),
                N(now.AddDays(-3).AddHours(-1)), N(now.AddDays(-3).AddHours(-2)),     // same day: keep newer
                N(now.AddDays(-40)), N(now.AddDays(-40).AddHours(-3)),                 // same week: keep newer
                N(now.AddDays(-100))                                                   // past weekly window
            };
            var del = Snapshots.PlanPrune(names, now, 48, 30, 12);
            T.Eq(3, del.Count, "prune: three to remove");
            T.True(del.Contains(N(now.AddDays(-3).AddHours(-2))), "prune: older of the same day");
            T.True(del.Contains(N(now.AddDays(-40).AddHours(-3))), "prune: older of the same week");
            T.True(del.Contains(N(now.AddDays(-100))), "prune: past the weekly window");
            T.Eq(0, Snapshots.PlanPrune(new List<string> { N(now.AddDays(-400)) }, now, 48, 30, 12).Count, "prune: never the only snapshot");
            Retention();

            string root = T.TempDir("ark");
            try
            {
                string src = Path.Combine(root, "src"), target = Path.Combine(root, "target");
                var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                Write(Path.Combine(src, "a.txt"), "first", t0);
                Write(Path.Combine(src, @"sub\b.txt"), "bee", t0);
                Write(Path.Combine(src, @"obj\skip.bin"), "skip", t0);
                Directory.CreateDirectory(Path.Combine(src, "empty"));
                var set = new BackupSet { Name = "Test set", Path = src, Slug = "Test set", Exclude = new List<string> { @"*\obj\*" } };

                var r1 = Snapshots.Take(set, target, long.MaxValue, null, CancellationToken.None);
                string setDir = Snapshots.SetDir(target, set);
                T.Eq(2, r1.Files, "snapshot 1: two files (obj excluded)");
                T.Eq(2, r1.Copied, "snapshot 1: both copied");
                T.Eq("first", File.ReadAllText(Path.Combine(setDir, r1.Snapshot, "a.txt")), "snapshot 1: content");
                T.True(Directory.Exists(Path.Combine(setDir, r1.Snapshot, "empty")), "snapshot 1: empty folder kept");
                T.True(!Directory.Exists(Path.Combine(setDir, r1.Snapshot, "obj")), "snapshot 1: excluded folder absent");
                T.Eq(t0, File.GetLastWriteTimeUtc(Path.Combine(setDir, r1.Snapshot, "a.txt")), "snapshot 1: file time kept");
                var man = Snapshots.LoadManifest(Path.Combine(setDir, r1.Snapshot + ".manifest.tsv"));
                T.Eq(FileUtil.Sha256(Path.Combine(src, "a.txt")), man["a.txt"].Hash, "snapshot 1: manifest hash");

                Write(Path.Combine(src, "a.txt"), "second", t0.AddHours(1));
                var r2 = Snapshots.Take(set, target, long.MaxValue, null, CancellationToken.None);
                T.Eq(1, r2.Copied, "snapshot 2: only the changed file copied");
                T.Eq(1, r2.Linked, "snapshot 2: unchanged file linked");
                T.Eq(2, T.LinkCount(Path.Combine(setDir, r2.Snapshot, @"sub\b.txt")), "snapshot 2: b.txt is one file in two snapshots");
                T.Eq("first", File.ReadAllText(Path.Combine(setDir, r1.Snapshot, "a.txt")), "snapshot 1 unchanged by snapshot 2");
                T.Eq(2, Snapshots.List(setDir).Count, "two snapshots listed");

                // a file locked by another program: the previous version is kept
                Write(Path.Combine(src, @"sub\b.txt"), "bee 2", t0.AddHours(2));
                SnapshotSummary sum;
                using (new FileStream(Path.Combine(src, @"sub\b.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    var r3 = Snapshots.Take(set, target, long.MaxValue, null, CancellationToken.None);
                    T.Eq(1, r3.Errors, "snapshot 3: locked file counted as an error");
                    T.Eq("bee", File.ReadAllText(Path.Combine(setDir, r3.Snapshot, @"sub\b.txt")), "snapshot 3: last good version kept");
                    sum = Snapshots.Summary(setDir, r3.Snapshot);
                }
                T.True(sum != null && sum.Errors == 1, "snapshot 3: summary records the error");
                T.Eq(0, Directory.GetDirectories(setDir, "*" + Snapshots.Partial).Length, "no unfinished snapshots left");

                // restore: a deleted file comes back; a different file in the way is kept aside
                File.Delete(Path.Combine(src, "a.txt"));
                T.True(Restore.File(Path.Combine(setDir, r1.Snapshot, "a.txt"), Path.Combine(src, "a.txt")), "restore: deleted file put back");
                T.Eq("first", File.ReadAllText(Path.Combine(src, "a.txt")), "restore: content");
                T.True(!Restore.File(Path.Combine(setDir, r1.Snapshot, "a.txt"), Path.Combine(src, "a.txt")), "restore: identical file left alone");
                Write(Path.Combine(src, "a.txt"), "edited", t0.AddHours(5));
                Restore.File(Path.Combine(setDir, r2.Snapshot, "a.txt"), Path.Combine(src, "a.txt"));
                T.Eq("second", File.ReadAllText(Path.Combine(src, "a.txt")), "restore: older version in place");
                T.Eq(1, Directory.GetFiles(src, "a (before restore*").Length, "restore: current version kept aside");
                var errors = new List<string>();
                int n = Restore.Folder(Path.Combine(setDir, r1.Snapshot), Path.Combine(root, "elsewhere"), errors);
                T.Eq(2, n, "restore folder: two files");
                T.Eq(0, errors.Count, "restore folder: no errors");

                Snapshots.Delete(setDir, r1.Snapshot);
                T.True(!Directory.Exists(Path.Combine(setDir, r1.Snapshot)), "delete: snapshot gone");
                T.Eq("bee", File.ReadAllText(Path.Combine(setDir, r2.Snapshot, @"sub\b.txt")), "delete: linked file still in the other snapshot");

                // long paths
                string deep = Path.Combine(src, new string('d', 120), new string('e', 120), new string('f', 40));
                Directory.CreateDirectory(Snapshots.L(deep));
                File.WriteAllText(Snapshots.L(Path.Combine(deep, "deep.txt")), "deep");
                var r4 = Snapshots.Take(set, target, long.MaxValue, null, CancellationToken.None);
                T.Eq(0, r4.Errors, "long path: no errors");
                T.True(File.Exists(Snapshots.L(Path.Combine(setDir, r4.Snapshot, new string('d', 120), new string('e', 120), new string('f', 40), "deep.txt"))), "long path: copied");
            }
            finally { T.Cleanup(root); }
        }

        public static void Retention()
        {
            string root = T.TempDir("ark-retention");
            try
            {
                var now = new DateTime(2026, 11, 18, 15, 0, 0);
                var cfg = new ArkConfig { KeepAllHours = 48, KeepDailyDays = 0, KeepWeeklyWeeks = 0 };
                Func<DateTime, int, string> save = (at, errors) =>
                {
                    string stamp = at.ToString(Snapshots.StampFormat, CultureInfo.InvariantCulture);
                    Directory.CreateDirectory(Path.Combine(root, stamp));
                    if (errors >= 0)
                        J.Save(Path.Combine(root, stamp + ".ark.json"), new SnapshotSummary
                        {
                            Snapshot = stamp, Started = Clock.Iso(at.ToUniversalTime()), Errors = errors
                        });
                    return stamp;
                };
                DateTime originalTime = now.AddDays(-100).ToUniversalTime();
                string original = save(now.AddDays(-100), 0);
                string oldPartial = save(now.AddDays(-4), 1);
                string unknown = save(now.AddDays(-3), -1);
                J.Save(Path.Combine(root, unknown + ".ark.json"), new { Snapshot = unknown, Started = Clock.Iso(now.AddDays(-3).ToUniversalTime()) });
                string latest = save(now, 1);
                var expired = Snapshots.PlanRetention(root, cfg, now);
                T.True(expired.SequenceEqual(new[] { oldPartial }), "retention: incomplete latest keeps complete and unknown snapshots");

                var state = new SetState { LastSnapshot = latest, LastSuccess = Clock.Iso(now.ToUniversalTime()), LastErrors = 1 };
                state.RecoverLastSuccess(root);
                T.Eq(original, state.LastCompleteSnapshot, "retention: find last complete from old on-disk summaries");
                T.Eq(Clock.Iso(originalTime), state.LastSuccess, "retention: repair legacy last successful time");

                state.LastRun = Clock.Iso(now.AddMinutes(5).ToUniversalTime());
                state.RecordSnapshot(new RunResult { Snapshot = latest, Errors = 2 });
                T.Eq(Clock.Iso(originalTime), state.LastSuccess, "retention: incomplete run preserves last successful time");
                T.Eq(2, state.LastErrors, "retention: latest snapshot errors remain visible");
                string fresh = save(now.AddMinutes(5), 0);
                state.RecordSnapshot(new RunResult { Snapshot = fresh });
                T.Eq(fresh, state.LastCompleteSnapshot, "retention: a later complete backup advances last complete");
                T.Eq(state.LastRun, state.LastSuccess, "retention: a later complete backup advances last successful time");

                expired = Snapshots.PlanRetention(root, cfg, now.AddMinutes(5));
                T.True(expired.Contains(original) && expired.Contains(oldPartial) && !expired.Contains(unknown) && !expired.Contains(fresh),
                    "retention: once a newer complete backup exists, old classified snapshots expire normally");

                string oldFile = Path.Combine(root, original, "example.txt");
                File.WriteAllText(oldFile, "original backup");
                string restored = Path.Combine(root, "restore", "example.txt");
                T.True(Restore.File(oldFile, restored), "retention: restore from protected complete snapshot");
                T.Eq("original backup", File.ReadAllText(restored), "retention: restored contents match");
            }
            finally { T.Cleanup(root); }
        }
    }
}
