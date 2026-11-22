// Routine updates and review state: Versioned (shared), signer identities, Argus's RoutineUpdate,
// settings, new-entry rating, COM occurrences and retirement, Cerberus's Classify and firewall rule names,
// and ArgusAlertReview.ApplyStatus. Real-world paths come from the 2026-11-20 updates of Claude, Edge and a
// Windows driver; the bypass cases come from Codex's reviews (rounds 1 and 2).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Olympus.Argus;
using Olympus.Cerberus;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class RoutineUpdateTests
    {
        static string WindowsApps
        {
            get
            {
                string pf = Environment.GetEnvironmentVariable("ProgramW6432");
                return Path.Combine(string.IsNullOrEmpty(pf) ? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) : pf, "WindowsApps");
            }
        }
        static string DriverStore { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\DriverStore\FileRepository"); } }

        public static void Run()
        {
            VersionedPaths();
            PlainPathsAndLaunch();
            AdminOnly();
            Drivers();
            SignerIdentity();
            Settings();
            ArgusRoutine();
            ArgusComRetire();
            ArgusOccurrences();
            ArgusNewEntries();
            CerberusClassify();
            ReviewStatus();
            Hardening();
        }

        // The later items from Codex's rounds 3 and 4, and the WHQL signer check.
        static void Hardening()
        {
            // Side-by-side installs aren't updates: only bare versions and Squirrel's app-<version> count.
            T.True(!Versioned.IsUpdate(@"C:\Data\tenant-1.0\agent.exe", @"C:\Data\tenant-2.0\agent.exe"), "layouts: tenant-1.0 to tenant-2.0 isn't an update");
            T.True(!Versioned.IsUpdate(@"C:\Program Files\Java\jdk-17.0.1\bin\java.exe", @"C:\Program Files\Java\jdk-21.0.2\bin\java.exe"), "layouts: side-by-side JDKs aren't an update");
            T.True(!Versioned.HasVersionFolder(@"C:\Data\tenant-1.0\agent.exe"), "layouts: a prefixed folder isn't a version folder");
            T.True(Versioned.IsUpdate(@"C:\Users\u\AppData\Local\Slack\app-4.41.105\slack.exe", @"C:\Users\u\AppData\Local\Slack\app-4.41.106\slack.exe"), "layouts: Squirrel's app-<version> still is");

            // Microsoft's own code, not third-party drivers Microsoft signs through WHQL or attestation.
            T.True(Signature.IsMicrosoftPublisher("Microsoft Windows") && Signature.IsMicrosoftPublisher("Microsoft Corporation"), "signer: Microsoft's own names");
            T.True(!Signature.IsMicrosoftPublisher("Microsoft Windows Hardware Compatibility Publisher"), "signer: WHQL-signed third-party code isn't Microsoft's");
            T.True(!Signature.IsMicrosoftPublisher("Microsoft Windows Third Party Application Component"), "signer: third-party components aren't Microsoft's");
            T.True(!Signature.IsMicrosoftPublisher(null) && !Signature.IsMicrosoftPublisher("Contoso"), "signer: others");
            var whql = new SignerInfo { Signed = true, Trusted = true, Publisher = "Microsoft Windows Hardware Compatibility Publisher", Id = "x" };
            T.True(!whql.IsMicrosoft, "signer: a WHQL signature doesn't make a program Microsoft's");

            // Microsoft's own code is judged by the verified chain's root too (roots from this PC's store; issuers
            // as surveyed here on 2026-11-21).
            const string root2010 = "3B1EFD3A66EA28B16697394703A72CA340A05BD5", root2011 = "8F43288AD272F3103B6FB1428485EA3014C0BCFE";
            T.True(Signature.IsMicrosoftCode("Microsoft Windows", "Microsoft Windows Production PCA 2026 RSA2048-SHA256", root2010), "chain: Windows files signed this year");
            T.True(Signature.IsMicrosoftCode("Microsoft Windows Publisher", "Windows Production PCA 2023", root2010), "chain: an issuer without Microsoft in its name");
            T.True(Signature.IsMicrosoftCode("Microsoft Corporation", "Microsoft Code Signing PCA 2024", root2011), "chain: Microsoft products under the 2011 root");
            T.True(!Signature.IsMicrosoftCode("Microsoft Corporation", "Microsoft Code Signing PCA 2024", "0123456789ABCDEF0123456789ABCDEF01234567"), "chain: a Microsoft name under an organisation's own root isn't Microsoft's");
            T.True(!Signature.IsMicrosoftCode("Microsoftware LLC", "Microsoft ID Verified CS EOC CA 01", "F40042E2E5F7E8EF8189FED15519AECE42C3BFA2"), "chain: Microsoft's signing service for other companies isn't Microsoft's code");
            T.True(!Signature.IsMicrosoftCode("Microsoft Windows", "Microsoft Windows Third Party Component CA 2014", root2010), "chain: a Third Party CA under the 2010 root isn't Microsoft's code");
            T.True(!Signature.IsMicrosoftCode("Microsoft Windows", "Microsoft Windows Production PCA 2026 RSA2048-SHA256", null), "chain: no root on record");
            var real = Signature.CheckNow(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
            T.True(real.IsMicrosoft && !string.IsNullOrEmpty(real.Root) && !string.IsNullOrEmpty(real.Issuer), "chain: kernel32.dll reads as Microsoft's own (root " + real.Root + ", issuer " + real.Issuer + ")");

            // History labels for routine settings changes say what changed.
            bool startOnly;
            T.Eq("Start mode changed to manual (was automatic)", Engine.SettingsChangeLabel("enabled=1;start=automatic;type=32;account=LocalSystem", "enabled=1;start=manual;type=32;account=LocalSystem", out startOnly), "history: a start-mode change");
            T.True(startOnly, "history: ...is a start-mode-only change (noted at most once a day)");
            T.Eq("Switched on (start mode automatic)", Engine.SettingsChangeLabel("enabled=0;start=disabled;type=16;account=", "enabled=1;start=automatic;type=16;account=", out startOnly), "history: a service switched on");
            T.True(!startOnly, "history: ...is always noted");
            T.Eq("Switched off", Engine.SettingsChangeLabel("enabled=1;start=manual;type=16;account=", "enabled=0;start=disabled;type=16;account=", out startOnly), "history: a service switched off");
            T.Eq("Switched on", Engine.SettingsChangeLabel("enabled=0;kind=String", "enabled=1;kind=String", out startOnly), "history: a startup entry switched on (no start mode)");

            // Re-checks of kept entries share one verification per program and neighbour check in a scan.
            int calls = 0;
            var once = Engine.OncePerScan((p, s) => { calls++; return new SignerInfo { Signed = true, Trusted = true, Id = "i" }; });
            once(@"C:\A\x.dll", Siblings.Files); once(@"C:\A\x.dll", Siblings.Files);
            T.Eq(1, calls, "scan cost: one verification per program and neighbour check");
            once(@"C:\a\X.DLL", Siblings.Files);
            T.Eq(2, calls, "scan cost: another spelling is checked on its own (case-sensitive folders exist)");
            once(@"C:\A\x.dll", Siblings.Tree);
            T.Eq(3, calls, "scan cost: another neighbour check is its own");

            // A program kept as Microsoft's must still be signed as Microsoft's own code.
            var keptMs = new BaselineEntry { SignerId = "whql-id", AutoKept = true, KeptBy = "signature" };
            var notepadItem = new Item { Category = "run", Target = Path.Combine(Environment.SystemDirectory, "notepad.exe") };
            SignerInfo heldWhql;
            string whqlWhy = Engine.LostTrust(keptMs, notepadItem, (p, s) => new SignerInfo { Signed = true, Trusted = true, Publisher = "Microsoft Windows Hardware Compatibility Publisher", Id = "whql-id" }, out heldWhql);
            T.True(whqlWhy != null && whqlWhy.Contains("Microsoft"), "trust: a WHQL-signed program kept as Microsoft's comes back for a look");

            // A service registered as a driver now (or the other way round) is a change to the accepted entry.
            var baseline = new Dictionary<string, BaselineEntry> { { @"service|HKLM\SYSTEM\CurrentControlSet\Services|Foo", new BaselineEntry { Category = "service", Name = "Foo" } } };
            var asDriver = new Item { Category = "driver", Key = @"driver|HKLM\SYSTEM\CurrentControlSet\Services|Foo" };
            T.True(Engine.OtherKind(baseline, asDriver) != null, "kind switch: a driver that was an accepted service");
            T.True(Engine.OtherKind(baseline, new Item { Category = "driver", Key = @"driver|HKLM\SYSTEM\CurrentControlSet\Services|Bar" }) == null, "kind switch: an unrelated driver");
            T.True(Engine.OtherKind(baseline, new Item { Category = "task", Key = @"task|\|Foo" }) == null, "kind switch: other kinds of entry");
            T.Eq(@"driver|HKLM\X|Foo", Engine.OtherKindKey(@"service|HKLM\X|Foo"), "kind switch: service key to driver key");
            T.Eq(@"service|HKLM\X|Foo", Engine.OtherKindKey(@"driver|HKLM\X|Foo"), "kind switch: driver key to service key");
            T.True(Engine.OtherKindKey(@"run|HKLM\X|Foo") == null && Engine.OtherKindKey(null) == null, "kind switch: no other kind for the rest");

            // Turn off acts only on the entry as reviewed: same command and actions, same settings.
            var reviewed = new Item { Category = "service", Hash = "h", Enabled = true };
            reviewed.Extra["start"] = "manual"; reviewed.Extra["type"] = "16";
            var same = reviewed.Copy();
            T.True(Engine.StillAsReviewed(reviewed, same), "turn off: unchanged since review");
            var moved = reviewed.Copy(); moved.Hash = "other";
            T.True(!Engine.StillAsReviewed(reviewed, moved), "turn off: another command since review");
            var switchedOn = reviewed.Copy(); switchedOn.Extra["start"] = "automatic";
            T.True(!Engine.StillAsReviewed(reviewed, switchedOn), "turn off: other settings since review");
            T.True(!Engine.StillAsReviewed(reviewed, null), "turn off: gone since review");
            // Codex round 5: the window pins the entry down before any question; a newer saved snapshot doesn't count.
            reviewed.Key = "service|x|y";
            string pinned = Engine.ReviewDigest(reviewed);
            T.True(pinned != null && pinned.Length == 64 && Actions.ValidDigest(pinned), "review digest: 64 hex digits");
            var replaced = reviewed.Copy(); replaced.Hash = "replacement";
            T.True(Engine.MatchesReview(reviewed, pinned) && !Engine.MatchesReview(replaced, pinned), "review digest: a replacement recorded meanwhile doesn't match");
            var otherSettings = reviewed.Copy(); otherSettings.Enabled = false;
            T.True(!Engine.MatchesReview(otherSettings, pinned), "review digest: other settings don't match");
            T.True(Engine.MatchesReview(replaced, null), "review digest: callers without one (hub alerts) rely on the alert ID");
            T.True(!Actions.ValidDigest("abc") && !Actions.ValidDigest(pinned + " --action accept-all"), "review digest: only the exact shape reaches an elevated Argus");
            // Reading one kind again gives the same entry and hash as before (a real service read twice).
            var first = new Collector().Only("service").FirstOrDefault(i => i.Name == "Winmgmt");
            var second = new Collector().Only("service").FirstOrDefault(i => i.Name == "Winmgmt");
            if (first != null && second != null)
            {
                first.Hash = Engine.EntryHash(first, first.HashBasis ?? first.Command);
                second.Hash = Engine.EntryHash(second, second.HashBasis ?? second.Command);
                T.True(Engine.StillAsReviewed(first, second), "turn off: re-reading a service finds it as it was");
            }
            else T.True(false, "turn off: Winmgmt service readable");

            // Saved data that exists but can't be read stops decisions (it would look like a first scan or no findings).
            string dir = T.TempDir("argus-unreadable");
            try
            {
                T.True(ArgusData.Load(dir).Readable, "saved data: nothing saved yet is readable (a first scan)");
                File.WriteAllText(Path.Combine(dir, "pending.json"), "{ not json");
                var d = ArgusData.Load(dir);
                T.True(!d.Readable && !d.PendingReadable && d.Pending.Count == 0, "saved data: an unreadable pending list is noticed");
                File.WriteAllText(Path.Combine(dir, "pending.json"), "{}");
                File.WriteAllText(Path.Combine(dir, "baseline.json"), "[broken");
                d = ArgusData.Load(dir);
                T.True(!d.Readable && d.PendingReadable && d.Unreadable.Contains("baseline.json"), "saved data: an unreadable baseline is noticed");
                // Codex round 5: meta.json too (without it every kind looks never read in full).
                File.WriteAllText(Path.Combine(dir, "baseline.json"), "{}");
                File.WriteAllText(Path.Combine(dir, "meta.json"), "<<garbage>>");
                d = ArgusData.Load(dir);
                T.True(!d.Readable && d.Unreadable.Contains("meta.json"), "saved data: an unreadable meta.json is noticed");
                File.WriteAllText(Path.Combine(dir, "meta.json"), "null");
                T.True(!ArgusData.Load(dir).Readable, "saved data: a file that parses to nothing is unreadable");
                File.WriteAllText(Path.Combine(dir, "meta.json"), "{}");
                // Rows that parse but can't be used.
                File.WriteAllText(Path.Combine(dir, "pending.json"), "{ \"k\": null }");
                d = ArgusData.Load(dir);
                T.True(!d.PendingReadable && d.Pending.Count == 0, "saved data: a missing finding makes the pending list unreadable (and it isn't used)");
                File.WriteAllText(Path.Combine(dir, "pending.json"), "{ \"k\": { \"Key\": \"other\", \"Now\": { \"Key\": \"other\" } } }");
                T.True(!ArgusData.Load(dir).PendingReadable, "saved data: a finding filed under another key");
                File.WriteAllText(Path.Combine(dir, "pending.json"), "{ \"k\": { \"Key\": \"k\", \"Now\": { \"Key\": \"k\" } } }");
                T.True(ArgusData.Load(dir).Readable, "saved data: a well-formed finding loads");
            }
            finally { T.Cleanup(dir); }

            // Cerberus checks first sightings on a worker thread and hands them back.
            using (var started = new System.Threading.ManualResetEvent(false))
            using (var release = new System.Threading.ManualResetEvent(false))
            {
                var worker = new SightingWorker(app => { started.Set(); release.WaitOne(5000); app.Verified = true; }, 1);
                try
                {
                    T.True(worker.TryAdd(new Sighting { Probe = new AppNet { Path = "a" } }), "worker: takes a sighting");
                    started.WaitOne(5000);
                    T.True(worker.TryAdd(new Sighting { Probe = new AppNet { Path = "b" } }), "worker: queues one while busy");
                    T.True(!worker.TryAdd(new Sighting { Probe = new AppNet { Path = "c" } }), "worker: a full queue says no (the sampler checks that one itself)");
                    Sighting got;
                    T.True(!worker.TryTake(out got), "worker: nothing finished while the check runs");
                    release.Set();
                    worker.Finish(TimeSpan.FromSeconds(10));
                    var paths = new List<string>();
                    while (worker.TryTake(out got)) { if (got.Probe.Verified) paths.Add(got.Probe.Path); }
                    T.Eq("a,b", string.Join(",", paths), "worker: both checked and handed back in order");
                }
                finally { release.Set(); worker.Dispose(); }
            }
            // Codex round 5: a check that throws hands back an unverified result, and the next one still runs.
            var sturdy = new SightingWorker(app =>
            {
                app.Verified = true; app.SignerId = "half-done";
                if (app.Path == "bad") throw new InvalidOperationException("boom");
            }, 4);
            try
            {
                sturdy.TryAdd(new Sighting { Probe = new AppNet { Path = "bad" } });
                sturdy.TryAdd(new Sighting { Probe = new AppNet { Path = "good" } });
                sturdy.Finish(TimeSpan.FromSeconds(10));
                Sighting r1, r2;
                bool got1 = sturdy.TryTake(out r1), got2 = sturdy.TryTake(out r2);
                T.True(got1 && got2, "worker: both sightings come back after a failure");
                T.True(r1.Probe.Path == "bad" && !r1.Probe.Verified && r1.Probe.SignerId == null, "worker: the failed check is handed back unverified");
                T.True(r2.Probe.Path == "good" && r2.Probe.Verified, "worker: the next check still runs");
            }
            finally { sturdy.Dispose(); }
        }

        static void VersionedPaths()
        {
            string claudeOld = Path.Combine(WindowsApps, @"Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe");
            string claudeNew = Path.Combine(WindowsApps, @"Claude_6.28899.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe");
            T.True(Versioned.IsUpdate(claudeOld, claudeNew), "versioned: newer MSIX package");
            T.True(!Versioned.IsUpdate(claudeNew, claudeOld), "versioned: an older package is a rollback");
            T.True(!Versioned.IsUpdate(claudeOld, claudeNew.Replace("pzs8sxrjxfjjc", "aaaaaaaaaaaaa")), "versioned: another publisher's package");
            T.True(!Versioned.IsUpdate(claudeOld, claudeNew.Replace("Claude_", "Clawde_")), "versioned: another package name");
            T.True(!Versioned.IsUpdate(claudeOld, claudeNew.Replace("_x64_", "_x86_")), "versioned: another architecture");
            T.True(!Versioned.IsUpdate(@"C:\Tools\Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\a.exe", @"C:\Tools\Claude_6.28899.2.0_x64__pzs8sxrjxfjjc\a.exe"),
                "versioned: package names count only under WindowsApps");
            T.True(!Versioned.InPackageOrDriverStore(Path.Combine(WindowsApps, @"Nobody_1.0.0.0_x64__aaaaaaaaaaaaa\a.exe")), "versioned: a package that isn't installed doesn't count");

            const string edgeOld = @"C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.60\Installer\setup.exe";
            string edgeNew = edgeOld.Replace("157.0.4341.60", "158.0.4370.33");
            T.True(Versioned.IsUpdate(edgeOld, edgeNew), "versioned: version folder went forward");
            T.True(!Versioned.IsUpdate(edgeNew, edgeOld), "versioned: version folder went back");
            T.True(!Versioned.InPackageOrDriverStore(edgeNew), "versioned: a version folder isn't a package layout");
            T.True(Versioned.HasVersionFolder(edgeNew), "versioned: sees a version folder");
            T.True(!Versioned.HasVersionFolder(Path.Combine(Environment.SystemDirectory, "svchost.exe")), "versioned: System32 has no version folder");
            T.True(!Versioned.IsUpdate(edgeOld, edgeNew.Replace("setup.exe", "setup2.exe")), "versioned: another program");
            T.True(!Versioned.IsUpdate(edgeOld, edgeOld.Replace("157.0.4341.60", "Temp")), "versioned: a version folder swapped for another folder");
            T.True(!Versioned.IsUpdate(edgeOld, edgeNew.Replace(@"\Installer\", @"\Installer\x\")), "versioned: an extra folder");
            T.True(!Versioned.IsUpdate(edgeOld, edgeNew.Replace("Program Files (x86)", "program files (x86)")), "versioned: exact apart from versions");
            T.True(!Versioned.IsUpdate(@"C:\A\1.0\B\2.0\x.exe", @"C:\A\1.1\B\2.1\x.exe"), "versioned: only one version folder may change");
            T.True(!Versioned.IsUpdate(edgeOld, edgeOld), "versioned: unchanged");
            T.True(!Versioned.IsUpdate(null, edgeOld), "versioned: null");
            T.True(Versioned.IsUpdate(@"C:\Users\u\AppData\Local\Discord\app-1.0.9175\Discord.exe", @"C:\Users\u\AppData\Local\Discord\app-1.0.9180\Discord.exe"),
                "versioned: app-<version> folder");
            T.True(!Versioned.IsUpdate(@"C:\Users\u\AppData\Local\Discord\app-1.0.9175\Discord.exe", @"C:\Users\u\AppData\Local\Discord\web-1.0.9180\Discord.exe"),
                "versioned: another prefix");
            T.True(!Versioned.IsUpdate(@"C:\Data\tenant-123456789012\agent.exe", @"C:\Data\tenant-123456789013\agent.exe"), "versioned: IDs aren't versions");
            T.True(!Versioned.IsUpdate(@"C:\X\deadbeefcafe0001\a.exe", @"C:\X\deadbeefcafe0002\a.exe"), "versioned: hashes outside the driver store aren't versions");
            // Spotting other versions (for blocks) compares paths the way Windows does, in either direction.
            T.True(Versioned.SameFamily(edgeOld, edgeNew.Replace("Program Files (x86)", "PROGRAM FILES (X86)").Replace("setup.exe", "SETUP.EXE")), "family: case doesn't matter");
            T.True(Versioned.SameFamily(edgeNew, edgeOld), "family: an older version is related too");
            T.True(!Versioned.SameFamily(edgeOld, edgeOld.Replace("setup.exe", "other.exe")), "family: another program isn't");
            T.True(!Versioned.SameFamily(edgeOld, edgeOld), "family: the same path isn't another version");
            T.True(Versioned.HasVersionFolder(claudeNew.Replace("Claude_6.28899.2.0_x64__pzs8sxrjxfjjc", "CLAUDE_6.28899.2.0_X64__PZS8SXRJXFJJC")),
                "versioned: a package folder in capitals still counts as a version (for spotting blocks)");

            // Task entry hashes: every field carries its length, so text inside one can't pass for a boundary.
            T.Eq("3:abc", Collector.Field("abc"), "hash field: length-prefixed");
            T.Eq("0:", Collector.Field(null), "hash field: empty");
            T.True(Collector.Field("a") + Collector.Field("b:c") != Collector.Field("a:1:b") + Collector.Field("c"), "hash field: no two splits read the same");
        }

        static void PlainPathsAndLaunch()
        {
            T.True(Versioned.PlainLocalPath(@"C:\Program Files\App\app.exe"), "plain path: ordinary");
            foreach (var bad in new[]
            {
                @"%ProgramFiles%\App\app.exe", "app.exe", @"C:app.exe", @"\App\app.exe", @"\\server\share\app.exe", "C:/Program Files/app.exe",
                @"C:\PROGRA~1\App\app.exe", @"C:\App\app.exe:stream", @"C:\App.\app.exe", @"C:\App \app.exe", @"C:\App\..\Windows\app.exe",
                @"C:\App\.\app.exe", @"C:\App\NUL\app.exe", @"C:\App\con.txt", "C:\\App\\a\tb.exe", @"C:\\App\app.exe",
                "C:\\App\\COM\u00B9\\a.exe", "C:\\App\\LPT\u00B3.log", @"C:\App\CONIN$\a.exe"
            })
                T.True(!Versioned.PlainLocalPath(bad), "plain path: rejects " + bad);

            string img, rest;
            T.True(Versioned.SplitLaunch("\"C:\\Program Files\\App\\1.0\\app.exe\" --run", false, out img, out rest)
                && img == @"C:\Program Files\App\1.0\app.exe" && rest == " --run", "launch: quoted path and arguments");
            T.True(Versioned.SplitLaunch(@"C:\Windows\app.exe -k x", false, out img, out rest) && img == @"C:\Windows\app.exe" && rest == " -k x",
                "launch: unquoted path without spaces");
            T.True(!Versioned.SplitLaunch(@"C:\Program Files\App\app.exe", false, out img, out rest) || img != @"C:\Program Files\App\app.exe",
                "launch: an unquoted path with spaces isn't read as one path");
            T.True(!Versioned.SplitLaunch("\"C:\\App\\app.exe\"x", false, out img, out rest), "launch: text glued to the closing quote");
            T.True(!Versioned.SplitLaunch("\"C:\\App\\app.exe", false, out img, out rest), "launch: no closing quote");
            T.True(!Versioned.SplitLaunch(" \"C:\\App\\app.exe\"", false, out img, out rest), "launch: leading space");
            T.True(!Versioned.SplitLaunch("\"%ProgramFiles%\\App\\app.exe\"", false, out img, out rest), "launch: environment variables");
            T.True(Versioned.SplitLaunch(@"\SystemRoot\System32\drivers\x.sys", true, out img, out rest)
                && img.EndsWith(@"\System32\drivers\x.sys", StringComparison.OrdinalIgnoreCase) && Versioned.PlainLocalPath(img), "launch: \\SystemRoot\\ for drivers");
            T.True(!Versioned.SplitLaunch(@"\SystemRoot\System32\drivers\x.sys", false, out img, out rest), "launch: \\SystemRoot\\ only where allowed");
            T.True(!Versioned.SplitLaunch(@"\SystemRoot\C:\Evil\x.sys", true, out img, out rest), "launch: \\SystemRoot\\ takes only a relative path");
            T.True(!Versioned.SplitLaunch(@"\SystemRoot\\Evil\x.sys", true, out img, out rest), "launch: \\SystemRoot\\ rejects a rooted rest");

            string temp = Path.GetTempPath();
            T.True(temp.IndexOf('~') < 0 || Versioned.LongPath(temp).IndexOf('~') < 0, "long path: expands 8.3 aliases");
            T.Eq(@"C:\No\Alias", Versioned.LongPath(@"C:\No\Alias"), "long path: leaves a missing path alone");
        }

        static void AdminOnly()
        {
            T.True(Versioned.AdminOnlyFolder(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), Siblings.None), "admin-only: a System32 file");
            T.True(Versioned.AdminOnlyFolder(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), Siblings.Files), "admin-only: System32 with the files beside it");
            string ps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            if (File.Exists(ps)) T.True(Versioned.AdminOnlyFolder(ps, Siblings.Tree), "admin-only: a Windows folder tree");
            using (var held = Versioned.Protect(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), Siblings.None))
            {
                T.True(held.Ok && held.Leaf != null && !held.Leaf.IsInvalid, "protect: holds the program open");
                var s = Signature.CheckHeld(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), held.Leaf);
                T.True(s.Signed && s.Trusted && !string.IsNullOrEmpty(s.Id), "protect: verifies the signature through the held handle");
            }
            T.True(Versioned.FolderLocked(Environment.SystemDirectory), "folder: System32 is locked down");
            T.True(!Versioned.FolderLocked(@"C:\"), "folder: a drive root that lets users create folders isn't");
            T.True(!Versioned.FolderLocked("C:") && !Versioned.FolderLocked(Environment.SystemDirectory.Substring(0, 2)), "folder: a bare drive (its current folder) isn't a folder Argus can check");
            T.True(!Versioned.FolderLocked(Environment.SystemDirectory.ToUpperInvariant() + @"\NO-SUCH-FOLDER"), "folder: a missing folder isn't");
            string dir = Versioned.LongPath(T.TempDir("admin-only"));
            try
            {
                string file = Path.Combine(dir, "app.exe");
                File.WriteAllText(file, "test fixture");
                T.True(!Versioned.AdminOnlyFolder(file, Siblings.None), "admin-only: your own temp folder is not");
                T.True(!Versioned.AdminOnlyFolder(Path.Combine(dir, "missing.exe"), Siblings.None), "admin-only: a missing file is not");
                T.True(!Versioned.FolderLocked(dir), "folder: your own temp folder is not");

                // A held folder can't be renamed away (Codex round 3: metadata-only handles wouldn't stop it).
                string a = Path.Combine(dir, "held"), b2 = Path.Combine(dir, "moved");
                Directory.CreateDirectory(a);
                bool blocked;
                using (var h = Versioned.OpenFolder(a))
                {
                    T.True(!h.IsInvalid, "protect: opens a folder handle");
                    try { Directory.Move(a, b2); blocked = false; }
                    catch (IOException) { blocked = true; }
                    catch (UnauthorizedAccessException) { blocked = true; }
                }
                T.True(blocked, "protect: a held folder can't be renamed");
                Directory.Move(a, b2);
                T.True(Directory.Exists(b2), "protect: once released it can");
            }
            finally { T.Cleanup(dir); }
            T.True(!Versioned.AdminOnlyFolder(@"\\server\share\app.exe", Siblings.None), "admin-only: network paths are not");
            T.True(!Versioned.AdminOnlyFolder(@"relative\app.exe", Siblings.None), "admin-only: relative paths are not");
            T.True(!Versioned.AdminOnlyFolder(null, Siblings.None), "admin-only: null");
        }

        static void Drivers()
        {
            string drvOld = Path.Combine(DriverStore, @"usb4hostrouter.inf_amd64_038bb1143cb55632\Usb4HostRouter.sys");
            string drvNew = Path.Combine(DriverStore, @"usb4hostrouter.inf_amd64_7a94a6c59dc12f81\Usb4HostRouter.sys");
            T.True(Versioned.IsUpdate(drvOld, drvNew), "drivers: another driver-store copy of the same INF (ordered by DriverVer)");
            T.True(!Versioned.IsUpdate(drvOld, drvNew.Replace("usb4hostrouter.inf", "evil.inf")), "drivers: another driver package");
            T.True(!Versioned.IsUpdate(@"C:\Drivers\usb4hostrouter.inf_amd64_038bb1143cb55632\x.sys", @"C:\Drivers\usb4hostrouter.inf_amd64_7a94a6c59dc12f81\x.sys"),
                "drivers: driver-store names count only in the driver store");
            T.True(Versioned.InDriverStore(drvNew) && Versioned.InPackageOrDriverStore(drvNew), "drivers: driver-store layout");
            T.True(Versioned.LaterDriver("10.0.26100.9000,2006-06-21", "10.0.26100.10068,2006-06-21"), "drivers: a higher DriverVer version");
            T.True(Versioned.LaterDriver("10.0.1.0,2026-01-01", "10.0.1.0,2026-02-01"), "drivers: the same version dated later");
            T.True(!Versioned.LaterDriver("10.0.26100.10068,2006-06-21", "10.0.26100.9000,2026-11-11"), "drivers: a lower version is a rollback");
            T.True(!Versioned.LaterDriver(null, "10.0.1.0,2026-02-01"), "drivers: no DriverVer on record means review");
            T.True(!Versioned.LaterDriver("10.0.1.0,2026-02-01", "10.0.1.0,2026-02-01"), "drivers: the same package isn't an update");
            // DriverVer from the [Version] section only (Codex round 3: an install section's own DriverVer overrides it).
            T.Eq("10.0.1.5,2026-11-11", Versioned.DriverVerOf("[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nDriverVer = 11/11/2026,10.0.1.5 ; the package\r\n[Manufacturer]\r\n%Std%=Models\r\n"),
                "drivers: DriverVer in [Version]");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=11/11/2026,10.0.1.5\n[Install.NT]\nDriverVer=01/01/2020,9.0.0.0\n") == null, "drivers: an install section with its own DriverVer is ambiguous");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=11/11/2026,10.0.1.5\nDriverVer=11/12/2026,10.0.1.6\n") == null, "drivers: two DriverVer lines are ambiguous");
            T.True(Versioned.DriverVerOf("[Strings]\nDriverVer=11/11/2026,10.0.1.5\n") == null, "drivers: DriverVer outside [Version] doesn't count");
            T.True(Versioned.DriverVerOf("[Version]\n;DriverVer=11/11/2026,10.0.1.5\n") == null, "drivers: a commented-out DriverVer doesn't count");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=%ver%\n") == null, "drivers: an unreadable DriverVer means review");
            // Codex round 4: the INF format's exact shape (four parts 0-65534, not 0.0.0.0; either date separator).
            T.Eq("10.0.1.5,2026-11-11", Versioned.DriverVerOf("[Version]\nDriverVer=11-11-2026,10.0.1.5\n"), "drivers: a dash-separated date");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=11/11/2026,2.0\n") == null, "drivers: fewer than four parts");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=11/11/2026,10.0.1.65535\n") == null, "drivers: a part above 65534");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=11/11/2026,0.0.0.0\n") == null, "drivers: 0.0.0.0");
            T.True(Versioned.DriverVerOf("[Version]\nDriverVer=11/11-2026,10.0.1.5\n") == null, "drivers: mixed date separators");
            var current = Directory.Exists(DriverStore) ? Directory.GetDirectories(DriverStore, "usb4hostrouter.inf_amd64_*").FirstOrDefault() : null;
            if (current != null)
            {
                string sys = Directory.GetFiles(current, "*.sys").FirstOrDefault();
                if (sys != null) T.True(Versioned.DriverVer(sys) != null, "drivers: reads a real DriverVer (" + Versioned.DriverVer(sys) + ")");
            }
        }

        static void SignerIdentity()
        {
            string a = Signature.IdOf(new byte[] { 1, 2 }, new byte[] { 3 }), b = Signature.IdOf(new byte[] { 1 }, new byte[] { 2, 3 });
            T.True(a != null && a != b, "signer id: subject and issuer key stay apart");
            T.Eq(a, Signature.IdOf(new byte[] { 1, 2 }, new byte[] { 3 }), "signer id: stable");
            T.True(Signature.IdOf(null, new byte[] { 1 }) == null, "signer id: needs both parts");
            var k1 = Signature.CheckNow(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
            var k2 = Signature.CheckNow(Path.Combine(Environment.SystemDirectory, "ntdll.dll"));
            T.True(k1.Signed && k1.Trusted && !string.IsNullOrEmpty(k1.Id) && !string.IsNullOrEmpty(k1.Publisher), "signer id: a Windows file has a verified identity");
            T.True(k1.Id == k2.Id, "signer id: two Windows files share the publisher's identity");
            T.Eq(-1, Signature.CheckNow(@"C:\No\Such\File.exe").Code, "signature: a missing file");
        }

        static void Settings()
        {
            var svc = new Item { Category = "service", Enabled = true };
            svc.Extra["start"] = "automatic"; svc.Extra["type"] = "16"; svc.Extra["account"] = "LocalSystem";
            string s = Engine.SettingsOf(svc);
            T.Eq("enabled=1;start=automatic;type=16;account=LocalSystem", s, "settings: a service's");
            T.True(Engine.SettingsKnown(svc), "settings: a current scan records them all");
            T.True(!Engine.SameSettings(s, "enabled=1;start=automatic"), "settings: an older record without type or account doesn't compare (one review)");
            T.True(!Engine.SameSettings(s, "enabled=1;start=manual;type=16;account=LocalSystem"), "settings: another start mode differs");
            T.True(!Engine.SameSettings(s, "enabled=1;start=automatic;type=16;account=.\\someone"), "settings: another account differs");
            // Codex round 3: an account that disappears (Windows' default, LocalSystem) is a change too.
            svc.Extra.Remove("account");
            T.Eq("enabled=1;start=automatic;type=16;account=", Engine.SettingsOf(svc), "settings: a missing account is written as the default");
            T.True(!Engine.SameSettings(s, Engine.SettingsOf(svc)), "settings: a removed account differs");
            T.True(!Engine.SameSettings("enabled=0", "enabled=1"), "settings: switched back on differs");
            T.True(!Engine.SameSettings(null, s) && !Engine.SameSettings("start=automatic", s), "settings: nothing on record means review");
            var older = new Item { Category = "service", Enabled = true };
            older.Extra["start"] = "automatic";
            T.True(!Engine.SettingsKnown(older), "settings: an item from before type was recorded isn't complete");
            var run = new Item { Category = "run", Enabled = true };
            run.Extra["kind"] = "ExpandString";
            T.Eq("enabled=1;kind=ExpandString", Engine.SettingsOf(run), "settings: a startup entry's value type counts");
            T.True(!Engine.SettingsKnown(new Item { Category = "run" }), "settings: a startup entry without its value type isn't complete");
            T.Eq("enabled=0", Engine.SettingsOf(new Item { Category = "task", Enabled = false }), "settings: a task's");
            // Turning an entry off records what the next scan will see, so that isn't taken for a change.
            var running = new Item { Category = "service", Enabled = true };
            running.Extra["start"] = "automatic"; running.Extra["type"] = "16"; running.Extra["account"] = "LocalSystem";
            T.Eq("enabled=0;start=disabled;type=16;account=LocalSystem", Engine.TurnedOffSettings(running), "settings: a service once turned off");
            T.Eq("enabled=0", Engine.TurnedOffSettings(new Item { Category = "task", Enabled = true }), "settings: a task once turned off");
            T.True(Engine.TurnedOffSettings(older) == null, "settings: an incomplete item records nothing (filled in by the next scan)");

            // What a change of settings alone means (the command is as accepted).
            string sev, why;
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            Func<string, Item> svcItem = start =>
            {
                var i = new Item { Category = "service", Command = "\"" + notepad + "\"", Target = notepad, Signed = true, Trusted = true, Signer = "Contoso Ltd", Enabled = start != "disabled" };
                i.Extra["start"] = start; i.Extra["type"] = "16";
                return i;
            };
            string auto = Engine.SettingsOf(svcItem("automatic")), off = Engine.SettingsOf(svcItem("disabled")), manual = Engine.SettingsOf(svcItem("manual"));
            T.True(Engine.SettingsRisk(auto, off, svcItem("disabled"), false, i => false, out sev) == null, "settings change: switched off is routine");
            why = Engine.SettingsRisk(off, auto, svcItem("automatic"), false, i => false, out sev);
            T.True(why != null && why.Contains("switched back on") && Sev.Rank(sev) >= Sev.Rank(Sev.Notice), "settings change: switched back on gets a look");
            T.True(Engine.SettingsRisk(off, auto, svcItem("automatic"), false, i => true, out sev) == null, "settings change: switched on is routine for a verified Microsoft program");
            // Codex round 4: an entry you turned off that comes back on always gets a look, whoever signed it.
            why = Engine.SettingsRisk(off, auto, svcItem("automatic"), true, i => true, out sev);
            T.True(why != null && sev == Sev.Warning && why.Contains("turned it off"), "settings change: switched back on after you turned it off is a warning");
            T.True(Engine.SettingsRisk(auto, off, svcItem("disabled"), true, i => true, out sev) == null, "settings change: staying off after you turned it off is quiet");
            why = Engine.SettingsRisk(manual, auto, svcItem("automatic"), false, i => false, out sev);
            T.True(why != null && why.Contains("start mode"), "settings change: a new start mode gets a look");
            var other = svcItem("automatic"); other.Extra["account"] = @".\someone";
            why = Engine.SettingsRisk(auto, Engine.SettingsOf(other), other, false, i => true, out sev);
            T.True(why != null && sev == Sev.Warning && why.Contains("runs as"), "settings change: a new account is always a warning");
            var expand = new Item { Category = "run", Enabled = true }; expand.Extra["kind"] = "ExpandString";
            var plain = new Item { Category = "run", Enabled = true }; plain.Extra["kind"] = "String";
            why = Engine.SettingsRisk(Engine.SettingsOf(plain), Engine.SettingsOf(expand), expand, false, i => true, out sev);
            T.True(why != null && sev == Sev.Warning && why.Contains("value type"), "settings change: a new registry value type is always a warning");

            // Codex round 4: on upgrade, the previous scan's record of what it did see (on or off, start mode) counts.
            var lastScan = new Item { Category = "run", Enabled = false };
            var today = new Item { Category = "run", Enabled = true }; today.Extra["kind"] = "String";
            T.Eq("enabled=0;kind=String", Engine.MergedSettings(lastScan, today), "settings: an older scan's on/off state with today's value type");
            var lastSvc = new Item { Category = "service", Enabled = true }; lastSvc.Extra["start"] = "manual";
            var todaySvc = svcItem("automatic");
            T.Eq("enabled=1;start=manual;type=16;account=", Engine.MergedSettings(lastSvc, todaySvc), "settings: an older scan's start mode counts");
        }

        static void ArgusRoutine()
        {
            string root = Versioned.LongPath(T.TempDir("argus-routine"));
            try
            {
                string v1 = Path.Combine(root, @"Contoso\1.0.0\app.exe"), v2 = Path.Combine(root, @"Contoso\2.0.0\app.exe");
                string s1 = Path.Combine(root, @"Con toso\1.0.0\app.exe"), s2 = Path.Combine(root, @"Con toso\2.0.0\app.exe");
                string ps1 = Path.Combine(root, @"Contoso\1.0.0\powershell.exe"), ps2 = Path.Combine(root, @"Contoso\2.0.0\powershell.exe");
                foreach (var f in new[] { v1, v2, s1, s2, ps1, ps2 }) { Directory.CreateDirectory(Path.GetDirectoryName(f)); File.WriteAllText(f, "test fixture"); }
                Func<string, SignerInfo> good = p => new SignerInfo { Signed = true, Trusted = true, Publisher = "Contoso Ltd", Id = "contoso-id" };
                Func<BaselineEntry> before = () => new BaselineEntry { Command = "\"" + v1 + "\" --run", Signer = "Contoso Ltd", Trusted = true, Category = "service", SignerId = "contoso-id", Settings = "enabled=1;start=automatic;type=16;account=" };
                Func<Item> now = () =>
                {
                    var i = new Item
                    {
                        Key = @"service|HKLM\SYSTEM\CurrentControlSet\Services|Contoso", Category = "service", Name = "Contoso",
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services", Command = "\"" + v2 + "\" --run", Target = v2,
                        Signer = "Contoso Ltd", Signed = true, Trusted = true, SignerId = "contoso-id", Enabled = true
                    };
                    i.Extra["start"] = "automatic";
                    i.Extra["type"] = "16";
                    return i;
                };
                SignerInfo v;
                T.True(Engine.RoutineUpdate(before(), now(), good, out v) && v != null && v.Id == "contoso-id", "argus routine: same verified signer, newer version folder");
                T.True(!Engine.RoutineUpdate(before(), now(), p => null, out v), "argus routine: not when the program or its folders aren't admin-only");
                T.True(!Engine.RoutineUpdate(before(), now(), p => new SignerInfo { Signed = true, Trusted = true, Publisher = "Contoso Ltd", Id = "other-id" }, out v),
                    "argus routine: another certificate identity needs review");
                T.True(!Engine.RoutineUpdate(before(), now(), p => new SignerInfo { Signed = true, Trusted = true, Publisher = "Someone Else", Id = "contoso-id" }, out v),
                    "argus routine: another publisher name needs review");
                T.True(!Engine.RoutineUpdate(before(), now(), p => new SignerInfo { Signed = true, Trusted = false, Publisher = "Contoso Ltd", Id = "contoso-id" }, out v),
                    "argus routine: an invalid signature needs review");
                T.True(!Engine.RoutineUpdate(before(), now(), p => new SignerInfo { Signed = true, Trusted = true, Publisher = null, Id = "contoso-id" }, out v),
                    "argus routine: an unknown publisher needs review");
                var b = before(); b.SignerId = null;
                T.True(!Engine.RoutineUpdate(b, now(), good, out v), "argus routine: an old baseline outside a package layout gets one review");
                b = before(); b.Trusted = false;
                T.True(!Engine.RoutineUpdate(b, now(), good, out v), "argus routine: an untrusted baseline needs review");

                // Execution settings (Codex rounds 2 and 3): exactly the settings on record, or review.
                var it = now();
                b = before(); b.Settings = "enabled=0;start=automatic;type=16;account=";
                T.True(!Engine.RoutineUpdate(b, it, good, out v), "argus routine: an update that also switches the entry on needs review");
                it = now(); it.Extra["start"] = "boot";
                T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: a new start mode needs review");
                it = now(); it.Extra["account"] = "LocalSystem";
                T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: a new account needs review");
                b = before(); b.Settings = "enabled=1;start=automatic;type=16;account=NT AUTHORITY\\LocalService";
                T.True(!Engine.RoutineUpdate(b, now(), good, out v), "argus routine: a removed account (now LocalSystem) needs review");
                b = before(); b.Settings = null;
                T.True(!Engine.RoutineUpdate(b, now(), good, out v), "argus routine: an entry with no settings on record gets one review (no previous-scan stand-in)");
                it = now(); it.Extra.Remove("type");
                T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: an item without all its settings needs review");

                it = now(); it.Command = "\"" + v2 + "\" --run --extra";
                T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: changed arguments need review");
                b = before(); b.Command = "\"" + v2 + "\" --config C:\\Profiles\\1.0\\settings.json";
                it = now(); it.Command = "\"" + v2 + "\" --config C:\\Profiles\\2.0\\settings.json";
                T.True(!Engine.RoutineUpdate(b, it, good, out v), "argus routine: a version change inside the arguments needs review");
                b = before(); b.Command = "\"" + v1 + "\" --config C:\\Profiles\\1.0\\settings.json";
                T.True(!Engine.RoutineUpdate(b, it, good, out v), "argus routine: a program update plus changed arguments needs review");
                b = before(); b.Command = "\"" + v2 + "\" --run";
                it = now(); it.Command = "\"" + v1 + "\" --run"; it.Target = v1;
                T.True(!Engine.RoutineUpdate(b, it, good, out v), "argus routine: going back a version needs review");
                it = now(); it.Target = Path.Combine(root, @"Contoso\2.0.0\helper.dll");
                T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: the verified file must be the program itself (not a hosted DLL)");
                it = now(); it.Why = "it runs from a temp folder";
                T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: a suspicious command needs review");
                foreach (var cat in new[] { "task", "startup", "winlogon", "ifeo", "wmi" })
                {
                    it = now(); it.Category = cat;
                    T.True(!Engine.RoutineUpdate(before(), it, good, out v), "argus routine: never for " + cat + " entries");
                }
                b = before(); b.Command = "\"" + s1 + "\" --run";
                it = now(); it.Command = s2 + " --run"; it.Target = s2;
                T.True(!Engine.RoutineUpdate(b, it, good, out v), "argus routine: an unquoted path with spaces needs review");
                b = before(); b.Command = "\"" + ps1 + "\" -File x.ps1";
                it = now(); it.Command = "\"" + ps2 + "\" -File x.ps1"; it.Target = ps2;
                T.True(!Engine.RoutineUpdate(b, it, good, out v), "argus routine: script runners always need review");
                T.True(!Engine.RoutineUpdate(null, now(), good, out v), "argus routine: needs a baseline");
                T.True(!Engine.RoutineUpdate(before(), now(), null, out v), "argus routine: needs the protected-file check");

                // Entries Argus kept on its own are verified again every scan (Codex round 3: from a held handle,
                // with the neighbour check that justified keeping them).
                var keptUpdate = new BaselineEntry { SignerId = "contoso-id", AutoKept = true, KeptBy = "update" };
                var keptNew = new BaselineEntry { SignerId = "contoso-id", AutoKept = true, KeptBy = "signature" };
                Siblings asked = Siblings.None;
                SignerInfo held;
                Func<string, Siblings, SignerInfo> verify = (p, s) => { asked = s; return new SignerInfo { Signed = true, Trusted = true, Publisher = "Contoso Ltd", Id = "contoso-id" }; };
                T.True(Engine.LostTrust(keptUpdate, now(), verify, out held) == null && asked == Siblings.Tree && held != null, "trust: a kept update still verifies (whole folder tree)");
                // A new entry is kept on its signature only when it's Microsoft's own code, so its re-check expects that.
                Func<string, Siblings, SignerInfo> msVerify = (p, s) => { asked = s; return new SignerInfo { Signed = true, Trusted = true, Publisher = "Microsoft Windows", Id = "contoso-id",
                    Issuer = "Microsoft Windows Production PCA 2026 RSA2048-SHA256", Root = "3B1EFD3A66EA28B16697394703A72CA340A05BD5" }; };
                T.True(Engine.LostTrust(keptNew, now(), msVerify, out held) == null && asked == Siblings.Files, "trust: a kept new entry still verifies (the files beside it)");
                var gone = now(); gone.Target = Path.Combine(root, @"Contoso\3.0.0\app.exe");
                T.Eq(Engine.TrustGone, Engine.LostTrust(keptUpdate, gone, verify, out held), "trust: the program is gone");
                gone.Target = Path.Combine(root, @"NoSuchFolder\app.exe");
                T.Eq(Engine.TrustGone, Engine.LostTrust(keptUpdate, gone, verify, out held), "trust: its folder is gone too");
                T.True(Engine.LostTrust(keptUpdate, now(), (p, s) => null, out held) != null, "trust: its folders can be changed now");
                T.True(Engine.LostTrust(keptUpdate, now(), (p, s) => new SignerInfo { Signed = true, Trusted = true, Publisher = "Contoso Ltd", Id = "other-id" }, out held) != null, "trust: another signer identity");
                T.True(Engine.LostTrust(keptUpdate, now(), (p, s) => new SignerInfo { Signed = true, Trusted = false, Publisher = "Contoso Ltd", Id = "contoso-id" }, out held) != null
                    && held != null && !held.Trusted, "trust: the signature no longer verifies (and the finding gets that result)");
                T.True(Engine.LostTrust(keptUpdate, now(), (p, s) => new SignerInfo { Signed = true, Trusted = true, Publisher = "Contoso Ltd" }, out held) != null, "trust: no verified identity");
                // Codex round 4: a task kept because it starts in an admin-only folder must still do so.
                var task = now(); task.Category = "task"; task.Extra["action"] = "exec"; task.Extra["workdir"] = root;
                string lostWhy = Engine.LostTrust(keptNew, task, msVerify, out held);
                T.True(lostWhy != null && lostWhy.Contains("folder"), "trust: a kept task whose working folder you can now change");
                task.Extra["workdir"] = Environment.SystemDirectory;
                T.True(Engine.LostTrust(keptNew, task, msVerify, out held) == null, "trust: a kept task still starting in System32");
            }
            finally { T.Cleanup(root); }

            // A baseline from before identities were recorded counts inside an installed MSIX package (CoworkVMService, 11-20).
            string pOld = Path.Combine(WindowsApps, @"Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe");
            string pNew = Path.Combine(WindowsApps, @"Claude_6.28899.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe");
            if (Versioned.InPackageOrDriverStore(pNew))
            {
                var li = new Item
                {
                    Key = @"service|HKLM\SYSTEM\CurrentControlSet\Services|CoworkVMService", Category = "service", Name = "CoworkVMService",
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services", Command = "\"" + pNew + "\"", Target = pNew,
                    Signer = "Anthropic, PBC", Signed = true, Trusted = true, Enabled = true
                };
                li.Extra["start"] = "automatic";
                li.Extra["type"] = "16";
                // No signer identity on record (accepted before identities), settings recorded while unchanged.
                var lb = new BaselineEntry { Command = "\"" + pOld + "\"", Signer = "Anthropic, PBC", Trusted = true, Category = "service", Settings = Engine.SettingsOf(li) };
                SignerInfo lv;
                T.True(Engine.RoutineUpdate(lb, li, p => new SignerInfo { Signed = true, Trusted = true, Publisher = "Anthropic, PBC", Id = "anthropic-id" }, out lv),
                    "argus routine: an old baseline inside an installed MSIX package");
            }
        }

        static void ArgusComRetire()
        {
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            var pending = new Finding
            {
                Key = "task", Kind = "new", Severity = Sev.Notice, ComRawHash = "raw-1",
                Now = new Item { Category = "task", Hash = "same", Target = notepad }
            };
            pending.Now.Extra["comActionsUnverified"] = "yes";
            var current = new Item { Key = "task", Category = "task", Hash = "same", Command = "COM handler", Target = notepad, Signed = true, Trusted = true, Microsoft = true, Signer = "Microsoft Windows" };
            current.Extra["inboxCom"] = "yes";
            current.Extra["comRawHash"] = "raw-1";
            current.Extra["actions"] = "1";
            T.True(Engine.CanRetireComNotice(pending, current, null), "packaged COM: a notice retires once the same data verifies");
            current.Extra["comRawHash"] = "raw-2";
            T.True(!Engine.CanRetireComNotice(pending, current, null), "packaged COM: data that changed since the notice keeps it open");
            current.Extra["comRawHash"] = "raw-1";
            pending.ComRawHash = null;
            T.True(!Engine.CanRetireComNotice(pending, current, null), "packaged COM: a notice without its data on record stays open");
            pending.ComRawHash = "raw-1";
            current.Extra.Remove("inboxCom");
            T.True(!Engine.CanRetireComNotice(pending, current, null), "packaged COM: still unverified, still open");
            current.Extra["inboxCom"] = "yes";
            pending.Now.Extra.Remove("comActionsUnverified");
            T.True(!Engine.CanRetireComNotice(pending, current, null), "packaged COM: other notices don't retire this way");
            T.True(!Engine.CanRetireComNotice(pending, null, null), "packaged COM: needs the current entry");
        }

        static void ArgusOccurrences()
        {
            var p = new Finding { Key = "t", Kind = "new", ComRawHash = "raw-1", Now = new Item { Category = "task", Hash = "h" } };
            var it = new Item { Category = "task", Hash = "h" };
            it.Extra["comRawHash"] = "raw-1";
            T.True(Engine.SameOccurrence(p, it), "occurrence: same COM data is the same finding");
            it.Extra["comRawHash"] = "raw-2";
            T.True(!Engine.SameOccurrence(p, it), "occurrence: new COM data with the same command is a new finding (its own alert)");
            it.Extra["comRawHash"] = "raw-1";
            it.Extra["inboxCom"] = "yes";
            T.True(!Engine.SameOccurrence(p, it), "occurrence: a change in verification is a new finding");
            var legacy = new Finding { Key = "t", Kind = "new", Now = new Item { Category = "task", Hash = "h" } };
            T.True(!Engine.SameOccurrence(legacy, it), "occurrence: a finding from before data was recorded is looked at again");
            T.True(Engine.SameOccurrence(new Finding { Now = new Item { Category = "run" } }, new Item { Category = "run" }), "occurrence: other entries are unchanged");

            // Codex round 3: settings count too, so a dismissal of a switched-off entry doesn't cover it once on.
            Func<bool, string, Item> svc = (on, account) =>
            {
                var i = new Item { Category = "service", Hash = "s", Enabled = on };
                i.Extra["start"] = on ? "automatic" : "disabled"; i.Extra["type"] = "16";
                if (account != null) i.Extra["account"] = account;
                return i;
            };
            var ps = new Finding { Key = "s", Kind = "new", Now = svc(false, null) };
            T.True(Engine.SameOccurrence(ps, svc(false, null)), "occurrence: same settings, same finding");
            T.True(!Engine.SameOccurrence(ps, svc(true, null)), "occurrence: switched on is a new finding");
            T.True(!Engine.SameOccurrence(new Finding { Now = svc(true, "LocalSystem") }, svc(true, null)), "occurrence: a removed account is a new finding");
            var older = new Item { Category = "service", Hash = "s", Enabled = true };
            older.Extra["start"] = "automatic";
            T.True(Engine.SameOccurrence(new Finding { Now = older }, svc(true, "LocalSystem")), "occurrence: a finding from before type and account were recorded compares what it has");
            T.True(!Engine.SameOccurrence(new Finding { Now = older }, svc(false, null)), "occurrence: ...including whether it was on");
        }

        static void ArgusNewEntries()
        {
            T.True(Engine.IsInterpreter("POWERSHELL.EXE", null), "interpreter: by name");
            T.True(Engine.IsInterpreter("updater.exe", "PowerShell.EXE.MUI"), "interpreter: a renamed copy, by the name it was built under");
            T.True(Engine.IsInterpreter("x.exe", "Cmd.Exe"), "interpreter: renamed cmd");
            T.True(!Engine.IsInterpreter("updater.exe", "updater.exe"), "interpreter: an ordinary program");
            T.True(!Engine.IsInterpreter(null, null), "interpreter: nothing");

            string why;
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            Func<string, Item> ms = cat => new Item { Category = cat, Command = "\"" + notepad + "\"", Target = notepad, Signed = true, Trusted = true, Microsoft = true, Signer = "Microsoft Windows" };
            T.Eq(Sev.Info, Engine.Rate(ms("run"), "new", null, out why), "rate: a new startup entry for a Microsoft program in System32 is routine");
            var loose = ms("run"); loose.Command = Environment.SystemDirectory + @"\..\" + Path.GetFileName(Environment.SystemDirectory) + @"\notepad.exe /x";
            T.Eq(Sev.Notice, Engine.Rate(loose, "new", null, out why), "rate: a startup entry whose program can't be read exactly gets a look");
            // Codex round 3: a signature doesn't vouch for what arguments point the program at.
            var args = ms("run"); args.Command += @" C:\Users\Public\plugin.cfg";
            T.Eq(Sev.Notice, Engine.Rate(args, "new", null, out why), "rate: a new startup entry passing arguments gets a look");
            T.True(why.Contains("arguments"), "rate: says it's the arguments");
            var taskArgs = ms("task"); taskArgs.Extra["actions"] = "1"; taskArgs.Extra["action"] = "exec"; taskArgs.Command += " /config x";
            T.Eq(Sev.Notice, Engine.Rate(taskArgs, "new", null, out why), "rate: a new task passing arguments gets a look");
            T.Eq(Sev.Notice, Engine.Rate(ms("startup"), "new", null, out why), "rate: a new startup-folder shortcut gets a look");
            var task = ms("task"); task.Extra["actions"] = "2"; task.Extra["action"] = "exec";
            T.Eq(Sev.Notice, Engine.Rate(task, "new", null, out why), "rate: a new task with two actions gets a look");
            task = ms("task"); task.Extra["actions"] = "1"; task.Extra["action"] = "com"; task.Command = "COM handler {00000000-0000-0000-0000-000000000000}";
            T.Eq(Sev.Notice, Engine.Rate(task, "new", null, out why), "rate: a new COM task that isn't a verified Windows handler gets a look");
            task.Extra["inboxCom"] = "yes";
            T.Eq(Sev.Info, Engine.Rate(task, "new", null, out why), "rate: a verified inbox COM task is routine");
            string dir = Versioned.LongPath(T.TempDir("argus-new"));
            try
            {
                task = ms("task"); task.Extra["actions"] = "1"; task.Extra["action"] = "exec"; task.Extra["workdir"] = dir;
                T.Eq(Sev.Notice, Engine.Rate(task, "new", null, out why), "rate: a new task starting in a folder you can write to gets a look");
                string exe = Path.Combine(dir, "OneDriveStandaloneUpdater.exe");
                File.WriteAllText(exe, "test fixture");
                var user = new Item { Category = "run", Command = "\"" + exe + "\"", Target = exe, Signed = true, Trusted = true, Microsoft = true, Signer = "Microsoft Corporation" };
                T.Eq(Sev.Notice, Engine.Rate(user, "new", null, out why), "rate: a new Microsoft-signed entry in a folder you can write to gets a look");
                T.True(why.Contains("folder"), "rate: says why");
            }
            finally { T.Cleanup(dir); }
        }

        static void CerberusClassify()
        {
            string oldPath = Path.Combine(WindowsApps, @"Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\app\claude.exe");
            string midPath = Path.Combine(WindowsApps, @"Claude_6.20000.0.0_x64__pzs8sxrjxfjjc\app\claude.exe");
            string newPath = Path.Combine(WindowsApps, @"Claude_6.28899.2.0_x64__pzs8sxrjxfjjc\app\claude.exe");
            var known = new List<AppNet>
            {
                new AppNet { Path = Path.Combine(Environment.SystemDirectory, "svchost.exe"), Signer = "Microsoft Windows", SignerId = "ms", Verified = true, Connections = 5 },
                new AppNet { Path = oldPath, Signer = "Anthropic, PBC", SignerId = "anthropic", Verified = true, Connections = 5 }
            };
            Func<HashSet<string>> none = () => new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var app = new AppNet { Path = newPath, Signer = "Anthropic, PBC", SignerId = "anthropic", Verified = true };
            AppNet earlier;
            T.Eq(NetEngine.PathKind.Update, NetEngine.Classify(known, app, none, out earlier), "cerberus: a verified newer version is not a first connection");
            T.True(earlier != null && earlier.Path == oldPath, "cerberus: names the earlier version");
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(known, app, () => new HashSet<string>(new[] { oldPath }, StringComparer.OrdinalIgnoreCase), out earlier),
                "cerberus: a blocked app's new version is reported");
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(known, new AppNet { Path = midPath, Signer = "Anthropic, PBC", SignerId = "anthropic", Verified = true },
                () => new HashSet<string>(new[] { newPath }, StringComparer.OrdinalIgnoreCase), out earlier),
                "cerberus: a block on a newer version counts too, even with an allowed older one");
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(new List<AppNet>(), app, () => new HashSet<string>(new[] { oldPath }, StringComparer.OrdinalIgnoreCase), out earlier),
                "cerberus: a block counts even when the app's record is gone");
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(known, new AppNet { Path = newPath, Signer = null }, () => new HashSet<string>(new[] { oldPath }, StringComparer.OrdinalIgnoreCase), out earlier),
                "cerberus: a block counts whoever signed the new file");
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(known, app, () => null, out earlier), "cerberus: unreadable firewall rules still report");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(known, new AppNet { Path = newPath, Signer = "Anthropic, PBC", SignerId = "anthropic", Verified = false }, none, out earlier),
                "cerberus: not when the new file isn't verified");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(known, new AppNet { Path = newPath, Signer = "Anthropic, PBC", SignerId = "other", Verified = true }, none, out earlier),
                "cerberus: not with another certificate identity");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(new List<AppNet> { new AppNet { Path = oldPath, Signer = "Anthropic, PBC" } }, app, none, out earlier),
                "cerberus: an app recorded before identities gets one notice");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(new List<AppNet> { app }, new AppNet { Path = oldPath, Signer = "Anthropic, PBC", SignerId = "anthropic", Verified = true }, none, out earlier),
                "cerberus: an older version is not an update");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(known, new AppNet { Path = newPath }, none, out earlier), "cerberus: unsigned");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(known, new AppNet { Path = Path.Combine(Environment.SystemDirectory, "curl.exe"), Signer = "Microsoft Windows" }, none, out earlier),
                "cerberus: a path with no version folder is simply new");
            // Codex round 3: rule paths compare as Windows paths; unreadable rules count any other version seen.
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(known, app, () => new HashSet<string>(new[] { oldPath.ToUpperInvariant() }, StringComparer.OrdinalIgnoreCase), out earlier),
                "cerberus: a block on the same app in other letter case counts");
            T.Eq(NetEngine.PathKind.BlockedUpdate, NetEngine.Classify(new List<AppNet> { new AppNet { Path = oldPath } }, new AppNet { Path = newPath }, () => null, out earlier),
                "cerberus: unreadable rules report any other version seen, signed or not");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(new List<AppNet>(), app, () => null, out earlier), "cerberus: unreadable rules, nothing related seen: simply new");
            // Driver-store programs: a later version needs a later DriverVer (no silent rollback).
            string dOld = Path.Combine(DriverStore, @"contoso.inf_amd64_038bb1143cb55632\helper.exe"), dNew = Path.Combine(DriverStore, @"contoso.inf_amd64_7a94a6c59dc12f81\helper.exe");
            var dKnown = new List<AppNet> { new AppNet { Path = dOld, Signer = "Contoso", SignerId = "c", Verified = true, DriverVer = "2.0.0.0,2026-01-01", Connections = 3 } };
            T.Eq(NetEngine.PathKind.Update, NetEngine.Classify(dKnown, new AppNet { Path = dNew, Signer = "Contoso", SignerId = "c", Verified = true, DriverVer = "2.1.0.0,2026-02-01" }, none, out earlier),
                "cerberus: a driver package's later version is an update");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(dKnown, new AppNet { Path = dNew, Signer = "Contoso", SignerId = "c", Verified = true, DriverVer = "1.0.0.0,2025-01-01" }, none, out earlier),
                "cerberus: an older driver package is not an update");
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(dKnown, new AppNet { Path = dNew, Signer = "Contoso", SignerId = "c", Verified = true }, none, out earlier),
                "cerberus: a driver package without a readable DriverVer is not an update");
            // Codex round 4: with versions 1 and 3 known, a first-seen version 2 is a rollback, not an update.
            string v1 = @"C:\Program Files\Contoso\1.0.0\app.exe", v2 = v1.Replace("1.0.0", "2.0.0"), v3 = v1.Replace("1.0.0", "3.0.0");
            var both = new List<AppNet>
            {
                new AppNet { Path = v1, Signer = "Contoso", SignerId = "c", Verified = true, Connections = 2 },
                new AppNet { Path = v3, Signer = "Contoso", SignerId = "c", Verified = true, Connections = 2 }
            };
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(both, new AppNet { Path = v2, Signer = "Contoso", SignerId = "c", Verified = true }, none, out earlier),
                "cerberus: an older version than one already seen is not an update");
            T.Eq(NetEngine.PathKind.Update, NetEngine.Classify(both, new AppNet { Path = v1.Replace("1.0.0", "4.0.0"), Signer = "Contoso", SignerId = "c", Verified = true }, none, out earlier),
                "cerberus: a version newer than all seen is");
            var dTwo = new List<AppNet>(dKnown) { new AppNet { Path = Path.Combine(DriverStore, @"contoso.inf_amd64_1111111111111111\helper.exe"), Signer = "Contoso", SignerId = "c", Verified = true, DriverVer = "3.0.0.0,2026-03-01" } };
            T.Eq(NetEngine.PathKind.New, NetEngine.Classify(dTwo, new AppNet { Path = dNew, Signer = "Contoso", SignerId = "c", Verified = true, DriverVer = "2.1.0.0,2026-02-01" }, none, out earlier),
                "cerberus: a driver package older than one already seen is not an update");
            T.True(Firewall.RuleName(@"C:\A\1.0\app.exe") != Firewall.RuleName(@"C:\A\2.0\app.exe"), "cerberus: each blocked path gets its own rule name");
            string rule = Firewall.RuleName(@"C:\A\1.0\app.exe");
            T.True(rule.StartsWith("Cerberus: block app.exe (", StringComparison.Ordinal) && rule.Length == "Cerberus: block app.exe (".Length + 17, "cerberus: rule names carry a 64-bit path hash");
        }

        static void ReviewStatus()
        {
            string dir = T.TempDir("argus-status");
            try
            {
                var finding = new Finding { Key = "k", AlertId = "0123456789abcdef", Severity = Sev.Warning, Kind = "changed" };
                J.Save(Path.Combine(dir, "pending.json"), new Dictionary<string, Finding> { { "k", finding } });
                // Older statuses (no "open" list): the pending list from the same folder, if the count matches.
                var st = new StatusInfo { State = States.Warn, Summary = "untouched", Facts = new Dictionary<string, object> { { "pending", 2 } } };
                ArgusAlertReview.ApplyStatus(st, dir);
                T.Eq("untouched", st.Summary, "review status: a pending list from another scan is left alone");
                st.Facts["pending"] = 1;
                ArgusAlertReview.ApplyStatus(st, null);
                T.Eq("untouched", st.Summary, "review status: needs the status's own folder");
                ArgusAlertReview.ApplyStatus(st, dir);
                T.True(st.State == States.Warn && st.Summary == "1 change to review", "review status: counts the open finding from the same scan");
                // Newer statuses name the findings they counted, so a replaced pending list can't be mixed in.
                st = new StatusInfo { State = States.Alert, Summary = "untouched", Facts = new Dictionary<string, object> { { "pending", 1 }, { "open", "fedcba9876543210:critical" } } };
                ArgusAlertReview.ApplyStatus(st, dir);
                T.True(st.State == States.Alert && st.Summary.StartsWith("1 serious change", StringComparison.Ordinal),
                    "review status: uses the status's own list, not the pending file (same count, other finding)");
                ArgusAlertReview.ApplyStatus(null, dir);

                // Codex round 3: the window's summary comes from the very list its rows come from.
                st = new StatusInfo { State = States.Ok, Summary = "No unexpected changes" };
                ArgusAlertReview.ApplyFindings(st, new[] { new Finding { Key = "k", AlertId = "0123456789abcdef", Severity = Sev.Critical } });
                T.True(st.State == States.Alert && st.Summary.StartsWith("1 serious change", StringComparison.Ordinal), "window summary: a newer critical row isn't shown under a green summary");
                st = new StatusInfo { State = States.Warn, Summary = "2 changes to review" };
                ArgusAlertReview.ApplyFindings(st, new Finding[0]);
                T.True(st.State == States.Ok && st.Summary == "No unreviewed changes", "window summary: nothing listed, nothing to review");
                st = new StatusInfo { State = States.Ok, Summary = "Baseline taken: watching for changes" };
                ArgusAlertReview.ApplyFindings(st, new Finding[0]);
                T.Eq("Baseline taken: watching for changes", st.Summary, "window summary: other good news is kept");
            }
            finally { T.Cleanup(dir); }

            // Only well-formed alert IDs reach an elevated Argus.
            T.True(Actions.ValidList(null) && Actions.ValidList("0123456789abcdef,fedcba9876543210"), "alert IDs: a valid list");
            T.True(!Actions.ValidList("") && !Actions.ValidList("0123456789abcdef --action accept-all") && !Actions.ValidList("0123456789ABCDEF") && !Actions.ValidList("0123456789abcdef,"),
                "alert IDs: anything else is refused");
        }
    }
}
