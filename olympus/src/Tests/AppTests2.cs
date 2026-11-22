// Tests for Ares, Athena, Cerberus and Arachne (pure logic: no system changes).
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Olympus.Ares;
using Olympus.Athena;
using Olympus.Cerberus;
using Olympus.Arachne;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class LaterTests
    {
        public static void Run()
        {
            // Ares: leak growth
            var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var mb = new List<long>();
            var at = new List<DateTime>();
            for (int i = 0; i < 60; i++) { mb.Add(3000 + i * 40); at.Add(t0.AddMinutes(i)); }   // +2.4 GB/hour, steady
            double g = LeakWatch.Growth(mb, at);
            T.True(g > 2000 && g < 2600, "leak: steady climb measured (" + (int)g + " MB/h)");
            var bumpy = mb.Select((v, i) => i == 59 ? 1000L : v).ToList();
            T.Eq(0.0, LeakWatch.Growth(bumpy, at), "leak: memory that dropped back isn't a leak");
            T.Eq(0.0, LeakWatch.Growth(mb.Take(10).ToList(), at.Take(10).ToList()), "leak: too little history");

            // Ares: what counts as a game
            var s = new AresSettings { Programs = new List<string> { "Fallout4.exe" }, Ignore = new List<string> { "wallpaper_engine", "Launcher" } };
            var roots = new List<string> { @"D:\SteamLibrary\steamapps\common\", @"C:\Program Files\Epic Games\" };
            T.True(Games.IsGame(@"D:\SteamLibrary\steamapps\common\The Outer Worlds\Indiana\Binaries\Win64\Indiana-Win64-Shipping.exe", roots, s), "game: Steam library");
            T.True(!Games.IsGame(@"D:\SteamLibrary\steamapps\common\wallpaper_engine\wallpaper64.exe", roots, s), "game: Wallpaper Engine ignored");
            T.True(!Games.IsGame(@"C:\Program Files\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe", roots, s), "game: the Epic launcher isn't a game");
            T.True(Games.IsGame(@"C:\MagnumOpus\Stock Game\Fallout4.exe", roots, s), "game: by program name anywhere");
            T.True(!Games.IsGame(@"C:\Windows\explorer.exe", roots, s), "game: explorer isn't");
            T.Eq("The Outer Worlds", Games.Friendly(@"D:\SteamLibrary\steamapps\common\The Outer Worlds\Indiana\Binaries\Win64\x.exe"), "game: friendly name from the Steam folder");

            // Athena: winget's table
            string winget = "\r   - \r   \\ \r" +
                "Name                            Id                          Version     Available   Source\r\n" +
                "------------------------------------------------------------------------------------------\r\n" +
                "7-Zip 26.02 (x64)               7zip.7zip                   26.02       26.06       winget\r\n" +
                "AMD Software                    AMD.AMDSoftware             26.6.4      26.10.1     winget\r\n" +
                "Epic Games Launcher             EpicGames.EpicGamesLauncher 1.3.161.0   1.3.210.0   winget\r\n" +
                "3 upgrades available.\r\n";
            var ups = Checks.ParseWinget(winget);
            T.Eq(3, ups.Count, "winget: three rows");
            T.Eq("7zip.7zip", ups[0].Id, "winget: id column");
            T.Eq("26.06", ups[0].Available, "winget: available column");
            T.True(Checks.Pinned(ups[1]), "winget: the AMD driver stays pinned");
            T.True(!Checks.Pinned(ups[2]), "winget: other apps aren't pinned");
            var rep = new Report();
            rep.Checks.Add(new Check { Group = "Protection", State = "good" });
            rep.Checks.Add(new Check { Group = "Protection", State = "warn" });
            rep.Checks.Add(new Check { Group = "Network", State = "info" });
            Checks.Grade(rep);
            T.Eq(75, rep.Percent, "grade: good + warn = 75%");
            T.Eq("C", rep.Grade, "grade: letter");

            // Cerberus: reading DNS-Client results
            var ips = DnsWatch.Addresses("type:  5 cdn.example.net;::ffff:93.184.216.34;2606:2800::1;");
            T.Eq(2, ips.Count, "dns results: two addresses");
            T.Eq("93.184.216.34", ips[0].ToString(), "dns results: mapped v4 unwrapped");
            T.True(DnsWatch.IsBlockAnswer(DnsWatch.Addresses("0.0.0.0;")), "dns results: Aegis block answer");
            T.True(!DnsWatch.IsBlockAnswer(DnsWatch.Addresses("1.2.3.4;0.0.0.0;")), "dns results: a real address isn't a block");

            // A dismissal follows the alert ID, so later reads by the same app still surface.
            string reviewDir = T.TempDir("arachne-review");
            try
            {
                string path = System.IO.Path.Combine(reviewDir, "dismissed-alerts.json");
                var reviewed = new AlertInfo { Id = "a1", Key = "read:example", Severity = Sev.Critical };
                var later = new AlertInfo { Id = "a2", Key = reviewed.Key, Severity = Sev.Critical };
                AlertReview.Save(path, new[] { reviewed.Id });
                AlertReview.Save(path, new[] { reviewed.Id, reviewed.Id });
                var saved = J.Load<List<string>>(path);
                T.Eq(1, saved.Count, "Arachne: dismissal is persistent and idempotent");
                string inbox = System.IO.Path.Combine(reviewDir, "inbox.json");
                var fromHub = new AlertInfo { Id = "hub", Severity = Sev.Critical };
                J.Save(inbox, new { Dismissed = new[] { fromHub.Id }, Offsets = new { } });
                string legacy = System.IO.Path.Combine(reviewDir, "arachne-dismissed.json");
                J.Save(legacy, new[] { "older-arachne-alert" });
                var dismissed = AlertReview.Read(path, inbox, legacy);
                T.True(dismissed.Contains("older-arachne-alert"), "preserve earlier Arachne dismissals");
                T.True(dismissed.Contains(fromHub.Id), "Arachne: honors a dismissal from the Olympus inbox");
                var open = ArachneAlertReview.Remaining(new[] { reviewed, later, fromHub }, dismissed).ToList();
                T.Eq(later, open.Single(), "Arachne: a later alert from the same program stays open");
                var status = new StatusInfo { State = States.Alert };
                ArachneAlertReview.ApplyStatus(status, open);
                T.Eq(States.Alert, status.State, "Arachne: unreviewed read keeps the alert badge");
                ArachneAlertReview.ApplyStatus(status, new AlertInfo[0]);
                T.Eq(States.Ok, status.State, "Arachne: reviewed alerts clear the badge");
                status.State = States.Error;
                ArachneAlertReview.ApplyStatus(status, new AlertInfo[0]);
                T.Eq(States.Error, status.State, "Arachne: dismissal cannot hide an engine failure");
            }
            finally { T.Cleanup(reviewDir); }

            // Arachne: the catalog (neutral made-up names) and who may read what
            string root = T.TempDir("tripwire");
            try
            {
                var u = new UserContext { Local = root, Roaming = root, Documents = root, Profile = root };
                var cat = Catalog.Parse(
                    "[kind:appx]\nowner = {pf}\\AppX\\Application\\appx.exe\nowner = C:\\Users\\*\\AppData\\Local\\AppX\\app-*\\appx.exe\n" +
                    "file = {local}\\AppX\\Store\\{profiles}\\Data A | AppX data ({name})\nfolder = {local}\\AppX\\Box | AppX box\n" +
                    "[everyone]\nowner = {programdata}\\Scanner\\Platform\\*\\scan.exe\n" +
                    "[decoy:one]\nfile = {documents}\\decoy.txt | a decoy\nunless = {local}\\RealApp\ncontent = id {random}\n", u);
                foreach (var p in new[] { @"AppX\Store\Default", @"AppX\Store\Profile 1", @"AppX\Store\System Profile", @"AppX\Box" }) System.IO.Directory.CreateDirectory(System.IO.Path.Combine(root, p));
                foreach (var p in new[] { @"AppX\Store\Default\Data A", @"AppX\Store\Profile 1\Data A", @"AppX\Store\System Profile\Data A" }) System.IO.File.WriteAllText(System.IO.Path.Combine(root, p), "x");
                var found = cat.Targets();
                T.Eq(3, found.Count, "catalog: two profile files plus the folder");
                T.True(found.Any(x => x.Label == "AppX data (Profile 1)"), "catalog: {name} filled in");
                T.True(!found.Any(x => x.Path.Contains("System Profile")), "catalog: only real profiles");
                T.Eq(1, cat.DecoysToPlace().Count, "catalog: decoy placed when the real app is absent");
                System.IO.Directory.CreateDirectory(System.IO.Path.Combine(root, "RealApp"));
                T.Eq(0, cat.DecoysToPlace().Count, "catalog: no decoy where the real app lives");
                var decoy = cat.Decoys[0];
                System.IO.File.WriteAllText(decoy.Path, "id 1234567890abcdef");
                T.True(!Catalog.Ours(decoy, null), "decoy: a plain file isn't ours");
                System.IO.File.SetAttributes(decoy.Path, System.IO.FileAttributes.Hidden | System.IO.FileAttributes.NotContentIndexed);
                T.True(!Catalog.Ours(decoy, null), "decoy: too short a template prefix proves nothing");
                decoy.Content = "old logins kept here {random}";
                System.IO.File.SetAttributes(decoy.Path, System.IO.FileAttributes.Normal);
                System.IO.File.WriteAllText(decoy.Path, "old logins kept here xyz");
                System.IO.File.SetAttributes(decoy.Path, System.IO.FileAttributes.Hidden | System.IO.FileAttributes.NotContentIndexed);
                T.True(Catalog.Ours(decoy, null), "decoy: hidden, unindexed and our template = ours");
                T.Eq(1, cat.DecoysToPlace().Count, "decoy: our own decoy is kept even where its folder exists");
                var old = new SetupState();
                old.Targets.Add(new Olympus.Arachne.Target { Path = decoy.Path, Decoy = true, CreatedByUs = true });
                System.IO.File.SetAttributes(decoy.Path, System.IO.FileAttributes.Normal);
                T.True(Catalog.Ours(decoy, old), "decoy: recorded as ours by the last setup");
                System.IO.File.Delete(decoy.Path);
                T.True(Tripwire.Allowed(cat, "appx", @"C:\Program Files\AppX\Application\appx.exe", null), "tripwire: the owner may read");
                T.True(Tripwire.Allowed(cat, "appx", @"C:\Users\me\AppData\Local\AppX\app-1.2\appx.exe", null), "tripwire: per-user owner with a version folder");
                T.True(!Tripwire.Allowed(cat, "appx", @"C:\Users\me\AppData\Local\Temp\appx.exe", null), "tripwire: a look-alike program elsewhere may not");
                T.True(!Tripwire.Allowed(cat, "appx", @"C:\Program Files\AppX\Application\sub\appx.exe", null), "tripwire: * doesn't cross folders");
                T.True(Tripwire.Allowed(cat, "decoy", @"C:\ProgramData\Scanner\Platform\4.18\scan.exe", null), "tripwire: everyone-readers");
                T.True(!Tripwire.Allowed(cat, "decoy", @"C:\Windows\System32\notepad.exe", null), "tripwire: nothing else opens a decoy");
                T.True(Tripwire.Allowed(cat, "appx", @"C:\Tools\x.exe", new Dictionary<string, List<string>> { { "appx", new List<string> { @"C:\Tools\x.exe" } } }), "tripwire: your own allow list");
                T.Eq("appx", Tripwire.Find(found, System.IO.Path.Combine(root, @"AppX\Box\000123.log")).Kind, "tripwire: file inside a watched folder");
                T.True(Tripwire.Find(found, System.IO.Path.Combine(root, @"AppX\Store\Default\Data A-journal")) == null, "tripwire: a different file");
            }
            finally { T.Cleanup(root); }
            var f = Tripwire.Fields("<Event><EventData><Data Name='ObjectName'>C:\\a &amp; b.txt</Data><Data Name='ProcessName'>C:\\x.exe</Data><Data Name='ProcessId'>0x1f4</Data></EventData></Event>");
            T.Eq(@"C:\a & b.txt", f["ObjectName"], "event: object name decoded");
            T.Eq("0x1f4", f["ProcessId"], "event: process id");
        }
    }
}
