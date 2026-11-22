// Tests for Argus, Sibyl and the apps that follow (pure logic: no network, no system changes).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Olympus.Argus;
using Olympus.Sibyl;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class ArgusTests
    {
        public static void Run()
        {
            string exe, rest;
            Targets.Split(@"""C:\Program Files\X\a.exe"" -b", out exe, out rest);
            T.Eq(@"C:\Program Files\X\a.exe", exe, "split: quoted");
            T.Eq(" -b", rest, "split: rest");
            string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            T.Eq(notepad, Targets.Resolve("notepad.exe /x"), "resolve: bare name found in System32");
            T.Eq(notepad, Targets.Resolve(@"%SystemRoot%\system32\notepad.exe"), "resolve: env vars");
            T.True(string.Equals(Path.Combine(Environment.SystemDirectory, "shell32.dll"), Targets.Resolve(@"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL"), StringComparison.OrdinalIgnoreCase), "resolve: rundll32 points at the dll");
            T.True(string.Equals(Path.Combine(Environment.SystemDirectory, @"drivers\acpi.sys"), Targets.Resolve(@"\SystemRoot\System32\drivers\acpi.sys"), StringComparison.OrdinalIgnoreCase), "resolve: \\SystemRoot\\ prefix");

            T.True(Engine.Suspicion(@"""C:\Users\x\AppData\Local\Temp\a.exe""", @"C:\Users\x\AppData\Local\Temp\a.exe").Contains("temp"), "suspicion: temp folder");
            T.True(Engine.Suspicion("powershell.exe -w hidden -enc SQBFAFgA", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe").Contains("PowerShell"), "suspicion: encoded PowerShell");
            T.True(Engine.Suspicion(@"mshta.exe http://x.example/a.hta", @"C:\Windows\System32\mshta.exe").Contains("script host"), "suspicion: mshta");
            T.Eq("", Engine.Suspicion(@"""C:\Program Files\Steam\steam.exe"" -silent", @"C:\Program Files\Steam\steam.exe"), "suspicion: normal program");

            string why;
            var proxy = new Item { Category = "proxy", Command = "proxy 127.0.0.1:8888", Name = "Internet proxy" };
            proxy.Extra["enabled"] = "yes";
            T.Eq(Sev.Critical, Engine.Rate(proxy, "changed", null, out why), "rate: proxy turned on is critical");
            proxy.Extra["enabled"] = "no";
            proxy.Extra["pac"] = "";
            T.Eq(Sev.Info, Engine.Rate(proxy, "changed", null, out why), "rate: proxy off is routine");
            var ms = new Item { Category = "task", Command = "\"" + notepad + "\"", Target = notepad, Signed = true, Trusted = true, Microsoft = true, Signer = "Microsoft Windows" };
            ms.Extra["actions"] = "1";
            ms.Extra["action"] = "exec";
            T.Eq(Sev.Info, Engine.Rate(ms, "new", null, out why), "rate: a one-action task running a Microsoft program from System32 is routine");

            var legacy = new Finding
            {
                Key = "task", Kind = "new", Severity = Sev.Notice,
                Now = new Item { Category = "task", Hash = "same", Target = "COM", Missing = true }
            };
            ms.Key = legacy.Key;
            ms.Hash = legacy.Now.Hash;
            ms.Extra["inboxCom"] = "yes";
            T.True(Engine.CanRetireComNotice(legacy, ms, null), "packaged COM: retire an unchanged legacy missing-file notice");
            T.True(Engine.CanRetireComNotice(legacy, ms, new BaselineEntry { Hash = ms.Hash }), "packaged COM: retry after an interrupted save");
            T.True(!Engine.CanRetireComNotice(legacy, ms, new BaselineEntry { Hash = "different" }), "packaged COM: a real baseline change needs review");
            ms.Extra["comActionsUnverified"] = "yes";
            T.Eq(Sev.Notice, Engine.Rate(ms, "new", null, out why), "packaged COM: unverified actions still require review");
            T.True(!Engine.CanRetireComNotice(legacy, ms, null), "packaged COM: retirement needs full verification");
            ms.Extra.Remove("comActionsUnverified");
            ms.Trusted = false;
            T.True(!Engine.CanRetireComNotice(legacy, ms, null), "packaged COM: registry identity alone is insufficient");
            ms.Trusted = true;
            ms.Hash = "different";
            T.True(!Engine.CanRetireComNotice(legacy, ms, null), "packaged COM: a changed task is still a finding");
            ms.Hash = legacy.Now.Hash;
            legacy.Severity = Sev.Warning;
            T.True(!Engine.CanRetireComNotice(legacy, ms, null), "packaged COM: never retire unrelated warnings");
            var trustedCom = new BaselineEntry { Hash = ms.Hash, Command = ms.Command, ComDataHash = "original-data" };
            ms.Extra["comDataHash"] = trustedCom.ComDataHash;
            T.True(!Engine.PackagedComChanged(trustedCom, ms), "packaged COM: identical verified data stays routine");
            ms.Extra["comDataHash"] = "new-data";
            T.True(Engine.PackagedComChanged(trustedCom, ms), "packaged COM: detect changed data without changing the command hash");
            T.Eq(Sev.Warning, Engine.Rate(ms, "changed", trustedCom, out why), "packaged COM: changed data needs review");
            ms.Extra["comDataHash"] = trustedCom.ComDataHash;
            ms.Extra.Remove("inboxCom");
            T.True(Engine.PackagedComChanged(trustedCom, ms), "packaged COM: loss of verification needs review");
            var baseline = new BaselineEntry { Command = "x /old", Signer = ms.Signer, Trusted = true };
            T.Eq(Sev.Warning, Engine.Rate(ms, "changed", baseline, out why), "rate: changed command needs review with the same publisher");
            T.True(why.Contains("command changed"), "rate: changed command reason");
            baseline.Command = ms.Command;
            T.Eq(Sev.Warning, Engine.Rate(ms, "changed", baseline, out why), "rate: changed execution settings need review");
            var unsigned = new Item { Category = "run", Command = "x", Target = notepad, Signed = false };
            T.Eq(Sev.Warning, Engine.Rate(unsigned, "new", null, out why), "rate: unsigned startup entry is a warning");
            var gone = new Item { Category = "run", Command = "x", Target = @"C:\nope\missing.exe", Signed = false };
            T.Eq(Sev.Notice, Engine.Rate(gone, "new", null, out why), "rate: missing program is only a notice");
            var dns = new Item { Category = "dns", Name = "Ethernet (IPv4)", Command = "8.8.8.8" };
            dns.Extra["loopback"] = "no";
            dns.Extra["adapter"] = "Ethernet";
            T.Eq(Sev.Critical, Engine.Rate(dns, "changed", null, out why), "rate: DNS moved off Aegis is critical");
            var forced = new Item { Category = "policy", Name = @"Chrome: ExtensionInstallForcelist\1", Command = "abc;https://x" };
            T.Eq(Sev.Critical, Engine.Rate(forced, "new", null, out why), "rate: forced extension policy is critical");

            T.True(Engine.OnlyOldQuoting("\"\\\"C:\\Program Files\\AMD\\x.exe\\\"\" -Check", "\"C:\\Program Files\\AMD\\x.exe\" -Check"), "migration: the old double-quoting is cosmetic");
            T.True(!Engine.OnlyOldQuoting("\"C:\\Program Files\\AMD\\x.exe\" -Check", "C:\\Program Files\\AMD\\x.exe -Check"), "migration: dropping quotes is still a real change");
            T.True(!Engine.OnlyOldQuoting("\"\\\"C:\\a.exe\\\"\" -Check", "\"C:\\b.exe\" -Check"), "migration: a different program is a real change");
            T.True(!Engine.OnlyOldQuoting("\"\\\"C:\\Program Files\\AMD\\x.exe\\\"\" \"-Check\"", "\"C:\\Program Files\\AMD\\x.exe\" -Check"), "migration: changes to argument quoting need review");
            T.True(Targets.Resolve("/UserInstall") == null, "resolve: options alone aren't a program");
            T.True(Targets.Resolve("U") == null, "resolve: a one-letter stub isn't a program");
            string ps = Targets.Resolve("powershell.exe -NoProfile -File C:\\x\\job.ps1");
            T.True(ps != null && ps.EndsWith(@"WindowsPowerShell\v1.0\powershell.exe", StringComparison.OrdinalIgnoreCase), "resolve: powershell.exe found on the PATH (" + ps + ")");
            var script = new Item { Category = "task", Command = "powershell.exe -NoProfile -File C:\\x\\job.ps1", Target = ps, Signed = true, Trusted = true, Microsoft = true, Signer = "Microsoft Windows" };
            T.Eq(Sev.Notice, Engine.Rate(script, "new", null, out why), "rate: a script through PowerShell isn't waved through as Microsoft-signed");
            T.True(Engine.RunsScript(script), "rate: PowerShell counts as a script runner");
            T.True(Engine.Suspicion("powershell.exe -NoP -W Hidden -File x.ps1", ps).Contains("hidden"), "suspicion: hidden-window PowerShell");
            T.True(Collector.HostsEntries("# c\n127.0.0.1 localhost # x\n\n  0.0.0.0   ads.example  \n").SequenceEqual(new[] { "127.0.0.1 localhost", "0.0.0.0 ads.example" }), "hosts: comments and spacing ignored");
            T.True(Collector.CertFromBlob(null) == null, "cert blob: null is fine");
            T.Eq("startup entries", Engine.Plural("run"), "plural: entries");
        }
    }

    static class SibylTests
    {
        public static void Run()
        {
            Psl.UseBuiltinForTests();
            T.Eq("example.co.uk", Psl.Registrable("www.shop.example.co.uk"), "psl: co.uk");
            T.Eq("evil.github.io", Psl.Registrable("a.evil.github.io"), "psl: github.io is a suffix");
            T.Eq("paypal.com", Psl.Registrable("www.paypal.com"), "psl: plain .com");

            string how;
            T.Eq("PayPal", Lookalike.Imitates("paypa1.com", "paypa1.com", out how), "lookalike: digit for letter");
            T.Eq("PayPal", Lookalike.Imitates("paypa1-secure-login.xyz", "paypa1-secure-login.xyz", out how), "lookalike: brand word inside a longer name");
            T.Eq("PayPal", Lookalike.Imitates("www.paypal.com.account-check.top", "www.paypal.com.account-check.top", out how), "lookalike: brand as a subdomain");
            T.Eq("Discord", Lookalike.Imitates("dlscord.gift", "dlscord.gift", out how), "lookalike: l for i");
            T.Eq("PayPal", Lookalike.Imitates("xn--pypal-4ve.com", "p\u0430ypal.com", out how), "lookalike: Cyrillic a");
            T.True(Lookalike.Imitates("www.paypal.com", "www.paypal.com", out how) == null, "lookalike: the real site");
            T.True(Lookalike.Imitates("pineapple.com", "pineapple.com", out how) == null, "lookalike: pineapple isn't Apple");
            T.True(Lookalike.Imitates("steamcommunity.com", "steamcommunity.com", out how) == null, "lookalike: real Steam");
            T.Eq("Steam", Lookalike.Imitates("steamcommunlty.com", "steamcommunlty.com", out how), "lookalike: steamcommunlty");

            T.Eq("https://example.com/a", Links.Unwrap(new Uri("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fa&data=x")), "unwrap: Outlook safelinks");
            T.Eq("https://example.com/", Links.Unwrap(new Uri("https://www.google.com/url?q=https://example.com/&sa=D")), "unwrap: Google");
            T.True(Links.Unwrap(new Uri("https://example.com/?url=https://evil.example")) == null, "unwrap: only known wrappers");
            T.Eq("http://bit.ly/abc", Links.Normalize("bit.ly/abc"), "normalize: adds http");
            T.True(Links.Normalize("hello there") == null, "normalize: words aren't links");
            T.Eq(2, Links.Find("see https://a.example/x, and www.b.example.").Count, "find: two links in text");

            var r = new LinkReport();
            Links.Static(r, new Uri("http://user@paypa1.xyz/login"), true);
            T.True(r.Flags.Any(f => f.Text.Contains("decoy")), "static: @ decoy");
            T.True(r.Flags.Any(f => f.Text.Contains("PayPal")), "static: lookalike flagged");
            T.True(r.Score >= 60, "static: adds up to dangerous (" + r.Score + ")");

            var m = Scam.Check("Hi! I paid through PayPal, the payment is pending until you upgrade to a business account. I'll send my own courier. Text me on WhatsApp +1 555 123 4567");
            T.Eq("dangerous", m.Verdict, "scam: eBay fake-payment message");
            T.True(m.Flags.Any(f => f.Text.Contains("pending")), "scam: pending payment");
            T.Eq(1, m.Phones.Count, "scam: phone number found");
            T.Eq("dangerous", Scam.Check("Hey, I accidentally reported your Steam account, talk to the admin on discord to fix it urgently").Verdict, "scam: accidental report");
            T.Eq("suspicious", Scam.Check("USPS: your package is on hold due to an address issue. Update here: usps-redelivery.top").Verdict == "ok" ? "ok" : "suspicious", "scam: delivery text");
            T.Eq("ok", Scam.Check("Hey! Are we still on for dinner Friday at 7?").Verdict, "scam: normal message");
        }
    }
}
