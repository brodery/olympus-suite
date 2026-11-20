// Athena's checks and grading. The report runs as you (most facts are readable without admin);
// the few that need admin (BitLocker, TPM, AnyDesk's unattended access, Windows Update's queue,
// failed sign-ins, Defender attack-surface audit events) come from admin-facts.json, written
// daily by the SYSTEM task (Athena.exe --collect).
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Olympus.Athena
{
    public sealed class Check
    {
        public string Id, Group, Name, State = "unknown", Detail = "", Fix, Action, ActionLabel;
        public List<string> Items = new List<string>();
    }

    public sealed class Report
    {
        public string Time, Grade;
        public int Percent;
        public List<Check> Checks = new List<Check>();
        public List<Device> Devices = new List<Device>();
    }

    public sealed class AdminFacts
    {
        public string Time, BitLocker, Tpm, AnyDesk, UpdateError;
        public bool AnyDeskUnattended;
        public int PendingUpdates = -1, FailedSignIns = -1, AsrAudits = -1;
        public List<string> UpdateTitles = new List<string>(), AsrTop = new List<string>();
    }

    public sealed class AppUpdate
    {
        public string Name, Id, Version, Available;
    }

    static class Asr
    {
        // Microsoft's attack-surface-reduction rules that suit a home gaming PC (the ones that
        // break games, mod tools or Olympus itself are left out).
        public static readonly string[][] Recommended =
        {
            new[] { "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of vulnerable signed drivers" },
            new[] { "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from LSASS" },
            new[] { "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscriptions" },
            new[] { "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block obfuscated scripts" },
            new[] { "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript/VBScript launching downloaded programs" },
            new[] { "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block programs from email and webmail" },
            new[] { "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office apps from starting other programs" },
            new[] { "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office apps from creating programs" },
            new[] { "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office apps from injecting into other programs" },
            new[] { "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros" },
            new[] { "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from starting other programs" },
            new[] { "c1db55ab-c21a-4637-bb3f-a12568109d35", "Advanced ransomware protection" },
            new[] { "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted programs from USB drives" },
            new[] { "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block copied or impersonated system tools" }
        };

        public static Dictionary<string, int> Current(out string error)
        {
            error = null;
            var d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference"))
                    foreach (ManagementObject o in s.Get())
                        using (o)
                        {
                            var ids = o["AttackSurfaceReductionRules_Ids"] as string[];
                            var acts = o["AttackSurfaceReductionRules_Actions"] as byte[];
                            if (ids != null) for (int i = 0; i < ids.Length; i++) d[ids[i]] = acts != null && i < acts.Length ? acts[i] : 0;
                        }
            }
            catch (Exception e) { error = e.Message; }
            return d;
        }
    }

    static class Checks
    {
        static RegistryKey Hklm { get { return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); } }
        static object RegValue(string path, string name)
        {
            try { using (var k = Hklm.OpenSubKey(path)) return k == null ? null : k.GetValue(name); } catch (Exception) { return null; }
        }
        static int RegInt(string path, string name, int def) { var v = RegValue(path, name); return v is int ? (int)v : def; }
        static bool KeyExists(string path) { try { using (var k = Hklm.OpenSubKey(path)) return k != null; } catch (Exception) { return false; } }

        static Check C(string group, string id, string name) { return new Check { Group = group, Id = id, Name = name }; }

        static ManagementObject Wmi(string ns, string query)
        {
            using (var s = new ManagementObjectSearcher(ns, query))
                foreach (ManagementObject o in s.Get()) return o;
            return null;
        }

        public static Report Run(Report previous, bool network, Action<string> progress)
        {
            var r = new Report { Time = Clock.NowIso() };
            var admin = J.Load<AdminFacts>(Path.Combine(Suite.SharedDir(AppId.Athena), "admin-facts.json")) ?? J.Load<AdminFacts>(Path.Combine(Suite.UserDir(AppId.Athena), "admin-facts.json"));
            bool adminFresh = admin != null && DateTime.UtcNow - Clock.Parse(admin.Time) < TimeSpan.FromDays(3);
            Action<string, Action> Step = (what, a) =>
            {
                if (progress != null) progress(what);
                try { a(); } catch (Exception e) { Log.Warn("check " + what + ": " + e.Message); }
            };
            Step("Microsoft Defender", () => Defender(r));
            Step("firewall", () => Firewall(r));
            Step("Aegis", () => Aegis(r));
            Step("Windows settings", () => WindowsSettings(r));
            Step("admin facts", () => AdminChecks(r, admin, adminFresh));
            Step("app updates", () => AppUpdates(r));
            Step("open ports", () => Ports(r, previous));
            if (network)
            {
                Step("router port forwards", () => Router(r));
                Step("devices on your network", () => Devices(r, previous));
            }
            Step("backups and guardians", () => Guardians(r));
            Grade(r);
            return r;
        }

        static void Defender(Report r)
        {
            var c = C("Protection", "defender", "Microsoft Defender antivirus");
            var sig = C("Protection", "signatures", "Virus definitions up to date");
            var tamper = C("Protection", "tamper", "Tamper protection");
            var cloud = C("Protection", "cloud", "Cloud-delivered protection");
            var pua = C("Protection", "pua", "Adware (PUA) blocking");
            var netp = C("Protection", "netprotect", "Network protection");
            var asr = C("Protection", "asr", "Attack-surface rules");
            r.Checks.AddRange(new[] { c, sig, tamper, cloud, pua, netp, asr });
            using (var st = Wmi(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
            {
                if (st == null) { c.State = "bad"; c.Detail = "Defender isn't reporting (another antivirus may have replaced it)"; return; }
                bool rtp = st["RealTimeProtectionEnabled"] is bool && (bool)st["RealTimeProtectionEnabled"];
                c.State = rtp ? "good" : "bad";
                c.Detail = rtp ? "Real-time protection is on" : "Real-time protection is OFF";
                c.Fix = rtp ? null : "Turn it back on in Windows Security > Virus & threat protection.";
                if (!rtp) { c.Action = "open:windowsdefender://threat"; c.ActionLabel = "Open Windows Security"; }
                int age = Convert.ToInt32(st["AntivirusSignatureAge"] ?? 99);
                sig.State = age <= 2 ? "good" : age <= 7 ? "warn" : "bad";
                sig.Detail = age == 0 ? "Updated today" : age + " days old";
                if (age > 2) { sig.Fix = "Windows Security > Virus & threat protection > Check for updates."; sig.Action = "open:windowsdefender://threat"; sig.ActionLabel = "Open Windows Security"; }
                bool tp = st["IsTamperProtected"] is bool && (bool)st["IsTamperProtected"];
                tamper.State = tp ? "good" : "warn";
                tamper.Detail = tp ? "On: malware can't switch Defender off" : "Off: malware could switch Defender off";
            }
            using (var pref = Wmi(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference"))
            {
                if (pref == null) return;
                int maps = Convert.ToInt32(pref["MAPSReporting"] ?? 0), p = Convert.ToInt32(pref["PUAProtection"] ?? 0), np = Convert.ToInt32(pref["EnableNetworkProtection"] ?? 0);
                cloud.State = maps > 0 ? "good" : "warn";
                cloud.Detail = maps > 0 ? "On: new threats are recognised within seconds" : "Off: Defender only knows what's in its last update";
                pua.State = p == 1 ? "good" : "warn";
                pua.Detail = p == 1 ? "On: bundled adware installers are blocked" : p == 2 ? "Audit only" : "Off";
                netp.State = "info";
                netp.Detail = np == 1 ? "On" : np == 2 ? "Audit only" : "Off (optional: Aegis already blocks known bad sites)";
            }
            string err;
            var rules = Asr.Current(out err);
            int block = rules.Values.Count(v => v == 1 || v == 6), audit = rules.Values.Count(v => v == 2);
            var missing = Asr.Recommended.Where(x => !rules.ContainsKey(x[0])).ToList();
            asr.State = "info";
            asr.Detail = rules.Count == 0 ? "None set. These extra Defender rules stop common attack tricks; trying them in audit mode first is harmless."
                       : block + " blocking, " + audit + " in audit (watch-only) mode";
            if (missing.Count > 0) { asr.Action = "asr-audit"; asr.ActionLabel = "Try " + missing.Count + " recommended rules in audit mode"; asr.Items = missing.Select(x => x[1]).ToList(); }
            else if (audit > 0) { asr.Action = "asr-enforce"; asr.ActionLabel = "Turn on the audited rules that caused no trouble"; }
        }

        static void Firewall(Report r)
        {
            var c = C("Protection", "firewall", "Windows Firewall");
            r.Checks.Add(c);
            var off = new List<string>();
            foreach (var kv in new[] { new[] { "DomainProfile", "domain" }, new[] { "StandardProfile", "private" }, new[] { "PublicProfile", "public" } })
            {
                int pol = RegInt(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + kv[0], "EnableFirewall", -1);
                int on = pol >= 0 ? pol : RegInt(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + kv[0], "EnableFirewall", 1);
                if (on == 0) off.Add(kv[1]);
            }
            c.State = off.Count == 0 ? "good" : "bad";
            c.Detail = off.Count == 0 ? "On for all networks" : "OFF for " + string.Join(", ", off) + " networks";
            if (off.Count > 0) { c.Fix = "Windows Security > Firewall & network protection."; c.Action = "open:windowsdefender://network"; c.ActionLabel = "Open firewall settings"; }
        }

        static void Aegis(Report r)
        {
            var c = C("Protection", "aegis", "Aegis DNS filter");
            r.Checks.Add(c);
            var f = AegisClient.Status();
            if (f.Count == 0) { c.State = AegisClient.Exe == null ? "info" : "bad"; c.Detail = AegisClient.Exe == null ? "Not installed" : "Installed but its engine isn't answering"; return; }
            bool used = AegisClient.WindowsUsesAegis();
            string state;
            f.TryGetValue("state", out state);
            long updated;
            string u;
            DateTime listsAt = f.TryGetValue("updated", out u) && long.TryParse(u, out updated) && updated > 0 && updated <= 253402300799L
                ? Clock.FromUnix(updated) : DateTime.MinValue;
            TimeSpan listAge = DateTime.UtcNow - listsAt;
            bool fresh = listAge >= TimeSpan.Zero && listAge < TimeSpan.FromDays(3);
            int missing;
            if (!f.TryGetValue("missing", out u) || !int.TryParse(u, out missing)) missing = 0;
            bool failed = f.TryGetValue("update", out u) && u.StartsWith("failed", StringComparison.OrdinalIgnoreCase);
            string blocked;
            f.TryGetValue("b", out blocked);
            c.State = !used ? "bad" : state == "paused" || !fresh || failed || missing > 0 ? "warn" : "good";
            var notes = new List<string>();
            notes.Add(!used ? "Windows isn't sending its lookups to Aegis" : state == "paused" ? "Paused" : "Filtering (" + (blocked ?? "0") + " blocked today)");
            if (missing > 0) notes.Add(Fmt.Plural(missing, "configured blocklist") + " missing");
            if (failed) notes.Add("last refresh attempt failed");
            if (listsAt == DateTime.MinValue) notes.Add("blocklist age unavailable");
            else notes.Add("oldest loaded list updated " + Fmt.Ago(listsAt));
            c.Detail = string.Join(" · ", notes);
        }

        static void WindowsSettings(Report r)
        {
            var uac = C("Protection", "uac", "User Account Control");
            int lua = RegInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1), prompt = RegInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5);
            uac.State = lua == 0 ? "bad" : prompt == 0 ? "bad" : "good";
            uac.Detail = lua == 0 ? "Off: every program runs with full admin rights" : prompt == 0 ? "Set to never ask: programs get admin rights silently" : "On";
            var sb = C("Protection", "secureboot", "Secure Boot");
            int sbv = RegInt(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", -1);
            sb.State = sbv == 1 ? "good" : sbv == 0 ? "warn" : "unknown";
            sb.Detail = sbv == 1 ? "On: boot-level malware can't load" : sbv == 0 ? "Off (turn on in the BIOS; check your games' anti-cheat first)" : "Couldn't tell";
            var vbs = C("Protection", "vbs", "Memory integrity (core isolation)");
            try
            {
                using (var dg = Wmi(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard"))
                {
                    var running = dg == null ? null : dg["SecurityServicesRunning"] as uint[];
                    bool hvci = running != null && running.Contains(2u);
                    vbs.State = "info";
                    vbs.Detail = hvci ? "On" : "Off (you turned virtualization-based security off for gaming on 2026-11-07; Microsoft's vulnerable-driver blocklist still applies)";
                }
            }
            catch (Exception) { vbs.Detail = "Couldn't tell"; }
            var ss = C("Protection", "smartscreen", "SmartScreen for apps and files");
            object pol = RegValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
            string val = RegValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") as string;
            bool ssOff = (pol is int && (int)pol == 0) || "Off".Equals(val, StringComparison.OrdinalIgnoreCase);
            ss.State = ssOff ? "warn" : "good";
            ss.Detail = ssOff ? "Off: unknown downloads run without a warning" : "On";
            var rdp = C("Access", "rdp", "Remote Desktop");
            int deny = RegInt(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1);
            rdp.State = deny == 1 ? "good" : "warn";
            rdp.Detail = deny == 1 ? "Off" : "ON: this PC accepts Remote Desktop sign-ins";
            var smb = C("Access", "smb1", "Old file sharing (SMBv1)");
            int smb1Start = RegInt(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4), smb1Server = RegInt(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0);
            bool smb1 = KeyExists(@"SYSTEM\CurrentControlSet\Services\mrxsmb10") && smb1Start != 4 || smb1Server == 1;
            smb.State = smb1 ? "bad" : "good";
            smb.Detail = smb1 ? "ON: the protocol WannaCry spread through" : "Off";
            var reboot = C("Updates", "reboot", "Restart pending");
            bool pending = KeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") || KeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
            reboot.State = pending ? "warn" : "good";
            reboot.Detail = pending ? "Updates are waiting for a restart to finish installing" : "No restart needed";
            r.Checks.AddRange(new[] { uac, sb, vbs, ss, rdp, smb, reboot });
        }

        static void AdminChecks(Report r, AdminFacts a, bool fresh)
        {
            var wu = C("Updates", "windowsupdate", "Windows Update");
            var bl = C("Access", "bitlocker", "Drive encryption (BitLocker)");
            var tpm = C("Protection", "tpm", "TPM security chip");
            var any = C("Access", "anydesk", "AnyDesk remote access");
            var logons = C("Access", "signins", "Failed sign-in attempts (7 days)");
            r.Checks.AddRange(new[] { wu, bl, tpm, any, logons });
            if (a == null || !fresh)
            {
                foreach (var c in new[] { wu, bl, tpm, any, logons }) { c.State = "unknown"; c.Detail = "Needs Olympus's SYSTEM task (install Olympus)"; }
                return;
            }
            wu.State = a.PendingUpdates < 0 ? "unknown" : a.PendingUpdates == 0 ? "good" : "warn";
            wu.Detail = a.PendingUpdates < 0 ? "Couldn't check" + (a.UpdateError != null ? ": " + a.UpdateError : "") : a.PendingUpdates == 0 ? "Up to date (checked " + Fmt.Ago(Clock.Parse(a.Time)) + ")" : Fmt.Plural(a.PendingUpdates, "update") + " waiting";
            wu.Items = a.UpdateTitles;
            if (a.PendingUpdates > 0) { wu.Action = "open:ms-settings:windowsupdate"; wu.ActionLabel = "Open Windows Update"; }
            bl.State = "info";
            bl.Detail = a.BitLocker ?? "Couldn't tell";
            tpm.State = a.Tpm == null ? "unknown" : a.Tpm.StartsWith("Ready") ? "good" : "warn";
            tpm.Detail = a.Tpm ?? "Couldn't tell";
            any.State = a.AnyDesk == null ? "info" : a.AnyDeskUnattended ? "warn" : "info";
            any.Detail = a.AnyDesk == null ? "Not installed" : a.AnyDesk + (a.AnyDeskUnattended ? "; unattended access is set up, so anyone with that password can connect" : "");
            logons.State = a.FailedSignIns < 0 ? "unknown" : a.FailedSignIns > 20 ? "warn" : "good";
            logons.Detail = a.FailedSignIns < 0 ? "Couldn't check" : a.FailedSignIns == 0 ? "None" : a.FailedSignIns + (a.FailedSignIns > 20 ? " (someone may be guessing a password)" : "");
            var asr = r.Checks.FirstOrDefault(c => c.Id == "asr");
            if (asr != null && a.AsrAudits >= 0) asr.Detail += " \u00B7 " + a.AsrAudits + " audit hits this week" + (a.AsrTop.Count > 0 ? " (" + string.Join(", ", a.AsrTop) + ")" : "");
        }

        // winget's table: columns start where the header words start.
        public static List<AppUpdate> ParseWinget(string output)
        {
            var list = new List<AppUpdate>();
            var lines = output.Replace("\r", "\n").Split('\n').Select(l => l.TrimEnd()).ToList();
            int h = lines.FindIndex(l => Regex.IsMatch(l, @"\bName\s+Id\s+Version\s+Available\b"));
            if (h < 0) return list;
            string header = lines[h];
            int idCol = header.IndexOf("Id", StringComparison.Ordinal), verCol = header.IndexOf("Version", StringComparison.Ordinal), avCol = header.IndexOf("Available", StringComparison.Ordinal);
            int srcCol = header.IndexOf("Source", StringComparison.Ordinal);
            for (int i = h + 1; i < lines.Count; i++)
            {
                string l = lines[i];
                if (l.Trim().Length == 0 || l.StartsWith("---")) continue;
                if (Regex.IsMatch(l, @"^\d+ (upgrades?|packages?)") || l.Contains("upgrades available") || l.Contains("require explicit targeting")) break;
                if (l.Length <= avCol) continue;
                Func<int, int, string> Col = (a, b) => (b < 0 || b > l.Length ? l.Substring(Math.Min(a, l.Length)) : l.Substring(a, Math.Max(0, b - a))).Trim();
                list.Add(new AppUpdate { Name = Col(0, idCol), Id = Col(idCol, verCol), Version = Col(verCol, avCol), Available = Col(avCol, srcCol) });
            }
            return list.Where(x => x.Id.Length > 0 && !x.Id.Contains(" ")).ToList();
        }

        public static bool Pinned(AppUpdate u)
        {
            return Regex.IsMatch(u.Name + " " + u.Id, @"AMD Software|Adrenalin|AMD\.AMDSoftware|Radeon", RegexOptions.IgnoreCase);
        }

        static void AppUpdates(Report r)
        {
            var c = C("Updates", "apps", "App updates");
            r.Checks.Add(c);
            string winget = Path.Combine(Suite.User.Local ?? "", @"Microsoft\WindowsApps\winget.exe");
            if (!File.Exists(winget)) { c.State = "unknown"; c.Detail = "winget isn't available"; return; }
            string o;
            int code = Proc.Run(winget, "upgrade --source winget --include-unknown --disable-interactivity", out o, 120000);
            var ups = ParseWinget(o);
            if (ups.Count == 0 && code != 0 && !o.Contains("No installed package") && !o.Contains("No available upgrade")) { c.State = "unknown"; c.Detail = "Couldn't check (winget exit " + code + ")"; return; }
            var pinned = ups.Where(Pinned).ToList();
            var rest = ups.Where(u => !Pinned(u)).ToList();
            c.State = rest.Count == 0 ? "good" : "warn";
            c.Detail = rest.Count == 0 ? "Everything's current" : Fmt.Plural(rest.Count, "app") + " can be updated";
            if (pinned.Count > 0) c.Detail += " (" + pinned[0].Name + " is kept on your chosen version on purpose)";
            c.Items = rest.Select(u => u.Name + "  " + u.Version + " \u2192 " + u.Available + "  [" + u.Id + "]").ToList();
            if (rest.Count > 0) { c.Action = "winget"; c.ActionLabel = "Update apps\u2026"; }
        }

        static void Ports(Report r, Report previous)
        {
            var c = C("Network", "ports", "Programs accepting connections");
            r.Checks.Add(c);
            c.Items = Listening.Open();
            var before = previous == null ? null : previous.Checks.FirstOrDefault(x => x.Id == "ports");
            var fresh = before == null ? new List<string>() : c.Items.Except(before.Items).ToList();
            c.State = "info";
            c.Detail = c.Items.Count + " open to your network" + (fresh.Count > 0 ? "; new since last time: " + string.Join(", ", fresh) : "");
        }

        static void Router(Report r)
        {
            var c = C("Network", "upnp", "Ports forwarded by your router (UPnP)");
            r.Checks.Add(c);
            string router, error;
            var maps = Upnp.Mappings(out router, out error);
            IPAddressHolder me = IPAddressHolder.Local();
            c.Items = maps.Select(m => m.Protocol + " " + m.External + " \u2192 " + m.Internal + ":" + m.InternalPort + "  " + m.Description + (m.Enabled ? "" : " (off)") + (me != null && m.Internal == me.Text ? "  [this PC]" : "")).ToList();
            c.State = "info";
            c.Detail = error != null ? "Couldn't ask the router: " + error : maps.Count == 0 ? "None" : Fmt.Plural(maps.Count, "port") + " open from the internet" + (router != null ? " on " + router : "");
        }

        static void Devices(Report r, Report previous)
        {
            var c = C("Network", "devices", "Devices on your network");
            r.Checks.Add(c);
            var known = (previous == null ? new List<Device>() : previous.Devices).ToDictionary(d => d.Mac, d => d);
            var now = LanScan.Sweep();
            string iso = Clock.NowIso();
            var fresh = new List<Device>();
            foreach (var d in now)
            {
                Device k;
                if (known.TryGetValue(d.Mac, out k)) { d.FirstSeen = k.FirstSeen; if (d.Name == null) d.Name = k.Name; }
                else { d.FirstSeen = iso; if (known.Count > 0) fresh.Add(d); }
                d.LastSeen = iso;
            }
            foreach (var k in known.Values) if (!now.Any(d => d.Mac == k.Mac) && DateTime.UtcNow - Clock.Parse(k.LastSeen) < TimeSpan.FromDays(30)) now.Add(k);
            r.Devices = now;
            c.State = "info";
            c.Items = now.OrderBy(d => d.Ip).Select(d => d.Ip + "  " + (d.Name ?? "(no name)") + "  " + d.Mac + (d.LastSeen != iso ? "  (not seen now)" : "")).ToList();
            c.Detail = now.Count(d => d.LastSeen == iso) + " answering now" + (fresh.Count > 0 ? "; new: " + string.Join(", ", fresh.Select(d => d.Name ?? d.Ip)) : "");
            foreach (var d in fresh)
                AlertStore.Raise(AlertStore.New(Sev.Notice, "New device on your network: " + (d.Name ?? d.Ip), d.Ip + " (" + d.Mac + ") joined your home network. If you don't recognise it, change your Wi-Fi password.", "device:" + d.Mac));
        }

        static void Guardians(Report r)
        {
            var ark = C("Backups", "ark", "Backups (Ark)");
            var st = StatusStore.Read(AppId.Ark);
            bool stale = st != null && DateTime.UtcNow - st.UpdatedUtc > TimeSpan.FromHours(3);
            ark.State = st == null || States.Rank(st.State) == 3 ? "bad" : st.State == States.Ok && !stale ? "good" : "warn";
            ark.Detail = st == null ? "No backups yet" : stale ? "Last report " + Fmt.Ago(st.UpdatedUtc) + " · " + st.Summary : st.Summary;
            r.Checks.Add(ark);
            foreach (var id in new[] { AppId.Argus, AppId.Cerberus, AppId.Arachne, AppId.Janus, AppId.Ares, AppId.Atlas })
            {
                var app = AppInfo.Of(id);
                var c = C("Olympus", "g-" + app.Key, app.Name + " (" + app.Role + ")");
                var s = StatusStore.Read(id);
                if (id == AppId.Arachne) ArachneAlertReview.ApplyStatus(s, ArachneAlertReview.Open(200));
                TimeSpan max = id == AppId.Argus ? TimeSpan.FromMinutes(30) : TimeSpan.FromMinutes(20);
                if (s == null) { c.State = "warn"; c.Detail = "Hasn't run yet"; }
                else if (DateTime.UtcNow - s.UpdatedUtc > max) { c.State = "warn"; c.Detail = "Not running (last report " + Fmt.Ago(s.UpdatedUtc) + ")"; }
                else if (s.State == States.Off) { c.State = "warn"; c.Detail = "Stopped"; }
                else { c.State = s.State == States.Ok || s.State == States.Busy ? "good" : "warn"; c.Detail = s.Summary; }
                r.Checks.Add(c);
            }
        }

        public static void Grade(Report r)
        {
            double got = 0, max = 0;
            foreach (var c in r.Checks)
            {
                if (c.State != "good" && c.State != "warn" && c.State != "bad") continue;
                double w = c.Group == "Olympus" ? 0.5 : 1;
                max += w;
                got += c.State == "good" ? w : c.State == "warn" ? w / 2 : 0;
            }
            r.Percent = max == 0 ? 0 : (int)Math.Round(100 * got / max);
            r.Grade = r.Percent >= 90 ? "A" : r.Percent >= 80 ? "B" : r.Percent >= 70 ? "C" : r.Percent >= 60 ? "D" : "F";
        }

        // ------------------------------------------------------------------ the SYSTEM collector

        public static AdminFacts Collect()
        {
            var a = new AdminFacts { Time = Clock.NowIso() };
            try
            {
                using (var v = Wmi(@"root\cimv2\Security\MicrosoftVolumeEncryption", "SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter='C:'"))
                {
                    if (v != null)
                    {
                        int prot = Convert.ToInt32(v["ProtectionStatus"] ?? 2);
                        a.BitLocker = prot == 1 ? "C: is encrypted" : "C: isn't encrypted (fine for a desktop at home; matters more if it could be stolen)";
                    }
                }
            }
            catch (Exception e) { a.BitLocker = "Couldn't check: " + e.Message; }
            try
            {
                using (var t = Wmi(@"root\cimv2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm"))
                {
                    if (t == null) a.Tpm = "No TPM found";
                    else
                    {
                        bool en = t["IsEnabled_InitialValue"] is bool && (bool)t["IsEnabled_InitialValue"], act = t["IsActivated_InitialValue"] is bool && (bool)t["IsActivated_InitialValue"];
                        a.Tpm = (en && act ? "Ready" : "Present but not ready") + " (TPM " + Convert.ToString(t["SpecVersion"]).Split(',')[0] + ")";
                    }
                }
            }
            catch (Exception e) { a.Tpm = null; Log.Warn("TPM: " + e.Message); }
            try
            {
                var svc = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName.StartsWith("AnyDesk", StringComparison.OrdinalIgnoreCase));
                if (svc != null)
                {
                    using (svc) a.AnyDesk = "Installed, service " + svc.Status.ToString().ToLowerInvariant();
                    string conf = @"C:\ProgramData\AnyDesk\service.conf";
                    if (File.Exists(conf)) a.AnyDeskUnattended = Regex.IsMatch(File.ReadAllText(conf), @"^ad\.anynet\.pwd_hash=\S+", RegexOptions.Multiline);
                }
            }
            catch (Exception e) { Log.Warn("AnyDesk: " + e.Message); }
            try
            {
                object session = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session"));
                object searcher = session.GetType().InvokeMember("CreateUpdateSearcher", BindingFlags.InvokeMethod, null, session, null);
                object result = searcher.GetType().InvokeMember("Search", BindingFlags.InvokeMethod, null, searcher, new object[] { "IsInstalled=0 and IsHidden=0 and Type='Software'" });
                object updates = result.GetType().InvokeMember("Updates", BindingFlags.GetProperty, null, result, null);
                int n = (int)updates.GetType().InvokeMember("Count", BindingFlags.GetProperty, null, updates, null);
                a.PendingUpdates = n;
                for (int i = 0; i < n && i < 15; i++)
                {
                    object u = updates.GetType().InvokeMember("Item", BindingFlags.GetProperty, null, updates, new object[] { i });
                    a.UpdateTitles.Add(Convert.ToString(u.GetType().InvokeMember("Title", BindingFlags.GetProperty, null, u, null)));
                }
            }
            catch (Exception e) { a.UpdateError = e.InnerException != null ? e.InnerException.Message : e.Message; }
            try
            {
                var q = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 604800000]]]");
                int n = 0;
                using (var reader = new EventLogReader(q)) { EventRecord e; while (n < 5000 && (e = reader.ReadEvent()) != null) { e.Dispose(); n++; } }
                a.FailedSignIns = n;
            }
            catch (Exception e) { Log.Warn("failed sign-ins: " + e.Message); }
            try
            {
                var q = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, "*[System[(EventID=1122) and TimeCreated[timediff(@SystemTime) <= 604800000]]]");
                var who = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                int n = 0;
                using (var reader = new EventLogReader(q))
                {
                    EventRecord e;
                    while (n < 5000 && (e = reader.ReadEvent()) != null)
                    {
                        using (e)
                        {
                            n++;
                            var m = Regex.Match(e.ToXml(), @"<Data Name='Process Name'>([^<]*)</Data>");
                            if (m.Success) { string p = Path.GetFileName(m.Groups[1].Value); int c; who.TryGetValue(p, out c); who[p] = c + 1; }
                        }
                    }
                }
                a.AsrAudits = n;
                a.AsrTop = who.OrderByDescending(kv => kv.Value).Take(3).Select(kv => kv.Key + " \u00D7" + kv.Value).ToList();
            }
            catch (Exception e) { Log.Warn("ASR audit events: " + e.Message); }
            return a;
        }
    }

    // This PC's LAN address as text (for marking router forwards that point here).
    sealed class IPAddressHolder
    {
        public string Text;
        public static IPAddressHolder Local()
        {
            System.Net.IPAddress ip, mask, gw;
            return LanScan.Local(out ip, out mask, out gw) ? new IPAddressHolder { Text = ip.ToString() } : null;
        }
    }
}
