// Argus's engine. Each scan collects every entry, works out what program it runs and who signed
// it, and compares it with the baseline (what you've accepted). New or changed entries become
// findings to review. Routine additions and removals are accepted automatically. Changed
// commands and execution settings always go to review. "Turn it off" removes or disables
// an entry and keeps what's needed to put it back (Undo).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace Olympus.Argus
{
    public sealed class BaselineEntry
    {
        public string Hash, Signer, Command, Accepted, Name, Category, ComDataHash;
        public bool Trusted;
    }

    public sealed class Finding : ArgusPendingAlert
    {
        public string Kind, Why;
        public Item Now;
        public BaselineEntry Before;
    }

    public sealed class UndoRecord
    {
        public string Id, Key, Time, What, Category;
        public bool Undone;
        public BaselineEntry Entry;
        public Dictionary<string, string> Data = new Dictionary<string, string>();
        public string D(string k) { string v; return Data.TryGetValue(k, out v) ? v : null; }
    }

    public sealed class HistoryLine
    {
        public string Time, Event, Key, What;
    }

    sealed class SignerCacheEntry
    {
        public long Stamp;
        public bool Signed, Trusted;
        public string Publisher;
    }

    // Everything Argus remembers, in its data folder.
    sealed class ArgusData
    {
        public string Dir;
        public Dictionary<string, BaselineEntry> Baseline = new Dictionary<string, BaselineEntry>();
        public Dictionary<string, Finding> Pending = new Dictionary<string, Finding>();
        public List<UndoRecord> Undo = new List<UndoRecord>();
        public List<Item> Current = new List<Item>();
        public string LastScan, HostsGood, Complete;   // Complete: kinds read in full at least once

        string P(string f) { return Path.Combine(Dir, f); }

        public static ArgusData Load(string dir)
        {
            var d = new ArgusData { Dir = dir };
            d.Baseline = J.Load<Dictionary<string, BaselineEntry>>(d.P("baseline.json")) ?? new Dictionary<string, BaselineEntry>();
            d.Pending = J.Load<Dictionary<string, Finding>>(d.P("pending.json")) ?? new Dictionary<string, Finding>();
            d.Undo = J.Load<List<UndoRecord>>(d.P("turned-off.json")) ?? new List<UndoRecord>();
            d.Current = J.Load<List<Item>>(d.P("current.json")) ?? new List<Item>();
            var meta = J.Load<Dictionary<string, string>>(d.P("meta.json")) ?? new Dictionary<string, string>();
            meta.TryGetValue("lastScan", out d.LastScan);
            meta.TryGetValue("hostsGood", out d.HostsGood);
            meta.TryGetValue("complete", out d.Complete);
            return d;
        }

        public void Save()
        {
            J.Save(P("baseline.json"), Baseline);
            J.Save(P("pending.json"), Pending);
            J.Save(P("turned-off.json"), Undo);
            J.Save(P("current.json"), Current);
            J.Save(P("meta.json"), new Dictionary<string, string> { { "lastScan", LastScan }, { "hostsGood", HostsGood }, { "complete", Complete } });
        }

        public void History(string ev, string key, string what)
        {
            try
            {
                File.AppendAllText(P("history.jsonl"), J.Write(new HistoryLine { Time = Clock.NowIso(), Event = ev, Key = key, What = what }) + "\n", Encoding.UTF8);
            }
            catch (Exception e) { Log.Error("writing history", e); }
        }

        public List<HistoryLine> ReadHistory(int max)
        {
            var list = new List<HistoryLine>();
            try
            {
                if (!File.Exists(P("history.jsonl"))) return list;
                foreach (var line in File.ReadAllLines(P("history.jsonl")).Reverse().Take(max))
                    try { list.Add(J.Read<HistoryLine>(line)); } catch (Exception) { }
            }
            catch (Exception) { }
            return list;
        }

        // What the window shows: the installed (SYSTEM) data if there is any, else yours.
        public static ArgusData ForDisplay()
        {
            return Load(ArgusAlertReview.DisplayDirectory);
        }

        public List<Finding> VisibleFindings()
        {
            var ids = ArgusAlertReview.PendingIds(Pending.Values);
            var dismissed = AlertReview.DismissedIds();
            return Pending.Values.Where(f => !dismissed.Contains(ids[f.Key])).ToList();
        }
    }

    static class Engine
    {
        static readonly HashSet<string> ExecKinds = new HashSet<string> { "run", "startup", "task", "service", "driver", "activesetup", "winlogon", "ifeo", "wmi" };

        static readonly Regex SecuritySites = new Regex(@"\b(microsoft\.com|windowsupdate|update\.microsoft|msftncsi|defender|smartscreen|virustotal|malwarebytes|kaspersky|eset|avast|avg\.com|bitdefender|norton|mcafee|sophos|github\.com|google\.com|aegis)\b", RegexOptions.IgnoreCase);

        public static string Noun(string cat)
        {
            switch (cat)
            {
                case "run": return "startup entry";
                case "startup": return "startup-folder item";
                case "task": return "scheduled task";
                case "service": return "service";
                case "driver": return "driver";
                case "extension": return "browser extension";
                case "policy": return "browser policy";
                case "proxy": return "proxy setting";
                case "hosts": return "hosts file";
                case "dns": return "DNS setting";
                case "rootcert": return "trusted root certificate";
                case "authroot": return "Windows root certificate";
                case "wmi": return "WMI subscription";
                case "ifeo": return "program hijack (IFEO)";
                case "winlogon": return "sign-in hook";
                case "activesetup": return "Active Setup entry";
                default: return cat;
            }
        }

        public static string Plural(string cat)
        {
            string n = Noun(cat);
            if (n.EndsWith("y") && !n.EndsWith("ey")) return n.Substring(0, n.Length - 1) + "ies";
            if (n.EndsWith("file") || n.Contains("(")) return n;
            return n + "s";
        }

        // ------------------------------------------------------------------ enrich: target, signer, suspicion, hash

        static Dictionary<string, SignerCacheEntry> signers;
        static string SignerFile { get { return Path.Combine(Suite.MyDir, "signers.json"); } }

        static void Sign(Item it)
        {
            if (it.Target == null || !ExecKinds.Contains(it.Category) || it.X("notarget") == "yes") return;
            long stamp;
            try
            {
                var fi = new FileInfo(it.Target);
                if (!fi.Exists) { it.Signer = null; it.Signed = false; it.Missing = true; return; }
                stamp = fi.LastWriteTimeUtc.Ticks ^ fi.Length;
            }
            catch (Exception) { return; }
            SignerCacheEntry c;
            if (!signers.TryGetValue(it.Target, out c) || c.Stamp != stamp)
            {
                var s = Signature.Check(it.Target);
                c = new SignerCacheEntry { Stamp = stamp, Signed = s.Signed, Trusted = s.Trusted, Publisher = s.Publisher };
                signers[it.Target] = c;
            }
            it.Signed = c.Signed;
            it.Trusted = c.Trusted;
            it.Signer = c.Signed ? (c.Publisher ?? "unknown publisher") : null;
            it.Microsoft = c.Trusted && c.Publisher != null && c.Publisher.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);
        }

        public static string Suspicion(string command, string target)
        {
            var reasons = new List<string>();
            string t = (target ?? "").ToLowerInvariant(), c = (command ?? "").ToLowerInvariant();
            if (t.Contains(@"\appdata\local\temp\") || t.Contains(@"\windows\temp\") || Regex.IsMatch(t, @"\\temp\\[^\\]+$")) reasons.Add("runs from a temp folder");
            if (t.Contains(@"\users\public\")) reasons.Add("runs from Users\\Public");
            if (t.Contains(@"\downloads\")) reasons.Add("runs from a Downloads folder");
            if (Regex.IsMatch(c, @"(^|[\\""\s])(mshta|wscript|cscript)(\.exe)?([""\s]|$)")) reasons.Add("uses a script host");
            if (Regex.IsMatch(c, @"(powershell|pwsh)(\.exe)?[""\s].*(\s-e(nc|ncodedcommand)?\s|frombase64string|downloadstring|downloadfile|\biex\b|invoke-expression|invoke-webrequest)")) reasons.Add("encoded or downloading PowerShell");
            else if (Regex.IsMatch(c, @"(powershell|pwsh)(\.exe)?[""\s].*\s-w(indowstyle)?\s+h(idden)?\b")) reasons.Add("PowerShell with a hidden window");
            if (c.Contains("regsvr32") && (c.Contains("/i:http") || c.Contains("scrobj"))) reasons.Add("regsvr32 script trick");
            if (Regex.IsMatch(c, @"https?://") && !t.EndsWith("msedge.exe") && !t.EndsWith("chrome.exe")) reasons.Add("fetches something from the internet");
            return string.Join("; ", reasons);
        }

        static bool Strong(Item it) { return !string.IsNullOrEmpty(it.Why); }

        // Programs that run whatever script or command they're given. Microsoft signs them, but the
        // signature says nothing about the script, so these entries always come to you for review.
        static readonly HashSet<string> Interpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"
        };
        public static bool RunsScript(Item it) { return it.Target != null && Interpreters.Contains(Path.GetFileName(it.Target)); }

        static void Enrich(Item it)
        {
            if (it.Target == null && ExecKinds.Contains(it.Category) && it.X("notarget") != "yes" && it.Category != "wmi") it.Target = Targets.Resolve(it.Command);
            if (it.Category == "wmi" && it.X("class") == "CommandLineEventConsumer") it.Target = Targets.Resolve(it.Command);
            Sign(it);
            it.Why = ExecKinds.Contains(it.Category) ? Suspicion(it.Command, it.Target) : "";
            it.Hash = EntryHash(it, it.HashBasis ?? it.Command);
            it.HashBasis = null;
        }

        static string EntryHash(Item it, string basis)
        {
            return FileUtil.Sha256Text(it.Category + "\n" + it.Location + "\n" + it.Name + "\n" + basis);
        }

        // Argus 1.0.0 wrote task commands whose path Windows had already quoted as "\"C:\...\""; the fixed
        // collector writes "C:\..." instead. Only that exact artifact counts as cosmetic: other quoting
        // changes stay real changes (an unquoted path with spaces is an attack trick).
        public static bool OnlyOldQuoting(string before, string now)
        {
            const string opening = "\"\\\"", closing = "\\\"\"";
            if (before == null || now == null || !before.StartsWith(opening, StringComparison.Ordinal)) return false;
            int end = before.IndexOf(closing, opening.Length, StringComparison.Ordinal);
            if (end < 0) return false;
            string path = before.Substring(opening.Length, end - opening.Length);
            return Proc.Quote(path) + before.Substring(end + closing.Length) == now;
        }

        static string VerifiedComData(Item it)
        {
            return it.X("inboxCom") == "yes" && it.Microsoft && it.Trusted && !Strong(it) ? it.X("comDataHash") : null;
        }

        internal static bool PackagedComChanged(BaselineEntry before, Item current)
        {
            return before != null && before.ComDataHash != null && before.ComDataHash != VerifiedComData(current);
        }

        static BaselineEntry Entry(Item it)
        {
            return new BaselineEntry
            {
                Hash = it.Hash, Signer = it.Signer, Trusted = it.Trusted, Command = it.Command,
                Accepted = Clock.NowIso(), Name = it.Name, Category = it.Category, ComDataHash = VerifiedComData(it)
            };
        }

        // ------------------------------------------------------------------ rating

        public static string Rate(Item it, string kind, BaselineEntry before, out string why)
        {
            var r = new List<string>();
            string sev;
            switch (it.Category)
            {
                case "proxy":
                    bool on = it.X("enabled") == "yes" || !string.IsNullOrEmpty(it.X("pac"));
                    sev = on ? Sev.Critical : Sev.Info;
                    if (on) r.Add("a proxy can see and change your web traffic");
                    break;
                case "rootcert":
                    sev = Sev.Critical;
                    r.Add("a trusted root certificate lets its owner impersonate any website (HTTPS interception); some antivirus and developer tools do add one");
                    break;
                case "authroot": sev = Sev.Info; break;
                case "hosts":
                    sev = Sev.Warning;
                    r.Add("hosts entries override DNS, and Aegis");
                    if (SecuritySites.IsMatch(it.Command)) { sev = Sev.Critical; r.Add("it redirects security, update or search sites"); }
                    if (it.Command == "(no entries)") sev = Sev.Info;
                    break;
                case "dns":
                    sev = it.X("loopback") == "yes" ? Sev.Info : Sev.Critical;
                    if (sev == Sev.Critical) r.Add("Windows no longer sends lookups to Aegis on " + it.X("adapter"));
                    break;
                case "ifeo": sev = Sev.Critical; r.Add("starting " + it.Name.Split(' ')[0] + " runs this instead (or with it)"); break;
                case "winlogon": sev = Sev.Critical; r.Add("this runs at sign-in or inside every program"); break;
                case "wmi": sev = Sev.Critical; r.Add("WMI event subscriptions are a classic hidden way to start code"); break;
                case "policy":
                    sev = Sev.Warning;
                    r.Add("browser policies lock settings (\"Managed by your organization\")");
                    if (Regex.IsMatch(it.Name, "ExtensionInstallForcelist|ExtensionSettings|HomepageLocation|RestoreOnStartupURLs|DefaultSearchProvider|NewTabPageLocation|Proxy", RegexOptions.IgnoreCase))
                    { sev = Sev.Critical; r.Add("it forces extensions, start pages, search or a proxy"); }
                    break;
                case "extension":
                    sev = it.X("broad") == "yes" ? Sev.Warning : Sev.Notice;
                    if (sev == Sev.Warning) r.Add("it can read and change every website you visit");
                    break;
                default:
                    if (RunsScript(it)) { sev = Sev.Notice; r.Add("it runs commands through " + Path.GetFileName(it.Target) + " (Microsoft signs that program; what matters is the script it's told to run)"); }
                    else if (it.Target != null && !File.Exists(it.Target)) { sev = Sev.Notice; r.Add("its program file is missing (often left over from an uninstall)"); }
                    else if (!it.Signed) { sev = Sev.Warning; r.Add(it.Target == null ? "can't tell what it runs" : "the program isn't signed by anyone"); }
                    else if (!it.Trusted) { sev = Sev.Warning; r.Add("its digital signature isn't valid"); }
                    else if (it.X("comActionsUnverified") == "yes") { sev = Sev.Notice; r.Add("Argus could not verify all of the COM task's actions or data"); }
                    else if (it.Microsoft) sev = Sev.Info;
                    else sev = Sev.Notice;
                    if (it.Category == "driver" && Sev.Rank(sev) == 1 && it.Signed) sev = Sev.Notice;
                    break;
            }
            if (Strong(it)) { r.Insert(0, it.Why); sev = Sev.Critical; }
            if (kind == "changed" && before != null && ExecKinds.Contains(it.Category))
            {
                if (Sev.Rank(sev) < Sev.Rank(Sev.Warning)) sev = Sev.Warning;
                r.Add(before.Command != it.Command ? "the command changed" :
                    PackagedComChanged(before, it) ? "the packaged COM handler or its data could not be verified against the baseline" : "the execution settings changed");
                if ((before.Signer ?? "") != (it.Signer ?? ""))
                    r.Add("now signed by " + (it.Signer ?? "nobody") + ", was " + (before.Signer ?? "nobody"));
            }
            why = string.Join("; ", r.Distinct());
            return sev;
        }

        static bool AutoAccept(Item it, string sev)
        {
            return it.Category == "authroot" || (!RunsScript(it) && sev == Sev.Info);
        }

        internal static bool CanRetireMissingComNotice(Finding pending, Item current, BaselineEntry baseline)
        {
            if (pending == null || pending.Now == null || pending.Before != null || pending.Kind != "new"
                || pending.Severity != Sev.Notice || pending.Key != current.Key || pending.Now.Hash != current.Hash
                || pending.Now.Category != "task" || !pending.Now.Missing || pending.Now.Target != "COM"
                || current.Category != "task" || current.X("inboxCom") != "yes" || current.Target == null
                || (baseline != null && baseline.Hash != current.Hash) || PackagedComChanged(baseline, current))
                return false;

            string why;
            return Rate(current, "new", null, out why) == Sev.Info;
        }

        // ------------------------------------------------------------------ the scan

        public sealed class ScanResult
        {
            public int Entries, Fresh, Auto, Removed;
            public bool First;
            public List<string> Problems = new List<string>();
            public TimeSpan Took;
        }

        [DllImport("kernel32.dll")] static extern bool SetPriorityClass(IntPtr process, uint cls);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();

        public static ScanResult Scan()
        {
            Mutex m;
            if (!Sync.Claim("argus.scan", out m)) return null;
            using (m)
            {
                try { SetPriorityClass(GetCurrentProcess(), 0x00100000); } catch (Exception) { }
                var started = DateTime.UtcNow;
                var col = new Collector();
                var items = col.All();
                signers = J.Load<Dictionary<string, SignerCacheEntry>>(SignerFile) ?? new Dictionary<string, SignerCacheEntry>(StringComparer.OrdinalIgnoreCase);
                signers = new Dictionary<string, SignerCacheEntry>(signers, StringComparer.OrdinalIgnoreCase);
                foreach (var it in items) { try { Enrich(it); } catch (Exception e) { Log.Warn("checking " + it.Key + ": " + e.Message); } }
                try { J.Save(SignerFile, signers); } catch (Exception) { }

                var data = ArgusData.Load(Suite.MyDir);
                var now = new Dictionary<string, Item>();
                foreach (var it in items) if (it.Hash != null && !now.ContainsKey(it.Key)) now[it.Key] = it;
                var res = new ScanResult { Entries = now.Count, Problems = col.Problems, First = data.Baseline.Count == 0 };
                var fresh = new List<Finding>();
                var previousAlerts = ArgusAlertReview.PendingIds(data.Pending.Values);
                // An area seen in full for the first time (it failed to read before) is just recorded;
                // an area that failed to read now keeps its entries rather than calling them removed.
                var complete = new HashSet<string>((data.Complete ?? "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
                var readNow = new HashSet<string>(Collector.Kinds.Where(k => !col.Failed.Contains(k)));

                if (res.First)
                {
                    foreach (var it in now.Values) data.Baseline[it.Key] = Entry(it);
                    foreach (var it in now.Values)
                    {
                        string why;
                        string sev = Rate(it, "existing", null, out why);
                        if (Strong(it) || ((it.Category == "proxy" || it.Category == "ifeo") && sev == Sev.Critical))
                            fresh.Add(new Finding { Key = it.Key, Kind = "existing", Severity = sev, Why = why, Seen = Clock.NowIso(), Now = it });
                    }
                    data.History("baseline", null, "First scan: " + now.Count + " entries recorded as the starting point");
                }
                else
                {
                    foreach (var it in now.Values)
                    {
                        BaselineEntry b;
                        data.Baseline.TryGetValue(it.Key, out b);
                        Finding p;
                        data.Pending.TryGetValue(it.Key, out p);
                        if (CanRetireMissingComNotice(p, it, b))
                        {
                            data.Baseline[it.Key] = Entry(it);
                            data.Pending.Remove(it.Key);
                            res.Auto++;
                            data.History("auto", it.Key, "Verified the Windows package handler for " + it.Name);
                            continue;
                        }
                        if (b != null && b.Hash == it.Hash && !PackagedComChanged(b, it))
                        {
                            if (b.ComDataHash == null) b.ComDataHash = VerifiedComData(it);
                            continue;
                        }
                        if (b != null && it.Category == "task" && OnlyOldQuoting(b.Command, it.Command)
                            && b.Hash == EntryHash(it, b.Command + "|" + it.X("runas") + "|" + it.X("highest")))
                        {
                            data.Baseline[it.Key] = Entry(it);
                            continue;
                        }
                        if (b == null && !complete.Contains(it.Category) && !Strong(it)) { data.Baseline[it.Key] = Entry(it); continue; }
                        if (p != null && p.Now != null && p.Now.Hash == it.Hash) { p.Now = it; continue; }
                        string kind = b == null ? "new" : "changed";
                        string why;
                        string sev = Rate(it, kind, b, out why);
                        if (AutoAccept(it, sev))
                        {
                            data.Baseline[it.Key] = Entry(it);
                            data.Pending.Remove(it.Key);
                            res.Auto++;
                            data.History("auto", it.Key, (kind == "new" ? "Added: " : "Updated: ") + Noun(it.Category) + " " + it.Name + (it.Signer != null ? " (" + it.Signer + ")" : ""));
                            continue;
                        }
                        var f = new Finding { Key = it.Key, Kind = kind, Severity = sev, Why = why, Seen = Clock.NowIso(), Now = it, Before = b };
                        data.Pending[it.Key] = f;
                        fresh.Add(f);
                    }
                    foreach (var key in data.Baseline.Keys.Where(k => !now.ContainsKey(k)).ToList())
                    {
                        var b = data.Baseline[key];
                        if (b.Category != null && (!readNow.Contains(b.Category) || !complete.Contains(b.Category))) continue;
                        if (b.Category == "dns" && Regex.IsMatch(b.Command ?? "", @"^(127\.0\.0\.1|::1)( (127\.0\.0\.1|::1))*$"))
                        {
                            if (!data.Pending.ContainsKey(key))
                            {
                                var gone = new Item { Key = key, Category = "dns", Name = b.Name, Command = "(automatic: whatever the network hands out)", Location = key.Split('|')[1] };
                                var f = new Finding { Key = key, Kind = "removed", Severity = Sev.Critical, Why = "Windows stopped sending lookups to Aegis on " + b.Name + "; ads and malware sites aren't filtered there", Seen = Clock.NowIso(), Now = gone, Before = b };
                                data.Pending[key] = f;
                                fresh.Add(f);
                            }
                            continue;
                        }
                        data.Baseline.Remove(key);
                        data.Pending.Remove(key);
                        res.Removed++;
                        data.History("removed", key, "Gone: " + Noun(b.Category) + " " + b.Name);
                    }
                    foreach (var key in data.Pending.Keys.Where(k => !now.ContainsKey(k) && data.Pending[k].Kind != "removed").ToList()) data.Pending.Remove(key);
                }

                try
                {
                    if (data.HostsGood == null || data.Baseline.ContainsKey("hosts|" + Collector.HostsPath + "|hosts file") && !data.Pending.Keys.Any(k => k.StartsWith("hosts|")))
                        data.HostsGood = File.ReadAllText(Collector.HostsPath);
                }
                catch (Exception) { }

                complete.UnionWith(readNow);
                data.Complete = string.Join(",", complete.OrderBy(k => k));
                foreach (var f in fresh) Raise(f);
                res.Fresh = fresh.Count;
                data.Current = now.Values.OrderBy(i => i.Category).ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList();
                data.LastScan = Clock.NowIso();
                res.Took = DateTime.UtcNow - started;
                data.Save();
                RecordClosedAlerts(data, previousAlerts);
                WriteStatus(data, res);
                Log.Info("scan: " + res.Entries + " entries, " + res.Fresh + " to review, " + res.Auto + " accepted automatically, " + res.Removed + " gone, " + (int)res.Took.TotalSeconds + " s" + (res.Problems.Count > 0 ? "; couldn't read: " + string.Join(" | ", res.Problems) : ""));
                return res;
            }
        }

        public static void RecordClosedAlerts(ArgusData data, Dictionary<string, string> previous)
        {
            var remaining = new HashSet<string>(ArgusAlertReview.PendingIds(data.Pending.Values).Values, StringComparer.Ordinal);
            ArgusAlertReview.RecordResolved(data.Dir, previous.Values.Where(id => !remaining.Contains(id)));
        }

        static void Raise(Finding f)
        {
            if (Sev.Rank(f.Severity) < 1) return;
            var it = f.Now;
            string verb = f.Kind == "new" ? "New " : f.Kind == "changed" ? "Changed " : f.Kind == "removed" ? "Turned off: " : "Worth a look: ";
            var sb = new StringBuilder();
            if (!string.IsNullOrEmpty(f.Why)) sb.Append(char.ToUpperInvariant(f.Why[0]) + f.Why.Substring(1) + ".\n");
            sb.Append((it.Category == "extension" ? "Access: " : "Runs: ") + Fmt.Clip(it.Command, 160) + "\n");
            if (ExecKinds.Contains(it.Category)) sb.Append("Signed by: " + (it.Signer ?? "nobody") + "\n");
            if (f.Kind == "changed" && f.Before != null) sb.Append("Before: " + Fmt.Clip(f.Before.Command, 120) + "\n");
            sb.Append("Where: " + it.Location);
            var a = AlertStore.New(f.Severity, verb + Noun(it.Category) + ": " + Fmt.Clip(it.Name, 60), sb.ToString(), it.Key).With("key", it.Key);
            bool admin = Suite.Installed || Elevation.IsElevated;
            a.Act("accept", f.Kind == "removed" ? "I meant to do that" : "It's fine, keep it", admin);
            if (CanTurnOff(it)) a.Act("disable", "Turn it off", true);
            AlertStore.Raise(a);
            f.AlertId = a.Id;
        }

        static void WriteStatus(ArgusData data, ScanResult res)
        {
            int crit = data.Pending.Values.Count(f => f.Severity == Sev.Critical), total = data.Pending.Count;
            var facts = new Dictionary<string, object>
            {
                { "entries", res.Entries }, { "pending", total }, { "seconds", (int)res.Took.TotalSeconds },
                { "coverage", Elevation.IsElevated ? "full" : "partial" }
            };
            string detail = res.Entries.ToString("N0") + " entries watched \u00B7 scanned " + DateTime.Now.ToString("h:mm tt")
                          + (Elevation.IsElevated ? "" : " \u00B7 partial view (not running as admin)")
                          + (res.Problems.Count > 0 ? " \u00B7 couldn't read " + res.Problems.Count + " areas" : "");
            if (crit > 0) StatusStore.Write(States.Alert, Fmt.Plural(crit, "serious change") + " to review" + (total > crit ? " (" + total + " in all)" : ""), detail, facts);
            else if (total > 0) StatusStore.Write(States.Warn, Fmt.Plural(total, "change") + " to review", detail, facts);
            else StatusStore.Write(States.Ok, res.First ? "Baseline taken: watching for changes" : "No unexpected changes", detail, facts);
        }

        public static void RefreshStatus(ArgusData data)
        {
            WriteStatus(data, new ScanResult { Entries = data.Current.Count, First = false });
        }

        // ------------------------------------------------------------------ accept, turn off, undo

        public static bool CanTurnOff(Item it)
        {
            switch (it.Category)
            {
                case "run": case "startup": case "task": case "service": case "driver": case "policy": case "proxy":
                case "hosts": case "rootcert": case "ifeo": case "activesetup": case "wmi":
                    return true;
                case "winlogon": return it.X("value") == "Shell" || it.X("value") == "Userinit";
                default: return false;
            }
        }

        public static Item Find(ArgusData data, string key)
        {
            Finding f;
            if (data.Pending.TryGetValue(key, out f) && f.Now != null) return f.Now;
            return data.Current.FirstOrDefault(i => i.Key == key);
        }

        public static string Accept(ArgusData data, string key)
        {
            Finding f;
            data.Pending.TryGetValue(key, out f);
            if (f != null && f.Kind == "removed") { data.Baseline.Remove(key); data.Pending.Remove(key); data.History("accepted", key, "Accepted removal: " + f.Now.Name); return null; }
            var it = Find(data, key);
            if (it == null) return "That entry isn't there any more.";
            data.Baseline[key] = Entry(it);
            data.Pending.Remove(key);
            data.History("accepted", key, "Kept: " + Noun(it.Category) + " " + it.Name);
            return null;
        }

        static void Schtasks(string args)
        {
            string output;
            int code = Proc.Run("schtasks.exe", args, out output, 30000);
            if (code != 0) throw new InvalidOperationException("schtasks: " + output.Trim());
        }

        public static string QuarantineDir { get { return Path.Combine(Suite.MyDir, "turned-off"); } }

        public static UndoRecord TurnOff(ArgusData data, string key)
        {
            var it = Find(data, key);
            if (it == null) throw new InvalidOperationException("That entry isn't there any more.");
            if (!CanTurnOff(it)) throw new InvalidOperationException(it.Category == "extension"
                ? "Browsers don't let other programs switch extensions off. Remove it on your browser's Extensions page."
                : "Argus can't turn this kind of entry off; change it by hand.");
            var u = new UndoRecord { Id = Guid.NewGuid().ToString("N").Substring(0, 12), Key = key, Time = Clock.NowIso(), What = Noun(it.Category) + ": " + it.Name, Category = it.Category };
            BaselineEntry be;
            u.Entry = data.Baseline.TryGetValue(key, out be) ? be : Entry(it);
            Directory.CreateDirectory(QuarantineDir);
            switch (it.Category)
            {
                case "run": case "policy": case "ifeo": case "activesetup":
                {
                    string value = it.X("value") ?? it.Name;
                    using (var k = Reg.Open(it.Location, true))
                    {
                        if (k == null) throw new InvalidOperationException("The registry key is gone: " + it.Location);
                        var kind = k.GetValueKind(value);
                        u.Data["location"] = it.Location;
                        u.Data["value"] = value;
                        u.Data["kind"] = kind.ToString();
                        u.Data["data"] = Reg.Encode(k.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames), kind);
                        k.DeleteValue(value);
                    }
                    break;
                }
                case "winlogon":
                {
                    string value = it.X("value");
                    string def = value == "Shell" ? "explorer.exe" : Path.Combine(Environment.SystemDirectory, "userinit.exe") + ",";
                    using (var k = Reg.Open(it.Location, true))
                    {
                        u.Data["location"] = it.Location;
                        u.Data["value"] = value;
                        u.Data["kind"] = k.GetValueKind(value).ToString();
                        u.Data["data"] = Convert.ToString(k.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                        k.SetValue(value, def, RegistryValueKind.String);
                    }
                    break;
                }
                case "startup":
                {
                    string file = it.X("file");
                    string moved = Path.Combine(QuarantineDir, u.Id + "-" + Path.GetFileName(file));
                    File.Move(file, moved);
                    u.Data["file"] = file;
                    u.Data["moved"] = moved;
                    break;
                }
                case "task":
                    Schtasks("/change /tn " + Proc.Quote(it.X("path") ?? it.Name) + " /disable");
                    u.Data["path"] = it.X("path") ?? it.Name;
                    break;
                case "service":
                case "driver":
                {
                    string svc = it.X("service");
                    using (var k = Reg.Open(@"HKLM\SYSTEM\CurrentControlSet\Services\" + svc, true))
                    {
                        u.Data["start"] = Convert.ToString(k.GetValue("Start"));
                        k.SetValue("Start", 4, RegistryValueKind.DWord);
                    }
                    u.Data["service"] = svc;
                    break;
                }
                case "proxy":
                {
                    u.Data["location"] = it.Location;
                    if (it.Location.EndsWith("Connections"))
                    {
                        using (var k = Reg.Open(it.Location, true))
                        {
                            var b = k.GetValue("WinHttpSettings") as byte[];
                            if (b != null) u.Data["winhttp"] = Convert.ToBase64String(b);
                        }
                        string output;
                        Proc.Run("netsh.exe", "winhttp reset proxy", out output, 20000);
                    }
                    else
                    {
                        using (var k = Reg.Open(it.Location, true))
                        {
                            u.Data["ProxyEnable"] = Convert.ToString(k.GetValue("ProxyEnable"));
                            u.Data["AutoConfigURL"] = k.GetValue("AutoConfigURL") as string ?? "";
                            k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                            k.DeleteValue("AutoConfigURL", false);
                        }
                    }
                    break;
                }
                case "hosts":
                {
                    if (string.IsNullOrEmpty(data.HostsGood)) throw new InvalidOperationException("Argus has no earlier copy of the hosts file to go back to.");
                    string saved = Path.Combine(QuarantineDir, u.Id + "-hosts");
                    File.Copy(Collector.HostsPath, saved);
                    File.WriteAllText(Collector.HostsPath, data.HostsGood);
                    u.Data["saved"] = saved;
                    break;
                }
                case "rootcert":
                {
                    string loc = it.Location + "\\" + it.X("thumbprint");
                    using (var k = Reg.Open(loc, false))
                    {
                        if (k == null) throw new InvalidOperationException("The certificate is gone.");
                        var blob = k.GetValue("Blob") as byte[];
                        u.Data["blob"] = blob == null ? "" : Convert.ToBase64String(blob);
                    }
                    using (var parent = Reg.Open(it.Location, true)) parent.DeleteSubKeyTree(it.X("thumbprint"));
                    u.Data["location"] = it.Location;
                    u.Data["thumbprint"] = it.X("thumbprint");
                    break;
                }
                case "wmi":
                {
                    var scope = new ManagementScope(@"\\.\root\subscription");
                    scope.Connect();
                    string q = it.X("class") == "__FilterToConsumerBinding"
                        ? "SELECT * FROM __FilterToConsumerBinding"
                        : "SELECT * FROM " + it.X("class") + " WHERE Name = '" + it.Name.Replace("'", "''") + "'";
                    using (var s = new ManagementObjectSearcher(scope, new ObjectQuery(q)))
                        foreach (ManagementObject o in s.Get())
                            using (o)
                            {
                                if (it.X("class") == "__FilterToConsumerBinding" && o.Path.RelativePath != it.X("relpath")) continue;
                                u.Data["deleted"] = o.Path.RelativePath;
                                o.Delete();
                            }
                    u.Data["noundo"] = "yes";
                    break;
                }
            }
            data.Undo.Insert(0, u);
            data.Pending.Remove(key);
            data.History("turned off", key, u.What);
            return u;
        }

        public static void Undo(ArgusData data, UndoRecord u)
        {
            if (u.Undone) return;
            if (u.D("noundo") == "yes") throw new InvalidOperationException("A deleted WMI subscription can't be put back automatically.");
            switch (u.Category)
            {
                case "run": case "policy": case "ifeo": case "activesetup": case "winlogon":
                {
                    var kind = (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), u.D("kind"));
                    using (var k = Reg.Create(u.D("location"))) k.SetValue(u.D("value"), Reg.Decode(u.D("data"), kind), kind);
                    break;
                }
                case "startup": File.Move(u.D("moved"), u.D("file")); break;
                case "task": Schtasks("/change /tn " + Proc.Quote(u.D("path")) + " /enable"); break;
                case "service":
                case "driver":
                    using (var k = Reg.Open(@"HKLM\SYSTEM\CurrentControlSet\Services\" + u.D("service"), true))
                        k.SetValue("Start", int.Parse(u.D("start")), RegistryValueKind.DWord);
                    break;
                case "proxy":
                    using (var k = Reg.Open(u.D("location"), true))
                    {
                        if (u.D("winhttp") != null) k.SetValue("WinHttpSettings", Convert.FromBase64String(u.D("winhttp")), RegistryValueKind.Binary);
                        else
                        {
                            int en;
                            if (int.TryParse(u.D("ProxyEnable"), out en)) k.SetValue("ProxyEnable", en, RegistryValueKind.DWord);
                            if (!string.IsNullOrEmpty(u.D("AutoConfigURL"))) k.SetValue("AutoConfigURL", u.D("AutoConfigURL"), RegistryValueKind.String);
                        }
                    }
                    break;
                case "hosts": File.Copy(u.D("saved"), Collector.HostsPath, true); break;
                case "rootcert":
                    using (var k = Reg.Create(u.D("location") + "\\" + u.D("thumbprint")))
                        k.SetValue("Blob", Convert.FromBase64String(u.D("blob")), RegistryValueKind.Binary);
                    break;
            }
            u.Undone = true;
            if (u.Entry != null) data.Baseline[u.Key] = u.Entry;   // back as it was, not as "new"
            data.History("undone", u.Key, "Put back: " + u.What);
        }
    }
}
