// Argus's engine. Each scan collects every entry, works out what program it runs and who signed
// it, and compares it with the baseline (what you've accepted). New or changed entries become
// findings to review. Routine additions and removals are accepted automatically, and so is an
// app updating itself in place (same valid signer, same program, only a version folder changed,
// in a folder only admins can change: see RoutineUpdate). Other changed commands and execution
// settings always go to review. "Turn it off" removes or disables an entry and keeps what's
// needed to put it back (Undo).
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
        // SignerId: the verified signer's identity (SignerInfo.Id) when accepted; older entries get it once
        // their program verifies in an admin-only folder while the command is unchanged. Settings: how the
        // entry runs apart from its command (Engine.SettingsOf). DriverVer: the driver package's DriverVer
        // (driver-store drivers). AutoKept: Argus kept it on its own because of its program's signature, so
        // it's verified again on every scan; KeptBy says which check that was ("update": RoutineUpdate, with
        // the whole folder tree; "signature": a new entry for a verified Microsoft program, with the files
        // beside it). TurnedOff: you turned it off with Argus; switching it back on is always looked at (and
        // for a new or changed entry, its command was never accepted, only recorded as off). StartNoted: when the
        // history last noted a routine start-mode change of it (noted at most once a day).
        public string Hash, Signer, Command, Accepted, Name, Category, ComDataHash, SignerId, Settings, DriverVer, KeptBy, StartNoted;
        public bool Trusted, AutoKept, TurnedOff;

        public BaselineEntry Copy() { return (BaselineEntry)MemberwiseClone(); }
    }

    public sealed class Finding : ArgusPendingAlert
    {
        // Kind: new, changed, removed, existing (first scan), settings (the same command with other settings; it
        // closes by itself if they go back to what was accepted), or trust (an entry Argus kept on its own no
        // longer verifies; it closes by itself if the program verifies again).
        public string Kind, Why;
        // A packaged COM task's raw action data when the finding was made (kept as the entry refreshes).
        public string ComRawHash;
        // Its alert ID is saved, but the alert isn't published yet (a scan stopped in between publishes it
        // with that same ID next time).
        public bool Unpublished;
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
        public string Publisher, Id, Issuer, Root;
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
        // A file that exists but couldn't be read (named here), as opposed to one that isn't there yet. Nothing
        // may be decided or saved from such a load: an unreadable baseline would look like a first scan (and
        // accept everything), an unreadable pending list like nothing to review.
        public readonly List<string> Unreadable = new List<string>();
        public bool Readable { get { return Unreadable.Count == 0; } }
        public bool PendingReadable { get { return !Unreadable.Contains("pending.json"); } }

        string P(string f) { return Path.Combine(Dir, f); }

        void Flag(string name) { if (!Unreadable.Contains(name)) Unreadable.Add(name); }

        // Only "the file (or its folder) isn't there" counts as missing; any other read error, or contents that
        // don't parse (or parse to nothing), make the file unreadable. File.Exists says false on an access error,
        // so it isn't asked.
        T LoadFile<T>(string name) where T : class, new()
        {
            string text;
            try { text = FileUtil.ReadShared(P(name)); }
            catch (FileNotFoundException) { return new T(); }
            catch (DirectoryNotFoundException) { return new T(); }
            catch (Exception) { Unreadable.Add(name); return new T(); }
            T v = null;
            try { v = J.Read<T>(text); }
            catch (Exception) { }
            if (v != null) return v;
            Unreadable.Add(name);
            return new T();
        }

        public static ArgusData Load(string dir)
        {
            var d = new ArgusData { Dir = dir };
            d.Baseline = d.LoadFile<Dictionary<string, BaselineEntry>>("baseline.json");
            d.Pending = d.LoadFile<Dictionary<string, Finding>>("pending.json");
            d.Undo = d.LoadFile<List<UndoRecord>>("turned-off.json");
            d.Current = d.LoadFile<List<Item>>("current.json");
            // Rows that parse but can't be used (a missing finding or entry, a finding filed under another key, one
            // with nothing to show) make their file unreadable too, instead of failing every scan later.
            if (d.Baseline.Any(kv => kv.Value == null)) { d.Flag("baseline.json"); d.Baseline = new Dictionary<string, BaselineEntry>(); }
            if (d.Pending.Any(kv => kv.Value == null || kv.Value.Now == null || kv.Value.Key != kv.Key)) { d.Flag("pending.json"); d.Pending = new Dictionary<string, Finding>(); }
            if (d.Undo.Any(u => u == null)) { d.Flag("turned-off.json"); d.Undo = new List<UndoRecord>(); }
            if (d.Current.Any(i => i == null || i.Key == null)) { d.Flag("current.json"); d.Current = new List<Item>(); }
            // meta.json too: without it every kind looks never read in full, and new entries would be recorded silently.
            var meta = d.LoadFile<Dictionary<string, string>>("meta.json");
            meta.TryGetValue("lastScan", out d.LastScan);
            meta.TryGetValue("hostsGood", out d.HostsGood);
            meta.TryGetValue("complete", out d.Complete);
            return d;
        }

        // What's needed to put things back is written first: a save cut short never loses an Undo. After an Undo
        // (undoLast), the restored baseline is written first and the record marked done last, so a save cut
        // short leaves the Undo to run again (every step of it can).
        public void Save()
        {
            Save(false);
        }

        public void Save(bool undoLast)
        {
            if (!undoLast) SaveUndo();
            J.Save(P("baseline.json"), Baseline);
            J.Save(P("pending.json"), Pending);
            J.Save(P("current.json"), Current);
            J.Save(P("meta.json"), new Dictionary<string, string> { { "lastScan", LastScan }, { "hostsGood", HostsGood }, { "complete", Complete } });
            if (undoLast) SaveUndo();
        }

        public void SaveUndo() { J.Save(P("turned-off.json"), Undo); }
        public void SavePending() { J.Save(P("pending.json"), Pending); }

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
            // Entries cached before signer identities (or their chains' roots) were recorded are checked again once.
            if (!signers.TryGetValue(it.Target, out c) || c.Stamp != stamp || (c.Trusted && (c.Id == null || c.Root == null)))
            {
                var s = Signature.Check(it.Target);
                c = new SignerCacheEntry { Stamp = stamp, Signed = s.Signed, Trusted = s.Trusted, Publisher = s.Publisher, Id = s.Id, Issuer = s.Issuer, Root = s.Root };
                signers[it.Target] = c;
            }
            it.Signed = c.Signed;
            it.Trusted = c.Trusted;
            it.SignerId = c.Trusted ? c.Id : null;
            it.Signer = c.Signed ? (c.Publisher ?? "unknown publisher") : null;
            // Microsoft only with the verified identity (without it the name is just what the file says), and only
            // Microsoft's own code: a Microsoft name on a chain that ends at one of Microsoft's product roots, not a
            // WHQL or third-party signature (Signature.IsMicrosoftCode).
            it.Microsoft = c.Trusted && !string.IsNullOrEmpty(c.Id) && Signature.IsMicrosoftCode(c.Publisher, c.Issuer, c.Root);
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
        // By file name (8.3 aliases like POWERS~1.EXE expanded) and by the name Microsoft built it under,
        // so a renamed copy still counts.
        public static bool RunsScript(Item it)
        {
            if (it.Target == null) return false;
            string original = null;
            try { if (File.Exists(it.Target)) original = System.Diagnostics.FileVersionInfo.GetVersionInfo(it.Target).OriginalFilename; }
            catch (Exception) { }
            return IsInterpreter(Path.GetFileName(Versioned.LongPath(it.Target)), original);
        }

        internal static bool IsInterpreter(string fileName, string originalFilename)
        {
            if (fileName != null && Interpreters.Contains(fileName)) return true;
            string o = (originalFilename ?? "").Trim();
            if (o.EndsWith(".mui", StringComparison.OrdinalIgnoreCase)) o = o.Substring(0, o.Length - 4);
            return o.Length > 0 && Interpreters.Contains(o);
        }

        static void Enrich(Item it)
        {
            if (it.Target == null && ExecKinds.Contains(it.Category) && it.X("notarget") != "yes" && it.Category != "wmi") it.Target = Targets.Resolve(it.Command);
            if (it.Category == "wmi" && it.X("class") == "CommandLineEventConsumer") it.Target = Targets.Resolve(it.Command);
            Sign(it);
            it.Why = ExecKinds.Contains(it.Category) ? Suspicion(it.Command, it.Target) : "";
            it.Hash = EntryHash(it, it.HashBasis ?? it.Command);
            it.HashBasis = null;
        }

        internal static string EntryHash(Item it, string basis)
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
                Accepted = Clock.NowIso(), Name = it.Name, Category = it.Category, ComDataHash = VerifiedComData(it),
                SignerId = it.Trusted ? it.SignerId : null, Settings = SettingsKnown(it) ? SettingsOf(it) : null,
                DriverVer = it.Target != null && Versioned.InDriverStore(it.Target) ? Versioned.DriverVer(it.Target) : null
            };
        }

        // How an entry runs apart from its command, as "name=value;..." in a fixed order: whether it's switched
        // on; for services and drivers the start mode, type and account (empty: Windows' default, LocalSystem);
        // for startup entries the registry value type (only an ExpandString has its %variables% expanded).
        // Every field that applies is always written, so one that disappears is a change too.
        internal static string SettingsOf(Item it)
        {
            if (it == null) return null;
            var sb = new StringBuilder("enabled=" + (it.Enabled ? "1" : "0"));
            foreach (var k in SettingKeys(it.Category)) sb.Append(";" + k + "=" + (it.X(k) ?? ""));
            return sb.ToString();
        }

        static string[] SettingKeys(string category)
        {
            switch (category)
            {
                case "service": case "driver": return new[] { "start", "type", "account" };
                case "run": return new[] { "kind" };
                default: return new string[0];
            }
        }

        // Whether the collector recorded all of an item's settings: items from before this version have no
        // service type or value kind (an account is recorded only when set, so its absence means the default).
        internal static bool SettingsKnown(Item it)
        {
            return it != null && SettingKeys(it.Category).All(k => k == "account" || it.X(k) != null);
        }

        static Dictionary<string, string> ParseSettings(string s)
        {
            return (s ?? "").Split(';').Select(p => p.Split(new[] { '=' }, 2)).Where(p => p.Length == 2)
                .GroupBy(p => p[0]).ToDictionary(g => g.Key, g => g.First()[1]);
        }

        static string Setting(Dictionary<string, string> d, string key)
        {
            string v;
            return d.TryGetValue(key, out v) ? v : "";
        }

        // Same settings: the same fields, each with the same value.
        internal static bool SameSettings(string a, string b)
        {
            if (a == null || b == null) return false;
            var x = ParseSettings(a); var y = ParseSettings(b);
            if (!x.ContainsKey("enabled") || x.Count != y.Count) return false;
            return x.All(kv => { string v; return y.TryGetValue(kv.Key, out v) && v == kv.Value; });
        }

        // An item's settings against an earlier item's: everything, or for an earlier item from before all
        // settings were recorded, what it did record (switched on or off, start mode). Refreshed findings
        // carry everything from then on.
        static bool SameSettingsAs(Item earlier, Item now)
        {
            if (earlier == null || now == null) return false;
            if (SettingsKnown(earlier)) return SameSettings(SettingsOf(earlier), SettingsOf(now));
            return earlier.Enabled == now.Enabled && SettingKeys(earlier.Category).All(k => earlier.X(k) == null || earlier.X(k) == now.X(k));
        }

        // What a change to an entry's settings alone means (its command and actions are as recorded). Null when
        // it's routine: switched off, or switched (back) on or given another start mode where 'routineOn' vouches
        // for the program (a verified Microsoft program in folders only admins can change: Windows switches its
        // own tasks and services on and off). Otherwise why it gets a look, rated like a new entry and at least a
        // notice; a new account, service type or value kind is always a warning, and so is switching back on an
        // entry you turned off ('turnedOff'), whoever signed it.
        internal static string SettingsRisk(string before, string now, Item it, bool turnedOff, Func<Item, bool> routineOn, out string sev)
        {
            sev = Sev.Info;
            var a = ParseSettings(before); var b = ParseSettings(now);
            if (Setting(a, "account") != Setting(b, "account"))
            {
                sev = Sev.Warning;
                return "it now runs as " + AccountName(Setting(b, "account")) + " (was " + AccountName(Setting(a, "account")) + ")";
            }
            if (Setting(a, "type") != Setting(b, "type")) { sev = Sev.Warning; return "its service type changed (" + Setting(a, "type") + " to " + Setting(b, "type") + ")"; }
            if (Setting(a, "kind") != Setting(b, "kind"))
            {
                sev = Sev.Warning;
                return "its registry value type changed (" + Setting(a, "kind") + " to " + Setting(b, "kind") + "), which changes how Windows reads the command";
            }
            if (Setting(b, "enabled") == "0") return null;   // switched off (a service set to disabled included)
            if (turnedOff) { sev = Sev.Warning; return "it was switched back on after you turned it off with Argus"; }
            if (routineOn != null && routineOn(it)) return null;
            string why;
            sev = Rate(it, "new", null, out why);
            if (Sev.Rank(sev) < Sev.Rank(Sev.Notice)) sev = Sev.Notice;
            string change = Setting(a, "enabled") == "0" ? "it was switched back on"
                : "its start mode changed from " + Setting(a, "start") + " to " + Setting(b, "start");
            return string.IsNullOrEmpty(why) ? change : change + "; " + why;
        }

        static string AccountName(string account)
        {
            return string.IsNullOrEmpty(account) ? "LocalSystem (Windows' default)" : account;
        }

        // How a routine settings change reads in the history: switched on (with its start mode) or off, or which
        // start mode it moved to. startOnly: it stayed switched on and only its start mode changed.
        internal static string SettingsChangeLabel(string before, string now, out bool startOnly)
        {
            var a = ParseSettings(before); var b = ParseSettings(now);
            bool wasOn = Setting(a, "enabled") != "0", isOn = Setting(b, "enabled") != "0";
            string was = Setting(a, "start"), start = Setting(b, "start");
            startOnly = false;
            if (wasOn != isOn) return isOn ? "Switched on" + (start.Length > 0 ? " (start mode " + start + ")" : "") : "Switched off";
            if (was != start)
            {
                startOnly = true;
                return "Start mode changed to " + start + " (was " + was + ")";
            }
            return "Settings changed";
        }

        // Whether 'iso' (a time Argus noted something) is within 'window' of now.
        static bool NotedWithin(string iso, TimeSpan window)
        {
            if (string.IsNullOrEmpty(iso)) return false;
            try { return DateTime.UtcNow - Clock.Parse(iso) < window; }
            catch (Exception) { return false; }
        }

        // The settings an entry had according to an earlier item from before every setting was recorded: what
        // that item recorded (switched on or off, start mode), and today's value for what it didn't.
        internal static string MergedSettings(Item earlier, Item now)
        {
            var merged = now.Copy();
            merged.Enabled = earlier.Enabled;
            foreach (var k in SettingKeys(now.Category)) if (earlier.X(k) != null) merged.Extra[k] = earlier.X(k);
            return SettingsOf(merged);
        }

        // The production check for SettingsRisk: the program verifies as Microsoft's from a held handle, in
        // folders only admins can change (the files beside it included), and isn't a script runner.
        static bool RoutineSwitch(Item it)
        {
            if (!it.Microsoft || Strong(it) || RunsScript(it) || it.Target == null) return false;
            var s = VerifyProtected(Versioned.LongPath(it.Target), Siblings.Files);
            return s != null && s.IsMicrosoft && !string.IsNullOrEmpty(s.Id);
        }

        // The accepted record of the same registry service under the other kind (a service now registered as a
        // driver, or the other way round), or null.
        internal static BaselineEntry OtherKind(Dictionary<string, BaselineEntry> baseline, Item it)
        {
            if (baseline == null || it == null) return null;
            string other = OtherKindKey(it.Key);
            BaselineEntry e;
            return other != null && baseline.TryGetValue(other, out e) ? e : null;
        }

        // The key the same registry service has under the other kind ("service|..." <-> "driver|..."), or null.
        internal static string OtherKindKey(string key)
        {
            if (key == null) return null;
            if (key.StartsWith("service|", StringComparison.Ordinal)) return "driver|" + key.Substring("service|".Length);
            if (key.StartsWith("driver|", StringComparison.Ordinal)) return "service|" + key.Substring("driver|".Length);
            return null;
        }

        // The settings an entry has once Argus turned it off: switched off, and a service or driver disabled.
        internal static string TurnedOffSettings(Item it)
        {
            if (!SettingsKnown(it)) return null;
            var off = new Item { Category = it.Category, Enabled = false };
            foreach (var kv in it.Extra) off.Extra[kv.Key] = kv.Value;
            if (it.Category == "service" || it.Category == "driver") off.Extra["start"] = "disabled";
            return SettingsOf(off);
        }

        // Why a new entry that would otherwise count as routine (a valid Microsoft signature) should get a look
        // anyway, or null. The whole launch has to be verified: a literal program path, with no arguments, that
        // is the file Argus checked (a signature says nothing about the files or settings arguments point a
        // program at); a task with one action whose working folder is admin-only too, or a verified inbox COM
        // handler; never a startup-folder shortcut, which sets its own folder and arguments. And the program,
        // verified now from a held handle, is Microsoft's, in folders only admins can change (the files beside
        // it included).
        static string NewEntryRisk(Item it)
        {
            string image, args;
            switch (it.Category)
            {
                case "startup":
                    return "a startup-folder shortcut chooses its own folder and arguments";
                case "task":
                    if (it.X("actions") != "1") return "the task has more than one action";
                    if (it.X("inboxCom") == "yes") break;
                    if (it.X("action") != "exec") return "it hands work to a COM handler Argus can't tie to Windows itself";
                    if (!Versioned.SplitLaunch(it.Command, false, out image, out args) || !string.Equals(image, it.Target, StringComparison.OrdinalIgnoreCase))
                        return "Argus can't read exactly which program it starts";
                    if (!string.IsNullOrWhiteSpace(args)) return "it passes arguments to the program, and a signature doesn't vouch for those";
                    string dir = it.X("workdir");
                    if (!string.IsNullOrEmpty(dir) && !Versioned.FolderLocked(dir))
                        return "it starts in a folder that programs running as you can change";
                    break;
                case "run":
                    if (!Versioned.SplitLaunch(it.Command, false, out image, out args) || !string.Equals(image, it.Target, StringComparison.OrdinalIgnoreCase))
                        return "Argus can't read exactly which program it starts";
                    if (!string.IsNullOrWhiteSpace(args)) return "it passes arguments to the program, and a signature doesn't vouch for those";
                    break;
            }
            var s = VerifyProtected(Versioned.LongPath(it.Target), Siblings.Files);
            if (s == null) return "it starts a Microsoft-signed program from a folder that programs running as you can change";
            return s.IsMicrosoft && !string.IsNullOrEmpty(s.Id) ? null : "Argus couldn't verify the program as Microsoft's just now";
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
                    else if (it.Microsoft)
                    {
                        // A Microsoft signature only vouches for the program file. A new entry is kept on its own
                        // only when its whole launch is pinned down (NewEntryRisk); a signed program in a folder
                        // you can write to, for one, can be made to load someone else's DLL.
                        string risk = kind == "new" ? NewEntryRisk(it) : null;
                        if (risk == null) sev = Sev.Info;
                        else { sev = Sev.Notice; r.Add(risk); }
                    }
                    else sev = Sev.Notice;
                    // (A new driver is routine only when it's Microsoft's own: a WHQL-signed third-party driver
                    // isn't "Microsoft" any more, see Signature.IsMicrosoftPublisher, so it gets a look.)
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

        // Entries whose whole launch is one command line naming one program. Tasks (several actions, working
        // folders, principals) and startup shortcuts (their own folder and arguments) always go to review.
        static readonly HashSet<string> UpdatableKinds = new HashSet<string> { "run", "service", "driver", "activesetup" };

        // An app that updated itself in place: the command still names the same program by a literal local
        // path, with exactly the same arguments; exactly one version folder moved forward (Versioned.IsUpdate,
        // and for the driver store a later DriverVer than the one on record); the file Argus verified is that
        // program (not a hosted DLL); it runs with exactly the settings on record (switched on or off, start
        // mode, type, account, value kind; an entry accepted before settings were recorded gets one review);
        // and, checked now on held handles, it's validly signed by the same publisher and signer identity in a
        // folder tree only admins can change (verifyProtected returns null otherwise). A baseline from before
        // identities were recorded counts only where the install layout itself ties the versions together (an
        // installed MSIX package or the driver store); anywhere else the update gets one review, after which
        // the identity is on record.
        internal static bool RoutineUpdate(BaselineEntry before, Item now, Func<string, SignerInfo> verifyProtected, out SignerInfo verified)
        {
            verified = null;
            if (before == null || now == null || verifyProtected == null || !UpdatableKinds.Contains(now.Category)) return false;
            if (!before.Trusted || !now.Signed || !now.Trusted || Strong(now) || now.Missing) return false;
            bool systemRoot = now.Category == "driver" || now.Category == "service";
            string oldImage, oldArgs, newImage, newArgs;
            if (!Versioned.SplitLaunch(before.Command, systemRoot, out oldImage, out oldArgs)
                || !Versioned.SplitLaunch(now.Command, systemRoot, out newImage, out newArgs)) return false;
            if (!string.Equals(oldArgs, newArgs, StringComparison.Ordinal) || !Versioned.IsUpdate(oldImage, newImage)) return false;
            if (!string.Equals(now.Target, newImage, StringComparison.OrdinalIgnoreCase)) return false;
            if (IsInterpreter(Path.GetFileName(newImage), null) || RunsScript(now)) return false;
            if (!SettingsKnown(now) || !SameSettings(before.Settings, SettingsOf(now))) return false;
            if (Versioned.InDriverStore(newImage) && !Versioned.LaterDriver(before.DriverVer, Versioned.DriverVer(newImage))) return false;
            var s = verifyProtected(newImage);
            if (s == null || !s.Signed || !s.Trusted || string.IsNullOrEmpty(s.Publisher) || string.IsNullOrEmpty(s.Id)
                || !string.Equals(s.Publisher, before.Signer, StringComparison.Ordinal)) return false;
            if (before.SignerId != null ? before.SignerId != s.Id : !Versioned.InPackageOrDriverStore(newImage)) return false;
            verified = s;
            return true;
        }

        // The production check behind every decision Argus makes on its own because of a signature: the program
        // and every folder above it are held open (none can be renamed, replaced or written meanwhile), its
        // neighbours are checked ('siblings'), and the signature is verified from the held handle, uncached.
        // Null when the program or its folders can be changed by others, or anything fails.
        static SignerInfo VerifyProtected(string image)
        {
            return VerifyProtected(image, Siblings.Tree);
        }

        static SignerInfo VerifyProtected(string image, Siblings siblings)
        {
            var timer = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using (var p = Versioned.Protect(image, siblings))
                    return p.Ok ? Signature.CheckHeld(image, p.Leaf) : null;
            }
            catch (Exception) { return null; }
            finally
            {
                verifications++;
                verifyTicks += timer.Elapsed.Ticks;
                if (image != null) verifiedImages.Add(image);
            }
        }

        // What a scan's held verifications cost: how many ran, for how many programs, and how long they took.
        static int verifications;
        static long verifyTicks;
        static readonly HashSet<string> verifiedImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // For checking entries Argus already kept, again: each program and neighbour check is verified once per
        // scan, however many entries run it (Windows tasks often share one COM server). New decisions verify
        // afresh. Paths are compared exactly: in a case-sensitive folder two spellings can be two files.
        internal static Func<string, Siblings, SignerInfo> OncePerScan(Func<string, Siblings, SignerInfo> verify)
        {
            var seen = new Dictionary<string, SignerInfo>(StringComparer.Ordinal);
            return (image, siblings) =>
            {
                string key = (int)siblings + "|" + image;
                SignerInfo s;
                if (!seen.TryGetValue(key, out s)) { s = verify(image, siblings); seen[key] = s; }
                return s;
            };
        }

        internal const string TrustGone = "the program Argus kept is gone (uninstalled?)";

        // An entry Argus kept on its own because of its program's signature (a routine update, or a new entry
        // for a verified Microsoft program) is verified again on every scan while it stays as kept: the program
        // must be there, verified now from a held handle with the signer identity on record, in folders only
        // admins can change (the same neighbour check that justified keeping it), and a task must still start
        // in an admin-only folder. Returns why not, or null; 'held' is the verification it made (null if none).
        internal static string LostTrust(BaselineEntry b, Item it, Func<string, Siblings, SignerInfo> verify, out SignerInfo held)
        {
            held = null;
            bool missing;
            if (it.Target == null) return "Argus can no longer tell which program it kept";
            if (!Present(it.Target, out missing)) return missing ? TrustGone : "Argus can't open the program it kept to check it";
            held = verify(Versioned.LongPath(it.Target), b.KeptBy == "signature" ? Siblings.Files : Siblings.Tree);
            if (held == null) return "programs running as you can now change the program Argus kept, or its folder (or Argus can't check it)";
            if (!held.Signed || !held.Trusted || string.IsNullOrEmpty(held.Id) || held.Id != b.SignerId) return "the program Argus kept is no longer validly signed by the same publisher";
            // Kept because it was Microsoft's own: still has to be (a WHQL-signed third-party program kept before
            // that changed comes back for a look).
            if (b.KeptBy == "signature" && !held.IsMicrosoft) return "the program Argus kept as Microsoft's isn't signed as Microsoft's own code";
            string dir = it.Category == "task" && it.X("action") == "exec" ? it.X("workdir") : null;
            if (!string.IsNullOrEmpty(dir) && !Versioned.FolderLocked(dir)) return "the task Argus kept now starts in a folder that programs running as you can change";
            return null;
        }

        // Whether the file is there. 'missing' is set only when Windows says the file or a folder on its path
        // doesn't exist (an access error isn't "gone").
        static bool Present(string path, out bool missing)
        {
            missing = false;
            try { return (File.GetAttributes(path) & FileAttributes.Directory) == 0; }
            catch (FileNotFoundException) { missing = true; return false; }
            catch (DirectoryNotFoundException) { missing = true; return false; }
            catch (Exception) { return false; }
        }

        // The item as the held verification saw it, for a finding: its signer fields from that result, not the
        // scan's cached signature.
        static Item AsVerified(Item it, SignerInfo held)
        {
            if (held == null) return it;
            var shown = it.Copy();
            shown.Signed = held.Signed;
            shown.Trusted = held.Trusted;
            shown.Signer = held.Signed ? (held.Publisher ?? "unknown publisher") : null;
            shown.SignerId = held.Trusted ? held.Id : null;
            shown.Microsoft = held.IsMicrosoft && !string.IsNullOrEmpty(held.Id);
            return shown;
        }

        // The baseline record for a new entry Argus keeps because its program verified as Microsoft's: verified
        // once more now from a held handle, recorded with that result, and marked to be verified on every scan.
        // Null when that check fails: then the entry isn't kept (it stays in review).
        static BaselineEntry SignatureKeep(Item it)
        {
            if (it.Target == null) return null;
            var s = VerifyProtected(Versioned.LongPath(it.Target), Siblings.Files);
            if (s == null || !s.IsMicrosoft || string.IsNullOrEmpty(s.Id)) return null;
            var e = Entry(it);
            e.Signer = s.Publisher;
            e.Trusted = true;
            e.SignerId = s.Id;
            e.AutoKept = true;
            e.KeptBy = "signature";
            return e;
        }

        // Whether a pending finding still describes what's there now: the same settings (switched on or off,
        // start mode, account, ...), and for a COM task the same action data, readability and verification.
        // Anything else is a new occurrence with its own alert, so a dismissal or an approval can't carry over.
        internal static bool SameOccurrence(Finding p, Item it)
        {
            if (p == null || p.Now == null || it == null) return false;
            if (!SameSettingsAs(p.Now, it)) return false;
            if (it.Category != "task") return true;
            return p.ComRawHash == it.X("comRawHash") && p.Now.X("inboxCom") == it.X("inboxCom")
                && p.Now.X("comActionsUnverified") == it.X("comActionsUnverified");
        }

        // A notice about a Windows task whose packaged COM handler Argus couldn't verify retires itself once
        // the same, unchanged task verifies as an inbox Windows handler: its server looked missing (legacy), or
        // its action data wasn't a known routine shape and is byte-for-byte the data the notice was raised for.
        internal static bool CanRetireComNotice(Finding pending, Item current, BaselineEntry baseline)
        {
            if (pending == null || pending.Now == null || current == null) return false;
            bool missingServer = pending.Now.Missing && pending.Now.Target == "COM";
            bool unverifiedData = pending.Now.X("comActionsUnverified") == "yes" && !string.IsNullOrEmpty(pending.ComRawHash)
                && pending.ComRawHash == current.X("comRawHash");
            if (pending.Before != null || pending.Kind != "new"
                || pending.Severity != Sev.Notice || pending.Key != current.Key || pending.Now.Hash != current.Hash
                || pending.Now.Category != "task" || !(missingServer || unverifiedData)
                || current.Category != "task" || current.X("inboxCom") != "yes" || current.Target == null
                || (baseline != null && baseline.Hash != current.Hash) || PackagedComChanged(baseline, current))
                return false;

            string why;
            return Rate(current, "new", null, out why) == Sev.Info;
        }

        // ------------------------------------------------------------------ the scan

        public sealed class ScanResult
        {
            public int Entries, Fresh, Auto, Removed, Verifications, VerifiedPrograms;
            public bool First;
            public List<string> Problems = new List<string>();
            public TimeSpan Took;
            public double VerifySeconds;
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
                verifications = 0; verifyTicks = 0; verifiedImages.Clear();
                var recheck = OncePerScan(VerifyProtected);
                var col = new Collector();
                var items = col.All();
                signers = J.Load<Dictionary<string, SignerCacheEntry>>(SignerFile) ?? new Dictionary<string, SignerCacheEntry>(StringComparer.OrdinalIgnoreCase);
                signers = new Dictionary<string, SignerCacheEntry>(signers, StringComparer.OrdinalIgnoreCase);
                // An entry that was collected but couldn't be checked isn't gone: it's kept (and its finding) as
                // last seen, like one that couldn't be read.
                foreach (var it in items) { try { Enrich(it); } catch (Exception e) { col.Unreadable.Add(it.Key); Log.Warn("checking " + it.Key + ": " + e.Message); } }
                try { J.Save(SignerFile, signers); } catch (Exception) { }

                var data = ArgusData.Load(Suite.MyDir);
                if (!data.Readable)
                {
                    string files = string.Join(", ", data.Unreadable);
                    StatusStore.Write(States.Error, "Can't read its saved data", "Argus skipped this scan and changed nothing: " + files + " couldn't be read.", null);
                    throw new InvalidOperationException("couldn't read " + files + "; scan skipped, nothing changed");
                }
                var now = new Dictionary<string, Item>();
                foreach (var it in items) if (it.Hash != null && !now.ContainsKey(it.Key)) now[it.Key] = it;
                var res = new ScanResult { Entries = now.Count, Problems = col.Problems, First = data.Baseline.Count == 0 };
                var fresh = new List<Finding>();
                // Findings saved before alert IDs were recorded get a lasting one now: their alert's (from the
                // protected log), or a new one if that log has moved on, so they stay actionable in the window.
                if (data.Pending.Values.Any(f => string.IsNullOrEmpty(f.AlertId)))
                {
                    var records = ArgusAlertReview.LegacyRecords();
                    foreach (var f in data.Pending.Values.Where(f => string.IsNullOrEmpty(f.AlertId)))
                        f.AlertId = ArgusAlertReview.Id(f, records) ?? ArgusAlertReview.NewId();
                }
                var previousAlerts = ArgusAlertReview.PendingIds(data.Pending.Values);
                // Alerts that were waiting to go out when this scan started (see PublishAlerts).
                var replays = new HashSet<string>(data.Pending.Values.Where(f => f.Unpublished && f.AlertId != null).Select(f => f.AlertId), StringComparer.Ordinal);
                // An area seen in full for the first time (it failed to read before) is just recorded;
                // an area that failed to read now keeps its entries rather than calling them removed.
                var complete = new HashSet<string>((data.Complete ?? "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
                var readNow = new HashSet<string>(Collector.Kinds.Where(k => !col.Failed.Contains(k)));
                // Absence only means "gone" when the area was read in full this scan and the entry itself didn't
                // fail to read (a task or service that errored is kept, as is its finding).
                Func<string, bool> settled = key =>
                {
                    string cat = key.Split('|')[0];
                    return !col.Unreadable.Contains(key) && !col.Partial.Contains(cat)
                        && (!Collector.Kinds.Contains(cat) || (readNow.Contains(cat) && complete.Contains(cat)));
                };
                var previousItems = new Dictionary<string, Item>();
                foreach (var i in data.Current) if (i != null && i.Key != null) previousItems[i.Key] = i;

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
                        // Tasks were hashed on their command, account and run level only; the entry hash now covers
                        // every action (with its working folder and data), the logon type and the group. An entry or
                        // finding recorded the older way moves over silently: nothing recorded then can show whether
                        // those parts changed before this version, which didn't watch them either.
                        string legacy = it.Category == "task" ? EntryHash(it, it.Command + "|" + it.X("runas") + "|" + it.X("highest")) : null;
                        if (legacy != null && legacy != it.Hash)
                        {
                            // An entry whose verified COM data no longer matches what was accepted keeps its old hash, so
                            // the change is reported once and putting the data back makes it match again.
                            if (b != null && b.Hash == legacy && !PackagedComChanged(b, it)) b.Hash = it.Hash;
                            if (p != null && p.Now != null && p.Now.Hash == legacy) p.Now.Hash = it.Hash;
                        }
                        if (CanRetireComNotice(p, it, b))
                        {
                            // Kept because of its signature, so verified again now and on every scan.
                            var retired = SignatureKeep(it);
                            if (retired != null)
                            {
                                data.Baseline[it.Key] = retired;
                                data.Pending.Remove(it.Key);
                                res.Auto++;
                                data.History("auto", it.Key, "Verified the Windows package handler for " + it.Name);
                                continue;
                            }
                        }
                        if (b != null && b.Hash == it.Hash && !PackagedComChanged(b, it))
                        {
                            if (b.ComDataHash == null) b.ComDataHash = VerifiedComData(it);
                            if (b.Settings == null && SettingsKnown(it))
                            {
                                // Settings weren't recorded when this was accepted. The previous scan's item, if it shows the
                                // accepted command, says what they were then (switched on or off, start mode), so a change
                                // made since isn't silently taken as accepted; otherwise today's are recorded.
                                Item last;
                                bool lastShowsAccepted = previousItems.TryGetValue(it.Key, out last) && last != null && last.Category == it.Category
                                    && (last.Hash == b.Hash || (legacy != null && last.Hash == legacy));
                                b.Settings = !lastShowsAccepted ? SettingsOf(it) : SettingsKnown(last) ? SettingsOf(last) : MergedSettings(last, it);
                            }
                            if (b.DriverVer == null && it.Target != null && Versioned.InDriverStore(it.Target)) b.DriverVer = Versioned.DriverVer(it.Target);
                            // An entry accepted before signer identities existed doesn't get one silently now: only a
                            // publisher name survives from then, which doesn't show the program is still the one you
                            // accepted. Its first update gets one review instead (where the install layout doesn't tie
                            // the versions together), and keeping it records the identity.
                            // The same command with other settings: switched off is noted; switched back on, a new
                            // start mode, account, service type or value kind is looked at (SettingsRisk).
                            string settings = SettingsOf(it), swhy = null, ssev = null;
                            if (b.Settings != null && SettingsKnown(it) && !SameSettings(b.Settings, settings))
                            {
                                swhy = SettingsRisk(b.Settings, settings, it, b.TurnedOff, RoutineSwitch, out ssev);
                                if (swhy == null)
                                {
                                    // Noted as what changed. Windows flips some of its own services between start modes
                                    // several times an hour (BITS), so a start-mode change of the same entry is noted at
                                    // most once a day; switching on or off always is.
                                    bool startOnly;
                                    string label = SettingsChangeLabel(b.Settings, settings, out startOnly);
                                    if (!startOnly || !NotedWithin(b.StartNoted, TimeSpan.FromHours(24)))
                                    {
                                        data.History("auto", it.Key, label + ": " + Noun(it.Category) + " " + it.Name
                                            + (startOnly ? " (further start-mode changes of it in the next 24 hours aren't listed)" : ""));
                                        if (startOnly) b.StartNoted = Clock.NowIso();
                                    }
                                    b.Settings = settings;
                                }
                            }
                            // An entry Argus kept on its own is verified again whatever else is going on: a loss of trust
                            // comes first, as an occurrence of its own (with any settings change in its reason), so an
                            // older finding you dismissed can't cover it.
                            SignerInfo held = null;
                            string lost = b.AutoKept ? LostTrust(b, it, recheck, out held) : null;
                            if (lost != null)
                            {
                                string twhy = swhy == null ? lost : lost + "; also " + swhy;
                                string tsev = lost == TrustGone ? Sev.Notice : Sev.Warning;
                                if (ssev != null && Sev.Rank(ssev) > Sev.Rank(tsev)) tsev = ssev;
                                var shown = AsVerified(it, held);
                                if (p != null && p.Kind == "trust" && p.Now != null && p.Now.Hash == it.Hash && p.Why == twhy && SameOccurrence(p, it)) p.Now = shown;
                                else
                                {
                                    var lf = new Finding { Key = it.Key, Kind = "trust", Severity = tsev, Why = twhy, Seen = Clock.NowIso(), Now = shown, Before = b, ComRawHash = it.X("comRawHash") };
                                    data.Pending[it.Key] = lf;
                                    fresh.Add(lf);
                                }
                                continue;
                            }
                            if (p != null && p.Kind == "trust")
                            {
                                // Verified again as kept (a reinstall put the same program back): that finding is over.
                                data.Pending.Remove(it.Key);
                                p = null;
                                data.History("auto", it.Key, "Verified again: " + Noun(it.Category) + " " + it.Name + " (" + (it.Signer ?? "") + ")");
                            }
                            if (swhy != null)
                            {
                                if (p != null && p.Kind == "settings" && p.Now != null && p.Now.Hash == it.Hash && p.Why == swhy && SameOccurrence(p, it)) { p.Now = it; continue; }
                                var sf = new Finding { Key = it.Key, Kind = "settings", Severity = ssev, Why = swhy, Seen = Clock.NowIso(), Now = it, Before = b, ComRawHash = it.X("comRawHash") };
                                data.Pending[it.Key] = sf;
                                fresh.Add(sf);
                                continue;
                            }
                            if (p != null && p.Kind == "settings")
                            {
                                // The settings are back as accepted: that finding is over.
                                data.Pending.Remove(it.Key);
                                p = null;
                                data.History("auto", it.Key, "Settings back as accepted: " + Noun(it.Category) + " " + it.Name);
                            }
                            // The entry is as accepted, and that acceptance came after the finding was raised (a save
                            // interrupted between the baseline and pending files, or a later version kept meanwhile):
                            // the finding is finished, so drop it and let its alert close.
                            if (p != null && (p.Kind == "new" || p.Kind == "changed") && string.CompareOrdinal(b.Accepted ?? "", p.Seen ?? "") >= 0)
                                data.Pending.Remove(it.Key);
                            continue;
                        }
                        if (b != null && it.Category == "task" && OnlyOldQuoting(b.Command, it.Command)
                            && b.Hash == EntryHash(it, b.Command + "|" + it.X("runas") + "|" + it.X("highest")))
                        {
                            var requoted = Entry(it);
                            requoted.TurnedOff = b.TurnedOff;
                            data.Baseline[it.Key] = requoted;
                            continue;
                        }
                        // Checked before the pending test below, so a routine update that was waiting
                        // for review (from before this rule) is kept and its alert closes.
                        SignerInfo verified;
                        if (b != null && RoutineUpdate(b, it, VerifyProtected, out verified))
                        {
                            it.SignerId = verified.Id;
                            var kept = Entry(it);
                            kept.AutoKept = true;
                            kept.KeptBy = "update";
                            kept.TurnedOff = b.TurnedOff;   // still one you turned off: switching it on gets a look
                            data.Baseline[it.Key] = kept;
                            data.Pending.Remove(it.Key);
                            res.Auto++;
                            data.History("auto", it.Key, "Updated: " + Noun(it.Category) + " " + it.Name + " (" + it.Signer + ", new version): " + b.Command + " -> " + it.Command);
                            continue;
                        }
                        // A service that became a driver (or the other way round) is the same registry entry with
                        // another kind: a change to the one you accepted (a warning), never a new entry to keep. Its
                        // old record stays until you've reviewed the switch (see the clean-up below).
                        var switched = b == null ? OtherKind(data.Baseline, it) : null;
                        if (b == null && switched == null && !complete.Contains(it.Category) && !Strong(it)) { data.Baseline[it.Key] = Entry(it); continue; }
                        if (p != null && p.Now != null && p.Now.Hash == it.Hash && SameOccurrence(p, it)) { p.Now = it; continue; }
                        var before = b ?? switched;
                        string kind = before == null ? "new" : "changed";
                        string why;
                        string sev = Rate(it, kind, before, out why);
                        if (switched != null) why = "it changed from a " + Noun(switched.Category) + " to a " + Noun(it.Category) + (string.IsNullOrEmpty(why) ? "" : "; " + why);
                        if (AutoAccept(it, sev))
                        {
                            // A new entry kept because its program verified as Microsoft's in admin-only folders is
                            // recorded from one more held verification and verified again on every scan from now on,
                            // like a routine update. If that verification fails now, it isn't kept: it gets a look.
                            BaselineEntry accepted = Entry(it);
                            if (kind == "new" && ExecKinds.Contains(it.Category) && it.Microsoft) accepted = SignatureKeep(it);
                            if (accepted != null)
                            {
                                data.Baseline[it.Key] = accepted;
                                data.Pending.Remove(it.Key);
                                res.Auto++;
                                data.History("auto", it.Key, (kind == "new" ? "Added: " : "Updated: ") + Noun(it.Category) + " " + it.Name + (it.Signer != null ? " (" + it.Signer + ")" : ""));
                                continue;
                            }
                            sev = Sev.Notice;
                            why = "Argus couldn't verify the program again just now";
                        }
                        var f = new Finding { Key = it.Key, Kind = kind, Severity = sev, Why = why, Seen = Clock.NowIso(), Now = it, Before = before, ComRawHash = it.X("comRawHash") };
                        data.Pending[it.Key] = f;
                        fresh.Add(f);
                    }
                    foreach (var key in data.Baseline.Keys.Where(k => !now.ContainsKey(k)).ToList())
                    {
                        var b = data.Baseline[key];
                        if (!settled(key)) continue;
                        // A service now registered as a driver (or the other way round) that you haven't kept yet:
                        // its old record is what the change is measured against, so it stays until then.
                        string other = OtherKindKey(key);
                        if (other != null && now.ContainsKey(other) && !data.Baseline.ContainsKey(other)) continue;
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
                    foreach (var key in data.Pending.Keys.Where(k => !now.ContainsKey(k) && data.Pending[k].Kind != "removed" && settled(k)).ToList()) data.Pending.Remove(key);
                }

                try
                {
                    if (data.HostsGood == null || data.Baseline.ContainsKey("hosts|" + Collector.HostsPath + "|hosts file") && !data.Pending.Keys.Any(k => k.StartsWith("hosts|")))
                        data.HostsGood = File.ReadAllText(Collector.HostsPath);
                }
                catch (Exception) { }

                complete.UnionWith(readNow);
                data.Complete = string.Join(",", complete.OrderBy(k => k));
                // Each new finding gets its alert ID now and is saved with it before its alert goes out, so a scan
                // stopped in between publishes that same alert next time instead of a second one.
                foreach (var f in fresh)
                    if (Sev.Rank(f.Severity) >= 1) { f.AlertId = ArgusAlertReview.NewId(); f.Unpublished = true; }
                res.Fresh = fresh.Count;
                // Entries that couldn't be read or checked this time stay listed as last seen.
                var current = now.Values.ToList();
                foreach (var key in col.Unreadable)
                {
                    Item last;
                    if (!now.ContainsKey(key) && previousItems.TryGetValue(key, out last)) current.Add(last);
                }
                data.Current = current.OrderBy(i => i.Category).ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList();
                data.LastScan = Clock.NowIso();
                // The first scan's notes aren't kept as findings: they go out before the first baseline is saved,
                // so a scan stopped in between takes the first scan again instead of losing them.
                foreach (var f in fresh.Where(f => { Finding saved; return !data.Pending.TryGetValue(f.Key, out saved) || !ReferenceEquals(saved, f); }).ToList())
                    Raise(f);
                // Closed alert IDs first: recording one twice is harmless, losing one would leave its alert
                // open in the hub after the pending list had already dropped it. If either step fails, the
                // next scan arrives at the same decisions again.
                RecordClosedAlerts(data, previousAlerts);
                data.Save();
                PublishAlerts(data, replays);
                // The whole scan, saving and alerts included, and what its held verifications cost.
                res.Took = DateTime.UtcNow - started;
                res.Verifications = verifications;
                res.VerifiedPrograms = verifiedImages.Count;
                res.VerifySeconds = TimeSpan.FromTicks(verifyTicks).TotalSeconds;
                WriteStatus(data, res);
                Log.Info("scan: " + res.Entries + " entries, " + res.Fresh + " to review, " + res.Auto + " accepted automatically, " + res.Removed + " gone, "
                    + res.Took.TotalSeconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " s"
                    + (res.Verifications > 0 ? " (" + res.Verifications + " held verifications of " + res.VerifiedPrograms + " programs, "
                        + res.VerifySeconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " s)" : "")
                    + (res.Problems.Count > 0 ? "; couldn't read: " + string.Join(" | ", res.Problems) : ""));
                return res;
            }
        }

        public static void RecordClosedAlerts(ArgusData data, Dictionary<string, string> previous)
        {
            var remaining = new HashSet<string>(ArgusAlertReview.PendingIds(data.Pending.Values).Values, StringComparer.Ordinal);
            ArgusAlertReview.RecordResolved(data.Dir, previous.Values.Where(id => !remaining.Contains(id)));
        }

        // Publishes the alerts of saved findings that don't have theirs out yet, each with its saved ID; one
        // stays unpublished (and is tried again next scan) until its alert is written. 'replays' are the IDs
        // that were already waiting when this scan started (a scan stopped after writing the alert but before
        // saving that): one already in the log isn't written twice. Only Argus writes its log, under the scan lock.
        static void PublishAlerts(ArgusData data, HashSet<string> replays)
        {
            var due = data.Pending.Values.Where(f => f.Unpublished).ToList();
            if (due.Count == 0) return;
            var logged = due.Any(f => f.AlertId != null && replays.Contains(f.AlertId))
                ? new HashSet<string>(ArgusAlertReview.LegacyRecords().Select(a => a.Id).Where(id => id != null), StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal);
            foreach (var f in due)
                if ((f.AlertId != null && replays.Contains(f.AlertId) && logged.Contains(f.AlertId)) || Raise(f)) f.Unpublished = false;
            try { data.SavePending(); }
            catch (Exception e) { Log.Warn("saving published alerts: " + e.Message); }
        }

        // True when the alert is out (or there's nothing to publish for a finding this minor).
        static bool Raise(Finding f)
        {
            if (Sev.Rank(f.Severity) < 1) return true;
            var it = f.Now;
            string verb = f.Kind == "new" ? "New " : f.Kind == "changed" || f.Kind == "settings" ? "Changed " : f.Kind == "removed" ? "Turned off: " : "Worth a look: ";
            var sb = new StringBuilder();
            if (!string.IsNullOrEmpty(f.Why)) sb.Append(char.ToUpperInvariant(f.Why[0]) + f.Why.Substring(1) + ".\n");
            sb.Append((it.Category == "extension" ? "Access: " : "Runs: ") + Fmt.Clip(it.Command, 160) + "\n");
            if (ExecKinds.Contains(it.Category)) sb.Append("Signed by: " + (it.Signer ?? "nobody") + "\n");
            if (f.Kind == "changed" && f.Before != null && f.Before.Command != it.Command) sb.Append("Before: " + Fmt.Clip(f.Before.Command, 120) + "\n");
            sb.Append("Where: " + it.Location);
            var a = AlertStore.New(f.Severity, verb + Noun(it.Category) + ": " + Fmt.Clip(it.Name, 60), sb.ToString(), it.Key).With("key", it.Key);
            a.Id = f.AlertId;   // the ID saved with the finding (AlertStore picks one if there's none)
            bool admin = Suite.Installed || Elevation.IsElevated;
            a.Act("accept", f.Kind == "removed" ? "I meant to do that" : "It's fine, keep it", admin);
            if (CanTurnOff(it)) a.Act("disable", "Turn it off", true);
            bool written = AlertStore.Raise(a);
            f.AlertId = a.Id;
            return written;
        }

        static void WriteStatus(ArgusData data, ScanResult res)
        {
            int crit = data.Pending.Values.Count(f => f.Severity == Sev.Critical), total = data.Pending.Count;
            // The exact findings this status counts ("alertId:severity"), so readers can leave out the ones
            // you dismissed without reading a pending list that a newer scan may have replaced meanwhile.
            var ids = ArgusAlertReview.PendingIds(data.Pending.Values);
            string open = string.Join(",", data.Pending.Values.Select(f => (ids[f.Key] ?? "-") + ":" + f.Severity));
            var facts = new Dictionary<string, object>
            {
                { "entries", res.Entries }, { "pending", total }, { "open", open }, { "seconds", (int)res.Took.TotalSeconds },
                { "verifications", res.Verifications }, { "verifiedPrograms", res.VerifiedPrograms },
                { "verifySeconds", Math.Round(res.VerifySeconds, 1) },
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

        // Thrown when an entry changed after Argus showed it to you: Turn off leaves it alone.
        public sealed class ChangedSinceReview : Exception
        {
            public ChangedSinceReview() : base("That entry changed since Argus showed it to you, so nothing was changed.") { }
        }

        // The entry as it's registered right now, read again just before Argus changes it (null: it's gone).
        static Item ReadAgain(Item reviewed)
        {
            var now = new Collector().Only(reviewed.Category).FirstOrDefault(i => i.Key == reviewed.Key);
            if (now != null) now.Hash = EntryHash(now, now.HashBasis ?? now.Command);
            return now;
        }

        // Whether what's registered now is the entry as you reviewed it: the same command and actions (entry
        // hash) and the same settings.
        internal static bool StillAsReviewed(Item reviewed, Item now)
        {
            return reviewed != null && now != null && reviewed.Hash == now.Hash && SameSettingsAs(reviewed, now);
        }

        // A digest of an entry as it was shown to you (key, entry hash, settings), taken before any question, so
        // an action can insist on exactly that state even if a scan records a newer one meanwhile.
        internal static string ReviewDigest(Item it)
        {
            return it == null ? null : FileUtil.Sha256Text((it.Key ?? "") + "\n" + (it.Hash ?? "") + "\n" + (SettingsOf(it) ?? ""));
        }

        // 'reviewed' (ReviewDigest, or null when the caller has none): the saved entry must still be that one.
        internal static bool MatchesReview(Item it, string reviewed)
        {
            return reviewed == null || (it != null && string.Equals(ReviewDigest(it), reviewed, StringComparison.OrdinalIgnoreCase));
        }

        public static UndoRecord TurnOff(ArgusData data, string key)
        {
            return TurnOff(data, key, null);
        }

        public static UndoRecord TurnOff(ArgusData data, string key, string reviewed)
        {
            var it = Find(data, key);
            if (it == null) throw new InvalidOperationException("That entry isn't there any more.");
            if (!MatchesReview(it, reviewed)) throw new ChangedSinceReview();
            if (!CanTurnOff(it)) throw new InvalidOperationException(it.Category == "extension"
                ? "Browsers don't let other programs switch extensions off. Remove it on your browser's Extensions page."
                : "Argus can't turn this kind of entry off; change it by hand.");
            // Turn off changes what's registered now, so that must still be what you reviewed: a registration
            // replaced since the last scan is left alone (the next scan reports it as it is).
            var again = ReadAgain(it);
            if (again == null) throw new InvalidOperationException("That entry isn't there any more.");
            if (!StillAsReviewed(it, again)) throw new ChangedSinceReview();
            var u = new UndoRecord { Id = Guid.NewGuid().ToString("N").Substring(0, 12), Key = key, Time = Clock.NowIso(), What = Noun(it.Category) + ": " + it.Name, Category = it.Category };
            BaselineEntry be;
            u.Entry = data.Baseline.TryGetValue(key, out be) ? be : Entry(it);
            Directory.CreateDirectory(QuarantineDir);
            // What's needed to put it back is saved before Windows is changed: commit() runs right before the
            // first change, so a stop after it leaves an Undo, never a change without one.
            bool committed = false;
            Action commit = () => { data.Undo.Insert(0, u); data.SaveUndo(); committed = true; };
            try
            {
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
                            commit();
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
                            commit();
                            k.SetValue(value, def, RegistryValueKind.String);
                        }
                        break;
                    }
                    case "startup":
                    {
                        string file = it.X("file");
                        string moved = Path.Combine(QuarantineDir, u.Id + "-" + Path.GetFileName(file));
                        u.Data["file"] = file;
                        u.Data["moved"] = moved;
                        commit();
                        File.Move(file, moved);
                        break;
                    }
                    case "task":
                        u.Data["path"] = it.X("path") ?? it.Name;
                        u.Data["enabled"] = it.Enabled ? "1" : "0";   // Undo switches it back on only if it was on
                        commit();
                        Schtasks("/change /tn " + Proc.Quote(it.X("path") ?? it.Name) + " /disable");
                        break;
                    case "service":
                    case "driver":
                    {
                        string svc = it.X("service");
                        using (var k = Reg.Open(@"HKLM\SYSTEM\CurrentControlSet\Services\" + svc, true))
                        {
                            u.Data["start"] = Convert.ToString(k.GetValue("Start"));
                            u.Data["service"] = svc;
                            commit();
                            k.SetValue("Start", 4, RegistryValueKind.DWord);
                        }
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
                            commit();
                            string output;
                            Proc.Run("netsh.exe", "winhttp reset proxy", out output, 20000);
                        }
                        else
                        {
                            using (var k = Reg.Open(it.Location, true))
                            {
                                u.Data["ProxyEnable"] = Convert.ToString(k.GetValue("ProxyEnable"));
                                u.Data["AutoConfigURL"] = k.GetValue("AutoConfigURL") as string ?? "";
                                commit();
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
                        u.Data["saved"] = saved;
                        commit();
                        File.WriteAllText(Collector.HostsPath, data.HostsGood);
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
                        u.Data["location"] = it.Location;
                        u.Data["thumbprint"] = it.X("thumbprint");
                        commit();
                        using (var parent = Reg.Open(it.Location, true)) parent.DeleteSubKeyTree(it.X("thumbprint"));
                        break;
                    }
                    case "wmi":
                    {
                        u.Data["noundo"] = "yes";
                        var scope = new ManagementScope(@"\\.\root\subscription");
                        scope.Connect();
                        string q = it.X("class") == "__FilterToConsumerBinding"
                            ? "SELECT * FROM __FilterToConsumerBinding"
                            : "SELECT * FROM " + it.X("class") + " WHERE Name = '" + it.Name.Replace("'", "''") + "'";
                        commit();
                        using (var s = new ManagementObjectSearcher(scope, new ObjectQuery(q)))
                            foreach (ManagementObject o in s.Get())
                                using (o)
                                {
                                    if (it.X("class") == "__FilterToConsumerBinding" && o.Path.RelativePath != it.X("relpath")) continue;
                                    u.Data["deleted"] = o.Path.RelativePath;
                                    o.Delete();
                                }
                        break;
                    }
                }
                if (!committed) commit();
            }
            catch (Exception)
            {
                // Each change above is one step made after the save, so a failure means nothing changed and the
                // record goes again. Hosts, proxy and WMI changes can stop halfway: their record stays.
                if (committed && it.Category != "hosts" && it.Category != "proxy" && it.Category != "wmi")
                {
                    data.Undo.Remove(u);
                    try { data.SaveUndo(); } catch (Exception) { }
                }
                throw;
            }
            // Tasks, services and drivers stay registered: they're now known as switched off by you, so the next
            // scan doesn't take that for a change, and switching them back on always gets a look (SettingsRisk).
            // An accepted entry keeps its record (and the trust behind it); a new or changed one is recorded only
            // as off, not as accepted.
            if (it.Category == "task" || it.Category == "service" || it.Category == "driver")
            {
                BaselineEntry off;
                if (be != null && be.Hash == it.Hash) off = be.Copy();
                else
                {
                    off = Entry(it);
                    off.AutoKept = false;
                    off.KeptBy = null;
                }
                off.Settings = TurnedOffSettings(it);
                off.TurnedOff = true;
                data.Baseline[key] = off;
            }
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
                case "startup":
                    // Already moved back by an Undo that stopped before it was recorded: nothing left to do.
                    if (!File.Exists(u.D("moved")) && File.Exists(u.D("file"))) break;
                    File.Move(u.D("moved"), u.D("file"));
                    break;
                case "task":
                    if (u.D("enabled") != "0") Schtasks("/change /tn " + Proc.Quote(u.D("path")) + " /enable");
                    break;
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
