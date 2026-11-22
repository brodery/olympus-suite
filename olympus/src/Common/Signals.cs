// How Olympus apps talk to each other: every app writes status.json and appends alerts to
// alerts.jsonl in its data folder; the hub reads them. Also: asking Aegis how it is (over DNS)
// and Ares's "a game is running" flag.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace Olympus
{
    static class States
    {
        public const string Ok = "ok", Warn = "warn", Alert = "alert", Off = "off", Busy = "busy", Error = "error";
        public static int Rank(string s)
        {
            switch (s)
            {
                case Alert: case Error: return 3;
                case Warn: return 2;
                case Ok: case Busy: return 1;
                default: return 0;
            }
        }
    }

    static class Sev
    {
        public const string Info = "info", Notice = "notice", Warning = "warning", Critical = "critical";
        public static int Rank(string s)
        {
            switch (s)
            {
                case Critical: return 3;
                case Warning: return 2;
                case Notice: return 1;
                default: return 0;
            }
        }
    }

    public sealed class StatusInfo
    {
        public string App, State, Summary, Detail, Updated, Version;
        public int Pid;
        public Dictionary<string, object> Facts = new Dictionary<string, object>();
        [ScriptIgnore] public DateTime UpdatedUtc { get { return Clock.Parse(Updated); } }
        public string Fact(string key)
        {
            object v;
            return Facts != null && Facts.TryGetValue(key, out v) && v != null ? Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) : null;
        }
    }

    static class StatusStore
    {
        public const string FileName = "status.json";

        public static void Write(string state, string summary, string detail, Dictionary<string, object> facts)
        {
            var s = new StatusInfo
            {
                App = Suite.Me.Name, State = state, Summary = summary, Detail = detail,
                Updated = Clock.NowIso(), Version = Suite.Version, Pid = Process.GetCurrentProcess().Id
            };
            if (facts != null) s.Facts = facts;
            try { J.Save(Path.Combine(Suite.MyDir, FileName), s); }
            catch (Exception e) { Log.Error("writing status", e); }
        }

        // The freshest status of an app, from either of its data folders.
        public static StatusInfo Read(AppId id)
        {
            string dir;
            return Read(id, out dir);
        }

        // The same, plus the folder it came from, so data that goes with that status is read from there too.
        public static StatusInfo Read(AppId id, out string from)
        {
            StatusInfo best = null;
            from = null;
            foreach (var dir in new[] { Suite.SharedDir(id), Suite.UserDir(id) })
            {
                var s = J.Load<StatusInfo>(Path.Combine(dir, FileName));
                if (s != null && (best == null || s.UpdatedUtc > best.UpdatedUtc)) { best = s; from = dir; }
            }
            return best;
        }
    }

    public sealed class AlertAction
    {
        public string Id, Label;
        public bool Elevate;
    }

    public sealed class AlertInfo
    {
        public string Id, App, Time, Severity, Title, Body, Key;
        public List<AlertAction> Actions = new List<AlertAction>();
        public Dictionary<string, string> Data = new Dictionary<string, string>();
        [ScriptIgnore] public DateTime TimeUtc { get { return Clock.Parse(Time); } }

        public AlertInfo Act(string id, string label, bool elevate)
        {
            Actions.Add(new AlertAction { Id = id, Label = label, Elevate = elevate });
            return this;
        }
        public AlertInfo With(string key, string value)
        {
            Data[key] = value ?? "";
            return this;
        }
        public string Get(string key)
        {
            string v;
            return Data != null && Data.TryGetValue(key, out v) ? v : null;
        }
    }

    static class AlertStore
    {
        public const string FileName = "alerts.jsonl", OldName = "alerts.old.jsonl";
        const long MaxBytes = 1024 * 1024;

        public static AlertInfo New(string severity, string title, string body, string key)
        {
            return new AlertInfo { Severity = severity, Title = title, Body = body, Key = key };
        }

        // True once the alert is written to the log (false: it couldn't be, and the error is logged).
        public static bool Raise(AlertInfo a)
        {
            bool written = false;
            a.App = Suite.Me.Name;
            if (a.Id == null) a.Id = Guid.NewGuid().ToString("N").Substring(0, 16);
            a.Time = Clock.NowIso();
            string dir = Suite.MyDir, path = Path.Combine(dir, FileName);
            Mutex m = null;
            bool owned = false;
            try
            {
                try
                {
                    m = new Mutex(false, (Elevation.IsElevated ? "Global\\" : "Local\\") + "Olympus.alerts." + Suite.Me.Key);
                    owned = m.WaitOne(3000);
                }
                catch (AbandonedMutexException) { owned = true; }
                catch (UnauthorizedAccessException) { m = null; }
                var fi = new FileInfo(path);
                if (fi.Exists && fi.Length > MaxBytes)
                {
                    string old = Path.Combine(dir, OldName);
                    FileUtil.TryDelete(old);
                    File.Move(path, old);
                }
                using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    var b = Encoding.UTF8.GetBytes(J.Write(a) + "\n");
                    fs.Write(b, 0, b.Length);
                }
                written = true;
                Log.Info("alert (" + a.Severity + "): " + a.Title);
            }
            catch (Exception e) { Log.Error("raising alert", e); }
            finally
            {
                if (m != null)
                {
                    if (owned) { try { m.ReleaseMutex(); } catch (Exception) { } }
                    m.Dispose();
                }
            }
            return written;
        }

        // Complete lines added since offset (also reads the tail of a file rotated in between).
        public static List<AlertInfo> Tail(string dir, ref long offset)
        {
            var list = new List<AlertInfo>();
            string path = Path.Combine(dir, FileName);
            long len = 0;
            try { if (File.Exists(path)) len = new FileInfo(path).Length; } catch (Exception) { }
            if (len < offset)
            {
                ReadFrom(Path.Combine(dir, OldName), offset, list);
                offset = 0;
            }
            if (len > offset) offset = ReadFrom(path, offset, list);
            return list;
        }

        static long ReadFrom(string path, long offset, List<AlertInfo> into)
        {
            try
            {
                if (!File.Exists(path)) return offset;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (offset >= fs.Length) return Math.Min(offset, fs.Length);
                    fs.Seek(offset, SeekOrigin.Begin);
                    var buf = new byte[fs.Length - offset];
                    int n = 0;
                    while (n < buf.Length)
                    {
                        int r = fs.Read(buf, n, buf.Length - n);
                        if (r <= 0) break;
                        n += r;
                    }
                    if (n == 0) return offset;
                    int lastNl = Array.LastIndexOf(buf, (byte)'\n', n - 1);
                    if (lastNl < 0) return offset;
                    string text = Encoding.UTF8.GetString(buf, 0, lastNl + 1);
                    foreach (var line in text.Split('\n'))
                    {
                        if (line.Trim().Length == 0) continue;
                        try { into.Add(J.Read<AlertInfo>(line)); } catch (Exception) { }
                    }
                    return offset + lastNl + 1;
                }
            }
            catch (IOException) { return offset; }
            catch (UnauthorizedAccessException) { return offset; }
        }

        // The newest alerts of one app (both data folders), newest first.
        public static List<AlertInfo> Recent(AppId id, int max)
        {
            var all = new List<AlertInfo>();
            foreach (var dir in new[] { Suite.SharedDir(id), Suite.UserDir(id) })
            {
                ReadFrom(Path.Combine(dir, OldName), 0, all);
                ReadFrom(Path.Combine(dir, FileName), 0, all);
            }
            return all.Where(a => a != null).OrderByDescending(a => a.Time, StringComparer.Ordinal).Take(max).ToList();
        }

        // The alerts only an installed SYSTEM engine could have written: its ProgramData logs, read only while
        // they are protected (nothing else can add to them). Newest first.
        public static List<AlertInfo> RecentProtected(AppId id)
        {
            var all = new List<AlertInfo>();
            var dir = Suite.SharedDir(id);
            if (!IsProtected(Suite.ProgramDataRoot, true) || !IsProtected(dir, true)) return all;
            foreach (string name in new[] { OldName, FileName })
            {
                var file = Path.Combine(dir, name);
                if (File.Exists(file) && IsProtected(file, false)) ReadFrom(file, 0, all);
            }
            return all.Where(a => a != null).OrderByDescending(a => a.Time, StringComparer.Ordinal).ToList();
        }

        public static AlertInfo Find(AppId id, string alertId)
        {
            return Recent(id, int.MaxValue).FirstOrDefault(a => a.Id == alertId);
        }

        // Installed SYSTEM engines take action on records their own engine could have written.
        public static AlertInfo FindForAction(AppId id, string alertId, string actionId)
        {
            if (!Regex.IsMatch(alertId ?? "", @"\A[0-9a-f]{16}\z") || string.IsNullOrEmpty(actionId)) return null;
            var app = AppInfo.Of(id);
            bool sharedOnly = app.SystemEngine && (Suite.Installed || Elevation.IsElevated);
            if (id == AppId.Argus && ArgusAlertReview.IsResolved(alertId, sharedOnly)) return null;
            if (!sharedOnly)
            {
                var record = Find(id, alertId);
                return Offers(record, app, actionId) ? record : null;
            }

            var dir = Suite.SharedDir(id);
            if (!IsProtected(Suite.ProgramDataRoot, true) || !IsProtected(dir, true)) return null;
            var records = new List<AlertInfo>();
            foreach (string name in new[] { OldName, FileName })
            {
                var file = Path.Combine(dir, name);
                if (IsProtected(file, false)) ReadFrom(file, 0, records);
            }
            return records.Where(a => Offers(a, app, actionId) && a.Id == alertId)
                .OrderByDescending(a => a.Time, StringComparer.Ordinal).FirstOrDefault();
        }

        static bool Offers(AlertInfo record, AppInfo app, string actionId)
        {
            return record != null && record.App == app.Name && record.Actions != null
                && record.Actions.Any(a => a != null && a.Id == actionId);
        }

        internal static bool IsProtected(string path, bool directory)
        {
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
                const AccessControlSections sections = AccessControlSections.Access | AccessControlSections.Owner;
                FileSystemSecurity acl = directory ? (FileSystemSecurity)Directory.GetAccessControl(path, sections) : File.GetAccessControl(path, sections);
                var owner = (SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier));
                if (!Trusted(owner)) return false;
                var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                if (rules.Count == 0) return false;
                const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
                    | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | (FileSystemRights)0x50000000; // generic write/all
                return !rules.OfType<FileSystemAccessRule>().Any(r => r.AccessControlType == AccessControlType.Allow
                    && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0 && (r.FileSystemRights & writes) != 0
                    && !Trusted((SecurityIdentifier)r.IdentityReference));
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (System.Security.SecurityException) { return false; }
        }

        static bool Trusted(SecurityIdentifier id)
        {
            return id != null && (id.IsWellKnown(WellKnownSidType.LocalSystemSid) || id.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        }
    }

    // Aegis answers TXT questions about itself on 127.0.0.1:53 (status.aegis.invalid,
    // NAME.check.aegis.invalid). Asking it directly works even while Windows isn't using it.
    static class AegisClient
    {
        public static string Txt(string name, int timeoutMs)
        {
            try
            {
                using (var udp = new UdpClient(AddressFamily.InterNetwork))
                {
                    udp.Client.ReceiveTimeout = timeoutMs;
                    var q = Query(name, 16);
                    udp.Send(q, q.Length, new IPEndPoint(IPAddress.Loopback, 53));
                    var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                    while (DateTime.UtcNow < deadline)
                    {
                        var from = new IPEndPoint(IPAddress.Any, 0);
                        var r = udp.Receive(ref from);
                        if (r.Length >= 2 && r[0] == q[0] && r[1] == q[1]) return ParseTxt(r);
                    }
                }
            }
            catch (Exception) { }
            return null;
        }

        static byte[] Query(string name, int qtype)
        {
            var b = new List<byte>();
            int id = new Random().Next(1, 65535);
            b.Add((byte)(id >> 8)); b.Add((byte)id);
            b.Add(1); b.Add(0);                              // recursion desired
            b.AddRange(new byte[] { 0, 1, 0, 0, 0, 0, 0, 0 });  // one question
            foreach (var label in name.TrimEnd('.').Split('.'))
            {
                var l = Encoding.ASCII.GetBytes(label);
                if (l.Length == 0 || l.Length > 63) throw new ArgumentException("bad name");
                b.Add((byte)l.Length);
                b.AddRange(l);
            }
            b.Add(0);
            b.Add((byte)(qtype >> 8)); b.Add((byte)qtype);
            b.Add(0); b.Add(1);
            return b.ToArray();
        }

        static string ParseTxt(byte[] r)
        {
            if (r.Length < 12 || (r[3] & 15) != 0) return null;
            int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
            int p = 12;
            for (int i = 0; i < qd; i++) p = SkipName(r, p) + 4;
            var sb = new StringBuilder();
            for (int i = 0; i < an && p + 10 <= r.Length; i++)
            {
                p = SkipName(r, p);
                if (p + 10 > r.Length) break;
                int type = (r[p] << 8) | r[p + 1];
                int len = (r[p + 8] << 8) | r[p + 9];
                p += 10;
                if (type == 16)
                {
                    int end = Math.Min(r.Length, p + len), x = p;
                    while (x < end)
                    {
                        int l = r[x++];
                        sb.Append(Encoding.UTF8.GetString(r, x, Math.Min(l, end - x)));
                        x += l;
                    }
                }
                p += len;
            }
            return sb.Length > 0 ? sb.ToString() : null;
        }

        static int SkipName(byte[] r, int p)
        {
            while (p < r.Length)
            {
                int l = r[p];
                if (l == 0) return p + 1;
                if ((l & 0xC0) == 0xC0) return p + 2;
                p += l + 1;
            }
            return p;
        }

        public static Dictionary<string, string> Fields(string txt)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (txt == null) return d;
            foreach (var part in txt.Split(';'))
            {
                int eq = part.IndexOf('=');
                if (eq > 0) d[part.Substring(0, eq).Trim()] = part.Substring(eq + 1).Trim();
            }
            return d;
        }

        public static Dictionary<string, string> Status() { return Fields(Txt("status.aegis.invalid", 700)); }

        // "block", "allow" or "none"; null if Aegis didn't answer.
        public static string Verdict(string name, out string rule)
        {
            rule = null;
            Dictionary<string, string> f;
            try { f = Fields(Txt(name.Trim().TrimEnd('.') + ".check.aegis.invalid", 700)); }
            catch (Exception) { return null; }
            string v;
            if (f.TryGetValue("rule", out rule) == false) rule = null;
            return f.TryGetValue("verdict", out v) ? v : null;
        }

        // Does Windows send its lookups to Aegis (127.0.0.1 or ::1 on a connected adapter)?
        public static bool WindowsUsesAegis()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var dns in nic.GetIPProperties().DnsAddresses)
                        if (IPAddress.IsLoopback(dns)) return true;
                }
            }
            catch (Exception) { }
            return false;
        }

        public static string Exe
        {
            get
            {
                try
                {
                    using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                    {
                        string v = k == null ? null : k.GetValue("Aegis") as string;
                        if (!string.IsNullOrEmpty(v))
                        {
                            v = v.Trim();
                            string exe = v.StartsWith("\"") ? v.Substring(1, v.IndexOf('"', 1) - 1) : v.Split(' ')[0];
                            if (File.Exists(exe)) return exe;
                        }
                    }
                }
                catch (Exception) { }
                return null;
            }
        }
    }

    // Ares sets this while a game runs (heartbeat every minute); readable by every app,
    // including SYSTEM engines (through the path the installer recorded).
    public sealed class GameInfo
    {
        public bool Playing;
        public string Game, Path, Since, Updated;
    }

    static class GameState
    {
        public static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Ares), "game.json"); } }

        public static GameInfo Read()
        {
            var g = J.Load<GameInfo>(FilePath);
            if (g == null || (DateTime.UtcNow - Clock.Parse(g.Updated)).TotalMinutes > 3) return null;
            return g;
        }
        public static bool Playing { get { var g = Read(); return g != null && g.Playing; } }
    }
}
