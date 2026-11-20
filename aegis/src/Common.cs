// Aegis - shared code for the engine, the tray app and the tests:
// paths, settings, DNS wire format, blocklist parsing, rules, and the small
// client the tray and the command line use to talk to the running engine.
// C# 5 (the compiler that ships with Windows), .NET Framework 4.8.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Aegis
{
    static class App
    {
        public const string Name = "Aegis";
        public const string Title = "Aegis DNS filter";
        public const string Version = "1.0.1";
        public const string ControlZone = "aegis.invalid";      // names the engine answers itself
        public const string ControlSuffix = ".aegis.invalid";
        public static readonly string ProgramDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');
        static readonly bool Bundled = String.Equals(ProgramDir,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Olympus Aegis"),
            StringComparison.OrdinalIgnoreCase);
        public static string Dir = Bundled
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Olympus Suite", Name)
            : ProgramDir;

        public static string IniPath { get { return Path.Combine(Dir, "aegis.ini"); } }
        public static string AllowPath { get { return Path.Combine(Dir, "allow.txt"); } }
        public static string BlockPath { get { return Path.Combine(Dir, "block.txt"); } }
        public static string ListDir { get { return Path.Combine(Dir, "lists"); } }
        public static string LogDir { get { return Path.Combine(Dir, "logs"); } }
        public static string StateDir { get { return Path.Combine(Dir, "state"); } }
        public static string PausePath { get { return Path.Combine(StateDir, "pause.txt"); } }
        public static string CountsPath { get { return Path.Combine(StateDir, "counts.txt"); } }
        public static string InstallPath { get { return Path.Combine(Bundled ? Path.Combine(ProgramDir, "state") : StateDir, "install.json"); } }

        public static void EnsureDirs()
        {
            Directory.CreateDirectory(ListDir);
            Directory.CreateDirectory(LogDir);
            Directory.CreateDirectory(StateDir);
            if (Bundled && !File.Exists(IniPath))
            {
                try { File.Copy(Path.Combine(ProgramDir, "aegis.ini"), IniPath); }
                catch (IOException) { if (!File.Exists(IniPath)) throw; }
            }
        }

        public static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static long Unix(DateTime utc) { return (long)(utc - Epoch).TotalSeconds; }
        public static DateTime FromUnix(long seconds) { return Epoch.AddSeconds(seconds); }
    }

    // Plain-text log for the engine or the tray (logs\engine.log / logs\tray.log), rolled at 1 MB.
    static class Log
    {
        static readonly object Gate = new object();
        static string path;

        public static void Init(string name)
        {
            try { Directory.CreateDirectory(App.LogDir); } catch { }
            path = Path.Combine(App.LogDir, name + ".log");
        }

        public static void Info(string msg) { Write("INFO ", msg); }
        public static void Warn(string msg) { Write("WARN ", msg); }
        public static void Error(string msg) { Write("ERROR", msg); }

        static void Write(string level, string msg)
        {
            if (path == null) return;
            lock (Gate)
            {
                try
                {
                    var fi = new FileInfo(path);
                    if (fi.Exists && fi.Length > 1000000)
                    {
                        string old = Path.ChangeExtension(path, ".old.log");
                        File.Delete(old);
                        File.Move(path, old);
                    }
                    File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
                        + " " + level + " " + msg + Environment.NewLine);
                }
                catch { }
            }
        }
    }

    // "key=value;key=value" strings, used by the engine's status replies.
    static class Kv
    {
        public static Dictionary<string, string> Parse(string text)
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            if (text == null) return d;
            foreach (var part in text.Split(';'))
            {
                int eq = part.IndexOf('=');
                if (eq > 0) d[part.Substring(0, eq).Trim()] = part.Substring(eq + 1).Trim();
            }
            return d;
        }

        public static string Get(Dictionary<string, string> d, string key, string fallback)
        {
            string v;
            return d.TryGetValue(key, out v) ? v : fallback;
        }

        public static long Long(Dictionary<string, string> d, string key)
        {
            long v;
            return long.TryParse(Get(d, key, ""), NumberStyles.Integer, CultureInfo.InvariantCulture, out v) ? v : 0;
        }

        public static string Clean(string s)
        {
            return (s ?? "").Replace(';', ',').Replace('=', ':').Replace('\r', ' ').Replace('\n', ' ');
        }
    }

    // ------------------------------------------------------------------ settings (aegis.ini)

    sealed class ListSource
    {
        public string Name, Url, Mirror;
        public string FilePath { get { return Path.Combine(App.ListDir, Name + ".txt"); } }
    }

    sealed class Config
    {
        public string[] Listen = { "127.0.0.1", "::1" };
        public int Port = 53;
        public string[] Upstreams = { "9.9.9.9", "149.112.112.112", "2620:fe::fe" };
        public string Router = "auto";
        public string[] LocalDomains = { "mynetworksettings.com", "lan", "home", "home.arpa", "local", "localdomain", "internal" };
        public int BlockTtl = 5;
        public bool CnameInspection = true;
        public int CacheEntries = 20000;
        public int MaxCacheTtl = 3600;
        public int UpstreamTimeoutMs = 2500;
        public int MaxClientTtl = 60;
        public bool RouterFallback = true;
        public int UpdateHours = 24;
        public bool LogAllQueries = false;
        public int KeepLogDays = 7;
        public List<ListSource> Lists = new List<ListSource>();
        public readonly List<string> Problems = new List<string>();
        public bool ReadFailed;      // the file exists but couldn't be read (locked?): keep the settings in use

        const string Hagezi = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";
        const string HageziMirror = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/";

        public static List<ListSource> DefaultLists()
        {
            return new List<ListSource>
            {
                new ListSource { Name = "hagezi-pro", Url = Hagezi + "pro-onlydomains.txt", Mirror = HageziMirror + "pro-onlydomains.txt" },
                new ListSource { Name = "hagezi-tif-full", Url = Hagezi + "tif-onlydomains.txt", Mirror = HageziMirror + "tif-onlydomains.txt" },
            };
        }

        public static Config Load()
        {
            var c = new Config();
            string[] lines;
            try
            {
                if (!File.Exists(App.IniPath))
                {
                    c.Lists = DefaultLists();
                    try { File.WriteAllText(App.IniPath, DefaultIni(), new UTF8Encoding(false)); } catch { }
                    return c;
                }
                lines = File.ReadAllLines(App.IniPath);
            }
            catch (Exception e)
            {
                c.Problems.Add("can't read aegis.ini (" + e.Message + "); using defaults");
                c.Lists = DefaultLists();
                c.ReadFailed = true;
                return c;
            }
            string section = "";
            bool sawLists = false;
            for (int n = 0; n < lines.Length; n++)
            {
                string line = lines[n].Trim();
                if (line.Length == 0 || line[0] == ';' || line[0] == '#') continue;
                if (line[0] == '[')
                {
                    section = line.Trim('[', ']', ' ').ToLowerInvariant();
                    if (section == "lists") sawLists = true;
                    continue;
                }
                int eq = line.IndexOf('=');
                if (eq <= 0) { c.Problems.Add("line " + (n + 1) + ": expected key = value"); continue; }
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
                try { c.Set(section, key, val); }
                catch (Exception e) { c.Problems.Add("line " + (n + 1) + " (" + key + "): " + e.Message); }
            }
            if (!sawLists) c.Lists = DefaultLists();
            return c;
        }

        void Set(string section, string key, string val)
        {
            if (section == "lists")
            {
                if (key == "update_hours") { UpdateHours = Clamp(Int(val), 1, 24 * 30); return; }
                if (!Regex.IsMatch(key, "^[a-z0-9._-]+$")) throw new FormatException("list names may only use a-z 0-9 . _ -");
                string[] parts = val.Split('|').Select(p => p.Trim()).ToArray();
                if (!IsUrl(parts[0])) throw new FormatException("expected a URL");
                string mirror = parts.Length > 1 && IsUrl(parts[1]) ? parts[1] : null;
                Lists.Add(new ListSource { Name = key, Url = parts[0], Mirror = mirror });
                return;
            }
            switch (key)
            {
                case "listen": Listen = Csv(val).Select(a => IPAddress.Parse(a).ToString()).ToArray(); break;
                case "port": Port = Clamp(Int(val), 1, 65535); break;
                case "upstreams": Upstreams = Csv(val).Select(a => IPAddress.Parse(a).ToString()).ToArray(); break;
                case "router": Router = val.ToLowerInvariant(); break;
                case "local_domains": LocalDomains = Csv(val).Select(d => d.ToLowerInvariant().Trim('.')).ToArray(); break;
                case "block_ttl": BlockTtl = Clamp(Int(val), 0, 86400); break;
                case "cname_inspection": CnameInspection = Bool(val); break;
                case "cache_entries": CacheEntries = Clamp(Int(val), 0, 1000000); break;
                case "max_cache_ttl": MaxCacheTtl = Clamp(Int(val), 0, 86400); break;
                case "upstream_timeout_ms": UpstreamTimeoutMs = Clamp(Int(val), 200, 30000); break;
                case "max_client_ttl": MaxClientTtl = Clamp(Int(val), 0, 86400); break;
                case "router_fallback": RouterFallback = Bool(val); break;
                case "log_all_queries": LogAllQueries = Bool(val); break;
                case "keep_log_days": KeepLogDays = Clamp(Int(val), 1, 365); break;
                default: throw new FormatException("unknown setting");
            }
        }

        static bool IsUrl(string s)
        {
            return s.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
        }
        static string[] Csv(string v) { return v.Split(new[] { ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries); }
        static int Int(string v) { return int.Parse(v, NumberStyles.Integer, CultureInfo.InvariantCulture); }
        static int Clamp(int v, int lo, int hi) { return Math.Max(lo, Math.Min(hi, v)); }
        static bool Bool(string v)
        {
            switch (v.ToLowerInvariant())
            {
                case "true": case "yes": case "on": case "1": return true;
                case "false": case "no": case "off": case "0": return false;
            }
            throw new FormatException("expected true or false");
        }

        public static string DefaultIni()
        {
            var b = new StringBuilder();
            b.AppendLine("; Aegis DNS filter settings.");
            b.AppendLine("; Changes apply within a few seconds, except listen/port (restart the PC for those).");
            b.AppendLine();
            b.AppendLine("[dns]");
            b.AppendLine("; Addresses Aegis answers on. install.ps1 points Windows at these.");
            b.AppendLine("listen = 127.0.0.1, ::1");
            b.AppendLine("port = 53");
            b.AppendLine("; Where allowed lookups go. Quad9 also refuses known malware domains.");
            b.AppendLine("upstreams = 9.9.9.9, 149.112.112.112, 2620:fe::fe");
            b.AppendLine("; Local names (local_domains, single-label names, private reverse lookups) go to");
            b.AppendLine("; your router instead. auto = the DNS server you had before installing; none = off.");
            b.AppendLine("router = auto");
            b.AppendLine("local_domains = mynetworksettings.com, lan, home, home.arpa, local, localdomain, internal");
            b.AppendLine("; If Quad9 can't be reached at all, ask the router instead (still filtered by the lists).");
            b.AppendLine("router_fallback = true");
            b.AppendLine("; Seconds Windows may remember a 'blocked' answer. Short, so allowing a site works fast.");
            b.AppendLine("block_ttl = 5");
            b.AppendLine("; Also block a name that is an alias (CNAME) of a blocked domain.");
            b.AppendLine("cname_inspection = true");
            b.AppendLine("cache_entries = 20000");
            b.AppendLine("max_cache_ttl = 3600");
            b.AppendLine("upstream_timeout_ms = 2500");
            b.AppendLine("; Longest time (seconds) Windows may keep an allowed answer, so a new block works within a minute.");
            b.AppendLine("max_client_ttl = 60");
            b.AppendLine();
            b.AppendLine("[lists]");
            b.AppendLine("; name = URL | mirror URL. A listed domain also blocks all of its subdomains.");
            b.AppendLine("update_hours = 24");
            foreach (var l in DefaultLists()) b.AppendLine(l.Name + " = " + l.Url + " | " + l.Mirror);
            b.AppendLine();
            b.AppendLine("[logs]");
            b.AppendLine("; true = log every lookup (logs\\queries-DATE.log), not only blocked ones.");
            b.AppendLine("log_all_queries = false");
            b.AppendLine("keep_log_days = 7");
            return b.ToString();
        }
    }

    // ------------------------------------------------------------------ DNS wire format

    sealed class DnsFormatException : Exception
    {
        public DnsFormatException(string message) : base(message) { }
    }

    // One resource record: Start is where its owner name begins, Pos is the offset of its TYPE field
    // (TTL at Pos+4, data at Pos+10).
    struct Rec
    {
        public int Section;   // 1 answer, 2 authority, 3 additional
        public int Start, Pos, Type, RdLen;
        public uint Ttl;
    }

    static class Dns
    {
        public const int QR = 0x8000, AA = 0x0400, TC = 0x0200, RD = 0x0100, RA = 0x0080, AD = 0x0020, CD = 0x0010, OPCODE = 0x7800;
        public const int A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16, AAAA = 28, SRV = 33, OPT = 41, SVCB = 64, HTTPS = 65, ANY = 255;
        public const int NOERROR = 0, FORMERR = 1, SERVFAIL = 2, NXDOMAIN = 3, NOTIMP = 4, REFUSED = 5;

        public static string TypeName(int t)
        {
            switch (t)
            {
                case A: return "A";
                case NS: return "NS";
                case CNAME: return "CNAME";
                case SOA: return "SOA";
                case PTR: return "PTR";
                case MX: return "MX";
                case TXT: return "TXT";
                case AAAA: return "AAAA";
                case SRV: return "SRV";
                case SVCB: return "SVCB";
                case HTTPS: return "HTTPS";
                case ANY: return "ANY";
                default: return "TYPE" + t;
            }
        }

        public static string RcodeName(int r)
        {
            switch (r)
            {
                case NOERROR: return "NOERROR";
                case FORMERR: return "FORMERR";
                case SERVFAIL: return "SERVFAIL";
                case NXDOMAIN: return "NXDOMAIN";
                case NOTIMP: return "NOTIMP";
                case REFUSED: return "REFUSED";
                default: return "RCODE" + r;
            }
        }

        public static int U16(byte[] b, int i) { return (b[i] << 8) | b[i + 1]; }
        public static uint U32(byte[] b, int i) { return ((uint)b[i] << 24) | ((uint)b[i + 1] << 16) | ((uint)b[i + 2] << 8) | b[i + 3]; }
        public static void W16(byte[] b, int i, int v) { b[i] = (byte)(v >> 8); b[i + 1] = (byte)v; }
        public static void W32(byte[] b, int i, uint v) { b[i] = (byte)(v >> 24); b[i + 1] = (byte)(v >> 16); b[i + 2] = (byte)(v >> 8); b[i + 3] = (byte)v; }

        public static byte LowerAscii(byte b) { return (b >= 65 && b <= 90) ? (byte)(b + 32) : b; }

        // Offset just past the (possibly compressed) name that starts at pos.
        public static int SkipName(byte[] m, int pos)
        {
            while (true)
            {
                if (pos >= m.Length) throw new DnsFormatException("name runs past the end");
                int n = m[pos];
                if (n == 0) return pos + 1;
                if (n >= 0xC0)
                {
                    if (pos + 2 > m.Length) throw new DnsFormatException("cut-off pointer");
                    return pos + 2;
                }
                if (n > 63) throw new DnsFormatException("bad label length");
                pos += 1 + n;
            }
        }

        // Lower-case dotted name at pos, following compression pointers; end = offset after it.
        public static string ReadName(byte[] m, int pos, out int end)
        {
            var sb = new StringBuilder();
            end = -1;
            int jumps = 0;
            while (true)
            {
                if (pos >= m.Length) throw new DnsFormatException("name runs past the end");
                int n = m[pos];
                if (n == 0) { pos++; break; }
                if (n >= 0xC0)
                {
                    if (pos + 2 > m.Length) throw new DnsFormatException("cut-off pointer");
                    if (end < 0) end = pos + 2;
                    pos = ((n & 0x3F) << 8) | m[pos + 1];
                    if (++jumps > 64) throw new DnsFormatException("pointer loop");
                    continue;
                }
                if (n > 63 || pos + 1 + n > m.Length) throw new DnsFormatException("bad label");
                if (sb.Length > 0) sb.Append('.');
                for (int i = 1; i <= n; i++) sb.Append((char)LowerAscii(m[pos + i]));
                pos += 1 + n;
            }
            if (end < 0) end = pos;
            return sb.ToString();
        }

        // Every resource record after the question section.
        public static IEnumerable<Rec> Records(byte[] m)
        {
            if (m.Length < 12) throw new DnsFormatException("short message");
            int qd = U16(m, 4);
            int[] counts = { U16(m, 6), U16(m, 8), U16(m, 10) };
            int p = 12;
            for (int i = 0; i < qd; i++) p = SkipName(m, p) + 4;
            for (int s = 0; s < 3; s++)
            {
                for (int i = 0; i < counts[s]; i++)
                {
                    int start = p;
                    p = SkipName(m, p);
                    if (p + 10 > m.Length) throw new DnsFormatException("cut-off record");
                    var r = new Rec { Section = s + 1, Start = start, Pos = p, Type = U16(m, p), Ttl = U32(m, p + 4), RdLen = U16(m, p + 8) };
                    if (p + 10 + r.RdLen > m.Length) throw new DnsFormatException("cut-off record data");
                    yield return r;
                    p += 10 + r.RdLen;
                }
            }
        }
    }

    // A parsed client query.
    sealed class Query
    {
        public byte[] Raw;
        public int Id, Flags, QType, QClass, QEnd;
        public string Name;
        public bool Edns, Do, HasEdnsOptions, HasExtraRecords;
        public int UdpSize = 512, EdnsVersion;

        public int UdpLimit { get { return Edns ? Math.Max(512, UdpSize) : 512; } }

        public static Query Parse(byte[] raw)
        {
            if (raw.Length < 12) throw new DnsFormatException("short message");
            var q = new Query { Raw = raw, Id = Dns.U16(raw, 0), Flags = Dns.U16(raw, 2) };
            if ((q.Flags & Dns.QR) != 0) throw new DnsFormatException("not a query");
            if (Dns.U16(raw, 4) != 1) throw new DnsFormatException("expected exactly one question");
            var sb = new StringBuilder();
            int pos = 12;
            while (true)
            {
                if (pos >= raw.Length) throw new DnsFormatException("cut-off name");
                int n = raw[pos];
                if (n == 0) { pos++; break; }
                if (n > 63 || pos + 1 + n > raw.Length) throw new DnsFormatException("bad name in question");
                if (sb.Length > 0) sb.Append('.');
                for (int i = 1; i <= n; i++) sb.Append((char)Dns.LowerAscii(raw[pos + i]));
                pos += 1 + n;
                if (pos - 12 > 255) throw new DnsFormatException("name too long");
            }
            if (pos + 4 > raw.Length) throw new DnsFormatException("cut-off question");
            q.Name = sb.ToString();
            q.QType = Dns.U16(raw, pos);
            q.QClass = Dns.U16(raw, pos + 2);
            q.QEnd = pos + 4;
            // The rest must be well-formed too: at most one OPT record, owned by the root, in the
            // additional section (RFC 6891). Anything else is a FORMERR.
            int opts = 0;
            foreach (var r in Dns.Records(raw))
            {
                if (r.Type != Dns.OPT)
                {
                    q.HasExtraRecords = true;      // e.g. TSIG: such a query never shares a cached reply
                    continue;
                }
                if (r.Section != 3 || ++opts > 1 || r.Pos != r.Start + 1 || raw[r.Start] != 0)
                    throw new DnsFormatException("bad OPT record");
                CheckOptions(raw, r.Pos + 10, r.RdLen);
                q.Edns = true;
                q.UdpSize = Dns.U16(raw, r.Pos + 2);
                q.EdnsVersion = (int)((r.Ttl >> 16) & 0xFF);
                q.Do = (r.Ttl & 0x8000) != 0;
                q.HasEdnsOptions = r.RdLen > 0;
            }
            return q;
        }

        // Each EDNS option is code (2), length (2), data; together they must fill the OPT data exactly.
        static void CheckOptions(byte[] m, int start, int length)
        {
            int p = start, end = start + length;
            while (p < end)
            {
                if (p + 4 > end) throw new DnsFormatException("cut-off EDNS option");
                p += 4 + Dns.U16(m, p + 2);
                if (p > end) throw new DnsFormatException("cut-off EDNS option");
            }
        }

        // Cache key: the question with the name lower-cased, plus the flags that change the answer.
        // (Queries carrying EDNS options, such as cookies, aren't cached at all; see the engine.)
        public string CacheKey()
        {
            var sb = new StringBuilder(QEnd + 8);
            for (int i = 12; i < QEnd - 4; i++) sb.Append((char)Dns.LowerAscii(Raw[i]));
            for (int i = QEnd - 4; i < QEnd; i++) sb.Append((char)Raw[i]);
            sb.Append(Edns ? '1' : '0').Append(Do ? '1' : '0').Append('|').Append(Flags & (Dns.RD | Dns.AD | Dns.CD));
            return sb.ToString();
        }
    }

    sealed class RR
    {
        public int Type, Ttl;
        public byte[] Data;
        public RR(int type, int ttl, byte[] data) { Type = type; Ttl = ttl; Data = data; }
    }

    // Replies the engine makes up itself.
    static class Reply
    {
        public static byte[] EncodeName(string name)
        {
            var ms = new MemoryStream();
            foreach (var label in name.Trim('.').Split('.'))
            {
                if (label.Length == 0) continue;
                byte[] b = Encoding.ASCII.GetBytes(label);
                if (b.Length > 63) throw new ArgumentException("label too long");
                ms.WriteByte((byte)b.Length);
                ms.Write(b, 0, b.Length);
            }
            ms.WriteByte(0);
            if (ms.Length > 255) throw new ArgumentException("name too long");
            return ms.ToArray();
        }

        static readonly byte[] SoaNames = Concat(EncodeName("blocked" + App.ControlSuffix), EncodeName("nobody" + App.ControlSuffix));

        static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        public static byte[] SoaData(int ttl)
        {
            var b = new byte[SoaNames.Length + 20];
            Buffer.BlockCopy(SoaNames, 0, b, 0, SoaNames.Length);
            int p = SoaNames.Length;
            Dns.W32(b, p, 1);
            Dns.W32(b, p + 4, 3600);
            Dns.W32(b, p + 8, 600);
            Dns.W32(b, p + 12, 86400);
            Dns.W32(b, p + 16, (uint)ttl);
            return b;
        }

        public static byte[] TxtData(string text)
        {
            byte[] t = Encoding.UTF8.GetBytes(text);
            var ms = new MemoryStream();
            int i = 0;
            do
            {
                int n = Math.Min(255, t.Length - i);
                ms.WriteByte((byte)n);
                ms.Write(t, i, n);
                i += n;
            } while (i < t.Length);
            return ms.ToArray();
        }

        public static byte[] Build(Query q, int rcode, RR[] answers, RR[] authority, bool aa, int extendedRcode = 0)
        {
            answers = answers ?? new RR[0];
            authority = authority ?? new RR[0];
            var ms = new MemoryStream();
            int flags = Dns.QR | (q.Flags & (Dns.OPCODE | Dns.RD | Dns.CD)) | Dns.RA | rcode | (aa ? Dns.AA : 0);
            var h = new byte[12];
            Dns.W16(h, 0, q.Id);
            Dns.W16(h, 2, flags);
            Dns.W16(h, 4, 1);
            Dns.W16(h, 6, answers.Length);
            Dns.W16(h, 8, authority.Length);
            Dns.W16(h, 10, q.Edns ? 1 : 0);
            ms.Write(h, 0, 12);
            ms.Write(q.Raw, 12, q.QEnd - 12);
            foreach (var rr in answers.Concat(authority))
            {
                var r = new byte[12];
                Dns.W16(r, 0, 0xC00C);             // name: pointer to the question
                Dns.W16(r, 2, rr.Type);
                Dns.W16(r, 4, 1);                  // class IN
                Dns.W32(r, 6, (uint)rr.Ttl);
                Dns.W16(r, 10, rr.Data.Length);
                ms.Write(r, 0, 12);
                ms.Write(rr.Data, 0, rr.Data.Length);
            }
            if (q.Edns) ms.Write(Opt(q, extendedRcode), 0, 11);
            return ms.ToArray();
        }

        // OPT: root name, type 41, class = our UDP size, TTL = extended rcode / version 0 / flags (DO echoed).
        static byte[] Opt(Query q, int extendedRcode)
        {
            var o = new byte[11];
            Dns.W16(o, 1, Dns.OPT);
            Dns.W16(o, 3, 1232);
            Dns.W32(o, 5, ((uint)extendedRcode << 24) | (q.Do ? 0x8000u : 0u));
            return o;
        }

        // 0.0.0.0 for A, :: for AAAA, an empty answer for every other type.
        public static byte[] Blocked(Query q, int ttl)
        {
            if (q.QType == Dns.A) return Build(q, Dns.NOERROR, new[] { new RR(Dns.A, ttl, new byte[4]) }, null, false);
            if (q.QType == Dns.AAAA) return Build(q, Dns.NOERROR, new[] { new RR(Dns.AAAA, ttl, new byte[16]) }, null, false);
            return Build(q, Dns.NOERROR, null, new[] { new RR(Dns.SOA, ttl, SoaData(ttl)) }, false);
        }

        public static byte[] NxDomain(Query q, int ttl) { return Build(q, Dns.NXDOMAIN, null, new[] { new RR(Dns.SOA, ttl, SoaData(ttl)) }, true); }
        public static byte[] NoData(Query q, int ttl) { return Build(q, Dns.NOERROR, null, new[] { new RR(Dns.SOA, ttl, SoaData(ttl)) }, true); }
        public static byte[] Txt(Query q, string text) { return Build(q, Dns.NOERROR, new[] { new RR(Dns.TXT, 0, TxtData(text)) }, null, true); }
        public static byte[] Error(Query q, int rcode) { return Build(q, rcode, null, null, false); }

        // An EDNS version we don't speak: BADVERS (16) = extended rcode 1 in the OPT record, 0 in the header.
        public static byte[] BadVersion(Query q) { return Build(q, Dns.NOERROR, null, null, false, 1); }

        // Error reply to a message we couldn't parse (null if it isn't a query at all).
        public static byte[] HeaderOnly(byte[] raw, int rcode)
        {
            if (raw.Length < 12) return null;
            int flags = Dns.U16(raw, 2);
            if ((flags & Dns.QR) != 0) return null;
            var h = new byte[12];
            Buffer.BlockCopy(raw, 0, h, 0, 2);
            Dns.W16(h, 2, Dns.QR | (flags & (Dns.OPCODE | Dns.RD)) | rcode);
            return h;
        }

        // Header + question (+ OPT for EDNS clients) with TC set: "too big for UDP, ask again over TCP".
        public static byte[] Truncated(byte[] resp, Query q)
        {
            var b = new byte[q.QEnd + (q.Edns ? 11 : 0)];
            Buffer.BlockCopy(q.Raw, 0, b, 0, q.QEnd);
            Dns.W16(b, 0, q.Id);
            Dns.W16(b, 2, Dns.U16(resp, 2) | Dns.TC);
            Dns.W16(b, 4, 1);
            Dns.W16(b, 6, 0);
            Dns.W16(b, 8, 0);
            Dns.W16(b, 10, q.Edns ? 1 : 0);
            if (q.Edns) Buffer.BlockCopy(Opt(q, 0), 0, b, q.QEnd, 11);
            return b;
        }
    }

    // Reading upstream replies.
    static class Msg
    {
        // How long an upstream reply may be cached (0 = don't).
        public static int CacheTtl(byte[] m, int cap)
        {
            try
            {
                if (m.Length < 12 || Dns.U16(m, 4) != 1) return 0;      // only replies that carry their question
                int flags = Dns.U16(m, 2), rcode = flags & 0xF;
                if ((flags & Dns.TC) != 0 || (rcode != Dns.NOERROR && rcode != Dns.NXDOMAIN)) return 0;
                long answerMin = -1, negative = -1;
                foreach (var r in Dns.Records(m))
                {
                    if (r.Type == Dns.OPT) continue;
                    if (r.Section == 1)
                    {
                        answerMin = answerMin < 0 ? r.Ttl : Math.Min(answerMin, (long)r.Ttl);
                    }
                    else if (r.Section == 2 && r.Type == Dns.SOA)
                    {
                        int p = Dns.SkipName(m, Dns.SkipName(m, r.Pos + 10));
                        if (p + 20 > m.Length) continue;
                        negative = Math.Min((long)r.Ttl, (long)Dns.U32(m, p + 16));   // RFC 2308
                    }
                }
                long ttl;
                if (answerMin >= 0 && negative >= 0) ttl = Math.Min(answerMin, negative);   // an alias chain ending in "no such data/name"
                else if (answerMin >= 0 && rcode == Dns.NOERROR) ttl = answerMin;
                else ttl = negative;                                                        // a negative answer needs its SOA
                return ttl < 0 ? 0 : (int)Math.Min(ttl, cap);
            }
            catch (DnsFormatException) { return 0; }
            catch (IndexOutOfRangeException) { return 0; }
        }

        // Copy of a cached reply with every TTL lowered by `seconds`.
        public static byte[] Aged(byte[] m, int seconds)
        {
            var b = (byte[])m.Clone();
            if (seconds <= 0) return b;
            foreach (var r in Dns.Records(m))
                if (r.Type != Dns.OPT) Dns.W32(b, r.Pos + 4, r.Ttl > (uint)seconds ? r.Ttl - (uint)seconds : 0u);
            return b;
        }

        public static List<string> CnameTargets(byte[] m)
        {
            var list = new List<string>();
            foreach (var r in Dns.Records(m))
            {
                if (r.Section != 1 || r.Type != Dns.CNAME) continue;
                int end;
                string target = Dns.ReadName(m, r.Pos + 10, out end);
                if (end != r.Pos + 10 + r.RdLen) throw new DnsFormatException("CNAME data doesn't hold exactly one name");
                list.Add(target);
            }
            return list;
        }

        // Fit to cache and reuse: a well-formed standard answer to exactly one question.
        public static bool Validate(byte[] m)
        {
            try
            {
                if (m.Length < 12 || (Dns.U16(m, 2) & (Dns.QR | Dns.OPCODE)) != Dns.QR || Dns.U16(m, 4) != 1) return false;
                foreach (var r in Dns.Records(m))
                {
                    int end;
                    Dns.ReadName(m, r.Start, out end);          // owner names, compression pointers included, must decode
                    if (r.Type == Dns.A && r.RdLen != 4) return false;
                    if (r.Type == Dns.AAAA && r.RdLen != 16) return false;
                }
                CnameTargets(m);
                return true;
            }
            catch (DnsFormatException) { return false; }
        }

        // Lowers every TTL above `cap` to `cap`, in place (OPT records excepted).
        public static void CapTtl(byte[] m, int cap)
        {
            if (cap <= 0) return;
            foreach (var r in Dns.Records(m))
                if (r.Type != Dns.OPT && r.Ttl > (uint)cap) Dns.W32(m, r.Pos + 4, (uint)cap);
        }

        // Is resp the answer to the message we sent: same ID, QR set, same question?
        public static bool Matches(byte[] resp, byte[] sent, int qend)
        {
            if (resp.Length < 12 || resp[0] != sent[0] || resp[1] != sent[1] || (resp[2] & 0x80) == 0) return false;
            int qd = Dns.U16(resp, 4);
            if (qd == 0) return (resp[3] & 0x0F) != Dns.NOERROR;    // bare error replies carry no question
            if (qd != 1 || resp.Length < qend) return false;
            for (int i = 12; i < qend - 4; i++)
                if (Dns.LowerAscii(resp[i]) != Dns.LowerAscii(sent[i])) return false;
            for (int i = qend - 4; i < qend; i++)
                if (resp[i] != sent[i]) return false;
            return true;
        }

        public static List<string> Addresses(byte[] m)
        {
            var list = new List<string>();
            foreach (var r in Dns.Records(m))
            {
                if (r.Section != 1) continue;
                if (r.Type == Dns.A && r.RdLen == 4)
                    list.Add(new IPAddress(new[] { m[r.Pos + 10], m[r.Pos + 11], m[r.Pos + 12], m[r.Pos + 13] }).ToString());
                else if (r.Type == Dns.AAAA && r.RdLen == 16)
                {
                    var b = new byte[16];
                    Buffer.BlockCopy(m, r.Pos + 10, b, 0, 16);
                    list.Add(new IPAddress(b).ToString());
                }
            }
            return list;
        }
    }

    // ------------------------------------------------------------------ names and blocklists

    static class Names
    {
        static readonly HashSet<string> NotDomains = new HashSet<string>(StringComparer.Ordinal)
        {
            "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
            "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
        };

        // a-z 0-9 - _ labels of 1-63 characters (no leading or trailing hyphen), up to 253 in all.
        public static bool IsDomain(string d, bool singleLabelOk)
        {
            if (d.Length == 0 || d.Length > 253) return false;
            int label = 0;
            bool dotted = false;
            for (int i = 0; i < d.Length; i++)
            {
                char c = d[i];
                if (c == '.')
                {
                    if (label == 0 || d[i - 1] == '-') return false;
                    label = 0;
                    dotted = true;
                    continue;
                }
                bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || (c == '-' && label > 0);
                if (!ok || ++label > 63) return false;
            }
            if (label == 0 || d[d.Length - 1] == '-') return false;
            return dotted || singleLabelOk;
        }

        // Domains named on one list line: plain, *.wildcard, hosts ("0.0.0.0 name") or adblock ("||name^").
        public static void ParseListLine(string line, bool singleLabelOk, List<string> output)
        {
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line.Substring(0, hash);
            line = line.Trim();
            if (line.Length == 0 || line[0] == '!' || line[0] == '[' || line.StartsWith("@@", StringComparison.Ordinal)) return;
            if (line.StartsWith("||", StringComparison.Ordinal))
            {
                int caret = line.IndexOf('^');
                string rest = caret >= 0 ? line.Substring(caret + 1) : "";
                if (rest.Length > 0 && rest != "$important" && rest != "|") return;   // other modifiers aren't DNS rules
                Add(caret >= 0 ? line.Substring(2, caret - 2) : line.Substring(2), singleLabelOk, output);
                return;
            }
            int sp = -1;
            for (int i = 0; i < line.Length; i++) if (line[i] == ' ' || line[i] == '\t') { sp = i; break; }
            if (sp < 0) { Add(line, singleLabelOk, output); return; }
            IPAddress ip;
            if (!IPAddress.TryParse(line.Substring(0, sp), out ip)) return;
            foreach (var part in line.Substring(sp + 1).Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                Add(part, singleLabelOk, output);
        }

        static void Add(string d, bool singleLabelOk, List<string> output)
        {
            d = d.ToLowerInvariant().Trim('.');
            if (d.StartsWith("*.", StringComparison.Ordinal)) d = d.Substring(2);
            if (!NotDomains.Contains(d) && IsDomain(d, singleLabelOk)) output.Add(d);
        }

        public static IEnumerable<string> ReadListFile(string path, bool singleLabelOk)
        {
            if (!File.Exists(path)) yield break;
            var found = new List<string>(4);
            foreach (var line in File.ReadLines(path))
            {
                found.Clear();
                ParseListLine(line, singleLabelOk, found);
                foreach (var d in found) yield return d;
            }
        }

        // What the user typed or pasted (URL, host:port, *.domain, unicode) -> bare domain, or null.
        public static string Normalize(string text)
        {
            if (text == null) return null;
            string t = text.Trim().ToLowerInvariant();
            int scheme = t.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0) t = t.Substring(scheme + 3);
            int cut = t.IndexOfAny(new[] { '/', '?', '#' });
            if (cut >= 0) t = t.Substring(0, cut);
            int at = t.LastIndexOf('@');
            if (at >= 0) t = t.Substring(at + 1);
            if (t.StartsWith("[", StringComparison.Ordinal)) return null;
            int colon = t.IndexOf(':');
            if (colon >= 0 && t.IndexOf(':', colon + 1) < 0) t = t.Substring(0, colon);
            if (t.StartsWith("*.", StringComparison.Ordinal)) t = t.Substring(2);
            t = t.Trim('.');
            if (t.Any(c => c > 127))
            {
                try { t = new IdnMapping().GetAscii(t); }
                catch (ArgumentException) { return null; }
            }
            return IsDomain(t, true) ? t : null;
        }

        static readonly string[] PrivateV4 = BuildPrivateV4();

        static string[] BuildPrivateV4()
        {
            var list = new List<string> { "10.", "127.", "192.168.", "169.254." };
            for (int i = 16; i <= 31; i++) list.Add("172." + i + ".");
            return list.ToArray();
        }

        // Reverse lookups for private, loopback and link-local addresses.
        public static bool IsPrivateReverse(string name)
        {
            const string v4 = ".in-addr.arpa", v6 = ".ip6.arpa";
            if (name.EndsWith(v4, StringComparison.Ordinal))
            {
                string[] octets = name.Substring(0, name.Length - v4.Length).Split('.');
                Array.Reverse(octets);
                string dotted = string.Join(".", octets) + ".";
                return PrivateV4.Any(p => dotted.StartsWith(p, StringComparison.Ordinal));
            }
            if (name.EndsWith(v6, StringComparison.Ordinal))
            {
                string[] nibbles = name.Substring(0, name.Length - v6.Length).Split('.');
                Array.Reverse(nibbles);
                string hex = string.Concat(nibbles);
                return hex.StartsWith("fe8", StringComparison.Ordinal) || hex.StartsWith("fe9", StringComparison.Ordinal)
                    || hex.StartsWith("fea", StringComparison.Ordinal) || hex.StartsWith("feb", StringComparison.Ordinal)
                    || hex.StartsWith("fc", StringComparison.Ordinal) || hex.StartsWith("fd", StringComparison.Ordinal)
                    || hex == new string('0', 31) + "1";
            }
            return false;
        }

        public static string Safe(string s)
        {
            // keep log lines one line each even for weird names
            if (s.All(c => c >= 0x20 && c < 0x7F)) return s;
            return new string(s.Select(c => c >= 0x20 && c < 0x7F ? c : '?').ToArray());
        }
    }

    interface INameSet
    {
        bool Contains(string name);
        int Count { get; }
    }

    sealed class SmallSet : INameSet
    {
        readonly HashSet<string> set;
        public SmallSet(IEnumerable<string> names) { set = new HashSet<string>(names, StringComparer.Ordinal); }
        public bool Contains(string name) { return set.Contains(name); }
        public int Count { get { return set.Count; } }
    }

    // A big set of names kept as sorted 64-bit FNV-1a hashes: about 8 bytes per name.
    sealed class HashedSet : INameSet
    {
        readonly ulong[] hashes;

        public HashedSet(IEnumerable<string> names)
        {
            var list = new List<ulong>(1 << 16);
            foreach (var n in names) list.Add(Hash(n));
            list.Sort();
            int w = 0;
            for (int i = 0; i < list.Count; i++)
                if (i == 0 || list[i] != list[i - 1]) list[w++] = list[i];
            hashes = new ulong[w];
            list.CopyTo(0, hashes, 0, w);
        }

        public bool Contains(string name) { return Array.BinarySearch(hashes, Hash(name)) >= 0; }
        public int Count { get { return hashes.Length; } }

        public static ulong Hash(string s)
        {
            ulong h = 14695981039346656037UL;
            for (int i = 0; i < s.Length; i++)
            {
                h ^= s[i];
                h *= 1099511628211UL;
            }
            return h;
        }
    }

    sealed class Verdict
    {
        public const int Allow = 1, Block = 2;
        public readonly int Kind;
        public readonly string Rule, Source;
        public Verdict(int kind, string rule, string source) { Kind = kind; Rule = rule; Source = source; }
        public bool Blocked { get { return Kind == Block; } }
    }

    sealed class Rules
    {
        public const string ProtectedSource = "built-in allow list";
        public static readonly Rules Empty = new Rules(null, new List<KeyValuePair<string, INameSet>>(), new List<KeyValuePair<string, INameSet>>());
        public readonly INameSet Protected;
        public readonly List<KeyValuePair<string, INameSet>> Allow, Block;

        public Rules(List<KeyValuePair<string, INameSet>> allow, List<KeyValuePair<string, INameSet>> block) : this(null, allow, block) { }

        public Rules(INameSet protectedNames, List<KeyValuePair<string, INameSet>> allow, List<KeyValuePair<string, INameSet>> block)
        {
            Protected = protectedNames;
            Allow = allow;
            Block = block;
        }

        // Protected names (and their subdomains) are always allowed, whatever the lists say. Otherwise the
        // most specific match wins (a.b.example.com, then b.example.com, then example.com ...), and at the
        // same level allow beats block. null = no rule matches.
        public Verdict Decide(string name)
        {
            if (Protected != null)
            {
                for (string c = name; c.Length > 0; )
                {
                    if (Protected.Contains(c)) return new Verdict(Verdict.Allow, c, ProtectedSource);
                    int d = c.IndexOf('.');
                    if (d < 0) break;
                    c = c.Substring(d + 1);
                }
            }
            string cand = name;
            while (cand.Length > 0)
            {
                foreach (var kv in Allow) if (kv.Value.Contains(cand)) return new Verdict(Verdict.Allow, cand, kv.Key);
                foreach (var kv in Block) if (kv.Value.Contains(cand)) return new Verdict(Verdict.Block, cand, kv.Key);
                int dot = cand.IndexOf('.');
                if (dot < 0) break;
                cand = cand.Substring(dot + 1);
            }
            return null;
        }
    }

    static class Essential
    {
        // Never blocked, whatever the lists say.
        public static readonly string[] Allow =
        {
            "msftconnecttest.com", "msftncsi.com",            // Windows' "am I online?" check
            "windowsupdate.com", "update.microsoft.com",      // Windows Update
            "anthropic.com", "claude.ai", "claude.com",       // Claude
            "raw.githubusercontent.com", "cdn.jsdelivr.net",  // where the blocklists come from
        };
    }

    // allow.txt / block.txt
    static class UserLists
    {
        const string AllowHeader =
            "# Aegis allow list: one domain per line. A domain here is never blocked, and neither\r\n" +
            "# are its subdomains (unless a more specific line in block.txt says otherwise).\r\n";
        const string BlockHeader =
            "# Aegis block list: one domain per line. A domain here is always blocked, and so are\r\n" +
            "# its subdomains (unless a more specific line in allow.txt says otherwise).\r\n";

        public static void EnsureFiles()
        {
            if (!File.Exists(App.AllowPath)) File.WriteAllText(App.AllowPath, AllowHeader, new UTF8Encoding(false));
            if (!File.Exists(App.BlockPath)) File.WriteAllText(App.BlockPath, BlockHeader, new UTF8Encoding(false));
        }

        public static List<string> Read(string path) { return Names.ReadListFile(path, true).Distinct().ToList(); }

        public static bool Add(string path, string domain) { return Locked(() => AddUnlocked(path, domain)); }
        public static bool Remove(string path, string domain) { return Locked(() => RemoveUnlocked(path, domain)); }

        // Onto one list and off the other, in one step. True if it wasn't on `addTo` before.
        public static bool Put(string addTo, string removeFrom, string domain)
        {
            return Locked(() =>
            {
                RemoveUnlocked(removeFrom, domain);
                return AddUnlocked(addTo, domain);
            });
        }

        static bool AddUnlocked(string path, string domain)
        {
            EnsureFiles();
            if (Read(path).Contains(domain)) return false;
            string text = File.ReadAllText(path);
            if (text.Length > 0 && !text.EndsWith("\n", StringComparison.Ordinal)) text += "\r\n";
            WriteAtomic(path, text + domain + "\r\n");
            return true;
        }

        static bool RemoveUnlocked(string path, string domain)
        {
            if (!File.Exists(path)) return false;
            var keep = new List<string>();
            var found = new List<string>();
            bool removed = false;
            foreach (var line in File.ReadAllLines(path))
            {
                found.Clear();
                Names.ParseListLine(line, true, found);
                if (!found.Contains(domain))
                {
                    keep.Add(line);
                    continue;
                }
                removed = true;
                if (found.Count > 1) keep.Add(WithoutName(line, domain));   // a hosts line naming several sites keeps the others
            }
            if (removed) WriteAtomic(path, string.Join("\r\n", keep) + "\r\n");
            return removed;
        }

        static string WithoutName(string line, string domain)
        {
            int hash = line.IndexOf('#');
            string body = hash >= 0 ? line.Substring(0, hash) : line;
            string comment = hash >= 0 ? " " + line.Substring(hash) : "";
            var one = new List<string>();
            var kept = body.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).Where((token, i) =>
            {
                if (i == 0) return true;            // the address at the start of a hosts line
                one.Clear();
                Names.ParseListLine(token, true, one);
                return !one.Contains(domain);
            });
            return string.Join(" ", kept) + comment;
        }

        // Edits from the tray and the command line take turns, and each file is replaced in one step.
        static T Locked<T>(Func<T> edit)
        {
            using (var m = new Mutex(false, @"Local\Aegis.UserLists"))
            {
                bool owned = false;
                try
                {
                    try { owned = m.WaitOne(5000); }
                    catch (AbandonedMutexException) { owned = true; }
                    if (!owned) throw new IOException("another change to your lists is still being saved; try again in a moment");
                    return edit();
                }
                finally { if (owned) m.ReleaseMutex(); }
            }
        }

        static void WriteAtomic(string path, string text)
        {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, text, new UTF8Encoding(false));
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else File.Move(tmp, path);
                    return;
                }
                catch (IOException) { if (attempt >= 20) throw; }                  // the engine may be reading it this instant
                catch (UnauthorizedAccessException) { if (attempt >= 20) throw; }
                Thread.Sleep(50);
            }
        }
    }

    static class Pause
    {
        public static DateTime UntilUtc()
        {
            try
            {
                if (!File.Exists(App.PausePath)) return DateTime.MinValue;
                return App.FromUnix(long.Parse(File.ReadAllText(App.PausePath).Trim(), CultureInfo.InvariantCulture));
            }
            catch { return DateTime.MinValue; }
        }

        public static void Set(TimeSpan d)
        {
            App.EnsureDirs();
            File.WriteAllText(App.PausePath, App.Unix(DateTime.UtcNow + d).ToString(CultureInfo.InvariantCulture));
        }

        public static void Clear()
        {
            try { File.Delete(App.PausePath); } catch { }
        }
    }

    static class Rand
    {
        static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();
        static readonly byte[] Buf = new byte[2];
        public static int Next16() { lock (Buf) { Rng.GetBytes(Buf); return (Buf[0] << 8) | Buf[1]; } }
    }

    // ------------------------------------------------------------------ talking to the running engine

    static class EngineClient
    {
        static int port = -1;

        static int Port
        {
            get
            {
                if (port < 0) { try { port = Config.Load().Port; } catch { port = 53; } }
                return port;
            }
        }

        // Ask the engine on 127.0.0.1 directly (not through Windows' resolver). null = no answer.
        public static byte[] Ask(string name, int qtype, int timeoutMs)
        {
            byte[] qname;
            try { qname = Reply.EncodeName(name); }
            catch (ArgumentException) { return null; }
            var msg = new byte[12 + qname.Length + 4 + 11];
            int id = Rand.Next16();
            Dns.W16(msg, 0, id);
            Dns.W16(msg, 2, Dns.RD);
            Dns.W16(msg, 4, 1);
            Dns.W16(msg, 10, 1);
            Buffer.BlockCopy(qname, 0, msg, 12, qname.Length);
            int p = 12 + qname.Length;
            Dns.W16(msg, p, qtype);
            Dns.W16(msg, p + 2, 1);
            Dns.W16(msg, p + 5, Dns.OPT);      // OPT record: root name (p+4 = 0), type, UDP size 4096
            Dns.W16(msg, p + 7, 4096);
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.ReceiveTimeout = Math.Max(1, timeoutMs);
                    s.Connect(new IPEndPoint(IPAddress.Loopback, Port));
                    s.Send(msg);
                    var buf = new byte[65535];
                    var sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < timeoutMs)
                    {
                        int n = s.Receive(buf);
                        if (n >= 12 && Dns.U16(buf, 0) == id)
                        {
                            var r = new byte[n];
                            Buffer.BlockCopy(buf, 0, r, 0, n);
                            return r;
                        }
                    }
                }
            }
            catch (SocketException) { }
            return null;
        }

        public static string AskTxt(string name, int timeoutMs)
        {
            byte[] r = Ask(name, Dns.TXT, timeoutMs);
            if (r == null) return null;
            try
            {
                var bytes = new List<byte>();
                foreach (var rec in Dns.Records(r))
                {
                    if (rec.Section != 1 || rec.Type != Dns.TXT) continue;
                    int i = rec.Pos + 10, end = rec.Pos + 10 + rec.RdLen;
                    while (i < end)
                    {
                        int n = r[i];
                        for (int k = 1; k <= n && i + k < end; k++) bytes.Add(r[i + k]);
                        i += 1 + n;
                    }
                }
                return Encoding.UTF8.GetString(bytes.ToArray());
            }
            catch (DnsFormatException) { return null; }
        }

        public static bool Reload() { return AskTxt("reload" + App.ControlSuffix, 3000) == "ok"; }
        public static bool StartUpdate() { return AskTxt("update" + App.ControlSuffix, 1500) != null; }

        public static Dictionary<string, string> Check(string domain)
        {
            string txt = AskTxt(domain + ".check" + App.ControlSuffix, 1500);
            return txt == null ? null : Kv.Parse(txt);
        }

        public static Dictionary<string, string> ListInfo()
        {
            string txt = AskTxt("lists" + App.ControlSuffix, 1500);
            return txt == null ? null : Kv.Parse(txt);
        }

        // What the engine answers for NAME right now (addresses, or the error code).
        public static string Lookup(string domain)
        {
            byte[] r = Ask(domain, Dns.A, 4000);
            if (r == null) return "no answer";
            try
            {
                int rcode = r[3] & 0xF;
                if (rcode != Dns.NOERROR) return Dns.RcodeName(rcode);
                var ips = Msg.Addresses(r);
                return ips.Count == 0 ? "no address" : string.Join(", ", ips);
            }
            catch (DnsFormatException) { return "bad reply"; }
        }
    }

    // What the engine reports about itself (status.aegis.invalid).
    sealed class EngineStatus
    {
        public string Version, Update, Router;
        public bool Paused;
        public DateTime PausedUntilUtc, UpdatedUtc;
        public long DayQueries, DayBlocked, TotalQueries, TotalBlocked, Domains, Uptime, CacheEntries, Fallbacks;
        public bool FallbackRecent;    // Quad9 didn't answer lately and the router stood in
        public int Lists, AllowEntries, BlockEntries, MissingLists;
        public double UpstreamMs;

        public static EngineStatus Fetch(int timeoutMs)
        {
            string txt = EngineClient.AskTxt("status" + App.ControlSuffix, timeoutMs);
            return txt == null ? null : Parse(txt);
        }

        public static EngineStatus Parse(string txt)
        {
            var d = Kv.Parse(txt);
            if (Kv.Get(d, "app", "") != App.Name) return null;
            var s = new EngineStatus();
            s.Version = Kv.Get(d, "ver", "?");
            s.Paused = Kv.Get(d, "state", "") == "paused";
            s.PausedUntilUtc = App.FromUnix(Kv.Long(d, "until"));
            s.DayQueries = Kv.Long(d, "q");
            s.DayBlocked = Kv.Long(d, "b");
            s.TotalQueries = Kv.Long(d, "tq");
            s.TotalBlocked = Kv.Long(d, "tb");
            s.Domains = Kv.Long(d, "domains");
            s.Lists = (int)Kv.Long(d, "lists");
            s.AllowEntries = (int)Kv.Long(d, "allow");
            s.BlockEntries = (int)Kv.Long(d, "block");
            s.Uptime = Kv.Long(d, "up");
            s.CacheEntries = Kv.Long(d, "cache");
            long updated = Kv.Long(d, "updated");
            s.UpdatedUtc = updated > 0 ? App.FromUnix(updated) : DateTime.MinValue;
            s.Update = Kv.Get(d, "update", "");
            s.Router = Kv.Get(d, "router", "none");
            s.Fallbacks = Kv.Long(d, "fb");
            s.MissingLists = (int)Kv.Long(d, "missing");
            s.FallbackRecent = Kv.Get(d, "fbrecent", "") == "1";
            double ms;
            s.UpstreamMs = double.TryParse(Kv.Get(d, "up_ms", "0"), NumberStyles.Float, CultureInfo.InvariantCulture, out ms) ? ms : 0;
            return s;
        }
    }

    static class NetInfo
    {
        // DNS servers of the adapters that carry internet traffic (up, with a default gateway).
        public static List<KeyValuePair<string, List<IPAddress>>> InternetAdapterDns()
        {
            var result = new List<KeyValuePair<string, List<IPAddress>>>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    var props = ni.GetIPProperties();
                    if (!props.GatewayAddresses.Any(g => !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any))) continue;
                    var dns = props.DnsAddresses.Where(a => !a.ToString().StartsWith("fec0:0:0:ffff::", StringComparison.OrdinalIgnoreCase)).ToList();
                    result.Add(new KeyValuePair<string, List<IPAddress>>(ni.Name, dns));
                }
                catch (NetworkInformationException) { }
            }
            return result;
        }

        // true = every internet adapter sends DNS only to this PC; false = some go elsewhere; null = offline.
        public static bool? WindowsUsesAegis()
        {
            var list = InternetAdapterDns();
            if (list.Count == 0) return null;
            return list.All(kv => kv.Value.Count > 0 && kv.Value.All(IPAddress.IsLoopback));
        }

        // The DNS suffixes the connected networks hand out (the router's "mynetworksettings.com").
        public static List<string> DnsSuffixes()
        {
            var list = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    string s = ni.GetIPProperties().DnsSuffix;
                    if (!string.IsNullOrEmpty(s)) list.Add(s.ToLowerInvariant().Trim('.'));
                }
            }
            catch (NetworkInformationException) { }
            return list;
        }

        public static string DefaultGatewayV4()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var g in ni.GetIPProperties().GatewayAddresses)
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                            return g.Address.ToString();
                }
            }
            catch (NetworkInformationException) { }
            return null;
        }
    }

    static class NetSubnet
    {
        // Is this IPv4 address on a network this PC is connected to right now? (IPv6: assume yes.)
        public static bool IsConnected(IPAddress a)
        {
            if (a.AddressFamily != AddressFamily.InterNetwork) return true;
            byte[] ab = a.GetAddressBytes();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var u in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (u.Address.AddressFamily != AddressFamily.InterNetwork || u.IPv4Mask == null) continue;
                        byte[] ub = u.Address.GetAddressBytes(), mb = u.IPv4Mask.GetAddressBytes();
                        if (mb.All(x => x == 0)) continue;
                        bool same = true;
                        for (int i = 0; i < 4 && same; i++) same = (ab[i] & mb[i]) == (ub[i] & mb[i]);
                        if (same) return true;
                    }
                }
            }
            catch (NetworkInformationException) { }
            return false;
        }
    }

    // ------------------------------------------------------------------ the blocked-lookups log

    sealed class BlockedEntry
    {
        public DateTime Time;
        public string Name, Type, Rule, Source;
        public int Count = 1;      // blocks this line stands for (older lines without the field count once)
    }

    sealed class BlockedSummary
    {
        public string Name, Rule, Source;
        public DateTime Last;
        public int Count;
        public readonly SortedSet<string> Types = new SortedSet<string>(StringComparer.Ordinal);
    }

    static class BlockLog
    {
        public const int HistoryDays = 7;          // what the window and `recent` cover (logs are kept 7 days)
        const long MaxBytesPerFile = 4L << 20;

        public static string PathFor(DateTime day) { return Path.Combine(App.LogDir, "blocked-" + day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".log"); }

        // The date and the sizes of the history's logs: a cheap "has anything changed?" check.
        public static long Signature()
        {
            DateTime today = DateTime.Today;
            long sig = today.Ticks;
            for (int back = HistoryDays - 1; back >= 0; back--)
            {
                long len = 0;
                try { var fi = new FileInfo(PathFor(today.AddDays(-back))); if (fi.Exists) len = fi.Length + 1; }
                catch (IOException) { }
                sig = unchecked(sig * 31 + len);
            }
            return sig;
        }

        // One row per blocked name over the history, newest first.
        public static List<BlockedSummary> Recent() { return Summarize(ReadEntries(HistoryDays)); }

        // Every entry of the last `days` days' logs (today included), oldest first. Reads at most the last
        // 4 MB of each file, so a huge log can't stall the window.
        public static IEnumerable<BlockedEntry> ReadEntries(int days)
        {
            DateTime today = DateTime.Today;
            for (int back = days - 1; back >= 0; back--)
            {
                DateTime day = today.AddDays(-back);
                byte[] bytes;
                bool partial;
                if (!ReadTail(PathFor(day), out bytes, out partial)) continue;
                using (var sr = new StreamReader(new MemoryStream(bytes), Encoding.UTF8))
                {
                    if (partial) sr.ReadLine();          // skip the partial line we landed in
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        var e = ParseLine(day, line);
                        if (e != null) yield return e;
                    }
                }
            }
        }

        // Exactly the last <= 4 MB of a file as it stands now, however fast it's growing. False if it
        // isn't there or can't be read.
        static bool ReadTail(string path, out byte[] bytes, out bool partial)
        {
            bytes = null;
            partial = false;
            if (!File.Exists(path)) return false;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long end = fs.Length, start = Math.Max(0, end - MaxBytesPerFile);
                    fs.Seek(start, SeekOrigin.Begin);
                    var buf = new byte[end - start];
                    int got = 0;
                    while (got < buf.Length)
                    {
                        int n = fs.Read(buf, got, buf.Length - got);
                        if (n <= 0) break;
                        got += n;
                    }
                    if (got < buf.Length) Array.Resize(ref buf, got);
                    bytes = buf;
                    partial = start > 0;
                    return true;
                }
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        // time, name, type, rule, list[, count]; null for a line that doesn't fit
        static BlockedEntry ParseLine(DateTime day, string line)
        {
            string[] f = line.Split('\t');
            if (f.Length < 5) return null;
            TimeSpan t;
            if (!TimeSpan.TryParse(f[0], CultureInfo.InvariantCulture, out t)) return null;
            int count;
            if (f.Length < 6 || !int.TryParse(f[5], NumberStyles.Integer, CultureInfo.InvariantCulture, out count) || count < 1) count = 1;
            return new BlockedEntry { Time = day.Date + t, Name = f[1], Type = f[2], Rule = f[3], Source = f[4], Count = count };
        }

        // One row per name, newest first.
        public static List<BlockedSummary> Summarize(IEnumerable<BlockedEntry> entries)
        {
            var map = new Dictionary<string, BlockedSummary>(StringComparer.Ordinal);
            foreach (var e in entries)
            {
                BlockedSummary s;
                if (!map.TryGetValue(e.Name, out s)) map[e.Name] = s = new BlockedSummary { Name = e.Name };
                s.Count += e.Count;
                s.Types.Add(e.Type);
                if (e.Time >= s.Last) { s.Last = e.Time; s.Rule = e.Rule; s.Source = e.Source; }
            }
            return map.Values.OrderByDescending(s => s.Last).ToList();
        }
    }

    // ------------------------------------------------------------------ things the tray, window and CLI do

    static class Actions
    {
        public static string Allow(string domain)
        {
            bool added = UserLists.Put(App.AllowPath, App.BlockPath, domain);
            return (added ? "Allowed " + domain + " (and its subdomains)." : domain + " was already allowed.") + Applied();
        }

        public static string Block(string domain)
        {
            string guard = ProtectedBy(domain);
            if (guard != null)
                return domain + " can't be blocked: " + guard + " is on Aegis's built-in allow list (Windows, Claude or the blocklist downloads need it).";
            bool added = UserLists.Put(App.BlockPath, App.AllowPath, domain);
            return (added ? "Blocked " + domain + " (and its subdomains)." : domain + " was already blocked.") + Applied();
        }

        static string ProtectedBy(string domain)
        {
            for (string c = domain; c.Length > 0; )
            {
                if (Essential.Allow.Contains(c)) return c;
                int d = c.IndexOf('.');
                if (d < 0) break;
                c = c.Substring(d + 1);
            }
            return null;
        }

        public static string Unallow(string domain)
        {
            return (UserLists.Remove(App.AllowPath, domain) ? "Removed " + domain + " from the allow list." : domain + " wasn't on the allow list.") + Applied();
        }

        public static string Unblock(string domain)
        {
            return (UserLists.Remove(App.BlockPath, domain) ? "Removed " + domain + " from the block list." : domain + " wasn't on the block list.") + Applied();
        }

        public static string PauseFor(TimeSpan d)
        {
            Pause.Set(d);
            return "Filtering paused until " + DateTime.Now.Add(d).ToString("t") + "." + Applied();
        }

        public static string Resume()
        {
            Pause.Clear();
            return "Filtering is back on." + Applied();
        }

        public static string Update()
        {
            return EngineClient.StartUpdate()
                ? "Downloading fresh blocklists. It takes about half a minute."
                : "The engine isn't answering, so nothing was downloaded.";
        }

        static string Applied()
        {
            return EngineClient.Reload()
                ? " Windows may keep its old answer for up to a minute."
                : " (The engine isn't answering; the change applies when it starts.)";
        }

        public static string Explain(string domain)
        {
            var sb = new StringBuilder();
            var check = EngineClient.Check(domain);
            if (check == null) return domain + ": the engine isn't answering, so it can't check.";
            string verdict = Kv.Get(check, "verdict", "none");
            string rule = Kv.Get(check, "rule", ""), source = Kv.Get(check, "source", "");
            if (verdict == "block")
                sb.Append(domain + " is BLOCKED: it matches " + rule + " in " + source + ".");
            else if (verdict == "allow")
                sb.Append(domain + " is allowed: it matches " + rule + " in " + source + ".");
            else
                sb.Append(domain + " isn't on any list, so it's allowed.");
            if (Kv.Get(check, "paused", "") == "1") sb.Append(" (Filtering is paused right now.)");
            if (Kv.Get(check, "local", "") == "1") sb.Append(" Lookups for it go to your router.");
            string answer = EngineClient.Lookup(domain);
            sb.Append(Environment.NewLine + "Aegis answers: " + answer);
            if (verdict != "block" && answer == "0.0.0.0")
                sb.Append(Environment.NewLine + "(Blocked because its address is an alias of a blocked domain; see Recent blocks.)");
            return sb.ToString();
        }
    }
}
