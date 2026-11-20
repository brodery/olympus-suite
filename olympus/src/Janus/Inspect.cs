// Janus's inspection of one file: what it really is (by its first bytes, not its name), name
// tricks (double extensions, right-to-left characters), who signed it, which site it came from
// (Windows' Mark of the Web), programs and passwords inside zip files, download portals known
// for bundling adware, and optionally its reputation with MalwareBazaar / VirusTotal.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Olympus.Janus
{
    public sealed class Finding
    {
        public string Level, Text;   // good | info | warn | bad
    }

    public sealed class FileReport
    {
        public string Path, Name, Kind, Sha256, Signer, From, Referrer, Verdict, Time, Reputation;
        public long Size;
        public bool Risky;   // a type that can run code
        public List<Finding> Findings = new List<Finding>();
        public void Add(string level, string text) { Findings.Add(new Finding { Level = level, Text = text }); }
        public int Worst { get { return Findings.Count == 0 ? 0 : Findings.Max(f => f.Level == "bad" ? 3 : f.Level == "warn" ? 2 : f.Level == "info" ? 1 : 0); } }
    }

    static class Inspect
    {
        static readonly HashSet<string> Programs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".scr", ".com", ".pif", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle", ".dll", ".cpl", ".sys", ".ocx", ".jar", ".apk" };
        static readonly HashSet<string> Scripts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".bat", ".cmd", ".reg", ".lnk", ".url", ".scf", ".inf", ".chm", ".xll", ".application", ".msc" };
        static readonly HashSet<string> Containers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".iso", ".img", ".vhd", ".vhdx" };
        static readonly HashSet<string> Archives = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".zip", ".rar", ".7z", ".cab", ".gz", ".tgz", ".tar", ".xz", ".bz2", ".arj" };
        static readonly HashSet<string> Macros = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".doc", ".xls", ".ppt" };
        static readonly HashSet<string> Harmless = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".mp4", ".mov", ".mkv", ".webm", ".mp3", ".wav", ".flac", ".m4a", ".txt", ".csv", ".json", ".pdf", ".docx", ".xlsx", ".pptx", ".srt"
        };
        public static readonly HashSet<string> Partial = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", ".!ut", ".ini" };
        static readonly string[] Portals = { "softonic.com", "download.cnet.com", "filehippo.com", "uptodown.com", "softpedia-secure-download.com", "download.com", "filehorse.com", "malavida.com", "soft112.com", "updatestar.com", "brothersoft.com", "getintopc.com", "oceanofgames.com", "igg-games.com", "fitgirl-repack.site" };
        static readonly string[] Bundlers = { "InstallCore", "OpenCandy", "Amonetize", "OutBrowse", "Somoto", "Solimba", "Download Admin", "IronSource", "Wajam", "Crossrider", "Softonic", "DownloadAssistant", "Firseria", "Linkury", "Conduit" };

        public static bool IsPartial(string path)
        {
            string name = System.IO.Path.GetFileName(path);
            return Partial.Contains(System.IO.Path.GetExtension(path)) || name.StartsWith("~$") || name.StartsWith(".");
        }

        static string Magic(byte[] b, int n, string path)
        {
            if (n >= 2 && b[0] == 'M' && b[1] == 'Z') return "program";
            if (n >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4) return "zip";
            if (n >= 4 && b[0] == 'R' && b[1] == 'a' && b[2] == 'r' && b[3] == '!') return "rar";
            if (n >= 6 && b[0] == '7' && b[1] == 'z' && b[2] == 0xBC && b[3] == 0xAF) return "7z";
            if (n >= 4 && b[0] == '%' && b[1] == 'P' && b[2] == 'D' && b[3] == 'F') return "pdf";
            if (n >= 8 && b[0] == 0xD0 && b[1] == 0xCF && b[2] == 0x11 && b[3] == 0xE0) return "ole";   // MSI or old Office
            if (n >= 8 && b[0] == 0x4C && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 1 && b[5] == 0x14 && b[6] == 2) return "shortcut";
            if (n >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "jpeg";
            if (n >= 4 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') return "png";
            try
            {
                using (var fs = Open(path))
                {
                    if (fs.Length > 0x8006)
                    {
                        fs.Seek(0x8001, SeekOrigin.Begin);
                        var id = new byte[5];
                        if (fs.Read(id, 0, 5) == 5 && Encoding.ASCII.GetString(id) == "CD001") return "iso";
                    }
                }
            }
            catch (Exception) { }
            return null;
        }

        static FileStream Open(string path) { return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); }

        // ------------------------------------------------------------------ Mark of the Web

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

        // Windows notes where a download came from in a hidden "Zone.Identifier" stream.
        public static Dictionary<string, string> Zone(string path)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var h = CreateFile(path + ":Zone.Identifier", 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) return d;
                    using (var fs = new FileStream(h, FileAccess.Read))
                    using (var r = new StreamReader(fs))
                    {
                        string line;
                        while ((line = r.ReadLine()) != null)
                        {
                            int eq = line.IndexOf('=');
                            if (eq > 0) d[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
                        }
                    }
                }
            }
            catch (Exception) { }
            return d;
        }

        // ------------------------------------------------------------------ zip contents

        public sealed class ZipEntryInfo { public string Name; public bool Encrypted; }

        // Reads a zip's table of contents directly (names and whether each is password-protected).
        public static List<ZipEntryInfo> ZipContents(string path)
        {
            var list = new List<ZipEntryInfo>();
            using (var fs = Open(path))
            {
                long len = fs.Length;
                int tail = (int)Math.Min(len, 65557);
                var buf = new byte[tail];
                fs.Seek(len - tail, SeekOrigin.Begin);
                fs.Read(buf, 0, tail);
                int eocd = -1;
                for (int i = tail - 22; i >= 0; i--)
                    if (buf[i] == 0x50 && buf[i + 1] == 0x4B && buf[i + 2] == 5 && buf[i + 3] == 6) { eocd = i; break; }
                if (eocd < 0) return list;
                int count = BitConverter.ToUInt16(buf, eocd + 10);
                long cdOffset = BitConverter.ToUInt32(buf, eocd + 16);
                if (cdOffset >= len) return list;
                fs.Seek(cdOffset, SeekOrigin.Begin);
                var br = new BinaryReader(fs);
                for (int i = 0; i < count && i < 20000; i++)
                {
                    if (br.ReadUInt32() != 0x02014B50) break;
                    br.ReadBytes(4);
                    ushort flags = br.ReadUInt16();
                    br.ReadBytes(18);
                    ushort nameLen = br.ReadUInt16(), extraLen = br.ReadUInt16(), commentLen = br.ReadUInt16();
                    br.ReadBytes(12);
                    var name = br.ReadBytes(nameLen);
                    br.ReadBytes(extraLen + commentLen);
                    list.Add(new ZipEntryInfo { Name = ((flags & 0x800) != 0 ? Encoding.UTF8 : Encoding.GetEncoding(437)).GetString(name), Encrypted = (flags & 1) != 0 });
                }
            }
            return list;
        }

        // ------------------------------------------------------------------ the inspection

        public static FileReport Analyze(string path, bool online)
        {
            var r = new FileReport { Path = path, Name = System.IO.Path.GetFileName(path), Time = Clock.NowIso() };
            var fi = new FileInfo(path);
            r.Size = fi.Length;
            string ext = System.IO.Path.GetExtension(path);
            var head = new byte[16];
            int n;
            using (var fs = Open(path)) n = fs.Read(head, 0, head.Length);
            string magic = Magic(head, n, path);
            using (var fs = Open(path))
            using (var sha = SHA256.Create()) r.Sha256 = FileUtil.Hex(sha.ComputeHash(fs));

            // name tricks
            if (r.Name.IndexOf('‮') >= 0) r.Add("bad", "The name hides a right-to-left character, so it reads backwards: a trick to disguise a program");
            var m = Regex.Match(r.Name, @"\.(pdf|docx?|xlsx?|jpe?g|png|gif|mp4|mp3|txt|zip)(\s|\.|_)*\.(exe|scr|com|pif|bat|cmd|js|vbs|hta|lnk|msi)$", RegexOptions.IgnoreCase);
            if (m.Success) r.Add("bad", "Double extension: it pretends to be a ." + m.Groups[1].Value.ToLowerInvariant() + " but it's really a ." + m.Groups[3].Value.ToLowerInvariant());
            if (Regex.IsMatch(r.Name, @"\s{4,}\.\w+$")) r.Add("bad", "Lots of spaces before the extension: hides the real file type");

            // what it really is
            bool program = magic == "program" || Programs.Contains(ext);
            if (magic == "program" && !Programs.Contains(ext) && !Scripts.Contains(ext))
                r.Add("bad", "It's really a program, disguised with a " + (ext.Length > 0 ? ext : "missing") + " extension");
            if (program)
            {
                r.Kind = ext.Equals(".msi", StringComparison.OrdinalIgnoreCase) || magic == "ole" && ext.Equals(".msi", StringComparison.OrdinalIgnoreCase) ? "installer" : "program";
                r.Risky = true;
                var sig = Signature.Check(path);
                r.Signer = sig.Signed ? sig.Publisher : null;
                if (!sig.Signed) r.Add("warn", "Not signed: there's no way to tell who made it");
                else if (!sig.Trusted) r.Add("bad", "Its signature is broken (the file was changed after signing, or the certificate isn't trusted)");
                else r.Add("good", "Signed by " + sig.Publisher);
                if (sig.Signed && Bundlers.Any(b => (sig.Publisher ?? "").IndexOf(b, StringComparison.OrdinalIgnoreCase) >= 0))
                    r.Add("bad", "Signed by " + sig.Publisher + ", a known adware bundler");
            }
            else if (Scripts.Contains(ext) || magic == "shortcut")
            {
                r.Kind = "script";
                r.Risky = true;
                r.Add("warn", "A script or shortcut (" + ext + "): it runs commands when opened, and isn't something websites normally hand out");
            }
            else if (Containers.Contains(ext) || magic == "iso")
            {
                r.Kind = "disk image";
                r.Risky = true;
                r.Add("warn", "A disk image (" + ext + "): a common way to sneak programs past Windows' download warnings");
            }
            else if (Macros.Contains(ext) || Archives.Contains(ext) || magic == "zip" || magic == "rar" || magic == "7z")
            {
                bool macroCapable = Macros.Contains(ext);
                r.Kind = macroCapable ? "macro-capable document" : "archive";
                if (macroCapable)
                {
                    r.Risky = true;
                    r.Add("warn", "This Office file can contain macros (code). Leave macros disabled unless you trust the source.");
                }
                if (magic == "zip" && !Regex.IsMatch(ext, @"^\.(docx|xlsx|pptx|jar|apk|appx|msix|nupkg|vsix|epub|odt|ods)$", RegexOptions.IgnoreCase))
                {
                    try
                    {
                        var entries = ZipContents(path);
                        var runnable = entries.Where(e => Programs.Contains(System.IO.Path.GetExtension(e.Name)) || Scripts.Contains(System.IO.Path.GetExtension(e.Name)) || Containers.Contains(System.IO.Path.GetExtension(e.Name))).ToList();
                        bool locked = entries.Any(e => e.Encrypted);
                        if (runnable.Count > 0)
                        {
                            r.Risky = true;
                            r.Add(locked ? "bad" : "warn", "Contains " + Fmt.Plural(runnable.Count, "program or script") + ": " + string.Join(", ", runnable.Take(3).Select(e => System.IO.Path.GetFileName(e.Name))) + (runnable.Count > 3 ? ", …" : ""));
                        }
                        if (locked) r.Add(runnable.Count > 0 ? "bad" : "warn", "Password-protected, so antivirus can't look inside" + (runnable.Count > 0 ? " (with programs inside: a favourite malware trick)" : ""));
                        if (entries.Count == 0) r.Add("info", "Couldn't read what's inside");
                        else if (!macroCapable && runnable.Count == 0 && !locked) r.Add("good", Fmt.Plural(entries.Count, "file") + " inside, no programs or scripts");
                    }
                    catch (Exception e) { r.Add("info", "Couldn't look inside: " + e.Message); }
                }
                else if (!macroCapable && magic != "zip") r.Add("info", "Janus can only look inside .zip files; open this one carefully");
            }
            else r.Kind = Harmless.Contains(ext) ? "document or media" : (ext.Length > 0 ? ext.TrimStart('.') + " file" : "file");

            // where it came from
            var zone = Zone(path);
            string host = null;
            if (zone.ContainsKey("HostUrl"))
            {
                r.From = zone["HostUrl"];
                Uri u;
                if (Uri.TryCreate(r.From, UriKind.Absolute, out u)) host = u.Host.ToLowerInvariant();
                if (zone.ContainsKey("ReferrerUrl")) r.Referrer = zone["ReferrerUrl"];
                r.Add("info", "Downloaded from " + (host ?? r.From) + (r.Referrer != null && !r.Referrer.Contains(host ?? "\u0000") ? " (via " + Fmt.Clip(r.Referrer, 80) + ")" : ""));
                if (host != null && Portals.Any(p => host == p || host.EndsWith("." + p)))
                    r.Add(r.Risky ? "warn" : "info", host + " is a download portal; they often wrap installers with adware. Get software from its maker's own site.");
                if (host != null)
                {
                    string rule;
                    if (AegisClient.Verdict(host, out rule) == "block") r.Add("bad", "Aegis blocks " + host + " (" + (rule ?? "listed") + "): this came from a known bad site");
                }
            }
            else if (zone.ContainsKey("ZoneId")) r.Add("info", "Marked as downloaded from the internet");

            if (online) Reputation(r);
            int worst = r.Worst;
            r.Verdict = worst >= 3 ? "danger" : worst == 2 || (r.Risky && r.Signer == null && r.Kind == "program") ? "caution" : "ok";
            if (r.Verdict == "ok" && r.Risky && r.Signer != null) r.Add("good", "Looks like a normal download from a known publisher");
            return r;
        }

        // ------------------------------------------------------------------ reputation (optional API keys)

        public static string KeyFile { get { return System.IO.Path.Combine(Suite.UserDir(AppId.Janus), "keys.dat"); } }

        // Keys are encrypted with your Windows account (DPAPI), so only you can read them.
        public static Dictionary<string, string> LoadKeys()
        {
            try
            {
                if (!File.Exists(KeyFile)) return new Dictionary<string, string>();
                var plain = ProtectedData.Unprotect(File.ReadAllBytes(KeyFile), null, DataProtectionScope.CurrentUser);
                return J.Read<Dictionary<string, string>>(Encoding.UTF8.GetString(plain)) ?? new Dictionary<string, string>();
            }
            catch (Exception) { return new Dictionary<string, string>(); }
        }
        public static void SaveKeys(Dictionary<string, string> keys)
        {
            var bytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(J.Write(keys)), null, DataProtectionScope.CurrentUser);
            FileUtil.WriteAtomic(KeyFile, bytes);
        }

        static void Reputation(FileReport r)
        {
            var keys = LoadKeys();
            string mb, vt;
            keys.TryGetValue("malwarebazaar", out mb);
            keys.TryGetValue("virustotal", out vt);
            if (string.IsNullOrEmpty(mb) && string.IsNullOrEmpty(vt)) { if (r.Risky) r.Reputation = "not checked (add a free key in Settings)"; return; }
            if (!string.IsNullOrEmpty(mb))
            {
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create("https://mb-api.abuse.ch/api/v1/");
                    req.Method = "POST";
                    req.Timeout = 10000;
                    req.ContentType = "application/x-www-form-urlencoded";
                    req.Headers["Auth-Key"] = mb;
                    var body = Encoding.ASCII.GetBytes("query=get_info&hash=" + r.Sha256);
                    using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);
                    using (var resp = req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream()))
                    {
                        var doc = J.Parse(sr.ReadToEnd());
                        string status = J.Str(doc, "query_status");
                        if (status == "ok")
                        {
                            string family = J.Str(doc, "data.0.signature") ?? "malware";
                            r.Add("bad", "MalwareBazaar knows this exact file as malware (" + family + ")");
                            r.Reputation = "known malware: " + family;
                        }
                        else if (status == "hash_not_found") r.Reputation = "not in MalwareBazaar";
                    }
                }
                catch (Exception e) { Log.Warn("MalwareBazaar: " + e.Message); }
            }
            if (!string.IsNullOrEmpty(vt))
            {
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create("https://www.virustotal.com/api/v3/files/" + r.Sha256);
                    req.Timeout = 10000;
                    req.Headers["x-apikey"] = vt;
                    using (var resp = req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream()))
                    {
                        var doc = J.Parse(sr.ReadToEnd());
                        long bad = J.Long(doc, "data.attributes.last_analysis_stats.malicious", 0);
                        long total = bad + J.Long(doc, "data.attributes.last_analysis_stats.undetected", 0) + J.Long(doc, "data.attributes.last_analysis_stats.harmless", 0);
                        r.Reputation = (r.Reputation != null ? r.Reputation + "; " : "") + "VirusTotal: " + bad + " of " + total + " engines flag it";
                        if (bad >= 3) r.Add("bad", bad + " antivirus engines on VirusTotal flag this file");
                        else if (bad > 0) r.Add("warn", bad + " antivirus engine" + (bad == 1 ? "" : "s") + " on VirusTotal flag" + (bad == 1 ? "s" : "") + " this file (could be a false alarm)");
                        else r.Add("good", "VirusTotal has seen this file and no engine flags it");
                    }
                }
                catch (WebException we)
                {
                    var hr = we.Response as HttpWebResponse;
                    if (hr != null && hr.StatusCode == HttpStatusCode.NotFound) r.Reputation = (r.Reputation != null ? r.Reputation + "; " : "") + "VirusTotal hasn't seen it";
                    else Log.Warn("VirusTotal: " + we.Message);
                }
                catch (Exception e) { Log.Warn("VirusTotal: " + e.Message); }
            }
        }
    }
}
