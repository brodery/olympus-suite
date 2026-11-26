// Olympus shared core, compiled into every Olympus exe: the app registry (names, roles,
// colours), where each app keeps its data, logging, INI settings, JSON, process and
// formatting helpers.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace Olympus
{
    public enum AppId { Olympus, Aegis, Argus, Sibyl, Janus, Arachne, Athena, Cerberus, Ark, Ares, Atlas }

    // Identity of every app in the suite.
    public sealed class AppInfo
    {
        public AppId Id;
        public string Name, Role, Blurb;
        public Color Top, Bottom;
        public bool SystemEngine;   // has a part that runs as SYSTEM (its data lives in ProgramData)
        public bool Watcher;        // runs in the background in your session, kept alive by the hub

        public string Key { get { return Name.ToLowerInvariant(); } }
        public string Title { get { return Name + " " + Role; } }

        static Color Rgb(int v) { return Color.FromArgb(255, (v >> 16) & 255, (v >> 8) & 255, v & 255); }
        static AppInfo A(AppId id, string name, string role, string blurb, int top, int bottom, bool system, bool watcher)
        {
            return new AppInfo { Id = id, Name = name, Role = role, Blurb = blurb, Top = Rgb(top), Bottom = Rgb(bottom), SystemEngine = system, Watcher = watcher };
        }

        // Order must match the AppId enum.
        static readonly AppInfo[] all =
        {
            A(AppId.Olympus,  "Olympus",  "app hub",               "Runs and watches over all your apps.",            0x5C6BC0, 0x283593, false, false),
            A(AppId.Aegis,    "Aegis",    "DNS filter",            "Blocks ad, tracker and malware sites.",           0x34C76F, 0x0E8643, false, false),
            A(AppId.Argus,    "Argus",    "hijack watcher",        "Watches every spot adware uses to dig in.",       0x26C6DA, 0x00838F, true,  false),
            A(AppId.Sibyl,    "Sibyl",    "link and scam checker", "Checks links and messages for scams.",            0xAB47BC, 0x6A1B9A, false, false),
            A(AppId.Janus,    "Janus",    "download inspector",    "Inspects new downloads before you run them.",     0xFFA040, 0xE65100, false, true),
            A(AppId.Arachne,  "Arachne",  "infostealer tripwire",  "Catches programs reading your saved logins.",     0x90A4AE, 0x455A64, true,  false),
            A(AppId.Athena,   "Athena",   "security report card",  "Grades your PC's defences and flags slips.",      0xE0B84A, 0x9C7A12, true,  false),
            A(AppId.Cerberus, "Cerberus", "outbound firewall",     "Shows which apps go online, and blocks any.",     0xEF5350, 0xB71C1C, true,  false),
            A(AppId.Ark,      "Ark",      "versioned backups",     "Hourly and nightly backups you can roll back.",   0x42A5F5, 0x1565C0, true,  false),
            A(AppId.Ares,     "Ares",     "game-mode autopilot",   "Clears the decks when a game starts.",            0xEC407A, 0xAD1457, false, true),
            A(AppId.Atlas,    "Atlas",    "disk space map",        "Shows what fills your drives and clears out junk.", 0xB08A62, 0x6D4C33, false, true),
        };

        public static AppInfo[] All { get { return all; } }
        public static AppInfo Of(AppId id) { return all[(int)id]; }
        public static AppInfo Find(string name)
        {
            return all.FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        }
        // Aegis and the nine Olympus apps (the "guardians"), in dashboard order. The hub adds the
        // programs registered in apps.ini (src/Olympus/Apps.cs).
        public static IEnumerable<AppInfo> Guardians { get { return all.Where(a => a.Id != AppId.Olympus); } }
    }

    static class Suite
    {
        public const string Version = "1.0.0";
        public static AppInfo Me = AppInfo.Of(AppId.Olympus);

        public static string ProgramDataRoot
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Olympus"); }
        }
        public static string UserRoot { get { return Path.Combine(User.Local, "Olympus"); } }
        public static string SharedDir(AppId id) { return Path.Combine(ProgramDataRoot, AppInfo.Of(id).Key); }
        public static string UserDir(AppId id) { return Path.Combine(UserRoot, AppInfo.Of(id).Key); }

        // Where this process keeps its own data. Once Olympus is installed, a SYSTEM-engine app
        // running elevated uses ProgramData (you can read it, only admins can change it).
        // Everything else, including test runs before installing, uses your profile.
        public static string DataDir(AppId id)
        {
            var app = AppInfo.Of(id);
            string dir = app.SystemEngine && Elevation.IsElevated && (Installed || Elevation.IsSystem) ? SharedDir(id) : UserDir(id);
            Directory.CreateDirectory(dir);
            return dir;
        }
        public static string MyDir { get { return DataDir(Me.Id); } }

        public static string BinDir { get { return AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'); } }
        public static string ExeOf(AppId id) { return Path.Combine(BinDir, AppInfo.Of(id).Name + ".exe"); }
        public static string InstallDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Olympus"); }
        }
        public static string InstallFile { get { return Path.Combine(ProgramDataRoot, "install.json"); } }
        public static bool Installed { get { return File.Exists(InstallFile); } }

        static UserContext user;
        public static UserContext User
        {
            get { if (user == null) user = UserContext.Resolve(); return user; }
        }
    }

    // Written by install.ps1 so SYSTEM engines know whose files to look after.
    public sealed class InstallInfo
    {
        public string Version, InstalledAt, BinDir, ArkTarget;
        public UserContext User;
    }

    // The person using this PC. A SYSTEM engine can't ask Windows who that is, so it reads
    // what the installer recorded.
    public sealed class UserContext
    {
        public string Sid, Name, Profile, Local, Roaming, Documents, Desktop, Downloads;

        public static UserContext Resolve()
        {
            // SYSTEM can't ask, and an elevated helper may run under a different admin account.
            if (Elevation.IsSystem || Elevation.IsElevated)
            {
                var saved = J.Load<InstallInfo>(Suite.InstallFile);
                if (saved != null && saved.User != null && !string.IsNullOrEmpty(saved.User.Local)) return saved.User;
            }
            var u = new UserContext();
            using (var id = WindowsIdentity.GetCurrent()) { u.Sid = id.User.Value; u.Name = id.Name; }
            u.Profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            u.Local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            u.Roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            u.Documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            u.Desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            u.Downloads = KnownFolders.Downloads() ?? Path.Combine(u.Profile, "Downloads");
            return u;
        }
    }

    static class KnownFolders
    {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid id, uint flags, IntPtr token, out IntPtr path);

        public static string Downloads() { return Get(new Guid("374DE290-123F-4565-9164-39C4925E467B")); }
        public static string SavedGames() { return Get(new Guid("4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4")); }
        static string Get(Guid g)
        {
            IntPtr p;
            try
            {
                if (SHGetKnownFolderPath(g, 0, IntPtr.Zero, out p) != 0) return null;
                try { return Marshal.PtrToStringUni(p); } finally { Marshal.FreeCoTaskMem(p); }
            }
            catch (Exception) { return null; }
        }
    }

    static class Elevation
    {
        static int elevated = -1, system = -1;
        public static bool IsElevated
        {
            get
            {
                if (elevated < 0)
                    using (var id = WindowsIdentity.GetCurrent())
                        elevated = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator) ? 1 : 0;
                return elevated == 1;
            }
        }
        public static bool IsSystem
        {
            get
            {
                if (system < 0) using (var id = WindowsIdentity.GetCurrent()) system = id.IsSystem ? 1 : 0;
                return system == 1;
            }
        }

        // Runs a program elevated (one UAC prompt). Returns its exit code (0 when not waiting),
        // or -1 if the prompt was declined.
        public static int Run(string exe, string args, bool wait)
        {
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            try
            {
                using (var p = Process.Start(psi))
                {
                    if (!wait || p == null) return 0;
                    p.WaitForExit();
                    return p.ExitCode;
                }
            }
            catch (Win32Exception e)
            {
                if (e.NativeErrorCode == 1223) return -1;
                throw;
            }
        }
    }

    // First thing in every Main.
    static class AppStart
    {
        public static void Init(AppId id, bool gui)
        {
            Suite.Me = AppInfo.Of(id);
            try { Log.Open(Suite.MyDir, Suite.Me.Key); } catch (Exception) { }
            if (gui)
            {
                try { Native.SetProcessDPIAware(); } catch (Exception) { }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += (s, e) => Log.Error("unhandled (UI thread)", e.Exception);
            }
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Error("unhandled", e.ExceptionObject as Exception);
            try { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288; }
            catch (NotSupportedException) { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; }
        }
    }

    static class Log
    {
        static string path;
        static readonly object gate = new object();
        static readonly int pid = Process.GetCurrentProcess().Id;
        public static string FilePath { get { return path; } }

        public static void Open(string dir, string name)
        {
            Directory.CreateDirectory(Path.Combine(dir, "logs"));
            path = Path.Combine(dir, "logs", name + ".log");
        }
        public static void Info(string m) { Write("info ", m); }
        public static void Warn(string m) { Write("warn ", m); }
        public static void Error(string m, Exception e)
        {
            Write("error", e == null ? m : m + ": " + e.GetType().Name + ": " + e.Message);
        }

        static void Write(string level, string m)
        {
            if (path == null) return;
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " " + level + " [" + pid + "] " + m + "\r\n";
            lock (gate)
            {
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        var fi = new FileInfo(path);
                        if (fi.Exists && fi.Length > 1024 * 1024)
                        {
                            string old = path + ".1";
                            if (File.Exists(old)) File.Delete(old);
                            File.Move(path, old);
                        }
                        using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                        {
                            var b = Encoding.UTF8.GetBytes(line);
                            fs.Write(b, 0, b.Length);
                        }
                        return;
                    }
                    catch (IOException) { Thread.Sleep(20); }
                    catch (UnauthorizedAccessException) { return; }
                }
            }
        }
    }

    static class FileUtil
    {
        public static string ReadShared(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var r = new StreamReader(fs, Encoding.UTF8, true))
                return r.ReadToEnd();
        }

        public static void WriteAtomic(string path, string text) { WriteAtomic(path, new UTF8Encoding(false).GetBytes(text)); }

        // Writes a temporary file and swaps it in, so readers never see half a file.
        public static void WriteAtomic(string path, byte[] bytes)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(path));
            Directory.CreateDirectory(dir);
            string tmp = path + "." + Process.GetCurrentProcess().Id + "." + Thread.CurrentThread.ManagedThreadId + ".tmp";
            File.WriteAllBytes(tmp, bytes);
            for (int i = 0; ; i++)
            {
                try
                {
                    if (File.Exists(path)) File.Replace(tmp, path, null, true);
                    else File.Move(tmp, path);
                    return;
                }
                catch (Exception e)
                {
                    if (!(e is IOException) && !(e is UnauthorizedAccessException)) throw;
                    if (i >= 6) { TryDelete(tmp); throw; }
                    Thread.Sleep(25 * (i + 1));
                }
            }
        }

        public static void TryDelete(string p) { try { File.Delete(p); } catch (Exception) { } }

        public static string Sha256(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var h = System.Security.Cryptography.SHA256.Create())
                return Hex(h.ComputeHash(fs));
        }
        public static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        public static string Sha256Text(string s)
        {
            using (var h = System.Security.Cryptography.SHA256.Create())
                return Hex(h.ComputeHash(Encoding.UTF8.GetBytes(s ?? "")));
        }
        // Expands %VARS% and makes the path absolute; null stays null.
        public static string Expand(string p)
        {
            if (string.IsNullOrWhiteSpace(p)) return null;
            p = Environment.ExpandEnvironmentVariables(p.Trim().Trim('"'));
            try { return Path.GetFullPath(p); } catch (Exception) { return p; }
        }
    }

    // A small INI reader: [section], key = value, ; or # comments. Keys may repeat.
    sealed class Ini
    {
        readonly Dictionary<string, Dictionary<string, List<string>>> data =
            new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> order = new List<string>();

        public static Ini Parse(string text)
        {
            var ini = new Ini();
            string sec = "";
            ini.Sec(sec, true);
            foreach (var raw in (text ?? "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == ';' || line[0] == '#') continue;
                if (line[0] == '[' && line.EndsWith("]"))
                {
                    sec = line.Substring(1, line.Length - 2).Trim();
                    ini.Sec(sec, true);
                    continue;
                }
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string k = line.Substring(0, eq).Trim(), v = line.Substring(eq + 1).Trim();
                var s = ini.Sec(sec, true);
                List<string> list;
                if (!s.TryGetValue(k, out list)) s[k] = list = new List<string>();
                list.Add(v);
            }
            return ini;
        }

        public static Ini Load(string path)
        {
            try { return Parse(File.Exists(path) ? FileUtil.ReadShared(path) : ""); }
            catch (IOException) { return Parse(""); }
            catch (UnauthorizedAccessException) { return Parse(""); }
        }

        // Writes the commented defaults the first time, so there's a file to edit.
        public static Ini LoadOrCreate(string path, string defaults)
        {
            if (!File.Exists(path)) { try { FileUtil.WriteAtomic(path, defaults); } catch (Exception) { } }
            return File.Exists(path) ? Load(path) : Parse(defaults);
        }

        Dictionary<string, List<string>> Sec(string name, bool create)
        {
            Dictionary<string, List<string>> s;
            if (data.TryGetValue(name, out s)) return s;
            if (!create) return null;
            s = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            data[name] = s;
            order.Add(name);
            return s;
        }

        public IEnumerable<string> Sections { get { return order; } }
        public bool Has(string sec) { return data.ContainsKey(sec); }

        public List<string> All(string sec, string key)
        {
            var s = Sec(sec, false);
            List<string> l;
            return s != null && s.TryGetValue(key, out l) ? l : new List<string>();
        }
        public string Get(string sec, string key, string def)
        {
            var l = All(sec, key);
            return l.Count > 0 ? l[l.Count - 1] : def;
        }
        public IEnumerable<KeyValuePair<string, string>> Pairs(string sec)
        {
            var s = Sec(sec, false);
            if (s == null) yield break;
            foreach (var kv in s) foreach (var v in kv.Value) yield return new KeyValuePair<string, string>(kv.Key, v);
        }
        public int Int(string sec, string key, int def)
        {
            int v;
            return int.TryParse(Get(sec, key, ""), NumberStyles.Integer, CultureInfo.InvariantCulture, out v) ? v : def;
        }
        public double Num(string sec, string key, double def)
        {
            double v;
            return double.TryParse(Get(sec, key, ""), NumberStyles.Float, CultureInfo.InvariantCulture, out v) ? v : def;
        }
        public bool Bool(string sec, string key, bool def)
        {
            string v = Get(sec, key, null);
            if (v == null) return def;
            switch (v.ToLowerInvariant())
            {
                case "true": case "yes": case "on": case "1": return true;
                case "false": case "no": case "off": case "0": return false;
                default: return def;
            }
        }
        public TimeSpan Span(string sec, string key, TimeSpan def)
        {
            TimeSpan t;
            return Spans.TryParse(Get(sec, key, ""), out t) ? t : def;
        }
        // Values split on commas or semicolons, across repeated keys.
        public List<string> List(string sec, string key)
        {
            var res = new List<string>();
            foreach (var v in All(sec, key))
                foreach (var part in v.Split(',', ';'))
                    if (part.Trim().Length > 0) res.Add(part.Trim());
            return res;
        }
    }

    static class Spans
    {
        // "90s", "15m", "1h", "2d", "1w"; a bare number means minutes.
        public static bool TryParse(string s, out TimeSpan t)
        {
            t = TimeSpan.Zero;
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim().ToLowerInvariant();
            char unit = s[s.Length - 1];
            string num = char.IsLetter(unit) ? s.Substring(0, s.Length - 1) : s;
            double v;
            if (!double.TryParse(num, NumberStyles.Float, CultureInfo.InvariantCulture, out v) || v < 0) return false;
            switch (char.IsLetter(unit) ? unit : 'm')
            {
                case 's': t = TimeSpan.FromSeconds(v); return true;
                case 'm': t = TimeSpan.FromMinutes(v); return true;
                case 'h': t = TimeSpan.FromHours(v); return true;
                case 'd': t = TimeSpan.FromDays(v); return true;
                case 'w': t = TimeSpan.FromDays(7 * v); return true;
                default: return false;
            }
        }
    }

    // JSON through the framework's JavaScriptSerializer, plus a pretty-printer and path access
    // into parsed documents (Dictionary<string, object> / object[]).
    static class J
    {
        static JavaScriptSerializer S() { return new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 512 }; }
        public static string Write(object o) { return S().Serialize(o); }
        public static T Read<T>(string s) { return S().Deserialize<T>(s); }
        public static object Parse(string s) { return S().DeserializeObject(s); }

        public static T Load<T>(string path) where T : class
        {
            try { return File.Exists(path) ? Read<T>(FileUtil.ReadShared(path)) : null; }
            catch (Exception) { return null; }
        }
        public static object LoadRaw(string path)
        {
            try { return File.Exists(path) ? Parse(FileUtil.ReadShared(path)) : null; }
            catch (Exception) { return null; }
        }
        public static void Save(string path, object o) { FileUtil.WriteAtomic(path, Pretty(Write(o))); }

        public static string Pretty(string json)
        {
            var sb = new StringBuilder(json.Length + json.Length / 3);
            int indent = 0;
            bool inStr = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inStr)
                {
                    sb.Append(c);
                    if (c == '\\' && i + 1 < json.Length) sb.Append(json[++i]);
                    else if (c == '"') inStr = false;
                    continue;
                }
                switch (c)
                {
                    case '"': inStr = true; sb.Append(c); break;
                    case '{':
                    case '[':
                        if (i + 1 < json.Length && (json[i + 1] == '}' || json[i + 1] == ']')) { sb.Append(c).Append(json[++i]); break; }
                        sb.Append(c).Append('\n').Append(' ', ++indent * 2);
                        break;
                    case '}':
                    case ']':
                        indent = Math.Max(0, indent - 1);
                        sb.Append('\n').Append(' ', indent * 2).Append(c);
                        break;
                    case ',': sb.Append(c).Append('\n').Append(' ', indent * 2); break;
                    case ':': sb.Append(": "); break;
                    default: if (!char.IsWhiteSpace(c)) sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        public static object Get(object o, string path)
        {
            if (string.IsNullOrEmpty(path)) return o;
            foreach (var part in path.Split('.'))
            {
                if (o == null) return null;
                var d = o as IDictionary<string, object>;
                if (d != null)
                {
                    object v;
                    o = d.TryGetValue(part, out v) ? v : null;
                    continue;
                }
                var list = o as System.Collections.IList;
                int idx;
                if (list != null && int.TryParse(part, out idx)) { o = idx >= 0 && idx < list.Count ? list[idx] : null; continue; }
                return null;
            }
            return o;
        }
        public static string Str(object o, string path)
        {
            var v = Get(o, path);
            return v == null ? null : Convert.ToString(v, CultureInfo.InvariantCulture);
        }
        public static long Long(object o, string path, long def)
        {
            var v = Get(o, path);
            if (v == null) return def;
            try { return Convert.ToInt64(v, CultureInfo.InvariantCulture); } catch (Exception) { return def; }
        }
        public static bool Bool(object o, string path, bool def)
        {
            var v = Get(o, path);
            return v is bool ? (bool)v : def;
        }
        public static IEnumerable<object> List(object o, string path)
        {
            var l = Get(o, path) as System.Collections.IList;
            return l == null ? Enumerable.Empty<object>() : l.Cast<object>();
        }
        public static IDictionary<string, object> Obj(object o, string path)
        {
            return Get(o, path) as IDictionary<string, object>;
        }
    }

    static class Clock
    {
        public static string Iso(DateTime utc)
        {
            if (utc.Kind == DateTimeKind.Local) utc = utc.ToUniversalTime();
            return utc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }
        public static string NowIso() { return Iso(DateTime.UtcNow); }
        public static DateTime Parse(string iso)
        {
            DateTime t;
            if (string.IsNullOrEmpty(iso)) return DateTime.MinValue;
            return DateTime.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t)
                ? DateTime.SpecifyKind(t, DateTimeKind.Utc) : DateTime.MinValue;
        }
        public static DateTime FromUnix(long s) { return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(s); }
    }

    static class Fmt
    {
        public static string Size(long b)
        {
            if (b < 1024) return b + " B";
            double v = b;
            string[] units = { "KB", "MB", "GB", "TB" };
            int i = -1;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return v.ToString(v < 10 ? "0.0" : "0", CultureInfo.InvariantCulture) + " " + units[i];
        }
        public static string Ago(DateTime utc)
        {
            if (utc == DateTime.MinValue) return "never";
            var t = DateTime.UtcNow - utc;
            if (t.TotalSeconds < 0) t = TimeSpan.Zero;
            if (t.TotalSeconds < 50) return "just now";
            if (t.TotalMinutes < 59.5) return Math.Max(1, (int)Math.Round(t.TotalMinutes)) + " min ago";
            if (t.TotalHours < 23.5) return Plural((long)Math.Round(t.TotalHours), "hour") + " ago";
            return Plural((long)Math.Round(t.TotalDays), "day") + " ago";
        }
        public static string Plural(long n, string word)
        {
            return n.ToString("N0", CultureInfo.CurrentCulture) + " " + word + (n == 1 ? "" : "s");
        }
        public static string Local(DateTime utc)
        {
            if (utc == DateTime.MinValue) return "-";
            var l = utc.ToLocalTime();
            string day = l.Date == DateTime.Today ? "today" : l.Date == DateTime.Today.AddDays(-1) ? "yesterday" : l.ToString("MMM d", CultureInfo.CurrentCulture);
            return day + " " + l.ToString("h:mm tt", CultureInfo.CurrentCulture);
        }
        public static string Duration(TimeSpan t)
        {
            if (t.TotalSeconds < 60) return Math.Max(0, (int)t.TotalSeconds) + " s";
            if (t.TotalMinutes < 60) return (int)t.TotalMinutes + " min";
            if (t.TotalHours < 48) return (int)t.TotalHours + " h" + (t.Minutes > 0 ? " " + t.Minutes + " min" : "");
            return (int)t.TotalDays + " days";
        }
        public static string Clip(string s, int max)
        {
            if (s == null) return "";
            s = s.Replace("\r", " ").Replace("\n", " ");
            return s.Length <= max ? s : s.Substring(0, Math.Max(0, max - 1)) + "…";
        }
    }

    static class Proc
    {
        // Runs a program hidden; returns its exit code (-999 if killed at the timeout) and output.
        public static int Run(string exe, string args, out string output, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            var sb = new StringBuilder();
            var gate = new object();
            using (var p = new Process { StartInfo = psi })
            {
                DataReceivedEventHandler h = (s, e) => { if (e.Data != null) lock (gate) sb.AppendLine(e.Data); };
                p.OutputDataReceived += h;
                p.ErrorDataReceived += h;
                try { p.Start(); }
                catch (Exception e) { output = e.Message; return -998; }
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch (Exception) { }
                    lock (gate) output = sb.ToString();
                    return -999;
                }
                p.WaitForExit();
                lock (gate) output = sb.ToString();
                return p.ExitCode;
            }
        }

        public static void Start(string exe, string args)
        {
            Process.Start(new ProcessStartInfo(exe, args ?? "") { UseShellExecute = false, CreateNoWindow = true });
        }
        public static void Open(string target)
        {
            try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); } catch (Exception) { }
        }
        public static void ShowInExplorer(string path)
        {
            try { Process.Start("explorer.exe", "/select,\"" + path + "\""); } catch (Exception) { }
        }
        public static string Quote(string a)
        {
            if (a == null) return "\"\"";
            return a.IndexOfAny(new[] { ' ', '\t', '"' }) >= 0 ? "\"" + a.Replace("\"", "\\\"") + "\"" : a;
        }
        // Path of a running process, or null (protected processes, or it has exited).
        public static string PathOf(int pid)
        {
            if (pid <= 4) return null;
            return Native.ProcessPath(pid);
        }
        public static bool Running(string exePath)
        {
            string name = Path.GetFileNameWithoutExtension(exePath);
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    string pp = Native.ProcessPath(p.Id);
                    if (pp != null && pp.Equals(exePath, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            return false;
        }
    }

    sealed class Args
    {
        readonly List<string> a;
        public Args(string[] args) { a = new List<string>(args ?? new string[0]); }
        public bool Has(string flag) { return a.Any(x => x.Equals(flag, StringComparison.OrdinalIgnoreCase)); }
        public string Opt(string name)
        {
            int i = a.FindIndex(x => x.Equals(name, StringComparison.OrdinalIgnoreCase));
            return i >= 0 && i + 1 < a.Count ? a[i + 1] : null;
        }
        public string First { get { return a.Count > 0 ? a[0] : null; } }
        public string this[int i] { get { return i >= 0 && i < a.Count ? a[i] : null; } }
        public int Count { get { return a.Count; } }
        public string Rest(int from) { return string.Join(" ", a.Skip(from)); }
    }

    // Command-line output from a window app (attaches to the console that started it).
    static class Cli
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);
        static bool attached;
        public static void Attach()
        {
            if (attached) return;
            attached = true;
            if (!Console.IsOutputRedirected && AttachConsole(-1)) Console.WriteLine();
        }
        // Consoles often aren't UTF-8, so the few typographic characters we use go out as ASCII.
        public static string Plain(string s)
        {
            if (s == null) return "";
            return s.Replace("·", "-").Replace("—", "-").Replace("–", "-").Replace("…", "...")
                    .Replace("●", "*").Replace("→", "->").Replace("’", "'").Replace("“", "\"").Replace("”", "\"");
        }
        public static void Out(string s) { Console.WriteLine(Plain(s)); }
        public static void Table(IList<string[]> rows)
        {
            if (rows.Count == 0) return;
            int cols = rows.Max(r => r.Length);
            var w = new int[cols];
            foreach (var r in rows) for (int i = 0; i < r.Length; i++) w[i] = Math.Max(w[i], (r[i] ?? "").Length);
            foreach (var r in rows)
            {
                var sb = new StringBuilder();
                for (int i = 0; i < r.Length; i++) sb.Append(i == r.Length - 1 ? r[i] : (r[i] ?? "").PadRight(w[i] + 2));
                Console.WriteLine(Plain(sb.ToString().TrimEnd()));
            }
        }
    }

    // Named mutexes (one copy of something at a time) and wake-up signals between processes.
    static class Sync
    {
        static string Prefix { get { return Elevation.IsElevated ? "Global\\Olympus." : "Local\\Olympus."; } }

        // Holds a named mutex for the life of the process; false if another copy holds it.
        public static bool Claim(string name, out Mutex m)
        {
            m = null;
            try
            {
                bool created;
                m = new Mutex(false, Prefix + name, out created);
                try { if (m.WaitOne(0)) return true; }
                catch (AbandonedMutexException) { return true; }
                m.Dispose();
                m = null;
                return false;
            }
            catch (UnauthorizedAccessException) { if (m != null) m.Dispose(); m = null; return false; }
        }
        public static EventWaitHandle Listen(string name)
        {
            return new EventWaitHandle(false, EventResetMode.AutoReset, "Local\\Olympus." + name);
        }
        public static bool Poke(string name)
        {
            try { using (var e = EventWaitHandle.OpenExisting("Local\\Olympus." + name)) { e.Set(); return true; } }
            catch (Exception) { return false; }
        }
    }

    static class Native
    {
        [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint modifiers, uint vk);
        [DllImport("user32.dll")] public static extern bool UnregisterHotKey(IntPtr hWnd, int id);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateHardLink(string newFile, string existingFile, IntPtr securityAttributes);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);

        public static string ProcessPath(int pid)
        {
            IntPtr h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int n = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString(0, n) : null;
            }
            finally { CloseHandle(h); }
        }
    }
}
