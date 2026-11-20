// Cerberus's engine (runs as SYSTEM): every 2 seconds it reads the TCP table to see which
// program opened which internet connection, estimates hostnames using Windows' DNS-Client log
// (event 3008 records which process looked up which name and got which addresses), counts
// lookups Aegis answered with 0.0.0.0 per program, and alerts when a program goes online for the
// first time (after a 24-hour learning period). Blocking adds a Windows Firewall rule.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Olympus.Cerberus
{
    public sealed class AppNet
    {
        public string Name, Path, Signer, FirstSeen, LastSeen;
        public int Connections;
        public Dictionary<string, int> Sites = new Dictionary<string, int>();
        public Dictionary<string, int> Blocked = new Dictionary<string, int>();   // lookups Aegis refused
    }

    public sealed class LiveConn
    {
        public string App, Path, Site, Remote;
        public int Pid, Port;
    }

    public sealed class NetMeta
    {
        public string Started, LearningUntil;
    }

    // Reads the DNS-Client log as it's written.
    sealed class DnsWatch : IDisposable
    {
        EventLogWatcher watcher;
        public string Error;
        readonly object gate = new object();
        readonly Dictionary<string, string> byPidIp = new Dictionary<string, string>(), byIp = new Dictionary<string, string>();
        readonly Dictionary<string, int> blocked = new Dictionary<string, int>();   // "pid|name" -> count
        public int Seen;

        public void Start()
        {
            try
            {
                using (var cfg = new EventLogConfiguration("Microsoft-Windows-DNS-Client/Operational"))
                    if (!cfg.IsEnabled) Error = "the log is switched off (install.cmd turns it on)";
            }
            catch (Exception) { }
            try
            {
                var q = new EventLogQuery("Microsoft-Windows-DNS-Client/Operational", PathType.LogName, "*[System[(EventID=3008)]]");
                watcher = new EventLogWatcher(q);
                watcher.EventRecordWritten += OnEvent;
                watcher.Enabled = true;
            }
            catch (Exception e) { Error = e.Message; Log.Warn("DNS-Client log: " + e.Message); }
        }

        // QueryResults looks like "type:  5 cdn.example.net;::ffff:93.184.216.34;2606:2800::1;"
        public static List<IPAddress> Addresses(string results)
        {
            var list = new List<IPAddress>();
            foreach (var raw in (results ?? "").Split(';'))
            {
                string t = raw.Trim();
                if (t.Length == 0 || t.StartsWith("type:")) continue;
                IPAddress ip;
                if (IPAddress.TryParse(t, out ip)) list.Add(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip);
            }
            return list;
        }

        public static bool IsBlockAnswer(List<IPAddress> ips)
        {
            return ips.Count > 0 && ips.All(i => i.Equals(IPAddress.Any) || i.Equals(IPAddress.IPv6Any));
        }

        void OnEvent(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            try
            {
                using (var r = e.EventRecord)
                {
                    var p = r.Properties;
                    if (p.Count < 5) return;
                    string name = Convert.ToString(p[0].Value);
                    string results = Convert.ToString(p[4].Value);
                    int pid = r.ProcessId ?? 0;
                    var ips = Addresses(results);
                    lock (gate)
                    {
                        Seen++;
                        if (IsBlockAnswer(ips))
                        {
                            string k = pid + "|" + name.ToLowerInvariant();
                            int c;
                            blocked.TryGetValue(k, out c);
                            blocked[k] = c + 1;
                            return;
                        }
                        foreach (var ip in ips)
                        {
                            string s = ip.ToString();
                            byPidIp[pid + "|" + s] = name;
                            byIp[s] = name;
                        }
                        if (byIp.Count > 60000) { byIp.Clear(); byPidIp.Clear(); }
                    }
                }
            }
            catch (Exception) { }
        }

        public string NameFor(int pid, IPAddress ip)
        {
            string s = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString(), n;
            lock (gate)
            {
                if (byPidIp.TryGetValue(pid + "|" + s, out n)) return n;
                return byIp.TryGetValue(s, out n) ? n : null;
            }
        }

        // The blocked lookups since the last call, as (pid, name, count).
        public List<Tuple<int, string, int>> TakeBlocked()
        {
            lock (gate)
            {
                var list = blocked.Select(kv => { var parts = kv.Key.Split(new[] { '|' }, 2); return Tuple.Create(int.Parse(parts[0]), parts[1], kv.Value); }).ToList();
                blocked.Clear();
                return list;
            }
        }

        public void Dispose() { if (watcher != null) { watcher.Enabled = false; watcher.Dispose(); } }
    }

    static class Firewall
    {
        public const string Group = "Olympus Cerberus";

        static object Get(object o, string n) { return o.GetType().InvokeMember(n, BindingFlags.GetProperty, null, o, null); }
        static void Set(object o, string n, object v) { o.GetType().InvokeMember(n, BindingFlags.SetProperty, null, o, new[] { v }); }

        static object Rules() { var pol = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); return Get(pol, "Rules"); }

        public static HashSet<string> BlockedApps()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (object rule in (System.Collections.IEnumerable)Rules())
                {
                    if (Convert.ToString(Get(rule, "Grouping")) == Group && Convert.ToInt32(Get(rule, "Direction")) == 2 && Convert.ToInt32(Get(rule, "Action")) == 0)
                    {
                        string app = Convert.ToString(Get(rule, "ApplicationName"));
                        if (!string.IsNullOrEmpty(app)) set.Add(app);
                    }
                }
            }
            catch (Exception e) { Log.Warn("reading firewall rules: " + e.Message); }
            return set;
        }

        public static void Block(string path)
        {
            if (BlockedApps().Contains(path)) return;
            var rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            Set(rule, "Name", "Cerberus: block " + System.IO.Path.GetFileName(path));
            Set(rule, "Description", "Added by Olympus Cerberus because you chose to keep this program off the internet. Remove it in Cerberus (Unblock).");
            Set(rule, "ApplicationName", path);
            Set(rule, "Protocol", 256);
            Set(rule, "Direction", 2);
            Set(rule, "Action", 0);
            Set(rule, "Profiles", 0x7FFFFFFF);
            Set(rule, "Grouping", Group);
            Set(rule, "Enabled", true);
            var rules = Rules();
            rules.GetType().InvokeMember("Add", BindingFlags.InvokeMethod, null, rules, new[] { rule });
            Log.Info("blocked " + path);
        }

        public static int Unblock(string path)
        {
            var rules = Rules();
            var names = new List<string>();
            foreach (object rule in (System.Collections.IEnumerable)rules)
                if (Convert.ToString(Get(rule, "Grouping")) == Group && string.Equals(Convert.ToString(Get(rule, "ApplicationName")), path, StringComparison.OrdinalIgnoreCase))
                    names.Add(Convert.ToString(Get(rule, "Name")));
            foreach (var n in names.Distinct()) rules.GetType().InvokeMember("Remove", BindingFlags.InvokeMethod, null, rules, new object[] { n });
            Log.Info("unblocked " + path + " (" + names.Count + " rules)");
            return names.Count;
        }
    }

    static class NetEngine
    {
        public static string AppsFile { get { return System.IO.Path.Combine(Suite.MyDir, "apps.json"); } }
        public static string LiveFile { get { return System.IO.Path.Combine(Suite.MyDir, "live.json"); } }

        static Dictionary<string, AppNet> LoadApps()
        {
            var d = J.Load<Dictionary<string, AppNet>>(AppsFile);
            return d == null ? new Dictionary<string, AppNet>(StringComparer.OrdinalIgnoreCase) : new Dictionary<string, AppNet>(d, StringComparer.OrdinalIgnoreCase);
        }

        static void Bump(Dictionary<string, int> d, string key, int by)
        {
            int c;
            d.TryGetValue(key, out c);
            d[key] = c + by;
            if (d.Count > 60)
                foreach (var k in d.OrderBy(kv => kv.Value).Take(d.Count - 50).Select(kv => kv.Key).ToList()) d.Remove(k);
        }

        // seconds > 0 stops after that long (for testing); the scheduled task runs it without a limit.
        public static int Run(int seconds)
        {
            var until = seconds > 0 ? DateTime.UtcNow.AddSeconds(seconds) : DateTime.MaxValue;
            Mutex m;
            if (!Sync.Claim("cerberus.engine", out m)) return 0;
            using (m)
            using (var dns = new DnsWatch())
            {
                dns.Start();
                var apps = LoadApps();
                string metaPath = System.IO.Path.Combine(Suite.MyDir, "meta.json");
                var meta = J.Load<NetMeta>(metaPath);
                if (meta == null) { meta = new NetMeta { Started = Clock.NowIso(), LearningUntil = Clock.Iso(DateTime.UtcNow.AddHours(24)) }; J.Save(metaPath, meta); }
                var names = new Dictionary<int, string>();
                var paths = new Dictionary<int, string>();
                var open = new Dictionary<string, DateTime>();
                DateTime lastSave = DateTime.UtcNow, lastLive = DateTime.MinValue;
                int newToday = 0;
                Log.Info("engine started" + (dns.Error != null ? " (no site names: " + dns.Error + ")" : ""));
                while (DateTime.UtcNow < until)
                {
                    Thread.Sleep(2000);
                    var now = DateTime.UtcNow;
                    bool learning = now < Clock.Parse(meta.LearningUntil);
                    try
                    {
                        var conns = NetTables.Tcp(false).Where(c => (c.State == NetTables.Established || c.State == NetTables.SynSent) && NetTables.IsPublic(c.RemoteIp)).ToList();
                        var live = new List<LiveConn>();
                        foreach (var c in conns)
                        {
                            string path;
                            if (!paths.TryGetValue(c.Pid, out path))
                            {
                                path = Proc.PathOf(c.Pid);
                                if (path == null)
                                {
                                    try { using (var p = Process.GetProcessById(c.Pid)) path = p.ProcessName + " (pid " + c.Pid + ")"; } catch (Exception) { path = "pid " + c.Pid; }
                                }
                                paths[c.Pid] = path;
                            }
                            string site = dns.NameFor(c.Pid, c.RemoteIp);
                            string remote = NetTables.Show(c.RemoteIp);
                            live.Add(new LiveConn { App = System.IO.Path.GetFileNameWithoutExtension(path), Path = path, Pid = c.Pid, Remote = remote, Port = c.RemotePort, Site = site });
                            string key = c.Pid + "|" + remote + "|" + c.RemotePort;
                            if (open.ContainsKey(key)) { open[key] = now; continue; }
                            open[key] = now;
                            AppNet app;
                            if (!apps.TryGetValue(path, out app))
                            {
                                app = new AppNet { Path = path, Name = System.IO.Path.GetFileNameWithoutExtension(path), FirstSeen = Clock.NowIso() };
                                if (File.Exists(path)) { var sig = Signature.Check(path); app.Signer = sig.Signed ? sig.Publisher : null; }
                                apps[path] = app;
                                newToday++;
                                if (!learning)
                                {
                                    var a = AlertStore.New(Sev.Notice, "First TCP activity seen for " + app.Name,
                                        app.Name + " (" + (app.Signer ?? "unsigned") + ") was observed connecting to " + remote
                                        + (site == null ? "" : " (likely " + site + ")") + ".\n" + path, "firstnet:" + path).With("path", path);
                                    if (File.Exists(path)) a.Act("block", "Keep it offline", true);
                                    AlertStore.Raise(a);
                                }
                            }
                            app.LastSeen = Clock.NowIso();
                            app.Connections++;
                            Bump(app.Sites, site ?? remote, 1);
                        }
                        foreach (var k in open.Where(kv => now - kv.Value > TimeSpan.FromMinutes(2)).Select(kv => kv.Key).ToList()) open.Remove(k);
                        if (now - lastLive > TimeSpan.FromSeconds(10))
                        {
                            lastLive = now;
                            try { J.Save(LiveFile, live); } catch (Exception) { }
                        }
                        if (now - lastSave > TimeSpan.FromSeconds(60))
                        {
                            lastSave = now;
                            foreach (var b in dns.TakeBlocked())
                            {
                                string path;
                                if (!paths.TryGetValue(b.Item1, out path)) { path = Proc.PathOf(b.Item1); if (path == null) continue; paths[b.Item1] = path; }
                                AppNet app;
                                if (!apps.TryGetValue(path, out app)) apps[path] = app = new AppNet { Path = path, Name = System.IO.Path.GetFileNameWithoutExtension(path), FirstSeen = Clock.NowIso(), LastSeen = Clock.NowIso() };
                                Bump(app.Blocked, b.Item2, b.Item3);
                            }
                            var alive = new HashSet<int>(Process.GetProcesses().Select(p => { int id = p.Id; p.Dispose(); return id; }));
                            foreach (var pid in paths.Keys.Where(k => !alive.Contains(k)).ToList()) paths.Remove(pid);
                            J.Save(AppsFile, apps);
                            string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
                            int online = apps.Values.Count(a => a.LastSeen != null && a.LastSeen.StartsWith(today));
                            int blocked = apps.Values.Sum(a => a.Blocked.Values.Sum());
                            string detail = learning ? "Learning baseline TCP activity until " + Fmt.Local(Clock.Parse(meta.LearningUntil)) : Fmt.Plural(apps.Count, "app") + " seen so far";
                            detail += dns.Error != null ? " · DNS lookup data unavailable" : " · destination names estimated from DNS";
                            StatusStore.Write(States.Ok, Fmt.Plural(online, "app") + " seen over public TCP today · " + blocked.ToString("N0") + " lookups blocked by Aegis", detail, new Dictionary<string, object> { { "apps", apps.Count }, { "dnsEvents", dns.Seen } });
                        }
                    }
                    catch (Exception e) { Log.Error("engine loop", e); }
                }
                J.Save(AppsFile, apps);
                return 0;
            }
        }
    }
}
