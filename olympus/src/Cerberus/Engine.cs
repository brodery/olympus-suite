// Cerberus's engine (runs as SYSTEM): every 2 seconds it reads the TCP table to see which
// program opened which internet connection, estimates hostnames using Windows' DNS-Client log
// (event 3008 records which process looked up which name and got which addresses), counts
// lookups Aegis answered with 0.0.0.0 per program, and alerts when a program goes online for the
// first time (after a 24-hour learning period). Blocking adds a Windows Firewall rule.
using System;
using System.Collections.Concurrent;
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
        // SignerId: the verified signer's identity (SignerInfo.Id) when first seen. Verified: that file was
        // validly signed and in a folder only admins can change, so a later version can be matched to it.
        // DriverVer: for a program in the driver store, its driver package's DriverVer (later must be higher).
        public string Name, Path, Signer, FirstSeen, LastSeen, SignerId, DriverVer;
        public bool Verified;
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

    // A program's first public TCP from a version folder, waiting for its check: Probe gets the worker's results
    // (signer, identity, verified, DriverVer); the rest is what was seen first, for the alert.
    sealed class Sighting
    {
        public AppNet Probe;
        public string Remote, Site, Verb;
    }

    // Checks first sightings on a thread of its own (a folder tree can take seconds to check), so the 2-second
    // sampler keeps sampling. The sampler hands sightings over with TryAdd (false when the queue is full: it then
    // checks that one itself) and takes finished ones back with TryTake, deciding each on its own thread.
    sealed class SightingWorker : IDisposable
    {
        readonly BlockingCollection<Sighting> todo;
        readonly ConcurrentQueue<Sighting> done = new ConcurrentQueue<Sighting>();
        readonly Action<AppNet> check;
        readonly Thread thread;

        public SightingWorker(Action<AppNet> check, int capacity)
        {
            this.check = check;
            todo = new BlockingCollection<Sighting>(capacity);
            thread = new Thread(Work) { IsBackground = true, Name = "Cerberus first sightings", Priority = ThreadPriority.BelowNormal };
            thread.Start();
        }

        public bool TryAdd(Sighting s)
        {
            try { return todo.TryAdd(s); }
            catch (InvalidOperationException) { return false; }   // shutting down
        }

        public bool TryTake(out Sighting s) { return done.TryDequeue(out s); }

        // Nothing may escape this thread (that would end Cerberus): a check that fails hands back an unverified
        // result, and even logging the failure is best-effort.
        void Work()
        {
            foreach (var s in todo.GetConsumingEnumerable())
            {
                try { check(s.Probe); }
                catch (Exception e)
                {
                    s.Probe.Verified = false;
                    s.Probe.SignerId = null;
                    s.Probe.DriverVer = null;
                    try { Log.Warn("checking " + s.Probe.Path + ": " + e.Message); } catch (Exception) { }
                }
                done.Enqueue(s);
            }
        }

        // Stops taking sightings and lets the ones queued finish (up to 'wait'), so the caller can still decide them.
        public void Finish(TimeSpan wait)
        {
            todo.CompleteAdding();
            thread.Join(wait);
        }

        public void Dispose() { Finish(TimeSpan.FromSeconds(10)); }
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
            return BlockedAppsOrNull() ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        // The programs Cerberus keeps offline (an enabled outbound block rule of its own names them), or null
        // when the firewall rules couldn't be read. A disabled rule doesn't count.
        public static HashSet<string> BlockedAppsOrNull()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (object rule in (System.Collections.IEnumerable)Rules())
                    if (IsOurBlock(rule) && Convert.ToBoolean(Get(rule, "Enabled")))
                    {
                        string app = Convert.ToString(Get(rule, "ApplicationName"));
                        if (!string.IsNullOrEmpty(app)) set.Add(app);
                    }
            }
            catch (Exception e) { Log.Warn("reading firewall rules: " + e.Message); return null; }
            return set;
        }

        static bool IsOurBlock(object rule)
        {
            return Convert.ToString(Get(rule, "Grouping")) == Group && Convert.ToInt32(Get(rule, "Direction")) == 2 && Convert.ToInt32(Get(rule, "Action")) == 0;
        }

        // A readable name with a 64-bit hash of the path, so each blocked path has a rule name of its own.
        internal static string RuleName(string path)
        {
            string id = FileUtil.Sha256Text((path ?? "").ToLowerInvariant()).Substring(0, 16);
            return "Cerberus: block " + System.IO.Path.GetFileName(path) + " (" + id + ")";
        }

        // Keeps the program offline: switches an existing rule of ours for that path back on, or adds one,
        // then checks that an enabled outbound block for exactly that path is in place.
        public static void Block(string path)
        {
            var rules = Rules();
            bool found = false;
            foreach (object rule in (System.Collections.IEnumerable)rules)
                if (IsOurBlock(rule) && string.Equals(Convert.ToString(Get(rule, "ApplicationName")), path, StringComparison.OrdinalIgnoreCase))
                {
                    found = true;
                    if (!Convert.ToBoolean(Get(rule, "Enabled"))) Set(rule, "Enabled", true);
                }
            if (!found)
            {
                var rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                Set(rule, "Name", RuleName(path));
                Set(rule, "Description", "Added by Olympus Cerberus because you chose to keep this program off the internet. Remove it in Cerberus (Unblock).");
                Set(rule, "ApplicationName", path);
                Set(rule, "Protocol", 256);
                Set(rule, "Direction", 2);
                Set(rule, "Action", 0);
                Set(rule, "Profiles", 0x7FFFFFFF);
                Set(rule, "Grouping", Group);
                Set(rule, "Enabled", true);
                rules.GetType().InvokeMember("Add", BindingFlags.InvokeMethod, null, rules, new[] { rule });
            }
            var now = BlockedAppsOrNull();
            if (now == null || !now.Contains(path)) throw new InvalidOperationException("the firewall rule for " + path + " isn't in effect");
            Log.Info("blocked " + path);
        }

        // Removes exactly our rules for that path. Windows removes rules by name, and older rules can share
        // a name with another path's, so each matching rule is first renamed to a name of its own.
        public static int Unblock(string path)
        {
            var rules = Rules();
            var mine = new List<object>();
            foreach (object rule in (System.Collections.IEnumerable)rules)
                if (Convert.ToString(Get(rule, "Grouping")) == Group && string.Equals(Convert.ToString(Get(rule, "ApplicationName")), path, StringComparison.OrdinalIgnoreCase))
                    mine.Add(rule);
            foreach (var rule in mine)
            {
                string unique = "Cerberus: removing " + Guid.NewGuid().ToString("N");
                Set(rule, "Name", unique);
                rules.GetType().InvokeMember("Remove", BindingFlags.InvokeMethod, null, rules, new object[] { unique });
            }
            // Success only once the rules, read again, show the path clear (removing a rule Windows can't find
            // does nothing and says nothing).
            var left = BlockedAppsOrNull();
            if (left == null) throw new InvalidOperationException("couldn't read the firewall rules back to confirm " + path + " is unblocked");
            if (left.Contains(path)) throw new InvalidOperationException("a firewall rule for " + path + " is still in effect");
            Log.Info("unblocked " + path + " (" + mine.Count + " rules)");
            return mine.Count;
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

        internal enum PathKind { New, Update, BlockedUpdate }

        // What a program first seen on public TCP at a path is.
        // - BlockedUpdate: another version (older or newer, paths compared as Windows does) of an app you chose
        //   to keep offline, judged from the firewall rules themselves (even if the app's record is gone). The
        //   rule names the other version's path, so this one is online: you're told, with the option to block
        //   it too. When the rules can't be read (blockedPaths returns null), any other version Cerberus has
        //   seen counts, whoever signed it: it might be the one you blocked.
        // - Update: a newer version of a verified app (validly signed, admin-only folder tree when first seen)
        //   with the same verified signer identity, itself verified now; in the driver store, a later DriverVer
        //   too. Not a new program going online. Callers stay quiet only with rules read just now.
        // - New: anything else, including the first update of an app recorded before identities existed.
        internal static PathKind Classify(IEnumerable<AppNet> known, AppNet app, Func<HashSet<string>> blockedPaths, out AppNet earlier)
        {
            earlier = null;
            if (app == null || app.Path == null || !Versioned.HasVersionFolder(app.Path)) return PathKind.New;
            var others = known.Where(a => a != null && a.Path != null && !string.Equals(a.Path, app.Path, StringComparison.OrdinalIgnoreCase)).ToList();
            var blocked = blockedPaths == null ? null : blockedPaths();
            if (blocked == null)
            {
                earlier = others.FirstOrDefault(a => Versioned.SameFamily(a.Path, app.Path));
                return earlier != null ? PathKind.BlockedUpdate : PathKind.New;
            }
            string rule = blocked.FirstOrDefault(p => !string.Equals(p, app.Path, StringComparison.OrdinalIgnoreCase) && Versioned.SameFamily(p, app.Path));
            if (rule != null)
            {
                earlier = others.FirstOrDefault(a => string.Equals(a.Path, rule, StringComparison.OrdinalIgnoreCase)) ?? new AppNet { Path = rule, Name = app.Name };
                return PathKind.BlockedUpdate;
            }
            if (!app.Verified || string.IsNullOrEmpty(app.SignerId) || string.IsNullOrEmpty(app.Signer)) return PathKind.New;
            bool driver = Versioned.InDriverStore(app.Path);
            // A rollback isn't an update: no version Cerberus has seen may be later than this one (in the driver
            // store by DriverVer, where a copy whose DriverVer isn't known might be later).
            bool laterSeen = driver
                ? others.Any(a => Versioned.InDriverStore(a.Path) && Versioned.SameFamily(a.Path, app.Path) && (a.DriverVer == null || !Versioned.LaterDriver(a.DriverVer, app.DriverVer)))
                : others.Any(a => Versioned.IsUpdate(app.Path, a.Path, true));
            if (laterSeen) return PathKind.New;
            earlier = others.FirstOrDefault(a => a.Verified && a.SignerId == app.SignerId && string.Equals(a.Signer, app.Signer, StringComparison.Ordinal)
                && Versioned.IsUpdate(a.Path, app.Path) && (!driver || Versioned.LaterDriver(a.DriverVer, app.DriverVer)));
            return earlier != null ? PathKind.Update : PathKind.New;
        }

        // The firewall rules (null: unreadable), read at most every 30 seconds unless 'fresh' (Block and Unblock
        // change them from another process). A failed read is remembered for 30 seconds too.
        static HashSet<string> rulesCache;
        static bool rulesTried;
        static DateTime rulesRead = DateTime.MinValue;
        static HashSet<string> BlockedRules(bool fresh)
        {
            if (fresh || !rulesTried || DateTime.UtcNow - rulesRead > TimeSpan.FromSeconds(30))
            {
                rulesCache = Firewall.BlockedAppsOrNull();
                rulesRead = DateTime.UtcNow;
                rulesTried = true;
            }
            return rulesCache;
        }

        // Signs and, for a path that could be a newer version of something, verifies a program first seen on
        // public TCP: its signer identity from the held file, and whether its folder tree is admin-only.
        static void Identify(AppNet app)
        {
            if (!File.Exists(app.Path)) return;
            if (!Versioned.HasVersionFolder(app.Path))
            {
                var quick = Signature.Check(app.Path);
                app.Signer = quick.Signed ? quick.Publisher : null;
                return;
            }
            // Neighbours checked now, not from a recent verdict: the result decides this path for good.
            using (var held = Versioned.Protect(app.Path, Siblings.Tree, true))
            {
                var sig = held.Ok ? Signature.CheckHeld(app.Path, held.Leaf) : Signature.Check(app.Path);
                app.Signer = sig.Signed ? sig.Publisher : null;
                if (held.Ok && sig.Signed && sig.Trusted && !string.IsNullOrEmpty(sig.Id))
                {
                    app.SignerId = sig.Id;
                    app.Verified = true;
                    if (Versioned.InDriverStore(app.Path)) app.DriverVer = Versioned.DriverVer(app.Path);
                }
            }
        }

        // Decides a program's first public TCP: an update stays quiet (logged); another version of an app you
        // blocked gets a warning; anything else gets the first-activity notice, except while learning.
        static void Decide(Dictionary<string, AppNet> apps, AppNet app, string verb, string remote, string site, bool learning)
        {
            AppNet earlier;
            var others = apps.Values.Where(x => x != app).ToList();
            // The rules as they are right now (Classify reads them only for a path with a version folder): you may
            // have blocked a version moments ago, and once this one has connections it isn't looked at again,
            // whether it was found an update or (while learning) let be.
            var kind = Classify(others, app, () => BlockedRules(true), out earlier);
            string path = app.Path;
            if (kind == PathKind.Update) { Log.Info(app.Name + " updated itself: now connecting from " + path + " (was " + earlier.Path + ")"); return; }
            if (kind != PathKind.BlockedUpdate && learning) return;
            // With the rules unreadable it can't say the app was blocked: the usual notice, with its block button.
            bool returned = kind == PathKind.BlockedUpdate && rulesCache != null;
            var a = returned
                ? AlertStore.New(Sev.Warning, app.Name + " is online again in another version",
                    "You chose to keep " + app.Name + " offline, but that firewall rule covers the version at " + earlier.Path
                    + ". This version (" + (app.Signer ?? "unsigned") + ")" + verb + remote + (site == null ? "" : " (likely " + site + ")") + ".\n" + path,
                    "firstnet:" + path).With("path", path)
                : AlertStore.New(Sev.Notice, "First TCP activity seen for " + app.Name,
                    app.Name + " (" + (app.Signer ?? "unsigned") + ")" + verb + remote
                    + (site == null ? "" : " (likely " + site + ")") + ".\n" + path, "firstnet:" + path).With("path", path);
            if (File.Exists(path)) a.Act("block", "Keep it offline", true);
            AlertStore.Raise(a);
        }

        // A sighting the worker has checked: its results go onto the app's record, then it's decided. The
        // connections seen while it waited ('waiting' counts them) are added only now (see Run).
        static void DecideSighting(Dictionary<string, AppNet> apps, Dictionary<string, int> waiting, Sighting s, bool learning)
        {
            string path = s.Probe.Path;
            int seen;
            waiting.TryGetValue(path, out seen);
            waiting.Remove(path);
            AppNet app;
            if (!apps.TryGetValue(path, out app)) return;
            app.Signer = s.Probe.Signer;
            app.SignerId = s.Probe.SignerId;
            app.Verified = s.Probe.Verified;
            app.DriverVer = s.Probe.DriverVer;
            Decide(apps, app, s.Verb, s.Remote, s.Site, learning);
            app.Connections += Math.Max(1, seen);
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
                // First sightings from version folders are checked on the worker; 'waiting' holds their paths until
                // they're decided, with the connections seen meanwhile.
                var sightings = new SightingWorker(Identify, 32);
                var waiting = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                while (DateTime.UtcNow < until)
                {
                    Thread.Sleep(2000);
                    var now = DateTime.UtcNow;
                    bool learning = now < Clock.Parse(meta.LearningUntil);
                    try
                    {
                        Sighting checkedOne;
                        while (sightings.TryTake(out checkedOne)) DecideSighting(apps, waiting, checkedOne, learning);
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
                            bool known = apps.TryGetValue(path, out app);
                            // First public TCP for this path: also when only blocked DNS lookups were recorded
                            // for it so far (those records have no connections and weren't checked).
                            if ((!known || app.Connections == 0) && !waiting.ContainsKey(path))
                            {
                                if (!known) app = new AppNet { Path = path, Name = System.IO.Path.GetFileNameWithoutExtension(path), FirstSeen = Clock.NowIso() };
                                apps[path] = app;
                                newToday++;
                                string verb = c.State == NetTables.SynSent ? " tried to connect to " : " was observed connecting to ";
                                // A program in a version folder goes to the worker (its folder tree is checked); anything
                                // else, or when the worker's queue is full, is checked and decided right here.
                                var sighting = new Sighting { Probe = new AppNet { Path = path, Name = app.Name }, Remote = remote, Site = site, Verb = verb };
                                if (Versioned.HasVersionFolder(path) && File.Exists(path) && sightings.TryAdd(sighting)) waiting[path] = 0;
                                else
                                {
                                    Identify(app);
                                    Decide(apps, app, verb, remote, site, learning);
                                }
                            }
                            app.LastSeen = Clock.NowIso();
                            // While its check is pending, connections are counted aside (in memory only), so if the engine
                            // stops meanwhile the next start meets the program as a first sighting again; DecideSighting
                            // adds them all.
                            int pendingSeen;
                            if (waiting.TryGetValue(path, out pendingSeen)) waiting[path] = pendingSeen + 1;
                            else app.Connections++;
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
                // Stopping: let queued checks finish, and decide them.
                sightings.Finish(TimeSpan.FromSeconds(10));
                Sighting lastOne;
                while (sightings.TryTake(out lastOne))
                {
                    try { DecideSighting(apps, waiting, lastOne, DateTime.UtcNow < Clock.Parse(meta.LearningUntil)); }
                    catch (Exception e) { Log.Error("deciding " + lastOne.Probe.Path, e); }
                }
                J.Save(AppsFile, apps);
                return 0;
            }
        }
    }
}
