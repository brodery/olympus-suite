// Aegis engine: the DNS server. Listens on 127.0.0.1:53 and [::1]:53 (UDP + TCP),
// blocks names on the lists, forwards the rest (Quad9 by default, local names to the
// router), caches answers, refreshes the blocklists and logs what it blocks.
// Runs in the background as a scheduled task (AegisEngine.exe); has no window.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Aegis
{
    interface IUpstream
    {
        byte[] Ask(Query q, bool tcp);
        double AverageMs { get; }
    }

    sealed class UpstreamException : Exception
    {
        public UpstreamException(string message) : base(message) { }
    }

    static class Clock
    {
        static readonly Stopwatch Sw = Stopwatch.StartNew();
        public static double Seconds { get { return Sw.Elapsed.TotalSeconds; } }
    }

    static class Net
    {
        // Reads exactly n bytes; null at end of stream or once the deadline passes, however slowly
        // the bytes trickle in.
        public static byte[] ReadExact(Socket s, int n, DateTime deadlineUtc)
        {
            var b = new byte[n];
            int got = 0;
            while (got < n)
            {
                int left = (int)(deadlineUtc - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) return null;
                s.ReceiveTimeout = left;
                int r;
                try { r = s.Receive(b, got, n - got, SocketFlags.None); }
                catch (SocketException e)
                {
                    if (e.SocketErrorCode == SocketError.TimedOut) return null;
                    throw;
                }
                if (r <= 0) return null;
                got += r;
            }
            return b;
        }
    }

    // Sends a query to a list of servers. UDP races them with staggered starts (the next server joins
    // every 400 ms, or at once when one fails); TCP tries them one after another. A SERVFAIL or REFUSED
    // from one server is only used if no other server does better before the deadline.
    sealed class Upstream : IUpstream
    {
        const int StaggerMs = 400;
        [ThreadStatic] static byte[] buffer;
        readonly IPAddress[] servers;
        readonly int port, timeoutMs;
        readonly object gate = new object();
        readonly double[] lastFail;
        long okCount;
        double okMs;

        public Upstream(string[] addresses, int timeoutMs) : this(addresses, timeoutMs, 53) { }

        public Upstream(string[] addresses, int timeoutMs, int port)
        {
            servers = addresses.Select(IPAddress.Parse).ToArray();
            lastFail = Enumerable.Repeat(-1e9, servers.Length).ToArray();
            this.timeoutMs = timeoutMs;
            this.port = port;
        }

        public double AverageMs { get { lock (gate) return okCount == 0 ? 0 : okMs / okCount; } }

        List<int> Order()
        {
            double now = Clock.Seconds;
            lock (gate)
            {
                // servers that failed in the last minute go last; OrderBy is stable, so the configured order stays
                return Enumerable.Range(0, servers.Length).OrderBy(i => now - lastFail[i] < 60 ? 1 : 0).ToList();
            }
        }

        void Ok(double ms) { lock (gate) { okCount++; okMs += ms; } }
        void Fail(int i) { lock (gate) lastFail[i] = Clock.Seconds; }

        static bool Retryable(byte[] resp)
        {
            int rcode = resp[3] & 0xF;
            return rcode == Dns.SERVFAIL || rcode == Dns.REFUSED;
        }

        // A reply worth taking as soon as it arrives: well-formed, with its question. Anything else (a
        // bare error, a malformed packet) is only used if no other server does better.
        static bool Usable(byte[] resp) { return Dns.U16(resp, 4) == 1 && Msg.Validate(resp); }

        public byte[] Ask(Query q, bool tcp)
        {
            if (servers.Length == 0) throw new UpstreamException("no upstream servers");
            var sent = (byte[])q.Raw.Clone();
            Dns.W16(sent, 0, Rand.Next16());       // our own random ID, so forged replies are hard to slip in
            byte[] resp = tcp ? AskTcp(sent, q) : AskUdp(sent, q);
            Dns.W16(resp, 0, q.Id);
            return resp;
        }

        byte[] AskUdp(byte[] sent, Query q)
        {
            var order = Order();
            var sockets = new List<Socket>();
            var who = new Dictionary<Socket, int>();
            var sentAt = new Dictionary<Socket, double>();
            var sw = Stopwatch.StartNew();
            double nextLaunch = 0;
            byte[] buf = buffer ?? (buffer = new byte[65535]);
            byte[] weak = null;        // a SERVFAIL/REFUSED: the answer only if nobody does better
            try
            {
                while (true)
                {
                    double now = sw.Elapsed.TotalMilliseconds;
                    if (order.Count > 0 && (now >= nextLaunch || sockets.Count == 0))
                    {
                        int i = order[0];
                        order.RemoveAt(0);
                        Socket s = null;
                        try
                        {
                            s = new Socket(servers[i].AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                            s.Connect(new IPEndPoint(servers[i], port));
                            s.Send(sent);
                            sockets.Add(s);
                            who[s] = i;
                            sentAt[s] = now;
                            nextLaunch = now + StaggerMs;
                        }
                        catch (SocketException)
                        {
                            Fail(i);
                            if (s != null) s.Close();
                            continue;
                        }
                    }
                    if (sockets.Count == 0)
                    {
                        if (order.Count > 0) continue;
                        if (weak != null) return weak;
                        throw new UpstreamException("no upstream server could be reached");
                    }
                    if (now >= timeoutMs)
                    {
                        if (weak != null) return weak;
                        foreach (var s in sockets) Fail(who[s]);
                        throw new UpstreamException("upstream timeout");
                    }
                    double wait = timeoutMs - now;
                    if (order.Count > 0) wait = Math.Min(wait, Math.Max(0, nextLaunch - now));
                    var ready = new List<Socket>(sockets);
                    Socket.Select(ready, null, null, (int)(Math.Max(1, wait) * 1000));
                    foreach (var s in ready)
                    {
                        int n;
                        try { n = s.Receive(buf); }
                        catch (SocketException)
                        {
                            Fail(who[s]);          // e.g. ICMP "port unreachable": drop it and start the next one now
                            sockets.Remove(s);
                            s.Close();
                            nextLaunch = 0;
                            continue;
                        }
                        var resp = new byte[n];
                        Buffer.BlockCopy(buf, 0, resp, 0, n);
                        if (!Msg.Matches(resp, sent, q.QEnd)) continue;
                        if (Retryable(resp) || !Usable(resp))
                        {
                            if (weak == null) weak = resp;
                            sockets.Remove(s);
                            s.Close();
                            nextLaunch = 0;
                            continue;
                        }
                        Ok(sw.Elapsed.TotalMilliseconds - sentAt[s]);
                        return resp;
                    }
                }
            }
            finally
            {
                foreach (var s in sockets) s.Close();
            }
        }

        byte[] AskTcp(byte[] sent, Query q)
        {
            string last = "no servers";
            byte[] weak = null;
            foreach (int i in Order())
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    using (var s = new Socket(servers[i].AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                    {
                        var ar = s.BeginConnect(new IPEndPoint(servers[i], port), null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) throw new TimeoutException("connect timeout");
                        s.EndConnect(ar);
                        s.SendTimeout = timeoutMs;
                        var framed = new byte[sent.Length + 2];
                        Dns.W16(framed, 0, sent.Length);
                        Buffer.BlockCopy(sent, 0, framed, 2, sent.Length);
                        s.Send(framed);
                        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                        byte[] len = Net.ReadExact(s, 2, deadline);
                        byte[] resp = len == null ? null : Net.ReadExact(s, Dns.U16(len, 0), deadline);
                        if (resp != null && Msg.Matches(resp, sent, q.QEnd))
                        {
                            if (!Retryable(resp) && Usable(resp))
                            {
                                Ok(sw.Elapsed.TotalMilliseconds);
                                return resp;
                            }
                            if (weak == null) weak = resp;
                            continue;
                        }
                        last = resp == null ? "no TCP reply" : "bad TCP reply";
                    }
                }
                catch (Exception e) { last = e.Message; }
                Fail(i);
            }
            if (weak != null) return weak;
            throw new UpstreamException("TCP: " + last);
        }
    }

    // Upstream replies by question, least recently used dropped first.
    sealed class Cache
    {
        sealed class Entry
        {
            public byte[] Msg;
            public double Stored, Expires;
            public LinkedListNode<string> Node;
        }

        readonly Dictionary<string, Entry> map = new Dictionary<string, Entry>(StringComparer.Ordinal);
        readonly LinkedList<string> lru = new LinkedList<string>();
        readonly object gate = new object();
        public volatile int Capacity;

        public Cache(int capacity) { Capacity = capacity; }

        public int Count { get { lock (gate) return map.Count; } }

        public byte[] Get(string key, out int age)
        {
            int remaining;
            return Get(key, out age, out remaining);
        }

        // age = seconds since stored; remaining = seconds left before the entry expires.
        public byte[] Get(string key, out int age, out int remaining)
        {
            age = 0;
            remaining = 0;
            if (Capacity <= 0) return null;
            double now = Clock.Seconds;
            lock (gate)
            {
                Entry e;
                if (!map.TryGetValue(key, out e)) return null;
                if (now >= e.Expires)
                {
                    map.Remove(key);
                    lru.Remove(e.Node);
                    return null;
                }
                lru.Remove(e.Node);
                lru.AddLast(e.Node);
                age = (int)(now - e.Stored);
                remaining = (int)Math.Ceiling(e.Expires - now);
                return e.Msg;
            }
        }

        public void Put(string key, byte[] msg, int ttl)
        {
            if (Capacity <= 0 || ttl <= 0) return;
            double now = Clock.Seconds;
            lock (gate)
            {
                Entry e;
                if (map.TryGetValue(key, out e)) lru.Remove(e.Node);
                else
                {
                    e = new Entry { Node = new LinkedListNode<string>(key) };
                    map[key] = e;
                }
                e.Msg = msg;
                e.Stored = now;
                e.Expires = now + ttl;
                lru.AddLast(e.Node);
                while (map.Count > Capacity)
                {
                    var first = lru.First;
                    lru.RemoveFirst();
                    map.Remove(first.Value);
                }
            }
        }

        public void Clear()
        {
            lock (gate)
            {
                map.Clear();
                lru.Clear();
            }
        }
    }

    sealed class Counters
    {
        readonly object gate = new object();
        string day = Today();
        long dayQueries, dayBlocked;
        long queries, blocked, cacheHits, forwarded, local, fallback, servfail, bad;
        readonly Dictionary<string, long> top = new Dictionary<string, long>(StringComparer.Ordinal);

        static string Today() { return DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture); }

        void RollDay()
        {
            string d = Today();
            if (d == day) return;
            day = d;
            dayQueries = 0;
            dayBlocked = 0;
        }

        public void Count(string how)
        {
            if (how == "control") return;     // the tray's own polling isn't a lookup
            lock (gate)
            {
                RollDay();
                queries++;
                dayQueries++;
                switch (how)
                {
                    case "blocked": blocked++; dayBlocked++; break;
                    case "cache": cacheHits++; break;
                    case "upstream": forwarded++; break;
                    case "local": local++; break;
                    case "fallback": fallback++; break;
                    case "servfail": servfail++; break;
                    case "bad": bad++; break;
                }
            }
        }

        public void Blocked(string rule)
        {
            lock (gate)
            {
                long n;
                top.TryGetValue(rule, out n);
                top[rule] = n + 1;
                if (top.Count > 5000)
                {
                    var keep = top.OrderByDescending(kv => kv.Value).Take(1000).ToList();
                    top.Clear();
                    foreach (var kv in keep) top[kv.Key] = kv.Value;
                }
            }
        }

        public List<KeyValuePair<string, long>> Top(int n)
        {
            lock (gate) return top.OrderByDescending(kv => kv.Value).Take(n).ToList();
        }

        public string Fields()
        {
            lock (gate)
            {
                RollDay();
                return string.Format(CultureInfo.InvariantCulture,
                    "day={0};q={1};b={2};tq={3};tb={4};hits={5};fwd={6};lan={7};fb={8};fail={9};bad={10}",
                    day, dayQueries, dayBlocked, queries, blocked, cacheHits, forwarded, local, fallback, servfail, bad);
            }
        }

        public void Save()
        {
            string text;
            lock (gate)
            {
                RollDay();
                text = "day=" + day + ";q=" + dayQueries + ";b=" + dayBlocked;
            }
            try { File.WriteAllText(App.CountsPath, text); } catch { }
        }

        public void LoadToday()
        {
            try
            {
                if (!File.Exists(App.CountsPath)) return;
                var d = Kv.Parse(File.ReadAllText(App.CountsPath));
                lock (gate)
                {
                    if (Kv.Get(d, "day", "") != day) return;
                    dayQueries = Kv.Long(d, "q");
                    dayBlocked = Kv.Long(d, "b");
                }
            }
            catch { }
        }
    }

    // Keeps the blocked log small without losing count: each name/type gets at most one line a minute,
    // and every line says how many blocks it stands for. Repeats held back during the minute are written
    // as one line once the minute is up.
    sealed class BlockTally
    {
        public sealed class Owed
        {
            public string Name, Type, Rule, Source;
            public DateTime LastHit;
            public int Count;
        }

        sealed class Slot
        {
            public string Name, Type, Rule, Source;
            public DateTime LastHit;
            public long LastWritten;
            public int Pending;
        }

        readonly Dictionary<string, Slot> slots = new Dictionary<string, Slot>(StringComparer.Ordinal);
        readonly object gate = new object();
        readonly long window;

        public BlockTally(TimeSpan window) { this.window = window.Ticks; }

        // One more block. Returns how many blocks to write in a line now (0 = held back for later).
        public int Hit(string name, string type, string rule, string source, DateTime nowLocal, long nowTicks)
        {
            lock (gate)
            {
                string key = name + "\t" + type;
                Slot s;
                if (!slots.TryGetValue(key, out s))
                {
                    if (slots.Count >= 20000) Prune(nowTicks);
                    slots[key] = s = new Slot { Name = name, Type = type };
                }
                s.Pending++;
                s.LastHit = nowLocal;
                s.Rule = rule;
                s.Source = source;
                if (nowTicks - s.LastWritten < window) return 0;
                int n = s.Pending;
                s.Pending = 0;
                s.LastWritten = nowTicks;
                return n;
            }
        }

        // Held-back blocks whose minute is up (all of them when everything is true, before exiting).
        public List<Owed> Take(long nowTicks, bool everything)
        {
            var list = new List<Owed>();
            lock (gate)
            {
                foreach (var s in slots.Values)
                {
                    if (s.Pending == 0 || (!everything && nowTicks - s.LastWritten < window)) continue;
                    list.Add(new Owed { Name = s.Name, Type = s.Type, Rule = s.Rule, Source = s.Source, LastHit = s.LastHit, Count = s.Pending });
                    s.Pending = 0;
                    s.LastWritten = nowTicks;
                }
            }
            return list;
        }

        void Prune(long nowTicks)   // caller holds gate: forget quiet names with nothing owed
        {
            foreach (var key in slots.Where(kv => kv.Value.Pending == 0 && nowTicks - kv.Value.LastWritten > 10 * window).Select(kv => kv.Key).ToList())
                slots.Remove(key);
            if (slots.Count < 20000) return;
            foreach (var key in slots.Where(kv => kv.Value.Pending == 0).Select(kv => kv.Key).ToList()) slots.Remove(key);
        }
    }

    // Appends lines to logs\<prefix>-YYYY-MM-DD.log from a background thread (the file of the line's day).
    sealed class DailyLog
    {
        readonly string prefix;
        readonly BlockingCollection<KeyValuePair<string, string>> lines = new BlockingCollection<KeyValuePair<string, string>>(100000);

        public DailyLog(string prefix)
        {
            this.prefix = prefix;
            new Thread(Run) { IsBackground = true, Name = "log " + prefix }.Start();
        }

        public void Write(string line) { Write(line, DateTime.Now); }

        public void Write(string line, DateTime when)
        {
            lines.TryAdd(new KeyValuePair<string, string>(when.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), line));
        }

        // Gives the writer a moment to save what's queued (just before the engine exits).
        public void Drain(int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            while (lines.Count > 0 && sw.ElapsedMilliseconds < timeoutMs) Thread.Sleep(20);
            Thread.Sleep(300);
        }

        void Run()
        {
            var batch = new List<KeyValuePair<string, string>>();
            while (true)
            {
                try
                {
                    batch.Clear();
                    batch.Add(lines.Take());
                    KeyValuePair<string, string> more;
                    while (batch.Count < 5000 && lines.TryTake(out more)) batch.Add(more);
                    foreach (var day in batch.GroupBy(kv => kv.Key))
                    {
                        string path = Path.Combine(App.LogDir, prefix + "-" + day.Key + ".log");
                        using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                        using (var w = new StreamWriter(fs, new UTF8Encoding(false)))
                            foreach (var kv in day) w.WriteLine(kv.Value);
                    }
                    Thread.Sleep(250);
                }
                catch (Exception) { Thread.Sleep(1000); }
            }
        }
    }

    sealed class Listener
    {
        const int SIO_UDP_CONNRESET = -1744830452;   // 0x9800000C
        public readonly string Kind;
        public readonly IPAddress Addr;
        public readonly object SendGate = new object();
        public volatile Socket Sock;
        public Thread Thread;
        public int Failures;
        public DateTime NextLogUtc;

        public Listener(string kind, IPAddress addr) { Kind = kind; Addr = addr; }

        public string Endpoint(int port)
        {
            return Addr.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + Addr + "]:" + port : Addr + ":" + port;
        }

        public void Open(int port)
        {
            bool udp = Kind == "udp";
            var s = new Socket(Addr.AddressFamily, udp ? SocketType.Dgram : SocketType.Stream, udp ? ProtocolType.Udp : ProtocolType.Tcp);
            try
            {
                s.ExclusiveAddressUse = true;
                // Without this, Windows fails the next receive after a client goes away (ICMP port unreachable).
                if (udp) s.IOControl(SIO_UDP_CONNRESET, new byte[4], null);
                s.Bind(new IPEndPoint(Addr, port));
                if (!udp) s.Listen(64);
            }
            catch
            {
                s.Close();
                throw;
            }
            Sock = s;
        }

        public void Close()
        {
            try { if (Sock != null) Sock.Close(); } catch { }
            Sock = null;
        }
    }

    sealed class Engine
    {
        const int MaxPending = 256;     // UDP lookups waiting on the network at once; more get SERVFAIL
        const int StaleMs = 3000;       // a queued lookup this old is dropped: the client has asked again by now

        Config cfg;
        volatile Rules rules = Rules.Empty;
        readonly object rulesGate = new object();
        readonly Dictionary<string, HashedSet> listSets = new Dictionary<string, HashedSet>(StringComparer.Ordinal);
        readonly Dictionary<string, DateTime> listMtimes = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        volatile IUpstream upstream, router;
        volatile string routerAddr;
        volatile HashSet<string> localDomains = new HashSet<string>(StringComparer.Ordinal);
        readonly Cache cache;
        readonly Counters counters = new Counters();
        readonly DailyLog blockedLog;
        readonly BlockTally tally = new BlockTally(TimeSpan.FromMinutes(1));
        int restarting;
        DailyLog queryLog;
        volatile bool logAll, networkChanged;
        long pausedUntilTicks, lastFallbackTicks, oldestListUnix, domainTotal;
        readonly AutoResetEvent updateNow = new AutoResetEvent(false);
        readonly List<Listener> listeners = new List<Listener>();
        int tcpActive, pending;
        int routeGen;                    // bumped when the network or routing settings change; stale lookups aren't cached
        bool iniRetry;
        DateTime nextListRetry = DateTime.MinValue;
        readonly DateTime started = DateTime.UtcNow;
        readonly int pid = Process.GetCurrentProcess().Id;
        volatile string lastRefreshResult = "never";
        volatile int allowCount, blockCount, listCount;
        SmallSet userAllow = new SmallSet(new string[0]), userBlock = new SmallSet(new string[0]);
        readonly SmallSet protectedNames = new SmallSet(Essential.Allow);
        readonly Dictionary<string, DateTime> watched = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        static readonly DateTime RetrySoon = new DateTime(1, 1, 1, 0, 0, 1, DateTimeKind.Utc);  // never a real file time
        DateTime iniLoaded = DateTime.MinValue;
        readonly bool writeFiles;
        bool upstreamsFixed;

        public Engine(Config cfg, bool writeFiles)
        {
            this.writeFiles = writeFiles;
            cache = new Cache(cfg.CacheEntries);
            ApplyConfig(cfg);
            if (writeFiles) blockedLog = new DailyLog("blocked");
        }

        // ---- hooks for the tests
        public void UseUpstreams(IUpstream up, IUpstream lan, string lanAddress)
        {
            upstreamsFixed = true;
            upstream = up;
            router = lan;
            routerAddr = lanAddress;
        }
        public void UseRules(Rules r) { rules = r; }
        public void PauseUntil(DateTime utc) { Interlocked.Exchange(ref pausedUntilTicks, utc.Ticks); }
        public bool IsPaused { get { return DateTime.UtcNow.Ticks < Interlocked.Read(ref pausedUntilTicks); } }

        void ApplyConfig(Config c)
        {
            cfg = c;
            cache.Capacity = c.CacheEntries;
            localDomains = LocalDomainsFor(c);
            Interlocked.Increment(ref routeGen);
            if (!upstreamsFixed)
            {
                // never forward to this PC itself: the engine would ask itself in a loop
                string[] ups = c.Upstreams.Where(u => !IPAddress.IsLoopback(IPAddress.Parse(u))).ToArray();
                if (ups.Length < c.Upstreams.Length) Log.Warn("upstreams: ignoring this PC's own address");
                if (ups.Length == 0) ups = new Config().Upstreams;
                upstream = new Upstream(ups, c.UpstreamTimeoutMs);
                SetRouter(FindRouter(c));
            }
            logAll = c.LogAllQueries && writeFiles;
            if (logAll && queryLog == null) queryLog = new DailyLog("queries");
        }

        void SetRouter(string address)
        {
            routerAddr = address;
            router = address == null ? null : new Upstream(new[] { address }, cfg.UpstreamTimeoutMs);
            Interlocked.Increment(ref routeGen);
        }

        // your local_domains plus the DNS suffixes the connected networks hand out right now
        static HashSet<string> LocalDomainsFor(Config c)
        {
            return new HashSet<string>(c.LocalDomains.Concat(NetInfo.DnsSuffixes()), StringComparer.Ordinal);
        }

        static string FindRouter(Config c)
        {
            if (c.Router == "none") return null;
            IPAddress ip;
            if (c.Router != "auto") return IPAddress.TryParse(c.Router, out ip) && !IPAddress.IsLoopback(ip) ? ip.ToString() : null;
            string saved = null;
            try
            {
                if (File.Exists(App.InstallPath))
                {
                    var m = Regex.Match(File.ReadAllText(App.InstallPath), "\"router\"\\s*:\\s*\"([0-9A-Fa-f.:]+)\"");
                    if (m.Success && IPAddress.TryParse(m.Groups[1].Value, out ip) && !IPAddress.IsLoopback(ip)) saved = ip.ToString();
                }
            }
            catch (Exception) { }
            // the DNS server you had before installing, while it's on a network this PC is connected to;
            // otherwise this network's router
            if (saved != null && NetSubnet.IsConnected(IPAddress.Parse(saved))) return saved;
            return NetInfo.DefaultGatewayV4() ?? saved;
        }

        // ---- start-up and the listener threads

        public void Start()
        {
            App.EnsureDirs();
            UserLists.EnsureFiles();
            counters.LoadToday();
            // copies set aside by an update (renamed while they were running) can go now
            foreach (var old in Directory.GetFiles(App.Dir, "*.old.exe"))
            {
                try { File.Delete(old); } catch { }
            }
            // Your lists and the blocklists already on disk are loaded before anything is answered, so
            // there's no unfiltered moment at start-up. Fresh downloads happen in the background later.
            ReloadUserState(false);
            LoadListsFromDisk(false);
            BindAll();
            foreach (var l in listeners) if (l.Sock != null) StartListener(l);
            NetworkChange.NetworkAddressChanged += (s, e) => networkChanged = true;
            new Thread(MaintenanceLoop) { IsBackground = true, Name = "maintenance" }.Start();
            Log.Info(string.Format("Aegis engine {0} started (pid {1}); listening on {2}; upstream {3}; router {4}",
                App.Version, pid, string.Join(", ", listeners.Where(l => l.Sock != null).Select(l => l.Kind + " " + l.Endpoint(cfg.Port))),
                string.Join(", ", cfg.Upstreams), routerAddr ?? "none"));
        }

        void BindAll()
        {
            foreach (var a in cfg.Listen)
            {
                IPAddress ip;
                if (!IPAddress.TryParse(a, out ip)) { Log.Warn("listen: not an IP address: " + a); continue; }
                foreach (var kind in new[] { "udp", "tcp" })
                {
                    var l = new Listener(kind, ip);
                    listeners.Add(l);          // kept even if it fails now: the supervisor keeps retrying it
                    try { l.Open(cfg.Port); }
                    catch (SocketException e)
                    {
                        l.Failures = 1;
                        l.NextLogUtc = DateTime.UtcNow.AddMinutes(5);
                        Log.Warn("can't listen on " + kind + " " + l.Endpoint(cfg.Port) + " yet (" + e.Message + "); will keep trying");
                    }
                }
            }
            if (!listeners.Any(l => l.Kind == "udp" && l.Sock != null))
            {
                foreach (var l in listeners) l.Close();
                listeners.Clear();
                throw new InvalidOperationException("can't listen for DNS on port " + cfg.Port + "; is another copy already running?");
            }
        }

        void StartListener(Listener l)
        {
            var t = new Thread(() => { if (l.Kind == "udp") UdpLoop(l); else TcpLoop(l); })
            {
                IsBackground = true,
                Name = l.Kind + " " + l.Addr
            };
            l.Thread = t;
            t.Start();
        }

        // Main thread: (re)open any listener that isn't running, every 2 seconds.
        public void Supervise()
        {
            while (true)
            {
                Thread.Sleep(2000);
                foreach (var l in listeners)
                {
                    if (l.Thread != null && l.Thread.IsAlive) continue;
                    if (l.Thread != null)
                    {
                        Log.Warn(l.Kind + " listener on " + l.Endpoint(cfg.Port) + " stopped; opening it again");
                        l.Thread = null;
                    }
                    try
                    {
                        l.Close();
                        l.Open(cfg.Port);
                        StartListener(l);
                        if (l.Failures > 0) Log.Info(l.Kind + " " + l.Endpoint(cfg.Port) + " is listening now");
                        l.Failures = 0;
                    }
                    catch (Exception e)
                    {
                        l.Failures++;
                        if (DateTime.UtcNow >= l.NextLogUtc)
                        {
                            Log.Warn("still can't listen on " + l.Kind + " " + l.Endpoint(cfg.Port) + ": " + e.Message);
                            l.NextLogUtc = DateTime.UtcNow.AddMinutes(5);
                        }
                    }
                }
            }
        }

        void UdpLoop(Listener l)
        {
            var buf = new byte[65535];
            int errors = 0;
            while (true)
            {
                try
                {
                    EndPoint remote = l.Addr.AddressFamily == AddressFamily.InterNetworkV6
                        ? (EndPoint)new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
                    int n = l.Sock.ReceiveFrom(buf, ref remote);
                    errors = 0;
                    var data = new byte[n];
                    Buffer.BlockCopy(buf, 0, data, 0, n);
                    var client = (IPEndPoint)remote;
                    bool loopback = IPAddress.IsLoopback(client.Address);

                    // Anything that needs no network (our status name, blocked names, cache hits) is answered
                    // right here, so it never waits behind slow upstream lookups.
                    byte[] resp;
                    Plan plan;
                    if (Local(data, false, loopback, out resp, out plan))
                    {
                        if (resp != null) Send(l, resp, client);
                        continue;
                    }
                    if (Interlocked.Increment(ref pending) > MaxPending)
                    {
                        Interlocked.Decrement(ref pending);
                        counters.Count("servfail");
                        Send(l, Reply.Error(plan.Q, Dns.SERVFAIL), client);
                        continue;
                    }
                    long queued = Stopwatch.GetTimestamp();
                    ThreadPool.QueueUserWorkItem(_ => UdpAnswer(l, data, client, loopback, queued));
                }
                catch (SocketException e)
                {
                    if (e.SocketErrorCode == SocketError.ConnectionReset) continue;
                    if (++errors > 100) { Log.Error("UDP listener keeps failing: " + e.Message); return; }
                    Thread.Sleep(50);
                }
                catch (ObjectDisposedException) { return; }
                catch (NullReferenceException) { return; }      // socket closed for a reopen
                catch (Exception e)
                {
                    Log.Error("UDP listener: " + e);
                    Thread.Sleep(200);
                }
            }
        }

        void UdpAnswer(Listener l, byte[] data, IPEndPoint client, bool loopback, long queued)
        {
            try
            {
                if ((Stopwatch.GetTimestamp() - queued) * 1000 / Stopwatch.Frequency > StaleMs) return;
                byte[] resp = Answer(data, false, loopback);
                if (resp != null) Send(l, resp, client);
            }
            catch (Exception e) { Log.Warn("UDP reply failed: " + e.Message); }
            finally { Interlocked.Decrement(ref pending); }
        }

        static void Send(Listener l, byte[] resp, IPEndPoint client)
        {
            try
            {
                var s = l.Sock;
                if (s == null) return;
                lock (l.SendGate) s.SendTo(resp, client);
            }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
        }

        void TcpLoop(Listener l)
        {
            int errors = 0;
            while (true)
            {
                Socket c;
                try
                {
                    c = l.Sock.Accept();
                    errors = 0;
                }
                catch (ObjectDisposedException) { return; }
                catch (NullReferenceException) { return; }
                catch (Exception e)
                {
                    if (++errors > 100) { Log.Error("TCP listener keeps failing: " + e.Message); return; }
                    Thread.Sleep(50);
                    continue;
                }
                if (Interlocked.Increment(ref tcpActive) > 32)
                {
                    Interlocked.Decrement(ref tcpActive);
                    try { c.Close(); } catch { }
                    continue;
                }
                try { new Thread(() => TcpSession(c)) { IsBackground = true, Name = "tcp client" }.Start(); }
                catch (Exception e)
                {
                    Interlocked.Decrement(ref tcpActive);
                    try { c.Close(); } catch { }
                    Log.Warn("couldn't start a TCP worker: " + e.Message);
                }
            }
        }

        // One TCP client: up to 100 queries, 10 s for each, 30 s for the whole session.
        void TcpSession(Socket c)
        {
            try
            {
                c.SendTimeout = 10000;
                bool loopback = IPAddress.IsLoopback(((IPEndPoint)c.RemoteEndPoint).Address);
                DateTime sessionEnd = DateTime.UtcNow.AddSeconds(30);
                for (int i = 0; i < 100; i++)
                {
                    DateTime frameEnd = DateTime.UtcNow.AddSeconds(10);
                    if (frameEnd > sessionEnd) frameEnd = sessionEnd;
                    byte[] len = Net.ReadExact(c, 2, frameEnd);
                    if (len == null) return;
                    byte[] data = Net.ReadExact(c, Dns.U16(len, 0), frameEnd);
                    if (data == null) return;
                    byte[] resp = Answer(data, true, loopback);
                    if (resp == null) return;
                    var framed = new byte[resp.Length + 2];
                    Dns.W16(framed, 0, resp.Length);
                    Buffer.BlockCopy(resp, 0, framed, 2, resp.Length);
                    c.Send(framed);
                }
            }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            catch (Exception e) { Log.Warn("TCP client: " + e.Message); }
            finally
            {
                try { c.Close(); } catch { }
                Interlocked.Decrement(ref tcpActive);
            }
        }

        // ---- answering

        // What Local() worked out about a query that has to go to the network.
        sealed class Plan
        {
            public Query Q;
            public Rules R;
            public Verdict V;
            public bool Filtering, IsLocal;
            public IUpstream Lan;
            public string Key;
            public long T0;
            public int Gen;          // routeGen when planned
            public bool Reload;      // the tray's "reload your lists" request: file I/O, so done on a worker
        }

        public byte[] Answer(byte[] raw, bool tcp, bool loopback)
        {
            byte[] resp;
            Plan plan;
            if (Local(raw, tcp, loopback, out resp, out plan)) return resp;
            string how;
            try
            {
                if (plan.Reload)
                {
                    ReloadUserState(false);
                    resp = Reply.Txt(plan.Q, "ok");
                    how = "control";
                }
                else resp = Forward(plan, tcp, out how);
            }
            catch (Exception e)
            {
                Log.Error("answering " + Names.Safe(plan.Q.Name) + ": " + e);
                resp = Reply.Error(plan.Q, Dns.SERVFAIL);
                how = "error";
            }
            Finish(plan.Q, ref resp, tcp, how, plan.T0);
            return resp;
        }

        // Everything that needs no network: malformed messages, our own names, blocked names and cache
        // hits. Returns true when it has the reply (null = send nothing); otherwise false and a plan.
        bool Local(byte[] raw, bool tcp, bool loopback, out byte[] resp, out Plan plan)
        {
            resp = null;
            plan = null;
            long t0 = Stopwatch.GetTimestamp();
            if (raw.Length < 12) return true;
            int flags = Dns.U16(raw, 2);
            if ((flags & Dns.QR) != 0) return true;
            if ((flags & Dns.OPCODE) != 0)
            {
                counters.Count("bad");
                resp = Reply.HeaderOnly(raw, Dns.NOTIMP);
                return true;
            }
            Query q;
            try { q = Query.Parse(raw); }
            catch (DnsFormatException)
            {
                counters.Count("bad");
                resp = Reply.HeaderOnly(raw, Dns.FORMERR);
                return true;
            }
            string how;
            try
            {
                if (q.Edns && q.EdnsVersion != 0)
                {
                    how = "bad";
                    resp = Reply.BadVersion(q);
                }
                else resp = LocalAnswer(q, tcp, loopback, out how, out plan);
            }
            catch (Exception e)
            {
                Log.Error("answering " + Names.Safe(q.Name) + ": " + e);
                resp = Reply.Error(q, Dns.SERVFAIL);
                how = "error";
                plan = null;
            }
            if (resp == null)
            {
                plan.T0 = t0;
                return false;
            }
            Finish(q, ref resp, tcp, how, t0);
            return true;
        }

        byte[] LocalAnswer(Query q, bool tcp, bool loopback, out string how, out Plan plan)
        {
            plan = null;
            string name = q.Name;
            if (name == App.ControlZone || name.EndsWith(App.ControlSuffix, StringComparison.Ordinal))
            {
                if (loopback && q.QType == Dns.TXT && name == "reload" + App.ControlSuffix)
                {
                    how = null;          // re-reading your lists is file I/O: not on the listener thread
                    plan = new Plan { Q = q, Reload = true };
                    return null;
                }
                how = "control";
                return Control(q, loopback);
            }
            if (name == "localhost" || name.EndsWith(".localhost", StringComparison.Ordinal))
            {
                how = "special";
                if (q.QType == Dns.A) return Reply.Build(q, Dns.NOERROR, new[] { new RR(Dns.A, 300, new byte[] { 127, 0, 0, 1 }) }, null, true);
                if (q.QType == Dns.AAAA)
                {
                    var v6 = new byte[16];
                    v6[15] = 1;
                    return Reply.Build(q, Dns.NOERROR, new[] { new RR(Dns.AAAA, 300, v6) }, null, true);
                }
                return Reply.NoData(q, 300);
            }
            if (name == "use-application-dns.net")
            {
                how = "special";          // tells Firefox not to go around this filter with DNS-over-HTTPS
                return Reply.NxDomain(q, 300);
            }

            var r = rules;
            bool filtering = q.QClass == 1 && !IsPaused;
            Verdict v = filtering ? r.Decide(name) : null;
            if (v != null && v.Blocked)
            {
                LogBlock(q, v.Rule, v.Source);
                how = "blocked";
                return Reply.Blocked(q, cfg.BlockTtl);
            }

            var lan = router;
            bool isLocal = lan != null && IsLocalName(name);
            // client-specific EDNS options (cookies...) or extra records (TSIG...) mean the reply isn't shareable
            string key = q.HasEdnsOptions || q.HasExtraRecords ? null : q.CacheKey();
            int gen = Volatile.Read(ref routeGen);
            if (key != null)
            {
                int age, remaining;
                byte[] cached = cache.Get(key, out age, out remaining);
                byte[] hit = cached == null ? null : FromCache(cached, age, remaining, q);
                if (hit != null)
                {
                    byte[] cloaked = CnameCheck(q, hit, r, v, filtering, isLocal);
                    if (cloaked != null)
                    {
                        how = "blocked";
                        return cloaked;
                    }
                    how = "cache";
                    // Too big for UDP: say so (TC) rather than asking upstream again, so the client retries over TCP.
                    return tcp || hit.Length <= q.UdpLimit ? hit : Reply.Truncated(hit, q);
                }
            }
            how = null;
            plan = new Plan { Q = q, R = r, V = v, Filtering = filtering, IsLocal = isLocal, Lan = lan, Key = key, Gen = gen };
            return null;
        }

        byte[] FromCache(byte[] cached, int age, int remaining, Query q)
        {
            try
            {
                byte[] resp = Msg.Aged(cached, age);
                Dns.W16(resp, 0, q.Id);
                Dns.W16(resp, 2, (Dns.U16(resp, 2) & ~(Dns.RD | Dns.CD)) | (q.Flags & (Dns.RD | Dns.CD)));
                Buffer.BlockCopy(q.Raw, 12, resp, 12, q.QEnd - 12);    // the client's own spelling of the name
                // never longer than the cache itself keeps it (a short negative lifetime included), nor max_client_ttl
                int cap = Math.Max(1, remaining);
                if (cfg.MaxClientTtl > 0) cap = Math.Min(cap, cfg.MaxClientTtl);
                Msg.CapTtl(resp, cap);
                return resp;
            }
            catch (DnsFormatException) { return null; }
        }

        byte[] Forward(Plan p, bool tcp, out string how)
        {
            var q = p.Q;
            byte[] resp;
            how = p.IsLocal ? "local" : "upstream";
            try { resp = (p.IsLocal ? p.Lan : upstream).Ask(q, tcp); }
            catch (UpstreamException e)
            {
                // Quad9 can't be reached at all: let the router answer instead (the lists still apply).
                if (p.IsLocal || p.Lan == null || !cfg.RouterFallback)
                {
                    how = "servfail";
                    return Reply.Error(q, Dns.SERVFAIL);
                }
                try { resp = p.Lan.Ask(q, tcp); }
                catch (UpstreamException)
                {
                    how = "servfail";
                    return Reply.Error(q, Dns.SERVFAIL);
                }
                how = "fallback";
                NoteFallback(e.Message);
            }
            if (Dns.U16(resp, 4) == 0) return resp;          // a bare error without the question: pass it on, never cache it
            if (!Msg.Validate(resp))
            {
                how = "servfail";
                return Reply.Error(q, Dns.SERVFAIL);
            }
            // a lookup that started before a network/routing change mustn't refill the cleared cache
            if (p.Key != null && p.Gen == Volatile.Read(ref routeGen))
            {
                int ttl = Msg.CacheTtl(resp, cfg.MaxCacheTtl);
                cache.Put(p.Key, resp, how == "fallback" ? Math.Min(ttl, 60) : ttl);
            }
            byte[] cloaked = CnameCheck(q, resp, p.R, p.V, p.Filtering, p.IsLocal);
            if (cloaked != null)
            {
                how = "blocked";
                return cloaked;
            }
            var outgoing = (byte[])resp.Clone();
            Msg.CapTtl(outgoing, cfg.MaxClientTtl);
            return outgoing;
        }

        // CNAME cloaking: an innocent-looking name that is really an alias of a blocked domain.
        byte[] CnameCheck(Query q, byte[] resp, Rules r, Verdict v, bool filtering, bool isLocal)
        {
            if (!filtering || !cfg.CnameInspection || isLocal || v != null) return null;
            List<string> targets;
            try { targets = Msg.CnameTargets(resp); }
            catch (DnsFormatException) { return null; }
            foreach (var t in targets)
            {
                var tv = r.Decide(t);
                if (tv == null || !tv.Blocked) continue;
                LogBlock(q, tv.Rule, tv.Source + " via CNAME " + t);
                return Reply.Blocked(q, cfg.BlockTtl);
            }
            return null;
        }

        void Finish(Query q, ref byte[] resp, bool tcp, string how, long t0)
        {
            if (!tcp && resp.Length > q.UdpLimit) resp = Reply.Truncated(resp, q);
            counters.Count(how);
            if (logAll && how != "control")
            {
                double ms = (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
                queryLog.Write(DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + "\t" + Names.Safe(q.Name) + "\t"
                    + Dns.TypeName(q.QType) + "\t" + how + "\t" + ms.ToString("0.0", CultureInfo.InvariantCulture));
            }
        }

        void NoteFallback(string why)
        {
            long now = DateTime.UtcNow.Ticks;
            long before = Interlocked.Exchange(ref lastFallbackTicks, now);
            if (now - before > TimeSpan.FromMinutes(10).Ticks)
                Log.Warn("Quad9 isn't answering (" + why + "), so the router is answering for now");
        }

        bool IsLocalName(string name)
        {
            if (name.Length == 0) return false;
            if (name.IndexOf('.') < 0) return true;        // single-label names: printer, router ...
            var local = localDomains;
            string cand = name;
            while (true)
            {
                if (local.Contains(cand)) return true;
                int dot = cand.IndexOf('.');
                if (dot < 0) break;
                cand = cand.Substring(dot + 1);
            }
            return Names.IsPrivateReverse(name);
        }

        void LogBlock(Query q, string rule, string source)
        {
            string safeRule = Names.Safe(rule);
            counters.Blocked(safeRule);
            if (blockedLog == null) return;
            // at most one line a minute per name and type (a program hammering a blocked host can't flood
            // the log), each carrying the number of blocks it stands for
            DateTime now = DateTime.Now;
            string name = Names.Safe(q.Name), type = Dns.TypeName(q.QType), src = Names.Safe(source);
            int n = tally.Hit(name, type, safeRule, src, now, DateTime.UtcNow.Ticks);
            if (n > 0) blockedLog.Write(BlockLine(now, name, type, safeRule, src, n), now);
        }

        static string BlockLine(DateTime when, string name, string type, string rule, string source, int count)
        {
            return when.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + "\t" + name + "\t" + type + "\t" + rule + "\t" + source
                + "\t" + count.ToString(CultureInfo.InvariantCulture);
        }

        // Writes the repeats held back by the once-a-minute rule.
        void FlushTally(bool everything)
        {
            if (blockedLog == null) return;
            foreach (var o in tally.Take(DateTime.UtcNow.Ticks, everything))
                blockedLog.Write(BlockLine(o.LastHit, o.Name, o.Type, o.Rule, o.Source, o.Count), o.LastHit);
        }

        // "restart" control command: save what's pending and exit cleanly, so an update can start the new
        // AegisEngine.exe straight away (the scheduled task's watchdog would also start it within a minute).
        void ExitForRestart()
        {
            try
            {
                Thread.Sleep(200);                     // let the reply go out first
                Log.Info("exiting on request so the updated engine can start");
                FlushTally(true);
                counters.Save();
                if (blockedLog != null) blockedLog.Drain(2000);
            }
            catch { }
            Environment.Exit(0);
        }

        // ---- control names (only answered for this PC): <command>.aegis.invalid TXT

        byte[] Control(Query q, bool loopback)
        {
            if (!loopback) return Reply.NxDomain(q, 60);
            if (q.QType != Dns.TXT) return Reply.NoData(q, 0);
            string name = q.Name;
            string sub = name.Length > App.ControlZone.Length ? name.Substring(0, name.Length - App.ControlSuffix.Length) : "";
            switch (sub)
            {
                case "status": return Reply.Txt(q, StatusText());
                case "lists": return Reply.Txt(q, ListText());
                case "top": return Reply.Txt(q, string.Join(";", counters.Top(10).Select(kv => Kv.Clean(kv.Key) + "=" + kv.Value)));
                case "reload":
                    ReloadUserState(false);
                    return Reply.Txt(q, "ok");
                case "update":
                    updateNow.Set();
                    return Reply.Txt(q, "started");
                case "restart":
                    if (Interlocked.Exchange(ref restarting, 1) == 0) new Thread(ExitForRestart) { Name = "restart" }.Start();
                    return Reply.Txt(q, "restarting");
            }
            if (sub.EndsWith(".check", StringComparison.Ordinal))
            {
                string target = sub.Substring(0, sub.Length - ".check".Length);
                var v = rules.Decide(target);
                string text = v == null ? "verdict=none"
                    : (v.Blocked ? "verdict=block" : "verdict=allow") + ";rule=" + Kv.Clean(Names.Safe(v.Rule)) + ";source=" + Kv.Clean(Names.Safe(v.Source));
                if (IsPaused) text += ";paused=1";
                if (router != null && IsLocalName(target)) text += ";local=1";
                return Reply.Txt(q, text);
            }
            return Reply.NxDomain(q, 60);
        }

        string StatusText()
        {
            var sb = new StringBuilder(320);
            long until = Interlocked.Read(ref pausedUntilTicks);
            bool paused = DateTime.UtcNow.Ticks < until;
            sb.Append("app=").Append(App.Name).Append(";ver=").Append(App.Version);
            sb.Append(";state=").Append(paused ? "paused" : "on");
            if (paused) sb.Append(";until=").Append(App.Unix(new DateTime(until, DateTimeKind.Utc)));
            sb.Append(";up=").Append((long)(DateTime.UtcNow - started).TotalSeconds);
            sb.Append(";pid=").Append(pid);
            sb.Append(';').Append(counters.Fields());
            if (DateTime.UtcNow.Ticks - Interlocked.Read(ref lastFallbackTicks) < TimeSpan.FromMinutes(5).Ticks) sb.Append(";fbrecent=1");
            sb.Append(";lists=").Append(listCount).Append(";domains=").Append(Interlocked.Read(ref domainTotal));
            int missing = Math.Max(0, cfg.Lists.Count - listCount);
            if (missing > 0) sb.Append(";missing=").Append(missing);
            sb.Append(";allow=").Append(allowCount).Append(";block=").Append(blockCount);
            sb.Append(";updated=").Append(Interlocked.Read(ref oldestListUnix)).Append(";update=").Append(lastRefreshResult);
            sb.Append(";cache=").Append(cache.Count);
            var up = upstream;
            sb.Append(";up_ms=").Append((up == null ? 0 : up.AverageMs).ToString("0.0", CultureInfo.InvariantCulture));
            sb.Append(";router=").Append(routerAddr ?? "none");
            return sb.ToString();
        }

        string ListText()
        {
            var parts = new List<string>();
            lock (rulesGate)
            {
                foreach (var src in cfg.Lists)
                {
                    HashedSet s;
                    DateTime mt;
                    int count = listSets.TryGetValue(src.Name, out s) ? s.Count : 0;
                    long when = listMtimes.TryGetValue(src.Name, out mt) ? App.Unix(mt) : 0;
                    parts.Add(src.Name + "=" + count + "@" + when);
                }
            }
            return string.Join(";", parts);
        }

        // ---- settings, your lists and the blocklists

        public void ReloadUserState(bool forceConfig)
        {
            lock (rulesGate)
            {
                DateTime iniTime = MTime(App.IniPath);
                if (forceConfig || iniTime != iniLoaded)
                {
                    var c = Config.Load();
                    foreach (var p in c.Problems) Log.Warn("aegis.ini " + p);
                    if (c.ReadFailed) iniRetry = true;       // keep the settings in use and try again shortly
                    else
                    {
                        ApplyConfig(c);
                        iniLoaded = MTime(App.IniPath);
                        iniRetry = false;
                    }
                }
                PauseUntil(Pause.UntilUtc());
                RebuildRules();
            }
        }

        void RebuildRules()   // caller holds rulesGate
        {
            var a = ReadUserList(App.AllowPath);
            var b = ReadUserList(App.BlockPath);
            if (a != null) userAllow = a;        // a read error keeps the last good copy, and is retried soon
            if (b != null) userBlock = b;
            var allow = new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>("allow.txt", userAllow) };
            var block = new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>("block.txt", userBlock) };
            long total = 0;
            DateTime oldest = DateTime.MaxValue;
            int n = 0;
            foreach (var src in cfg.Lists)
            {
                HashedSet s;
                if (!listSets.TryGetValue(src.Name, out s)) continue;
                block.Add(new KeyValuePair<string, INameSet>(src.Name, s));
                total += s.Count;
                n++;
                oldest = listMtimes[src.Name] < oldest ? listMtimes[src.Name] : oldest;
            }
            rules = new Rules(protectedNames, allow, block);
            allowCount = userAllow.Count;
            blockCount = userBlock.Count;
            listCount = n;
            Interlocked.Exchange(ref domainTotal, total);
            Interlocked.Exchange(ref oldestListUnix, n == 0 ? 0 : App.Unix(oldest));
            watched[App.IniPath] = iniRetry ? RetrySoon : MTime(App.IniPath);
            watched[App.PausePath] = MTime(App.PausePath);
            watched[App.AllowPath] = a != null ? MTime(App.AllowPath) : RetrySoon;
            watched[App.BlockPath] = b != null ? MTime(App.BlockPath) : RetrySoon;
        }

        // A missing file is an empty list; a file that's there but can't be read (locked, no access) is
        // null, so the last good copy stays in use.
        static SmallSet ReadUserList(string path)
        {
            string[] lines;
            try { lines = File.ReadAllLines(path); }
            catch (FileNotFoundException) { return new SmallSet(new string[0]); }
            catch (DirectoryNotFoundException) { return new SmallSet(new string[0]); }
            catch (Exception e)
            {
                Log.Warn("can't read " + Path.GetFileName(path) + " (" + e.Message + "); keeping the last copy");
                return null;
            }
            var all = new List<string>();
            var found = new List<string>();
            foreach (var line in lines)
            {
                found.Clear();
                Names.ParseListLine(line, true, found);
                all.AddRange(found);
            }
            return new SmallSet(all);
        }

        static DateTime MTime(string path)
        {
            try { return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue; }
            catch (Exception) { return DateTime.MinValue; }
        }

        bool WatchedChanged()
        {
            lock (rulesGate)
            {
                foreach (var kv in watched)
                    if (MTime(kv.Key) != kv.Value) return true;
            }
            return false;
        }

        // Builds the big sets outside the lock (a fraction of a second each), then swaps them in.
        List<string> LoadListsFromDisk(bool onlyChanged)
        {
            var errors = new List<string>();
            foreach (var src in cfg.Lists.ToArray())
            {
                string path = src.FilePath;
                DateTime mt = MTime(path);
                if (mt == DateTime.MinValue) continue;
                DateTime prev;
                lock (rulesGate) { if (onlyChanged && listMtimes.TryGetValue(src.Name, out prev) && prev == mt) continue; }
                var sw = Stopwatch.StartNew();
                HashedSet set;
                try { set = new HashedSet(Names.ReadListFile(path, false)); }
                catch (Exception e)
                {
                    Log.Warn("can't read " + path + ": " + e.Message);
                    errors.Add("couldn't load " + src.Name);
                    continue;
                }
                lock (rulesGate)
                {
                    listSets[src.Name] = set;
                    listMtimes[src.Name] = mt;
                }
                Log.Info(string.Format(CultureInfo.InvariantCulture, "loaded {0}: {1:N0} domains in {2:0.0}s", src.Name, set.Count, sw.Elapsed.TotalSeconds));
            }
            lock (rulesGate)
            {
                foreach (var name in listSets.Keys.ToList())
                {
                    if (cfg.Lists.Any(l => l.Name == name)) continue;
                    listSets.Remove(name);
                    listMtimes.Remove(name);
                }
                RebuildRules();
            }
            // reading a list makes tens of MB of short-lived strings; hand that memory back now
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect();
            return errors;
        }

        void MaintenanceLoop()
        {
            DateTime nextCheck = DateTime.UtcNow.AddSeconds(3);
            DateTime lastSave = DateTime.UtcNow, lastClean = DateTime.MinValue, lastHealth = DateTime.UtcNow;
            int failures = 0;
            while (true)
            {
                bool forced = updateNow.WaitOne(2000);
                try
                {
                    if (WatchedChanged()) ReloadUserState(false);
                    if (networkChanged) OnNetworkChanged();
                    FlushTally(false);
                    if (DateTime.UtcNow >= nextListRetry)
                    {
                        // A list on disk that couldn't be loaded (for example, while locked) gets another read soon.
                        nextListRetry = DateTime.UtcNow.AddSeconds(30);
                        if (ListsNeedReload()) LoadListsFromDisk(true);
                    }
                    if (forced || DateTime.UtcNow >= nextCheck)
                    {
                        var due = cfg.Lists.Where(l => forced || AgeHours(l.FilePath) >= cfg.UpdateHours).ToList();
                        if (due.Count > 0) failures = UpdateLists(due) ? 0 : failures + 1;
                        nextCheck = DateTime.UtcNow.AddMinutes(failures == 0 ? 30 : Math.Min(5 << Math.Min(failures - 1, 5), 120));
                    }
                    if ((DateTime.UtcNow - lastSave).TotalSeconds >= 60)
                    {
                        counters.Save();
                        lastSave = DateTime.UtcNow;
                    }
                    if ((DateTime.UtcNow - lastClean).TotalHours >= 6)
                    {
                        CleanLogs();
                        lastClean = DateTime.UtcNow;
                    }
                    if ((DateTime.UtcNow - lastHealth).TotalHours >= 1)
                    {
                        LogHealth();
                        lastHealth = DateTime.UtcNow;
                    }
                }
                catch (Exception e) { Log.Error("maintenance: " + e); }
            }
        }

        // Once an hour: how the engine itself is doing, so a slow leak would show up in engine.log.
        void LogHealth()
        {
            using (var me = Process.GetCurrentProcess())
            {
                Log.Info(string.Format(CultureInfo.InvariantCulture,
                    "health: up {0:0.0} h; {1} handles, {2} threads, {3:0.0} MB private ({4:0.0} MB managed); GCs {5}/{6}/{7}; cache {8}; {9}",
                    (DateTime.UtcNow - started).TotalHours, me.HandleCount, me.Threads.Count, me.PrivateMemorySize64 / 1048576.0,
                    GC.GetTotalMemory(false) / 1048576.0, GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2),
                    cache.Count, counters.Fields()));
            }
        }

        bool ListsNeedReload()
        {
            lock (rulesGate)
            {
                foreach (var list in cfg.Lists)
                {
                    DateTime loaded;
                    DateTime onDisk = MTime(list.FilePath);
                    if (onDisk != DateTime.MinValue && (!listMtimes.TryGetValue(list.Name, out loaded) || loaded != onDisk))
                        return true;
                }
            }
            return false;
        }

        // Wi-Fi vs Ethernet, another router...: local names follow the network this PC is on now, and
        // answers from the old network aren't reused (even when both routers use the same address).
        void OnNetworkChanged()
        {
            networkChanged = false;
            if (upstreamsFixed) return;
            string now = FindRouter(cfg);
            localDomains = LocalDomainsFor(cfg);
            if (now != routerAddr)
            {
                Log.Info("network changed: local names now go to " + (now ?? "nobody (no router found)"));
                SetRouter(now);
            }
            Interlocked.Increment(ref routeGen);
            cache.Clear();
        }

        static double AgeHours(string path)
        {
            DateTime mt = MTime(path);
            return mt == DateTime.MinValue ? double.MaxValue : (DateTime.UtcNow - mt).TotalHours;
        }

        bool UpdateLists(List<ListSource> due)
        {
            var errors = new List<string>();
            int ok = 0;
            foreach (var src in due)
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    int count = Download(src);
                    ok++;
                    Log.Info(string.Format(CultureInfo.InvariantCulture, "downloaded {0}: {1:N0} domains in {2:0.0}s", src.Name, count, sw.Elapsed.TotalSeconds));
                }
                catch (Exception e)
                {
                    errors.Add(src.Name + ": " + e.Message);
                    Log.Warn("couldn't download " + src.Name + ": " + e.Message);
                }
            }
            if (ok > 0) errors.AddRange(LoadListsFromDisk(true));
            string summary = errors.Count == 0 ? "ok" : "failed " + string.Join(", ", errors);
            lastRefreshResult = Kv.Clean(summary.Length > 120 ? summary.Substring(0, 120) : summary);
            return errors.Count == 0;
        }

        // A downloaded list must look like a real list and mustn't suddenly shrink below half of what we
        // have (a cut-off or broken download would quietly remove most of the protection).
        public static bool DownloadLooksRight(int count, int previous)
        {
            return count >= 1000 && (previous == 0 || count >= previous / 2);
        }

        int Download(ListSource src)
        {
            int previous = 0;
            lock (rulesGate)
            {
                HashedSet old;
                if (listSets.TryGetValue(src.Name, out old)) previous = old.Count;
            }
            Exception last = null;
            foreach (var url in new[] { src.Url, src.Mirror })
            {
                if (string.IsNullOrEmpty(url)) continue;
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(url);
                    req.UserAgent = "Aegis/" + App.Version;
                    req.Timeout = 60000;
                    req.ReadWriteTimeout = 60000;
                    req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
                    string text;
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    using (var stream = resp.GetResponseStream())
                    using (var ms = new MemoryStream())
                    {
                        var buf = new byte[81920];
                        int n;
                        while ((n = stream.Read(buf, 0, buf.Length)) > 0)
                        {
                            if (ms.Length + n > (64L << 20)) throw new IOException("bigger than 64 MB");
                            ms.Write(buf, 0, n);
                        }
                        text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
                    }
                    if (text.Length > 0 && text[0] == '﻿') text = text.Substring(1);
                    // count distinct domains: a broken feed repeating the same batch mustn't look complete
                    var hashes = new List<ulong>(1 << 16);
                    var found = new List<string>();
                    using (var sr = new StringReader(text))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            found.Clear();
                            Names.ParseListLine(line, false, found);
                            foreach (var d in found) hashes.Add(HashedSet.Hash(d));
                        }
                    }
                    hashes.Sort();
                    int count = 0;
                    for (int i = 0; i < hashes.Count; i++)
                        if (i == 0 || hashes[i] != hashes[i - 1]) count++;
                    if (!DownloadLooksRight(count, previous))
                        throw new InvalidDataException(string.Format(CultureInfo.InvariantCulture, "only {0:N0} domains (had {1:N0}); kept the old list", count, previous));
                    string tmp = src.FilePath + ".tmp";
                    File.WriteAllText(tmp, text, new UTF8Encoding(false));
                    if (File.Exists(src.FilePath)) File.Replace(tmp, src.FilePath, null);
                    else File.Move(tmp, src.FilePath);
                    return count;
                }
                catch (Exception e) { last = e; }
            }
            throw last ?? new InvalidOperationException("no URL");
        }

        void CleanLogs()
        {
            try
            {
                var cutoff = DateTime.Today.AddDays(-cfg.KeepLogDays);
                foreach (var f in Directory.GetFiles(App.LogDir, "*.log"))
                {
                    var m = Regex.Match(Path.GetFileName(f), @"^(blocked|queries)-(\d{4}-\d{2}-\d{2})\.log$");
                    DateTime d;
                    if (m.Success && DateTime.TryParseExact(m.Groups[2].Value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out d) && d < cutoff)
                        File.Delete(f);
                }
            }
            catch (Exception e) { Log.Warn("cleaning logs: " + e.Message); }
        }
    }

    static class EngineHost
    {
        public static int Run(string[] args)
        {
            Log.Init("engine");
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Error("crashed: " + e.ExceptionObject);
            try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.Normal; } catch { }
            int workers, io;
            ThreadPool.GetMinThreads(out workers, out io);
            ThreadPool.SetMinThreads(Math.Max(workers, 64), Math.Max(io, 64));
            try { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288; }
            catch (NotSupportedException) { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; }
            var cfg = Config.Load();
            foreach (var p in cfg.Problems) Log.Warn("aegis.ini " + p);
            var engine = new Engine(cfg, true);
            try { engine.Start(); }
            catch (Exception e)
            {
                Log.Error("can't start: " + e.Message);
                return 2;
            }
            engine.Supervise();
            return 0;
        }
    }
}
