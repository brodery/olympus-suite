// Janus.exe: --watch (the background watcher the hub keeps running), the command line, alert
// actions, and the window.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Olympus.Janus
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "check" || first == "history" || first == "help" || first == "--help" || first == "/?";
            bool headless = cli || a.Has("--watch") || a.Has("--stop") || a.Has("--action");
            AppStart.Init(AppId.Janus, !headless);
            try
            {
                if (a.Has("--watch")) return Watcher.Run();
                if (a.Has("--stop")) { Sync.Poke("janus.stop"); return 0; }
                if (a.Has("--action")) return DoAction(a.Opt("--action"), a.Opt("--alert"));
                if (cli) { Cli.Attach(); return JanusCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new JanusWindow());
            }
            catch (Exception e)
            {
                Log.Error("Janus failed", e);
                if (a.Has("--action")) { Cli.Attach(); Cli.Out(e.Message); }
                return 1;
            }
        }

        static int DoAction(string action, string alertId)
        {
            var al = AlertStore.Find(AppId.Janus, alertId ?? "");
            string path = al == null ? null : al.Get("path");
            if (path == null) return 1;
            switch (action)
            {
                case "delete":
                    string error = Recycle(path, al.Get("sha256"));
                    if (error == null) return 0;
                    Cli.Attach();
                    Cli.Out(error);
                    return 1;
                case "show":
                    if (File.Exists(path)) Proc.ShowInExplorer(path);
                    return 0;
                default:
                    return 1;
            }
        }

        public static string Recycle(string path, string expectedHash)
        {
            if (string.IsNullOrWhiteSpace(expectedHash))
                return "This report has no fingerprint. Check the file again before recycling it.";
            if (!File.Exists(path)) return "The file is no longer at that location.";

            string currentHash;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
                currentHash = FileUtil.Hex(sha.ComputeHash(stream));
            if (!string.Equals(expectedHash, currentHash, StringComparison.OrdinalIgnoreCase))
                return "The file has changed since this report. Check it again before recycling it.";

            Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(path, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin, Microsoft.VisualBasic.FileIO.UICancelOption.ThrowException);
            Log.Info("moved to the Recycle Bin: " + path);
            return null;
        }
    }

    static class History
    {
        public static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Janus), "history.jsonl"); } }
        static readonly object gate = new object();

        public static void Add(FileReport r)
        {
            lock (gate)
            {
                try
                {
                    File.AppendAllText(FilePath, J.Write(r) + "\n", Encoding.UTF8);
                    var fi = new FileInfo(FilePath);
                    if (fi.Length > 3 * 1024 * 1024)
                    {
                        var keep = File.ReadAllLines(FilePath).Reverse().Take(1500).Reverse().ToArray();
                        FileUtil.WriteAtomic(FilePath, string.Join("\n", keep) + "\n");
                    }
                }
                catch (Exception e) { Log.Error("saving history", e); }
            }
        }

        public static List<FileReport> Read(int max)
        {
            var list = new List<FileReport>();
            try
            {
                if (!File.Exists(FilePath)) return list;
                foreach (var line in File.ReadAllLines(FilePath).Reverse())
                {
                    if (list.Count >= max) break;
                    try { list.Add(J.Read<FileReport>(line)); } catch (Exception) { }
                }
            }
            catch (Exception) { }
            return list;
        }
    }

    // Watches Downloads; each file is inspected once it has stopped growing (browsers write to a
    // .crdownload/.part file and rename it when done).
    static class Watcher
    {
        sealed class Waiting { public DateTime Since; public int Tries; }

        public static int Run()
        {
            Mutex m;
            if (!Sync.Claim("janus.watch", out m)) return 0;
            using (m)
            using (var stop = Sync.Listen("janus.stop"))
            {
                string dir = Suite.User.Downloads;
                if (!Directory.Exists(dir)) { StatusStore.Write(States.Error, "Can't find your Downloads folder", dir, null); return 1; }
                var waiting = new Dictionary<string, Waiting>(StringComparer.OrdinalIgnoreCase);
                var done = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
                var vanish = new List<KeyValuePair<FileReport, DateTime>>();
                var gate = new object();
                using (var fsw = new FileSystemWatcher(dir) { IncludeSubdirectories = false, InternalBufferSize = 65536, NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite })
                {
                    Action<string> note = p =>
                    {
                        if (Inspect.IsPartial(p)) return;
                        lock (gate)
                        {
                            Waiting w;
                            if (!waiting.TryGetValue(p, out w)) waiting[p] = w = new Waiting();
                            w.Since = DateTime.UtcNow;
                        }
                    };
                    fsw.Created += (s, e) => note(e.FullPath);
                    fsw.Changed += (s, e) => note(e.FullPath);
                    fsw.Renamed += (s, e) => note(e.FullPath);
                    fsw.Error += (s, e) => Log.Warn("watcher overflow: " + e.GetException().Message);
                    fsw.EnableRaisingEvents = true;
                    Log.Info("watching " + dir);
                    Beat(dir);
                    var lastBeat = DateTime.UtcNow;
                    while (!stop.WaitOne(1000))
                    {
                        List<string> ready;
                        lock (gate) ready = waiting.Where(kv => DateTime.UtcNow - kv.Value.Since > TimeSpan.FromSeconds(3)).Select(kv => kv.Key).ToList();
                        foreach (var p in ready)
                        {
                            Waiting w;
                            lock (gate) { w = waiting[p]; waiting.Remove(p); }
                            try
                            {
                                if (!File.Exists(p)) continue;
                                var fi = new FileInfo(p);
                                string sig = p + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks;
                                if (done.ContainsKey(sig)) continue;
                                try { using (new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read)) { } }
                                catch (IOException)
                                {
                                    if (++w.Tries < 40) lock (gate) { w.Since = DateTime.UtcNow; waiting[p] = w; }   // still being written
                                    continue;
                                }
                                done[sig] = DateTime.UtcNow;
                                var r = Inspect.Analyze(p, true);
                                History.Add(r);
                                Raise(r);
                                if (r.Risky) vanish.Add(new KeyValuePair<FileReport, DateTime>(r, DateTime.UtcNow.AddSeconds(20)));
                                Beat(dir);
                            }
                            catch (Exception e) { Log.Error("inspecting " + p, e); }
                        }
                        // a risky file that disappears right away was usually removed by Windows Security
                        foreach (var v in vanish.Where(x => x.Value < DateTime.UtcNow).ToList())
                        {
                            vanish.Remove(v);
                            if (!File.Exists(v.Key.Path))
                                AlertStore.Raise(AlertStore.New(Sev.Notice, v.Key.Name + " disappeared", "It was removed within seconds of downloading, usually by Windows Security (check its Protection history), or you deleted it.", "gone:" + v.Key.Sha256));
                        }
                        foreach (var k in done.Where(x => DateTime.UtcNow - x.Value > TimeSpan.FromHours(6)).Select(x => x.Key).ToList()) done.Remove(k);
                        if (DateTime.UtcNow - lastBeat > TimeSpan.FromMinutes(5)) { Beat(dir); lastBeat = DateTime.UtcNow; }
                    }
                }
                Log.Info("watcher stopped");
                StatusStore.Write(States.Off, "Stopped", null, null);
            }
            return 0;
        }

        static void Beat(string dir)
        {
            var recent = History.Read(300);
            string today = DateTime.Now.ToString("yyyy-MM-dd");
            int n = recent.Count(r => Clock.Parse(r.Time).ToLocalTime().ToString("yyyy-MM-dd") == today);
            var last = recent.FirstOrDefault();
            StatusStore.Write(States.Ok, "Watching Downloads", Fmt.Plural(n, "download") + " checked today" + (last != null ? " · last: " + Fmt.Clip(last.Name, 40) + " (" + Words.Verdict(last.Verdict) + ")" : ""), null);
        }

        static void Raise(FileReport r)
        {
            if (!r.Risky && r.Verdict == "ok") return;
            string sev = r.Verdict == "danger" ? Sev.Critical : r.Verdict == "caution" ? Sev.Warning : Sev.Notice;
            var top = r.Findings.OrderByDescending(f => f.Level == "bad" ? 3 : f.Level == "warn" ? 2 : f.Level == "good" ? 1 : 0).Take(3).Select(f => f.Text);
            var a = AlertStore.New(sev, Fmt.Clip(r.Name, 50) + ": " + Words.Verdict(r.Verdict), string.Join("\n", top), "dl:" + r.Sha256)
                .With("path", r.Path).With("sha256", r.Sha256);
            a.Act("delete", "Move it to the Recycle Bin", false);
            a.Act("show", "Show in folder", false);
            AlertStore.Raise(a);
        }
    }

    static class Words
    {
        public static string Verdict(string v)
        {
            switch (v) { case "danger": return "dangerous"; case "caution": return "be careful"; default: return "looks fine"; }
        }
    }

    static class JanusCli
    {
        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "check":
                {
                    string p = FileUtil.Expand(a.Rest(1));
                    if (p == null || !File.Exists(p)) { Cli.Out("No such file: " + a.Rest(1)); return 1; }
                    var r = Inspect.Analyze(p, true);
                    Cli.Out(r.Name + ": " + Words.Verdict(r.Verdict).ToUpperInvariant() + " (" + r.Kind + ", " + Fmt.Size(r.Size) + ")");
                    foreach (var f in r.Findings) Cli.Out("  [" + f.Level + "] " + f.Text);
                    Cli.Out("  SHA-256: " + r.Sha256 + (r.Reputation != null ? "   reputation: " + r.Reputation : ""));
                    return r.Verdict == "danger" ? 2 : r.Verdict == "caution" ? 1 : 0;
                }
                case "history":
                {
                    int n;
                    if (!int.TryParse(a[1] ?? "20", out n)) n = 20;
                    foreach (var r in History.Read(n))
                        Cli.Out(Fmt.Local(Clock.Parse(r.Time)).PadRight(18) + " " + Words.Verdict(r.Verdict).PadRight(11) + " " + r.Name);
                    return 0;
                }
                default:
                    Cli.Out("Janus download inspector - commands:\n  Janus.exe                 open the window\n  Janus.exe check FILE      inspect a file\n  Janus.exe history [N]     the last N downloads it checked\n  Janus.exe --watch         watch Downloads (the hub keeps this running)\n  Janus.exe --stop          stop the watcher\nFrom PowerShell, add | Out-String so the output waits for the command.");
                    return 0;
            }
        }
    }
}
