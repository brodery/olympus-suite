// Arachne.exe: --setup / --teardown (install and uninstall, elevated), --engine (the SYSTEM task
// that reads the audit events), --test (proves the wire works), alert actions, and the window.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Olympus.Arachne
{
    static class Program
    {
        public static string TestMarker { get { return Path.Combine(Suite.SharedDir(AppId.Arachne), "test-ok.txt"); } }

        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "status" || first == "help" || first == "--help" || first == "/?";
            bool headless = cli || a.Has("--setup") || a.Has("--teardown") || a.Has("--engine") || a.Has("--test") || a.Has("--action");
            AppStart.Init(AppId.Arachne, !headless);
            try
            {
                if (a.Has("--setup")) { Cli.Attach(); Cli.Out(Tripwire.Setup()); return 0; }
                if (a.Has("--teardown")) { Cli.Attach(); Cli.Out(Tripwire.Teardown()); return 0; }
                if (a.Has("--engine")) { int s; int.TryParse(a.Opt("--for") ?? "0", out s); return Engine.Run(s); }
                if (a.Has("--test")) return Test();
                if (a.Has("--action")) return DoAction(a.Opt("--action"), a.Opt("--alert"));
                if (cli) { Cli.Attach(); return Status(); }
                return AppWindow.Run(args, a.Opt("--show"), () => new ArachneWindow());
            }
            catch (Exception e)
            {
                Log.Error("Arachne failed", e);
                if (headless) { Cli.Attach(); Cli.Out("Error: " + e.Message); }
                return 1;
            }
        }

        static int Status()
        {
            var st = J.Load<SetupState>(Tripwire.SetupFile);
            if (st == null) { Cli.Out("Arachne isn't set up (install.cmd does it; it needs admin rights)."); return 1; }
            var s = StatusStore.Read(AppId.Arachne);
            ArachneAlertReview.ApplyStatus(s, ArachneAlertReview.Open(200));
            Cli.Out("Arachne: " + (s == null ? "engine hasn't reported" : s.State + " - " + s.Summary));
            foreach (var t in st.Targets) Cli.Out("  " + (t.Decoy ? "[decoy] " : "") + t.Label + "  " + t.Path);
            return 0;
        }

        // Reads a decoy (so it's this program doing the reading) and waits for the engine to notice.
        public static int Test()
        {
            var st = J.Load<SetupState>(Tripwire.SetupFile);
            var decoy = st == null ? null : st.Targets.FirstOrDefault(t => t.Decoy && File.Exists(t.Path));
            if (decoy == null) return 1;
            var started = DateTime.UtcNow.AddSeconds(-1);
            File.ReadAllBytes(decoy.Path);
            for (int i = 0; i < 40; i++)
            {
                try { if (File.Exists(TestMarker) && File.GetLastWriteTimeUtc(TestMarker) >= started) return 0; } catch (Exception) { }
                Thread.Sleep(500);
            }
            return 2;
        }

        static int DoAction(string action, string alertId)
        {
            var al = AlertStore.FindForAction(AppId.Arachne, alertId, action);
            if (al == null) return 1;
            string program = al.Get("program"), kind = al.Get("kind");
            int pid;
            switch (action)
            {
                case "kill":
                    if (string.IsNullOrEmpty(program) || !int.TryParse(al.Get("pid"), out pid) || pid <= 4) return 1;
                    try
                    {
                        using (var p = Process.GetProcessById(pid))
                        {
                            string path = Native.ProcessPath(pid);
                            if (path == null) return ElevateAlert("kill", alertId);
                            if (!path.Equals(program, StringComparison.OrdinalIgnoreCase)) return 1;   // PID may have been reused
                            p.Kill();
                        }
                        Log.Info("ended " + program + " (" + pid + ")");
                        return 0;
                    }
                    catch (ArgumentException) { return 0; }
                    catch (Win32Exception)
                    {
                        return ElevateAlert("kill", alertId);
                    }
                case "scan":
                {
                    string mp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
                    if (!File.Exists(mp) || !File.Exists(program)) return 1;
                    string o;
                    int code = Proc.Run(mp, "-Scan -ScanType 3 -File " + Proc.Quote(program), out o, 600000);
                    AlertStore.Raise(AlertStore.New(code == 0 ? Sev.Info : Sev.Warning, code == 0 ? "Defender found nothing in " + Path.GetFileName(program) : "Defender flagged " + Path.GetFileName(program),
                        code == 0 ? "That doesn't prove it's harmless: if you don't recognise it, remove it." : "Open Windows Security > Protection history to see what it found and what it did.", "scan:" + program));
                    return 0;
                }
                case "allow":
                {
                    if (!Elevation.IsElevated) return ElevateAlert("allow", alertId);
                    var allow = Tripwire.LoadAllow();
                    List<string> list;
                    if (!allow.TryGetValue(kind, out list)) allow[kind] = list = new List<string>();
                    if (!list.Contains(program, StringComparer.OrdinalIgnoreCase)) list.Add(program);
                    J.Save(Tripwire.AllowFile, allow);
                    Log.Info("allowed " + program + " to read " + kind + " files");
                    return 0;
                }
                default:
                    return 1;
            }
        }

        static int ElevateAlert(string action, string alertId)
        {
            if (Elevation.IsElevated || !Suite.Installed) return 1;
            string exe = Path.Combine(Suite.InstallDir, "Arachne.exe");
            return Elevation.Run(exe, "--action " + action + " --alert " + Proc.Quote(alertId), true) == 0 ? 0 : 1;
        }
    }

    // The SYSTEM engine: reads Security event 4663 as Windows writes it.
    static class Engine
    {
        static readonly object gate = new object();
        static List<Target> targets = new List<Target>();
        static Catalog catalog = new Catalog();
        static Dictionary<string, List<string>> allow = new Dictionary<string, List<string>>();
        static readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>();
        static int normal, flagged;

        public static int Run(int seconds)
        {
            var until = seconds > 0 ? DateTime.UtcNow.AddSeconds(seconds) : DateTime.MaxValue;
            Mutex m;
            if (!Sync.Claim("arachne.engine", out m)) return 0;
            using (m)
            {
                var st = J.Load<SetupState>(Tripwire.SetupFile);
                if (st == null) { StatusStore.Write(States.Off, "Not set up", "install.cmd sets up the tripwire (it needs admin rights)", null); return 1; }
                targets = st.Targets;
                catalog = Catalog.Load();
                allow = Tripwire.LoadAllow();
                DateTime allowTime = File.Exists(Tripwire.AllowFile) ? File.GetLastWriteTimeUtc(Tripwire.AllowFile) : DateTime.MinValue;
                EventLogWatcher w = null;
                Exception subscriptionError = null;
                try
                {
                    w = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663)]]"));
                    w.EventRecordWritten += (s, e) =>
                    {
                        if (e.EventException != null)
                        {
                            Interlocked.CompareExchange(ref subscriptionError, e.EventException, null);
                            return;
                        }
                        try { if (e.EventRecord != null) using (var r = e.EventRecord) Handle(r.ToXml()); }
                        catch (Exception ex) { Log.Error("reading an audit event", ex); }
                    };
                    w.Enabled = true;
                }
                catch (Exception e)
                {
                    StatusStore.Write(States.Error, "Can't read the Security log", e.Message, null);
                    if (w != null) w.Dispose();
                    return 1;
                }
                Log.Info("tripwire armed on " + targets.Count + " files");
                using (w)
                {
                    while (DateTime.UtcNow < until)
                    {
                        var error = Volatile.Read(ref subscriptionError);
                        if (error != null)
                        {
                            Log.Error("Security log subscription stopped", error);
                            StatusStore.Write(States.Error, "Security log monitoring stopped", error.Message, null);
                            return 1;
                        }
                        Beat();
                        Thread.Sleep(Math.Max(1000, Math.Min(60000, (int)Math.Min(int.MaxValue, (until - DateTime.UtcNow).TotalMilliseconds))));
                        if (File.Exists(Tripwire.AllowFile) && File.GetLastWriteTimeUtc(Tripwire.AllowFile) != allowTime)
                        {
                            allowTime = File.GetLastWriteTimeUtc(Tripwire.AllowFile);
                            lock (gate) allow = Tripwire.LoadAllow();
                        }
                    }
                }
            }
            return 0;
        }

        static void Beat()
        {
            int decoys = targets.Count(t => t.Decoy);
            lock (gate)
                StatusStore.Write(flagged > 0 ? States.Alert : States.Ok, flagged > 0 ? Fmt.Plural(flagged, "suspicious read") + " since start" : "Armed: watching " + targets.Count + " login files and decoys",
                    Fmt.Plural(decoys, "decoy") + " · " + Fmt.Plural(normal, "normal read") + " by the files' own programs", null);
        }

        static bool IsSelf(string program)
        {
            return program.Equals(Path.Combine(Suite.InstallDir, "Arachne.exe"), StringComparison.OrdinalIgnoreCase)
                || program.Equals(Suite.ExeOf(AppId.Arachne), StringComparison.OrdinalIgnoreCase);
        }

        public static void Handle(string xml)
        {
            var f = Tripwire.Fields(xml);
            string obj, program, pidText;
            f.TryGetValue("ObjectName", out obj);
            f.TryGetValue("ProcessName", out program);
            f.TryGetValue("ProcessId", out pidText);
            Target t;
            Dictionary<string, List<string>> extra;
            Catalog cat;
            lock (gate) { t = Tripwire.Find(targets, obj); extra = allow; cat = catalog; }
            if (t == null) return;
            int pid = 0;
            try { pid = Convert.ToInt32((pidText ?? "0").Replace("0x", ""), 16); } catch (Exception) { }
            if (program != null && IsSelf(program) && t.Decoy)
            {
                try { File.WriteAllText(Program.TestMarker, Clock.NowIso()); } catch (Exception) { }
                AlertStore.Raise(AlertStore.New(Sev.Info, "Tripwire test worked", "Arachne noticed a test read of the " + t.Label + " within seconds.", "test"));
                return;
            }
            if (Tripwire.Allowed(cat, t.Kind, program, extra)) { lock (gate) normal++; return; }
            string key = program + "|" + t.Kind;
            lock (gate)
            {
                DateTime last;
                if (recent.TryGetValue(key, out last) && DateTime.UtcNow - last < TimeSpan.FromMinutes(10)) return;
                recent[key] = DateTime.UtcNow;
                flagged++;
            }
            var sig = Signature.Check(program);
            string name = Path.GetFileNameWithoutExtension(program ?? "unknown");
            var a = AlertStore.New(Sev.Critical, name + " read your " + t.Label,
                "Program: " + program + " (" + sig.Describe() + ")\nFile: " + obj + "\n" +
                (t.Decoy ? "Nothing legitimate ever opens this decoy. This is how password-stealing malware behaves."
                         : "Only " + t.Kind + " itself should read this file. If you don't know this program, end it, scan it, and change the passwords saved there."),
                "read:" + key).With("pid", pid.ToString()).With("program", program ?? "").With("kind", t.Kind).With("file", obj ?? "");
            a.Act("kill", "End it now", false);
            a.Act("scan", "Scan it with Defender", false);
            a.Act("allow", "It's fine, allow it", true);
            AlertStore.Raise(a);
            Beat();
        }
    }
}
