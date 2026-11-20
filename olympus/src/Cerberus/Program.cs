// Cerberus.exe: --engine (the SYSTEM task), block/unblock actions (elevated), the command line,
// and the window.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Cerberus
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "apps" || first == "blocked" || first == "help" || first == "--help" || first == "/?";
            bool headless = cli || a.Has("--engine") || a.Has("--action");
            AppStart.Init(AppId.Cerberus, !headless);
            try
            {
                if (a.Has("--engine")) { int s; int.TryParse(a.Opt("--for") ?? "0", out s); return NetEngine.Run(s); }
                if (a.Has("--action")) return DoAction(a.Opt("--action"), a.Opt("--alert"), a.Opt("--path"));
                if (cli) { Cli.Attach(); return CerberusCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new CerberusWindow());
            }
            catch (Exception e)
            {
                Log.Error("Cerberus failed", e);
                return 1;
            }
        }

        // Firewall rules need admin rights, so a non-elevated caller re-runs Cerberus elevated.
        public static int DoAction(string action, string alertId, string path)
        {
            if (action != "block" && action != "unblock") return 1;
            if (alertId != null)
            {
                if (path != null) return 1;
                var al = AlertStore.FindForAction(AppId.Cerberus, alertId, action);
                path = al == null ? null : al.Get("path");
            }
            if (string.IsNullOrEmpty(path)) return 1;
            if (!Elevation.IsElevated)
            {
                if (!Suite.Installed) return 1;
                string exe = Path.Combine(Suite.InstallDir, "Cerberus.exe");
                string target = alertId != null ? " --alert " + alertId : " --path " + Proc.Quote(path);
                return Elevation.Run(exe, "--action " + action + target, true) == 0 ? 0 : 1;
            }
            if (action == "block") Firewall.Block(path);
            else Firewall.Unblock(path);
            return 0;
        }

        public static Dictionary<string, AppNet> Apps()
        {
            string shared = Path.Combine(Suite.SharedDir(AppId.Cerberus), "apps.json");
            var d = J.Load<Dictionary<string, AppNet>>(File.Exists(shared) ? shared : Path.Combine(Suite.UserDir(AppId.Cerberus), "apps.json"));
            return d ?? new Dictionary<string, AppNet>();
        }

        public static List<LiveConn> Live()
        {
            string shared = Path.Combine(Suite.SharedDir(AppId.Cerberus), "live.json");
            return J.Load<List<LiveConn>>(File.Exists(shared) ? shared : Path.Combine(Suite.UserDir(AppId.Cerberus), "live.json")) ?? new List<LiveConn>();
        }
    }

    static class CerberusCli
    {
        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "apps":
                {
                    var apps = Program.Apps().Values.OrderByDescending(x => x.LastSeen, StringComparer.Ordinal).ToList();
                    if (apps.Count == 0) { Cli.Out("No samples yet. The engine samples public TCP connections."); return 0; }
                    foreach (var x in apps)
                    {
                        Cli.Out(x.Name.PadRight(28) + " " + x.Connections.ToString().PadLeft(6) + " sampled connections   last " + Fmt.Ago(Clock.Parse(x.LastSeen)) + (x.Blocked.Count > 0 ? "   Aegis blocked " + x.Blocked.Values.Sum() + " lookups" : ""));
                        Cli.Out("    Estimated destinations " + string.Join(", ", x.Sites.OrderByDescending(s => s.Value).Take(5).Select(s => s.Key)));
                    }
                    return 0;
                }
                case "blocked":
                    foreach (var p in Firewall.BlockedApps()) Cli.Out(p);
                    return 0;
                default:
                    Cli.Out("Cerberus outbound firewall - commands:\n  Cerberus.exe            open the window\n  Cerberus.exe apps       sampled public TCP connections and estimated destinations\n  Cerberus.exe blocked    programs Cerberus keeps offline\n  Cerberus.exe --engine   the watcher (runs as a SYSTEM task once installed)\nFrom PowerShell, add | Out-String so the output waits for the command.");
                    return 0;
            }
        }
    }
}
