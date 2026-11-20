// Ares.exe: --watch (kept running by the hub), --toggle (manual game mode), --stop, the command
// line, alert actions, and the window.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Olympus.Ares
{
    public sealed class Session
    {
        public string Game, Path, Start, End;
        public int Minutes;
        public List<string> Did = new List<string>();
    }

    static class Program
    {
        public static string ManualFlag { get { return Path.Combine(Suite.UserDir(AppId.Ares), "manual-game-mode.flag"); } }
        public static string SessionsFile { get { return Path.Combine(Suite.UserDir(AppId.Ares), "sessions.jsonl"); } }

        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "status" || first == "sessions" || first == "memory" || first == "help" || first == "--help" || first == "/?";
            bool headless = cli || a.Has("--watch") || a.Has("--toggle") || a.Has("--stop") || a.Has("--action");
            AppStart.Init(AppId.Ares, !headless);
            try
            {
                if (a.Has("--watch")) return Watch();
                if (a.Has("--toggle")) return Toggle();
                if (a.Has("--stop")) { Sync.Poke("ares.stop"); return 0; }
                if (a.Has("--action")) return DoAction(a.Opt("--action"), a.Opt("--alert"));
                if (cli) { Cli.Attach(); return AresCli.Run(a); }
                return AppWindow.Run(args, a.Opt("--show"), () => new AresWindow());
            }
            catch (Exception e)
            {
                Log.Error("Ares failed", e);
                return 1;
            }
        }

        public static int Toggle()
        {
            if (File.Exists(ManualFlag)) FileUtil.TryDelete(ManualFlag);
            else { Directory.CreateDirectory(Path.GetDirectoryName(ManualFlag)); File.WriteAllText(ManualFlag, Clock.NowIso()); }
            Sync.Poke("ares.wake");
            return 0;
        }

        static void WriteGame(bool playing, string game, string path, DateTime since)
        {
            try { J.Save(GameState.FilePath, new GameInfo { Playing = playing, Game = game, Path = path, Since = since == DateTime.MinValue ? null : Clock.Iso(since), Updated = Clock.NowIso() }); }
            catch (Exception e) { Log.Error("writing game state", e); }
        }

        static int Watch()
        {
            Mutex m;
            if (!Sync.Claim("ares.watch", out m)) return 0;
            using (m)
            using (var wake = Sync.Listen("ares.wake"))
            using (var stop = Sync.Listen("ares.stop"))
            {
                var s = AresSettings.Load();
                DateTime settingsTime = File.Exists(AresSettings.FilePath) ? File.GetLastWriteTimeUtc(AresSettings.FilePath) : DateTime.MinValue;
                var roots = Games.Roots(s);
                var paths = new Dictionary<int, string>();
                GameUndo undo = J.Load<GameUndo>(GameMode.UndoFile);   // left over from a crash mid-game: undone when no game is running
                string current = null, currentPath = null;
                DateTime since = DateTime.MinValue, lastSeen = DateTime.MinValue, lastBeat = DateTime.MinValue, lastLeak = DateTime.MinValue;
                var did = new List<string>();
                MemReport mem = null;
                Log.Info("watching for games in " + roots.Count + " folders");
                while (true)
                {
                    if (WaitHandle.WaitAny(new WaitHandle[] { stop, wake }, 3000) == 0) break;
                    var now = DateTime.UtcNow;
                    try
                    {
                        if (File.Exists(AresSettings.FilePath) && File.GetLastWriteTimeUtc(AresSettings.FilePath) != settingsTime)
                        {
                            settingsTime = File.GetLastWriteTimeUtc(AresSettings.FilePath);
                            s = AresSettings.Load();
                            roots = Games.Roots(s);
                        }
                        var gamePids = new HashSet<int>();
                        string game = null, gamePath = null;
                        var alive = new HashSet<int>();
                        foreach (var p in Process.GetProcesses())
                        {
                            using (p)
                            {
                                alive.Add(p.Id);
                                string path;
                                if (!paths.TryGetValue(p.Id, out path)) paths[p.Id] = path = p.Id > 4 ? Native.ProcessPath(p.Id) : null;
                                if (path != null && Games.IsGame(path, roots, s))
                                {
                                    gamePids.Add(p.Id);
                                    if (game == null) { game = Games.Friendly(path); gamePath = path; }
                                }
                            }
                        }
                        foreach (var pid in paths.Keys.Where(k => !alive.Contains(k)).ToList()) paths.Remove(pid);
                        if (game == null && File.Exists(ManualFlag)) game = "Game mode (turned on by hand)";
                        if (game != null) lastSeen = now;

                        if (current == null && game != null)
                        {
                            current = game;
                            currentPath = gamePath;
                            since = now;
                            did = new List<string>();
                            if (undo == null) undo = GameMode.Enter(s, game, did);
                            Log.Info("game mode on: " + game + (did.Count > 0 ? " (" + string.Join(", ", did) + ")" : ""));
                            WriteGame(true, current, currentPath, since);
                            lastBeat = DateTime.MinValue;
                        }
                        else if (current != null && game == null && now - lastSeen > TimeSpan.FromSeconds(20))
                        {
                            var after = new List<string>();
                            GameMode.Leave(undo, after);
                            undo = null;
                            int minutes = (int)Math.Round((now - since).TotalMinutes);
                            var session = new Session { Game = current, Path = currentPath, Start = Clock.Iso(since), End = Clock.NowIso(), Minutes = minutes, Did = did.Concat(after).ToList() };
                            try { File.AppendAllText(SessionsFile, J.Write(session) + "\n", Encoding.UTF8); } catch (Exception) { }
                            Log.Info("game mode off after " + minutes + " min" + (after.Count > 0 ? " (" + string.Join(", ", after) + ")" : ""));
                            current = null;
                            WriteGame(false, null, null, DateTime.MinValue);
                            lastBeat = DateTime.MinValue;
                        }
                        else if (current == null && undo != null)
                        {
                            GameMode.Leave(undo, new List<string>());   // tidy up after a crash
                            undo = null;
                        }

                        if (now - lastLeak > TimeSpan.FromSeconds(60))
                        {
                            lastLeak = now;
                            mem = LeakWatch.Sample(s, gamePids);
                        }
                        if (now - lastBeat > TimeSpan.FromSeconds(60))
                        {
                            lastBeat = now;
                            if (current != null) WriteGame(true, current, currentPath, since);
                            string memText = mem == null || mem.LimitMb == 0 ? "" : "memory " + (mem.CommitMb * 100 / mem.LimitMb) + "% used" + (mem.Top.Count > 0 ? " · biggest: " + mem.Top[0].Name + " " + (mem.Top[0].Mb / 1024.0).ToString("0.0") + " GB" : "");
                            if (current != null) StatusStore.Write(States.Busy, "Game mode on: " + current + " (" + Fmt.Duration(now - since) + ")", memText, null);
                            else StatusStore.Write(States.Ok, "Ready · no game running", memText, null);
                        }
                    }
                    catch (Exception e) { Log.Error("watch loop", e); }
                }
                if (current != null)
                {
                    GameMode.Leave(undo, new List<string>());
                    WriteGame(false, null, null, DateTime.MinValue);
                }
                StatusStore.Write(States.Off, "Stopped", null, null);
            }
            return 0;
        }

        static int DoAction(string action, string alertId)
        {
            var al = AlertStore.Find(AppId.Ares, alertId ?? "");
            if (al == null) return 1;
            string name = al.Get("name");
            int pid;
            switch (action)
            {
                case "kill":
                    if (!int.TryParse(al.Get("pid"), out pid)) return 1;
                    try
                    {
                        using (var p = Process.GetProcessById(pid))
                        {
                            if (!p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase)) return 0;   // it already restarted as something else
                            p.Kill();
                            Log.Info("ended " + name + " (" + pid + ") for leaking memory");
                        }
                        return 0;
                    }
                    catch (ArgumentException) { return 0; }   // already gone
                    catch (Win32Exception)
                    {
                        if (Elevation.IsElevated) return 1;
                        return Elevation.Run(Suite.ExeOf(AppId.Ares), "--action kill --alert " + alertId, true) == 0 ? 0 : 1;
                    }
                case "ignore":
                    File.AppendAllText(LeakWatch.IgnoreFile, name + "\r\n");
                    return 0;
                default:
                    return 1;
            }
        }

        public static List<Session> Sessions(int max)
        {
            var list = new List<Session>();
            try
            {
                if (File.Exists(SessionsFile))
                    foreach (var line in File.ReadAllLines(SessionsFile).Reverse().Take(max))
                        try { list.Add(J.Read<Session>(line)); } catch (Exception) { }
            }
            catch (Exception) { }
            return list;
        }
    }

    static class AresCli
    {
        public static int Run(Args a)
        {
            switch (a.First.ToLowerInvariant())
            {
                case "status":
                {
                    var g = GameState.Read();
                    Cli.Out(g != null && g.Playing ? "Game mode ON: " + g.Game + " since " + Fmt.Local(Clock.Parse(g.Since)) : "Game mode off");
                    var st = StatusStore.Read(AppId.Ares);
                    if (st != null) Cli.Out(st.Summary + (string.IsNullOrEmpty(st.Detail) ? "" : " - " + st.Detail));
                    var s = AresSettings.Load();
                    Cli.Out("Game folders: " + string.Join("; ", Games.Roots(s).Where(Directory.Exists)));
                    return 0;
                }
                case "sessions":
                    foreach (var x in Program.Sessions(30)) Cli.Out(Fmt.Local(Clock.Parse(x.Start)).PadRight(18) + " " + Fmt.Duration(TimeSpan.FromMinutes(x.Minutes)).PadRight(12) + " " + x.Game);
                    return 0;
                case "memory":
                {
                    long used, limit;
                    LeakWatch.Commit(out used, out limit);
                    Cli.Out("Memory committed: " + (used / 1024.0).ToString("0.0") + " of " + (limit / 1024.0).ToString("0.0") + " GB");
                    var r = J.Load<MemReport>(LeakWatch.ReportFile);
                    if (r != null) foreach (var row in r.Top.Take(15)) Cli.Out("  " + row.Name.PadRight(34) + (row.Mb / 1024.0).ToString("0.00").PadLeft(7) + " GB" + (row.MbPerHour > 0 ? "   +" + (row.MbPerHour / 1024).ToString("0.0") + " GB/h" : ""));
                    return 0;
                }
                default:
                    Cli.Out("Ares game-mode autopilot - commands:\n  Ares.exe              open the window\n  Ares.exe status       is game mode on, which folders count as games\n  Ares.exe sessions     recent game sessions\n  Ares.exe memory       memory use and the biggest programs\n  Ares.exe --toggle     turn game mode on/off by hand\n  Ares.exe --watch      watch for games (the hub keeps this running)\nFrom PowerShell, add | Out-String so the output waits for the command.");
                    return 0;
            }
        }
    }
}
