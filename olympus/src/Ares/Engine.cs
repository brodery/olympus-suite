// Ares's engine: settings, spotting games (Steam libraries, Epic, GOG, Xbox, EA, Ubisoft, Riot,
// Rockstar, plus folders you add, like C:\MagnumOpus), what game mode does and undoes, and the
// leak watch (a program whose memory keeps climbing, or Windows running out of memory).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Olympus.Ares
{
    sealed class AresSettings
    {
        public bool UnloadLmStudio = true, HighPerformance, LeakWatch = true;
        public List<string> Close = new List<string>(), Folders = new List<string>(), Programs = new List<string>(), Ignore = new List<string>();
        public double MinGb = 2, GrowthGbPerHour = 1.5;
        public int CommitPercent = 90;

        public const string Defaults =
            "; Ares settings. Changes apply within a minute.\r\n\r\n" +
            "[game_mode]\r\n" +
            "; Unload LM Studio's model while you play (frees the GPU memory it holds; LM Studio reloads it when asked).\r\n" +
            "unload_lm_studio = true\r\n" +
            "; Switch to Windows' High performance power plan while playing, and back afterwards.\r\n" +
            "high_performance_power = false\r\n" +
            "; Programs to close while you play and start again afterwards (exe names), for example OneDrive.exe\r\n" +
            "close_while_playing =\r\n\r\n" +
            "[games]\r\n" +
            "; Store folders are found automatically (Steam libraries, Epic, GOG, Xbox, EA, Ubisoft, Riot, Rockstar).\r\n" +
            "; Extra folders whose programs count as games:\r\n" +
            "folders = C:\\MagnumOpus\r\n" +
            "; Programs that count as games wherever they are:\r\n" +
            "programs = Fallout4.exe, SkyrimSE.exe\r\n" +
            "; Never count these (folder or program names):\r\n" +
            "ignore = wallpaper_engine, Steamworks Shared, SteamVR, Riot Client, Launcher, Social Club, EA Desktop, UnityCrashHandler64.exe, UnityCrashHandler32.exe, CrashReportClient.exe, EasyAntiCheat.exe, EasyAntiCheat_EOS.exe, BEService.exe, steamerrorreporter.exe, steamerrorreporter64.exe\r\n\r\n" +
            "[leak_watch]\r\n" +
            "enabled = true\r\n" +
            "; Warn when a program uses more than this many GB and keeps growing...\r\n" +
            "min_gb = 2\r\n" +
            "; ...at least this fast (GB per hour).\r\n" +
            "growth_gb_per_hour = 1.5\r\n" +
            "; Warn when Windows' memory (commit charge) is this full, in percent.\r\n" +
            "commit_percent = 90\r\n";

        public static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Ares), "ares.ini"); } }

        public static AresSettings Load()
        {
            var ini = Ini.LoadOrCreate(FilePath, Defaults);
            return new AresSettings
            {
                UnloadLmStudio = ini.Bool("game_mode", "unload_lm_studio", true),
                HighPerformance = ini.Bool("game_mode", "high_performance_power", false),
                Close = ini.List("game_mode", "close_while_playing"),
                Folders = ini.List("games", "folders").Select(FileUtil.Expand).Where(f => f != null).ToList(),
                Programs = ini.List("games", "programs"),
                Ignore = ini.List("games", "ignore"),
                LeakWatch = ini.Bool("leak_watch", "enabled", true),
                MinGb = ini.Num("leak_watch", "min_gb", 2),
                GrowthGbPerHour = ini.Num("leak_watch", "growth_gb_per_hour", 1.5),
                CommitPercent = ini.Int("leak_watch", "commit_percent", 90)
            };
        }
    }

    static class Games
    {
        public static List<string> SteamLibraries()
        {
            var libs = new List<string>();
            string steam = null;
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                    steam = k == null ? null : (k.GetValue("SteamPath") as string);
            }
            catch (Exception) { }
            if (steam == null) steam = @"C:\Program Files (x86)\Steam";
            steam = steam.Replace('/', '\\');
            libs.Add(steam);
            try
            {
                string vdf = Path.Combine(steam, @"steamapps\libraryfolders.vdf");
                if (File.Exists(vdf))
                    foreach (Match m in Regex.Matches(File.ReadAllText(vdf), "\"path\"\\s+\"([^\"]+)\""))
                        libs.Add(m.Groups[1].Value.Replace(@"\\", @"\"));
            }
            catch (Exception) { }
            return libs.Distinct(StringComparer.OrdinalIgnoreCase).Select(l => Path.Combine(l, @"steamapps\common")).ToList();
        }

        // Every folder whose programs count as games.
        public static List<string> Roots(AresSettings s)
        {
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var roots = new List<string>(SteamLibraries())
            {
                Path.Combine(pf, "Epic Games"), Path.Combine(pf86, @"GOG Galaxy\Games"), @"C:\GOG Games", @"C:\XboxGames",
                Path.Combine(pf, "EA Games"), Path.Combine(pf86, @"Ubisoft\Ubisoft Game Launcher\games"), @"C:\Riot Games",
                Path.Combine(pf, "Rockstar Games"), Path.Combine(pf86, "Battle.net")
            };
            roots.AddRange(s.Folders);
            return roots.Where(r => !string.IsNullOrEmpty(r)).Select(r => r.TrimEnd('\\') + "\\").Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static bool IsGame(string path, List<string> roots, AresSettings s)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string name = Path.GetFileName(path);
            var parts = path.Split('\\');
            if (s.Ignore.Any(i => parts.Any(p => p.Equals(i, StringComparison.OrdinalIgnoreCase)))) return false;
            if (s.Programs.Any(p => p.Equals(name, StringComparison.OrdinalIgnoreCase))) return true;
            return roots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase));
        }

        public static string Friendly(string path)
        {
            int i = path.IndexOf(@"\steamapps\common\", StringComparison.OrdinalIgnoreCase);
            if (i >= 0)
            {
                string rest = path.Substring(i + 18);
                int slash = rest.IndexOf('\\');
                if (slash > 0) return rest.Substring(0, slash);
            }
            try
            {
                var v = FileVersionInfo.GetVersionInfo(path);
                if (!string.IsNullOrWhiteSpace(v.ProductName) && v.ProductName.Length < 60) return v.ProductName.Trim();
                if (!string.IsNullOrWhiteSpace(v.FileDescription) && v.FileDescription.Length < 60) return v.FileDescription.Trim();
            }
            catch (Exception) { }
            return Path.GetFileNameWithoutExtension(path);
        }
    }

    // What game mode changed, saved to disk so it's undone even if Ares was restarted mid-game.
    sealed class GameUndo
    {
        public string PowerScheme, Game;
        public List<string> Closed = new List<string>();
        public bool UnloadedModels;
    }

    static class GameMode
    {
        public static string UndoFile { get { return Path.Combine(Suite.UserDir(AppId.Ares), "undo.json"); } }
        static string Lms { get { return Path.Combine(Suite.User.Profile ?? "", @".lmstudio\bin\lms.exe"); } }

        static string ActiveScheme()
        {
            string o;
            if (Proc.Run("powercfg.exe", "/getactivescheme", out o, 10000) != 0) return null;
            var m = Regex.Match(o, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
            return m.Success ? m.Value : null;
        }

        public static GameUndo Enter(AresSettings s, string game, List<string> done)
        {
            var u = new GameUndo { Game = game };
            if (s.UnloadLmStudio && File.Exists(Lms) && Process.GetProcessesByName("LM Studio").Length > 0)
            {
                string o;
                int code = Proc.Run(Lms, "unload --all", out o, 30000);
                u.UnloadedModels = code == 0;
                done.Add(code == 0 ? "unloaded LM Studio's model" : "couldn't unload LM Studio's model");
            }
            if (s.HighPerformance)
            {
                u.PowerScheme = ActiveScheme();
                string o;
                if (u.PowerScheme != null && Proc.Run("powercfg.exe", "/setactive SCHEME_MIN", out o, 10000) == 0) done.Add("High performance power plan");
                else { u.PowerScheme = null; done.Add("no High performance plan on this PC"); }
            }
            foreach (var exe in s.Close)
            {
                bool leftRunning = false, closedAny = false;
                foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exe)))
                {
                    using (p)
                    {
                        string path = Native.ProcessPath(p.Id);
                        try
                        {
                            if (path == null) { leftRunning = true; continue; }
                            bool requested;
                            if (Path.GetFileName(path).Equals("OneDrive.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                string o;
                                requested = Proc.Run(path, "/shutdown", out o, 15000) == 0;
                            }
                            else requested = p.CloseMainWindow();
                            if (!requested || !p.WaitForExit(8000)) { leftRunning = true; continue; }
                            closedAny = true;
                            if (!u.Closed.Contains(path, StringComparer.OrdinalIgnoreCase)) u.Closed.Add(path);
                        }
                        catch (Exception e)
                        {
                            leftRunning = true;
                            Log.Warn("closing " + exe + ": " + e.Message);
                        }
                    }
                }
                if (leftRunning) done.Add("left " + exe + " running");
                else if (closedAny) done.Add("closed " + exe);
            }
            try { J.Save(UndoFile, u); } catch (Exception) { }
            return u;
        }

        public static void Leave(GameUndo u, List<string> done)
        {
            if (u == null) return;
            string o;
            if (u.PowerScheme != null && Proc.Run("powercfg.exe", "/setactive " + u.PowerScheme, out o, 10000) == 0) done.Add("power plan back");
            foreach (var path in u.Closed)
            {
                try
                {
                    if (!File.Exists(path) || Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path)).Length > 0) continue;
                    Process.Start(new ProcessStartInfo(path, Path.GetFileName(path).Equals("OneDrive.exe", StringComparison.OrdinalIgnoreCase) ? "/background" : "") { UseShellExecute = true });
                    done.Add("restarted " + Path.GetFileName(path));
                }
                catch (Exception e) { Log.Warn("restarting " + path + ": " + e.Message); }
            }
            FileUtil.TryDelete(UndoFile);
        }
    }

    public sealed class MemRow
    {
        public string Name, Path;
        public int Pid, Handles;
        public long Mb;
        public double MbPerHour;
    }

    public sealed class MemReport
    {
        public string Updated;
        public long CommitMb, LimitMb;
        public List<MemRow> Top = new List<MemRow>();
    }

    static class LeakWatch
    {
        [StructLayout(LayoutKind.Sequential)]
        struct MEMORYSTATUSEX
        {
            public uint dwLength, dwMemoryLoad;
            public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

        public static void Commit(out long usedMb, out long limitMb)
        {
            var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX)) };
            usedMb = limitMb = 0;
            if (!GlobalMemoryStatusEx(ref m)) return;
            limitMb = (long)(m.ullTotalPageFile / (1024 * 1024));
            usedMb = (long)((m.ullTotalPageFile - m.ullAvailPageFile) / (1024 * 1024));
        }

        sealed class Track
        {
            public string Name;
            public List<long> Mb = new List<long>();
            public List<DateTime> At = new List<DateTime>();
            public DateTime Alerted = DateTime.MinValue;
        }

        static readonly Dictionary<string, Track> tracks = new Dictionary<string, Track>();
        public static string ReportFile { get { return Path.Combine(Suite.UserDir(AppId.Ares), "memory.json"); } }
        public static string IgnoreFile { get { return Path.Combine(Suite.UserDir(AppId.Ares), "leak-ignore.txt"); } }

        // When each warning last went out, kept on disk so a restart of Ares (an install, an update,
        // signing in) doesn't repeat it.
        public sealed class LeakState
        {
            public string Commit;
            public Dictionary<string, string> Programs = new Dictionary<string, string>();
        }
        static LeakState leakState;
        static string StateFile { get { return Path.Combine(Suite.UserDir(AppId.Ares), "leak-state.json"); } }
        static LeakState State
        {
            get
            {
                if (leakState == null) leakState = J.Load<LeakState>(StateFile) ?? new LeakState();
                if (leakState.Programs == null) leakState.Programs = new Dictionary<string, string>();
                return leakState;
            }
        }
        static DateTime LastWarned(string program)
        {
            string v;
            return State.Programs.TryGetValue(program, out v) ? Clock.Parse(v) : DateTime.MinValue;
        }
        static void SaveState() { try { J.Save(StateFile, State); } catch (Exception e) { Log.Error("saving leak-watch state", e); } }

        // Growth in MB per hour over the samples kept (up to two hours), or 0 with too little history
        // or when the memory went down along the way (that's normal use, not a leak).
        public static double Growth(IList<long> mb, IList<DateTime> at)
        {
            if (mb.Count < 20) return 0;
            double hours = (at[at.Count - 1] - at[0]).TotalHours;
            if (hours < 0.3) return 0;
            long first = mb.Take(5).Min(), last = mb.Skip(mb.Count - 5).Max(), peak = mb.Max();
            if (mb[mb.Count - 1] < peak * 0.9) return 0;   // it gave memory back: normal use
            int ups = 0;
            for (int i = 10; i < mb.Count; i += 10) if (mb[i] >= mb[i - 10]) ups++;
            if (ups < (mb.Count - 1) / 10 * 0.8) return 0;
            return (last - first) / hours;
        }

        public static MemReport Sample(AresSettings s, HashSet<int> games)
        {
            var now = DateTime.UtcNow;
            var seen = new HashSet<string>();
            var rows = new List<MemRow>();
            var ignore = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { if (File.Exists(IgnoreFile)) foreach (var l in File.ReadAllLines(IgnoreFile)) if (l.Trim().Length > 0) ignore.Add(l.Trim()); } catch (Exception) { }
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    long mb;
                    int handles;
                    try { mb = p.PrivateMemorySize64 / (1024 * 1024); handles = p.HandleCount; }
                    catch (Exception) { continue; }
                    if (p.Id <= 4) continue;
                    string key = p.Id + ":" + p.ProcessName;
                    seen.Add(key);
                    Track t;
                    if (!tracks.TryGetValue(key, out t)) tracks[key] = t = new Track { Name = p.ProcessName };
                    t.Mb.Add(mb);
                    t.At.Add(now);
                    if (t.Mb.Count > 120) { t.Mb.RemoveAt(0); t.At.RemoveAt(0); }
                    double growth = Growth(t.Mb, t.At);
                    rows.Add(new MemRow { Name = p.ProcessName, Pid = p.Id, Mb = mb, MbPerHour = Math.Round(growth), Handles = handles });
                    if (s.LeakWatch && !games.Contains(p.Id) && !ignore.Contains(p.ProcessName) && mb >= s.MinGb * 1024 && growth >= s.GrowthGbPerHour * 1024
                        && now - t.Alerted > TimeSpan.FromHours(6) && now - LastWarned(p.ProcessName) > TimeSpan.FromHours(6))
                    {
                        t.Alerted = now;
                        State.Programs[p.ProcessName] = Clock.NowIso();
                        SaveState();
                        string path = Native.ProcessPath(p.Id);
                        var a = AlertStore.New(Sev.Warning, p.ProcessName + " is leaking memory",
                            p.ProcessName + " uses " + (mb / 1024.0).ToString("0.0") + " GB and has been growing about " + (growth / 1024).ToString("0.0") + " GB an hour. Left alone it can run Windows out of memory and crash your game. Restarting it usually fixes it.",
                            "leak:" + p.ProcessName).With("pid", p.Id.ToString()).With("name", p.ProcessName).With("path", path ?? "");
                        a.Act("kill", "End it now", false);
                        a.Act("ignore", "Don't watch this program", false);
                        AlertStore.Raise(a);
                    }
                }
            }
            foreach (var k in tracks.Keys.Where(k => !seen.Contains(k)).ToList()) tracks.Remove(k);
            long used, limit;
            Commit(out used, out limit);
            if (s.LeakWatch && limit > 0 && used * 100 / limit >= s.CommitPercent && now - Clock.Parse(State.Commit) > TimeSpan.FromHours(4))
            {
                State.Commit = Clock.NowIso();
                SaveState();
                var top = rows.OrderByDescending(r => r.Mb).Take(3).Select(r => r.Name + " " + (r.Mb / 1024.0).ToString("0.0") + " GB");
                AlertStore.Raise(AlertStore.New(Sev.Warning, "Memory is nearly full (" + (used * 100 / limit) + "%)",
                    "Windows has committed " + (used / 1024.0).ToString("0.0") + " of " + (limit / 1024.0).ToString("0.0") + " GB. Biggest users: " + string.Join(", ", top) + ". Close something before a game or program crashes.", "commit"));
            }
            var report = new MemReport { Updated = Clock.NowIso(), CommitMb = used, LimitMb = limit, Top = rows.OrderByDescending(r => r.Mb).Take(30).ToList() };
            try { J.Save(ReportFile, report); } catch (Exception) { }
            return report;
        }
    }
}
