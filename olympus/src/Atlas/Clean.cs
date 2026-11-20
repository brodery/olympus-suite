// Atlas's cleanup: the list of throwaway data (atlas.ini for places in your profile; Windows' own
// folders are built in, because cleaning them needs admin rights and so mustn't come from a file
// your account can edit), measuring and cleaning it without ever following a junction, Steam's
// leftovers, the Recycle Bin, and "worth a look" suggestions (big games you haven't played, LM
// Studio models, big downloads). Atlas only cleans what you tick, and refuses whole drives,
// Windows, Program Files, your main folders and Ark's backups.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Olympus.Atlas
{
    sealed class CleanItem
    {
        public string Id, Name, About = "", How = "delete", Group = "junk", Blocked;
        public List<string> Paths = new List<string>();
        public TimeSpan OlderThan = TimeSpan.Zero;
        public bool Admin, Default, WholeFolder;
        public List<string> WaitFor = new List<string>(), Keep = new List<string>();
        // what Measure found
        public long Bytes, Count;
        public bool Measured, Partial, Unreadable, Exists;
    }

    sealed class CleanResult
    {
        public string Id, Name, Note;
        public long Freed, Files, Failed;
    }

    static class Catalog
    {
        public static string IniPath { get { return Path.Combine(Suite.BinDir, "atlas.ini"); } }

        // Everything the Clean up tab lists.
        public static List<CleanItem> Load()
        {
            var list = new List<CleanItem>();
            try { list.AddRange(Parse(File.Exists(IniPath) ? File.ReadAllText(IniPath) : "")); }
            catch (Exception e) { Log.Error("reading atlas.ini", e); }
            list.Add(new CleanItem { Id = "recycle-bin", Name = "Recycle Bin", About = "Files you deleted. Emptying it removes them for good.", How = "empty-bin" });
            list.AddRange(AdminItems());
            try { list.AddRange(SteamItems()); } catch (Exception e) { Log.Error("looking at Steam's folders", e); }
            return list;
        }

        // [clean:ID] sections. An "admin" key is ignored: only Atlas's built-in list may ask for admin rights.
        public static List<CleanItem> Parse(string text)
        {
            var ini = Ini.Parse(text);
            var list = new List<CleanItem>();
            foreach (var sec in ini.Sections)
            {
                if (!sec.StartsWith("clean:", StringComparison.OrdinalIgnoreCase)) continue;
                string id = sec.Substring(6).Trim();
                var it = new CleanItem
                {
                    Id = id,
                    Name = ini.Get(sec, "name", id),
                    About = ini.Get(sec, "about", ""),
                    How = ini.Get(sec, "how", "delete").Trim().ToLowerInvariant(),
                    OlderThan = ini.Span(sec, "older_than", TimeSpan.Zero),
                    Default = ini.Bool(sec, "default", false),
                    WaitFor = ini.List(sec, "wait_for"),
                    Keep = ini.List(sec, "keep")
                };
                foreach (var p in ini.All(sec, "path"))
                    if (p.Trim().Length > 0) it.Paths.Add(FsNative.LongName(Environment.ExpandEnvironmentVariables(p.Trim().Trim('"'))));
                if (id.Length == 0 || it.Paths.Count == 0 || (it.How != "delete" && it.How != "recycle")) continue;
                list.Add(it);
            }
            return list;
        }

        public static List<CleanItem> AdminItems()
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string data = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string wer = Path.Combine(data, @"Microsoft\Windows\WER");
            return new List<CleanItem>
            {
                new CleanItem
                {
                    Id = "win-temp", Name = "Windows' temporary files", Admin = true, Default = true, OlderThan = TimeSpan.FromDays(2),
                    About = "What Windows and installers leave in C:\\Windows\\Temp. Files from the last 2 days and anything in use stay.",
                    Paths = { Path.Combine(win, "Temp") }
                },
                new CleanItem
                {
                    Id = "win-update", Name = "Old Windows Update downloads", Admin = true, Default = true, OlderThan = TimeSpan.FromDays(10),
                    About = "Update files Windows has already installed. The last 10 days stay, in case an update is still going.",
                    Paths = { Path.Combine(win, @"SoftwareDistribution\Download") }
                },
                new CleanItem
                {
                    Id = "win-reports", Name = "Windows error reports (all accounts)", Admin = true, Default = true,
                    About = "Crash and hang reports Windows keeps after sending them (or not).",
                    Paths = { Path.Combine(wer, "ReportArchive"), Path.Combine(wer, "ReportQueue"), Path.Combine(wer, "Temp") }
                },
                new CleanItem
                {
                    Id = "win-dumps", Name = "Windows crash dumps", Admin = true,
                    About = "Memory dumps from blue screens and graphics driver resets. Keep them while you're chasing a crash.",
                    Paths = { Path.Combine(win, "MEMORY.DMP"), Path.Combine(win, "Minidump"), Path.Combine(win, "LiveKernelReports") }
                },
            };
        }

        // Steam: folders of games that were uninstalled, and their shader caches and workshop items.
        public static List<CleanItem> SteamItems()
        {
            var list = new List<CleanItem>();
            var games = Steam.Games();
            var installed = new HashSet<string>(games.Select(g => g.AppId));
            var shaders = new List<string>();
            var workshop = new List<string>();
            foreach (var lib in Steam.Libraries())
            {
                string apps = Path.Combine(lib, "steamapps");
                string common = Path.Combine(apps, "common");
                if (Directory.Exists(common))
                {
                    var used = games.Where(g => g.Library.Equals(lib, StringComparison.OrdinalIgnoreCase)).Select(g => g.InstallDir);
                    foreach (var left in Steam.Leftovers(Directory.GetDirectories(common).Select(Path.GetFileName), used))
                    {
                        string full = Path.Combine(common, left);
                        list.Add(new CleanItem
                        {
                            Id = "steam-left:" + full, Name = "Leftover game folder: " + left, Group = "leftovers", How = "recycle", WholeFolder = true,
                            About = "No installed Steam game uses it (an uninstall left it behind). Some games keep saves, mods or settings here, so look first.",
                            Paths = { full }
                        });
                    }
                }
                foreach (var pair in new[] { new KeyValuePair<string, List<string>>("shadercache", shaders), new KeyValuePair<string, List<string>>(@"workshop\content", workshop) })
                {
                    string dir = Path.Combine(apps, pair.Key);
                    if (!Directory.Exists(dir)) continue;
                    foreach (var d in Directory.GetDirectories(dir))
                    {
                        string id = Path.GetFileName(d);
                        if (id.Length > 0 && id.All(char.IsDigit) && !installed.Contains(id)) pair.Value.Add(d);
                    }
                }
            }
            if (shaders.Count > 0)
                list.Add(new CleanItem
                {
                    Id = "steam-shaders-gone", Name = "Shader caches of uninstalled games", How = "delete", WholeFolder = true, Default = true,
                    About = "Steam's compiled shaders for games that aren't installed any more.", Paths = shaders
                });
            if (workshop.Count > 0)
                list.Add(new CleanItem
                {
                    Id = "steam-workshop-gone", Name = "Workshop items of uninstalled games", How = "delete", WholeFolder = true,
                    About = "Mods and maps downloaded for games that aren't installed any more. Steam fetches them again if you reinstall.", Paths = workshop
                });
            return list;
        }
    }

    static class Cleaner
    {
        static readonly char[] Wild = { '*', '?' };

        // The existing files and folders an item points at (wildcards expanded).
        public static List<string> Places(CleanItem it)
        {
            var list = new List<string>();
            foreach (var raw in it.Paths)
                foreach (var p in Glob(Environment.ExpandEnvironmentVariables(raw)))
                    if (!list.Contains(p, StringComparer.OrdinalIgnoreCase)) list.Add(p);
            return list;
        }

        public static List<string> Glob(string pattern)
        {
            var found = new List<string>();
            if (string.IsNullOrWhiteSpace(pattern)) return found;
            pattern = pattern.Trim().TrimEnd('\\');
            if (pattern.IndexOfAny(Wild) < 0)
            {
                if (File.Exists(pattern) || Directory.Exists(pattern)) found.Add(pattern);
                return found;
            }
            var parts = pattern.Split('\\');
            if (parts.Length < 2 || parts[0].IndexOfAny(Wild) >= 0) return found;
            var current = new List<string> { parts[0] + "\\" };
            for (int i = 1; i < parts.Length; i++)
            {
                bool last = i == parts.Length - 1;
                var next = new List<string>();
                foreach (var dir in current)
                {
                    if (parts[i].IndexOfAny(Wild) < 0)
                    {
                        string p = Path.Combine(dir, parts[i]);
                        if (Directory.Exists(p) || (last && File.Exists(p))) next.Add(p);
                        continue;
                    }
                    try
                    {
                        next.AddRange(Directory.GetDirectories(dir, parts[i]).Where(d => !IsLink(new DirectoryInfo(d))));
                        if (last) next.AddRange(Directory.GetFiles(dir, parts[i]));
                    }
                    catch (Exception) { }
                }
                current = next;
            }
            found.AddRange(current);
            return found;
        }

        static bool IsLink(FileSystemInfo f)
        {
            try { return (f.Attributes & FileAttributes.ReparsePoint) != 0; }
            catch (Exception) { return true; }
        }

        static bool Matches(string name, List<string> patterns)
        {
            foreach (var p in patterns)
            {
                string rx = "^" + Regex.Escape(p).Replace("\\*", ".*").Replace("\\?", ".") + "$";
                if (Regex.IsMatch(name, rx, RegexOptions.IgnoreCase)) return true;
            }
            return false;
        }

        static long Length(FileInfo f)
        {
            try { return f.Length; } catch (Exception) { return 0; }
        }

        // Every file an item covers, never following junctions or symlinks; "dirs" collects the
        // folders walked, parents before their subfolders.
        static void Walk(CleanItem it, List<string> places, Action<FileInfo> visit, List<string> dirs)
        {
            DateTime cutoff = DateTime.UtcNow - it.OlderThan;
            Func<FileInfo, bool> wanted = f =>
            {
                if (it.OlderThan > TimeSpan.Zero && (f.LastWriteTimeUtc > cutoff || f.CreationTimeUtc > cutoff)) return false;
                return it.Keep.Count == 0 || !Matches(f.Name, it.Keep);
            };
            foreach (var place in places)
            {
                if (File.Exists(place))
                {
                    var fi = new FileInfo(place);
                    if (wanted(fi)) visit(fi);
                    continue;
                }
                var root = new DirectoryInfo(place);
                if (!root.Exists || IsLink(root)) continue;
                var stack = new Stack<DirectoryInfo>();
                stack.Push(root);
                while (stack.Count > 0)
                {
                    var d = stack.Pop();
                    FileSystemInfo[] entries;
                    try { entries = d.GetFileSystemInfos(); }
                    catch (UnauthorizedAccessException)
                    {
                        if (d.FullName.TrimEnd('\\').Equals(root.FullName.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) it.Unreadable = true;
                        else it.Partial = true;
                        continue;
                    }
                    catch (IOException) { it.Partial = true; continue; }
                    if (dirs != null) dirs.Add(d.FullName);
                    foreach (var e in entries)
                    {
                        var sub = e as DirectoryInfo;
                        if (sub != null)
                        {
                            if (!IsLink(sub)) stack.Push(sub);
                            continue;
                        }
                        var fi = e as FileInfo;
                        if (fi != null && wanted(fi)) visit(fi);
                    }
                }
            }
        }

        static readonly Dictionary<string, string> Friendly = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "chrome", "Chrome" }, { "msedge", "Edge" }, { "brave", "Brave" }, { "firefox", "Firefox" }, { "discord", "Discord" }, { "steam", "Steam" }
        };

        // "Close Discord first" when a program the item waits for is running.
        public static string BlockedBy(CleanItem it)
        {
            foreach (var name in it.WaitFor)
            {
                string n = name.Trim();
                if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) n = n.Substring(0, n.Length - 4);
                if (n.Length == 0) continue;
                var ps = Process.GetProcessesByName(n);
                bool running = ps.Length > 0;
                foreach (var p in ps) p.Dispose();
                string label;
                if (!Friendly.TryGetValue(n, out label)) label = char.ToUpperInvariant(n[0]) + n.Substring(1);
                if (running) return "Close " + label + " first";
            }
            return null;
        }

        // Why an item's places can't be cleaned, or null. Clean checks this before touching anything.
        public static string Refused(CleanItem it, List<string> places)
        {
            if (it.Admin) return null;   // Atlas's own list, checked when it was written
            foreach (var p in places)
            {
                string why = Safety.Refuse(p);
                if (why != null) return "Atlas won't clean " + p + ": " + why;
            }
            return null;
        }

        public static void Measure(CleanItem it)
        {
            it.Bytes = 0;
            it.Count = 0;
            it.Partial = it.Unreadable = false;
            it.Blocked = null;
            if (it.How == "empty-bin")
            {
                long b, n;
                Recycler.Query(out b, out n);
                it.Bytes = b;
                it.Count = n;
                it.Exists = true;
                it.Measured = true;
                return;
            }
            var places = Places(it);
            it.Exists = places.Count > 0;
            long bytes = 0, count = 0;
            Walk(it, places, f => { bytes += Length(f); count++; }, null);
            it.Bytes = bytes;
            it.Count = count;
            it.Measured = true;
            it.Blocked = Refused(it, places) ?? BlockedBy(it);
        }

        public static CleanResult Clean(CleanItem it)
        {
            var r = new CleanResult { Id = it.Id, Name = it.Name };
            try
            {
                var places = Places(it);
                r.Note = Refused(it, places) ?? BlockedBy(it);
                if (r.Note != null) return r;
                if (it.How == "empty-bin")
                {
                    long b, n;
                    Recycler.Query(out b, out n);
                    if (Recycler.Empty()) { r.Freed = b; r.Files = n; }
                    else r.Note = "Windows didn't empty it";
                }
                else if (it.How == "recycle") Recycle(it, places, r);
                else Delete(it, places, r);
                Log.Info("cleaned " + it.Id + ": " + Fmt.Size(r.Freed) + " in " + r.Files + " files" + (r.Failed > 0 ? " (" + r.Failed + " in use, left alone)" : "") + (r.Note != null ? " - " + r.Note : ""));
            }
            catch (Exception e)
            {
                r.Note = e.Message;
                Log.Error("cleaning " + it.Id, e);
            }
            return r;
        }

        static void Delete(CleanItem it, List<string> places, CleanResult r)
        {
            var dirs = new List<string>();
            Walk(it, places, f =>
            {
                long len = Length(f);
                try
                {
                    if ((f.Attributes & FileAttributes.ReadOnly) != 0) f.Attributes &= ~FileAttributes.ReadOnly;
                    f.Delete();
                    r.Freed += len;
                    r.Files++;
                }
                catch (IOException) { r.Failed++; }
                catch (UnauthorizedAccessException) { r.Failed++; }
            }, dirs);
            // folders that emptied out, deepest first; the places themselves only when the item
            // covers whole folders
            var keep = new HashSet<string>(places.Select(p => p.TrimEnd('\\')), StringComparer.OrdinalIgnoreCase);
            for (int i = dirs.Count - 1; i >= 0; i--)
            {
                string d = dirs[i].TrimEnd('\\');
                if (!it.WholeFolder && keep.Contains(d)) continue;
                try { if (!Directory.EnumerateFileSystemEntries(d).Any()) Directory.Delete(d, false); }
                catch (Exception) { }
            }
        }

        static void Recycle(CleanItem it, List<string> places, CleanResult r)
        {
            var targets = new List<string>();
            var sizes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            var counts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            if (it.WholeFolder)
            {
                foreach (var p in places)
                {
                    long bytes = 0, n = 0;
                    Walk(new CleanItem { Paths = { p } }, new List<string> { p }, f => { bytes += Length(f); n++; }, null);
                    targets.Add(p);
                    sizes[p] = bytes;
                    counts[p] = n;
                }
            }
            else
                Walk(it, places, f => { targets.Add(f.FullName); sizes[f.FullName] = Length(f); counts[f.FullName] = 1; }, null);
            for (int i = 0; i < targets.Count; i += 200)
            {
                var batch = targets.Skip(i).Take(200).ToList();
                Recycler.Recycle(batch);
                foreach (var t in batch)
                {
                    if (File.Exists(t) || Directory.Exists(t)) r.Failed++;
                    else { r.Freed += sizes[t]; r.Files += counts[t]; }
                }
            }
        }
    }

    static class Recycler
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            public uint wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            public int fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct SHQUERYRBINFO { public int cbSize; public long i64Size; public long i64NumItems; }
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] static extern int SHFileOperation(ref SHFILEOPSTRUCT op);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] static extern int SHQueryRecycleBin(string root, ref SHQUERYRBINFO info);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] static extern int SHEmptyRecycleBin(IntPtr hwnd, string root, uint flags);

        // Shell calls want a single-threaded apartment.
        static T Sta<T>(Func<T> f)
        {
            if (Thread.CurrentThread.GetApartmentState() == ApartmentState.STA) return f();
            T result = default(T);
            Exception err = null;
            var t = new Thread(() => { try { result = f(); } catch (Exception e) { err = e; } });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();
            if (err != null) throw err;
            return result;
        }

        // Sends files or folders to the Recycle Bin without dialogs, except Windows' own warning when
        // something can't go there and would be deleted for good.
        public static bool Recycle(IList<string> paths)
        {
            if (paths.Count == 0) return true;
            return Sta(() =>
            {
                var op = new SHFILEOPSTRUCT
                {
                    wFunc = 3,   // delete
                    pFrom = string.Join("\0", paths) + "\0\0",
                    fFlags = 0x40 | 0x10 | 0x4 | 0x400 | 0x4000   // undo, no confirmation, silent, no error UI, warn before deleting for good
                };
                return SHFileOperation(ref op) == 0 && op.fAnyOperationsAborted == 0;
            });
        }

        public static void Query(out long bytes, out long items)
        {
            var q = new SHQUERYRBINFO();
            q.cbSize = Marshal.SizeOf(q);
            bytes = items = 0;
            try
            {
                if (SHQueryRecycleBin(null, ref q) == 0) { bytes = q.i64Size; items = q.i64NumItems; }
            }
            catch (Exception) { }
        }

        public static bool Empty()
        {
            return Sta(() =>
            {
                int hr = SHEmptyRecycleBin(IntPtr.Zero, null, 0x1 | 0x2 | 0x4);   // no confirmation, progress or sound
                return hr == 0 || hr == unchecked((int)0x8000FFFF);   // E_UNEXPECTED: it was already empty
            });
        }
    }

    sealed class SteamGame
    {
        public string AppId, Name, InstallDir, Library;
        public long SizeOnDisk;
        public DateTime LastPlayed = DateTime.MinValue, LastUpdated = DateTime.MinValue;
        public string Folder { get { return Path.Combine(Library, "steamapps", "common", InstallDir); } }
    }

    static class Steam
    {
        static readonly string[] NotGames = { "Steam Controller Configs", "Steamworks Shared" };
        const string Pair = "\"(\\w+)\"\\s+\"((?:[^\"\\\\]|\\\\.)*)\"";

        public static string Root()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                {
                    string p = k == null ? null : k.GetValue("SteamPath") as string;
                    if (!string.IsNullOrEmpty(p))
                    {
                        p = p.Replace('/', '\\');
                        if (Directory.Exists(p)) return p;
                    }
                }
            }
            catch (Exception) { }
            string def = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam");
            return Directory.Exists(def) ? def : null;
        }

        static string Unescape(string s) { return s.Replace("\\\\", "\\").Replace("\\\"", "\""); }

        public static List<string> ParseLibraries(string vdf)
        {
            var list = new List<string>();
            foreach (Match m in Regex.Matches(vdf ?? "", Pair))
            {
                if (!m.Groups[1].Value.Equals("path", StringComparison.OrdinalIgnoreCase)) continue;
                string p = Unescape(m.Groups[2].Value).TrimEnd('\\');
                if (p.Length > 0 && !list.Contains(p, StringComparer.OrdinalIgnoreCase)) list.Add(p);
            }
            return list;
        }

        public static List<string> Libraries()
        {
            string root = Root();
            if (root == null) return new List<string>();
            string vdf = Path.Combine(root, @"steamapps\libraryfolders.vdf");
            List<string> libs;
            try { libs = File.Exists(vdf) ? ParseLibraries(File.ReadAllText(vdf)) : new List<string>(); }
            catch (Exception) { libs = new List<string>(); }
            if (libs.Count == 0) libs.Add(root);
            return libs.Where(Directory.Exists).ToList();
        }

        public static SteamGame ParseManifest(string text, string library)
        {
            var g = new SteamGame { Library = library };
            foreach (Match m in Regex.Matches(text ?? "", Pair))
            {
                string v = Unescape(m.Groups[2].Value);
                long num;
                switch (m.Groups[1].Value.ToLowerInvariant())
                {
                    case "appid": if (g.AppId == null) g.AppId = v; break;
                    case "name": if (g.Name == null) g.Name = v; break;
                    case "installdir": if (g.InstallDir == null) g.InstallDir = v; break;
                    case "sizeondisk": if (g.SizeOnDisk == 0 && long.TryParse(v, out num)) g.SizeOnDisk = num; break;
                    case "lastplayed": if (g.LastPlayed == DateTime.MinValue && long.TryParse(v, out num) && num > 0) g.LastPlayed = Clock.FromUnix(num); break;
                    case "lastupdated": if (g.LastUpdated == DateTime.MinValue && long.TryParse(v, out num) && num > 0) g.LastUpdated = Clock.FromUnix(num); break;
                }
            }
            if (g.AppId == null || string.IsNullOrEmpty(g.InstallDir)) return null;
            if (g.Name == null) g.Name = g.InstallDir;
            return g;
        }

        public static List<SteamGame> Games()
        {
            var list = new List<SteamGame>();
            foreach (var lib in Libraries())
            {
                string apps = Path.Combine(lib, "steamapps");
                if (!Directory.Exists(apps)) continue;
                foreach (var f in Directory.GetFiles(apps, "appmanifest_*.acf"))
                {
                    try
                    {
                        var g = ParseManifest(File.ReadAllText(f), lib);
                        if (g != null) list.Add(g);
                    }
                    catch (Exception) { }
                }
            }
            MergeLastPlayed(list, LastPlayedByAccount());
            return list;
        }

        // A game's manifest doesn't always note when it was last played; each Steam account's
        // localconfig.vdf does. The later of the two wins.
        public static void MergeLastPlayed(List<SteamGame> games, Dictionary<string, DateTime> played)
        {
            foreach (var g in games)
            {
                DateTime t;
                if (played.TryGetValue(g.AppId, out t) && t > g.LastPlayed) g.LastPlayed = t;
            }
        }

        public static Dictionary<string, DateTime> LastPlayedByAccount()
        {
            var res = new Dictionary<string, DateTime>();
            string root = Root();
            string users = root == null ? null : Path.Combine(root, "userdata");
            if (users == null || !Directory.Exists(users)) return res;
            foreach (var dir in Directory.GetDirectories(users))
            {
                string cfg = Path.Combine(dir, @"config\localconfig.vdf");
                if (!File.Exists(cfg)) continue;
                try { ReadLastPlayed(File.ReadAllText(cfg), res); } catch (Exception) { }
            }
            return res;
        }

        public static void ReadLastPlayed(string localConfig, Dictionary<string, DateTime> into)
        {
            var apps = Vdf.Get(Vdf.Parse(localConfig), "UserLocalConfigStore", "Software", "Valve", "Steam", "apps") as Dictionary<string, object>;
            if (apps == null) return;
            foreach (var kv in apps)
            {
                var app = kv.Value as Dictionary<string, object>;
                object v;
                long n;
                if (app == null || !app.TryGetValue("LastPlayed", out v) || !long.TryParse(v as string, out n) || n <= 0) continue;
                var t = Clock.FromUnix(n);
                DateTime have;
                if (!into.TryGetValue(kv.Key, out have) || t > have) into[kv.Key] = t;
            }
        }

        // Folders in steamapps\common that no installed game uses.
        public static List<string> Leftovers(IEnumerable<string> commonDirs, IEnumerable<string> installDirs)
        {
            var used = new HashSet<string>(installDirs, StringComparer.OrdinalIgnoreCase);
            return commonDirs.Where(d => !used.Contains(d) && !NotGames.Contains(d, StringComparer.OrdinalIgnoreCase)).ToList();
        }

        // The installed game a path belongs to (its folder or anything inside), or null.
        public static SteamGame GameAt(string path, IEnumerable<SteamGame> games)
        {
            string p = (path ?? "").TrimEnd('\\');
            foreach (var g in games)
            {
                string f = g.Folder.TrimEnd('\\');
                if (p.Equals(f, StringComparison.OrdinalIgnoreCase) || p.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase)) return g;
            }
            return null;
        }
    }

    // Valve's text KeyValues format: "key" "value" pairs and "key" { ... } blocks, // comments.
    static class Vdf
    {
        public static Dictionary<string, object> Parse(string text)
        {
            int i = 0;
            return Block(text ?? "", ref i, 0);
        }

        static Dictionary<string, object> Block(string t, ref int i, int depth)
        {
            var d = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            while (true)
            {
                string key = Next(t, ref i);
                if (key == null || key == "}") return d;
                if (key == "{") continue;
                string val = Next(t, ref i);
                if (val == null) return d;
                if (val == "{") d[key] = depth < 64 ? (object)Block(t, ref i, depth + 1) : null;
                else if (val != "}") d[key] = val;
                else return d;
            }
        }

        // The next token: a quoted string (unescaped), "{", "}", a bare word, or null at the end.
        static string Next(string t, ref int i)
        {
            while (i < t.Length)
            {
                char c = t[i];
                if (char.IsWhiteSpace(c)) { i++; continue; }
                if (c == '/' && i + 1 < t.Length && t[i + 1] == '/') { while (i < t.Length && t[i] != '\n') i++; continue; }
                if (c == '{' || c == '}') { i++; return c.ToString(); }
                if (c == '"')
                {
                    var sb = new StringBuilder();
                    i++;
                    while (i < t.Length && t[i] != '"')
                    {
                        if (t[i] == '\\' && i + 1 < t.Length) { i++; char e = t[i]; sb.Append(e == 'n' ? '\n' : e == 't' ? '\t' : e); }
                        else sb.Append(t[i]);
                        i++;
                    }
                    i++;
                    return sb.ToString();
                }
                int start = i;
                while (i < t.Length && !char.IsWhiteSpace(t[i]) && t[i] != '{' && t[i] != '}' && t[i] != '"') i++;
                return t.Substring(start, i - start);
            }
            return null;
        }

        public static object Get(Dictionary<string, object> d, params string[] path)
        {
            object cur = d;
            foreach (var p in path)
            {
                var dd = cur as Dictionary<string, object>;
                object next;
                if (dd == null || !dd.TryGetValue(p, out next)) return null;
                cur = next;
            }
            return cur;
        }
    }

    // Places Atlas never deletes or recycles, whatever a map click or atlas.ini says.
    static class Safety
    {
        static string Norm(string p)
        {
            if (string.IsNullOrWhiteSpace(p)) return "";
            try { return FsNative.LongName(Path.GetFullPath(p.Trim())).TrimEnd('\\'); }
            catch (Exception) { return FsNative.LongName(p.Trim()).TrimEnd('\\'); }
        }
        static bool Same(string a, string b) { return a.Length > 0 && a.Equals(b, StringComparison.OrdinalIgnoreCase); }
        static bool Under(string p, string dir) { return dir.Length > 2 && (Same(p, dir) || p.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase)); }
        static string Special(Environment.SpecialFolder f) { try { return Norm(Environment.GetFolderPath(f)); } catch (Exception) { return ""; } }

        public static string ArkRoot()
        {
            var info = J.Load<InstallInfo>(Suite.InstallFile);
            return Norm(info != null && !string.IsNullOrEmpty(info.ArkTarget) ? info.ArkTarget : @"A:\Ark");
        }

        // Why not, or null when it's fine.
        public static string Refuse(string path, bool includeContents = false)
        {
            string p = Norm(path);
            if (p.Length <= 2) return "that's a whole drive";
            Func<string, bool> covers = dir => includeContents && Under(dir, p);
            string windows = Special(Environment.SpecialFolder.Windows);
            if (Under(p, windows) || covers(windows)) return "it includes part of Windows";
            foreach (var f in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolder.CommonProgramFiles, Environment.SpecialFolder.CommonProgramFilesX86 })
            {
                string dir = Special(f);
                if (Same(p, dir) || covers(dir)) return "it includes a system folder";
            }
            string install = Norm(Suite.InstallDir), bin = Norm(Suite.BinDir);
            if (Under(p, install) || Under(p, bin) || covers(install) || covers(bin)) return "it includes Olympus itself";
            string profile = Norm(Suite.User.Profile);
            if (Same(p, profile) || covers(profile) || Same(p, Norm(Path.GetDirectoryName(profile) ?? ""))) return "it includes a whole user folder";
            var main = new List<string>
            {
                Suite.User.Documents, Suite.User.Desktop, Suite.User.Downloads, Suite.User.Local, Suite.User.Roaming, Path.Combine(profile, "AppData"),
                Path.Combine(profile, "OneDrive"), Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Environment.GetFolderPath(Environment.SpecialFolder.MyMusic), Environment.GetFolderPath(Environment.SpecialFolder.MyVideos), KnownFolders.SavedGames()
            };
            foreach (var m in main)
            {
                string dir = Norm(m);
                if (Same(p, dir) || covers(dir)) return "it includes one of your main folders (pick something inside it)";
            }
            if (includeContents && covers(Norm(Path.GetTempPath()))) return "it includes the folder Windows uses for temporary files";
            string ark = ArkRoot();
            if (Under(p, ark) || covers(ark)) return "it includes Ark's backups (Ark trims old ones itself)";
            return null;
        }
    }

    sealed class ReviewItem
    {
        public string Kind, Name, Path, AppId, Action, When;
        public long Size;
    }

    // Big things Atlas suggests a look at; it never removes them by itself.
    static class Review
    {
        static string Days(DateTime utc)
        {
            if (utc == DateTime.MinValue) return "never";
            int d = (int)(DateTime.UtcNow - utc).TotalDays;
            return d <= 0 ? "today" : d == 1 ? "yesterday" : d < 60 ? d + " days ago" : d < 730 ? (d / 30) + " months ago" : (d / 365) + " years ago";
        }

        public static List<ReviewItem> Collect(AtlasSettings s)
        {
            var list = new List<ReviewItem>();
            var cutoff = DateTime.UtcNow.AddDays(-s.UnplayedDays);
            var games = new List<SteamGame>();
            try { games = Steam.Games(); } catch (Exception e) { Log.Error("listing Steam games", e); }
            try
            {
                foreach (var g in games.Where(x => x.SizeOnDisk >= (1L << 30) && x.LastPlayed < cutoff).OrderByDescending(x => x.SizeOnDisk).Take(15))
                    list.Add(new ReviewItem
                    {
                        Kind = "game", Name = g.Name + " (Steam)", Size = g.SizeOnDisk, Path = g.Folder, AppId = g.AppId,
                        When = g.LastPlayed == DateTime.MinValue ? "never played" : "played " + Days(g.LastPlayed), Action = "Uninstall in Steam…"
                    });
            }
            catch (Exception e) { Log.Error("listing Steam games", e); }

            string profile = Suite.User.Profile;
            foreach (var dir in new[] { System.IO.Path.Combine(profile, @".lmstudio\models"), System.IO.Path.Combine(profile, @".cache\lm-studio\models") })
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*", SearchOption.AllDirectories).Where(x => x.Length >= (1L << 30)))
                        list.Add(new ReviewItem { Kind = "model", Name = f.Name + " (LM Studio model)", Size = f.Length, Path = f.FullName, When = "added " + Days(f.CreationTimeUtc), Action = "Show in folder" });
                }
                catch (Exception) { }
            }

            try
            {
                var old = DateTime.UtcNow.AddDays(-30);
                var setupish = new HashSet<string>(new[] { ".exe", ".msi", ".zip", ".7z", ".rar", ".iso", ".img" }, StringComparer.OrdinalIgnoreCase);
                if (Directory.Exists(Suite.User.Downloads))
                    foreach (var f in new DirectoryInfo(Suite.User.Downloads).EnumerateFiles()
                        .Where(x => x.Length >= 200L << 20 || (setupish.Contains(x.Extension) && x.Length >= 20L << 20 && x.LastWriteTimeUtc < old))
                        .OrderByDescending(x => x.Length).Take(15))
                        list.Add(new ReviewItem { Kind = "download", Name = f.Name + " (Downloads)", Size = f.Length, Path = f.FullName, When = "downloaded " + Days(f.CreationTimeUtc), Action = "Move to the Recycle Bin…" });
            }
            catch (Exception) { }

            try { list.AddRange(FlightSim(games)); } catch (Exception e) { Log.Error("looking at Flight Simulator", e); }

            string system = System.IO.Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";
            try
            {
                var hib = new FileInfo(System.IO.Path.Combine(system, "hiberfil.sys"));
                if (hib.Exists && hib.Length >= (1L << 30))
                    list.Add(new ReviewItem { Kind = "hibernate", Name = "Hibernation file (hiberfil.sys)", Size = hib.Length, Path = hib.FullName, When = "for hibernate and Fast Startup", Action = "How to turn it off" });
            }
            catch (Exception) { }

            string winOld = System.IO.Path.Combine(system, "Windows.old");
            if (Directory.Exists(winOld))
                list.Add(new ReviewItem { Kind = "winold", Name = "Previous Windows installation (Windows.old)", Path = winOld, When = "Windows removes it after about 10 days", Action = "Open Storage settings" });
            return list.OrderByDescending(x => x.Size).ToList();
        }

        // Microsoft Flight Simulator keeps its scenery outside the game's folder, so it stays behind
        // when the game is uninstalled.
        static List<ReviewItem> FlightSim(List<SteamGame> games)
        {
            var found = new List<ReviewItem>();
            string roaming = Suite.User.Roaming, local = Suite.User.Local;
            var spots = new[]
            {
                new[] { System.IO.Path.Combine(roaming, "Microsoft Flight Simulator"), "1250410", "Microsoft Flight Simulator" },
                new[] { System.IO.Path.Combine(roaming, "Microsoft Flight Simulator 2024"), "2537590", "Microsoft Flight Simulator 2024" },
                new[] { System.IO.Path.Combine(local, @"Packages\Microsoft.FlightSimulator_8wekyb3d8bbwe\LocalCache"), "", "Microsoft Flight Simulator (Microsoft Store)" },
            };
            foreach (var spot in spots)
            {
                string cfg = System.IO.Path.Combine(spot[0], "UserCfg.opt");
                if (!File.Exists(cfg)) continue;
                var m = Regex.Match(File.ReadAllText(cfg), "InstalledPackagesPath\\s+\"([^\"]+)\"");
                if (!m.Success || !Directory.Exists(m.Groups[1].Value)) continue;
                string packages = m.Groups[1].Value;
                long size = new Scanner().Run(packages).Root.Size;
                if (size < (1L << 30)) continue;
                var game = games.FirstOrDefault(g => g.AppId == spot[1]);
                found.Add(new ReviewItem
                {
                    Kind = "folder", Name = spot[2] + " scenery packages", Size = size, Path = packages, Action = "Show in folder",
                    When = spot[1].Length == 0 ? "" : game == null ? "the game isn't installed: left behind" : game.LastPlayed == DateTime.MinValue ? "never played" : "played " + Days(game.LastPlayed)
                });
            }
            return found;
        }
    }

    static class History
    {
        public static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Atlas), "clean-history.jsonl"); } }

        public static void Add(CleanResult r)
        {
            try
            {
                File.AppendAllText(FilePath, J.Write(new { Time = Clock.NowIso(), r.Id, r.Name, r.Freed, r.Files, r.Failed, r.Note }) + "\n");
            }
            catch (Exception) { }
        }
    }
}
