// Ark's engine: settings, snapshots and retention.
//
// Each backup set is snapshotted into <target>\<set>\<yyyy-MM-dd_HHmmss>\ as a full, browsable
// copy of the folder. Files that haven't changed since the previous snapshot (same size and
// time) are hard links to it, so they cost no extra space; changed files are copied (with a
// SHA-256 recorded in <stamp>.manifest.tsv). A snapshot is built as <stamp>.partial and only
// published when the summary records the outcome. Retention keeps everything from the last
// 48 hours, then the newest snapshot per day for 30 days, then the newest per week for 12 weeks.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Olympus.Ark
{
    sealed class BackupSet
    {
        public string Name, Path, Slug;
        public TimeSpan Every = TimeSpan.FromHours(24);
        public List<string> Exclude = new List<string>();
    }

    sealed class ArkConfig
    {
        public const string DefaultTarget = @"A:\Ark";
        public string Target = DefaultTarget, FilePath;
        public int KeepAllHours = 48, KeepDailyDays = 30, KeepWeeklyWeeks = 12;
        public long MaxFileBytes = 4096L * 1024 * 1024;
        public bool PauseWhileGaming = true;
        public List<BackupSet> Sets = new List<BackupSet>();

        public static string DefaultText(UserContext u)
        {
            Func<string, string, string> In = (a, b) => System.IO.Path.Combine(a ?? "", b);
            var sb = new StringBuilder();
            sb.Append("; Ark backup settings. Changes apply at the next backup.\r\n");
            sb.Append("; Each [set:NAME] is a folder Ark keeps versioned snapshots of.\r\n\r\n");
            sb.Append("[ark]\r\n");
            sb.Append("; Where snapshots go. Use an NTFS drive separate from the files you back up.\r\n");
            sb.Append("target = " + DefaultTarget + "\r\n");
            sb.Append("; Keep every snapshot from the last N hours, then the newest per day for N days,\r\n");
            sb.Append("; then the newest per week for N weeks.\r\n");
            sb.Append("keep_all_hours = 48\r\nkeep_daily_days = 30\r\nkeep_weekly_weeks = 12\r\n");
            sb.Append("; Files bigger than this (MB) are skipped.\r\nmax_file_mb = 4096\r\n");
            sb.Append("; Frequent backups wait while a game is running (Ares tells Ark); an overdue one still runs.\r\n");
            sb.Append("pause_while_gaming = true\r\n\r\n");
            sb.Append("; For a source folder that is missing during setup, remove the leading '; ' to enable its set later.\r\n\r\n");
            Action<string, string, string, string> Set = (name, path, every, exclude) =>
            {
                string prefix = Directory.Exists(path) ? "" : "; ";
                sb.Append(prefix + "[set:" + name + "]\r\n");
                sb.Append(prefix + "path = " + path + "\r\n");
                sb.Append(prefix + "every = " + every + "\r\n");
                if (exclude != null) sb.Append(prefix + "exclude = " + exclude + "\r\n");
                sb.Append("\r\n");
            };
            Set("Claude projects", @"C:\Claude", "1h", @"*\obj\*; *.old; *.tmp; *\node_modules\*");
            Set("Claude memory", In(u.Profile, @".claude\projects\C--Claude\memory"), "1h", null);
            Set("MCP server", @"C:\MCP", "6h", @"*\__pycache__\*; *\.venv\*");
            Set("Documents", u.Documents, "24h", null);
            Set("Desktop", u.Desktop, "24h", null);
            Set("Saved Games", In(u.Profile, "Saved Games"), "24h", null);
            Set("Pictures", In(u.Profile, "Pictures"), "24h", null);
            return sb.ToString();
        }

        public static string PathIn(string dir) { return System.IO.Path.Combine(dir, "ark.ini"); }

        // The settings this process uses (ProgramData when elevated, else your profile).
        public static ArkConfig Load() { return Parse(PathIn(Suite.MyDir), true); }

        // What the window shows: the installed settings if there are any, else yours.
        public static ArkConfig LoadForDisplay()
        {
            string shared = PathIn(Suite.SharedDir(AppId.Ark));
            return File.Exists(shared) ? Parse(shared, false) : Parse(PathIn(Suite.UserDir(AppId.Ark)), true);
        }

        static ArkConfig Parse(string path, bool create)
        {
            var ini = create && !File.Exists(path) ? Ini.LoadOrCreate(path, DefaultText(Suite.User)) : Ini.Load(path);
            var c = new ArkConfig { FilePath = path };
            c.Target = FileUtil.Expand(ini.Get("ark", "target", c.Target)) ?? c.Target;
            c.KeepAllHours = Math.Max(1, ini.Int("ark", "keep_all_hours", 48));
            c.KeepDailyDays = Math.Max(0, ini.Int("ark", "keep_daily_days", 30));
            c.KeepWeeklyWeeks = Math.Max(0, ini.Int("ark", "keep_weekly_weeks", 12));
            c.MaxFileBytes = Math.Max(1, ini.Int("ark", "max_file_mb", 4096)) * 1024L * 1024;
            c.PauseWhileGaming = ini.Bool("ark", "pause_while_gaming", true);
            foreach (var sec in ini.Sections)
            {
                if (!sec.StartsWith("set:", StringComparison.OrdinalIgnoreCase)) continue;
                string name = sec.Substring(4).Trim();
                string p = FileUtil.Expand(ini.Get(sec, "path", null));
                if (name.Length == 0 || p == null) continue;
                var s = new BackupSet { Name = name, Path = p.TrimEnd('\\'), Slug = Slug(name) };
                s.Every = ini.Span(sec, "every", TimeSpan.FromHours(24));
                if (s.Every < TimeSpan.FromMinutes(15)) s.Every = TimeSpan.FromMinutes(15);
                s.Exclude = ini.List(sec, "exclude");
                c.Sets.Add(s);
            }
            return c;
        }

        public static string Slug(string name)
        {
            var sb = new StringBuilder();
            foreach (char ch in name) sb.Append(char.IsLetterOrDigit(ch) || ch == '-' || ch == '_' || ch == ' ' ? ch : '_');
            return sb.ToString().Trim();
        }
    }

    sealed class SetState
    {
        public string LastRun, LastSuccess, LastSnapshot, LastCompleteSnapshot, LastError;
        public int LastFiles, LastCopied, LastErrors;
        public long LastCopiedBytes, LastTotalBytes;

        public void RecoverLastSuccess(string setDir)
        {
            // Older versions recorded an incomplete snapshot as the last successful backup.
            if (LastErrors == 0 || LastSuccess == null || LastCompleteSnapshot != null) return;
            var complete = Snapshots.List(setDir).AsEnumerable().Reverse()
                .Select(name => Snapshots.Summary(setDir, name)).FirstOrDefault(s => s != null && s.Errors == 0);
            LastCompleteSnapshot = complete == null ? null : complete.Snapshot;
            LastSuccess = complete == null ? null : complete.Started;
        }

        public void RecordSnapshot(RunResult result)
        {
            if (result.Errors == 0)
            {
                LastSuccess = LastRun;
                LastCompleteSnapshot = result.Snapshot;
            }
            LastSnapshot = result.Snapshot;
            LastFiles = result.Files;
            LastCopied = result.Copied;
            LastErrors = result.Errors;
            LastCopiedBytes = result.CopiedBytes;
            LastTotalBytes = result.TotalBytes;
            LastError = null;
        }
    }

    sealed class ArkState
    {
        public Dictionary<string, SetState> Sets = new Dictionary<string, SetState>();
        public Dictionary<string, string> Alerted = new Dictionary<string, string>();

        public SetState For(string set)
        {
            SetState s;
            if (!Sets.TryGetValue(set, out s)) Sets[set] = s = new SetState();
            return s;
        }

        public static string PathIn(string dir) { return Path.Combine(dir, "ark-state.json"); }
        public static ArkState Load(string dir)
        {
            var s = J.Load<ArkState>(PathIn(dir)) ?? new ArkState();
            if (s.Sets == null) s.Sets = new Dictionary<string, SetState>();
            if (s.Alerted == null) s.Alerted = new Dictionary<string, string>();
            return s;
        }
        public void Save(string dir) { try { J.Save(PathIn(dir), this); } catch (Exception e) { Log.Error("saving Ark state", e); } }
    }

    sealed class ManifestEntry
    {
        public string Rel, Hash;
        public long Size, Mtime;
    }

    sealed class RunResult
    {
        public string Snapshot;
        public int Files, Linked, Copied, Errors, Skipped;
        public long CopiedBytes, TotalBytes;
        public List<string> ErrorList = new List<string>();
        public TimeSpan Took;
    }

    sealed class SnapshotSummary
    {
        public string Set, Source, Snapshot, Started, Finished;
        public int Files, Linked, Copied, Skipped;
        public int Errors = -1;
        public long CopiedBytes, TotalBytes;
        public List<string> ErrorList = new List<string>();
    }

    static class Snapshots
    {
        public const string Partial = ".partial", StampFormat = "yyyy-MM-dd_HHmmss";
        static readonly Regex StampRx = new Regex(@"^\d{4}-\d{2}-\d{2}_\d{6}$", RegexOptions.CultureInvariant);

        // Long paths: \\?\ lets Windows handle paths over 260 characters.
        public static string L(string p)
        {
            if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) return p;
            if (p.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + p.Substring(2);
            return @"\\?\" + p;
        }

        public static string SetDir(string target, BackupSet set) { return Path.Combine(target, set.Slug); }

        // Published snapshots of a set, oldest first.
        public static List<string> List(string setDir)
        {
            try
            {
                if (!Directory.Exists(setDir)) return new List<string>();
                return Directory.GetDirectories(setDir).Select(Path.GetFileName).Where(n => StampRx.IsMatch(n)).OrderBy(n => n, StringComparer.Ordinal).ToList();
            }
            catch (Exception) { return new List<string>(); }
        }

        public static DateTime StampTime(string name)
        {
            DateTime t;
            return DateTime.TryParseExact(name, StampFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out t) ? t : DateTime.MinValue;
        }

        public static SnapshotSummary Summary(string setDir, string name)
        {
            var summary = J.Load<SnapshotSummary>(Path.Combine(setDir, name + ".ark.json"));
            return summary != null && summary.Snapshot == name && summary.Errors >= 0
                && Clock.Parse(summary.Started) != DateTime.MinValue ? summary : null;
        }

        public static Dictionary<string, ManifestEntry> LoadManifest(string path)
        {
            var d = new Dictionary<string, ManifestEntry>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(path)) return d;
            foreach (var line in File.ReadLines(path, Encoding.UTF8))
            {
                var p = line.Split('\t');
                if (p.Length < 4) continue;
                long size, mt;
                if (!long.TryParse(p[1], out size) || !long.TryParse(p[2], out mt)) continue;
                d[p[0]] = new ManifestEntry { Rel = p[0], Size = size, Mtime = mt, Hash = p[3] };
            }
            return d;
        }

        static void SaveManifest(string path, List<ManifestEntry> entries)
        {
            using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
                foreach (var e in entries) w.Write(e.Rel + "\t" + e.Size + "\t" + e.Mtime + "\t" + (e.Hash ?? "") + "\n");
        }

        // "*\obj\*" style patterns: with a backslash they match the full path, without one just the name.
        public static Func<string, bool, bool> Excluder(IEnumerable<string> patterns)
        {
            var full = new List<Regex>();
            var name = new List<Regex>();
            foreach (var raw in patterns)
            {
                string g = raw.Trim().Replace('/', '\\');
                if (g.Length == 0) continue;
                var rx = new Regex("^" + Regex.Escape(g).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                (g.Contains("\\") ? full : name).Add(rx);
            }
            return (path, isDir) =>
            {
                string p = isDir ? path.TrimEnd('\\') + "\\" : path;
                string n = Path.GetFileName(path.TrimEnd('\\'));
                return full.Any(r => r.IsMatch(p)) || name.Any(r => r.IsMatch(n));
            };
        }

        const int OfflineOrCloud = 0x1000 | 0x40000 | 0x400000;   // offline, recall-on-open, recall-on-data-access

        public static RunResult Take(BackupSet set, string target, long maxFile, Action<string> progress, CancellationToken cancel)
        {
            var started = DateTime.UtcNow;
            var r = new RunResult();
            if (!Directory.Exists(set.Path)) throw new DirectoryNotFoundException("The folder " + set.Path + " doesn't exist.");
            string setDir = SetDir(target, set);
            Directory.CreateDirectory(setDir);
            foreach (var leftover in Directory.GetDirectories(setDir, "*" + Partial))
            {
                try { DeleteTree(leftover); } catch (Exception e) { Log.Warn("couldn't remove an unfinished snapshot " + leftover + ": " + e.Message); }
            }

            var existing = List(setDir);
            string prevName = existing.Count > 0 ? existing[existing.Count - 1] : null;
            string prevDir = prevName == null ? null : Path.Combine(setDir, prevName);
            var prev = prevName == null ? new Dictionary<string, ManifestEntry>(StringComparer.OrdinalIgnoreCase) : LoadManifest(Path.Combine(setDir, prevName + ".manifest.tsv"));

            string stamp = DateTime.Now.ToString(StampFormat, CultureInfo.InvariantCulture);
            while (Directory.Exists(Path.Combine(setDir, stamp))) { Thread.Sleep(1000); stamp = DateTime.Now.ToString(StampFormat, CultureInfo.InvariantCulture); }
            string work = Path.Combine(setDir, stamp + Partial);
            Directory.CreateDirectory(L(work));
            var excluded = Excluder(set.Exclude);
            var manifest = new List<ManifestEntry>();
            var buf = new byte[1 << 20];
            var dirs = new Stack<string>();
            dirs.Push("");
            DateTime lastNote = DateTime.MinValue;
            while (dirs.Count > 0)
            {
                cancel.ThrowIfCancellationRequested();
                string rel = dirs.Pop();
                string srcDir = rel.Length == 0 ? set.Path : Path.Combine(set.Path, rel);
                FileSystemInfo[] items;
                try { items = new DirectoryInfo(L(srcDir)).GetFileSystemInfos(); }
                catch (Exception e)
                {
                    r.Errors++;
                    if (r.ErrorList.Count < 50) r.ErrorList.Add(srcDir + ": " + e.Message);
                    continue;
                }
                foreach (var it in items)
                {
                    string childRel = rel.Length == 0 ? it.Name : rel + "\\" + it.Name;
                    string childSrc = Path.Combine(set.Path, childRel);
                    int attrs = (int)it.Attributes;
                    bool isDir = (it.Attributes & FileAttributes.Directory) != 0;
                    if ((it.Attributes & FileAttributes.ReparsePoint) != 0 || (attrs & OfflineOrCloud) != 0) { r.Skipped++; continue; }
                    if (excluded(childSrc, isDir)) { r.Skipped++; continue; }
                    if (isDir)
                    {
                        Directory.CreateDirectory(L(Path.Combine(work, childRel)));
                        dirs.Push(childRel);
                        continue;
                    }
                    var fi = (FileInfo)it;
                    if (fi.Length > maxFile) { r.Skipped++; continue; }
                    r.Files++;
                    r.TotalBytes += fi.Length;
                    var entry = new ManifestEntry { Rel = childRel, Size = fi.Length, Mtime = fi.LastWriteTimeUtc.Ticks };
                    string dest = Path.Combine(work, childRel);
                    ManifestEntry old;
                    bool same = prev.TryGetValue(childRel, out old) && old.Size == entry.Size && old.Mtime == entry.Mtime && prevDir != null;
                    if (same && Native.CreateHardLink(L(dest), L(Path.Combine(prevDir, childRel)), IntPtr.Zero))
                    {
                        entry.Hash = old.Hash;
                        r.Linked++;
                    }
                    else
                    {
                        try
                        {
                            entry.Hash = Copy(L(childSrc), L(dest), buf);
                            try { File.SetLastWriteTimeUtc(L(dest), fi.LastWriteTimeUtc); } catch (Exception) { }
                            r.Copied++;
                            r.CopiedBytes += fi.Length;
                        }
                        catch (Exception e)
                        {
                            FileUtil.TryDelete(L(dest));
                            // keep the last good version rather than nothing
                            if (old != null && prevDir != null && Native.CreateHardLink(L(dest), L(Path.Combine(prevDir, childRel)), IntPtr.Zero))
                            {
                                entry.Hash = old.Hash;
                                entry.Size = old.Size;
                                entry.Mtime = old.Mtime;
                                r.Linked++;
                            }
                            else entry = null;
                            r.Errors++;
                            if (r.ErrorList.Count < 50) r.ErrorList.Add(childSrc + ": " + e.Message);
                        }
                    }
                    if (entry != null) manifest.Add(entry);
                    if (progress != null && (DateTime.UtcNow - lastNote).TotalSeconds > 2)
                    {
                        lastNote = DateTime.UtcNow;
                        progress(set.Name + ": " + r.Files.ToString("N0") + " files, " + Fmt.Size(r.CopiedBytes) + " copied");
                    }
                }
            }

            SaveManifest(Path.Combine(setDir, stamp + ".manifest.tsv"), manifest);
            r.Took = DateTime.UtcNow - started;
            var summary = new SnapshotSummary
            {
                Set = set.Name, Source = set.Path, Snapshot = stamp, Started = Clock.Iso(started), Finished = Clock.NowIso(),
                Files = r.Files, Linked = r.Linked, Copied = r.Copied, Errors = r.Errors, Skipped = r.Skipped,
                CopiedBytes = r.CopiedBytes, TotalBytes = r.TotalBytes, ErrorList = r.ErrorList.Take(20).ToList()
            };
            J.Save(Path.Combine(setDir, stamp + ".ark.json"), summary);
            Directory.Move(L(work), L(Path.Combine(setDir, stamp)));
            r.Snapshot = stamp;
            return r;
        }

        static string Copy(string from, string to, byte[] buf)
        {
            using (var src = new FileStream(from, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan))
            using (var dst = new FileStream(to, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
            using (var sha = SHA256.Create())
            {
                int n;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                {
                    sha.TransformBlock(buf, 0, n, null, 0);
                    dst.Write(buf, 0, n);
                }
                sha.TransformFinalBlock(buf, 0, 0);
                return FileUtil.Hex(sha.Hash);
            }
        }

        // Which snapshots retention would remove (newest is always kept).
        public static List<string> PlanPrune(IList<string> names, DateTime nowLocal, int keepAllHours, int dailyDays, int weeklyWeeks)
        {
            var del = new List<string>();
            var days = new HashSet<string>();
            var weeks = new HashSet<string>();
            var ordered = names.Where(n => StampTime(n) != DateTime.MinValue).OrderByDescending(n => n, StringComparer.Ordinal).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                var t = StampTime(ordered[i]);
                var age = nowLocal - t;
                if (i == 0 || age <= TimeSpan.FromHours(keepAllHours)) continue;
                if (age <= TimeSpan.FromDays(dailyDays))
                {
                    if (days.Add(t.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))) continue;
                }
                else if (age <= TimeSpan.FromDays(7 * weeklyWeeks))
                {
                    int week = CultureInfo.InvariantCulture.Calendar.GetWeekOfYear(t, CalendarWeekRule.FirstFourDayWeek, DayOfWeek.Monday);
                    if (weeks.Add(t.Year + "-W" + week)) continue;
                }
                del.Add(ordered[i]);
            }
            return del;
        }

        public static List<string> PlanRetention(string setDir, ArkConfig cfg, DateTime nowLocal)
        {
            var names = List(setDir);
            var expired = PlanPrune(names, nowLocal, cfg.KeepAllHours, cfg.KeepDailyDays, cfg.KeepWeeklyWeeks);
            if (expired.Count == 0) return expired;

            // The newest snapshot is already protected by PlanPrune. Only retire complete
            // snapshots when that newest one is complete. Keep any snapshot with an unknown state.
            var newest = Summary(setDir, names[names.Count - 1]);
            bool canRetireComplete = newest != null && newest.Errors == 0;
            return expired.Where(name =>
            {
                var summary = Summary(setDir, name);
                return summary != null && (summary.Errors > 0 || canRetireComplete);
            }).ToList();
        }

        public static void Delete(string setDir, string name)
        {
            if (!StampRx.IsMatch(name)) throw new ArgumentException("not a snapshot name: " + name);
            DeleteTree(Path.Combine(setDir, name));
            FileUtil.TryDelete(Path.Combine(setDir, name + ".manifest.tsv"));
            FileUtil.TryDelete(Path.Combine(setDir, name + ".ark.json"));
        }

        static void DeleteTree(string dir)
        {
            var d = new DirectoryInfo(L(dir));
            if (!d.Exists) return;
            foreach (var f in d.EnumerateFiles("*", SearchOption.AllDirectories))
                if ((f.Attributes & FileAttributes.ReadOnly) != 0) f.Attributes &= ~FileAttributes.ReadOnly;
            d.Delete(true);
        }
    }

    // One backup run: every set that's due (or all of them when forced), then retention.
    static class Job
    {
        [DllImport("kernel32.dll")] static extern bool SetPriorityClass(IntPtr process, uint cls);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();

        public static string ForceFlag { get { return Path.Combine(Suite.UserDir(AppId.Ark), "backup-now.flag"); } }

        static bool TargetReady(string target, out string reason)
        {
            reason = null;
            try
            {
                string root = Path.GetPathRoot(target);
                var drive = new DriveInfo(root);
                if (!drive.IsReady) { reason = "Drive " + root + " isn't available."; return false; }
                if (string.Equals(Path.GetFullPath(target).TrimEnd(Path.DirectorySeparatorChar), ArkConfig.DefaultTarget, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    reason = "Drive " + root + " must use NTFS for the default backup location. You can change the target in ark.ini.";
                    return false;
                }
                Directory.CreateDirectory(target);
                string probe = Path.Combine(target, ".ark-probe-" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                if (drive.AvailableFreeSpace < 2L * 1024 * 1024 * 1024) { reason = "Only " + Fmt.Size(drive.AvailableFreeSpace) + " free on " + root + "."; return false; }
                return true;
            }
            catch (Exception e) { reason = "Can't write to " + target + ": " + e.Message; return false; }
        }

        static void AlertOnce(ArkState st, string key, TimeSpan every, AlertInfo a)
        {
            string last;
            if (st.Alerted.TryGetValue(key, out last) && DateTime.UtcNow - Clock.Parse(last) < every) return;
            st.Alerted[key] = Clock.NowIso();
            a.Key = key;
            AlertStore.Raise(a);
        }

        public static int Run(bool force, string onlySet, Action<string> progress)
        {
            Mutex m;
            if (!Sync.Claim("ark.backup", out m)) { if (progress != null) progress("Another backup is already running."); return 2; }
            using (m)
            {
                try { SetPriorityClass(GetCurrentProcess(), 0x00100000); } catch (Exception) { }   // background CPU and disk priority
                string dir = Suite.MyDir;
                var cfg = ArkConfig.Load();
                var state = ArkState.Load(dir);
                if (File.Exists(ForceFlag)) { force = true; FileUtil.TryDelete(ForceFlag); }

                string reason;
                if (!TargetReady(cfg.Target, out reason))
                {
                    AlertOnce(state, "target", TimeSpan.FromHours(12), AlertStore.New(Sev.Critical, "Ark can't reach its backup drive", reason + " Backups are paused until it's back.", null).Act("retry", "Try again", false));
                    state.Save(dir);
                    WriteStatus(cfg, state, reason, false);
                    if (progress != null) progress(reason);
                    return 1;
                }

                bool playing = cfg.PauseWhileGaming && !force && GameState.Playing;
                bool waited = false;
                int failures = 0;
                foreach (var set in cfg.Sets)
                {
                    var ss = state.For(set.Name);
                    string setDir = Snapshots.SetDir(cfg.Target, set);
                    ss.RecoverLastSuccess(setDir);
                    if (onlySet != null && !set.Name.Equals(onlySet, StringComparison.OrdinalIgnoreCase)) continue;
                    var last = Clock.Parse(ss.LastSuccess);
                    bool due = force || onlySet != null || DateTime.UtcNow - last >= set.Every - TimeSpan.FromMinutes(5);
                    if (!due) continue;
                    if (playing && DateTime.UtcNow - last < set.Every + set.Every) { waited = true; continue; }
                    ss.LastRun = Clock.NowIso();
                    StatusStore.Write(States.Busy, "Backing up " + set.Name + "\u2026", "Started " + Fmt.Local(DateTime.UtcNow), null);
                    try
                    {
                        var r = Snapshots.Take(set, cfg.Target, cfg.MaxFileBytes, progress, CancellationToken.None);
                        ss.RecordSnapshot(r);
                        Log.Info(set.Name + ": snapshot " + r.Snapshot + ", " + r.Files + " files (" + r.Copied + " copied, " + Fmt.Size(r.CopiedBytes) + "), " + r.Errors + " errors, " + Fmt.Duration(r.Took));
                        if (progress != null) progress(set.Name + " · " + r.Copied + " changed files copied" + (r.Errors > 0 ? ", incomplete with " + Fmt.Plural(r.Errors, "error") : "") + ".");
                        if (r.Errors > 0)
                            AlertOnce(state, "skipped:" + set.Name, TimeSpan.FromHours(24), AlertStore.New(Sev.Warning,
                                "Incomplete backup of " + set.Name,
                                Fmt.Plural(r.Errors, "error") + " while reading files or folders. Ark preserves complete snapshots while the latest backup is incomplete.\n" + string.Join("\n", r.ErrorList.Take(5)), null));
                        foreach (var old in Snapshots.PlanRetention(setDir, cfg, DateTime.Now))
                        {
                            try { Snapshots.Delete(setDir, old); Log.Info(set.Name + ": removed old snapshot " + old); }
                            catch (Exception e) { Log.Warn(set.Name + ": couldn't remove " + old + ": " + e.Message); }
                        }
                    }
                    catch (Exception e)
                    {
                        failures++;
                        ss.LastError = e.Message;
                        Log.Error("backing up " + set.Name, e);
                        AlertOnce(state, "failed:" + set.Name, TimeSpan.FromHours(12), AlertStore.New(Sev.Warning, "Backup of " + set.Name + " failed", e.Message, null).Act("retry", "Try again", false));
                    }
                    state.Save(dir);
                }
                state.Save(dir);
                WriteStatus(cfg, state, null, waited);
                return failures == 0 ? 0 : 1;
            }
        }

        public static void WriteStatus(ArkConfig cfg, ArkState state, string targetProblem, bool waitingForGame)
        {
            var facts = new Dictionary<string, object>();
            facts["target"] = cfg.Target;
            try
            {
                var drive = new DriveInfo(Path.GetPathRoot(cfg.Target));
                if (drive.IsReady) facts["free"] = drive.AvailableFreeSpace;
            }
            catch (Exception) { }
            if (targetProblem != null)
            {
                StatusStore.Write(States.Alert, "Can't reach " + cfg.Target, targetProblem, facts);
                return;
            }
            var overdue = new List<string>();
            var failed = new List<string>();
            var incomplete = new List<string>();
            var never = new List<string>();
            DateTime newest = DateTime.MinValue;
            DateTime nextDue = DateTime.MaxValue;
            string nextSet = null;
            foreach (var set in cfg.Sets)
            {
                var ss = state.For(set.Name);
                var last = Clock.Parse(ss.LastSuccess);
                if (last == DateTime.MinValue) never.Add(set.Name);
                else
                {
                    if (last > newest) newest = last;
                    if (DateTime.UtcNow - last > set.Every + set.Every + TimeSpan.FromHours(1)) overdue.Add(set.Name);
                    if (last + set.Every < nextDue) { nextDue = last + set.Every; nextSet = set.Name; }
                }
                if (ss.LastError != null) failed.Add(set.Name);
                else if (ss.LastErrors > 0) incomplete.Add(set.Name);
            }
            string free = facts.ContainsKey("free") ? " \u00B7 " + Fmt.Size((long)facts["free"]) + " free" : "";
            string detail = cfg.Target + free + (nextSet != null ? " \u00B7 next: " + nextSet + (nextDue <= DateTime.UtcNow ? " (due now)" : " in " + Fmt.Duration(nextDue - DateTime.UtcNow)) : "");
            facts["sets"] = cfg.Sets.Count;
            facts["incomplete"] = incomplete.Count;
            if (failed.Count > 0) StatusStore.Write(States.Warn, "Last backup failed: " + string.Join(", ", failed), detail, facts);
            else if (incomplete.Count > 0) StatusStore.Write(States.Warn, "Incomplete backup of " + string.Join(", ", incomplete), detail, facts);
            else if (never.Count == cfg.Sets.Count) StatusStore.Write(States.Warn, "No backups yet", detail, facts);
            else if (overdue.Count > 0) StatusStore.Write(States.Warn, "Overdue: " + string.Join(", ", overdue), detail, facts);
            else if (never.Count > 0) StatusStore.Write(States.Warn, "Not backed up yet: " + string.Join(", ", never), detail, facts);
            else if (waitingForGame) StatusStore.Write(States.Ok, "Waiting for your game to finish \u00B7 last backup " + Fmt.Ago(newest), detail, facts);
            else StatusStore.Write(States.Ok, Fmt.Plural(cfg.Sets.Count, "folder") + " backed up \u00B7 last " + Fmt.Ago(newest), detail, facts);
        }
    }

    // Copying files back out of a snapshot.
    static class Restore
    {
        // Copies one snapshot file to dest. A different file already there is kept as
        // "name (before restore 2026-11-18 1530).ext". Returns false when dest already matched.
        public static bool File(string snapFile, string dest)
        {
            var src = new FileInfo(Snapshots.L(snapFile));
            var cur = new FileInfo(Snapshots.L(dest));
            if (cur.Exists)
            {
                if (cur.Length == src.Length && cur.LastWriteTimeUtc == src.LastWriteTimeUtc) return false;
                string keep = Path.Combine(Path.GetDirectoryName(dest), Path.GetFileNameWithoutExtension(dest) + " (before restore " + DateTime.Now.ToString("yyyy-MM-dd HHmm", CultureInfo.InvariantCulture) + ")" + Path.GetExtension(dest));
                int n = 2;
                while (System.IO.File.Exists(Snapshots.L(keep))) keep = Path.Combine(Path.GetDirectoryName(dest), Path.GetFileNameWithoutExtension(dest) + " (before restore " + n++ + ")" + Path.GetExtension(dest));
                System.IO.File.Move(Snapshots.L(dest), Snapshots.L(keep));
            }
            Directory.CreateDirectory(Snapshots.L(Path.GetDirectoryName(dest)));
            System.IO.File.Copy(Snapshots.L(snapFile), Snapshots.L(dest), false);
            var copied = new FileInfo(Snapshots.L(dest));
            if ((copied.Attributes & FileAttributes.ReadOnly) != 0) copied.Attributes &= ~FileAttributes.ReadOnly;
            return true;
        }

        // Restores a whole folder; returns how many files were put back.
        public static int Folder(string snapDir, string destDir, List<string> errors)
        {
            int count = 0;
            var root = new DirectoryInfo(Snapshots.L(snapDir));
            string prefix = root.FullName.TrimEnd('\\') + "\\";
            foreach (var f in root.EnumerateFiles("*", SearchOption.AllDirectories))
            {
                string rel = f.FullName.Substring(prefix.Length);
                try { if (File(f.FullName, Path.Combine(destDir, rel))) count++; }
                catch (Exception e) { errors.Add(rel + ": " + e.Message); }
            }
            return count;
        }
    }
}
