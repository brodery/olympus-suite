// Atlas's watch (Atlas.exe --watch, kept running by the hub): free space on every fixed drive each
// minute, a warning when one gets full (again daily while it stays that way, every 6 hours once
// it's nearly full), and every few hours a measure of the junk Atlas could clean.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Olympus.Atlas
{
    sealed class AtlasSettings
    {
        public int WarnPercent = 10, JunkHours = 6, JunkNoticeGb = 20, UnplayedDays = 60;
        public List<string> Ignore = new List<string>();

        public const string Defaults =
            "; Atlas settings. Changes apply within a minute.\r\n\r\n" +
            "[drives]\r\n" +
            "; Warn when a drive's free space drops below this share of its size (percent). The line never\r\n" +
            "; sits above 100 GB free or below 10 GB; \"nearly full\" is 3% (at most 25 GB, at least 2 GB).\r\n" +
            "warn_percent = 10\r\n" +
            "; Drive letters not to watch, e.g.: ignore = B, E\r\n" +
            "ignore =\r\n\r\n" +
            "[clean]\r\n" +
            "; How often Atlas measures the junk it could clean (hours), and from how much it mentions it (GB).\r\n" +
            "junk_check_hours = 6\r\n" +
            "junk_notice_gb = 20\r\n" +
            "; Steam games you haven't played for this many days show up under \"Worth a look\".\r\n" +
            "unplayed_days = 60\r\n";

        public static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Atlas), "settings.ini"); } }

        public static AtlasSettings Load()
        {
            var ini = Ini.LoadOrCreate(FilePath, Defaults);
            return new AtlasSettings
            {
                WarnPercent = Math.Max(1, Math.Min(50, ini.Int("drives", "warn_percent", 10))),
                Ignore = ini.List("drives", "ignore").Select(x => x.Trim().TrimEnd(':', '\\').ToUpperInvariant()).Where(x => x.Length > 0).ToList(),
                JunkHours = Math.Max(1, ini.Int("clean", "junk_check_hours", 6)),
                JunkNoticeGb = Math.Max(1, ini.Int("clean", "junk_notice_gb", 20)),
                UnplayedDays = Math.Max(7, ini.Int("clean", "unplayed_days", 60))
            };
        }
    }

    sealed class DriveRow
    {
        public string Root, Letter, Label;
        public long Total, Free;
        public int Level;
    }

    static class DriveWatch
    {
        public const long GB = 1L << 30;
        static long Clamp(long v, long lo, long hi) { return Math.Max(lo, Math.Min(hi, v)); }

        public static long WarnBelow(long total, int percent) { return Clamp(total / 100 * percent, 10 * GB, 100 * GB); }
        public static long CriticalBelow(long total) { return Clamp(total / 100 * 3, 2 * GB, 25 * GB); }

        // 0 room to spare, 1 getting full, 2 nearly full. Climbing back down a level takes 10% more
        // room than the line that was crossed, so a drive hovering at the line doesn't flap.
        public static int Level(long free, long total, int previous, int percent)
        {
            if (total <= 0) return 0;
            long warn = WarnBelow(total, percent), crit = CriticalBelow(total);
            if (free < crit) return 2;
            if (previous == 2 && free < crit + crit / 10) return 2;
            if (free < warn) return 1;
            if (previous >= 1 && free < warn + warn / 10) return 1;
            return 0;
        }

        // Alert when it gets worse, and again while it stays bad: daily, or every 6 hours when nearly full.
        public static bool ShouldAlert(int level, int previous, DateTime lastAlert, DateTime now)
        {
            if (level == 0) return false;
            if (level > previous) return true;
            return now - lastAlert > (level == 2 ? TimeSpan.FromHours(6) : TimeSpan.FromHours(24));
        }

        // Fixed drives; "all" includes small ones and the ones you told Atlas to ignore.
        public static List<DriveRow> Fixed(AtlasSettings s, bool all)
        {
            var list = new List<DriveRow>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    string letter = d.Name.Substring(0, 1).ToUpperInvariant();
                    if (!all && (d.TotalSize < 32 * GB || s.Ignore.Contains(letter))) continue;
                    list.Add(new DriveRow { Root = d.Name, Letter = letter, Label = d.VolumeLabel, Total = d.TotalSize, Free = d.TotalFreeSpace });
                }
                catch (Exception) { }
            }
            return list;
        }
    }

    sealed class DriveState { public int Level; public string Alerted; }

    sealed class AtlasState
    {
        public Dictionary<string, DriveState> Drives = new Dictionary<string, DriveState>();
        public string JunkNotice;
    }

    sealed class JunkLine { public string Id, Name; public long Bytes; }

    sealed class JunkReport
    {
        public string Measured;
        public long Bytes;
        public List<JunkLine> Items = new List<JunkLine>();
    }

    static class Watcher
    {
        public static string StateFile { get { return Path.Combine(Suite.UserDir(AppId.Atlas), "state.json"); } }
        public static string JunkFile { get { return Path.Combine(Suite.UserDir(AppId.Atlas), "junk.json"); } }

        // What the Clean up tab ticks by default (your own places only; admin ones need a prompt).
        public static JunkReport MeasureJunk()
        {
            var r = new JunkReport { Measured = Clock.NowIso() };
            foreach (var it in Catalog.Load().Where(i => i.Default && !i.Admin && i.Group == "junk"))
            {
                try
                {
                    Cleaner.Measure(it);
                    if (it.Blocked != null || it.Bytes == 0) continue;
                    r.Bytes += it.Bytes;
                    r.Items.Add(new JunkLine { Id = it.Id, Name = it.Name, Bytes = it.Bytes });
                }
                catch (Exception e) { Log.Error("measuring " + it.Id, e); }
            }
            return r;
        }

        static string Short(string root) { return root.TrimEnd('\\'); }

        public static int Run()
        {
            Mutex m;
            if (!Sync.Claim("atlas.watch", out m)) return 0;
            using (m)
            using (var stop = Sync.Listen("atlas.stop"))
            {
                var state = J.Load<AtlasState>(StateFile) ?? new AtlasState();
                if (state.Drives == null) state.Drives = new Dictionary<string, DriveState>();
                var junk = J.Load<JunkReport>(JunkFile);
                var started = DateTime.UtcNow;
                Log.Info("watching drive space");
                do
                {
                    try
                    {
                        var s = AtlasSettings.Load();
                        var now = DateTime.UtcNow;
                        var drives = DriveWatch.Fixed(s, false);
                        bool changed = false;
                        foreach (var d in drives)
                        {
                            DriveState ds;
                            if (!state.Drives.TryGetValue(d.Letter, out ds)) state.Drives[d.Letter] = ds = new DriveState();
                            d.Level = DriveWatch.Level(d.Free, d.Total, ds.Level, s.WarnPercent);
                            if (DriveWatch.ShouldAlert(d.Level, ds.Level, Clock.Parse(ds.Alerted), now))
                            {
                                RaiseSpace(d);
                                ds.Alerted = Clock.Iso(now);
                                changed = true;
                            }
                            if (d.Level != ds.Level) { ds.Level = d.Level; changed = true; }
                        }
                        bool due = junk == null ? now - started > TimeSpan.FromMinutes(5) : now - Clock.Parse(junk.Measured) > TimeSpan.FromHours(s.JunkHours);
                        if (due && !GameState.Playing)
                        {
                            junk = MeasureJunk();
                            J.Save(JunkFile, junk);
                            if (junk.Bytes >= s.JunkNoticeGb * DriveWatch.GB && now - Clock.Parse(state.JunkNotice) > TimeSpan.FromDays(7))
                            {
                                AlertStore.Raise(AlertStore.New(Sev.Notice, "Atlas can free " + Fmt.Size(junk.Bytes),
                                    "Temporary files and caches are taking " + Fmt.Size(junk.Bytes) + ". Open Atlas's Clean up tab to clear them.", "junk"));
                                state.JunkNotice = Clock.Iso(now);
                                changed = true;
                            }
                        }
                        if (changed) J.Save(StateFile, state);
                        WriteStatus(drives, junk);
                    }
                    catch (Exception e) { Log.Error("watch loop", e); }
                } while (!stop.WaitOne(60000));
                Log.Info("watcher stopped");
                StatusStore.Write(States.Off, "Stopped", null, null);
            }
            return 0;
        }

        static void RaiseSpace(DriveRow d)
        {
            string name = Short(d.Root);
            var a = d.Level == 2
                ? AlertStore.New(Sev.Critical, name + " is nearly full", "Only " + Fmt.Size(d.Free) + " left of " + Fmt.Size(d.Total) +
                    ". Games, updates and Windows itself misbehave when a drive fills up. Atlas shows what's using the space and clears out junk.", "space:" + d.Letter)
                : AlertStore.New(Sev.Warning, name + " is getting full", Fmt.Size(d.Free) + " left of " + Fmt.Size(d.Total) +
                    ". Atlas shows what's using the space and clears out junk.", "space:" + d.Letter);
            AlertStore.Raise(a.With("drive", d.Root));
        }

        static void WriteStatus(List<DriveRow> drives, JunkReport junk)
        {
            if (drives.Count == 0) { StatusStore.Write(States.Ok, "No fixed drives to watch", null, null); return; }
            var worst = drives.OrderByDescending(d => d.Level).ThenBy(d => (double)d.Free / Math.Max(1, d.Total)).First();
            string windows = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";
            var sys = drives.FirstOrDefault(d => d.Root.Equals(windows, StringComparison.OrdinalIgnoreCase)) ?? drives[0];
            string state = worst.Level == 2 ? States.Alert : worst.Level == 1 ? States.Warn : States.Ok;
            string summary = worst.Level == 2 ? Short(worst.Root) + " is nearly full · " + Fmt.Size(worst.Free) + " free"
                           : worst.Level == 1 ? Short(worst.Root) + " is getting full · " + Fmt.Size(worst.Free) + " free"
                           : "Drives have room · " + Short(sys.Root) + " " + Fmt.Size(sys.Free) + " free";
            string detail = string.Join(" · ", drives.Select(d => Short(d.Root) + " " + Fmt.Size(d.Free))) + " free" +
                            (junk != null && junk.Bytes >= 100L << 20 ? " · " + Fmt.Size(junk.Bytes) + " of junk to clean" : "");
            StatusStore.Write(state, summary, detail, null);
        }
    }
}
