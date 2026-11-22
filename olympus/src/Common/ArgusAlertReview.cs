// Argus resolves stale notices by ID and leaves their original alert records intact.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Olympus
{
    public class ArgusPendingAlert
    {
        public string Key, AlertId, Seen, Severity;
    }

    static class ArgusAlertReview
    {
        internal const string FileName = "resolved-alerts.json";
        const int MaxIds = 10000;
        static readonly Regex AlertId = new Regex(@"\A[0-9a-f]{16}\z");

        // The scanner holds its scan lock while recording resolutions.
        public static void RecordResolved(string dataDir, IEnumerable<string> ids)
        {
            var candidates = ids.Where(IsAlertId).ToList();
            if (candidates.Count == 0) return;
            string path = Path.Combine(dataDir, FileName);
            var previous = (J.Load<List<string>>(path) ?? new List<string>()).Where(IsAlertId).ToList();
            var known = new HashSet<string>(previous, StringComparer.Ordinal);
            var additions = candidates.Where(known.Add).ToList();
            if (additions.Count == 0) return;
            previous.AddRange(additions);
            if (previous.Count > MaxIds) previous.RemoveRange(0, previous.Count - MaxIds);
            J.Save(path, previous);
        }

        public static HashSet<string> ResolvedIds()
        {
            return ResolvedIds(Suite.Installed || Elevation.IsSystem);
        }

        // Older findings have no AlertId. Use their key and creation time to avoid
        // matching a previous finding about the same task or startup entry.
        public static string Id(ArgusPendingAlert finding, IEnumerable<AlertInfo> records)
        {
            if (!string.IsNullOrEmpty(finding.AlertId)) return finding.AlertId;
            if (string.IsNullOrEmpty(finding.Key) || string.IsNullOrEmpty(finding.Seen)) return null;
            var first = records.Where(a => (a.Key ?? a.Get("key")) == finding.Key &&
                string.CompareOrdinal(a.Time, finding.Seen) >= 0).OrderBy(a => a.Time, StringComparer.Ordinal).FirstOrDefault();
            return first == null ? null : first.Id;
        }

        // Every finding's alert ID. Findings saved before IDs were recorded are matched to their alert by key
        // and time; once Olympus is installed, only in the protected ProgramData log (a record in your own
        // folder could be planted). Each scan gives such findings a lasting ID, so this lookup fades out.
        public static Dictionary<string, string> PendingIds(IEnumerable<ArgusPendingAlert> findings)
        {
            var saved = findings.ToList();
            var records = saved.Any(f => string.IsNullOrEmpty(f.AlertId)) ? LegacyRecords() : new List<AlertInfo>();
            return saved.ToDictionary(f => f.Key, f => Id(f, records), StringComparer.Ordinal);
        }

        internal static List<AlertInfo> LegacyRecords()
        {
            return Suite.Installed || Elevation.IsSystem ? AlertStore.RecentProtected(AppId.Argus) : AlertStore.Recent(AppId.Argus, int.MaxValue);
        }

        public static string NewId() { return Guid.NewGuid().ToString("N").Substring(0, 16); }

        // Argus's status and the folder it came from, for showing findings: the same folder the rows are read
        // from (DisplayDirectory), so a newer scan of your own (not installed, or run by hand) can't put its
        // rows beside the installed engine's, whose data the elevated actions change.
        public static StatusInfo ReadDisplayStatus(out string dir)
        {
            dir = DisplayDirectory;
            return J.Load<StatusInfo>(Path.Combine(dir, StatusStore.FileName));
        }

        // The window's summary from the findings it lists (dismissed ones already left out), so the summary
        // and the rows always come from the same pending list.
        public static void ApplyFindings(StatusInfo status, IEnumerable<ArgusPendingAlert> visible)
        {
            if (status == null) return;
            var open = visible.Select(f => new KeyValuePair<string, string>(f.AlertId, f.Severity)).ToList();
            if (open.Count == 0 && status.State != States.Warn && status.State != States.Alert) return;
            Summarize(status, open);
        }

        // Counts only the findings you haven't dismissed. The status names the exact findings it counted
        // ("open": "alertId:severity,..."); for a status written before that existed, 'dir' (the folder the
        // status came from, ReadDisplayStatus(out dir)) supplies that scan's pending list, used only when it
        // still holds as many findings as the status reported.
        public static void ApplyStatus(StatusInfo status, string dir)
        {
            if (status == null || (status.State != States.Warn && status.State != States.Alert)
                || status.Facts == null || !status.Facts.ContainsKey("pending")) return;
            List<KeyValuePair<string, string>> counted;   // alert ID (or null), severity
            if (status.Facts.ContainsKey("open"))
            {
                counted = new List<KeyValuePair<string, string>>();
                foreach (var part in Convert.ToString(status.Facts["open"] ?? "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int colon = part.IndexOf(':');
                    if (colon < 0) return;
                    string id = part.Substring(0, colon);
                    counted.Add(new KeyValuePair<string, string>(IsAlertId(id) ? id : null, part.Substring(colon + 1)));
                }
            }
            else
            {
                if (string.IsNullOrEmpty(dir)) return;
                var pending = J.Load<Dictionary<string, ArgusPendingAlert>>(Path.Combine(dir, "pending.json"));
                if (pending == null) return;
                int reported;
                try { reported = Convert.ToInt32(status.Facts["pending"]); }
                catch (Exception) { return; }
                if (reported != pending.Count) return;   // a newer or older scan's list: don't mix them
                var ids = PendingIds(pending.Values);
                counted = pending.Values.Select(f => new KeyValuePair<string, string>(ids[f.Key], f.Severity)).ToList();
            }
            if (counted.Count == 0) return;
            var dismissed = AlertReview.DismissedIds();
            Summarize(status, counted.Where(f => f.Key == null || !dismissed.Contains(f.Key)).ToList());
        }

        // State and summary from the open findings (alert ID, severity).
        static void Summarize(StatusInfo status, List<KeyValuePair<string, string>> open)
        {
            int critical = open.Count(f => f.Value == Sev.Critical);
            status.State = critical > 0 ? States.Alert : open.Count > 0 ? States.Warn : States.Ok;
            status.Summary = critical > 0 ? Fmt.Plural(critical, "serious change") + " to review" +
                (open.Count > critical ? " (" + open.Count + " in all)" : "")
                : open.Count > 0 ? Fmt.Plural(open.Count, "change") + " to review" : "No unreviewed changes";
        }

        // Where the findings shown to you live: once Olympus is installed, always the installed engine's
        // protected ProgramData folder (the one its elevated actions change); before that, yours.
        public static string DisplayDirectory
        {
            get
            {
                string shared = Suite.SharedDir(AppId.Argus);
                return Suite.Installed || File.Exists(Path.Combine(shared, "baseline.json")) ? shared : Suite.UserDir(AppId.Argus);
            }
        }

        public static bool IsResolved(string alertId, bool sharedOnly)
        {
            return ResolvedIds(sharedOnly).Contains(alertId);
        }

        internal static IEnumerable<AlertInfo> Remaining(IEnumerable<AlertInfo> alerts, HashSet<string> resolved)
        {
            string app = AppInfo.Of(AppId.Argus).Name;
            return alerts.Where(alert => alert.App != app || !resolved.Contains(alert.Id));
        }

        static HashSet<string> ResolvedIds(bool sharedOnly)
        {
            string dir = sharedOnly ? Suite.SharedDir(AppId.Argus) : Suite.UserDir(AppId.Argus);
            string path = Path.Combine(dir, FileName);
            var ids = new HashSet<string>(StringComparer.Ordinal);
            if (sharedOnly && (!AlertStore.IsProtected(Suite.ProgramDataRoot, true)
                || !AlertStore.IsProtected(dir, true) || !AlertStore.IsProtected(path, false))) return ids;
            var resolved = J.Load<List<string>>(path);
            if (resolved != null) ids.UnionWith(resolved.Where(IsAlertId));
            return ids;
        }

        internal static bool IsAlertId(string id) { return id != null && AlertId.IsMatch(id); }
    }
}
