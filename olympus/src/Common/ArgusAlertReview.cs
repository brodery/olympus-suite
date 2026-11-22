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

        public static Dictionary<string, string> PendingIds(IEnumerable<ArgusPendingAlert> findings)
        {
            var saved = findings.ToList();
            var records = saved.Any(f => string.IsNullOrEmpty(f.AlertId))
                ? AlertStore.Recent(AppId.Argus, int.MaxValue) : new List<AlertInfo>();
            return saved.ToDictionary(f => f.Key, f => Id(f, records), StringComparer.Ordinal);
        }

        public static void ApplyStatus(StatusInfo status)
        {
            if (status == null || (status.State != States.Warn && status.State != States.Alert)
                || status.Facts == null || !status.Facts.ContainsKey("pending")) return;
            string dir = DisplayDirectory;
            var pending = J.Load<Dictionary<string, ArgusPendingAlert>>(Path.Combine(dir, "pending.json"));
            if (pending == null || pending.Count == 0) return;
            var ids = PendingIds(pending.Values);
            var dismissed = AlertReview.DismissedIds();
            var open = pending.Values.Where(f => !dismissed.Contains(ids[f.Key])).ToList();
            int critical = open.Count(f => f.Severity == Sev.Critical);
            status.State = critical > 0 ? States.Alert : open.Count > 0 ? States.Warn : States.Ok;
            status.Summary = critical > 0 ? Fmt.Plural(critical, "serious change") + " to review" +
                (open.Count > critical ? " (" + open.Count + " in all)" : "")
                : open.Count > 0 ? Fmt.Plural(open.Count, "change") + " to review" : "No unreviewed changes";
        }

        public static string DisplayDirectory
        {
            get
            {
                string shared = Suite.SharedDir(AppId.Argus);
                return File.Exists(Path.Combine(shared, "baseline.json")) ? shared : Suite.UserDir(AppId.Argus);
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

        static bool IsAlertId(string id) { return id != null && AlertId.IsMatch(id); }
    }
}
