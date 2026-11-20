// Argus resolves stale notices by ID and leaves their original alert records intact.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Olympus
{
    static class ArgusAlertReview
    {
        internal const string FileName = "resolved-alerts.json";
        const int MaxIds = 10000;
        static readonly Regex AlertId = new Regex(@"\A[0-9a-f]{16}\z");

        // The scanner holds its scan lock while recording resolutions.
        public static void RecordResolved(string dataDir, IEnumerable<string> ids)
        {
            string path = Path.Combine(dataDir, FileName);
            var previous = (J.Load<List<string>>(path) ?? new List<string>()).Where(IsAlertId).ToList();
            var known = new HashSet<string>(previous, StringComparer.Ordinal);
            var additions = ids.Where(id => IsAlertId(id) && known.Add(id)).ToList();
            if (additions.Count == 0) return;
            previous.AddRange(additions);
            if (previous.Count > MaxIds) previous.RemoveRange(0, previous.Count - MaxIds);
            J.Save(path, previous);
        }

        public static List<AlertInfo> Open(int max)
        {
            var resolved = ResolvedIds(Suite.Installed || Elevation.IsSystem);
            return Remaining(AlertStore.Recent(AppId.Argus, int.MaxValue), resolved).Take(max).ToList();
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
