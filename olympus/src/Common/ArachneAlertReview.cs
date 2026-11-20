// Per-user acknowledgement for Arachne alerts. The engine's evidence and allow list live separately.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Olympus
{
    static class ArachneAlertReview
    {
        public const string ChangedSignal = "arachne.alerts.dismissed";

        sealed class InboxDismissals
        {
            public List<string> Dismissed = new List<string>();
        }

        static string UserFile { get { return Path.Combine(Suite.UserDir(AppId.Arachne), "dismissed-alerts.json"); } }

        public static HashSet<string> DismissedIds()
        {
            return ReadDismissed(UserFile, Path.Combine(Suite.UserDir(AppId.Olympus), "inbox.json"));
        }

        internal static HashSet<string> ReadDismissed(string userFile, string inboxFile)
        {
            var inbox = J.Load<InboxDismissals>(inboxFile);
            var dismissed = new HashSet<string>(J.Load<List<string>>(userFile) ?? new List<string>(), StringComparer.Ordinal);
            if (inbox != null && inbox.Dismissed != null) dismissed.UnionWith(inbox.Dismissed);
            return dismissed;
        }

        public static List<AlertInfo> Open(int max)
        {
            var dismissed = DismissedIds();
            return Remaining(AlertStore.Recent(AppId.Arachne, int.MaxValue), dismissed).Take(max).ToList();
        }

        internal static IEnumerable<AlertInfo> Remaining(IEnumerable<AlertInfo> alerts, HashSet<string> dismissed)
        {
            return alerts.Where(a => !string.IsNullOrEmpty(a.Id) && !dismissed.Contains(a.Id));
        }

        public static void Dismiss(IEnumerable<string> ids)
        {
            SaveDismissed(UserFile, ids);
            Sync.Poke(ChangedSignal);
        }

        // The Arachne window is the only writer of this file. Olympus reads it alongside its inbox.
        internal static void SaveDismissed(string path, IEnumerable<string> ids)
        {
            var dismissed = J.Load<List<string>>(path) ?? new List<string>();
            var known = new HashSet<string>(dismissed, StringComparer.Ordinal);
            dismissed.AddRange(ids.Where(id => !string.IsNullOrEmpty(id) && known.Add(id)));
            if (dismissed.Count > 2000) dismissed.RemoveRange(0, dismissed.Count - 2000);
            J.Save(path, dismissed);
        }

        public static void ApplyStatus(StatusInfo status, IEnumerable<AlertInfo> open)
        {
            // An acknowledgement can clear the alert badge, but only while the engine is armed.
            if (status == null || (status.State != States.Ok && status.State != States.Alert)) return;
            int critical = open.Count(a => a.Severity == Sev.Critical);
            if (critical > 0)
            {
                status.State = States.Alert;
                status.Summary = Fmt.Plural(critical, "suspicious read") + " to review";
            }
            else if (status.State == States.Alert)
            {
                status.State = States.Ok;
                status.Summary = "Tripwire armed";
            }
        }
    }
}

