using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Olympus
{
    // Acknowledgements are per-user, independent of alert logs and privileged engine state.
    static class AlertReview
    {
        public const string ChangedSignal = "alerts.review.changed";
        static string DirectoryPath { get { return Suite.UserDir(AppId.Olympus); } }

        sealed class InboxDismissals
        {
            public List<string> Dismissed = new List<string>();
        }

        public static HashSet<string> DismissedIds()
        {
            return Read(Path.Combine(DirectoryPath, "dismissed-alerts.json"), Path.Combine(DirectoryPath, "inbox.json"),
                Path.Combine(Suite.UserDir(AppId.Arachne), "dismissed-alerts.json"));
        }

        internal static HashSet<string> Read(string path, string legacyInbox, string legacyArachne)
        {
            var ids = new HashSet<string>(J.Load<List<string>>(path) ?? new List<string>(), StringComparer.Ordinal);
            var inbox = J.Load<InboxDismissals>(legacyInbox);
            if (inbox != null && inbox.Dismissed != null) ids.UnionWith(inbox.Dismissed);
            var arachne = J.Load<List<string>>(legacyArachne);
            if (arachne != null) ids.UnionWith(arachne);
            return ids;
        }

        public static void Dismiss(IEnumerable<string> ids)
        {
            // Serialize read/modify/write across the hub and any app window, even across sessions.
            using (var mutex = new Mutex(false, "Global\\Olympus.alert-review." + Suite.User.Sid))
            {
                bool acquired;
                try { acquired = mutex.WaitOne(3000); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("The alert list is busy. Try dismissing again.");
                try { Save(Path.Combine(DirectoryPath, "dismissed-alerts.json"), ids); }
                finally { mutex.ReleaseMutex(); }
            }
            Sync.Poke(ChangedSignal);
        }

        internal static void Save(string path, IEnumerable<string> ids)
        {
            var saved = File.Exists(path) ? J.Read<List<string>>(FileUtil.ReadShared(path)) : new List<string>();
            var known = new HashSet<string>(saved, StringComparer.Ordinal);
            var added = ids.Where(id => !string.IsNullOrEmpty(id) && known.Add(id)).ToList();
            if (added.Count == 0) return;
            saved.AddRange(added);
            J.Save(path, saved);
        }
    }
}
