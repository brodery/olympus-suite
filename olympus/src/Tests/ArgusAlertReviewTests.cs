using System.Collections.Generic;
using System.IO;
using System.Linq;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class ArgusAlertReviewTests
    {
        public static void Run()
        {
            string dir = T.TempDir("argus-alert-review");
            try
            {
                const string retired = "0123456789abcdef";
                const string later = "fedcba9876543210";
                ArgusAlertReview.RecordResolved(dir, new[] { retired, "invalid" });
                ArgusAlertReview.RecordResolved(dir, new[] { retired });
                var saved = J.Load<List<string>>(Path.Combine(dir, ArgusAlertReview.FileName));
                T.True(saved != null && saved.SequenceEqual(new[] { retired }), "record only valid IDs once");

                var alerts = new[]
                {
                    new AlertInfo { App = "Argus", Id = retired, Key = "same-task" },
                    new AlertInfo { App = "Argus", Id = later, Key = "same-task" },
                    new AlertInfo { App = "Arachne", Id = retired, Key = "same-task" }
                };
                var remaining = ArgusAlertReview.Remaining(alerts, new HashSet<string>(saved ?? new List<string>())).ToList();
                T.True(remaining.SequenceEqual(alerts.Skip(1)), "retire the exact Argus notice only");

                var findings = new Olympus.Argus.Finding { Key = "same-task", AlertId = later, Kind = "new" };
                var reloaded = J.Read<Dictionary<string, ArgusPendingAlert>>(J.Write(
                    new Dictionary<string, Olympus.Argus.Finding> { { findings.Key, findings } }));
                T.True(reloaded[findings.Key].AlertId == later, "read the same Argus alert ID in another app");
                var legacy = new ArgusPendingAlert { Key = findings.Key, Seen = "2026-01-02T00:00:00Z" };
                alerts[0].Time = "2026-01-01T00:00:00Z";
                alerts[1].Time = "2026-01-02T00:00:01Z";
                T.True(ArgusAlertReview.Id(legacy, alerts.Take(2)) == later, "do not dismiss an older notice about a changed task");

                var data = new Olympus.Argus.ArgusData { Dir = dir };
                data.Pending[findings.Key] = findings;
                var old = ArgusAlertReview.PendingIds(data.Pending.Values);
                findings.AlertId = "1111111111111111";
                Olympus.Argus.Engine.RecordClosedAlerts(data, old);
                var resolved = J.Load<List<string>>(Path.Combine(dir, ArgusAlertReview.FileName));
                T.True(resolved.Contains(later) && !resolved.Contains(findings.AlertId), "close only the superseded notice");
            }
            finally { T.Cleanup(dir); }
        }
    }
}
