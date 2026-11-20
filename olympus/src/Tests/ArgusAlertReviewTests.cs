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
            }
            finally { T.Cleanup(dir); }
        }
    }
}
