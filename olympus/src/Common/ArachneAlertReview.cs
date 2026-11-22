// Per-user acknowledgement for Arachne alerts. The engine's evidence and allow list live separately.
using System;
using System.Collections.Generic;
using System.Linq;

namespace Olympus
{
    static class ArachneAlertReview
    {
        public static List<AlertInfo> Open(int max)
        {
            var dismissed = AlertReview.DismissedIds();
            return Remaining(AlertStore.Recent(AppId.Arachne, int.MaxValue), dismissed).Take(max).ToList();
        }

        internal static IEnumerable<AlertInfo> Remaining(IEnumerable<AlertInfo> alerts, HashSet<string> dismissed)
        {
            return alerts.Where(a => !string.IsNullOrEmpty(a.Id) && !dismissed.Contains(a.Id));
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

