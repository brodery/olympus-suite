// Arachne's window: is the tripwire armed, which files it watches (and the decoys), recent alerts,
// and a test button that proves it works.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Arachne
{
    sealed class ArachneWindow : AppWindow
    {
        readonly TabControl tabs = new TabControl();
        readonly ListView files = Ui.Empty(Ui.List("What|300", "File|560*", "Kind|80"), "No login files found to watch.");
        readonly ListView alerts = Ui.Empty(Ui.List("When|140", "Level|80", "What|620"), "No alerts: nothing unexpected has read these files.");
        readonly Label explain = new Label();
        readonly Button dismiss;

        public ArachneWindow() : base(AppInfo.Of(AppId.Arachne), 1020, 620)
        {
            AutoRefresh(15);
            Activated += (s, e) => RefreshNow();
            dismiss = Ui.Btn("Dismiss selected alerts", (s, e) => DismissSelected());
            dismiss.Enabled = false;
            Add(Ui.Btn("Test the tripwire", (s, e) => RunTest()), dismiss);
            alerts.SelectedIndexChanged += (s, e) => UpdateDismissButton();
            tabs.SelectedIndexChanged += (s, e) => UpdateDismissButton();
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Body.Controls.Add(layout);
            explain.AutoSize = true;
            explain.MaximumSize = new System.Drawing.Size(Ui.S(980), 0);
            explain.Margin = new Padding(Ui.S(2), 0, 0, Ui.S(8));
            explain.Text = "Password-stealing malware (often a fake game, crack or \"try my game\" download) goes straight for the files below. Windows now notes every program that reads them; " +
                           "Arachne raises the alarm when it isn't the file's own program, or when anything touches a decoy.";
            layout.Controls.Add(explain, 0, 0);
            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Ui.Tab("Watched files", files));
            tabs.TabPages.Add(Ui.Tab("Alerts", alerts));
            layout.Controls.Add(tabs, 0, 1);
        }

        protected override void RefreshView()
        {
            var st = J.Load<SetupState>(Tripwire.SetupFile);
            var status = StatusStore.Read(AppId.Arachne);
            var list = ArachneAlertReview.Open(200);
            ArachneAlertReview.ApplyStatus(status, list);
            if (st == null) SetState(States.Off, "Not set up yet \u2014 install.cmd sets up the tripwire (it needs admin rights once)");
            else if (status == null || DateTime.UtcNow - status.UpdatedUtc > TimeSpan.FromMinutes(5)) SetState(States.Warn, "Set up, but the engine isn't running (its scheduled task restarts it within 5 minutes)");
            else SetState(status.State, status.Summary);
            StatusBar.Text = status != null ? status.Detail : "";
            List<Target> targets;
            if (st != null) targets = st.Targets;
            else { var cat = Catalog.Load(); targets = cat.Targets().Concat(cat.DecoysToPlace()).ToList(); }
            Ui.Fill(files, targets.Select(t => Ui.Row(t.Path, t.Label.Length > 0 ? char.ToUpperInvariant(t.Label[0]) + t.Label.Substring(1) : t.Label, t.Path + (t.Folder ? "\\*" : ""), t.Kind)).ToList());
            tabs.TabPages[0].Text = (st == null ? "Would watch (" : "Watched files (") + targets.Count + ")";
            Ui.Fill(alerts, list.Select(a =>
            {
                var it = Ui.Row(a.Id, Fmt.Local(a.TimeUtc), Ui.SevWord(a.Severity), a.Title);
                it.ToolTipText = a.Body;
                if (a.Severity == Sev.Critical) it.ForeColor = Ui.StateColor(States.Alert);
                return it;
            }).ToList());
            tabs.TabPages[1].Text = "Alerts (" + list.Count + ")";
            UpdateDismissButton();
        }

        protected override void HandleRequest(string request)
        {
            if (request.StartsWith("alert:", StringComparison.Ordinal))
            {
                tabs.SelectedIndex = 1;
                RefreshNow();
                var row = alerts.Items.Cast<ListViewItem>().FirstOrDefault(i => Equals(i.Tag, request.Substring(6)));
                if (row != null)
                {
                    alerts.SelectedItems.Clear();
                    row.Selected = true;
                    row.EnsureVisible();
                }
            }
            base.HandleRequest(request);
        }

        void UpdateDismissButton()
        {
            dismiss.Enabled = tabs.SelectedIndex == 1 && alerts.SelectedItems.Count > 0;
        }

        void DismissSelected()
        {
            var ids = alerts.SelectedItems.Cast<ListViewItem>().Select(row => row.Tag as string).ToArray();
            if (ids.Length == 0) return;
            try { AlertReview.Dismiss(ids); }
            catch (Exception e)
            {
                Log.Error("dismissing Arachne alerts", e);
                Ui.Warn(this, "Couldn't save the dismissal. The alerts are still open.");
                return;
            }
            RefreshNow();
        }

        void RunTest()
        {
            if (!File.Exists(Tripwire.SetupFile)) { Ui.Info(this, "The tripwire isn't set up yet. Run install.cmd in C:\\Claude\\olympus first."); return; }
            StatusBar.Text = "Reading a decoy file and waiting for the engine to notice (up to 20 seconds)\u2026";
            Ui.Background(this, () => Program.Test(), (code, err) =>
            {
                if (code == 0) Ui.Info(this, "It works: Arachne caught the test read within seconds.");
                else Ui.Warn(this, "The engine didn't report the test read. Check that the \"\\Olympus\\Arachne\" scheduled task is running.");
                RefreshNow();
            });
        }
    }
}
