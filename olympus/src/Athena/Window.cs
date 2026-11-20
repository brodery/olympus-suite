// Athena's window: the grade, every check grouped by topic, details and the fix for the one you
// pick, and app updates you can tick and install.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Athena
{
    sealed class AthenaWindow : AppWindow
    {
        readonly ListView list = Ui.List("|34", "Check|280", "Result|620");
        readonly TextBox detail = new TextBox();
        readonly Label grade = new Label();
        readonly Button fix;
        Report report;
        bool busy;

        public AthenaWindow() : base(AppInfo.Of(AppId.Athena), 1020, 720)
        {
            fix = Ui.Btn("Fix this…", (s, e) => FixSelected());
            Add(Ui.Btn("Check again", (s, e) => Recheck()), fix,
                Ui.Btn("Update apps…", (s, e) => UpdateApps()),
                Ui.Btn("Windows Security", (s, e) => Proc.Open("windowsdefender:")));
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(140)));
            Body.Controls.Add(layout);
            grade.AutoSize = true;
            grade.Font = new Font(Ui.Base.FontFamily, Ui.Base.Size * 2.2f, FontStyle.Bold);
            grade.Margin = new Padding(0, 0, 0, Ui.S(6));
            layout.Controls.Add(grade, 0, 0);
            list.ShowGroups = true;
            list.MultiSelect = false;
            list.SelectedIndexChanged += (s, e) => ShowDetail();
            list.DoubleClick += (s, e) => FixSelected();
            layout.Controls.Add(list, 0, 1);
            detail.Multiline = true;
            detail.ReadOnly = true;
            detail.ScrollBars = ScrollBars.Vertical;
            detail.Dock = DockStyle.Fill;
            detail.Margin = new Padding(0, Ui.S(6), 0, 0);
            layout.Controls.Add(detail, 0, 2);
        }

        protected override void RefreshView()
        {
            if (busy) return;
            report = J.Load<Report>(Reporter.ReportFile);
            if (report == null)
            {
                SetState(States.Off, "No report yet");
                grade.Text = "Checking…";
                if (Visible) Recheck();
                return;
            }
            Show(report);
        }

        void Show(Report r)
        {
            int issues = r.Checks.Count(c => c.State == "warn" || c.State == "bad");
            SetState(r.Grade == "A" || r.Grade == "B" ? States.Ok : r.Grade == "C" ? States.Warn : States.Alert, issues == 0 ? "Nothing to fix" : Fmt.Plural(issues, "thing") + " to improve");
            grade.Text = "Grade " + r.Grade + "  ·  " + r.Percent + "%";
            grade.ForeColor = r.Grade == "A" || r.Grade == "B" ? Ui.StateColor(States.Ok) : r.Grade == "C" ? Ui.StateColor(States.Warn) : Ui.StateColor(States.Alert);
            StatusBar.Text = "Checked " + Fmt.Local(Clock.Parse(r.Time)) + " · Olympus re-checks daily and tells you when something slips";
            list.BeginUpdate();
            list.Items.Clear();
            list.Groups.Clear();
            foreach (var g in r.Checks.GroupBy(c => c.Group))
            {
                var group = new ListViewGroup(g.Key, g.Key);
                list.Groups.Add(group);
                foreach (var c in g.OrderByDescending(c => c.State == "bad" ? 3 : c.State == "warn" ? 2 : 0))
                {
                    var it = new ListViewItem(new[] { c.State == "good" ? "✔" : c.State == "warn" ? "⚠" : c.State == "bad" ? "✖" : c.State == "info" ? "•" : "?", c.Name, c.Detail }, group) { Tag = c.Id };
                    it.ForeColor = c.State == "bad" ? Ui.StateColor(States.Alert) : c.State == "warn" ? Ui.StateColor(States.Warn) : c.State == "good" ? SystemColors.ControlText : Ui.Muted;
                    list.Items.Add(it);
                }
            }
            list.EndUpdate();
            ShowDetail();
        }

        Check Selected()
        {
            if (report == null || list.SelectedItems.Count == 0) return null;
            string id = list.SelectedItems[0].Tag as string;
            return report.Checks.FirstOrDefault(c => c.Id == id);
        }

        void ShowDetail()
        {
            var c = Selected();
            fix.Enabled = c != null && c.Action != null;
            fix.Text = c != null && c.ActionLabel != null ? c.ActionLabel : "Fix this…";
            if (c == null) { detail.Text = "Pick a check to see the details."; return; }
            var lines = new List<string> { c.Name + ": " + c.Detail };
            if (c.Fix != null) lines.Add("How to fix: " + c.Fix);
            lines.AddRange(c.Items.Select(i => "  • " + i));
            detail.Text = string.Join("\r\n", lines);
        }

        void Recheck()
        {
            if (busy) return;
            busy = true;
            SetState(States.Busy, "Checking (the app-update and network checks take up to a minute)…");
            Ui.Background(this, () => Reporter.Run(true, s => { try { BeginInvoke((Action)(() => StatusBar.Text = "Checking " + s + "…")); } catch (Exception) { } }), (r, err) =>
            {
                busy = false;
                if (err != null) { SetState(States.Error, "Couldn't finish: " + err.Message); return; }
                report = r;
                Show(r);
            });
        }

        void FixSelected()
        {
            var c = Selected();
            if (c == null || c.Action == null) return;
            if (c.Action == "winget") { UpdateApps(); return; }
            if (c.Action.StartsWith("asr-"))
            {
                string what = c.Action == "asr-audit"
                    ? "Add " + c.Items.Count + " Defender attack-surface rules in watch-only (audit) mode?\n\nThey block nothing; they log what they would have blocked, so you can see whether any would get in your way.\n\n" + string.Join("\n", c.Items.Select(i => "• " + i))
                    : "Switch on the audited Defender rules that didn't flag anything in the past week? Rules that did flag something stay in watch-only mode.";
                if (!Ui.Confirm(this, what)) return;
                StatusBar.Text = "Asking Windows for admin rights…";
                Ui.Background(this, () => Fixes.Run(c.Action), (code, err) => { StatusBar.Text = code == 0 ? "Done." : "That didn't work (or was cancelled)."; Recheck(); });
                return;
            }
            Fixes.Run(c.Action);
        }

        void UpdateApps()
        {
            var apps = report == null ? null : report.Checks.FirstOrDefault(x => x.Id == "apps");
            if (apps == null || apps.Items.Count == 0) { Ui.Info(this, "No app updates found at the last check."); return; }
            using (var d = new Form { Text = "Update apps", Font = Ui.Base, StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.None, ClientSize = new Size(Ui.S(640), Ui.S(420)), MinimizeBox = false })
            {
                var t = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1, Padding = new Padding(Ui.S(10)) };
                t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                d.Controls.Add(t);
                var intro = Ui.Lbl("Tick the apps to update. They install one after another in a console window (some may ask for admin rights).");
                intro.MaximumSize = new Size(Ui.S(600), 0);
                t.Controls.Add(intro);
                var box = new CheckedListBox { Dock = DockStyle.Fill, CheckOnClick = true };
                foreach (var i in apps.Items) box.Items.Add(i, true);
                t.Controls.Add(box);
                var go = Ui.Btn("Update the ticked apps", (s, e) => d.DialogResult = DialogResult.OK);
                t.Controls.Add(go);
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var ids = box.CheckedItems.Cast<string>().Select(i => { int a = i.LastIndexOf('['), b = i.LastIndexOf(']'); return a >= 0 && b > a ? i.Substring(a + 1, b - a - 1) : null; }).Where(x => x != null).ToList();
                if (ids.Count == 0) return;
                string cmd = string.Join(" & ", ids.Select(id => "winget upgrade --id " + id + " --source winget --accept-package-agreements")) + " & echo. & echo Done. Athena re-checks next time it runs. & pause";
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd) { UseShellExecute = true });
            }
        }
    }
}
