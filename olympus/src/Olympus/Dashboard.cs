// The Olympus dashboard: a tile for every guardian (click to open it) and one inbox for every
// alert, with each alert's own buttons.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Hub
{
    sealed class Dashboard : AppWindow
    {
        readonly HubApp hub;
        readonly Dictionary<AppId, Tile> tiles = new Dictionary<AppId, Tile>();
        readonly ListView alerts = Ui.Empty(Ui.List("When|130", "App|86", "Level|80", "What|520"), "No alerts. New ones from any guardian show up here.");
        readonly FlowLayoutPanel alertButtons = new FlowLayoutPanel();
        readonly TextBox alertDetail = new TextBox();
        readonly Label alertsTitle = new Label();
        readonly ToolTip tileTips = new ToolTip { InitialDelay = 400, AutoPopDelay = 20000 };
        List<AlertInfo> shown = new List<AlertInfo>();
        bool collecting;

        public Dashboard(HubApp hub) : base(AppInfo.Of(AppId.Olympus), 1000, 800)
        {
            this.hub = hub;
            AutoRefresh(hub == null ? 10 : 0);
            Add(Ui.Btn("Check a link or message…", (s, e) => Launch.Command(AppId.Sibyl, "")),
                Ui.Btn("Back up now", (s, e) => { Launch.Command(AppId.Ark, "--backup-now"); StatusBar.Text = "Asked Ark to back up now."; }),
                Ui.Btn("Scan for hijacks", (s, e) => { Launch.Command(AppId.Argus, "--scan-now"); StatusBar.Text = "Asked Argus to scan now."; }),
                Ui.Btn("Report card", (s, e) => Launch.Open(AppId.Athena, null)),
                Ui.Btn("Free up space", (s, e) => Launch.Open(AppId.Atlas, "clean")),
                Ui.Btn("Game mode on/off", (s, e) => Launch.Command(AppId.Ares, "--toggle")),
                Ui.Btn("Settings", (s, e) => Proc.Open(HubSettings.FilePath)));

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Body.Controls.Add(layout);

            int tileRows = (AppInfo.Guardians.Count() + 2) / 3;
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = tileRows, AutoSize = true, Margin = new Padding(0, 0, 0, Ui.S(8)) };
            for (int i = 0; i < 3; i++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            for (int i = 0; i < tileRows; i++) grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            int n = 0;
            foreach (var app in AppInfo.Guardians)
            {
                var id = app.Id;
                var t = new Tile(app) { Dock = DockStyle.Fill, Margin = new Padding(Ui.S(3)) };
                t.Click += (s, e) => Launch.Open(id, null);
                tiles[id] = t;
                grid.Controls.Add(t, n % 3, n / 3);
                n++;
            }
            layout.Controls.Add(grid, 0, 0);

            var head = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, Ui.S(4)) };
            alertsTitle.Text = "Alerts";
            alertsTitle.Font = Ui.Big;
            alertsTitle.AutoSize = true;
            alertsTitle.Margin = new Padding(0, Ui.S(4), Ui.S(16), 0);
            head.Controls.Add(alertsTitle);
            head.Controls.Add(Ui.Btn("Dismiss", (s, e) => DismissSelected()));
            head.Controls.Add(Ui.Btn("Dismiss all shown", (s, e) =>
            {
                if (shown.Count > 0 && Ui.Confirm(this, "Dismiss all " + shown.Count + " alerts in the list?")) DismissAlerts(shown.Select(a => a.Id));
            }));
            layout.Controls.Add(head, 0, 1);

            alerts.SelectedIndexChanged += (s, e) => ShowSelected();
            alerts.DoubleClick += (s, e) => { var a = Selected(); if (a != null) OpenFor(a); };
            alerts.KeyDown += (s, e) => { if (e.KeyCode == Keys.Delete) DismissSelected(); };
            layout.Controls.Add(alerts, 0, 2);

            var detail = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1, RowCount = 2, Margin = new Padding(0, Ui.S(6), 0, 0) };
            alertDetail.Multiline = true;
            alertDetail.ReadOnly = true;
            alertDetail.BorderStyle = BorderStyle.None;
            alertDetail.BackColor = SystemColors.Control;
            alertDetail.Dock = DockStyle.Fill;
            alertDetail.Height = Ui.S(58);
            alertDetail.ScrollBars = ScrollBars.Vertical;
            alertDetail.Text = "Select an alert to see what happened and what you can do about it.";
            detail.Controls.Add(alertDetail, 0, 0);
            alertButtons.AutoSize = true;
            alertButtons.Dock = DockStyle.Fill;
            alertButtons.Margin = new Padding(0, Ui.S(4), 0, 0);
            detail.Controls.Add(alertButtons, 0, 1);
            layout.Controls.Add(detail, 0, 3);

            StatusBar.Text = "Olympus " + Suite.Version + " · running from " + Suite.BinDir + (Suite.Installed ? "" : " · not installed yet (run install.cmd)");

            if (hub != null)
            {
                Action changed = () => { if (!IsDisposed) RefreshView(); };
                Action arrived = () => { if (!IsDisposed) LoadAlerts(); };
                hub.Changed += changed;
                hub.AlertsArrived += arrived;
                FormClosed += (s, e) => { hub.Changed -= changed; hub.AlertsArrived -= arrived; };
            }
        }

        protected override void RefreshView()
        {
            if (hub != null && hub.AppStates.Count > 0)
            {
                Apply(hub.AppStates, hub.OverallState, hub.OverallText);
            }
            else if (hub == null && !Visible)
            {
                var states = Overview.Collect();   // snapshot: synchronously
                string text;
                Apply(states, Overview.Overall(states, Inbox.Count(), out text), text);
            }
            else if (!collecting)
            {
                collecting = true;
                Ui.Background(this, () => Overview.Collect(), (states, err) =>
                {
                    collecting = false;
                    if (states == null) return;
                    string text;
                    Apply(states, Overview.Overall(states, Inbox.Count(), out text), text);
                });
            }
            LoadAlerts();
        }

        void Apply(List<AppState> states, string overall, string text)
        {
            foreach (var st in states)
            {
                Tile t;
                if (!tiles.TryGetValue(st.App.Id, out t)) continue;
                t.Model = st;
                t.Invalidate();
                // the whole text, for when the tile has to cut it short
                string tip = st.App.Name + " — " + st.App.Role + "\n" + st.Summary + (string.IsNullOrEmpty(st.Detail) ? "" : "\n" + st.Detail);
                if (tileTips.GetToolTip(t) != tip) tileTips.SetToolTip(t, tip);
            }
            SetState(overall, text);
        }

        void LoadAlerts()
        {
            shown = Inbox.Open(150).Take(400).ToList();
            var rows = new List<ListViewItem>();
            foreach (var a in shown)
            {
                var it = Ui.Row(a.Id, Fmt.Local(a.TimeUtc), a.App ?? "", Ui.SevWord(a.Severity), a.Title ?? "");
                if (a.Severity == Sev.Critical || a.Severity == Sev.Warning) it.ForeColor = Ui.SevColor(a.Severity);
                rows.Add(it);
            }
            Ui.Fill(alerts, rows);
            alertsTitle.Text = shown.Count == 0 ? "Alerts — none" : "Alerts (" + shown.Count + ")";
            ShowSelected();
        }

        AlertInfo Selected()
        {
            if (alerts.SelectedItems.Count == 0) return null;
            string id = alerts.SelectedItems[0].Tag as string;
            return shown.FirstOrDefault(a => a.Id == id);
        }

        AlertInfo detailFor;
        void ShowSelected()
        {
            var a = Selected();
            if (a == detailFor && a != null) return;
            detailFor = a;
            alertButtons.Controls.Clear();
            if (a == null)
            {
                alertDetail.Text = shown.Count == 0 ? "" : "Select an alert to see what happened and what you can do about it.";
                return;
            }
            alertDetail.Text = a.Title + "\r\n" + (a.Body ?? "");
            foreach (var act in a.Actions ?? new List<AlertAction>())
            {
                if (act == null) continue;
                var action = act;
                var alert = a;
                alertButtons.Controls.Add(Ui.Btn(act.Label + (act.Elevate ? " (admin)" : ""), (s, e) => RunAction(alert, action)));
            }
            var app = AppInfo.Find(a.App);
            if (app != null && app.Id != AppId.Olympus)
                alertButtons.Controls.Add(Ui.Btn("Open " + app.Name, (s, e) => OpenFor(a)));
            alertButtons.Controls.Add(Ui.Btn("Dismiss", (s, e) => DismissSelected()));
        }

        void OpenFor(AlertInfo a)
        {
            var app = AppInfo.Find(a.App);
            if (app != null) Launch.Open(app.Id, "alert:" + a.Id);
        }

        void RunAction(AlertInfo a, AlertAction act)
        {
            if ((act.Id == "disable" || act.Id == "allow" || act.Id == "block" ||
                act.Id == "kill" || act.Id == "ignore" || act.Id == "delete") &&
                !Ui.Confirm(this, act.Label + "?\n\n" + a.Title + "\n\n" + a.Body)) return;
            StatusBar.Text = "Working: " + act.Label + "…";
            Ui.Background(this, () => Launch.Action(a, act), (msg, err) =>
            {
                if (err != null) msg = err.Message;
                if (msg != null) { StatusBar.Text = "Didn't finish: " + act.Label; Ui.Warn(this, msg); return; }
                StatusBar.Text = "Done: " + act.Label + " (" + a.App + ")";
                if (act.Id != "show" && act.Id != "scan" && act.Id != "retry") DismissAlerts(new[] { a.Id });
            });
        }

        void DismissSelected()
        {
            var ids = alerts.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as string).Where(x => x != null).ToList();
            if (ids.Count > 0) DismissAlerts(ids);
        }

        void DismissAlerts(IEnumerable<string> ids)
        {
            try { AlertReview.Dismiss(ids); }
            catch (Exception e) { Ui.Warn(this, "Couldn't save the dismissal. " + e.Message); return; }
            detailFor = null;
            LoadAlerts();
        }
    }

    // One guardian on the dashboard: icon, name, role, and how it's doing.
    sealed class Tile : Control
    {
        public AppState Model;
        readonly AppInfo app;
        readonly Bitmap icon;
        bool hover;

        public Tile(AppInfo app)
        {
            this.app = app;
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true);
            Cursor = Cursors.Hand;
            icon = IconArt.Draw(app.Id, Ui.S(40));
            Height = Ui.S(96);
            MinimumSize = new Size(Ui.S(200), Ui.S(96));
            BackColor = SystemColors.Window;
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            string state = Model == null ? States.Off : Model.State;
            using (var bg = new SolidBrush(hover ? Color.FromArgb(0xF3, 0xF6, 0xFB) : SystemColors.Window)) g.FillRectangle(bg, r);
            using (var border = new Pen(hover ? app.Bottom : Color.FromArgb(0xD9, 0xD9, 0xD9))) g.DrawRectangle(border, r);
            using (var stripe = new SolidBrush(Ui.StateColor(state))) g.FillRectangle(stripe, 1, 1, Ui.S(4), Height - 2);
            int x = Ui.S(14);
            g.DrawImage(icon, x, (Height - icon.Height) / 2);
            int tx = x + icon.Width + Ui.S(10);
            int w = Width - tx - Ui.S(8);
            TextRenderer.DrawText(g, app.Name, Ui.Big, new Point(tx, Ui.S(8)), SystemColors.ControlText);
            int nameW = TextRenderer.MeasureText(app.Name, Ui.Big).Width;
            TextRenderer.DrawText(g, app.Role, Ui.Base, new Rectangle(tx + nameW, Ui.S(11), Math.Max(0, w - nameW), Ui.S(18)), Ui.Muted, TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            string summary = Model == null ? "Checking…" : Model.Summary;
            TextRenderer.DrawText(g, "● " + summary, Ui.Base, new Rectangle(tx, Ui.S(34), w, Ui.S(20)), Ui.StateColor(state), TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            // the details get two lines, broken between words; hover the tile for all of it
            string detail = Model == null ? app.Blurb : (string.IsNullOrEmpty(Model.Detail) ? app.Blurb : Model.Detail);
            TextRenderer.DrawText(g, detail, Ui.Base, new Rectangle(tx, Ui.S(54), w, Height - Ui.S(58)), Ui.Muted,
                TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }
    }
}
