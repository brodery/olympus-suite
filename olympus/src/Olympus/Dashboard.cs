// The Olympus dashboard. Overview: a tile for every app (click to open it, right-click to
// switch it on or off, start or stop it) and one inbox for every alert, with each alert's own
// buttons. Apps: every app in one list, with Enable/Disable, Start/Stop and Run.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Hub
{
    sealed class Dashboard : AppWindow
    {
        const int Columns = 4;
        readonly HubApp hub;
        readonly Dictionary<string, Tile> tiles = new Dictionary<string, Tile>(StringComparer.OrdinalIgnoreCase);
        readonly TableLayoutPanel grid = new TableLayoutPanel();
        readonly ListView alerts = Ui.Empty(Ui.List("When|130", "App|86", "Level|80", "What|520"), "No alerts. New ones from any app show up here.");
        readonly FlowLayoutPanel alertButtons = new FlowLayoutPanel();
        readonly TextBox alertDetail = new TextBox();
        readonly Label alertsTitle = new Label();
        readonly ToolTip tileTips = new ToolTip { InitialDelay = 400, AutoPopDelay = 20000 };
        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };
        readonly ListView apps = Ui.Empty(Ui.List("App|120", "Kind|130", "On|50", "Running|70", "Status|260", "Details|300*"), "Checking…");
        readonly TextBox appDetail = new TextBox();
        Button btnOpen, btnStart, btnStop, btnEnable, btnDisable, btnRun, btnLog;
        readonly ImageList appPictures = new ImageList { ColorDepth = ColorDepth.Depth32Bit };
        List<AlertInfo> shown = new List<AlertInfo>();
        List<AppState> current = new List<AppState>();
        string tileNames = "";
        bool collecting, working;

        public Dashboard(HubApp hub) : base(AppInfo.Of(AppId.Olympus), 1100, 860)
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

            Body.Controls.Add(tabs);
            tabs.TabPages.Add(Ui.Tab("Overview", BuildOverview()));
            tabs.TabPages.Add(Ui.Tab("Apps", BuildApps()));

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

        Control BuildOverview()
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            grid.Dock = DockStyle.Fill;
            grid.ColumnCount = Columns;
            grid.AutoSize = true;
            grid.Margin = new Padding(0, 0, 0, Ui.S(8));
            for (int i = 0; i < Columns; i++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / Columns));
            // the suite's own straight away; registered apps join on the first refresh
            LayTiles(AppInfo.Guardians.Select(AppRegistry.FromSuite).ToList());
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
            return layout;
        }

        Control BuildApps()
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var intro = Ui.Lbl("Enable and Disable stick after a restart; Start and Stop act now. The SYSTEM apps (Argus, Ark, Athena, Cerberus, Arachne) ask for admin rights. Disable on Aegis pauses filtering: DNS keeps working.", true);
            intro.MaximumSize = new Size(Ui.S(1040), 0);
            intro.Margin = new Padding(0, 0, 0, Ui.S(6));
            layout.Controls.Add(intro, 0, 0);

            var bar = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 0, 0, Ui.S(4)) };
            btnOpen = Ui.Btn("Open", (s, e) => { var st = SelectedApp(); if (st != null) OpenApp(st.Entry); });
            btnStart = Ui.Btn("Start", (s, e) => Act("start"));
            btnStop = Ui.Btn("Stop", (s, e) => Act("stop"));
            btnEnable = Ui.Btn("Enable", (s, e) => Act("enable"));
            btnDisable = Ui.Btn("Disable", (s, e) => Act("disable"));
            btnRun = Ui.Btn("Run", (s, e) => Act("run"));
            btnLog = Ui.Btn("Show log", (s, e) => { var st = SelectedApp(); if (st != null && st.Entry.LogPath != null) Proc.Open(st.Entry.LogPath); });
            bar.Controls.AddRange(new Control[] { btnOpen, btnStart, btnStop, btnEnable, btnDisable, btnRun, btnLog });
            bar.Controls.Add(Ui.Btn("Edit my apps list", (s, e) =>
            {
                try { Ini.LoadOrCreate(AppRegistry.UserFile, AppRegistry.UserTemplate); } catch (Exception) { }
                Proc.Open(AppRegistry.UserFile);
            }));
            layout.Controls.Add(bar, 0, 1);

            apps.MultiSelect = false;
            apps.SmallImageList = appPictures;
            appPictures.ImageSize = new Size(Ui.S(16), Ui.S(16));
            apps.SelectedIndexChanged += (s, e) => ShowApp();
            apps.DoubleClick += (s, e) => { var st = SelectedApp(); if (st != null) { if (st.Entry.Kind == AppKind.Launcher) Act("run"); else OpenApp(st.Entry); } };
            layout.Controls.Add(apps, 0, 2);

            appDetail.Multiline = true;
            appDetail.ReadOnly = true;
            appDetail.BorderStyle = BorderStyle.None;
            appDetail.BackColor = SystemColors.Control;
            appDetail.Dock = DockStyle.Fill;
            appDetail.Height = Ui.S(74);
            appDetail.Margin = new Padding(0, Ui.S(6), 0, 0);
            layout.Controls.Add(appDetail, 0, 3);
            ShowApp();
            return layout;
        }

        // ------------------------------------------------------------------ refreshing

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
            current = states;
            var tiled = states.Where(s => s.Entry.Kind != AppKind.Launcher && (s.Entry.IsSuite || s.Present)).Select(s => s.Entry).ToList();
            string names = string.Join("|", tiled.Select(e => e.Name));
            if (names != tileNames) LayTiles(tiled);
            foreach (var st in states)
            {
                Tile t;
                if (!tiles.TryGetValue(st.Name, out t)) continue;
                t.Model = st;
                t.Invalidate();
                // the whole text, for when the tile has to cut it short
                string tip = st.Name + (st.Entry.Role.Length > 0 ? " — " + st.Entry.Role : "") + "\n" + st.Summary + (string.IsNullOrEmpty(st.Detail) ? "" : "\n" + st.Detail) +
                    "\nRight-click to switch it on or off, or start or stop it.";
                if (tileTips.GetToolTip(t) != tip) tileTips.SetToolTip(t, tip);
            }
            FillApps(states);
            SetState(overall, text);
        }

        void LayTiles(List<AppEntry> entries)
        {
            tileNames = string.Join("|", entries.Select(e => e.Name));
            grid.SuspendLayout();
            try
            {
                foreach (var t in tiles.Values) t.Dispose();
                tiles.Clear();
                grid.Controls.Clear();
                grid.RowStyles.Clear();
                int rows = (entries.Count + Columns - 1) / Columns;
                grid.RowCount = Math.Max(1, rows);
                for (int i = 0; i < grid.RowCount; i++) grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                int n = 0;
                foreach (var e in entries)
                {
                    var entry = e;
                    var t = new Tile(entry) { Dock = DockStyle.Fill, Margin = new Padding(Ui.S(3)) };
                    t.MouseUp += (s, ev) =>
                    {
                        if (ev.Button == MouseButtons.Left) OpenApp(entry);
                        else if (ev.Button == MouseButtons.Right) TileMenu(t, entry).Show(t, ev.Location);
                    };
                    tiles[entry.Name] = t;
                    grid.Controls.Add(t, n % Columns, n / Columns);
                    n++;
                }
            }
            finally { grid.ResumeLayout(); }
        }

        ContextMenuStrip TileMenu(Tile t, AppEntry e)
        {
            var st = current.FirstOrDefault(x => x.Name.Equals(e.Name, StringComparison.OrdinalIgnoreCase));
            var m = new ContextMenuStrip();
            m.Closed += (s, ev) => BeginInvoke((Action)m.Dispose);
            if (CanOpen(e)) { var open = new ToolStripMenuItem("Open " + e.Name, null, (s, ev) => OpenApp(e)); open.Font = new Font(m.Font, FontStyle.Bold); m.Items.Add(open); }
            if (st != null)
            {
                if (CanStart(st)) m.Items.Add(new ToolStripMenuItem(StartWord(e), null, (s, ev) => Act("start", st)));
                if (CanStop(st)) m.Items.Add(new ToolStripMenuItem("Stop", null, (s, ev) => Act("stop", st)));
                if (e.CanSwitch)
                {
                    m.Items.Add(new ToolStripSeparator());
                    if (st.Enabled != true) m.Items.Add(new ToolStripMenuItem("Enable" + (e.NeedsAdmin ? " (admin)" : ""), null, (s, ev) => Act("enable", st)));
                    if (st.Enabled != false) m.Items.Add(new ToolStripMenuItem("Disable" + (e.NeedsAdmin ? " (admin)" : ""), null, (s, ev) => Act("disable", st)));
                }
            }
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add(new ToolStripMenuItem("Show in the Apps tab", null, (s, ev) => SelectInApps(e.Name)));
            return m;
        }

        void FillApps(List<AppState> states)
        {
            foreach (var st in states)
                if (!appPictures.Images.ContainsKey(st.Name)) appPictures.Images.Add(st.Name, AppRegistry.Picture(st.Entry, Ui.S(16)));
            var rows = new List<ListViewItem>();
            foreach (var st in states)
            {
                var it = Ui.Row(st.Name, st.Name, st.Entry.KindWord, st.OnWord,
                    st.RunWord.Replace("-", "—"), st.Summary, st.Detail ?? "");
                it.ImageKey = st.Name;
                if (States.Rank(st.State) >= 2) it.ForeColor = Ui.StateColor(st.State);
                else if (st.Faded) it.ForeColor = Ui.Muted;
                it.ToolTipText = st.Summary + (string.IsNullOrEmpty(st.Detail) ? "" : "\n" + st.Detail);
                rows.Add(it);
            }
            Ui.Fill(apps, rows);
            ShowApp();
        }

        AppState SelectedApp()
        {
            if (apps.SelectedItems.Count == 0) return null;
            string name = apps.SelectedItems[0].Tag as string;
            return current.FirstOrDefault(s => s.Name == name);
        }

        void SelectInApps(string name)
        {
            tabs.SelectedIndex = 1;
            foreach (ListViewItem it in apps.Items)
            {
                it.Selected = (it.Tag as string) == name;
                if (it.Selected) { it.Focused = true; it.EnsureVisible(); }
            }
            apps.Focus();
        }

        void ShowApp()
        {
            if (btnOpen == null) return;
            var st = SelectedApp();
            bool any = st != null && !working;
            btnOpen.Enabled = any && CanOpen(st.Entry);
            btnStart.Enabled = any && CanStart(st);
            btnStart.Text = st == null ? "Start" : StartWord(st.Entry);
            btnStop.Enabled = any && CanStop(st);
            btnEnable.Enabled = any && st.Entry.CanSwitch && st.Present && st.Enabled != true;
            btnDisable.Enabled = any && st.Entry.CanSwitch && st.Present && st.Enabled != false;
            btnEnable.Text = st != null && st.Entry.NeedsAdmin ? "Enable (admin)" : "Enable";
            btnDisable.Text = st != null && st.Entry.NeedsAdmin ? "Disable (admin)" : "Disable";
            btnRun.Enabled = any && st.Entry.Kind == AppKind.Launcher && st.Present;
            btnLog.Enabled = any && st.Entry.LogPath != null && File.Exists(st.Entry.LogPath);
            if (st == null) { Ui.Show(appDetail, current.Count == 0 ? "" : "Select an app to switch it on or off, start or stop it."); return; }
            var e = st.Entry;
            string where = e.IsSuite ? (e.Kind == AppKind.Aegis ? AegisClient.Exe ?? "" : Suite.ExeOf(e.Info.Id)) : (e.Kind == AppKind.Launcher ? e.Command : e.Exe);
            string on = e.Kind == AppKind.Launcher ? "It runs once when you click Run."
                : "Switched on means " + e.OnMeaning + "." + (e.Kind == AppKind.Startup ? " (Windows' Startup apps switch, value \"" + e.RunName + "\" in your Run key.)" : "");
            Ui.Show(appDetail, e.Name + (e.Role.Length > 0 ? " — " + e.Role : "") + ". " + (e.Blurb ?? "") + "\r\n" + on + "\r\n" + where);
        }

        static string StartWord(AppEntry e)
        {
            switch (e.Kind)
            {
                case AppKind.Periodic: return "Run now";
                case AppKind.OnDemand: return "Open";
                case AppKind.Aegis: return "Open tray icon";
                case AppKind.Launcher: return "Run";
                default: return "Start";
            }
        }

        static bool CanOpen(AppEntry e) { return e.IsSuite; }
        static bool CanStart(AppState st)
        {
            if (!st.Present) return false;
            switch (st.Entry.Kind)
            {
                case AppKind.Watcher: case AppKind.Engine: case AppKind.Startup: return !st.Running;
                case AppKind.Periodic: return st.Enabled != false;
                case AppKind.Aegis: return !st.Tray;
                case AppKind.OnDemand: return !st.Off;
                default: return false;
            }
        }
        static bool CanStop(AppState st)
        {
            if (!st.Present || !st.Entry.HasStop) return false;
            return st.Entry.Kind == AppKind.Aegis ? st.Tray : st.Running;
        }

        void OpenApp(AppEntry e)
        {
            if (e.IsSuite) Launch.Open(e.Info.Id, null);
            else SelectInApps(e.Name);
        }

        void Act(string verb) { var st = SelectedApp(); if (st != null) Act(verb, st); }

        void Act(string verb, AppState st)
        {
            var e = st.Entry;
            if (working) return;
            if (verb == "run" && e.Confirm != null && !Ui.Confirm(this, e.Confirm)) return;
            if (verb == "disable" && e.Kind == AppKind.Engine &&
                !Ui.Confirm(this, "Disable " + e.Name + "? Its scheduled task is switched off and its engine stops until you enable it again (one admin prompt).")) return;
            if (verb == "disable" && e.Kind == AppKind.Aegis &&
                !Ui.Confirm(this, "Disable Aegis? It keeps answering DNS, so the internet keeps working, but it blocks nothing until you enable it again.")) return;
            working = true;
            ShowApp();
            StatusBar.Text = "Working: " + verb + " " + e.Name + "…";
            Ui.Background(this, () =>
            {
                string err;
                if (verb == "enable" || verb == "disable") err = AppControl.Switch(e, verb == "enable");
                else if (verb == "stop") err = AppControl.Stop(e);
                else if (verb == "run") err = AppControl.Run(e);
                else err = AppControl.Start(e);
                Sync.Poke(AppControl.ChangedSignal);
                return err;
            }, (err, x) =>
            {
                working = false;
                if (x != null) err = x.Message;
                if (err != null) { StatusBar.Text = "Didn't finish: " + verb + " " + e.Name; Ui.Warn(this, err); }
                else StatusBar.Text = HubCli.Done(verb, e);
                if (hub == null) { collecting = false; RefreshView(); }
                ShowApp();
            });
        }

        // ------------------------------------------------------------------ alerts

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

        // "apps" opens the Apps tab; "apps:<name>" selects that app there.
        protected override void HandleRequest(string request)
        {
            if (request == "apps") { tabs.SelectedIndex = 1; return; }
            if (request.StartsWith("apps:", StringComparison.Ordinal)) { SelectInApps(request.Substring(5)); return; }
            base.HandleRequest(request);
        }
    }

    // One app on the dashboard: icon, name, role, and how it's doing.
    sealed class Tile : Control
    {
        public AppState Model;
        readonly AppEntry app;
        readonly Bitmap icon;
        bool hover;

        public Tile(AppEntry app)
        {
            this.app = app;
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true);
            Cursor = Cursors.Hand;
            icon = AppRegistry.Picture(app, Ui.S(40));
            Height = Ui.S(96);
            MinimumSize = new Size(Ui.S(200), Ui.S(96));
            BackColor = SystemColors.Window;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) icon.Dispose();
            base.Dispose(disposing);
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            string state = Model == null ? States.Off : Model.State;
            bool off = Model != null && Model.Faded;
            using (var bg = new SolidBrush(hover ? Color.FromArgb(0xF3, 0xF6, 0xFB) : SystemColors.Window)) g.FillRectangle(bg, r);
            using (var border = new Pen(hover ? app.Bottom : Color.FromArgb(0xD9, 0xD9, 0xD9))) g.DrawRectangle(border, r);
            using (var stripe = new SolidBrush(Ui.StateColor(state))) g.FillRectangle(stripe, 1, 1, Ui.S(4), Height - 2);
            int x = Ui.S(14);
            if (off)
            {
                // a switched-off app's picture is drawn faded
                var cm = new System.Drawing.Imaging.ColorMatrix { Matrix33 = 0.4f };
                using (var ia = new System.Drawing.Imaging.ImageAttributes())
                {
                    ia.SetColorMatrix(cm);
                    g.DrawImage(icon, new Rectangle(x, (Height - icon.Height) / 2, icon.Width, icon.Height), 0, 0, icon.Width, icon.Height, GraphicsUnit.Pixel, ia);
                }
            }
            else g.DrawImage(icon, x, (Height - icon.Height) / 2);
            int tx = x + icon.Width + Ui.S(10);
            int w = Width - tx - Ui.S(8);
            TextRenderer.DrawText(g, app.Name, Ui.Big, new Point(tx, Ui.S(8)), off ? Ui.Muted : SystemColors.ControlText);
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
