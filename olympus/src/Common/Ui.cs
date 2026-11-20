// Olympus window kit: DPI scaling, fonts, state colours, helpers, and AppWindow, the frame every
// Olympus window shares (header with the app's icon, name and state; toolbar; body; status line).
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Olympus
{
    static class Ui
    {
        public static readonly float Scale = GetScale();
        static float GetScale()
        {
            try { using (var g = Graphics.FromHwnd(IntPtr.Zero)) return g.DpiX / 96f; }
            catch (Exception) { return 1f; }
        }
        public static int S(float px) { return (int)Math.Round(px * Scale); }

        public static readonly Font Base = SystemFonts.MessageBoxFont;
        public static readonly Font Bold = new Font(Base, FontStyle.Bold);
        public static readonly Font Big = new Font(Base.FontFamily, Base.Size * 1.25f, FontStyle.Bold);
        public static readonly Font Huge = new Font(Base.FontFamily, Base.Size * 1.6f, FontStyle.Bold);
        public static readonly Font Mono = new Font("Consolas", Base.Size);
        public static Color Muted { get { return SystemColors.GrayText; } }

        public static Color StateColor(string st)
        {
            switch (st)
            {
                case States.Ok: return Color.FromArgb(0x1E, 0x8E, 0x3E);
                case States.Warn: return Color.FromArgb(0xB8, 0x72, 0x00);
                case States.Alert: case States.Error: return Color.FromArgb(0xD3, 0x2F, 0x2F);
                case States.Busy: return Color.FromArgb(0x15, 0x65, 0xC0);
                default: return Color.FromArgb(0x75, 0x75, 0x75);
            }
        }
        public static Color SevColor(string sev)
        {
            switch (sev)
            {
                case Sev.Critical: return StateColor(States.Alert);
                case Sev.Warning: return StateColor(States.Warn);
                case Sev.Notice: return StateColor(States.Busy);
                default: return Muted;
            }
        }
        public static string SevWord(string sev)
        {
            switch (sev)
            {
                case Sev.Critical: return "Critical";
                case Sev.Warning: return "Warning";
                case Sev.Notice: return "Notice";
                default: return "Info";
            }
        }
        public static Badge StateBadge(string st)
        {
            switch (st)
            {
                case States.Ok: return Badge.Ok;
                case States.Busy: return Badge.Busy;
                case States.Warn: return Badge.Warn;
                case States.Alert: case States.Error: return Badge.Alert;
                default: return Badge.Off;
            }
        }

        public static Button Btn(string text, EventHandler click)
        {
            var b = new Button
            {
                Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(S(6), S(2), S(6), S(2)), Margin = new Padding(0, 0, S(6), S(4)),
                UseVisualStyleBackColor = true
            };
            if (click != null) b.Click += click;
            return b;
        }

        public static Label Lbl(string text, bool muted = false, Font font = null)
        {
            return new Label
            {
                Text = text, AutoSize = true, Font = font ?? Base,
                ForeColor = muted ? Muted : SystemColors.ControlText,
                Margin = new Padding(S(3), S(3), S(3), S(3))
            };
        }

        // "Name|200" sets a column width in (unscaled) pixels; a trailing ">" right-aligns the column,
        // for numbers ("Size|90>"; not the first column). The width left over goes to the column
        // marked "*" ("Name|240*"), else to the last column when it holds text; a table of short
        // values just ends.
        public static ListView List(params string[] columns)
        {
            var lv = new ListPlus
            {
                View = View.Details, FullRowSelect = true, HideSelection = false, Dock = DockStyle.Fill,
                MultiSelect = true, ShowItemToolTips = true
            };
            foreach (var c in columns)
            {
                string spec = c;
                var align = HorizontalAlignment.Left;
                if (spec.EndsWith(">", StringComparison.Ordinal)) { align = HorizontalAlignment.Right; spec = spec.Substring(0, spec.Length - 1); }
                if (spec.EndsWith("*", StringComparison.Ordinal)) { lv.FillColumn = lv.Columns.Count; spec = spec.Substring(0, spec.Length - 1); }
                string name = spec;
                int w = 110, bar = spec.IndexOf('|');
                if (bar >= 0) { name = spec.Substring(0, bar); int.TryParse(spec.Substring(bar + 1), out w); }
                if (lv.Columns.Count == 0) align = HorizontalAlignment.Left;   // Windows keeps the first column left-aligned
                lv.Columns.Add(name, S(w), align);
            }
            return lv;
        }

        // A line of grey text in the middle of a list while it has no rows ("Nothing to review").
        public static ListView Empty(ListView lv, string text)
        {
            var p = lv as ListPlus;
            if (p != null) p.EmptyText = text;
            return lv;
        }

        // Sets a read-only text box's text without it all turning selected when the box gets focus.
        public static void Show(TextBox t, string text)
        {
            if (t.Text == text) return;
            t.Text = text;
            t.Select(0, 0);
        }

        public static ListViewItem Row(object tag, params string[] cells)
        {
            var it = new ListViewItem(cells) { Tag = tag };
            return it;
        }

        // Replaces a list's rows, keeping the selection (by Tag) and scroll position where possible.
        public static void Fill(ListView lv, IList<ListViewItem> items)
        {
            var selected = new HashSet<object>(lv.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag).Where(t => t != null));
            int top = lv.TopItem != null ? lv.TopItem.Index : 0;
            lv.BeginUpdate();
            try
            {
                lv.Items.Clear();
                lv.Items.AddRange(items.ToArray());
                foreach (ListViewItem it in lv.Items) if (it.Tag != null && selected.Contains(it.Tag)) it.Selected = true;
                if (top > 0 && top < lv.Items.Count) { try { lv.TopItem = lv.Items[top]; } catch (Exception) { } }
            }
            finally { lv.EndUpdate(); }
            var p = lv as ListPlus;
            if (p != null && p.IsHandleCreated)
            {
                p.FitColumns();   // a scroll bar may have come or gone; once more after it's drawn
                p.BeginInvoke((Action)p.FitColumns);
            }
        }

        public static TabPage Tab(string title, Control content)
        {
            var t = new TabPage(title) { Padding = new Padding(S(8)), UseVisualStyleBackColor = true };
            content.Dock = DockStyle.Fill;
            t.Controls.Add(content);
            return t;
        }

        public static TextBox Text(bool multiline)
        {
            var t = new TextBox { Multiline = multiline, Dock = DockStyle.Fill };
            if (multiline) { t.ScrollBars = ScrollBars.Vertical; t.AcceptsReturn = true; }
            return t;
        }

        public static void Warn(IWin32Window owner, string text)
        {
            MessageBox.Show(owner, text, Suite.Me.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        public static void Info(IWin32Window owner, string text)
        {
            MessageBox.Show(owner, text, Suite.Me.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        public static bool Confirm(IWin32Window owner, string text)
        {
            return MessageBox.Show(owner, text, Suite.Me.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;
        }

        // Runs work off the UI thread, then done(result) back on it.
        public static void Background<T>(Control owner, Func<T> work, Action<T, Exception> done)
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                T result = default(T);
                Exception err = null;
                try { result = work(); } catch (Exception e) { err = e; Log.Error("background work", e); }
                try { if (!owner.IsDisposed) owner.BeginInvoke((Action)(() => done(result, err))); } catch (Exception) { }
            });
        }

        // Renders a form to a PNG without showing it on screen (for checking layouts). tab: the page
        // of its first TabControl to show (-1: as it opens; returns 2 when there's no such page).
        // waitMs: time for background loading before the picture is taken.
        public static int Snapshot(Form f, string png, int tab = -1, int waitMs = 200)
        {
            f.StartPosition = FormStartPosition.Manual;
            f.Location = new Point(-20000, -20000);
            f.ShowInTaskbar = false;
            f.Show();
            Application.DoEvents();
            var aw = f as AppWindow;
            if (aw != null) aw.RefreshNow();
            if (tab >= 0)
            {
                var tabs = FindTabs(f);
                if (tabs == null || tab >= tabs.TabCount) { f.Close(); return 2; }
                tabs.SelectedIndex = tab;
            }
            var until = DateTime.UtcNow.AddMilliseconds(Math.Max(0, waitMs));
            do { Application.DoEvents(); Thread.Sleep(40); } while (DateTime.UtcNow < until);
            using (var bmp = new Bitmap(f.Width, f.Height))
            {
                f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                bmp.Save(png, ImageFormat.Png);
            }
            f.Close();
            return 0;
        }

        static TabControl FindTabs(Control c)
        {
            foreach (Control k in c.Controls)
            {
                var t = k as TabControl ?? FindTabs(k);
                if (t != null) return t;
            }
            return null;
        }
    }

    // The list every Olympus window uses (Ui.List): double-buffered; its last text column takes the
    // width that's left over, so there's no scroll bar for a few pixels and no dead space, while
    // number columns stay compact (it never gets narrower than it was given); and it can show a
    // line of text while it's empty.
    class ListPlus : ListView
    {
        string empty;
        int[] least;     // each column's own width
        bool fitting;

        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr hWnd, int index);

        public ListPlus() { DoubleBuffered = true; }

        public string EmptyText
        {
            get { return empty; }
            set { empty = value; if (IsHandleCreated) Invalidate(); }
        }

        // The column that stretches: one marked "*" in Ui.List, else the last one when it holds text
        // (a last column of numbers means a compact table that just ends: -1).
        public int FillColumn = -1;
        int Filler()
        {
            if (FillColumn >= 0) return FillColumn < Columns.Count ? FillColumn : -1;
            int last = Columns.Count - 1;
            return last >= 0 && Columns[last].TextAlign == HorizontalAlignment.Left ? last : -1;
        }

        // A list scrolls sideways when its rows need a vertical scroll bar it hasn't drawn yet, so
        // that one counts too.
        int UsableWidth()
        {
            int w = ClientSize.Width;
            bool shown = (GetWindowLong(Handle, -16) & 0x00200000) != 0;   // GWL_STYLE, WS_VSCROLL
            if (!shown && Items.Count > 0)
            {
                try { if (GetItemRect(Items.Count - 1).Bottom > ClientSize.Height) w -= SystemInformation.VerticalScrollBarWidth; }
                catch (Exception) { }
            }
            return w;
        }

        public void FitColumns()
        {
            if (View != View.Details || Columns.Count == 0 || !IsHandleCreated) return;
            if (least == null || least.Length != Columns.Count) least = Columns.Cast<ColumnHeader>().Select(c => c.Width).ToArray();
            int fill = Filler(), used = 0;
            if (fill < 0) return;
            for (int i = 0; i < Columns.Count; i++) if (i != fill) used += Columns[i].Width;
            int want = Math.Max(least[fill], UsableWidth() - used - 1);
            if (Columns[fill].Width == want) return;
            fitting = true;
            try { Columns[fill].Width = want; }
            finally { fitting = false; }
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); FitColumns(); }
        protected override void OnResize(EventArgs e) { base.OnResize(e); FitColumns(); }

        protected override void OnColumnWidthChanged(ColumnWidthChangedEventArgs e)
        {
            base.OnColumnWidthChanged(e);
            if (fitting || least == null || e.ColumnIndex >= least.Length || Filler() < 0) return;
            if (e.ColumnIndex == Filler()) least[e.ColumnIndex] = Columns[e.ColumnIndex].Width;   // sized by hand: keep it at least that
            else FitColumns();
        }

        [StructLayout(LayoutKind.Sequential)]
        struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct NMLVEMPTYMARKUP
        {
            public NMHDR hdr;
            public int dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2084)] public string szMarkup;
        }

        // LVN_GETEMPTYMARKUP: an empty list asks its parent what to show (Windows reflects it back here).
        protected override void WndProc(ref Message m)
        {
            const int WM_REFLECT_NOTIFY = 0x2000 + 0x004E, LVN_GETEMPTYMARKUP = -187, EMF_CENTERED = 1;
            if (m.Msg == WM_REFLECT_NOTIFY && !string.IsNullOrEmpty(empty) && m.LParam != IntPtr.Zero)
            {
                var h = (NMHDR)Marshal.PtrToStructure(m.LParam, typeof(NMHDR));
                if (h.code == LVN_GETEMPTYMARKUP)
                {
                    string text = empty.Replace("<", "‹").Replace(">", "›");   // the text is markup: no tags
                    var mk = new NMLVEMPTYMARKUP { hdr = h, dwFlags = EMF_CENTERED, szMarkup = text.Length > 1000 ? text.Substring(0, 1000) : text };
                    Marshal.StructureToPtr(mk, m.LParam, false);
                    m.Result = (IntPtr)1;
                    return;
                }
            }
            base.WndProc(ref m);
        }
    }

    // The frame every Olympus window shares.
    class AppWindow : Form
    {
        protected readonly AppInfo App;
        readonly PictureBox icon = new PictureBox();
        readonly Label title = new Label(), role = new Label(), stateLine = new Label();
        protected readonly FlowLayoutPanel Toolbar = new FlowLayoutPanel();
        protected readonly Panel Body = new Panel();
        protected readonly Label StatusBar = new Label();
        protected readonly System.Windows.Forms.Timer Ticker = new System.Windows.Forms.Timer();

        public AppWindow(AppInfo app, int width, int height)
        {
            App = app;
            Text = app.Name + " — " + app.Role;
            Font = Ui.Base;
            AutoScaleMode = AutoScaleMode.None;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(Ui.S(width), Ui.S(height));
            MinimumSize = new Size(Ui.S(Math.Min(width, 620)), Ui.S(Math.Min(height, 420)));
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (Exception) { }

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(Ui.S(12)) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            var head = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2, RowCount = 2, Margin = new Padding(0, 0, 0, Ui.S(8)) };
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            icon.Image = IconArt.Draw(app.Id, Ui.S(44));
            icon.Size = new Size(Ui.S(48), Ui.S(48));
            icon.SizeMode = PictureBoxSizeMode.CenterImage;
            icon.Margin = new Padding(0, 0, Ui.S(10), 0);
            head.Controls.Add(icon, 0, 0);
            head.SetRowSpan(icon, 2);
            var names = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            title.Text = app.Name;
            title.Font = Ui.Huge;
            title.AutoSize = true;
            title.Margin = new Padding(0);
            role.Text = app.Role;
            role.AutoSize = true;
            role.ForeColor = Ui.Muted;
            role.Margin = new Padding(Ui.S(4), Ui.S(9), 0, 0);
            names.Controls.Add(title);
            names.Controls.Add(role);
            head.Controls.Add(names, 1, 0);
            stateLine.AutoSize = true;
            stateLine.Font = Ui.Bold;
            stateLine.Margin = new Padding(Ui.S(2), Ui.S(2), 0, 0);
            stateLine.Text = "Checking…";
            head.Controls.Add(stateLine, 1, 1);
            root.Controls.Add(head, 0, 0);

            Toolbar.Dock = DockStyle.Fill;
            Toolbar.AutoSize = true;
            Toolbar.Margin = new Padding(0, 0, 0, Ui.S(6));
            root.Controls.Add(Toolbar, 0, 1);

            Body.Dock = DockStyle.Fill;
            Body.Margin = new Padding(0);
            root.Controls.Add(Body, 0, 2);

            StatusBar.AutoSize = true;
            StatusBar.ForeColor = Ui.Muted;
            StatusBar.Margin = new Padding(Ui.S(2), Ui.S(6), 0, 0);
            root.Controls.Add(StatusBar, 0, 3);

            Ticker.Tick += (s, e) => RefreshNow();
            Shown += (s, e) =>
            {
                RefreshNow();
                if (autoSeconds > 0) { Ticker.Interval = autoSeconds * 1000; Ticker.Start(); }
                HandlePending();
            };
            FormClosed += (s, e) => Ticker.Stop();
        }

        int autoSeconds;
        // Refresh interval in seconds (0 = only when asked).
        protected void AutoRefresh(int seconds) { autoSeconds = seconds; }

        bool refreshing;
        public void RefreshNow()
        {
            if (refreshing) return;
            refreshing = true;
            try { RefreshView(); }
            catch (Exception e) { Log.Error("refreshing the window", e); StatusBar.Text = "Couldn't refresh: " + e.Message; }
            finally { refreshing = false; }
        }

        protected virtual void RefreshView() { }

        protected void SetState(string state, string text)
        {
            stateLine.ForeColor = Ui.StateColor(state);
            stateLine.Text = "●  " + text;
        }

        protected void Add(params Control[] buttons) { Toolbar.Controls.AddRange(buttons); }

        public void BringUp()
        {
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Show();
            Activate();
            try { Native.SetForegroundWindow(Handle); } catch (Exception) { }
            HandlePending();
        }

        void HandlePending()
        {
            string r = TakeRequest();
            if (r == null) return;
            try { HandleRequest(r); } catch (Exception e) { Log.Error("handling " + r, e); }
        }

        // "alert:<id>" by default shows that alert; apps override this to jump to the right place.
        protected virtual void HandleRequest(string request)
        {
            if (!request.StartsWith("alert:", StringComparison.Ordinal)) return;
            var a = AlertStore.Find(App.Id, request.Substring(6));
            if (a != null) Ui.Info(this, a.Title + "\n\n" + a.Body);
        }

        // A request left for an already-open window (for example "show this alert").
        public static string RequestFile { get { return Path.Combine(Suite.UserDir(Suite.Me.Id), "window-request.txt"); } }
        public static string TakeRequest()
        {
            try
            {
                if (!File.Exists(RequestFile)) return null;
                string r = File.ReadAllText(RequestFile).Trim();
                File.Delete(RequestFile);
                return r.Length > 0 ? r : null;
            }
            catch (Exception) { return null; }
        }

        // One window per app: a second start just brings the first one forward (passing along
        // "request", e.g. an alert to show). Handles --snapshot.
        public static int Run(string[] args, string request, Func<AppWindow> make)
        {
            var a = new Args(args);
            string snap = a.Opt("--snapshot");
            if (snap != null)
            {
                int tab, wait;
                if (!int.TryParse(a.Opt("--tab") ?? "-1", out tab)) tab = -1;
                if (!int.TryParse(a.Opt("--wait") ?? "200", out wait)) wait = 200;
                using (var f = make()) return Ui.Snapshot(f, snap, tab, wait);
            }
            string key = Suite.Me.Key;
            if (request != null)
            {
                try { Directory.CreateDirectory(Path.GetDirectoryName(RequestFile)); File.WriteAllText(RequestFile, request); } catch (Exception) { }
            }
            Mutex m;
            if (!Sync.Claim(key + ".window", out m))
            {
                Sync.Poke(key + ".show");
                return 0;
            }
            using (m)
            using (var show = Sync.Listen(key + ".show"))
            {
                var f = make();
                var t = new Thread(() =>
                {
                    while (show.WaitOne())
                    {
                        try { f.BeginInvoke((Action)f.BringUp); } catch (Exception) { return; }
                    }
                }) { IsBackground = true };
                t.Start();
                Application.Run(f);
            }
            return 0;
        }
    }
}
