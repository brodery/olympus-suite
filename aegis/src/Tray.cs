// Aegis tray app (Aegis.exe): the shield in the notification area and its menu, the
// main window (recent blocks, your lists, check a site, about), the command line,
// and the icon artwork, which is drawn in code (build.ps1 also writes it to aegis.ico).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Aegis
{
    // On = filtering (green check), Paused (amber), Idle = Windows isn't using Aegis (grey),
    // Off = the engine isn't answering (red).
    enum Shield { On, Paused, Idle, Off }

    static class IconArt
    {
        static void Palette(Shield s, out Color top, out Color bottom)
        {
            switch (s)
            {
                case Shield.On: top = Color.FromArgb(0x34, 0xC7, 0x6F); bottom = Color.FromArgb(0x0E, 0x86, 0x43); break;
                case Shield.Paused: top = Color.FromArgb(0xFF, 0xC4, 0x3D); bottom = Color.FromArgb(0xD9, 0x86, 0x00); break;
                case Shield.Idle: top = Color.FromArgb(0xB0, 0xB6, 0xBE); bottom = Color.FromArgb(0x6C, 0x74, 0x7E); break;
                default: top = Color.FromArgb(0xF2, 0x5C, 0x50); bottom = Color.FromArgb(0xBE, 0x26, 0x1C); break;
            }
        }

        static Color Darken(Color c, float f) { return Color.FromArgb(c.A, (int)(c.R * f), (int)(c.G * f), (int)(c.B * f)); }

        static GraphicsPath ShieldPath(float x, float y, float w, float h)
        {
            Func<float, float, PointF> P = (u, v) => new PointF(x + u * w, y + v * h);
            var p = new GraphicsPath();
            p.AddBezier(P(0.50f, 0.00f), P(0.64f, 0.085f), P(0.80f, 0.115f), P(0.97f, 0.115f));
            p.AddLine(P(0.97f, 0.115f), P(0.97f, 0.46f));
            p.AddBezier(P(0.97f, 0.46f), P(0.97f, 0.74f), P(0.77f, 0.905f), P(0.50f, 1.00f));
            p.AddBezier(P(0.50f, 1.00f), P(0.23f, 0.905f), P(0.03f, 0.74f), P(0.03f, 0.46f));
            p.AddLine(P(0.03f, 0.46f), P(0.03f, 0.115f));
            p.AddBezier(P(0.03f, 0.115f), P(0.20f, 0.115f), P(0.36f, 0.085f), P(0.50f, 0.00f));
            p.CloseFigure();
            return p;
        }

        public static Bitmap Draw(int size, Shield state)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.Clear(Color.Transparent);
                float s = size;
                float outline = Math.Max(1f, s / 22f);
                float pad = outline / 2f + (size >= 48 ? s * 0.02f : 0f);
                Color top, bottom;
                Palette(state, out top, out bottom);
                using (var path = ShieldPath(pad, pad, s - 2 * pad, s - 2 * pad))
                {
                    using (var fill = new LinearGradientBrush(new RectangleF(0, 0, s, s), top, bottom, LinearGradientMode.Vertical))
                        g.FillPath(fill, path);
                    if (size >= 48) DrawMesh(g, path, s);
                    using (var pen = new Pen(Darken(bottom, 0.55f), outline) { LineJoin = LineJoin.Round })
                        g.DrawPath(pen, path);
                }
                DrawGlyph(g, s, state);
            }
            return bmp;
        }

        // A faint rivet texture, only on the sizes with room for it.
        static void DrawMesh(Graphics g, GraphicsPath path, float s)
        {
            var old = g.Clip;
            g.SetClip(path);
            float step = s * 0.085f, r = s * 0.017f;
            using (var dot = new SolidBrush(Color.FromArgb(46, 0, 0, 0)))
            {
                int row = 0;
                for (float y = s * 0.14f; y < s * 0.98f; y += step, row++)
                    for (float x = s * 0.06f + (row % 2 == 0 ? 0 : step / 2); x < s * 0.96f; x += step)
                        g.FillEllipse(dot, x - r, y - r, 2 * r, 2 * r);
            }
            g.Clip = old;
        }

        static void DrawGlyph(Graphics g, float s, Shield state)
        {
            float w = Math.Max(1.7f, s * 0.125f);
            using (var pen = new Pen(Color.White, w) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            using (var white = new SolidBrush(Color.White))
            {
                switch (state)
                {
                    case Shield.On:
                        g.DrawLines(pen, new[] { new PointF(s * 0.29f, s * 0.53f), new PointF(s * 0.44f, s * 0.68f), new PointF(s * 0.72f, s * 0.37f) });
                        break;
                    case Shield.Paused:
                        g.DrawLine(pen, s * 0.39f, s * 0.36f, s * 0.39f, s * 0.66f);
                        g.DrawLine(pen, s * 0.61f, s * 0.36f, s * 0.61f, s * 0.66f);
                        break;
                    case Shield.Idle:
                        g.DrawLine(pen, s * 0.33f, s * 0.51f, s * 0.67f, s * 0.51f);
                        break;
                    default:
                        g.DrawLine(pen, s * 0.50f, s * 0.30f, s * 0.50f, s * 0.55f);
                        g.FillEllipse(white, s * 0.50f - w * 0.62f, s * 0.71f - w * 0.62f, w * 1.24f, w * 1.24f);
                        break;
                }
            }
        }

        // The icon lives as long as the app, so its handle is never freed.
        public static Icon MakeIcon(int size, Shield state)
        {
            using (var bmp = Draw(size, state)) return Icon.FromHandle(bmp.GetHicon());
        }

        // A multi-size .ico: 32-bit DIB images up to 64 px, PNG for 256 px.
        public static void WriteIco(string path, Shield state, int[] sizes)
        {
            var images = new List<byte[]>();
            foreach (int sz in sizes)
                using (var bmp = Draw(sz, state))
                    images.Add(sz >= 256 ? Png(bmp) : Dib(bmp));
            using (var fs = File.Create(path))
            using (var w = new BinaryWriter(fs))
            {
                w.Write((ushort)0);
                w.Write((ushort)1);
                w.Write((ushort)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    int sz = sizes[i];
                    w.Write((byte)(sz >= 256 ? 0 : sz));
                    w.Write((byte)(sz >= 256 ? 0 : sz));
                    w.Write((byte)0);
                    w.Write((byte)0);
                    w.Write((ushort)1);
                    w.Write((ushort)32);
                    w.Write(images[i].Length);
                    w.Write(offset);
                    offset += images[i].Length;
                }
                foreach (var img in images) w.Write(img);
            }
        }

        static byte[] Png(Bitmap bmp)
        {
            using (var ms = new MemoryStream())
            {
                bmp.Save(ms, ImageFormat.Png);
                return ms.ToArray();
            }
        }

        static byte[] Dib(Bitmap bmp)
        {
            int w = bmp.Width, h = bmp.Height;
            int maskStride = ((w + 31) / 32) * 4;
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(40); bw.Write(w); bw.Write(h * 2); bw.Write((ushort)1); bw.Write((ushort)32);
                bw.Write(0); bw.Write(w * h * 4 + maskStride * h); bw.Write(0); bw.Write(0); bw.Write(0); bw.Write(0);
                var data = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
                try
                {
                    var row = new byte[w * 4];
                    for (int y = h - 1; y >= 0; y--)
                    {
                        Marshal.Copy(data.Scan0 + y * data.Stride, row, 0, row.Length);
                        bw.Write(row);
                    }
                    var mask = new byte[maskStride];
                    for (int y = h - 1; y >= 0; y--)
                    {
                        Array.Clear(mask, 0, mask.Length);
                        Marshal.Copy(data.Scan0 + y * data.Stride, row, 0, row.Length);
                        for (int x = 0; x < w; x++)
                            if (row[x * 4 + 3] == 0) mask[x / 8] |= (byte)(0x80 >> (x % 8));
                        bw.Write(mask);
                    }
                }
                finally { bmp.UnlockBits(data); }
                return ms.ToArray();
            }
        }

        // A sheet of every state at every size on dark and light backgrounds, plus the
        // 20 px tray size blown up 8x (for checking the artwork).
        public static void WritePreview(string path)
        {
            int[] sizes = { 16, 20, 24, 32, 48, 64, 128 };
            var states = (Shield[])Enum.GetValues(typeof(Shield));
            int gap = 14, bandW = sizes.Sum() + gap * (sizes.Length + 1), rowH = 128 + gap;
            int zoomRowY = rowH * states.Length + gap;
            using (var canvas = new Bitmap(bandW * 2, zoomRowY + 160 + gap, PixelFormat.Format32bppArgb))
            using (var g = Graphics.FromImage(canvas))
            {
                g.Clear(Color.FromArgb(0x20, 0x20, 0x20));
                using (var light = new SolidBrush(Color.FromArgb(0xF3, 0xF3, 0xF3)))
                    g.FillRectangle(light, bandW, 0, bandW, canvas.Height);
                for (int band = 0; band < 2; band++)
                {
                    for (int r = 0; r < states.Length; r++)
                    {
                        int x = band * bandW + gap;
                        foreach (int sz in sizes)
                        {
                            using (var b = Draw(sz, states[r])) g.DrawImageUnscaled(b, x, gap + r * rowH + (128 - sz) / 2);
                            x += sz + gap;
                        }
                    }
                    g.InterpolationMode = InterpolationMode.NearestNeighbor;
                    g.PixelOffsetMode = PixelOffsetMode.Half;
                    for (int r = 0; r < states.Length; r++)
                        using (var b = Draw(20, states[r]))
                            g.DrawImage(b, new Rectangle(band * bandW + gap + r * (160 + gap), zoomRowY, 160, 160));
                    g.PixelOffsetMode = PixelOffsetMode.Default;
                    g.InterpolationMode = InterpolationMode.Default;
                }
                canvas.Save(path, ImageFormat.Png);
            }
        }
    }

    static class Fmt
    {
        public static string Ago(TimeSpan t)
        {
            if (t.TotalSeconds < 90) return (int)t.TotalSeconds + " s";
            if (t.TotalMinutes < 90) return (int)t.TotalMinutes + " min";
            if (t.TotalHours < 48) return (int)t.TotalHours + " h " + t.Minutes + " min";
            return (int)t.TotalDays + " days";
        }

        public static string Percent(long part, long whole)
        {
            return whole == 0 ? "0%" : (100.0 * part / whole).ToString("0.0", CultureInfo.CurrentCulture) + "%";
        }

        public static string Dot { get { return "  ·  "; } }
    }

    // ------------------------------------------------------------------ the tray icon

    sealed class TrayApp : ApplicationContext
    {
        [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] static extern bool AllowSetForegroundWindow(int processId);

        readonly NotifyIcon tray = new NotifyIcon();
        readonly ContextMenuStrip menu = new ContextMenuStrip();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly Control ui = new Control();
        readonly Dictionary<Shield, Icon> icons = new Dictionary<Shield, Icon>();
        readonly Font bold;
        readonly DateTime startedAt = DateTime.UtcNow;
        Shield state = Shield.Idle;
        bool haveState, warned;
        EngineStatus status;
        bool? inUse;
        DateTime lastDnsCheck = DateTime.MinValue, badSince = DateTime.MinValue;
        int polling;
        MainWindow window;

        public static int Run(bool showWindow)
        {
            bool created;
            using (var mutex = new Mutex(true, @"Local\Aegis.Tray", out created))
            using (var show = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\Aegis.Tray.Show"))
            using (var exit = new EventWaitHandle(false, EventResetMode.AutoReset, ExitEventName))
            {
                if (!created)
                {
                    // already running: ask that copy to open its window
                    if (showWindow)
                    {
                        AllowSetForegroundWindow(-1);
                        show.Set();
                    }
                    return 0;
                }
                try { SetProcessDPIAware(); } catch { }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Log.Init("tray");
                Application.ThreadException += (s, e) => Log.Error("tray: " + e.Exception);
                AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Error("tray crashed: " + e.ExceptionObject);
                Application.Run(new TrayApp(show, exit, showWindow));
                GC.KeepAlive(mutex);
                return 0;
            }
        }

        public const string ExitEventName = @"Local\Aegis.Tray.Exit";

        // Aegis.exe --exit: ask a running tray icon to close (used by uninstall).
        public static int SignalExit()
        {
            bool createdNew;
            using (var exit = new EventWaitHandle(false, EventResetMode.AutoReset, ExitEventName, out createdNew))
                if (!createdNew) exit.Set();
            return 0;
        }

        TrayApp(EventWaitHandle showSignal, EventWaitHandle exitSignal, bool showWindow)
        {
            IntPtr handle = ui.Handle;      // a window handle so worker threads can BeginInvoke
            GC.KeepAlive(handle);
            bold = new Font(menu.Font, FontStyle.Bold);
            int size = SystemInformation.SmallIconSize.Width;
            foreach (Shield s in Enum.GetValues(typeof(Shield))) icons[s] = IconArt.MakeIcon(size, s);
            tray.Icon = icons[Shield.Idle];
            tray.Text = "Aegis: starting";
            tray.ContextMenuStrip = menu;
            menu.Opening += (s, e) => { BuildMenu(); e.Cancel = false; };
            tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowWindow(); };
            BuildMenu();
            tray.Visible = true;
            timer.Interval = 3000;
            timer.Tick += (s, e) => Poll();
            timer.Start();
            Poll();
            new Thread(() =>
            {
                var signals = new WaitHandle[] { showSignal, exitSignal };
                while (true)
                {
                    int which = WaitHandle.WaitAny(signals);
                    try { ui.BeginInvoke(which == 0 ? (Action)ShowWindow : ExitTray); } catch { }
                    if (which == 1) return;
                }
            }) { IsBackground = true, Name = "signals" }.Start();
            if (showWindow) ShowWindow();
        }

        void Poll()
        {
            if (Interlocked.Exchange(ref polling, 1) == 1) return;
            bool checkDns = (DateTime.UtcNow - lastDnsCheck).TotalSeconds >= 10;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                EngineStatus st = null;
                bool? use = null;
                try
                {
                    st = EngineStatus.Fetch(800);
                    if (checkDns) use = NetInfo.WindowsUsesAegis();
                }
                catch (Exception e) { Log.Warn("poll: " + e.Message); }
                try
                {
                    ui.BeginInvoke((Action)(() =>
                    {
                        Interlocked.Exchange(ref polling, 0);
                        Apply(st, use, checkDns);
                    }));
                }
                catch { Interlocked.Exchange(ref polling, 0); }
            });
        }

        void Apply(EngineStatus st, bool? use, bool checkedDns)
        {
            if (checkedDns)
            {
                inUse = use;
                lastDnsCheck = DateTime.UtcNow;
            }
            status = st;
            Shield s = st == null ? Shield.Off : inUse == false ? Shield.Idle : st.Paused ? Shield.Paused : Shield.On;
            if (s != state || !haveState)
            {
                state = s;
                haveState = true;
                tray.Icon = icons[s];
            }
            tray.Text = TipText();

            // Say so once if protection has been off for a while (longer grace right after logon).
            bool bad = s == Shield.Off || s == Shield.Idle;
            double grace = (DateTime.UtcNow - startedAt).TotalSeconds < 120 ? 60 : 30;
            if (!bad)
            {
                badSince = DateTime.MinValue;
                warned = false;
            }
            else if (badSince == DateTime.MinValue) badSince = DateTime.UtcNow;
            else if (!warned && (DateTime.UtcNow - badSince).TotalSeconds >= grace)
            {
                warned = true;
                if (s == Shield.Off)
                    tray.ShowBalloonTip(15000, "Aegis isn't filtering", "Its engine isn't answering. If Windows still points at Aegis, the safety switch puts normal DNS back within about 5 minutes.", ToolTipIcon.Warning);
                else
                    tray.ShowBalloonTip(15000, "Aegis isn't filtering", "Windows isn't sending its lookups to Aegis. Run install.cmd in the Aegis folder to turn it on.", ToolTipIcon.Warning);
            }
            if (window != null && !window.IsDisposed) window.ShowStatus(s, st);
        }

        string TipText()
        {
            string t;
            switch (state)
            {
                case Shield.On:
                    t = status.FallbackRecent ? "Aegis: on (Quad9 down, router answering)"
                        : "Aegis: on, " + status.DayBlocked.ToString("N0", CultureInfo.CurrentCulture) + " blocked today";
                    break;
                case Shield.Paused: t = "Aegis: paused until " + status.PausedUntilUtc.ToLocalTime().ToString("t", CultureInfo.CurrentCulture); break;
                case Shield.Idle: t = "Aegis: not in use (Windows DNS isn't set to it)"; break;
                default: t = "Aegis: engine not answering"; break;
            }
            return t.Length > 63 ? t.Substring(0, 63) : t;
        }

        string HeadText()
        {
            if (!haveState) return "Aegis: checking...";
            switch (state)
            {
                case Shield.On: return "Aegis is filtering";
                case Shield.Paused: return "Aegis is paused until " + status.PausedUntilUtc.ToLocalTime().ToString("t", CultureInfo.CurrentCulture);
                case Shield.Idle: return "Aegis isn't in use";
                default: return "The Aegis engine isn't answering";
            }
        }

        void BuildMenu()
        {
            menu.Items.Clear();
            menu.Items.Add(new ToolStripLabel(HeadText()) { Font = bold });
            if (status != null)
            {
                menu.Items.Add(new ToolStripLabel(string.Format(CultureInfo.CurrentCulture, "{0:N0} of {1:N0} lookups blocked today", status.DayBlocked, status.DayQueries))
                {
                    ForeColor = SystemColors.GrayText
                });
            }
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(new ToolStripMenuItem("Open Aegis", null, (s, e) => ShowWindow()) { Font = bold });
            menu.Items.Add(new ToolStripSeparator());
            bool running = status != null;
            menu.Items.Add(Item("Pause for 10 minutes", running, () => Notify(Actions.PauseFor(TimeSpan.FromMinutes(10)))));
            menu.Items.Add(Item("Pause for 1 hour", running, () => Notify(Actions.PauseFor(TimeSpan.FromHours(1)))));
            menu.Items.Add(Item("Resume filtering", running && status.Paused, () => Notify(Actions.Resume())));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item("Update blocklists now", running, () => Notify(Actions.Update())));
            menu.Items.Add(Item("Open the Aegis folder", true, () => Process.Start("explorer.exe", "\"" + App.ProgramDir + "\"")));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item("Hide this icon (Aegis keeps filtering)", true, ExitTray));
        }

        static ToolStripMenuItem Item(string text, bool enabled, Action act)
        {
            return new ToolStripMenuItem(text, null, (s, e) => act()) { Enabled = enabled };
        }

        void Notify(string message)
        {
            tray.ShowBalloonTip(4000, App.Title, message, ToolTipIcon.Info);
            Poll();
        }

        void ShowWindow()
        {
            if (window == null || window.IsDisposed)
            {
                window = new MainWindow();
                window.FormClosed += (s, e) => window = null;
                if (haveState) window.ShowStatus(state, status);
                window.Show();
            }
            if (window.WindowState == FormWindowState.Minimized) window.WindowState = FormWindowState.Normal;
            window.Activate();
            window.BringToFront();
        }

        void ExitTray()
        {
            tray.Visible = false;
            if (window != null && !window.IsDisposed) window.Close();
            ExitThread();
        }
    }

    // ------------------------------------------------------------------ the main window

    sealed class MainWindow : Form
    {
        static readonly float DpiScale = GetScale();
        static float GetScale() { using (var g = Graphics.FromHwnd(IntPtr.Zero)) return g.DpiX / 96f; }
        static int S(float px) { return (int)Math.Round(px * DpiScale); }

        readonly PictureBox stateIcon = new PictureBox();
        readonly Label stateText = new Label(), countsText = new Label(), statusLine = new Label();
        readonly Button pause10 = new Button(), pause60 = new Button(), resume = new Button(), update = new Button();
        readonly TabControl tabs = new TabControl();
        readonly TextBox search = new TextBox();
        readonly ListView recent = new ListView();
        readonly ListBox allowBox = new ListBox(), blockBox = new ListBox();
        readonly TextBox allowInput = new TextBox(), blockInput = new TextBox(), checkInput = new TextBox();
        readonly Label checkOut = new Label(), aboutText = new Label();
        readonly Button checkButton = new Button(), checkAllow = new Button(), checkBlock = new Button();
        readonly System.Windows.Forms.Timer refresh = new System.Windows.Forms.Timer();
        readonly Dictionary<Shield, Bitmap> stateImages = new Dictionary<Shield, Bitmap>();
        long logSignature = long.MinValue;
        List<BlockedSummary> rows = new List<BlockedSummary>();
        string checkedName;
        int checkGeneration;
        bool loadingRecent;
        EngineStatus lastStatus;

        public MainWindow()
        {
            Text = App.Title;
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.None;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(S(820), S(560));
            MinimumSize = new Size(S(640), S(420));
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            foreach (Shield s in Enum.GetValues(typeof(Shield))) stateImages[s] = IconArt.Draw(S(40), s);

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(S(12)) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            var head = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2, RowCount = 2, Margin = new Padding(0, 0, 0, S(8)) };
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            stateIcon.Size = new Size(S(44), S(44));
            stateIcon.SizeMode = PictureBoxSizeMode.CenterImage;
            stateIcon.Margin = new Padding(0, 0, S(10), 0);
            head.Controls.Add(stateIcon, 0, 0);
            head.SetRowSpan(stateIcon, 2);
            stateText.AutoSize = true;
            stateText.Font = new Font(Font.FontFamily, Font.Size * 1.4f, FontStyle.Bold);
            stateText.Text = "Checking...";
            head.Controls.Add(stateText, 1, 0);
            countsText.AutoSize = true;
            countsText.ForeColor = SystemColors.GrayText;
            countsText.Margin = new Padding(S(3), S(2), 0, 0);
            head.Controls.Add(countsText, 1, 1);
            root.Controls.Add(head, 0, 0);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 0, 0, S(8)) };
            Setup(pause10, "Pause 10 minutes", (s, e) => Do(Actions.PauseFor(TimeSpan.FromMinutes(10))));
            Setup(pause60, "Pause 1 hour", (s, e) => Do(Actions.PauseFor(TimeSpan.FromHours(1))));
            Setup(resume, "Resume filtering", (s, e) => Do(Actions.Resume()));
            Setup(update, "Update blocklists", (s, e) => Do(Actions.Update()));
            buttons.Controls.AddRange(new Control[] { pause10, pause60, resume, update });
            root.Controls.Add(buttons, 0, 1);

            tabs.Dock = DockStyle.Fill;
            tabs.Padding = new Point(S(10), S(4));
            tabs.TabPages.Add(RecentTab());
            tabs.TabPages.Add(ListsTab());
            tabs.TabPages.Add(CheckTab());
            tabs.TabPages.Add(AboutTab());
            tabs.SelectedIndexChanged += (s, e) => RefreshTab(true);
            root.Controls.Add(tabs, 0, 2);

            statusLine.AutoSize = true;
            statusLine.Margin = new Padding(S(2), S(8), 0, 0);
            root.Controls.Add(statusLine, 0, 3);

            refresh.Interval = 3000;
            refresh.Tick += (s, e) => RefreshTab(false);
            refresh.Start();
            FormClosed += (s, e) =>
            {
                refresh.Stop();
                foreach (var b in stateImages.Values) b.Dispose();
            };
            LoadLists();
            Shown += (s, e) => RefreshTab(true);    // the tab control has no selected tab until it's shown
        }

        static void Setup(Button b, string text, EventHandler click)
        {
            b.Text = text;
            b.AutoSize = true;
            b.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            b.Padding = new Padding(S(8), S(3), S(8), S(3));
            b.Margin = new Padding(0, 0, S(6), 0);
            b.Click += click;
        }

        static TableLayoutPanel Rows(params SizeType[] rows)
        {
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = rows.Length };
            foreach (var r in rows) t.RowStyles.Add(r == SizeType.Percent ? new RowStyle(SizeType.Percent, 100) : new RowStyle(r));
            return t;
        }

        TabPage RecentTab()
        {
            var page = new TabPage("Recent blocks") { Padding = new Padding(S(8)) };
            var t = Rows(SizeType.AutoSize, SizeType.Percent, SizeType.AutoSize);
            var top = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, 0, 0, S(6)) };
            top.Controls.Add(new Label { Text = "Search:", AutoSize = true, Margin = new Padding(0, S(5), S(6), 0) });
            search.Width = S(280);
            search.TextChanged += (s, e) => FillRecent();
            top.Controls.Add(search);
            top.Controls.Add(new Label
            {
                AutoSize = true,
                ForeColor = SystemColors.GrayText,
                Margin = new Padding(S(12), S(5), 0, 0),
                Text = "The last " + BlockLog.HistoryDays + " days, newest first; Times counts every block."
            });
            t.Controls.Add(top, 0, 0);

            recent.Dock = DockStyle.Fill;
            recent.View = View.Details;
            recent.FullRowSelect = true;
            recent.HideSelection = false;
            recent.MultiSelect = false;
            recent.Columns.Add("Last seen", S(124));
            recent.Columns.Add("Site", S(270));
            recent.Columns.Add("Times", S(56), HorizontalAlignment.Right);
            recent.Columns.Add("Matched rule", S(170));
            recent.Columns.Add("List", S(116));
            recent.DoubleClick += (s, e) =>
            {
                string n = SelectedRecent();
                if (n == null) return;
                checkInput.Text = n;
                tabs.SelectedIndex = 2;
                RunCheck();
            };
            t.Controls.Add(recent, 0, 1);

            var bottom = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, S(6), 0, 0) };
            var allowSel = new Button();
            Setup(allowSel, "Allow this site", (s, e) => { string n = SelectedRecent(); if (n != null) Do(Actions.Allow(n)); });
            var copySel = new Button();
            Setup(copySel, "Copy name", (s, e) => { string n = SelectedRecent(); if (n != null) Clipboard.SetText(n); });
            var note = new Label
            {
                AutoSize = true,
                ForeColor = SystemColors.GrayText,
                Margin = new Padding(S(6), S(6), 0, 0),
                Text = "Site not loading? Find it here and allow it. Double-click a row for details."
            };
            bottom.Controls.AddRange(new Control[] { allowSel, copySel, note });
            t.Controls.Add(bottom, 0, 2);
            page.Controls.Add(t);
            return page;
        }

        string SelectedRecent() { return recent.SelectedItems.Count == 0 ? null : recent.SelectedItems[0].SubItems[1].Text; }

        // Reads the log on a worker thread so a big log never freezes the window.
        void LoadRecent(bool force)
        {
            long sig = BlockLog.Signature();
            if (loadingRecent || (!force && sig == logSignature)) return;
            logSignature = sig;
            loadingRecent = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                List<BlockedSummary> fresh = null;
                try { fresh = BlockLog.Recent(); }
                catch (Exception e) { Log.Warn("reading the blocked log: " + e.Message); }
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        loadingRecent = false;
                        if (fresh == null) return;
                        rows = fresh;
                        FillRecent();
                    }));
                }
                catch (InvalidOperationException) { }    // window closed meanwhile
            });
        }

        void FillRecent()
        {
            string keep = SelectedRecent();
            string filter = search.Text.Trim().ToLowerInvariant();
            recent.BeginUpdate();
            recent.Items.Clear();
            foreach (var r in rows)
            {
                if (filter.Length > 0 && r.Name.IndexOf(filter, StringComparison.Ordinal) < 0
                    && (r.Source ?? "").IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                string when = r.Last.Date == DateTime.Today ? r.Last.ToString("T", CultureInfo.CurrentCulture) : r.Last.ToString("ddd T", CultureInfo.CurrentCulture);
                var item = new ListViewItem(new[] { when, r.Name, r.Count.ToString("N0", CultureInfo.CurrentCulture), r.Rule, r.Source });
                recent.Items.Add(item);
                if (r.Name == keep) item.Selected = true;
                if (recent.Items.Count >= 1000) break;
            }
            recent.EndUpdate();
        }

        TabPage ListsTab()
        {
            var page = new TabPage("Your lists") { Padding = new Padding(S(8)) };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            t.Controls.Add(ListEditor("Always allowed", "Never blocked, subdomains included.", allowBox, allowInput, true), 0, 0);
            t.Controls.Add(ListEditor("Always blocked", "Blocked even if no list has them, subdomains included.", blockBox, blockInput, false), 1, 0);
            page.Controls.Add(t);
            return page;
        }

        Control ListEditor(string title, string note, ListBox box, TextBox input, bool allow)
        {
            var t = Rows(SizeType.AutoSize, SizeType.AutoSize, SizeType.Percent, SizeType.AutoSize);
            t.Margin = new Padding(S(4));
            t.Controls.Add(new Label { Text = title, AutoSize = true, Font = new Font(Font, FontStyle.Bold) }, 0, 0);
            t.Controls.Add(new Label { Text = note, AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(S(3), S(2), S(3), S(6)) }, 0, 1);
            box.Dock = DockStyle.Fill;
            box.IntegralHeight = false;
            t.Controls.Add(box, 0, 2);
            var row = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, S(6), 0, 0) };
            input.Width = S(170);
            input.Margin = new Padding(0, S(3), S(6), 0);
            input.KeyDown += (s, e) =>
            {
                if (e.KeyCode != Keys.Enter) return;
                e.SuppressKeyPress = true;
                AddToList(input, allow);
            };
            var add = new Button();
            Setup(add, "Add", (s, e) => AddToList(input, allow));
            var remove = new Button();
            Setup(remove, "Remove selected", (s, e) =>
            {
                var sel = box.SelectedItem as string;
                if (sel != null) Do(allow ? Actions.Unallow(sel) : Actions.Unblock(sel));
            });
            row.Controls.AddRange(new Control[] { input, add, remove });
            t.Controls.Add(row, 0, 3);
            return t;
        }

        void AddToList(TextBox input, bool allow)
        {
            string d = Names.Normalize(input.Text);
            if (d == null)
            {
                statusLine.Text = "That doesn't look like a site name. Try something like example.com.";
                return;
            }
            Do(allow ? Actions.Allow(d) : Actions.Block(d));
            input.Clear();
        }

        void LoadLists()
        {
            Fill(allowBox, UserLists.Read(App.AllowPath));
            Fill(blockBox, UserLists.Read(App.BlockPath));
        }

        static void Fill(ListBox box, List<string> items)
        {
            object keep = box.SelectedItem;
            box.BeginUpdate();
            box.Items.Clear();
            foreach (var i in items.OrderBy(x => x, StringComparer.Ordinal)) box.Items.Add(i);
            if (keep != null && box.Items.Contains(keep)) box.SelectedItem = keep;
            box.EndUpdate();
        }

        TabPage CheckTab()
        {
            var page = new TabPage("Check a site") { Padding = new Padding(S(10)) };
            var t = Rows(SizeType.AutoSize, SizeType.AutoSize, SizeType.AutoSize, SizeType.Percent);
            t.Controls.Add(new Label { Text = "Type or paste a site name or link:", AutoSize = true }, 0, 0);
            var row = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, S(4), 0, 0) };
            checkInput.Width = S(380);
            checkInput.Margin = new Padding(0, S(3), S(6), 0);
            checkInput.KeyDown += (s, e) =>
            {
                if (e.KeyCode != Keys.Enter) return;
                e.SuppressKeyPress = true;
                RunCheck();
            };
            Setup(checkButton, "Check", (s, e) => RunCheck());
            row.Controls.AddRange(new Control[] { checkInput, checkButton });
            t.Controls.Add(row, 0, 1);
            checkOut.AutoSize = true;
            checkOut.MaximumSize = new Size(S(740), 0);
            checkOut.Margin = new Padding(S(2), S(14), 0, S(10));
            t.Controls.Add(checkOut, 0, 2);
            var acts = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
            Setup(checkAllow, "Allow this site", (s, e) => ActOnChecked(true));
            Setup(checkBlock, "Block this site", (s, e) => ActOnChecked(false));
            checkAllow.Enabled = checkBlock.Enabled = false;
            acts.Controls.AddRange(new Control[] { checkAllow, checkBlock });
            t.Controls.Add(acts, 0, 3);
            page.Controls.Add(t);
            return page;
        }

        void RunCheck()
        {
            string d = Names.Normalize(checkInput.Text);
            int gen = ++checkGeneration;            // only the newest check may update the page,
            checkedName = null;                     // and the buttons never act on an older result
            checkAllow.Enabled = checkBlock.Enabled = false;
            if (d == null)
            {
                checkOut.Text = "That doesn't look like a site name. Try something like ads.example.com.";
                checkButton.Enabled = true;
                return;
            }
            checkOut.Text = "Checking " + d + "...";
            checkButton.Enabled = false;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string text;
                try { text = Actions.Explain(d); }
                catch (Exception e) { text = "Couldn't check: " + e.Message; }
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        if (gen != checkGeneration) return;
                        checkedName = d;                // the buttons act on the site whose result is shown
                        checkOut.Text = text;
                        checkButton.Enabled = true;
                        checkAllow.Enabled = checkBlock.Enabled = true;
                    }));
                }
                catch (InvalidOperationException) { }    // window closed meanwhile
            });
        }

        void ActOnChecked(bool allow)
        {
            string n = checkedName;
            if (n == null) return;
            Do(allow ? Actions.Allow(n) : Actions.Block(n));
            checkInput.Text = n;
            RunCheck();
        }

        TabPage AboutTab()
        {
            var page = new TabPage("About") { Padding = new Padding(S(12)) };
            var t = Rows(SizeType.AutoSize, SizeType.AutoSize, SizeType.Percent);
            aboutText.AutoSize = true;
            aboutText.MaximumSize = new Size(S(760), 0);
            t.Controls.Add(aboutText, 0, 0);
            var link = new LinkLabel { Text = "Open the Aegis folder", AutoSize = true, Margin = new Padding(S(2), S(10), 0, 0) };
            link.LinkClicked += (s, e) => Process.Start("explorer.exe", "\"" + App.ProgramDir + "\"");
            t.Controls.Add(link, 0, 1);
            page.Controls.Add(t);
            return page;
        }

        void FillAbout()
        {
            var sb = new StringBuilder();
            sb.AppendLine(App.Title + " " + App.Version);
            sb.AppendLine("Blocks ad, tracker and malware sites for this PC by answering their lookups with 0.0.0.0.");
            sb.AppendLine();
            var st = lastStatus;
            var cfg = Config.Load();
            if (st != null)
            {
                sb.AppendLine("Engine: running for " + Fmt.Ago(TimeSpan.FromSeconds(st.Uptime)) + ". Allowed lookups go to "
                    + string.Join(", ", cfg.Upstreams) + " (Quad9, which also refuses known malware sites); answers take "
                    + st.UpstreamMs.ToString("0", CultureInfo.CurrentCulture) + " ms on average. Local names go to " + st.Router + ".");
                sb.AppendLine(string.Format(CultureInfo.CurrentCulture, "Since it started: {0:N0} lookups, {1:N0} blocked, {2:N0} answers cached.",
                    st.TotalQueries, st.TotalBlocked, st.CacheEntries));
            }
            else sb.AppendLine("Engine: not answering.");
            var lists = st == null ? null : EngineClient.ListInfo();
            if (lists != null && lists.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Blocklists (a listed domain also covers its subdomains):");
                foreach (var kv in lists)
                {
                    string[] p = kv.Value.Split('@');
                    long count = 0, when = 0;
                    long.TryParse(p[0], out count);
                    if (p.Length > 1) long.TryParse(p[1], out when);
                    sb.AppendLine(string.Format(CultureInfo.CurrentCulture, "    {0}: {1:N0} domains, downloaded {2}", kv.Key, count,
                        when > 0 ? App.FromUnix(when).ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "not yet"));
                }
                if (st != null && st.Update.StartsWith("failed", StringComparison.OrdinalIgnoreCase)) sb.AppendLine("    Last refresh attempt " + st.Update);
            }
            sb.AppendLine();
            sb.AppendLine(string.Format("Your lists: {0} always allowed, {1} always blocked.", allowBox.Items.Count, blockBox.Items.Count));
            sb.AppendLine();
            sb.AppendLine("Aegis keeps settings and logs in " + App.Dir + ".");
            sb.AppendLine("To turn Aegis off for good, run uninstall.cmd in the Aegis folder.");
            aboutText.Text = sb.ToString();
        }

        void RefreshTab(bool force)
        {
            switch (tabs.SelectedIndex)
            {
                case 0: LoadRecent(force); break;
                case 1: if (force) LoadLists(); break;
                case 3: if (force) FillAbout(); break;
            }
        }

        void Do(string message)
        {
            statusLine.Text = message;
            LoadLists();
            logSignature = long.MinValue;
            RefreshTab(true);
        }

        public void ShowStatus(Shield s, EngineStatus st)
        {
            lastStatus = st;
            stateIcon.Image = stateImages[s];
            switch (s)
            {
                case Shield.On:
                    stateText.Text = "Aegis is filtering";
                    break;
                case Shield.Paused:
                    stateText.Text = "Paused until " + st.PausedUntilUtc.ToLocalTime().ToString("t", CultureInfo.CurrentCulture);
                    break;
                case Shield.Idle:
                    stateText.Text = "Not in use";
                    break;
                default:
                    stateText.Text = "The engine isn't answering";
                    break;
            }
            if (s == Shield.Off)
                countsText.Text = "If Windows still points at Aegis, the safety switch puts normal DNS back within a couple of minutes.";
            else if (s == Shield.Idle && st != null)
                countsText.Text = "Windows is sending its lookups somewhere else, so nothing is filtered. Run install.cmd in the Aegis folder to turn it on.";
            else if (st != null)
            {
                string updated = st.UpdatedUtc == DateTime.MinValue ? "no blocklist refresh recorded" : "oldest loaded list updated " + Fmt.Ago(DateTime.UtcNow - st.UpdatedUtc) + " ago";
                countsText.Text = string.Format(CultureInfo.CurrentCulture, "Today: {0:N0} of {1:N0} lookups blocked ({2}){3}{4:N0} domains on {5} blocklists\r\n{6}",
                    st.DayBlocked, st.DayQueries, Fmt.Percent(st.DayBlocked, st.DayQueries), Fmt.Dot, st.Domains, st.Lists, updated)
                    + (st.MissingLists > 0 ? Fmt.Dot + st.MissingLists + " blocklist(s) missing" : "")
                    + (st.Update.StartsWith("failed", StringComparison.OrdinalIgnoreCase) ? Fmt.Dot + "last refresh attempt failed" : "")
                    + (st.FallbackRecent ? "\r\nQuad9 isn't answering, so your router is standing in" : "");
            }
            pause10.Enabled = pause60.Enabled = update.Enabled = st != null;
            resume.Enabled = st != null && st.Paused;
        }

        // For checking the layout: renders each tab of a window with live data to <path>-<n>.png.
        public static int Snapshot(string path)
        {
            Application.EnableVisualStyles();
            var st = EngineStatus.Fetch(1500);
            bool? use = NetInfo.WindowsUsesAegis();
            Shield s = st == null ? Shield.Off : use == false ? Shield.Idle : st.Paused ? Shield.Paused : Shield.On;
            using (var w = new MainWindow { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000) })
            {
                w.ShowStatus(s, st);
                w.Show();
                for (int tab = 0; tab < w.tabs.TabCount; tab++)
                {
                    w.tabs.SelectedIndex = tab;
                    if (tab == 2) { w.checkInput.Text = "googleads.g.doubleclick.net"; w.RunCheck(); Thread.Sleep(1500); }
                    for (int i = 0; i < 20; i++) { Application.DoEvents(); Thread.Sleep(25); }
                    using (var bmp = new Bitmap(w.Width, w.Height))
                    {
                        w.DrawToBitmap(bmp, new Rectangle(0, 0, w.Width, w.Height));
                        bmp.Save(path + "-" + tab + ".png", ImageFormat.Png);
                    }
                }
                w.Close();
            }
            return 0;
        }
    }

    static class NativeDpi
    {
        [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    }

    // ------------------------------------------------------------------ the command line

    static class Cli
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int processId);

        const string Help =
            "Aegis DNS filter - commands:\n" +
            "  Aegis.exe                 open the window (starts the tray icon if needed)\n" +
            "  Aegis.exe status          is it running? today's counts, lists, Windows DNS\n" +
            "  Aegis.exe recent [N]      the N latest blocked names of the last 7 days (default 30)\n" +
            "  Aegis.exe check NAME      is NAME blocked, and by which rule?\n" +
            "  Aegis.exe allow NAME      never block NAME or its subdomains\n" +
            "  Aegis.exe block NAME      always block NAME and its subdomains\n" +
            "  Aegis.exe unallow NAME | unblock NAME\n" +
            "  Aegis.exe pause [MIN]     stop filtering for a while (default 10 minutes)\n" +
            "  Aegis.exe resume          filter again now\n" +
            "  Aegis.exe update          download fresh blocklists now\n" +
            "From PowerShell, add | Out-String so the output waits for the command.";

        public static bool IsCommand(string a)
        {
            switch (a.ToLowerInvariant())
            {
                case "status": case "recent": case "check": case "allow": case "block": case "unallow": case "unblock":
                case "pause": case "resume": case "update": case "help": case "--help": case "-h": case "/?":
                    return true;
                default:
                    return false;
            }
        }

        public static int Run(string[] args)
        {
            if (!Console.IsOutputRedirected && AttachConsole(-1)) Console.WriteLine();
            try { return Dispatch(args); }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
                return 1;
            }
        }

        static int Dispatch(string[] args)
        {
            string cmd = args[0].ToLowerInvariant();
            string arg = args.Length > 1 ? args[1] : null;
            switch (cmd)
            {
                case "status": return Status();
                case "recent": return Recent(arg == null ? 30 : int.Parse(arg, CultureInfo.InvariantCulture));
                case "check": return WithDomain(arg, Actions.Explain);
                case "allow": return WithDomain(arg, Actions.Allow);
                case "block": return WithDomain(arg, Actions.Block);
                case "unallow": return WithDomain(arg, Actions.Unallow);
                case "unblock": return WithDomain(arg, Actions.Unblock);
                case "pause":
                    int minutes = arg == null ? 10 : int.Parse(arg, CultureInfo.InvariantCulture);
                    Console.WriteLine(Actions.PauseFor(TimeSpan.FromMinutes(Math.Max(1, Math.Min(minutes, 24 * 60)))));
                    return 0;
                case "resume":
                    Console.WriteLine(Actions.Resume());
                    return 0;
                case "update":
                    Console.WriteLine(Actions.Update());
                    return 0;
                default:
                    Console.WriteLine(Help);
                    return 0;
            }
        }

        static int WithDomain(string arg, Func<string, string> act)
        {
            string d = Names.Normalize(arg);
            if (d == null)
            {
                Console.WriteLine("Give a site name, for example: Aegis.exe check ads.example.com");
                return 1;
            }
            Console.WriteLine(act(d));
            return 0;
        }

        static int Status()
        {
            var st = EngineStatus.Fetch(1500);
            Console.WriteLine(App.Title + " " + App.Version + " in " + App.Dir);
            if (st == null) Console.WriteLine("Engine:   NOT answering on 127.0.0.1:53");
            else Console.WriteLine("Engine:   " + (st.Paused ? "PAUSED until " + st.PausedUntilUtc.ToLocalTime().ToString("t", CultureInfo.CurrentCulture) : "filtering")
                + ", running for " + Fmt.Ago(TimeSpan.FromSeconds(st.Uptime)));
            bool? uses = NetInfo.WindowsUsesAegis();
            if (uses == true) Console.WriteLine("Windows:  sends its lookups to Aegis");
            else if (uses == null) Console.WriteLine("Windows:  offline (no adapter with a gateway)");
            else Console.WriteLine("Windows:  NOT using Aegis: " + string.Join("; ", NetInfo.InternetAdapterDns().Select(kv => kv.Key + " -> " + string.Join(", ", kv.Value))));
            if (st == null) return 1;
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture, "Today:    {0:N0} of {1:N0} lookups blocked ({2})", st.DayBlocked, st.DayQueries, Fmt.Percent(st.DayBlocked, st.DayQueries)));
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture, "Lists:    {0:N0} domains on {1} blocklists. Oldest loaded list updated {2}.", st.Domains, st.Lists,
                st.UpdatedUtc == DateTime.MinValue ? "at an unknown time" : Fmt.Ago(DateTime.UtcNow - st.UpdatedUtc) + " ago"));
            if (st.Update != "never" && st.Update.Length > 0)
                Console.WriteLine("          Last refresh attempt " + (st.Update == "ok" ? "succeeded" : st.Update));
            if (st.MissingLists > 0) Console.WriteLine("          " + st.MissingLists + " configured blocklist(s) not loaded yet (retried every 30 s)");
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture, "Yours:    {0} always allowed, {1} always blocked", st.AllowEntries, st.BlockEntries));
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture, "Upstream: answers in {0:0.0} ms on average; router {1}; {2:N0} answers cached", st.UpstreamMs, st.Router, st.CacheEntries));
            var top = Kv.Parse(EngineClient.AskTxt("top" + App.ControlSuffix, 1500));
            if (top.Count > 0) Console.WriteLine("Top blocked since start: " + string.Join(", ", top.Select(kv => kv.Key + " (" + kv.Value + ")")));
            return 0;
        }

        static int Recent(int n)
        {
            var rows = BlockLog.Recent().Take(Math.Max(1, n)).ToList();
            if (rows.Count == 0)
            {
                Console.WriteLine("Nothing blocked in the last " + BlockLog.HistoryDays + " days.");
                return 0;
            }
            Console.WriteLine("Last " + rows.Count + " blocked names, newest first:");
            foreach (var r in rows)
                Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "  {0:MM-dd HH:mm:ss}  {1,-45} {2,5}x  {3} ({4})", r.Last, r.Name, r.Count, r.Source, r.Rule));
            return 0;
        }
    }
}
