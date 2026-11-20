// Atlas's treemap: every folder and file as a block sized by the space it takes, laid out with the
// squarified algorithm (Bruls, Huizing and van Wijk) and coloured by kind of file.
// - Things too small to point at (under about 11x11 pixels) are gathered into one "smaller items"
//   block per folder, so every block on the map can be hovered.
// - A folder too small to open up is drawn whole, in the colour of what mostly fills it.
// - A folder that's little more than one subfolder shares that subfolder's name strip
//   ("Program Files (x86)\Steam\steamapps\common") instead of stacking a strip per level.
// - Text uses grayscale anti-aliasing (ClearType's colour fringes look ragged on coloured blocks)
//   and ends in "…" when it doesn't fit.
// Hovering shows a card with the details; double-click goes a level deeper.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Atlas
{
    static class Squarify
    {
        // One rectangle per size (sizes biggest first), together filling r. Sizes of 0 get none.
        public static RectangleF[] Layout(IList<double> sizes, RectangleF r)
        {
            int n = sizes.Count;
            var res = new RectangleF[n];
            double total = 0;
            for (int i = 0; i < n; i++) total += Math.Max(0, sizes[i]);
            if (n == 0 || total <= 0 || r.Width <= 0 || r.Height <= 0) return res;
            double scale = (double)r.Width * r.Height / total;
            double x = r.X, y = r.Y, w = r.Width, h = r.Height;
            int k = 0;
            while (k < n)
            {
                double side = Math.Min(w, h);
                double first = sizes[k] * scale;
                if (side <= 0 || first <= 0) break;
                int start = k;
                double sum = first, worst = Worst(first, first, sum, side);
                k++;
                while (k < n)
                {
                    double a = sizes[k] * scale;
                    if (a <= 0) break;
                    double next = Worst(first, a, sum + a, side);
                    if (next > worst) break;
                    sum += a;
                    worst = next;
                    k++;
                }
                if (w >= h)
                {
                    double colW = sum / h, yy = y;
                    for (int i = start; i < k; i++)
                    {
                        double ih = sizes[i] * scale / colW;
                        res[i] = new RectangleF((float)x, (float)yy, (float)colW, (float)ih);
                        yy += ih;
                    }
                    x += colW;
                    w -= colW;
                }
                else
                {
                    double rowH = sum / w, xx = x;
                    for (int i = start; i < k; i++)
                    {
                        double iw = sizes[i] * scale / rowH;
                        res[i] = new RectangleF((float)xx, (float)y, (float)iw, (float)rowH);
                        xx += iw;
                    }
                    y += rowH;
                    h -= rowH;
                }
            }
            return res;
        }

        static double Worst(double biggest, double smallest, double sum, double side)
        {
            double s2 = sum * sum, w2 = side * side;
            return Math.Max(w2 * biggest / s2, s2 / (w2 * smallest));
        }
    }

    // One block on the map.
    sealed class MapBlock
    {
        public RectangleF R;
        public Node Node;          // the folder or file; for "smaller items" and "hidden": the folder they sit in
        public byte Kind;          // Kinds.*
        public long Size;
        public bool Pseudo;        // "smaller items" or "hidden from Atlas", not one real file or folder
        public int Depth;
        public MapBlock Parent;    // the folder block it sits in (null at the top level)
        public string Title;       // folders: the name strip's text, which may name a chain of folders
        public bool Header;        // an opened folder with a name strip
        public bool Solid;         // a folder too small to open up, drawn whole
        public byte Fill;          // Solid: the kind of file that mostly fills it
        public long Count, Files;  // pseudo: how many things, and how many files, it stands for
        public List<Node> Members; // "smaller items": the files and folders gathered into it, biggest first

        public bool IsFolderBox { get { return !Pseudo && !Solid && Node.IsDir; } }
        public byte Paint { get { return Solid ? Fill : Kind; } }
        public float Area { get { return R.Width * R.Height; } }
    }

    // Works out the blocks for one folder in one rectangle. No drawing here, so it can be tested.
    sealed class MapLayout
    {
        public float HeaderH = 17, MinArea = 121, MinOpen = 22, Pad = 1.5f, HeaderMinW = 48;
        public double LeadShare = 0.9;   // a subfolder holding this share of its folder shares the folder's name strip
        public int MaxBlocks = 60000;
        public readonly List<MapBlock> Blocks = new List<MapBlock>();
        MapInfo map;

        public static MapLayout ForScreen()
        {
            int unit = Ui.S(11);
            return new MapLayout
            {
                HeaderH = Ui.S(17), MinArea = unit * unit, MinOpen = Ui.S(22),
                Pad = Math.Max(1.5f, 1.5f * Ui.Scale), HeaderMinW = Ui.S(48)
            };
        }

        public bool HasHeader(RectangleF r) { return r.Height >= HeaderH * 2.6f && r.Width >= HeaderMinW; }

        public void Build(MapInfo m, Node root, RectangleF r)
        {
            Blocks.Clear();
            map = m;
            if (m == null || root == null || r.Width < 2 || r.Height < 2) return;
            Lay(root, r, 0, null, null, null);
        }

        // Adds the blocks for what's inside a folder. Returns false, adding nothing, when all it would
        // show is one "smaller items" block: the folder is drawn whole instead.
        bool Lay(Node folder, RectangleF r, int depth, MapBlock parent, string carry, Node carryTo)
        {
            var parts = new List<MapBlock>();
            if (folder.Kids != null)
                foreach (var k in folder.Kids)
                    if (k.Size > 0) parts.Add(new MapBlock { Node = k, Kind = k.Kind, Size = k.Size });
            if (folder.SmallSize > 0)
                parts.Add(new MapBlock { Node = folder, Kind = Kinds.Small, Size = folder.SmallSize, Pseudo = true, Count = folder.SmallCount, Files = folder.SmallCount });
            if (folder == map.Root && map.Unseen > 0)
                parts.Add(new MapBlock { Node = folder, Kind = Kinds.Hidden, Size = map.Unseen, Pseudo = true });
            if (parts.Count == 0) return true;
            parts.Sort((a, b) => b.Size.CompareTo(a.Size));
            parts = Gather(parts, folder, r);
            if (parent != null && parts.Count == 1 && parts[0].Members != null) return false;
            var rects = Squarify.Layout(parts.Select(p => (double)p.Size).ToList(), r);
            for (int i = 0; i < parts.Count; i++)
            {
                var b = parts[i];
                b.R = rects[i];
                b.Depth = depth;
                b.Parent = parent;
                if (b.Area < 0.5f) continue;
                Blocks.Add(b);
                if (b.Pseudo || !b.Node.IsDir) continue;
                b.Title = (carry != null && b.Node == carryTo ? carry + "\\" : "") + b.Node.Name;
                if (b.R.Width < MinOpen || b.R.Height < MinOpen || Blocks.Count > MaxBlocks) { MakeSolid(b); continue; }
                var lead = Leading(b.Node, LeadShare);
                if (lead != null)
                {
                    // no strip of its own: its big subfolder's strip names both
                    if (!Lay(b.Node, b.R, depth + 1, b, b.Title, lead)) MakeSolid(b);
                    continue;
                }
                var inner = RectangleF.Inflate(b.R, -Pad, -Pad);
                b.Header = HasHeader(b.R);
                if (b.Header) { inner.Y += HeaderH; inner.Height -= HeaderH; }
                if (inner.Width < 2 || inner.Height < 2 || !Lay(b.Node, inner, depth + 1, b, null, null)) MakeSolid(b);
            }
            return true;
        }

        static void MakeSolid(MapBlock b)
        {
            b.Solid = true;
            b.Header = false;
            b.Fill = MainKind(b.Node);
        }

        // Folds the parts too small to point at into one "smaller items" block, when there are two or
        // more of them. Space Atlas couldn't see always keeps its own block.
        List<MapBlock> Gather(List<MapBlock> parts, Node folder, RectangleF r)
        {
            double total = 0;
            foreach (var p in parts) total += p.Size;
            double scale = (double)r.Width * r.Height / total;
            int first = parts.FindIndex(p => p.Kind != Kinds.Hidden && p.Size * scale < MinArea);
            if (first < 0) return parts;
            int tiny = 0;
            for (int i = first; i < parts.Count; i++) if (parts[i].Kind != Kinds.Hidden) tiny++;
            if (tiny < 2) return parts;
            var rest = new MapBlock { Node = folder, Kind = Kinds.Small, Pseudo = true, Members = new List<Node>() };
            var kept = new List<MapBlock>(first + 2);
            for (int i = 0; i < parts.Count; i++)
            {
                var p = parts[i];
                if (i < first || p.Kind == Kinds.Hidden) { kept.Add(p); continue; }
                rest.Size += p.Size;
                if (p.Pseudo) { rest.Count += p.Count; rest.Files += p.Files; }
                else { rest.Members.Add(p.Node); rest.Count++; rest.Files += p.Node.IsDir ? p.Node.Files : 1; }
            }
            kept.Add(rest);
            kept.Sort((a, b) => b.Size.CompareTo(a.Size));
            return kept;
        }

        // The kind of file that mostly fills a folder: follows the biggest thing inside, level by level.
        public static byte MainKind(Node n)
        {
            for (int guard = 0; n != null && guard < 256; guard++)
            {
                if (!n.IsDir) return n.Kind;
                if (n.Kids == null || n.Kids.Length == 0 || n.SmallSize >= n.Kids[0].Size) return Kinds.Small;
                n = n.Kids[0];
            }
            return Kinds.Folder;
        }

        // The subfolder holding at least "share" of a folder, if there is one.
        public static Node Leading(Node n, double share)
        {
            if (n.Kids == null || n.Kids.Length == 0) return null;
            var k = n.Kids[0];
            return k.IsDir && k.Size > 0 && k.Size >= n.Size * share ? k : null;
        }

        // The block under a point: the innermost one. A sliver thinner than "thin" reaches half that
        // further out, and within its reach it wins over its big neighbour, so it can be pointed at.
        public MapBlock At(PointF p, float thin)
        {
            MapBlock hit = null;
            for (int i = Blocks.Count - 1; i >= 0 && hit == null; i--) if (Blocks[i].R.Contains(p)) hit = Blocks[i];
            float reach = thin / 2;
            for (int i = Blocks.Count - 1; i >= 0; i--)
            {
                var b = Blocks[i];
                if (b == hit || b.IsFolderBox || (b.R.Width >= thin && b.R.Height >= thin)) continue;
                if (RectangleF.Inflate(b.R, b.R.Width < thin ? reach : 0, b.R.Height < thin ? reach : 0).Contains(p)) return b;
            }
            return hit;
        }

        // The block showing a node: its own, the "smaller items" it was gathered into, or the nearest
        // folder around it that's on the map.
        public MapBlock Find(Node n)
        {
            for (var x = n; x != null; x = x.Parent)
                foreach (var b in Blocks)
                {
                    if (b.Node == x && !b.Pseudo) return b;
                    if (b.Members != null && b.Members.Contains(x)) return b;
                }
            return null;
        }
    }

    sealed class TreemapView : Control
    {
        sealed class CardLine
        {
            public string Text;
            public Font Font;
            public Color Color;
            public TextFormatFlags Flags;
        }

        readonly MapLayout layout = MapLayout.ForScreen();
        MapInfo map;
        Node root;
        Bitmap cache;
        MapBlock hover, mark;
        Point mouse;
        Point? pinned;     // snapshots only: a pointer position that survives rebuilds
        bool cardHidden;
        readonly Timer resizeTimer = new Timer { Interval = 150 };
        readonly Font labelFont, headFont, cardFont, cardBold;
        readonly int thinHit = Ui.S(6), labelMinW = Ui.S(44);

        // Map labels: GDI+ anti-aliasing without grid-fitting, so the font keeps its own spacing and
        // coloured blocks get no ClearType colour fringes. The details card: GDI ClearType, which
        // looks right on its plain dark background.
        static readonly StringFormat LineFormat = MapFormat(StringAlignment.Near);
        static readonly StringFormat MiddleFormat = MapFormat(StringAlignment.Center);
        const TextFormatFlags LineFlags = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding;
        const TextFormatFlags PathFlags = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.PathEllipsis | TextFormatFlags.NoPadding;
        // Measuring with an ellipsis flag on gives the width of an already shortened text, so measure without.
        const TextFormatFlags MeasureFlags = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.NoPadding;
        static readonly Color HeadText = Color.FromArgb(0xF4, 0xF1, 0xEC), MarkColor = Color.FromArgb(0xFF, 0xD5, 0x4F);

        public event Action<Node> NodeClicked, NodeOpened;
        public event Action<string> Hovered;
        public event Action<Node, Point> MenuRequested;
        public event Action Rebuilt;
        public Node Root { get { return root; } }

        public TreemapView()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Color.FromArgb(0x2B, 0x2B, 0x2B);
            float size = Math.Max(7.5f, Ui.Base.Size * 0.95f);
            labelFont = new Font(Ui.Base.FontFamily, size);
            headFont = SemiBold(size);
            cardFont = new Font(Ui.Base.FontFamily, Ui.Base.Size);
            cardBold = SemiBold(Ui.Base.Size * 1.05f);
            resizeTimer.Tick += (s, e) => { resizeTimer.Stop(); Rebuild(); };
        }

        static StringFormat MapFormat(StringAlignment line)
        {
            var f = new StringFormat(StringFormat.GenericTypographic);
            f.FormatFlags = StringFormatFlags.NoWrap | StringFormatFlags.LineLimit;
            f.Trimming = StringTrimming.EllipsisCharacter;
            f.LineAlignment = line;
            return f;
        }

        static Font SemiBold(float size)
        {
            try
            {
                var f = new Font("Segoe UI Semibold", size);
                if (f.Name == "Segoe UI Semibold") return f;
                f.Dispose();
            }
            catch (Exception) { }
            return new Font(Ui.Base.FontFamily, size, FontStyle.Bold);
        }

        public void Display(MapInfo m, Node folder)
        {
            map = m;
            root = folder;
            Rebuild();
        }

        public void Clear()
        {
            map = null;
            root = null;
            Rebuild();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            resizeTimer.Stop();
            resizeTimer.Start();
        }

        public void Rebuild()
        {
            hover = null;
            mark = null;
            if (cache != null) { cache.Dispose(); cache = null; }
            if (Width >= 8 && Height >= 8) layout.Build(map, root, new RectangleF(0, 0, Width, Height));
            else layout.Blocks.Clear();
            if (layout.Blocks.Count > 0)
            {
                cache = new Bitmap(Width, Height, PixelFormat.Format32bppRgb);   // opaque: GDI text needs no alpha
                using (var g = Graphics.FromImage(cache)) Render(g);
            }
            if (pinned.HasValue) { mouse = pinned.Value; hover = layout.At(mouse, thinHit); }
            Invalidate();
            if (Rebuilt != null) Rebuilt();
        }

        public static Color Shade(Color c, float f)
        {
            if (f >= 1)
            {
                float t = Math.Min(1, f - 1);
                return Color.FromArgb(c.R + (int)((255 - c.R) * t), c.G + (int)((255 - c.G) * t), c.B + (int)((255 - c.B) * t));
            }
            return Color.FromArgb((int)(c.R * f), (int)(c.G * f), (int)(c.B * f));
        }

        public static bool Light(Color c) { return c.R * 0.299 + c.G * 0.587 + c.B * 0.114 > 150; }

        // Diagonal lines that mark a "smaller items" block (dark on light colours, light on dark ones).
        public static HatchBrush Hatch(Color under)
        {
            return new HatchBrush(HatchStyle.WideUpwardDiagonal, Light(under) ? Color.FromArgb(46, 0, 0, 0) : Color.FromArgb(46, 255, 255, 255), Color.Transparent);
        }

        void Render(Graphics g)
        {
            g.Clear(BackColor);
            g.SmoothingMode = SmoothingMode.None;
            g.TextRenderingHint = TextRenderingHint.AntiAlias;
            var brushes = new Dictionary<int, SolidBrush>();
            var pens = new Dictionary<int, Pen>();
            Func<Color, SolidBrush> brush = c => { SolidBrush b; if (!brushes.TryGetValue(c.ToArgb(), out b)) brushes[c.ToArgb()] = b = new SolidBrush(c); return b; };
            Func<Color, Pen> pen = c => { Pen p; if (!pens.TryGetValue(c.ToArgb(), out p)) pens[c.ToArgb()] = p = new Pen(c); return p; };
            var texts = new List<MapBlock>();
            float lineH = labelFont.GetHeight(g);
            try
            {
                foreach (var b in layout.Blocks)
                {
                    var r = b.R;
                    if (b.IsFolderBox)
                    {
                        Color bg = FolderBack(b.Depth);
                        g.FillRectangle(brush(bg), r);
                        if (b.Header)
                        {
                            g.FillRectangle(brush(Shade(bg, 0.8f)), new RectangleF(r.X, r.Y, r.Width, layout.Pad + layout.HeaderH));
                            texts.Add(b);
                        }
                        continue;
                    }
                    Color c = Kinds.Colors[b.Paint];
                    if (r.Width >= 6 && r.Height >= 6)
                    {
                        using (var gb = new LinearGradientBrush(RectangleF.Inflate(r, 1, 1), Shade(c, 1.22f), Shade(c, 0.78f), LinearGradientMode.ForwardDiagonal))
                            g.FillRectangle(gb, r);
                        if (b.Members != null) using (var h = Hatch(c)) g.FillRectangle(h, r);
                    }
                    else g.FillRectangle(brush(c), r);
                    if (r.Width >= 3 && r.Height >= 3) g.DrawRectangle(pen(Shade(c, 0.5f)), r.X, r.Y, r.Width - 1, r.Height - 1);
                    if (r.Width >= labelMinW && r.Height >= lineH + 4) texts.Add(b);
                }
                foreach (var b in texts)
                {
                    if (b.IsFolderBox) HeaderText(g, b);
                    else LeafText(g, b, Kinds.Colors[b.Paint], lineH);
                }
            }
            finally
            {
                foreach (var x in brushes.Values) x.Dispose();
                foreach (var x in pens.Values) x.Dispose();
            }
        }

        static Color FolderBack(int depth) { return Shade(Kinds.Colors[Kinds.Folder], 1f + Math.Min(depth, 12) * 0.04f); }

        static Color Mix(Color a, Color b, float t)
        {
            return Color.FromArgb((int)(a.R * t + b.R * (1 - t)), (int)(a.G * t + b.G * (1 - t)), (int)(a.B * t + b.B * (1 - t)));
        }

        // Text with an optional 1-pixel shadow underneath (a darker shade of what's behind it).
        static void Write(Graphics g, string s, Font f, RectangleF r, Color c, Color shadow, StringFormat fmt)
        {
            if (!shadow.IsEmpty)
                using (var sb = new SolidBrush(shadow)) g.DrawString(s, f, sb, new RectangleF(r.X + 1, r.Y + 1, r.Width, r.Height), fmt);
            using (var b = new SolidBrush(c)) g.DrawString(s, f, b, r, fmt);
        }

        static float Measure(Graphics g, string s, Font f) { return g.MeasureString(s, f, PointF.Empty, LineFormat).Width; }

        // A folder's name strip: its name and size. When both don't fit, the name wins; a chain of
        // folders shortens to its first and last ("PAYDAY3\…\Paks"), then to its first, cut with "…".
        void HeaderText(Graphics g, MapBlock b)
        {
            var r = b.R;
            float x = r.X + layout.Pad + 3, y = r.Y + layout.Pad, w = r.Width - 2 * layout.Pad - 6, hh = layout.HeaderH;
            if (w < Ui.S(14)) return;
            Color strip = Shade(FolderBack(b.Depth), 0.8f), shadow = Shade(strip, 0.45f);
            string title = b.Title, size = Fmt.Size(b.Size);
            float gap = Ui.S(6), titleW = Measure(g, title, headFont), sizeW = Measure(g, size, labelFont);
            if (titleW + gap + sizeW <= w)
            {
                Write(g, title, headFont, new RectangleF(x, y, titleW + 2, hh), HeadText, shadow, MiddleFormat);
                Write(g, size, labelFont, new RectangleF(x + titleW + gap, y, sizeW + 2, hh), Mix(HeadText, strip, 0.68f), shadow, MiddleFormat);
                return;
            }
            string fit = title;
            var names = title.Split('\\');
            if (names.Length > 1 && titleW > w)
            {
                string ends = names[0] + "\\…\\" + names[names.Length - 1];
                fit = names.Length > 2 && Measure(g, ends, headFont) <= w ? ends : names[0];
            }
            Write(g, fit, headFont, new RectangleF(x, y, w, hh), HeadText, shadow, MiddleFormat);
        }

        // A block's name, and its size underneath when there's room.
        void LeafText(Graphics g, MapBlock b, Color c, float lineH)
        {
            bool light = Light(c);
            Color fore = light ? Color.FromArgb(0x1C, 0x1C, 0x1C) : Color.White;
            Color shadow = light ? Color.Empty : Shade(c, 0.42f);
            var r = b.R;
            var line = new RectangleF(r.X + 3, r.Y + 2, r.Width - 6, lineH + 1);
            Write(g, Caption(b), labelFont, line, fore, shadow, LineFormat);
            if (r.Height >= lineH * 2 + 6)
                Write(g, Fmt.Size(b.Size), labelFont, new RectangleF(line.X, line.Y + lineH, line.Width, lineH + 1), Mix(fore, c, 0.78f), shadow, LineFormat);
        }

        static string Caption(MapBlock b)
        {
            if (b.Kind == Kinds.Hidden) return "Hidden from Atlas";
            if (b.Pseudo) return Fmt.Plural(b.Count, b.Members != null ? "smaller item" : "smaller file");
            return b.Node.Name;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            if (cache == null)
            {
                g.Clear(BackColor);
                TextRenderer.DrawText(g, map == null ? "Pick a drive above to map it." : "Nothing here takes up space.", Ui.Base, ClientRectangle,
                    Color.Gainsboro, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                return;
            }
            g.DrawImageUnscaled(cache, 0, 0);
            if (mark != null)
                using (var p = new Pen(MarkColor, Math.Max(2, Ui.S(2))) { Alignment = PenAlignment.Inset })
                    g.DrawRectangle(p, Rectangle.Round(mark.R));
            if (hover == null) return;
            if (hover.Parent != null && hover.Parent != mark)
                using (var p = new Pen(Color.FromArgb(130, 255, 255, 255)) { Alignment = PenAlignment.Inset })
                    g.DrawRectangle(p, Rectangle.Round(hover.Parent.R));
            using (var br = new SolidBrush(Color.FromArgb(hover.IsFolderBox ? 26 : 60, 255, 255, 255))) g.FillRectangle(br, hover.R);
            using (var p = new Pen(Color.White, Math.Max(2, Ui.S(2))) { Alignment = PenAlignment.Inset })
                g.DrawRectangle(p, Rectangle.Round(hover.R));
            if (!cardHidden) DrawCard(g, hover);
        }

        long ViewTotal() { return root == null ? 0 : root.Size + (map != null && root == map.Root ? map.Unseen : 0); }

        static string Share(long part, long total)
        {
            if (total <= 0) return "";
            double p = part * 100.0 / total;
            return p >= 10 ? p.ToString("0") + "%" : p >= 0.1 ? p.ToString("0.0") + "%" : "under 0.1%";
        }

        List<CardLine> Card(MapBlock b)
        {
            var lines = new List<CardLine>();
            Color plain = Color.FromArgb(0xE6, 0xE6, 0xE6), dim = Color.FromArgb(0xA8, 0xA8, 0xA8);
            Action<string, Font, Color, TextFormatFlags> add = (t, f, c, fl) => lines.Add(new CardLine { Text = t, Font = f, Color = c, Flags = fl });
            string share = Share(b.Size, ViewTotal()) + " of " + root.Name;
            if (b.Kind == Kinds.Hidden)
            {
                add("Hidden from Atlas", cardBold, Color.White, LineFlags);
                add(Fmt.Size(b.Size) + " · " + share, cardFont, plain, LineFlags);
                add(map.Elevated ? "Space Windows uses outside any folder: restore points, the file table, reserved storage."
                                 : "Restore points, Windows' file table and folders that need admin (Complete scan sees more).", cardFont, dim, LineFlags);
                return lines;
            }
            if (b.Pseudo)
            {
                add(Caption(b), cardBold, Color.White, LineFlags);
                add(Fmt.Size(b.Size) + " · " + share + " · " + Fmt.Plural(b.Files, "file"), cardFont, plain, LineFlags);
                add(b.Node.FullPath, cardFont, dim, PathFlags);
                if (b.Members != null && b.Members.Count > 0)
                    add("Biggest: " + string.Join(", ", b.Members.Take(3).Select(n => n.Name + " " + Fmt.Size(n.Size))), cardFont, dim, LineFlags);
                return lines;
            }
            var node = b.Node;
            string what = node.IsDir ? Fmt.Plural(node.Files, "file") + (node.Dirs > 0 ? " in " + Fmt.Plural(node.Dirs, "folder") : "") : Kinds.Names[node.Kind];
            add(node.Name, cardBold, Color.White, LineFlags);
            add(Fmt.Size(b.Size) + " · " + share + " · " + what, cardFont, plain, LineFlags);
            add(node.FullPath, cardFont, dim, PathFlags);
            if (b.Solid) add("Mostly " + (b.Fill == Kinds.Small ? "smaller files" : Kinds.Names[b.Fill].ToLowerInvariant()), cardFont, dim, LineFlags);
            if (node.ModifiedUtc != DateTime.MinValue) add((node.IsDir ? "Newest change " : "Changed ") + Fmt.Local(node.ModifiedUtc), cardFont, dim, LineFlags);
            add(node.IsDir ? "Double-click to zoom in · right-click for more" : "Right-click for more", cardFont, dim, LineFlags);
            return lines;
        }

        // The details card next to the pointer.
        void DrawCard(Graphics g, MapBlock b)
        {
            if (root == null || map == null) return;
            var lines = Card(b);
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;   // a plain dark card: ClearType has no colours to fringe against
            int maxW = Ui.S(430), padX = Ui.S(10), padY = Ui.S(7), gapY = Ui.S(1);
            var sizes = new List<Size>();
            int w = 0, h = 0;
            foreach (var l in lines)
            {
                var s = TextRenderer.MeasureText(g, l.Text, l.Font, Size.Empty, MeasureFlags);
                s.Width = Math.Min(maxW, s.Width);
                sizes.Add(s);
                w = Math.Max(w, s.Width);
                h += s.Height + gapY;
            }
            h -= gapY;
            var box = new Rectangle(mouse.X + Ui.S(16), mouse.Y + Ui.S(20), w + padX * 2, h + padY * 2);
            if (box.Right > Width - 2) box.X = Math.Max(2, mouse.X - Ui.S(12) - box.Width);
            if (box.Bottom > Height - 2) box.Y = Math.Max(2, mouse.Y - Ui.S(12) - box.Height);
            using (var path = Rounded(box, Ui.S(6)))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using (var fill = new SolidBrush(Color.FromArgb(244, 0x1E, 0x1E, 0x20))) g.FillPath(fill, path);
                using (var edge = new Pen(Color.FromArgb(80, 255, 255, 255))) g.DrawPath(edge, path);
                g.SmoothingMode = SmoothingMode.None;
            }
            int y = box.Y + padY;
            for (int i = 0; i < lines.Count; i++)
            {
                TextRenderer.DrawText(g, lines[i].Text, lines[i].Font, new Rectangle(box.X + padX, y, w, sizes[i].Height), lines[i].Color, lines[i].Flags);
                y += sizes[i].Height + gapY;
            }
        }

        static GraphicsPath Rounded(RectangleF r, float radius)
        {
            float d = radius * 2;
            var p = new GraphicsPath();
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        // Outlines a folder or file if it's on the map right now (or what shows it: the "smaller
        // items" it was gathered into, or the folder around it).
        public void Mark(Node n)
        {
            mark = n == null ? null : layout.Find(n);
            Invalidate();
        }

        // For window snapshots: show the card as if the pointer were at p (kept through rebuilds).
        public void HoverAt(Point p)
        {
            pinned = p;
            mouse = p;
            hover = layout.At(p, thinHit);
            Invalidate();
        }

        // The kinds of file on the map now, the most space first (for the legend).
        public List<byte> KindsShown()
        {
            var area = new Dictionary<byte, double>();
            foreach (var b in layout.Blocks)
            {
                if (b.IsFolderBox) continue;
                double a;
                area.TryGetValue(b.Paint, out a);
                area[b.Paint] = a + b.Area;
            }
            return area.Where(x => x.Value >= 40).OrderByDescending(x => x.Value).Select(x => x.Key).ToList();
        }

        string Describe(MapBlock b)
        {
            if (b == null) return "";
            if (b.Kind == Kinds.Hidden) return "Hidden from Atlas: " + Fmt.Size(b.Size) + (map.Elevated ? " (restore points, Windows' file table, reserved storage)" : " (restore points, Windows' file table, folders that need admin; Complete scan sees more)");
            if (b.Pseudo) return b.Node.FullPath + " — " + Caption(b) + ", " + Fmt.Size(b.Size);
            return b.Node.FullPath + " — " + Fmt.Size(b.Size) + (b.Node.IsDir ? " · " + Fmt.Plural(b.Node.Files, "file") : " · " + Kinds.Names[b.Kind]);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (e.Location == mouse && !cardHidden) return;
            mouse = e.Location;
            cardHidden = false;
            var b = layout.At(e.Location, thinHit);
            if (b != hover)
            {
                hover = b;
                if (Hovered != null) Hovered(Describe(b));
            }
            Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (hover == null) return;
            hover = null;
            Invalidate();
            if (Hovered != null) Hovered("");
        }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            var b = layout.At(e.Location, thinHit);
            if (b == null) return;
            if (e.Button == MouseButtons.Left)
            {
                mark = b.Pseudo ? null : b;
                Invalidate();
                if (NodeClicked != null) NodeClicked(b.Node);
            }
            else if (e.Button == MouseButtons.Right && !b.Pseudo && MenuRequested != null)
            {
                cardHidden = true;
                Invalidate();
                MenuRequested(b.Node, e.Location);
            }
        }

        // Double-click goes one level deeper: into the folder under the pointer that sits directly
        // inside what's shown now.
        protected override void OnMouseDoubleClick(MouseEventArgs e)
        {
            base.OnMouseDoubleClick(e);
            var b = layout.At(e.Location, thinHit);
            if (b == null || root == null) return;
            var n = b.Node;
            while (n != null && n.Parent != root && n != root) n = n.Parent;
            if (n != null && n != root && n.IsDir && NodeOpened != null) NodeOpened(n);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                resizeTimer.Dispose();
                labelFont.Dispose();
                headFont.Dispose();
                cardFont.Dispose();
                cardBold.Dispose();
                if (cache != null) cache.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    // The colour key under the map: the kinds of file it shows, the most space first.
    sealed class KindLegend : Control
    {
        List<byte> kinds = new List<byte>();

        public KindLegend()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = Ui.S(24);
            ForeColor = Color.FromArgb(0x50, 0x50, 0x50);
        }

        public void SetKinds(List<byte> shown)
        {
            kinds = shown ?? new List<byte>();
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            int x = 0, chip = Ui.S(11), gap = Ui.S(16), space = Ui.S(5);
            foreach (var k in kinds)
            {
                string name = k == Kinds.Small ? "Smaller items" : Kinds.Names[k];
                var size = TextRenderer.MeasureText(g, name, Font, Size.Empty, TextFormatFlags.NoPadding);
                if (x + chip + space + size.Width > Width) break;
                var cr = new Rectangle(x, (Height - chip) / 2, chip, chip);
                Color c = Kinds.Colors[k];
                using (var b = new SolidBrush(c)) g.FillRectangle(b, cr);
                if (k == Kinds.Small) using (var h = TreemapView.Hatch(c)) g.FillRectangle(h, cr);
                using (var p = new Pen(TreemapView.Shade(c, 0.55f))) g.DrawRectangle(p, cr.X, cr.Y, cr.Width - 1, cr.Height - 1);
                TextRenderer.DrawText(g, name, Font, new Point(x + chip + space, (Height - size.Height) / 2), ForeColor, TextFormatFlags.NoPadding);
                x += chip + space + size.Width + gap;
            }
        }
    }
}
