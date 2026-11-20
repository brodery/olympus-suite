// Olympus icon artwork, drawn in code: each app gets a rounded tile in its own colours with a
// white glyph (Olympus a mountain and lightning bolt, Argus an eye, Sibyl a crystal ball, Janus
// a gate, Arachne a web, Athena an owl, Cerberus a brick wall, Ark a boat, Ares a helmet, Atlas
// the globe he carries).
// build.ps1 writes them to assets\<app>.ico; the hub's tray icon adds a status badge.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Olympus
{
    public enum Badge { None, Ok, Warn, Alert, Off, Busy }

    static class IconArt
    {
        public static readonly int[] IcoSizes = { 16, 20, 24, 32, 40, 48, 64, 256 };

        static Color Dark(Color c, float f) { return Color.FromArgb(c.A, (int)(c.R * f), (int)(c.G * f), (int)(c.B * f)); }

        static GraphicsPath Rounded(RectangleF r, float rad)
        {
            var p = new GraphicsPath();
            float d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static Bitmap Draw(AppId id, int size, Badge badge = Badge.None)
        {
            var app = AppInfo.Of(id);
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.Clear(Color.Transparent);
                float s = size;
                float pad = size <= 20 ? 0.5f : s * 0.04f;
                var tile = new RectangleF(pad, pad, s - 2 * pad, s - 2 * pad);
                using (var path = Rounded(tile, tile.Width * 0.22f))
                {
                    using (var fill = new LinearGradientBrush(new RectangleF(0, -1, s, s + 2), app.Top, app.Bottom, LinearGradientMode.Vertical))
                        g.FillPath(fill, path);
                    if (size >= 32)
                    {
                        var old = g.Clip;
                        g.SetClip(path);
                        using (var hi = new LinearGradientBrush(new RectangleF(0, 0, s, s * 0.5f + 1), Color.FromArgb(56, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), LinearGradientMode.Vertical))
                            g.FillRectangle(hi, 0, 0, s, s * 0.5f);
                        g.Clip = old;
                    }
                    using (var pen = new Pen(Dark(app.Bottom, 0.68f), Math.Max(1f, s / 32f)))
                        g.DrawPath(pen, path);
                }
                Glyph(g, id, s, app);
                if (badge != Badge.None) DrawBadge(g, s, badge);
            }
            return bmp;
        }

        static void Star(Graphics g, Brush b, PointF c, float r)
        {
            float k = r * 0.32f;
            g.FillPolygon(b, new[]
            {
                new PointF(c.X, c.Y - r), new PointF(c.X + k, c.Y - k), new PointF(c.X + r, c.Y), new PointF(c.X + k, c.Y + k),
                new PointF(c.X, c.Y + r), new PointF(c.X - k, c.Y + k), new PointF(c.X - r, c.Y), new PointF(c.X - k, c.Y - k)
            });
        }

        static void Glyph(Graphics g, AppId id, float s, AppInfo app)
        {
            Func<float, float, PointF> P = (u, v) => new PointF(u * s, v * s);
            Func<float, float, float, float, RectangleF> R = (u, v, w, h) => new RectangleF(u * s, v * s, w * s, h * s);
            Brush white = Brushes.White;
            Color ink = Dark(app.Bottom, 0.82f);
            using (var inkBrush = new SolidBrush(ink))
            using (var thick = new Pen(Color.White, Math.Max(1.6f, s * 0.085f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            using (var medium = new Pen(Color.White, Math.Max(1.25f, s * 0.062f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            using (var thin = new Pen(Color.White, Math.Max(1f, s * 0.045f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                switch (id)
                {
                    case AppId.Olympus:
                    {
                        g.FillPolygon(white, new[] { P(0.10f, 0.84f), P(0.37f, 0.47f), P(0.48f, 0.61f), P(0.64f, 0.39f), P(0.90f, 0.84f) });
                        var bolt = new[] { P(0.53f, 0.07f), P(0.36f, 0.29f), P(0.47f, 0.29f), P(0.38f, 0.45f), P(0.62f, 0.20f), P(0.51f, 0.20f), P(0.62f, 0.07f) };
                        using (var gold = new SolidBrush(Color.FromArgb(0xFF, 0xD5, 0x4F))) g.FillPolygon(gold, bolt);
                        if (s >= 32) using (var edge = new Pen(Dark(app.Bottom, 0.55f), s / 64f) { LineJoin = LineJoin.Round }) g.DrawPolygon(edge, bolt);
                        break;
                    }
                    case AppId.Aegis:
                    {
                        using (var sh = new GraphicsPath())
                        {
                            sh.AddBezier(P(0.50f, 0.10f), P(0.60f, 0.16f), P(0.72f, 0.19f), P(0.82f, 0.19f));
                            sh.AddLine(P(0.82f, 0.19f), P(0.82f, 0.48f));
                            sh.AddBezier(P(0.82f, 0.48f), P(0.82f, 0.70f), P(0.68f, 0.83f), P(0.50f, 0.90f));
                            sh.AddBezier(P(0.50f, 0.90f), P(0.32f, 0.83f), P(0.18f, 0.70f), P(0.18f, 0.48f));
                            sh.AddLine(P(0.18f, 0.48f), P(0.18f, 0.19f));
                            sh.AddBezier(P(0.18f, 0.19f), P(0.28f, 0.19f), P(0.40f, 0.16f), P(0.50f, 0.10f));
                            sh.CloseFigure();
                            g.FillPath(white, sh);
                        }
                        using (var ck = new Pen(ink, Math.Max(1.5f, s * 0.09f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                            g.DrawLines(ck, new[] { P(0.35f, 0.51f), P(0.46f, 0.62f), P(0.66f, 0.39f) });
                        break;
                    }
                    case AppId.Argus:
                    {
                        using (var eye = new GraphicsPath())
                        {
                            eye.AddBezier(P(0.08f, 0.50f), P(0.30f, 0.17f), P(0.70f, 0.17f), P(0.92f, 0.50f));
                            eye.AddBezier(P(0.92f, 0.50f), P(0.70f, 0.83f), P(0.30f, 0.83f), P(0.08f, 0.50f));
                            eye.CloseFigure();
                            g.FillPath(white, eye);
                        }
                        g.FillEllipse(inkBrush, R(0.31f, 0.31f, 0.38f, 0.38f));
                        if (s >= 24) using (var pupil = new SolidBrush(Color.FromArgb(210, 10, 20, 24))) g.FillEllipse(pupil, R(0.42f, 0.42f, 0.16f, 0.16f));
                        g.FillEllipse(white, R(0.52f, 0.35f, 0.10f, 0.10f));
                        break;
                    }
                    case AppId.Sibyl:
                    {
                        g.FillPolygon(white, new[] { P(0.25f, 0.88f), P(0.34f, 0.73f), P(0.66f, 0.73f), P(0.75f, 0.88f) });
                        g.FillEllipse(white, R(0.19f, 0.09f, 0.62f, 0.62f));
                        Star(g, inkBrush, P(0.43f, 0.37f), s * 0.15f);
                        if (s >= 24) Star(g, inkBrush, P(0.61f, 0.53f), s * 0.075f);
                        break;
                    }
                    case AppId.Janus:
                    {
                        using (var arch = new GraphicsPath())
                        {
                            arch.AddLine(P(0.22f, 0.86f), P(0.22f, 0.44f));
                            arch.AddArc(R(0.22f, 0.16f, 0.56f, 0.56f), 180, 180);
                            arch.AddLine(P(0.78f, 0.44f), P(0.78f, 0.86f));
                            g.DrawPath(thick, arch);
                        }
                        g.DrawLine(thick, P(0.50f, 0.31f), P(0.50f, 0.58f));
                        g.FillPolygon(white, new[] { P(0.35f, 0.53f), P(0.65f, 0.53f), P(0.50f, 0.74f) });
                        break;
                    }
                    case AppId.Arachne:
                    {
                        var c = P(0.50f, 0.50f);
                        int spokes = s < 32 ? 6 : 8;
                        float[] rings = s < 32 ? new[] { 0.15f, 0.30f } : new[] { 0.11f, 0.22f, 0.33f };
                        Func<int, float, PointF> At = (i, r) =>
                        {
                            double a = Math.PI * 2 * i / spokes - Math.PI / 2;
                            return new PointF(c.X + (float)Math.Cos(a) * r * s, c.Y + (float)Math.Sin(a) * r * s);
                        };
                        for (int i = 0; i < spokes; i++) g.DrawLine(thin, c, At(i, 0.38f));
                        foreach (var r in rings)
                        {
                            var pts = new PointF[spokes];
                            for (int i = 0; i < spokes; i++) pts[i] = At(i, r);
                            g.DrawPolygon(thin, pts);
                        }
                        if (s >= 20)
                        {
                            var sp = P(0.67f, 0.69f);
                            float rr = s * 0.08f;
                            g.FillEllipse(white, sp.X - rr, sp.Y - rr, rr * 2, rr * 2);
                        }
                        break;
                    }
                    case AppId.Athena:
                    {
                        g.FillPolygon(white, new[] { P(0.19f, 0.10f), P(0.43f, 0.30f), P(0.23f, 0.41f) });
                        g.FillPolygon(white, new[] { P(0.81f, 0.10f), P(0.57f, 0.30f), P(0.77f, 0.41f) });
                        g.FillEllipse(white, R(0.16f, 0.22f, 0.68f, 0.68f));
                        g.FillEllipse(inkBrush, R(0.25f, 0.38f, 0.22f, 0.22f));
                        g.FillEllipse(inkBrush, R(0.53f, 0.38f, 0.22f, 0.22f));
                        if (s >= 24)
                        {
                            g.FillEllipse(white, R(0.33f, 0.43f, 0.07f, 0.07f));
                            g.FillEllipse(white, R(0.61f, 0.43f, 0.07f, 0.07f));
                        }
                        g.FillPolygon(inkBrush, new[] { P(0.44f, 0.63f), P(0.56f, 0.63f), P(0.50f, 0.75f) });
                        break;
                    }
                    case AppId.Cerberus:
                    {
                        float gap = Math.Max(1f, s * 0.05f) / s;
                        float x0 = 0.13f, x1 = 0.87f, top = 0.17f, rowH = 0.19f;
                        for (int row = 0; row < 3; row++)
                        {
                            float y = top + row * (rowH + gap);
                            float[] cuts = row % 2 == 0 ? new[] { x0, 0.50f, x1 } : new[] { x0, 0.31f, 0.69f, x1 };
                            for (int i = 0; i + 1 < cuts.Length; i++)
                            {
                                float a = cuts[i] + (i == 0 ? 0 : gap / 2);
                                float b = cuts[i + 1] - (i + 1 == cuts.Length - 1 ? 0 : gap / 2);
                                g.FillRectangle(white, R(a, y, b - a, rowH));
                            }
                        }
                        break;
                    }
                    case AppId.Ark:
                    {
                        g.FillPolygon(white, new[] { P(0.30f, 0.41f), P(0.50f, 0.22f), P(0.70f, 0.41f) });
                        g.FillRectangle(white, R(0.34f, 0.40f, 0.32f, 0.18f));
                        if (s >= 32) g.FillRectangle(inkBrush, R(0.45f, 0.45f, 0.10f, 0.08f));
                        g.FillPolygon(white, new[] { P(0.10f, 0.57f), P(0.90f, 0.57f), P(0.75f, 0.77f), P(0.25f, 0.77f) });
                        using (var wave = new GraphicsPath())
                        {
                            wave.AddBezier(P(0.10f, 0.88f), P(0.20f, 0.82f), P(0.30f, 0.82f), P(0.40f, 0.88f));
                            wave.AddBezier(P(0.40f, 0.88f), P(0.50f, 0.94f), P(0.60f, 0.94f), P(0.70f, 0.88f));
                            wave.AddBezier(P(0.70f, 0.88f), P(0.78f, 0.83f), P(0.85f, 0.83f), P(0.90f, 0.87f));
                            g.DrawPath(medium, wave);
                        }
                        break;
                    }
                    case AppId.Ares:
                    {
                        using (var crest = new GraphicsPath())
                        {
                            crest.AddBezier(P(0.30f, 0.34f), P(0.30f, 0.04f), P(0.70f, 0.04f), P(0.70f, 0.34f));
                            crest.CloseFigure();
                            g.FillPath(white, crest);
                        }
                        using (var helm = new GraphicsPath())
                        {
                            helm.AddLine(P(0.26f, 0.89f), P(0.21f, 0.55f));
                            helm.AddBezier(P(0.21f, 0.55f), P(0.19f, 0.25f), P(0.81f, 0.25f), P(0.79f, 0.55f));
                            helm.AddLine(P(0.79f, 0.55f), P(0.74f, 0.89f));
                            helm.CloseFigure();
                            g.FillPath(white, helm);
                        }
                        float line = Math.Max(1f, s * 0.035f);
                        using (var sep = new Pen(ink, line)) g.DrawArc(sep, R(0.24f, 0.30f, 0.52f, 0.30f), 200, 140);
                        g.FillRectangle(inkBrush, R(0.29f, 0.52f, 0.42f, 0.09f));
                        g.FillRectangle(inkBrush, R(0.455f, 0.52f, 0.09f, 0.38f));
                        break;
                    }
                    case AppId.Atlas:
                    {
                        // a wireframe globe: rim, a meridian, the equator and (when there's room) two latitudes
                        g.DrawEllipse(thick, R(0.17f, 0.17f, 0.66f, 0.66f));
                        g.DrawEllipse(thin, R(0.37f, 0.17f, 0.26f, 0.66f));
                        g.DrawLine(thin, P(0.17f, 0.50f), P(0.83f, 0.50f));
                        if (s >= 24)
                        {
                            g.DrawLine(thin, P(0.24f, 0.34f), P(0.76f, 0.34f));
                            g.DrawLine(thin, P(0.24f, 0.66f), P(0.76f, 0.66f));
                        }
                        break;
                    }
                }
            }
        }

        static void DrawBadge(Graphics g, float s, Badge b)
        {
            Color c = b == Badge.Ok ? Color.FromArgb(0x2E, 0xB8, 0x5C)
                    : b == Badge.Warn ? Color.FromArgb(0xF5, 0xA6, 0x23)
                    : b == Badge.Alert ? Color.FromArgb(0xE5, 0x39, 0x35)
                    : b == Badge.Busy ? Color.FromArgb(0x1E, 0x88, 0xE5)
                    : Color.FromArgb(0x9E, 0x9E, 0x9E);
            float d = Math.Max(7f, s * 0.44f);
            var r = new RectangleF(s - d, s - d, d - 0.5f, d - 0.5f);
            using (var br = new SolidBrush(c)) g.FillEllipse(br, r);
            using (var pen = new Pen(Color.White, Math.Max(1f, s / 18f))) g.DrawEllipse(pen, r);
        }

        // The icon lives as long as the app, so the handle is never freed.
        public static Icon MakeIcon(AppId id, int size, Badge badge = Badge.None)
        {
            using (var bmp = Draw(id, size, badge)) return Icon.FromHandle(bmp.GetHicon());
        }

        // A multi-size .ico: 32-bit DIB images up to 64 px, PNG for 256 px.
        public static void WriteIco(string path, AppId id)
        {
            var sizes = IcoSizes;
            var images = new List<byte[]>();
            foreach (int sz in sizes)
                using (var bmp = Draw(id, sz))
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

        // Every app at every size on dark and light backgrounds, the 16 px tray size blown up,
        // and the hub's badge states (for checking the artwork).
        public static void WritePreview(string path)
        {
            int[] sizes = { 16, 20, 24, 32, 48, 64, 128 };
            var apps = AppInfo.All;
            int gap = 12, labelW = 90, bandW = labelW + sizes.Sum() + gap * (sizes.Length + 1), rowH = 128 + gap;
            int zoomY = rowH * apps.Length + gap, zoom = 96;
            int height = zoomY + zoom + gap * 3 + 64;
            using (var canvas = new Bitmap(bandW * 2, height, PixelFormat.Format32bppArgb))
            using (var g = Graphics.FromImage(canvas))
            using (var font = new Font("Segoe UI", 10f, FontStyle.Bold))
            {
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
                g.Clear(Color.FromArgb(0x20, 0x20, 0x20));
                using (var light = new SolidBrush(Color.FromArgb(0xF3, 0xF3, 0xF3))) g.FillRectangle(light, bandW, 0, bandW, height);
                for (int band = 0; band < 2; band++)
                {
                    var textBrush = band == 0 ? Brushes.Gainsboro : Brushes.DimGray;
                    for (int r = 0; r < apps.Length; r++)
                    {
                        int y = gap + r * rowH;
                        g.DrawString(apps[r].Name, font, textBrush, band * bandW + gap, y + 56);
                        int x = band * bandW + labelW + gap;
                        foreach (int sz in sizes)
                        {
                            using (var b = Draw(apps[r].Id, sz)) g.DrawImageUnscaled(b, x, y + (128 - sz) / 2);
                            x += sz + gap;
                        }
                    }
                    g.InterpolationMode = InterpolationMode.NearestNeighbor;
                    g.PixelOffsetMode = PixelOffsetMode.Half;
                    for (int r = 0; r < apps.Length; r++)
                        using (var b = Draw(apps[r].Id, 16))
                            g.DrawImage(b, new Rectangle(band * bandW + gap + r * (zoom + 8), zoomY, zoom, zoom));
                    var badges = new[] { Badge.Ok, Badge.Busy, Badge.Warn, Badge.Alert, Badge.Off };
                    for (int i = 0; i < badges.Length; i++)
                        using (var b = Draw(AppId.Olympus, 20, badges[i]))
                            g.DrawImage(b, new Rectangle(band * bandW + gap + i * 72, zoomY + zoom + gap, 60, 60));
                    g.PixelOffsetMode = PixelOffsetMode.Default;
                    g.InterpolationMode = InterpolationMode.Default;
                }
                canvas.Save(path, ImageFormat.Png);
            }
        }
    }
}
