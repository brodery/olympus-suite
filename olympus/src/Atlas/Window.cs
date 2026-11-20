// Atlas's window: a strip of drives (click one to map it), the map itself (folder tree on top,
// treemap below, kept in step), the cleanup list with "worth a look" suggestions, the biggest
// files, and the space by file type.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

namespace Olympus.Atlas
{
    // What the window remembers between runs (view.json).
    sealed class AtlasView { public double Split = 0.3; }

    sealed class AtlasWindow : AppWindow
    {
        readonly TabControl tabs = new TabControl();
        readonly FlowLayoutPanel drivesPanel = new FlowLayoutPanel();
        readonly Dictionary<string, DriveCard> cards = new Dictionary<string, DriveCard>(StringComparer.OrdinalIgnoreCase);
        readonly TreeList tree = new TreeList();
        readonly TreemapView treemap = new TreemapView();
        readonly KindLegend legend = new KindLegend();
        readonly SplitContainer split = new SplitContainer();
        readonly Label crumbs = new Label();
        readonly Button upButton, stopButton, adminButton;
        readonly ListView junk = Ui.Empty(Ui.List("What|300", "Size|90>", "Files|80>", "Where|330", "About|300"), "Measuring what can be cleaned…");
        readonly ListView review = Ui.Empty(Ui.List("Worth a look|340", "Size|90>", "Last used|190", "Where|300*", "Do|170"), "Nothing big to suggest right now.");
        readonly Label junkTotal = new Label();
        readonly ListView bigFiles = Ui.Empty(Ui.List("File|330", "Size|90>", "Kind|170", "Changed|150", "Folder|560"), "Map a drive to see its biggest files.");
        readonly ListView types = Ui.Empty(Ui.List("Type|130", "Kind|230", "Size|100>", "Files|100>", "Share|80>"), "Map a drive to see the space per file type.");
        readonly Timer progress = new Timer { Interval = 250 };
        readonly HashSet<string> ticked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly ToolTip tips = new ToolTip();
        readonly bool snapshot;
        Point? snapHover;      // --snapshot --hover X,Y: show the map's details card at that point
        MapInfo map;
        Scanner scanning;
        string scanningRoot;
        DateTime scanStarted;
        bool adminScan, loadingMap, measuring, cleaning, deletingNode, filling, tickedInit, dirty;
        List<CleanItem> items = new List<CleanItem>();
        List<ReviewItem> reviews = new List<ReviewItem>();
        List<SteamGame> games;

        public AtlasWindow() : base(AppInfo.Of(AppId.Atlas), 1180, 800)
        {
            var args = new Args(Environment.GetCommandLineArgs().Skip(1).ToArray());
            snapshot = args.Has("--snapshot");
            AutoRefresh(30);
            upButton = Ui.Btn("Up a level", (s, e) => { if (treemap.Root != null && treemap.Root.Parent != null) Zoom(treemap.Root.Parent); });
            stopButton = Ui.Btn("Stop", (s, e) => { if (scanning != null) scanning.Cancel(); });
            stopButton.Visible = false;
            adminButton = Ui.Btn("Complete scan (admin)", (s, e) => StartScan(map != null ? map.RootPath : @"C:\", true));
            tips.SetToolTip(adminButton, "Maps it again with admin rights, so Atlas sees inside every folder (Windows asks once).");
            Add(Ui.Btn("Rescan", (s, e) => StartScan(map != null ? map.RootPath : @"C:\", false)),
                Ui.Btn("Map a folder…", (s, e) => PickFolder()),
                adminButton, stopButton,
                Ui.Btn("Settings", (s, e) => Proc.Open(AtlasSettings.FilePath)));

            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Ui.Tab("Map", BuildMap()));
            tabs.TabPages.Add(Ui.Tab("Clean up", BuildClean()));
            tabs.TabPages.Add(Ui.Tab("Biggest files", bigFiles));
            tabs.TabPages.Add(Ui.Tab("File types", types));
            Body.Controls.Add(tabs);

            bigFiles.MultiSelect = false;
            bigFiles.MouseUp += (s, e) =>
            {
                if (e.Button != MouseButtons.Right) return;
                var row = bigFiles.GetItemAt(e.X, e.Y);
                if (row != null) ShowMenu(row.Tag as Node, bigFiles, e.Location);
            };
            bigFiles.DoubleClick += (s, e) => { var n = Tagged(bigFiles); if (n != null) Proc.ShowInExplorer(n.FullPath); };
            progress.Tick += (s, e) => ShowProgress();
            Shown += (s, e) => FirstLoad();
            FormClosing += (s, e) =>
            {
                if (deletingNode && e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    return;
                }
                OnWindowClosing();
            };
            StatusBar.Text = "Pick a drive above, or Map a folder…";
            if (snapshot) PrepareSnapshot(args);
        }

        // ------------------------------------------------------------------ layout

        Control BuildMap()
        {
            var layout = new TableLayoutPanel { ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            drivesPanel.AutoSize = true;
            drivesPanel.Dock = DockStyle.Fill;
            drivesPanel.Margin = new Padding(0, 0, 0, Ui.S(6));
            drivesPanel.SizeChanged += (s, e) => FitCards();
            layout.Controls.Add(drivesPanel, 0, 0);

            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.SplitterWidth = Ui.S(6);
            split.Panel1.Controls.Add(tree);
            var lower = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = new Padding(0) };
            lower.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            lower.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            lower.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var bar = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, Ui.S(2), 0, 0) };
            upButton.Margin = new Padding(0, 0, Ui.S(8), Ui.S(2));
            bar.Controls.Add(upButton);
            crumbs.AutoSize = true;
            crumbs.Font = Ui.Bold;
            crumbs.Margin = new Padding(0, Ui.S(7), 0, 0);
            bar.Controls.Add(crumbs);
            lower.Controls.Add(bar, 0, 0);
            treemap.Dock = DockStyle.Fill;
            lower.Controls.Add(treemap, 0, 1);
            legend.Dock = DockStyle.Fill;
            legend.Margin = new Padding(0, Ui.S(3), 0, 0);
            lower.Controls.Add(legend, 0, 2);
            split.Panel2.Controls.Add(lower);
            layout.Controls.Add(split, 0, 1);

            tree.NodeSelected += n => treemap.Mark(n);
            tree.NodeActivated += n =>
            {
                if (n.IsDir) Zoom(n);
                else if (n.Parent != null) { Zoom(n.Parent); treemap.Mark(n); }
            };
            tree.MenuRequested += (n, p) => ShowMenu(n, tree, p);
            treemap.NodeClicked += n => tree.Reveal(n);
            treemap.NodeOpened += n => Zoom(n);
            treemap.Hovered += text => { if (!deletingNode && scanning == null && !adminScan) StatusBar.Text = text.Length > 0 ? text : MapLine(); };
            treemap.MenuRequested += (n, p) => ShowMenu(n, treemap, p);
            treemap.Rebuilt += () => legend.SetKinds(treemap.KindsShown());
            return layout;
        }

        Control BuildClean()
        {
            var layout = new TableLayoutPanel { ColumnCount = 1, RowCount = 4, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 58));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 42));
            var top = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, 0, 0, Ui.S(4)) };
            junkTotal.AutoSize = true;
            junkTotal.Font = Ui.Big;
            junkTotal.Margin = new Padding(0, Ui.S(4), Ui.S(16), 0);
            junkTotal.Text = "Measuring…";
            top.Controls.Add(junkTotal);
            top.Controls.Add(Ui.Btn("Clean ticked", (s, e) => CleanTicked()));
            top.Controls.Add(Ui.Btn("Measure again", (s, e) => MeasureJunk()));
            top.Controls.Add(Ui.Btn("Show in Explorer", (s, e) => ShowJunkPlace()));
            layout.Controls.Add(top, 0, 0);

            junk.CheckBoxes = true;
            junk.MultiSelect = false;
            junk.Groups.Add(new ListViewGroup("junk", "Safe to clean"));
            junk.Groups.Add(new ListViewGroup("admin", "Windows' own folders (Windows asks once for admin rights when you clean them)"));
            junk.Groups.Add(new ListViewGroup("leftovers", "Leftovers from uninstalled games (they go to the Recycle Bin)"));
            junk.ItemCheck += (s, e) =>
            {
                if (filling) return;
                var it = junk.Items[e.Index].Tag as CleanItem;
                if (it != null && it.Blocked != null && e.NewValue == CheckState.Checked) e.NewValue = CheckState.Unchecked;
            };
            junk.ItemChecked += (s, e) =>
            {
                if (filling) return;
                var it = e.Item.Tag as CleanItem;
                if (it == null) return;
                if (e.Item.Checked) ticked.Add(it.Id); else ticked.Remove(it.Id);
                UpdateJunkTotal();
            };
            layout.Controls.Add(junk, 0, 1);

            var title = new Label
            {
                AutoSize = true, Font = Ui.Bold, Margin = new Padding(0, Ui.S(10), 0, Ui.S(4)),
                Text = "Worth a look: big things you may not need. Atlas never removes these by itself; double-click one to act on it."
            };
            layout.Controls.Add(title, 0, 2);
            review.MultiSelect = false;
            review.DoubleClick += (s, e) => ReviewAction();
            layout.Controls.Add(review, 0, 3);
            return layout;
        }

        void PrepareSnapshot(Args args)
        {
            var m = MapFile.Load(MapFile.PathFor(args.Opt("--map") ?? @"C:\"));
            if (m != null) ShowMap(m);
            items = Catalog.Load();
            foreach (var it in items) { try { Cleaner.Measure(it); } catch (Exception) { } }
            reviews = Review.Collect(AtlasSettings.Load());
            FillJunk();
            FillReview();
            int tab;
            if (int.TryParse(args.Opt("--tab") ?? "0", out tab) && tab >= 0 && tab < tabs.TabCount) tabs.SelectedIndex = tab;
            var hover = (args.Opt("--hover") ?? "").Split(',');
            int hx, hy;
            if (hover.Length == 2 && int.TryParse(hover[0], out hx) && int.TryParse(hover[1], out hy)) snapHover = new Point(hx, hy);
        }

        // The folder list's share of the map tab; you can drag the bar between them, and Atlas remembers it.
        static string ViewFile { get { return Path.Combine(Suite.UserDir(AppId.Atlas), "view.json"); } }

        void FitSplit()
        {
            var v = snapshot ? null : J.Load<AtlasView>(ViewFile);
            double share = v != null && v.Split >= 0.12 && v.Split <= 0.8 ? v.Split : 0.3;
            try { split.SplitterDistance = Math.Max(Ui.S(120), (int)(split.Height * share)); } catch (Exception) { }
        }

        void FirstLoad()
        {
            FitSplit();
            if (snapshot) return;
            if (map == null && scanning == null && !adminScan && !loadingMap) LoadOrScan(@"C:\", false);
            if (!measuring && items.Count == 0) MeasureJunk();
        }

        void OnWindowClosing()
        {
            if (scanning != null) scanning.Cancel();
            if (!snapshot && split.Height > 0)
            {
                try { J.Save(ViewFile, new AtlasView { Split = Math.Round((double)split.SplitterDistance / split.Height, 3) }); } catch (Exception) { }
            }
            if (dirty && map != null)
            {
                try { MapFile.Save(map, MapFile.PathFor(map.RootPath)); } catch (Exception e) { Log.Error("saving the map", e); }
            }
        }

        protected override void RefreshView()
        {
            RefreshDrives();
            var s = AtlasSettings.Load();
            var drives = DriveWatch.Fixed(s, false);
            var worst = drives.OrderByDescending(d => DriveWatch.Level(d.Free, d.Total, 0, s.WarnPercent)).ThenBy(d => (double)d.Free / Math.Max(1, d.Total)).FirstOrDefault();
            int level = worst == null ? 0 : DriveWatch.Level(worst.Free, worst.Total, 0, s.WarnPercent);
            if (worst == null) SetState(States.Off, "No drives to watch");
            else if (level == 2) SetState(States.Alert, worst.Root.TrimEnd('\\') + " is nearly full: " + Fmt.Size(worst.Free) + " free");
            else if (level == 1) SetState(States.Warn, worst.Root.TrimEnd('\\') + " is getting full: " + Fmt.Size(worst.Free) + " free");
            else SetState(States.Ok, "All drives have room · " + string.Join(" · ", drives.Select(d => d.Root.TrimEnd('\\') + " " + Fmt.Size(d.Free) + " free")));
            if (snapshot)
            {
                FitSplit();
                treemap.Rebuild();
                if (snapHover.HasValue) treemap.HoverAt(snapHover.Value);
            }
        }

        protected override void HandleRequest(string request)
        {
            if (request == "clean") { tabs.SelectedIndex = 1; return; }
            if (request.StartsWith("map:", StringComparison.OrdinalIgnoreCase))
            {
                tabs.SelectedIndex = 0;
                LoadOrScan(request.Substring(4), false);
                return;
            }
            if (request.StartsWith("alert:", StringComparison.Ordinal))
            {
                var a = AlertStore.Find(AppId.Atlas, request.Substring(6));
                if (a != null && a.Key != null && (a.Key.StartsWith("space:", StringComparison.Ordinal) || a.Key == "junk"))
                {
                    tabs.SelectedIndex = 1;
                    return;
                }
            }
            base.HandleRequest(request);
        }

        // ------------------------------------------------------------------ drives

        void RefreshDrives()
        {
            var s = AtlasSettings.Load();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in DriveWatch.Fixed(s, true))
            {
                seen.Add(d.Root);
                DriveCard card;
                if (!cards.TryGetValue(d.Root, out card))
                {
                    string root = d.Root;
                    card = new DriveCard { Root = root };
                    card.Click += (o, e) => LoadOrScan(root, false);
                    cards[root] = card;
                    drivesPanel.Controls.Add(card);
                }
                card.VolumeName = d.Label;
                card.Total = d.Total;
                card.Free = d.Free;
                card.WarnPercent = s.WarnPercent;
                card.Current = map != null && map.IsDrive && map.RootPath.Equals(d.Root, StringComparison.OrdinalIgnoreCase);
                string file = MapFile.PathFor(d.Root);
                string note = File.Exists(file) ? "mapped " + Fmt.Ago(File.GetLastWriteTimeUtc(file)) : "not mapped yet";
                if (note != card.Note) { card.Note = note; tips.SetToolTip(card, "Click to show the map of " + d.Root + " (" + note + ")"); }
                card.Invalidate();
            }
            foreach (var k in cards.Keys.Where(k => !seen.Contains(k)).ToList())
            {
                drivesPanel.Controls.Remove(cards[k]);
                cards[k].Dispose();
                cards.Remove(k);
            }
            FitCards();
        }

        // The drive cards share the strip's width (one row when they fit at a readable size).
        void FitCards()
        {
            int n = cards.Count;
            if (n == 0 || drivesPanel.ClientSize.Width <= 0) return;
            int gap = Ui.S(8);
            int w = Math.Max(Ui.S(160), Math.Min(Ui.S(250), (drivesPanel.ClientSize.Width - n * gap - 2) / n));
            foreach (var c in cards.Values) if (c.Width != w) c.Width = w;
        }

        // ------------------------------------------------------------------ the map

        void LoadOrScan(string root, bool rescan)
        {
            if (deletingNode) return;
            if (scanning != null || adminScan) { StatusBar.Text = "Finish or stop the scan that's running first."; return; }
            try { root = Scanner.NormalizeRoot(root); } catch (Exception) { return; }
            string file = MapFile.PathFor(root);
            if (rescan || !File.Exists(file)) { StartScan(root, false); return; }
            loadingMap = true;
            StatusBar.Text = "Opening the last map of " + root + "…";
            Ui.Background(this, () => MapFile.Load(file), (m, err) =>
            {
                loadingMap = false;
                if (m == null) { StartScan(root, false); return; }
                ShowMap(m);
            });
        }

        void StartScan(string root, bool admin)
        {
            if (scanning != null || adminScan || deletingNode) return;
            try { root = Scanner.NormalizeRoot(root); } catch (Exception) { Ui.Warn(this, "That isn't a folder Atlas can map."); return; }
            scanningRoot = root;
            scanStarted = DateTime.UtcNow;
            tabs.SelectedIndex = 0;
            progress.Start();
            if (admin)
            {
                adminScan = true;
                string outFile = MapFile.PathFor(root);
                StatusBar.Text = "Windows asks for admin rights to read every folder…";
                Ui.Background(this, () => Elevation.Run(Suite.ExeOf(AppId.Atlas), "--map-admin " + Proc.Quote(root) + " --out " + Proc.Quote(outFile), true), (code, err) =>
                {
                    adminScan = false;
                    progress.Stop();
                    if (err != null) { StatusBar.Text = "The complete scan didn't start: " + err.Message; return; }
                    if (code == -1) { StatusBar.Text = "Cancelled: Windows asked for admin rights and the request was declined."; return; }
                    var m = code == 0 ? MapFile.Load(outFile) : null;
                    if (m == null) { StatusBar.Text = "The complete scan didn't finish (code " + code + "); see Atlas's log."; return; }
                    ShowMap(m);
                });
                return;
            }
            var sc = new Scanner();
            scanning = sc;
            stopButton.Visible = true;
            Ui.Background(this, () =>
            {
                var m = sc.Run(root);
                if (!sc.Cancelled)
                {
                    try { MapFile.Save(m, MapFile.PathFor(root)); } catch (Exception e) { Log.Error("saving the map", e); }
                    Log.Info("mapped " + m.RootPath + ": " + Fmt.Size(m.Root.Size) + " in " + m.Root.Files.ToString("N0") + " files, " + m.DeniedDirs + " folders unreadable, " + Fmt.Duration(m.Took));
                }
                return m;
            }, (m, err) =>
            {
                scanning = null;
                progress.Stop();
                stopButton.Visible = false;
                if (err != null) { StatusBar.Text = "The scan stopped: " + err.Message; return; }
                if (sc.Cancelled) { StatusBar.Text = "Scan stopped."; return; }
                ShowMap(m);
            });
        }

        void ShowProgress()
        {
            if (adminScan) StatusBar.Text = "Mapping " + scanningRoot + " as admin… " + Fmt.Duration(DateTime.UtcNow - scanStarted);
            else if (scanning != null)
                StatusBar.Text = "Mapping " + scanningRoot + "… " + scanning.FilesSeen.ToString("N0") + " files, " + Fmt.Size(scanning.BytesSeen) + " · " + Fmt.Clip(scanning.Current ?? "", 90);
        }

        void ShowMap(MapInfo m)
        {
            map = m;
            tree.ShowMap(m);
            Zoom(m.Root);
            FillBigFiles();
            FillTypes();
            RefreshDrives();
            StatusBar.Text = MapLine();
        }

        string MapLine()
        {
            if (map == null) return "Pick a drive above, or Map a folder…";
            var sb = new StringBuilder("Mapped " + map.RootPath + " " + Fmt.Ago(map.ScannedUtc) + " in " + Fmt.Duration(map.Took) + " · " +
                                       map.Root.Files.ToString("N0") + " files, " + Fmt.Size(map.Root.Size));
            if (map.Unseen > 0) sb.Append(" · " + Fmt.Size(map.Unseen) + " hidden from Atlas");
            if (map.DeniedDirs > 0 && !map.Elevated) sb.Append(" · " + map.DeniedDirs.ToString("N0") + " folders need admin (Complete scan)");
            if (DateTime.UtcNow - map.ScannedUtc > TimeSpan.FromHours(12)) sb.Append(" · Rescan for fresh numbers");
            return sb.ToString();
        }

        void Zoom(Node n)
        {
            if (map == null || n == null) return;
            treemap.Display(map, n);
            crumbs.Text = n.FullPath + "   ·   " + Fmt.Size(n.Size + (n == map.Root ? map.Unseen : 0));
            upButton.Enabled = n.Parent != null;
        }

        void PickFolder()
        {
            using (var d = new FolderBrowserDialog { Description = "Pick a folder for Atlas to map", ShowNewFolderButton = false })
                if (d.ShowDialog(this) == DialogResult.OK) StartScan(d.SelectedPath, false);
        }

        List<SteamGame> Games()
        {
            if (games == null)
            {
                try { games = Steam.Games(); } catch (Exception) { games = new List<SteamGame>(); }
            }
            return games;
        }

        static Node Tagged(ListView lv) { return lv.SelectedItems.Count > 0 ? lv.SelectedItems[0].Tag as Node : null; }

        void ShowMenu(Node n, Control c, Point p)
        {
            if (n == null) return;
            string path = n.FullPath;
            var menu = new ContextMenuStrip();
            if (n.IsDir) menu.Items.Add("Open in Explorer", null, (s, e) => Proc.Open(path));
            else menu.Items.Add("Show in Explorer", null, (s, e) => Proc.ShowInExplorer(path));
            if (n.IsDir) menu.Items.Add("Show it on the map", null, (s, e) => { tabs.SelectedIndex = 0; Zoom(n); });
            menu.Items.Add("Copy path", null, (s, e) => { try { Clipboard.SetText(path); } catch (Exception) { } });
            var game = Steam.GameAt(path, Games());
            if (game != null) menu.Items.Add("Uninstall " + game.Name + " in Steam…", null, (s, e) => Proc.Open("steam://uninstall/" + game.AppId));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Move to the Recycle Bin…", null, (s, e) => RecycleNode(n)).Enabled = !deletingNode;
            menu.Items.Add("Delete permanently…", null, (s, e) => DeleteNode(n)).Enabled =
                !deletingNode && !cleaning && scanning == null && !adminScan && !loadingMap;
            menu.Show(c, p);
        }

        bool CanRemoveNode(Node n, bool permanent)
        {
            string path = n.FullPath;
            string why = Safety.Refuse(path);
            if (why == null && path.TrimEnd('\\').Equals(Path.GetTempPath().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                why = "Windows needs that folder. The Clean up tab can empty it";
            if (why != null)
            {
                Ui.Info(this, "Atlas can't remove " + path + ".\n\n" + char.ToUpperInvariant(why[0]) + why.Substring(1) + ".");
                return false;
            }
            var installed = Games();
            var game = Steam.GameAt(path, installed);
            if (game == null && permanent && n.IsDir)
            {
                string prefix = FsNative.LongName(path).TrimEnd('\\') + "\\";
                game = installed.FirstOrDefault(g => FsNative.LongName(g.Folder).StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
            }
            if (game == null) return true;
            Ui.Info(this, "This selection includes files from " + game.Name + ". Use Steam to uninstall the game.");
            return false;
        }

        void RecycleNode(Node n)
        {
            if (deletingNode || !CanRemoveNode(n, false)) return;
            string path = n.FullPath;
            if (!Ui.Confirm(this, "Move " + path + " (" + Fmt.Size(n.Size) + ") to the Recycle Bin?\n\nYou can put it back from the Recycle Bin until it's emptied.")) return;
            bool ok = Recycler.Recycle(new[] { path });
            if (File.Exists(path) || Directory.Exists(path)) { Ui.Warn(this, "Windows couldn't move all of it" + (ok ? "" : " (something may be using it)") + "."); return; }
            var parent = n.Parent;
            bool shownInside = Inside(treemap.Root, n);
            Detach(n);
            dirty = true;
            tree.Rebuild(parent);
            if (shownInside) Zoom(parent); else treemap.Rebuild();
            FillBigFiles();
            RefreshDrives();
            StatusBar.Text = "Moved " + path + " (" + Fmt.Size(n.Size) + ") to the Recycle Bin.";
        }

        void DeleteNode(Node n)
        {
            if (deletingNode || cleaning || scanning != null || adminScan || loadingMap || map == null
                || !Inside(n, map.Root) || !CanRemoveNode(n, true)) return;

            var originalMap = map;
            string path = n.FullPath;
            string target = n.IsDir ? "this folder and everything inside it" : "this file";
            string prompt = "Permanently delete " + target + "?\n\n" + path + "\n\nThis bypasses the Recycle Bin.";
            if (MessageBox.Show(this, prompt, "Delete permanently", MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            if (map != originalMap || scanning != null || adminScan || loadingMap || cleaning) return;

            deletingNode = true;
            StatusBar.Text = "Permanently deleting " + path + "…";
            Ui.Background(this, () =>
            {
                PermanentDelete.Remove(path, n.IsDir, n.ModifiedUtc);
                Log.Info("Permanently deleted " + path);
                return true;
            }, (removed, err) =>
            {
                deletingNode = false;
                dirty = false;
                FileUtil.TryDelete(MapFile.PathFor(originalMap.RootPath));
                if (err != null)
                    Ui.Warn(this, "Atlas couldn't finish deleting " + path + ".\n\n" + err.Message);
                string refreshRoot = removed && n == originalMap.Root ? Path.GetDirectoryName(path.TrimEnd('\\')) : originalMap.RootPath;
                if (!string.IsNullOrEmpty(refreshRoot)) StartScan(refreshRoot, false);
            });
        }

        static bool Inside(Node x, Node folder)
        {
            for (var p = x; p != null; p = p.Parent) if (p == folder) return true;
            return false;
        }

        // Takes a recycled folder or file out of the map and its folders' totals.
        static void Detach(Node n)
        {
            var parent = n.Parent;
            if (parent == null || parent.Kids == null) return;
            parent.Kids = parent.Kids.Where(k => k != n).ToArray();
            if (parent.Kids.Length == 0) parent.Kids = null;
            for (var p = parent; p != null; p = p.Parent)
            {
                p.Size -= n.Size;
                p.Files -= n.Files;
                if (n.IsDir) p.Dirs -= 1 + n.Dirs;
                if (p.Parent != null && p.Parent.Kids != null) Array.Sort(p.Parent.Kids, (a, b) => b.Size.CompareTo(a.Size));
            }
        }

        void FillBigFiles()
        {
            if (map == null) return;
            var files = AtlasCli.Files(map.Root).ToList();
            files.Sort((a, b) => b.Size.CompareTo(a.Size));
            Ui.Fill(bigFiles, files.Take(1000).Select(f => Ui.Row(f, f.Name, Fmt.Size(f.Size), Kinds.Names[f.Kind], Fmt.Local(f.ModifiedUtc), f.Parent == null ? "" : f.Parent.FullPath)).ToList());
        }

        void FillTypes()
        {
            if (map == null) return;
            long total = Math.Max(1, map.Root.Size);
            Ui.Fill(types, map.Types.OrderByDescending(kv => kv.Value.Size).Take(400)
                .Select(kv => Ui.Row(kv.Key, kv.Key, Kinds.Names[Kinds.Of("x" + kv.Key)], Fmt.Size(kv.Value.Size), kv.Value.Count.ToString("N0"),
                                     (100.0 * kv.Value.Size / total).ToString("0.0") + "%")).ToList());
        }

        // ------------------------------------------------------------------ clean up

        void MeasureJunk()
        {
            if (measuring || cleaning) return;
            measuring = true;
            junkTotal.Text = "Measuring…";
            Ui.Background(this, () =>
            {
                var list = Catalog.Load();
                foreach (var it in list)
                {
                    try { Cleaner.Measure(it); } catch (Exception e) { it.Blocked = e.Message; }
                }
                var rev = Review.Collect(AtlasSettings.Load());
                return Tuple.Create(list, rev);
            }, (res, err) =>
            {
                measuring = false;
                if (res == null) { junkTotal.Text = "Couldn't measure" + (err != null ? ": " + err.Message : ""); return; }
                items = res.Item1;
                reviews = res.Item2;
                games = null;
                FillJunk();
                FillReview();
            });
        }

        static string SizeText(CleanItem it)
        {
            if (it.How == "empty-bin") return Fmt.Size(it.Bytes);
            if (it.Unreadable) return "admin to see";
            return Fmt.Size(it.Bytes) + (it.Partial ? "+" : "");
        }

        static string WhereText(CleanItem it)
        {
            if (it.How == "empty-bin") return "every drive";
            string first = it.Paths.Count > 0 ? Environment.ExpandEnvironmentVariables(it.Paths[0]) : "";
            return first + (it.Paths.Count > 1 ? "  (+" + (it.Paths.Count - 1) + " more)" : "");
        }

        void FillJunk()
        {
            if (!tickedInit)
            {
                foreach (var it in items) if (it.Default) ticked.Add(it.Id);
                tickedInit = true;
            }
            filling = true;
            junk.BeginUpdate();
            try
            {
                junk.Items.Clear();
                foreach (var it in items)
                {
                    if (!it.Admin && !it.Exists) continue;
                    if (it.Group == "leftovers" && it.Bytes < (1L << 20)) continue;
                    if (it.Id.StartsWith("steam-", StringComparison.Ordinal) && it.Measured && it.Bytes == 0) continue;
                    var row = new ListViewItem(new[] { it.Name, SizeText(it), it.Count > 0 ? it.Count.ToString("N0") : "", WhereText(it), it.Blocked ?? it.About }) { Tag = it };
                    row.Group = junk.Groups[it.Admin ? "admin" : it.Group == "leftovers" ? "leftovers" : "junk"];
                    row.Checked = ticked.Contains(it.Id) && it.Blocked == null;
                    if (it.Blocked != null) row.ForeColor = Ui.StateColor(States.Warn);
                    else if (it.Measured && it.Bytes == 0 && !it.Unreadable) row.ForeColor = Ui.Muted;
                    junk.Items.Add(row);
                }
            }
            finally
            {
                junk.EndUpdate();
                filling = false;
            }
            UpdateJunkTotal();
        }

        void UpdateJunkTotal()
        {
            var chosen = junk.CheckedItems.Cast<ListViewItem>().Select(x => x.Tag as CleanItem).Where(x => x != null).ToList();
            long sum = chosen.Sum(x => x.Bytes);
            bool more = chosen.Any(x => x.Unreadable || x.Partial);
            junkTotal.Text = chosen.Count == 0 ? "Nothing ticked" : "Ticked: " + Fmt.Size(sum) + (more ? " and more" : "");
        }

        void ShowJunkPlace()
        {
            if (junk.SelectedItems.Count == 0) { Ui.Info(this, "Select a row first."); return; }
            var it = junk.SelectedItems[0].Tag as CleanItem;
            if (it == null) return;
            if (it.How == "empty-bin") { Proc.Open("shell:RecycleBinFolder"); return; }
            var place = Cleaner.Places(it).FirstOrDefault();
            if (place == null) { Ui.Info(this, "There's nothing there right now."); return; }
            if (Directory.Exists(place)) Proc.Open(place); else Proc.ShowInExplorer(place);
        }

        void CleanTicked()
        {
            if (cleaning || measuring || deletingNode) return;
            var chosen = junk.CheckedItems.Cast<ListViewItem>().Select(x => x.Tag as CleanItem).Where(x => x != null && x.Blocked == null).ToList();
            if (chosen.Count == 0) { Ui.Info(this, "Tick what you'd like cleaned first."); return; }
            long bytes = chosen.Sum(i => i.Bytes);
            var admin = chosen.Where(i => i.Admin).ToList();
            var sb = new StringBuilder("Clean " + Fmt.Plural(chosen.Count, "item") + " (" + Fmt.Size(bytes) + (chosen.Any(i => i.Unreadable) ? " plus what Windows' folders hold" : "") + ")?\n\n");
            if (chosen.Any(i => i.How == "delete")) sb.Append("Temporary files and caches are deleted for good; programs make new ones as they need them.\n");
            if (chosen.Any(i => i.How == "recycle")) sb.Append("Leftover folders go to the Recycle Bin, so you can still get them back.\n");
            if (chosen.Any(i => i.How == "empty-bin")) sb.Append("The Recycle Bin is emptied: what's in it is gone for good.\n");
            if (admin.Count > 0) sb.Append("Windows asks once for admin rights, for: " + string.Join(", ", admin.Select(i => i.Name)) + ".\n");
            if (GameState.Playing) sb.Append("\nA game is running: anything it's using is skipped.\n");
            if (!Ui.Confirm(this, sb.ToString().TrimEnd())) return;
            cleaning = true;
            junkTotal.Text = "Cleaning…";
            StatusBar.Text = "Cleaning " + Fmt.Plural(chosen.Count, "item") + "…";
            Ui.Background(this, () => DoClean(chosen), (results, err) =>
            {
                cleaning = false;
                if (results == null) { Ui.Warn(this, "Cleaning stopped: " + (err != null ? err.Message : "unknown problem")); MeasureJunk(); return; }
                long freed = results.Sum(r => r.Freed), failed = results.Sum(r => r.Failed);
                var notes = results.Where(r => r.Note != null).Select(r => r.Name + ": " + r.Note).ToList();
                StatusBar.Text = "Cleaned: freed " + Fmt.Size(freed) + ".";
                Ui.Info(this, "Freed " + Fmt.Size(freed) + "." + (failed > 0 ? "\n" + failed.ToString("N0") + " files were in use and stayed." : "") +
                              (notes.Count > 0 ? "\n\n" + string.Join("\n", notes) : ""));
                MeasureJunk();
                RefreshDrives();
            });
        }

        static List<CleanResult> DoClean(List<CleanItem> chosen)
        {
            var results = new List<CleanResult>();
            foreach (var it in chosen.Where(i => !i.Admin))
            {
                var r = Cleaner.Clean(it);
                History.Add(r);
                results.Add(r);
            }
            var admin = chosen.Where(i => i.Admin).ToList();
            if (admin.Count == 0) return results;
            string outFile = Path.Combine(Suite.UserDir(AppId.Atlas), "clean-result.json");
            FileUtil.TryDelete(outFile);
            int code;
            try { code = Elevation.Run(Suite.ExeOf(AppId.Atlas), "--clean-admin " + string.Join(",", admin.Select(i => i.Id)) + " --out " + Proc.Quote(outFile), true); }
            catch (Exception e) { results.Add(new CleanResult { Id = "admin", Name = "Windows' own folders", Note = e.Message }); return results; }
            if (code == -1) { results.Add(new CleanResult { Id = "admin", Name = "Windows' own folders", Note = "skipped (the admin prompt was declined)" }); return results; }
            var got = J.Load<List<CleanResult>>(outFile);
            if (got != null) results.AddRange(got);
            else results.Add(new CleanResult { Id = "admin", Name = "Windows' own folders", Note = "didn't report back (code " + code + ")" });
            return results;
        }

        void FillReview()
        {
            Ui.Fill(review, reviews.Select(r => Ui.Row(r, r.Name, r.Size > 0 ? Fmt.Size(r.Size) : "", r.When ?? "", r.Path ?? "", r.Action ?? "")).ToList());
        }

        void ReviewAction()
        {
            if (deletingNode || review.SelectedItems.Count == 0) return;
            var r = review.SelectedItems[0].Tag as ReviewItem;
            if (r == null) return;
            switch (r.Kind)
            {
                case "game":
                    if (Ui.Confirm(this, "Ask Steam to uninstall " + r.Name + " (" + Fmt.Size(r.Size) + ")? Steam shows its own confirmation first.")) Proc.Open("steam://uninstall/" + r.AppId);
                    break;
                case "download":
                    if (!Ui.Confirm(this, "Move " + r.Path + " (" + Fmt.Size(r.Size) + ") to the Recycle Bin?")) return;
                    Recycler.Recycle(new[] { r.Path });
                    if (File.Exists(r.Path)) { Ui.Warn(this, "Windows couldn't move it (something may be using it)."); return; }
                    reviews.Remove(r);
                    FillReview();
                    RefreshDrives();
                    break;
                case "winold":
                    Proc.Open("ms-settings:storagesense");
                    break;
                case "hibernate":
                    Ui.Info(this, "Windows saves your memory to this file (" + Fmt.Size(r.Size) + ") when the PC hibernates, and for Fast Startup.\n\n" +
                        "If you never use hibernate, you can turn it off from an admin Command Prompt:\n\n    powercfg /hibernate off\n\n" +
                        "That frees the space right away. Fast Startup goes too, so a cold boot takes a few seconds longer. " +
                        "\"powercfg /hibernate on\" brings it back. Atlas doesn't change this setting itself.");
                    break;
                default:
                    Proc.ShowInExplorer(r.Path);
                    break;
            }
        }
    }

    // The folder tree as a list: indented rows you open and close, with each one's share of its folder.
    sealed class TreeList : ListView
    {
        sealed class Row { public Node Node; public int Depth; public byte Pseudo; }   // Pseudo: Kinds.Small or Kinds.Hidden
        readonly List<Row> rows = new List<Row>();
        readonly HashSet<Node> open = new HashSet<Node>();
        readonly int indent = Ui.S(16), glyph = Ui.S(14), swatch = Ui.S(12);
        MapInfo map;
        public event Action<Node> NodeSelected, NodeActivated;
        public event Action<Node, Point> MenuRequested;

        public TreeList()
        {
            View = View.Details;
            VirtualMode = true;
            FullRowSelect = true;
            HideSelection = false;
            MultiSelect = false;
            OwnerDraw = true;
            Dock = DockStyle.Fill;
            Font = Ui.Base;
            foreach (var c in new[] { "Name|440", "Size|90", "Share of its folder|150", "Files|85", "Folders|75", "Newest change|135" })
            {
                int bar = c.IndexOf('|');
                Columns.Add(c.Substring(0, bar), Ui.S(int.Parse(c.Substring(bar + 1))));
            }
            Columns[1].TextAlign = HorizontalAlignment.Right;
            Columns[3].TextAlign = HorizontalAlignment.Right;
            Columns[4].TextAlign = HorizontalAlignment.Right;
            SmallImageList = new ImageList { ImageSize = new Size(1, Ui.S(20)) };
            var prop = typeof(Control).GetProperty("DoubleBuffered", BindingFlags.NonPublic | BindingFlags.Instance);
            if (prop != null) prop.SetValue(this, true, null);
            RetrieveVirtualItem += (s, e) => e.Item = Item(e.ItemIndex);
            DrawColumnHeader += (s, e) => e.DrawDefault = true;
            DrawItem += (s, e) => { };
            DrawSubItem += DrawCell;
            SelectedIndexChanged += (s, e) => { if (NodeSelected != null) NodeSelected(SelectedNode); };
            MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Left) return;
                int i = IndexAt(e.Location);
                if (i >= 0 && OnGlyph(i, e.X)) Toggle(i);
            };
            MouseDoubleClick += (s, e) =>
            {
                int i = IndexAt(e.Location);
                if (i >= 0 && !OnGlyph(i, e.X)) Toggle(i);
            };
            MouseUp += (s, e) =>
            {
                if (e.Button != MouseButtons.Right) return;
                int i = IndexAt(e.Location);
                if (i < 0 || rows[i].Pseudo != 0) return;
                SelectRow(i);
                if (MenuRequested != null) MenuRequested(rows[i].Node, e.Location);
            };
            KeyDown += Key;
            Resize += (s, e) => FitName();
        }

        // The name column takes whatever width the other columns leave.
        void FitName()
        {
            if (Columns.Count < 2) return;
            int others = 0;
            for (int c = 1; c < Columns.Count; c++) others += Columns[c].Width;
            int w = ClientSize.Width - others - SystemInformation.VerticalScrollBarWidth - 2;
            if (w >= Ui.S(180) && Math.Abs(Columns[0].Width - w) > 2) Columns[0].Width = w;
        }

        public Node SelectedNode
        {
            get
            {
                int i = SelectedIndices.Count > 0 ? SelectedIndices[0] : -1;
                return i >= 0 && i < rows.Count && rows[i].Pseudo == 0 ? rows[i].Node : null;
            }
        }

        public void ShowMap(MapInfo m)
        {
            map = m;
            open.Clear();
            if (m != null) open.Add(m.Root);
            Rebuild(m == null ? null : m.Root);
        }

        public void Rebuild(Node keep)
        {
            BeginUpdate();
            try
            {
                if (IsHandleCreated) SelectedIndices.Clear();
                rows.Clear();
                if (map != null) AddRows(map.Root, 0);
                VirtualListSize = rows.Count;
                int i = keep == null ? -1 : rows.FindIndex(x => x.Node == keep && x.Pseudo == 0);
                if (i >= 0) SelectRow(i);
            }
            finally { EndUpdate(); }
            Invalidate();
        }

        // Opens the folders down to n and selects it.
        public void Reveal(Node n)
        {
            if (map == null || n == null) return;
            for (var p = n.Parent; p != null; p = p.Parent) open.Add(p);
            Rebuild(n);
        }

        bool HasContent(Node n) { return n.Kids != null || n.SmallCount > 0 || (map != null && n == map.Root && map.Unseen > 0); }

        void AddRows(Node n, int depth)
        {
            rows.Add(new Row { Node = n, Depth = depth });
            if (!n.IsDir || !open.Contains(n)) return;
            long small = n.SmallCount > 0 ? n.SmallSize : -1;
            long hidden = n == map.Root && map.Unseen > 0 ? map.Unseen : -1;
            // the "smaller files" and "hidden" rows go where their size puts them
            Action<long> pseudo = threshold =>
            {
                while (true)
                {
                    long best = Math.Max(small, hidden);
                    if (best < 0 || best < threshold) return;
                    if (hidden == best) { rows.Add(new Row { Node = n, Depth = depth + 1, Pseudo = Kinds.Hidden }); hidden = -1; }
                    else { rows.Add(new Row { Node = n, Depth = depth + 1, Pseudo = Kinds.Small }); small = -1; }
                }
            };
            if (n.Kids != null)
                foreach (var k in n.Kids)
                {
                    pseudo(k.Size);
                    AddRows(k, depth + 1);
                }
            pseudo(0);
        }

        long SizeOf(Row r) { return r.Pseudo == Kinds.Small ? r.Node.SmallSize : r.Pseudo == Kinds.Hidden ? map.Unseen : r.Node.Size; }
        long Total(Node folder) { return folder.Size + (folder == map.Root ? map.Unseen : 0); }
        long ParentTotal(Row r) { return r.Pseudo != 0 ? Total(r.Node) : r.Node.Parent != null ? Total(r.Node.Parent) : 0; }

        string Caption(Row r)
        {
            if (r.Pseudo == Kinds.Small) return "(" + Fmt.Plural(r.Node.SmallCount, "smaller file") + ")";
            if (r.Pseudo == Kinds.Hidden) return "(hidden from Atlas: restore points, Windows' file table, folders that need admin)";
            var n = r.Node;
            string s = n.Parent == null ? n.FullPath : n.Name;
            if (n.Has(Node.Denied)) s += "   (needs admin to read)";
            if (n.Has(Node.Link)) s += "   (a link to somewhere else; not counted)";
            if (n.Has(Node.HardLink)) s += "   (hard link: its space is counted at another link to the same file)";
            return s;
        }

        ListViewItem Item(int i)
        {
            var it = new ListViewItem(i >= 0 && i < rows.Count ? Caption(rows[i]) : "");
            for (int c = 1; c < Columns.Count; c++) it.SubItems.Add("");
            return it;
        }

        static Rectangle Inset(Rectangle b) { return new Rectangle(b.X + Ui.S(4), b.Y, Math.Max(0, b.Width - Ui.S(8)), b.Height); }

        void DrawCell(object sender, DrawListViewSubItemEventArgs e)
        {
            int i = e.ItemIndex;
            if (i < 0 || i >= rows.Count || map == null) return;
            var r = rows[i];
            var g = e.Graphics;
            var b = e.ColumnIndex == 0 ? new Rectangle(e.Bounds.X, e.Bounds.Y, Columns[0].Width, e.Bounds.Height) : e.Bounds;
            bool sel = SelectedIndices.Contains(i);
            bool dim = r.Pseudo != 0 || r.Node.Has(Node.Denied) || r.Node.Has(Node.Link);
            Color back = sel ? (Focused ? SystemColors.Highlight : Color.FromArgb(0xDD, 0xE7, 0xF3)) : BackColor;
            Color fore = sel && Focused ? SystemColors.HighlightText : dim ? Ui.Muted : ForeColor;
            using (var bb = new SolidBrush(back)) g.FillRectangle(bb, b);
            var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix;
            long size = SizeOf(r);
            switch (e.ColumnIndex)
            {
                case 0:
                {
                    int x = b.X + Ui.S(4) + r.Depth * indent;
                    if (r.Pseudo == 0 && r.Node.IsDir && HasContent(r.Node)) DrawGlyph(g, new Rectangle(x, b.Y, glyph, b.Height), open.Contains(r.Node), fore);
                    x += glyph + Ui.S(2);
                    DrawSwatch(g, new Rectangle(x, b.Y + (b.Height - swatch) / 2, swatch, swatch), r);
                    x += swatch + Ui.S(6);
                    TextRenderer.DrawText(g, Caption(r), r.Depth == 0 ? Ui.Bold : Font, new Rectangle(x, b.Y, Math.Max(0, b.Right - x - 2), b.Height), fore, flags);
                    break;
                }
                case 1:
                    TextRenderer.DrawText(g, Fmt.Size(size), Font, Inset(b), fore, flags | TextFormatFlags.Right);
                    break;
                case 2:
                {
                    long total = ParentTotal(r);
                    if (total <= 0) break;
                    double share = Math.Max(0, Math.Min(1, (double)size / total));
                    var track = new Rectangle(b.X + Ui.S(4), b.Y + b.Height / 2 - Ui.S(5), Math.Max(0, b.Width - Ui.S(54)), Ui.S(10));
                    using (var tb = new SolidBrush(sel && Focused ? Color.FromArgb(70, 255, 255, 255) : Color.FromArgb(0xE6, 0xE6, 0xE6))) g.FillRectangle(tb, track);
                    using (var fb = new SolidBrush(AppInfo.Of(AppId.Atlas).Top)) g.FillRectangle(fb, new Rectangle(track.X, track.Y, (int)Math.Round(track.Width * share), track.Height));
                    TextRenderer.DrawText(g, (share * 100).ToString(share < 0.1 ? "0.0" : "0") + "%", Font, new Rectangle(track.Right + Ui.S(4), b.Y, Ui.S(48), b.Height), fore, flags);
                    break;
                }
                case 3:
                    if (r.Pseudo == 0 && r.Node.IsDir) TextRenderer.DrawText(g, r.Node.Files.ToString("N0"), Font, Inset(b), fore, flags | TextFormatFlags.Right);
                    else if (r.Pseudo == Kinds.Small) TextRenderer.DrawText(g, r.Node.SmallCount.ToString("N0"), Font, Inset(b), fore, flags | TextFormatFlags.Right);
                    break;
                case 4:
                    if (r.Pseudo == 0 && r.Node.IsDir) TextRenderer.DrawText(g, r.Node.Dirs.ToString("N0"), Font, Inset(b), fore, flags | TextFormatFlags.Right);
                    break;
                case 5:
                    if (r.Pseudo == 0) TextRenderer.DrawText(g, Fmt.Local(r.Node.ModifiedUtc), Font, Inset(b), fore, flags);
                    break;
            }
        }

        static void DrawGlyph(Graphics g, Rectangle r, bool isOpen, Color c)
        {
            var old = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, s = Math.Min(r.Width, r.Height) * 0.28f;
            PointF[] pts = isOpen
                ? new[] { new PointF(cx - s, cy - s * 0.55f), new PointF(cx + s, cy - s * 0.55f), new PointF(cx, cy + s * 0.75f) }
                : new[] { new PointF(cx - s * 0.55f, cy - s), new PointF(cx + s * 0.75f, cy), new PointF(cx - s * 0.55f, cy + s) };
            using (var br = new SolidBrush(Color.FromArgb(160, c))) g.FillPolygon(br, pts);
            g.SmoothingMode = old;
        }

        static void DrawSwatch(Graphics g, Rectangle r, Row row)
        {
            bool folder = row.Pseudo == 0 && row.Node.IsDir;
            Color c = row.Pseudo != 0 ? Kinds.Colors[row.Pseudo] : folder ? Color.FromArgb(0xE8, 0xB0, 0x4B) : Kinds.Colors[row.Node.Kind];
            using (var br = new SolidBrush(c))
            {
                if (folder)
                {
                    g.FillRectangle(br, r.X, r.Y + r.Height / 4, r.Width, r.Height - r.Height / 4);
                    g.FillRectangle(br, r.X, r.Y + r.Height / 10, r.Width / 2, r.Height / 4);
                }
                else g.FillRectangle(br, r);
            }
        }

        int IndexAt(Point p)
        {
            var hit = HitTest(p);
            return hit.Item != null ? hit.Item.Index : -1;
        }

        bool OnGlyph(int i, int x)
        {
            var r = rows[i];
            if (r.Pseudo != 0 || !r.Node.IsDir) return false;
            int gx = GetItemRect(i).X + Ui.S(4) + r.Depth * indent;
            return x >= gx - 2 && x <= gx + glyph + 2;
        }

        void Toggle(int i)
        {
            if (i < 0 || i >= rows.Count) return;
            var r = rows[i];
            if (r.Pseudo != 0 || !r.Node.IsDir || !HasContent(r.Node)) return;
            if (!open.Remove(r.Node)) open.Add(r.Node);
            Rebuild(r.Node);
        }

        void SelectRow(int i)
        {
            if (!IsHandleCreated || i < 0 || i >= rows.Count) return;
            SelectedIndices.Clear();
            SelectedIndices.Add(i);
            try { FocusedItem = Items[i]; } catch (Exception) { }
            EnsureVisible(i);
        }

        void Key(object sender, KeyEventArgs e)
        {
            int i = SelectedIndices.Count > 0 ? SelectedIndices[0] : -1;
            if (i < 0 || i >= rows.Count) return;
            var r = rows[i];
            if (e.KeyCode == Keys.Right)
            {
                if (r.Pseudo == 0 && r.Node.IsDir && HasContent(r.Node) && !open.Contains(r.Node)) Toggle(i);
                else if (i + 1 < rows.Count && rows[i + 1].Depth > r.Depth) SelectRow(i + 1);
                e.Handled = true;
            }
            else if (e.KeyCode == Keys.Left)
            {
                if (r.Pseudo == 0 && open.Contains(r.Node)) Toggle(i);
                else
                {
                    var parent = r.Pseudo != 0 ? r.Node : r.Node.Parent;
                    int pi = parent == null ? -1 : rows.FindIndex(x => x.Node == parent && x.Pseudo == 0);
                    if (pi >= 0) SelectRow(pi);
                }
                e.Handled = true;
            }
            else if (e.KeyCode == Keys.Enter && r.Pseudo == 0)
            {
                if (NodeActivated != null) NodeActivated(r.Node);
                e.Handled = true;
            }
            else if ((e.KeyCode == Keys.Apps || (e.KeyCode == Keys.F10 && e.Shift)) && r.Pseudo == 0 && MenuRequested != null)
            {
                var rect = GetItemRect(i);
                MenuRequested(r.Node, new Point(rect.X + Ui.S(40), rect.Bottom));
                e.Handled = true;
            }
        }
    }

    // One drive on the strip above the map: name, how full it is, when it was last mapped.
    sealed class DriveCard : Control
    {
        public string Root = "", VolumeName = "", Note = "";
        public long Total, Free;
        public int WarnPercent = 10;
        public bool Current;
        bool hover;

        public DriveCard()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true);
            Size = new Size(Ui.S(214), Ui.S(58));
            Margin = new Padding(0, 0, Ui.S(8), Ui.S(4));
            Cursor = Cursors.Hand;
            BackColor = SystemColors.Window;
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var app = AppInfo.Of(AppId.Atlas);
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var bg = new SolidBrush(hover ? Color.FromArgb(0xF7, 0xF3, 0xEE) : SystemColors.Window)) g.FillRectangle(bg, r);
            using (var border = new Pen(Current ? app.Bottom : hover ? app.Top : Color.FromArgb(0xD9, 0xD9, 0xD9), Current ? Ui.S(2) : 1)) g.DrawRectangle(border, r);
            string letter = Root.TrimEnd('\\');
            TextRenderer.DrawText(g, letter, Ui.Big, new Point(Ui.S(8), Ui.S(5)), SystemColors.ControlText);
            int lw = TextRenderer.MeasureText(letter, Ui.Big).Width;
            TextRenderer.DrawText(g, VolumeName, Ui.Base, new Rectangle(Ui.S(8) + lw, Ui.S(8), Math.Max(0, Width - lw - Ui.S(16)), Ui.S(18)), Ui.Muted,
                TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
            var bar = new Rectangle(Ui.S(8), Ui.S(30), Width - Ui.S(16), Ui.S(7));
            double used = Total > 0 ? 1.0 - (double)Free / Total : 0;
            int level = DriveWatch.Level(Free, Total, 0, WarnPercent);
            Color c = level == 2 ? Ui.StateColor(States.Alert) : level == 1 ? Ui.StateColor(States.Warn) : app.Top;
            using (var track = new SolidBrush(Color.FromArgb(0xE6, 0xE6, 0xE6))) g.FillRectangle(track, bar);
            using (var fill = new SolidBrush(c)) g.FillRectangle(fill, new Rectangle(bar.X, bar.Y, (int)(bar.Width * Math.Max(0, Math.Min(1, used))), bar.Height));
            string text = Fmt.Size(Free) + " free of " + Fmt.Size(Total);
            TextRenderer.DrawText(g, text, Ui.Base, new Rectangle(Ui.S(8), Ui.S(38), Width - Ui.S(12), Ui.S(18)), Ui.Muted,
                TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }
    }
}
