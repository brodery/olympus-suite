// Ark's window: your backup folders, the snapshots of each (newest first), and the files inside,
// compared with what's on disk now. Restore puts files back where they came from (anything
// different that's in the way is kept as a "(before restore)" copy) or into a folder you pick.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Ark
{
    sealed class ArkWindow : AppWindow
    {
        readonly TreeView tree = new TreeView();
        readonly ListView files = Ui.Empty(Ui.List("Name|220*", "Size|80>", "Modified|140", "Compared with now|130"), "Pick a time on the left to see the files in that backup.");
        readonly Label where = new Label();
        readonly SplitContainer split = new SplitContainer();
        ArkConfig cfg;

        sealed class Node
        {
            public string Kind;      // set | snap | dir
            public BackupSet Set;
            public string Snapshot, Rel = "";
        }

        public ArkWindow() : base(AppInfo.Of(AppId.Ark), 1040, 700)
        {
            AutoRefresh(20);
            Add(Ui.Btn("Back up now", (s, e) => { Proc.Start(Suite.ExeOf(AppId.Ark), "--backup-now"); StatusBar.Text = "Backup started; this window updates when it's done."; }),
                Ui.Btn("Restore", (s, e) => RestoreHere()),
                Ui.Btn("Restore to…", (s, e) => RestoreTo()),
                Ui.Btn("Open in Explorer", (s, e) => OpenInExplorer()),
                Ui.Btn("Reload", (s, e) => LoadTree()),
                Ui.Btn("Settings", (s, e) => OpenSettings()));

            split.Dock = DockStyle.Fill;
            split.FixedPanel = FixedPanel.Panel1;
            tree.Dock = DockStyle.Fill;
            tree.HideSelection = false;
            tree.ShowNodeToolTips = true;
            tree.BeforeExpand += (s, e) => Expand(e.Node);
            tree.AfterSelect += (s, e) => ShowFiles(e.Node);
            split.Panel1.Controls.Add(tree);
            var right = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
            right.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            where.AutoSize = true;
            where.ForeColor = Ui.Muted;
            where.Margin = new Padding(Ui.S(4), Ui.S(2), 0, Ui.S(6));
            where.Text = "Pick a folder, then a time, to see what was backed up.";
            right.Controls.Add(where, 0, 0);
            files.DoubleClick += (s, e) => OpenSelectedFile();
            right.Controls.Add(files, 0, 1);
            split.Panel2.Controls.Add(right);
            Body.Controls.Add(split);
            Load += (s, e) =>
            {
                try { split.SplitterDistance = Ui.S(380); } catch (Exception) { }
                LoadTree();
            };
        }

        protected override void RefreshView()
        {
            var st = StatusStore.Read(AppId.Ark);
            if (st == null) SetState(States.Off, "No backups yet — click Back up now, or install Olympus for hourly backups");
            else
            {
                SetState(st.State, st.Summary);
                StatusBar.Text = st.Detail + (cfg != null ? " · settings: " + cfg.FilePath : "");
            }
        }

        void LoadTree()
        {
            cfg = ArkConfig.LoadForDisplay();
            tree.BeginUpdate();
            tree.Nodes.Clear();
            foreach (var set in cfg.Sets)
            {
                // the name only (the path shows above the files, and when you hover the name)
                var n = new TreeNode(set.Name) { Tag = new Node { Kind = "set", Set = set }, ToolTipText = set.Path };
                n.Nodes.Add(new TreeNode("…"));
                tree.Nodes.Add(n);
            }
            tree.EndUpdate();
            if (tree.Nodes.Count > 0) { tree.Nodes[0].Expand(); tree.SelectedNode = tree.Nodes[0]; }
            RefreshView();
        }

        string SetDir(BackupSet set) { return Snapshots.SetDir(cfg.Target, set); }
        string SnapPath(Node n) { return Path.Combine(SetDir(n.Set), n.Snapshot, n.Rel); }
        string LivePath(Node n) { return n.Rel.Length == 0 ? n.Set.Path : Path.Combine(n.Set.Path, n.Rel); }

        void Expand(TreeNode node)
        {
            var info = node.Tag as Node;
            if (info == null || node.Nodes.Count != 1 || node.Nodes[0].Tag != null) return;
            node.Nodes.Clear();
            try
            {
                if (info.Kind == "set")
                {
                    string dir = SetDir(info.Set);
                    var names = Snapshots.List(dir);
                    names.Reverse();
                    foreach (var name in names)
                    {
                        var sum = Snapshots.Summary(dir, name);
                        string label = Fmt.Local(Snapshots.StampTime(name).ToUniversalTime());
                        if (sum != null)
                            label += "   " + (sum.Linked == 0 && sum.Copied > 0 ? "full copy, " + Fmt.Plural(sum.Files, "file") : sum.Copied == 0 ? "no changes" : Fmt.Plural(sum.Copied, "changed file"))
                                   + (sum.Errors > 0 ? ", incomplete with " + Fmt.Plural(sum.Errors, "error") : "");
                        var child = new TreeNode(label) { Tag = new Node { Kind = "snap", Set = info.Set, Snapshot = name } };
                        child.Nodes.Add(new TreeNode("…"));
                        node.Nodes.Add(child);
                    }
                    if (names.Count == 0) node.Nodes.Add(new TreeNode("(no snapshots yet)") { ForeColor = Ui.Muted });
                }
                else
                {
                    foreach (var d in new DirectoryInfo(Snapshots.L(SnapPath(info))).GetDirectories().OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        var child = new TreeNode(d.Name) { Tag = new Node { Kind = "dir", Set = info.Set, Snapshot = info.Snapshot, Rel = info.Rel.Length == 0 ? d.Name : info.Rel + "\\" + d.Name } };
                        child.Nodes.Add(new TreeNode("…"));
                        node.Nodes.Add(child);
                    }
                }
            }
            catch (Exception e) { node.Nodes.Add(new TreeNode("(couldn't read: " + e.Message + ")") { ForeColor = Ui.Muted }); }
        }

        void ShowFiles(TreeNode node)
        {
            var info = node == null ? null : node.Tag as Node;
            var rows = new List<ListViewItem>();
            if (info == null || info.Kind == "set")
            {
                where.Text = info == null ? "" : info.Set.Name + ": pick a time to see that snapshot (backed up from " + info.Set.Path + ").";
                Ui.Fill(files, rows);
                return;
            }
            where.Text = LivePath(info) + "  —  as it was " + Fmt.Local(Snapshots.StampTime(info.Snapshot).ToUniversalTime());
            try
            {
                foreach (var f in new DirectoryInfo(Snapshots.L(SnapPath(info))).GetFiles().OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                {
                    var live = new FileInfo(Snapshots.L(Path.Combine(LivePath(info), f.Name)));
                    string cmp = !live.Exists ? "deleted since" : live.Length == f.Length && live.LastWriteTimeUtc == f.LastWriteTimeUtc ? "same as now" : "changed since";
                    var it = Ui.Row(f.Name, f.Name, Fmt.Size(f.Length), Fmt.Local(f.LastWriteTimeUtc), cmp);
                    if (cmp != "same as now") it.ForeColor = Ui.StateColor(States.Busy);
                    rows.Add(it);
                }
            }
            catch (Exception e) { where.Text = "Couldn't read this snapshot: " + e.Message; }
            Ui.Fill(files, rows);
        }

        Node Current { get { return tree.SelectedNode == null ? null : tree.SelectedNode.Tag as Node; } }
        List<string> SelectedNames { get { return files.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as string).Where(x => x != null).ToList(); } }

        void RestoreHere()
        {
            var n = Current;
            if (n == null || n.Kind == "set") { Ui.Info(this, "Pick a snapshot (a time) first, then the files or folder to restore."); return; }
            var names = SelectedNames;
            string what = names.Count > 0 ? Fmt.Plural(names.Count, "file") : "the whole folder " + LivePath(n);
            if (!Ui.Confirm(this, "Put back " + what + " as of " + Fmt.Local(Snapshots.StampTime(n.Snapshot).ToUniversalTime()) + "?\n\nFiles that are different now are kept next to it as \"(before restore)\" copies, so nothing is lost.")) return;
            Run(n, names, LivePath(n));
        }

        void RestoreTo()
        {
            var n = Current;
            if (n == null || n.Kind == "set") { Ui.Info(this, "Pick a snapshot (a time) first."); return; }
            using (var dlg = new FolderBrowserDialog { Description = "Restore into which folder?" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                var names = SelectedNames;
                string dest = names.Count > 0 ? dlg.SelectedPath : Path.Combine(dlg.SelectedPath, n.Rel.Length == 0 ? n.Set.Slug : Path.GetFileName(n.Rel));
                Run(n, names, dest);
            }
        }

        void Run(Node n, List<string> names, string dest)
        {
            StatusBar.Text = "Restoring…";
            Ui.Background(this, () =>
            {
                var errors = new List<string>();
                int count = 0;
                if (names.Count > 0)
                {
                    foreach (var name in names)
                    {
                        try { if (Restore.File(Path.Combine(SnapPath(n), name), Path.Combine(dest, name))) count++; }
                        catch (Exception e) { errors.Add(name + ": " + e.Message); }
                    }
                }
                else count = Restore.Folder(SnapPath(n), dest, errors);
                return new KeyValuePair<int, List<string>>(count, errors);
            }, (r, err) =>
            {
                if (err != null) { Ui.Warn(this, "Restore failed: " + err.Message); return; }
                string msg = "Put back " + Fmt.Plural(r.Key, "file") + " into " + dest + ".";
                if (r.Value.Count > 0) msg += "\n\n" + Fmt.Plural(r.Value.Count, "file") + " couldn't be restored:\n" + string.Join("\n", r.Value.Take(8));
                StatusBar.Text = msg.Split('\n')[0];
                Log.Info("restored " + r.Key + " files from " + SnapPath(n) + " to " + dest);
                Ui.Info(this, msg);
                ShowFiles(tree.SelectedNode);
            });
        }

        void OpenInExplorer()
        {
            var n = Current;
            if (n == null) return;
            string p = n.Kind == "set" ? SetDir(n.Set) : SnapPath(n);
            if (Directory.Exists(p)) Proc.Open(p);
        }

        void OpenSelectedFile()
        {
            var n = Current;
            var names = SelectedNames;
            if (n == null || n.Kind == "set" || names.Count == 0) return;
            Proc.ShowInExplorer(Path.Combine(SnapPath(n), names[0]));
        }

        void OpenSettings()
        {
            if (cfg == null) return;
            if (cfg.FilePath.StartsWith(Suite.ProgramDataRoot, StringComparison.OrdinalIgnoreCase))
            {
                try { Elevation.Run("notepad.exe", Proc.Quote(cfg.FilePath), false); } catch (Exception e) { Ui.Warn(this, e.Message); }
            }
            else Proc.Open(cfg.FilePath);
        }
    }
}
