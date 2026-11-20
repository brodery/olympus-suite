// Argus's window: changes to review (keep or turn off), everything it watches (filterable),
// what you've turned off (with Undo), and the history.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Argus
{
    sealed class ArgusWindow : AppWindow
    {
        readonly TabControl tabs = new TabControl();
        readonly ListView review = Ui.Empty(Ui.List("Level|80", "Change|80", "Kind|140", "Name|230", "Signed by|170", "Why|300"), "Nothing to review. Argus checks every few minutes; new and changed entries that aren't routine show up here.");
        readonly ListView all = Ui.Empty(Ui.List("Kind|170", "Name|250", "Signed by|170", "On|40", "Runs / details|360"), "Nothing matches.");
        readonly ListView off = Ui.Empty(Ui.List("When|140", "What|420*", "Status|120"), "Nothing turned off. Things you turn off show up here, with Undo.");
        readonly ListView history = Ui.Empty(Ui.List("When|140", "Event|90", "What|620"), "No history yet.");
        readonly TextBox filter = new TextBox();
        readonly ComboBox kind = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly TextBox detail = new TextBox();
        readonly Button keep, turnOff, undo;
        ArgusData data;
        bool scanning;

        public ArgusWindow() : base(AppInfo.Of(AppId.Argus), 1080, 720)
        {
            AutoRefresh(30);
            keep = Ui.Btn("It's fine, keep it", (s, e) => Act("accept"));
            turnOff = Ui.Btn("Turn it off", (s, e) => Act("disable"));
            undo = Ui.Btn("Undo (put it back)", (s, e) => UndoSelected());
            Add(Ui.Btn("Scan now", (s, e) => ScanNow()), keep, turnOff, undo,
                Ui.Btn("Show where it lives", (s, e) => ShowLocation()),
                Ui.Btn("Keep everything listed", (s, e) => KeepAll()));

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(118)));
            Body.Controls.Add(layout);

            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Ui.Tab("To review", review));
            var everything = new TableLayoutPanel { ColumnCount = 1, RowCount = 2 };
            everything.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            everything.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var bar = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, 0, 0, Ui.S(4)) };
            bar.Controls.Add(Ui.Lbl("Show"));
            kind.Width = Ui.S(200);
            bar.Controls.Add(kind);
            bar.Controls.Add(Ui.Lbl("Search"));
            filter.Width = Ui.S(260);
            bar.Controls.Add(filter);
            everything.Controls.Add(bar, 0, 0);
            everything.Controls.Add(all, 0, 1);
            tabs.TabPages.Add(Ui.Tab("Everything", everything));
            tabs.TabPages.Add(Ui.Tab("Turned off", off));
            tabs.TabPages.Add(Ui.Tab("History", history));
            layout.Controls.Add(tabs, 0, 0);

            detail.Multiline = true;
            detail.ReadOnly = true;
            detail.ScrollBars = ScrollBars.Vertical;
            detail.Dock = DockStyle.Fill;
            detail.Font = Ui.Base;
            detail.Margin = new Padding(0, Ui.S(6), 0, 0);
            layout.Controls.Add(detail, 0, 1);

            kind.SelectedIndexChanged += (s, e) => FillAll();
            filter.TextChanged += (s, e) => FillAll();
            foreach (var lv in new[] { review, all, off, history }) lv.SelectedIndexChanged += (s, e) => { ShowDetail(); UpdateButtons(); };
            tabs.SelectedIndexChanged += (s, e) => { ShowDetail(); UpdateButtons(); };
            review.DoubleClick += (s, e) => ShowLocation();
            all.DoubleClick += (s, e) => ShowLocation();
        }

        protected override void RefreshView()
        {
            data = ArgusData.ForDisplay();
            var st = StatusStore.Read(AppId.Argus);
            if (st == null) SetState(States.Off, "No scan yet — click Scan now");
            else SetState(st.State, st.Summary);
            StatusBar.Text = (st != null ? st.Detail + " · " : "") + "data: " + data.Dir;

            var rows = new List<ListViewItem>();
            foreach (var f in data.Pending.Values.OrderByDescending(x => Sev.Rank(x.Severity)).ThenByDescending(x => x.Seen, StringComparer.Ordinal))
            {
                var it = Ui.Row(f.Key, Ui.SevWord(f.Severity), f.Kind, Engine.Noun(f.Now.Category), f.Now.Name, f.Now.SignedBy, f.Why ?? "");
                it.ForeColor = Ui.SevColor(f.Severity);
                rows.Add(it);
            }
            Ui.Fill(review, rows);
            tabs.TabPages[0].Text = "To review (" + data.Pending.Count + ")";

            var kinds = new List<string> { "All kinds" };
            kinds.AddRange(data.Current.Select(i => i.Category).Distinct().OrderBy(c => c).Select(Engine.Plural));
            if (kind.Items.Count != kinds.Count)
            {
                object sel = kind.SelectedItem;
                kind.Items.Clear();
                kind.Items.AddRange(kinds.ToArray());
                kind.SelectedItem = sel != null && kinds.Contains(sel) ? sel : kinds[0];
            }
            FillAll();
            tabs.TabPages[1].Text = "Everything (" + data.Current.Count + ")";

            Ui.Fill(off, data.Undo.Select(u => Ui.Row(u.Id, Fmt.Local(Clock.Parse(u.Time)), u.What, u.Undone ? "put back" : "off")).ToList());
            tabs.TabPages[2].Text = "Turned off (" + data.Undo.Count(u => !u.Undone) + ")";
            Ui.Fill(history, data.ReadHistory(500).Select(h => Ui.Row(null, Fmt.Local(Clock.Parse(h.Time)), h.Event, h.What)).ToList());
            UpdateButtons();
            ShowDetail();
        }

        void FillAll()
        {
            if (data == null) return;
            string k = kind.SelectedItem as string;
            string q = filter.Text.Trim();
            var rows = new List<ListViewItem>();
            foreach (var it in data.Current)
            {
                if (k != null && k != "All kinds" && Engine.Plural(it.Category) != k) continue;
                if (q.Length > 0 && (it.Name + " " + it.Command + " " + it.Signer + " " + it.Location).IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0) continue;
                var row = Ui.Row(it.Key, Engine.Noun(it.Category), it.Name, it.SignedBy, it.Enabled ? "yes" : "off", it.Command);
                if (!string.IsNullOrEmpty(it.Why)) row.ForeColor = Ui.SevColor(Sev.Critical);
                else if (it.Target != null && !it.Signed && !it.Missing) row.ForeColor = Ui.SevColor(Sev.Warning);
                else if (it.Missing) row.ForeColor = Ui.Muted;
                rows.Add(row);
            }
            Ui.Fill(all, rows);
        }

        ListView CurrentList { get { return tabs.SelectedIndex == 0 ? review : tabs.SelectedIndex == 1 ? all : tabs.SelectedIndex == 2 ? off : history; } }
        string SelectedTag { get { var lv = CurrentList; return lv.SelectedItems.Count == 0 ? null : lv.SelectedItems[0].Tag as string; } }

        // The buttons that act on a row only work while one is picked.
        void UpdateButtons()
        {
            int t = tabs.SelectedIndex;
            bool picked = SelectedTag != null;
            keep.Enabled = t == 0 && picked;
            turnOff.Enabled = (t == 0 || t == 1) && picked;
            undo.Enabled = t == 2 && picked;
        }

        void ShowDetail()
        {
            if (data == null) return;
            string tag = SelectedTag;
            if (tag == null) { detail.Text = CurrentList.Items.Count > 0 ? "Pick a row to see its details." : ""; return; }
            if (tabs.SelectedIndex == 2)
            {
                var u = data.Undo.FirstOrDefault(x => x.Id == tag);
                if (u != null) detail.Text = u.What + "\r\nTurned off " + Fmt.Local(Clock.Parse(u.Time)) + (u.Undone ? " · put back since" : "") + "\r\n" + string.Join("\r\n", u.Data.Where(kv => kv.Key != "data" && kv.Key != "blob").Select(kv => kv.Key + ": " + kv.Value));
                return;
            }
            Finding f;
            data.Pending.TryGetValue(tag, out f);
            var it = f != null ? f.Now : data.Current.FirstOrDefault(i => i.Key == tag);
            if (it == null) { detail.Text = ""; return; }
            var lines = new List<string>();
            lines.Add(Engine.Noun(it.Category) + ": " + it.Name + (it.Enabled ? "" : "   (switched off)"));
            if (f != null && !string.IsNullOrEmpty(f.Why)) lines.Add("Why it's flagged: " + f.Why);
            lines.Add((it.Category == "extension" ? "Access: " : "Runs: ") + it.Command);
            if (f != null && f.Before != null) lines.Add("Before: " + f.Before.Command + (f.Before.Signer != null ? "  (signed by " + f.Before.Signer + ")" : ""));
            if (it.Target != null) lines.Add("Program: " + it.Target + "  —  " + (it.Signer != null ? "signed by " + it.Signer + (it.Trusted ? "" : " (signature not valid)") : File.Exists(it.Target) ? "not signed" : "file missing"));
            lines.Add("Where: " + it.Location);
            foreach (var kv in it.Extra.Where(kv => kv.Key != "value" && kv.Key != "notarget" && kv.Key != "relpath")) lines.Add(kv.Key + ": " + kv.Value);
            detail.Text = string.Join("\r\n", lines);
        }

        void Act(string action)
        {
            string key = SelectedTag;
            if (key == null || tabs.SelectedIndex > 1) { Ui.Info(this, "Pick an entry first."); return; }
            var it = Engine.Find(data, key);
            if (action == "disable")
            {
                if (it != null && !Engine.CanTurnOff(it)) { Ui.Info(this, it.Category == "extension" ? "Browsers don't let other programs switch extensions off. Open your browser's Extensions page and remove or disable it there." : "Argus can't turn this kind of entry off; change it by hand."); return; }
                if (it != null && (it.Category == "service" || it.Category == "driver") && !Ui.Confirm(this, "Turn off the " + Engine.Noun(it.Category) + " \"" + it.Name + "\"?\n\nIt won't start any more (takes effect after a restart). If something stops working, use Undo on the Turned off tab.")) return;
                if (it != null && !Ui.Confirm(this, "Turn off " + Engine.Noun(it.Category) + " \"" + it.Name + "\"?\n\nYou can put it back later from the Turned off tab.")) return;
            }
            Run(action, key, null);
        }

        void UndoSelected()
        {
            string id = SelectedTag;
            if (id == null) return;
            var u = data.Undo.FirstOrDefault(x => x.Id == id);
            if (u == null || u.Undone) return;
            if (!Ui.Confirm(this, "Put back " + u.What + "?")) return;
            Run("undo", u.Key, u.Id);
        }

        void KeepAll()
        {
            if (data == null || data.Pending.Count == 0) return;
            if (!Ui.Confirm(this, "Keep all " + data.Pending.Count + " changes as they are? Only do this if you recognise them.")) return;
            Run("accept-all", null, null);
        }

        void Run(string action, string key, string undoId)
        {
            StatusBar.Text = "Working…";
            Ui.Background(this, () => Actions.Do(action, key, undoId), (err, ex) =>
            {
                if (ex != null) err = ex.Message;
                if (err != null) Ui.Warn(this, err);
                RefreshNow();
            });
        }

        void ScanNow()
        {
            if (scanning) return;
            scanning = true;
            StatusBar.Text = Suite.Installed ? "Asked the Argus task to scan; results appear in a moment…" : "Scanning (as you, so some areas aren't visible until Olympus is installed)…";
            Ui.Background(this, () => { Program.ScanNow(); if (Suite.Installed) System.Threading.Thread.Sleep(8000); return 0; }, (r, ex) => { scanning = false; RefreshNow(); });
        }

        void ShowLocation()
        {
            string key = SelectedTag;
            if (key == null || data == null) return;
            var it = Engine.Find(data, key);
            if (it == null) return;
            if (it.X("file") != null && File.Exists(it.X("file"))) { Proc.ShowInExplorer(it.X("file")); return; }
            if (it.X("folder") != null && Directory.Exists(it.X("folder"))) { Proc.Open(it.X("folder")); return; }
            if (it.Category == "task") { Proc.Open("taskschd.msc"); return; }
            if (it.Location.StartsWith("HKLM\\") || it.Location.StartsWith("HKU\\"))
            {
                // regedit opens at the last key it showed, so point that at this entry
                string full = "Computer\\" + (it.Location.StartsWith("HKLM\\") ? "HKEY_LOCAL_MACHINE" + it.Location.Substring(4) : "HKEY_USERS" + it.Location.Substring(3));
                try
                {
                    using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"))
                        k.SetValue("LastKey", full);
                    Proc.Open("regedit.exe");
                }
                catch (Exception e) { Ui.Warn(this, e.Message); }
                return;
            }
            if (it.Target != null && File.Exists(it.Target)) Proc.ShowInExplorer(it.Target);
        }

        protected override void HandleRequest(string request)
        {
            if (!request.StartsWith("alert:")) return;
            var a = AlertStore.Find(AppId.Argus, request.Substring(6));
            if (a == null) return;
            string key = a.Get("key");
            tabs.SelectedIndex = 0;
            foreach (ListViewItem row in review.Items)
                if ((row.Tag as string) == key) { row.Selected = true; row.EnsureVisible(); review.Focus(); return; }
        }
    }
}
