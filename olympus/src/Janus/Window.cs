// Janus's window: every download it has checked, the reasons, and what to do. Drop any file on
// the window to check it.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Janus
{
    sealed class JanusWindow : AppWindow
    {
        readonly ListView list = Ui.Empty(Ui.List("When|130", "File|280", "Verdict|100", "Kind|130", "Signed by|170", "From|160"), "No downloads checked yet. New files in Downloads are checked automatically; you can also drop a file here.");
        readonly TextBox detail = new TextBox();
        List<FileReport> rows = new List<FileReport>();
        FileReport extra;   // a file checked by hand (not in the history)

        public JanusWindow() : base(AppInfo.Of(AppId.Janus), 1040, 660)
        {
            AutoRefresh(10);
            Add(Ui.Btn("Check a file…", (s, e) => Pick()),
                Ui.Btn("Check again", (s, e) => { var r = Selected(); if (r != null && File.Exists(r.Path)) Check(r.Path); }),
                Ui.Btn("Show in folder", (s, e) => { var r = Selected(); if (r != null && File.Exists(r.Path)) Proc.ShowInExplorer(r.Path); }),
                Ui.Btn("Move to Recycle Bin", (s, e) => Delete()),
                Ui.Btn("Reputation keys…", (s, e) => { using (var d = new KeysDialog()) d.ShowDialog(this); }));
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(130)));
            Body.Controls.Add(layout);
            list.SelectedIndexChanged += (s, e) => ShowDetail();
            list.DoubleClick += (s, e) => { var r = Selected(); if (r != null && File.Exists(r.Path)) Proc.ShowInExplorer(r.Path); };
            layout.Controls.Add(list, 0, 0);
            detail.Multiline = true;
            detail.ReadOnly = true;
            detail.ScrollBars = ScrollBars.Vertical;
            detail.Dock = DockStyle.Fill;
            detail.Margin = new Padding(0, Ui.S(6), 0, 0);
            layout.Controls.Add(detail, 0, 1);
            AllowDrop = true;
            DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            DragDrop += (s, e) => { var files = e.Data.GetData(DataFormats.FileDrop) as string[]; if (files != null && files.Length > 0 && File.Exists(files[0])) Check(files[0]); };
        }

        protected override void RefreshView()
        {
            var st = StatusStore.Read(AppId.Janus);
            bool watching = st != null && st.State == States.Ok && DateTime.UtcNow - st.UpdatedUtc < TimeSpan.FromMinutes(10);
            SetState(watching ? States.Ok : States.Warn, watching ? "Watching " + Suite.User.Downloads : "Not watching right now (Olympus starts the watcher; you can still check files here)");
            StatusBar.Text = (st != null ? st.Detail + " · " : "") + "drop a file on this window to check it";
            var fresh = History.Read(400);
            if (extra != null) fresh.Insert(0, extra);
            rows = fresh;
            var items = new List<ListViewItem>();
            for (int i = 0; i < rows.Count; i++)
            {
                var r = rows[i];
                string from = r.From;
                Uri u;
                if (from != null && Uri.TryCreate(from, UriKind.Absolute, out u)) from = u.Host;
                var it = Ui.Row(i.ToString(), Fmt.Local(Clock.Parse(r.Time)), r.Name, Words.Verdict(r.Verdict), r.Kind ?? "", r.Signer ?? (r.Kind == "program" ? "unsigned" : ""), from ?? "");
                if (r.Verdict == "danger") it.ForeColor = Ui.StateColor(States.Alert);
                else if (r.Verdict == "caution") it.ForeColor = Ui.StateColor(States.Warn);
                if (!File.Exists(r.Path)) it.ForeColor = Ui.Muted;
                items.Add(it);
            }
            Ui.Fill(list, items);
            ShowDetail();
        }

        FileReport Selected()
        {
            if (list.SelectedItems.Count == 0) return null;
            int i;
            return int.TryParse(list.SelectedItems[0].Tag as string, out i) && i < rows.Count ? rows[i] : null;
        }

        void ShowDetail()
        {
            var r = Selected();
            if (r == null) { detail.Text = rows.Count == 0 ? "" : "Pick a download to see the details."; return; }
            var lines = new List<string> { r.Name + "  —  " + Words.Verdict(r.Verdict) + "  (" + r.Kind + ", " + Fmt.Size(r.Size) + ")" + (File.Exists(r.Path) ? "" : "   [no longer in Downloads]") };
            foreach (var f in r.Findings.OrderByDescending(f => f.Level == "bad" ? 3 : f.Level == "warn" ? 2 : f.Level == "good" ? 1 : 0))
                lines.Add((f.Level == "bad" ? "✖ " : f.Level == "warn" ? "⚠ " : f.Level == "good" ? "✔ " : "• ") + f.Text);
            if (r.Reputation != null) lines.Add("Reputation: " + r.Reputation);
            lines.Add("SHA-256: " + r.Sha256);
            detail.Text = string.Join("\r\n", lines);
        }

        void Pick()
        {
            using (var d = new OpenFileDialog { Title = "Check which file?", InitialDirectory = Suite.User.Downloads })
                if (d.ShowDialog(this) == DialogResult.OK) Check(d.FileName);
        }

        void Check(string path)
        {
            StatusBar.Text = "Checking " + Path.GetFileName(path) + "…";
            Ui.Background(this, () => Inspect.Analyze(path, true), (r, err) =>
            {
                if (err != null) { Ui.Warn(this, "Couldn't check it: " + err.Message); return; }
                extra = r;
                RefreshNow();
                if (list.Items.Count > 0) { list.Items[0].Selected = true; list.Items[0].EnsureVisible(); }
            });
        }

        void Delete()
        {
            var r = Selected();
            if (r == null) return;
            if (!Ui.Confirm(this, "Move " + r.Name + " to the Recycle Bin?")) return;
            try
            {
                UseWaitCursor = true;
                string error = Program.Recycle(r.Path, r.Sha256);
                if (error != null) Ui.Warn(this, error);
            }
            catch (Exception e) { Ui.Warn(this, e.Message); }
            finally { UseWaitCursor = false; RefreshNow(); }
        }
    }

    // Optional free API keys for looking a file's fingerprint up (only the SHA-256 is sent).
    sealed class KeysDialog : Form
    {
        readonly TextBox vt = new TextBox(), mb = new TextBox();

        public KeysDialog()
        {
            Text = "Janus — reputation lookups";
            Font = Ui.Base;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(Ui.S(560), Ui.S(270));
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(Ui.S(12)) };
            Controls.Add(t);
            var intro = Ui.Lbl("With a free key, Janus also looks up each risky download's fingerprint (SHA-256, never the file itself). Keys are stored encrypted with your Windows account.");
            intro.MaximumSize = new Size(Ui.S(530), 0);
            t.Controls.Add(intro);
            t.Controls.Add(Ui.Lbl("VirusTotal API key (free account at virustotal.com):", false, Ui.Bold));
            vt.Width = Ui.S(520);
            t.Controls.Add(vt);
            t.Controls.Add(Ui.Lbl("MalwareBazaar Auth-Key (free account at auth.abuse.ch):", false, Ui.Bold));
            mb.Width = Ui.S(520);
            t.Controls.Add(mb);
            var buttons = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, Ui.S(10), 0, 0) };
            var save = Ui.Btn("Save", (s, e) =>
            {
                Inspect.SaveKeys(new Dictionary<string, string> { { "virustotal", vt.Text.Trim() }, { "malwarebazaar", mb.Text.Trim() } });
                DialogResult = DialogResult.OK;
            });
            buttons.Controls.Add(save);
            buttons.Controls.Add(Ui.Btn("Cancel", (s, e) => DialogResult = DialogResult.Cancel));
            t.Controls.Add(buttons);
            AcceptButton = save;
            var keys = Inspect.LoadKeys();
            string v;
            if (keys.TryGetValue("virustotal", out v)) vt.Text = v;
            if (keys.TryGetValue("malwarebazaar", out v)) mb.Text = v;
        }
    }
}
