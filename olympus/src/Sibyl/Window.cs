// Sibyl's window: paste a link or a message, see the verdict, the reasons, the path a link takes,
// and (optionally) what the local AI thinks.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Sibyl
{
    sealed class SibylWindow : AppWindow
    {
        readonly TextBox input = new TextBox();
        readonly Panel banner = new Panel();
        readonly Label verdict = new Label(), sub = new Label();
        readonly TabControl tabs = new TabControl();
        readonly ListView findings = Ui.Empty(Ui.List("Level|80", "What Sibyl noticed|820"), "Paste a link or a message above and press Check.");
        readonly ListView path = Ui.Empty(Ui.List("Step|50", "Site|240", "What happened|330*", "Aegis|200"), "Where a link really leads shows up here, step by step.");
        readonly TextBox ai = new TextBox();
        readonly Button check, aiButton, copyFinal, open;
        Result last;
        bool busy;

        public SibylWindow() : base(AppInfo.Of(AppId.Sibyl), 980, 680)
        {
            check = Ui.Btn("Check", (s, e) => RunCheck());
            aiButton = Ui.Btn("Ask the local AI (slower)", (s, e) => AskAi());
            copyFinal = Ui.Btn("Copy where it really goes", (s, e) => { if (last != null && last.Link != null && last.Link.Final != null) { Clipboard.SetText(last.Link.Final); StatusBar.Text = "Copied: " + last.Link.Final; } });
            open = Ui.Btn("Open in browser…", (s, e) => OpenLink());
            Add(Ui.Btn("Paste and check", (s, e) => { try { input.Text = Clipboard.GetText(); } catch (Exception) { } RunCheck(); }), check, aiButton, copyFinal, open,
                Ui.Btn("Clear", (s, e) => { input.Clear(); Show(null); input.Focus(); }));
            AcceptButton = null;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(110)));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Body.Controls.Add(layout);

            input.Multiline = true;
            input.ScrollBars = ScrollBars.Vertical;
            input.Dock = DockStyle.Fill;
            input.Font = new Font(Ui.Base.FontFamily, Ui.Base.Size * 1.1f);
            input.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter && e.Control) { e.SuppressKeyPress = true; RunCheck(); } };
            layout.Controls.Add(input, 0, 0);

            banner.Dock = DockStyle.Fill;
            banner.Height = Ui.S(64);
            banner.Margin = new Padding(0, Ui.S(8), 0, Ui.S(8));
            banner.Padding = new Padding(Ui.S(12), Ui.S(8), Ui.S(12), Ui.S(8));
            verdict.Font = Ui.Huge;
            verdict.AutoSize = true;
            verdict.ForeColor = Color.White;
            verdict.Location = new Point(Ui.S(12), Ui.S(6));
            sub.AutoSize = true;
            sub.ForeColor = Color.White;
            sub.Location = new Point(Ui.S(14), Ui.S(38));
            banner.Controls.Add(verdict);
            banner.Controls.Add(sub);
            layout.Controls.Add(banner, 0, 1);

            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Ui.Tab("What Sibyl noticed", findings));
            tabs.TabPages.Add(Ui.Tab("Where the link goes", path));
            ai.Multiline = true;
            ai.ReadOnly = true;
            ai.ScrollBars = ScrollBars.Vertical;
            ai.Font = Ui.Base;
            Ui.Show(ai, "Click \"Ask the local AI\" for a second opinion from the model in LM Studio. It runs on this PC, so the message never leaves it.");
            tabs.TabPages.Add(Ui.Tab("Local AI", ai));
            layout.Controls.Add(tabs, 0, 2);
            Show(null);
        }

        protected override void RefreshView()
        {
            if (last == null && !busy) SetState(States.Ok, "Ready — paste a link or message, or press Ctrl+Alt+L anywhere to check what you copied");
        }

        protected override void HandleRequest(string request)
        {
            if (!request.StartsWith("check:", StringComparison.Ordinal)) return;
            input.Text = request.Substring(6);
            RunCheck();
        }

        void RunCheck()
        {
            string text = input.Text.Trim();
            if (text.Length == 0 || busy) return;
            busy = true;
            SetState(States.Busy, Checker.IsLink(text) ? "Following the link (without opening it in a browser)…" : "Reading the message…");
            check.Enabled = false;
            Ui.Background(this, () => Checker.Run(text, true), (r, err) =>
            {
                busy = false;
                check.Enabled = true;
                if (err != null) { SetState(States.Error, "Couldn't finish: " + err.Message); return; }
                Show(r);
                string where = r.Link != null ? r.Link.Registrable : r.Inner.Count > 0 ? r.Inner[0].Registrable : null;
                StatusStore.Write(States.Ok, "Ready · Ctrl+Alt+L checks what you copied", "Last check " + DateTime.Now.ToString("h:mm tt") + ": " + Checker.Word(r.Verdict) + (where != null ? " (" + where + ")" : ""), null);
            });
        }

        void Show(Result r)
        {
            last = r;
            var rows = new List<ListViewItem>();
            var hops = new List<ListViewItem>();
            Color c;
            if (r == null)
            {
                c = Color.FromArgb(0x75, 0x75, 0x75);
                verdict.Text = "Paste something to check";
                sub.Text = "A link (even a short bit.ly one) or a whole message: eBay \"buyers\", delivery texts, DMs, emails.";
            }
            else
            {
                c = r.Verdict == "dangerous" ? Ui.StateColor(States.Alert) : r.Verdict == "suspicious" ? Color.FromArgb(0xC7, 0x7C, 0x02) : r.Verdict == "ok" ? Ui.StateColor(States.Ok) : Color.FromArgb(0x75, 0x75, 0x75);
                verdict.Text = r.Headline;
                var link = r.Link ?? r.Inner.FirstOrDefault();
                sub.Text = link == null ? (r.Message != null ? Fmt.Plural(r.Message.Flags.Count(f => f.Level != "good"), "warning sign") + " in the wording" : "")
                         : "Really goes to: " + (link.FinalHost ?? "?") + (link.Registered != DateTime.MinValue ? " · registered " + link.Registered.ToString("MMM yyyy") : "") + (link.CertIssuer != null ? " · certificate from " + link.CertIssuer : "");
                foreach (var f in r.Flags.OrderByDescending(f => f.Level == "bad" ? 3 : f.Level == "warn" ? 2 : f.Level == "info" ? 1 : 0))
                {
                    var it = Ui.Row(null, f.Level == "bad" ? "Danger" : f.Level == "warn" ? "Caution" : f.Level == "good" ? "Good" : "Note", f.Text);
                    it.ForeColor = f.Level == "bad" ? Ui.StateColor(States.Alert) : f.Level == "warn" ? Ui.StateColor(States.Warn) : f.Level == "good" ? Ui.StateColor(States.Ok) : SystemColors.ControlText;
                    rows.Add(it);
                }
                if (r.Message != null)
                {
                    foreach (var p in r.Message.Phones) rows.Add(Ui.Row(null, "Note", "Phone number in the message: " + p + " (look the company's number up yourself instead)"));
                    foreach (var em in r.Message.Emails) rows.Add(Ui.Row(null, "Note", "Email address in the message: " + em));
                }
                int n = 1;
                foreach (var lr in r.Link != null ? new List<LinkReport> { r.Link } : r.Inner)
                    foreach (var h in lr.Hops)
                    {
                        var it = Ui.Row(null, (n++).ToString(), h.Host, h.Note ?? "", h.Aegis ?? "");
                        if ((h.Aegis ?? "").StartsWith("blocked")) it.ForeColor = Ui.StateColor(States.Alert);
                        hops.Add(it);
                    }
                SetState(r.Verdict == "dangerous" ? States.Alert : r.Verdict == "suspicious" ? States.Warn : States.Ok, "Checked " + DateTime.Now.ToString("h:mm tt"));
            }
            banner.BackColor = c;
            Ui.Fill(findings, rows);
            Ui.Fill(path, hops);
            bool hasLink = r != null && (r.Link ?? r.Inner.FirstOrDefault()) != null;
            copyFinal.Enabled = r != null && r.Link != null;
            open.Enabled = hasLink;
            aiButton.Enabled = r != null || input.Text.Trim().Length > 0;
        }

        void AskAi()
        {
            string text = input.Text.Trim();
            if (text.Length == 0) return;
            tabs.SelectedIndex = 2;
            Ui.Show(ai, "Asking the local model… (if it isn't loaded yet, LM Studio loads it first, which can take a minute or two)");
            aiButton.Enabled = false;
            Ui.Background(this, () => { string e; string a = Scam.AskAi(text, out e); return a ?? ("Couldn't ask: " + e); }, (answer, err) =>
            {
                aiButton.Enabled = true;
                Ui.Show(ai, (err != null ? err.Message : answer).Replace("\r\n", "\n").Replace("\n", "\r\n"));
            });
        }

        void OpenLink()
        {
            if (last == null) return;
            var link = last.Link ?? last.Inner.FirstOrDefault();
            if (link == null || link.Final == null) return;
            if (last.Verdict != "ok" && !Ui.Confirm(this, "Sibyl thinks this is " + Checker.Word(last.Verdict) + ". Open it anyway?\n\nIf it asks for a password, a payment or a download, close it.")) return;
            Proc.Open(link.Final);
        }
    }
}
