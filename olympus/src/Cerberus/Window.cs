// Cerberus's window: sampled public TCP connections, likely destinations, the lookups Aegis blocked
// for it, what's connected right now, and Block / Unblock.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Cerberus
{
    sealed class CerberusWindow : AppWindow
    {
        readonly TabControl tabs = new TabControl();
        readonly ListView apps = Ui.Empty(Ui.List("Program|190", "Signed by|185", "TCP seen|75>", "Last seen|100", "Likely destinations|305*", "Aegis blocked|110>"), "No programs seen online yet today.");
        readonly ListView live = Ui.Empty(Ui.List("Program|200", "Likely hostname|330*", "Address|240", "Port|60>"), "No public TCP connections in the last sample.");
        readonly ListView lookups = Ui.Empty(Ui.List("Program|200", "Blocked name|420*", "Times|80>"), "Nothing blocked by Aegis today.");
        readonly TextBox detail = new TextBox();
        HashSet<string> blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, AppNet> data = new Dictionary<string, AppNet>();

        public CerberusWindow() : base(AppInfo.Of(AppId.Cerberus), 1060, 680)
        {
            AutoRefresh(10);
            Add(Ui.Btn("Keep offline (block)", (s, e) => Act("block")),
                Ui.Btn("Allow online again", (s, e) => Act("unblock")),
                Ui.Btn("Show in folder", (s, e) => { var p = SelectedPath(); if (p != null && File.Exists(p)) Proc.ShowInExplorer(p); }));
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, Ui.S(100)));
            Body.Controls.Add(layout);
            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Ui.Tab("Programs", apps));
            tabs.TabPages.Add(Ui.Tab("Recent TCP sample", live));
            tabs.TabPages.Add(Ui.Tab("Blocked by Aegis", lookups));
            layout.Controls.Add(tabs, 0, 0);
            detail.Multiline = true;
            detail.ReadOnly = true;
            detail.ScrollBars = ScrollBars.Vertical;
            detail.Dock = DockStyle.Fill;
            detail.Margin = new Padding(0, Ui.S(6), 0, 0);
            layout.Controls.Add(detail, 0, 1);
            apps.SelectedIndexChanged += (s, e) => ShowDetail();
        }

        protected override void RefreshView()
        {
            var st = StatusStore.Read(AppId.Cerberus);
            bool running = st != null && DateTime.UtcNow - st.UpdatedUtc < TimeSpan.FromMinutes(5);
            if (running) SetState(States.Ok, st.Summary);
            else SetState(States.Warn, Suite.Installed ? "The engine isn't running (its scheduled task restarts it within 5 minutes)" : "Not running yet: install Olympus to start the engine (it runs as SYSTEM)");
            StatusBar.Text = st != null ? st.Detail : "";
            data = Program.Apps();
            try { blocked = Firewall.BlockedApps(); } catch (Exception) { }
            var rows = new List<ListViewItem>();
            foreach (var a in data.Values.OrderByDescending(x => x.LastSeen, StringComparer.Ordinal))
            {
                var it = Ui.Row(a.Path, a.Name + (blocked.Contains(a.Path) ? "  (blocked)" : ""), a.Signer ?? (File.Exists(a.Path) ? "unsigned" : ""), a.Connections.ToString("N0"),
                    Fmt.Ago(Clock.Parse(a.LastSeen)), string.Join(", ", a.Sites.OrderByDescending(s => s.Value).Take(4).Select(s => s.Key)), a.Blocked.Count == 0 ? "" : a.Blocked.Values.Sum().ToString("N0"));
                if (blocked.Contains(a.Path)) it.ForeColor = Ui.StateColor(States.Alert);
                rows.Add(it);
            }
            Ui.Fill(apps, rows);
            var now = Program.Live();
            Ui.Fill(live, now.OrderBy(c => c.App).Select(c => Ui.Row(c.Path, c.App, c.Site ?? "", c.Remote, c.Port.ToString())).ToList());
            var bl = new List<ListViewItem>();
            foreach (var a in data.Values)
                foreach (var kv in a.Blocked.OrderByDescending(x => x.Value))
                    bl.Add(Ui.Row(a.Path, a.Name, kv.Key, kv.Value.ToString("N0")));
            Ui.Fill(lookups, bl.OrderByDescending(r => int.Parse(r.SubItems[2].Text.Replace(",", ""))).ToList());
            tabs.TabPages[0].Text = "Programs (" + data.Count + ")";
            tabs.TabPages[1].Text = "Recent TCP sample (" + now.Count + ")";
            tabs.TabPages[2].Text = "Blocked by Aegis (" + bl.Count + ")";
            ShowDetail();
        }

        string SelectedPath()
        {
            var lv = tabs.SelectedIndex == 0 ? apps : tabs.SelectedIndex == 1 ? live : lookups;
            return lv.SelectedItems.Count == 0 ? null : lv.SelectedItems[0].Tag as string;
        }

        void ShowDetail()
        {
            const string coverage = "Cerberus samples public TCP connections every two seconds. Short sessions can be missed, and UDP is outside this view. Hostnames are estimated from DNS lookups.";
            string p = SelectedPath();
            AppNet a;
            if (p == null || !data.TryGetValue(p, out a)) { detail.Text = coverage; return; }
            detail.Text = a.Name + (blocked.Contains(a.Path) ? "  —  BLOCKED from the internet" : "") + "\r\n" + a.Path + "\r\nFirst observed " + Fmt.Local(Clock.Parse(a.FirstSeen)) + ", last " + Fmt.Ago(Clock.Parse(a.LastSeen)) + ", " + a.Connections.ToString("N0") + " TCP connections observed\r\nLikely destinations  " + string.Join(", ", a.Sites.OrderByDescending(s => s.Value).Select(s => s.Key + " (" + s.Value + ")"))
                        + (a.Blocked.Count > 0 ? "\r\nAegis blocked  " + string.Join(", ", a.Blocked.OrderByDescending(s => s.Value).Select(s => s.Key + " (" + s.Value + ")")) : "")
                        + "\r\n" + coverage;
        }

        void Act(string action)
        {
            string p = SelectedPath();
            if (p == null || !File.Exists(p)) { Ui.Info(this, "Pick a program first."); return; }
            if (action == "block" && !Ui.Confirm(this, "Keep " + Path.GetFileName(p) + " off the internet?\n\nCerberus adds a Windows Firewall rule (it asks for admin rights). Use \"Allow online again\" to undo it.")) return;
            StatusBar.Text = "Asking Windows for admin rights…";
            Ui.Background(this, () => Program.DoAction(action, null, p), (code, err) =>
            {
                StatusBar.Text = code == 0 ? (action == "block" ? "Blocked " : "Unblocked ") + Path.GetFileName(p) : "That didn't work (or was cancelled).";
                RefreshNow();
            });
        }
    }
}
