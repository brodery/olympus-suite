// Ares's window: game mode on/off, what's using memory (and growing), recent game sessions,
// and the settings.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace Olympus.Ares
{
    sealed class AresWindow : AppWindow
    {
        readonly TabControl tabs = new TabControl();
        readonly ListView memory = Ui.Empty(Ui.List("Program|260*", "Memory|90>", "Growing|120>", "Handles|80>", "PID|70>"), "Reading memory use…");
        readonly ListView sessions = Ui.Empty(Ui.List("Started|150", "Game|360", "Played for|100>", "Game mode did|360"), "No games played yet. Sessions show up here once a game runs.");
        readonly TextBox settings = new TextBox();
        readonly Label commit = new Label();

        public AresWindow() : base(AppInfo.Of(AppId.Ares), 980, 640)
        {
            AutoRefresh(10);
            Add(Ui.Btn("Game mode on/off", (s, e) => { Program.Toggle(); StatusBar.Text = "Switched; Ares applies it within a few seconds."; }),
                Ui.Btn("End selected program", (s, e) => EndSelected()),
                Ui.Btn("Edit settings", (s, e) => Proc.Open(AresSettings.FilePath)));
            var mem = new TableLayoutPanel { ColumnCount = 1, RowCount = 2 };
            mem.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mem.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            commit.AutoSize = true;
            commit.Font = Ui.Bold;
            commit.Margin = new Padding(Ui.S(2), Ui.S(2), 0, Ui.S(6));
            mem.Controls.Add(commit, 0, 0);
            mem.Controls.Add(memory, 0, 1);
            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Ui.Tab("Memory", mem));
            tabs.TabPages.Add(Ui.Tab("Game sessions", sessions));
            settings.Multiline = true;
            settings.ReadOnly = true;
            settings.ScrollBars = ScrollBars.Both;
            settings.Font = Ui.Mono;
            settings.WordWrap = false;
            tabs.TabPages.Add(Ui.Tab("Settings", settings));
            Body.Controls.Add(tabs);
        }

        protected override void RefreshView()
        {
            var g = GameState.Read();
            var st = StatusStore.Read(AppId.Ares);
            bool watching = st != null && DateTime.UtcNow - st.UpdatedUtc < TimeSpan.FromMinutes(5) && st.State != States.Off;
            if (g != null && g.Playing) SetState(States.Busy, "Game mode on: " + g.Game + " (since " + Fmt.Local(Clock.Parse(g.Since)) + ")");
            else SetState(watching ? States.Ok : States.Warn, watching ? "Ready — game mode switches on by itself when a game starts" : "Not watching right now (Olympus starts Ares in the background)");

            long used, limit;
            LeakWatch.Commit(out used, out limit);
            commit.Text = limit > 0 ? "Memory committed: " + (used / 1024.0).ToString("0.0") + " of " + (limit / 1024.0).ToString("0.0") + " GB (" + (used * 100 / limit) + "%)" : "";
            var report = J.Load<MemReport>(LeakWatch.ReportFile);
            var rows = new List<ListViewItem>();
            if (report != null)
                foreach (var r in report.Top)
                {
                    var it = Ui.Row(r.Pid + ":" + r.Name, r.Name, (r.Mb / 1024.0).ToString("0.00") + " GB", Growth(r.MbPerHour), r.Handles.ToString("N0"), r.Pid.ToString());
                    if (r.MbPerHour > 512) it.ForeColor = Ui.StateColor(States.Warn);
                    rows.Add(it);
                }
            Ui.Fill(memory, rows);
            StatusBar.Text = report == null ? "Memory figures appear once Ares has been watching for a minute." : "Updated " + Fmt.Ago(Clock.Parse(report.Updated)) + " · growth shows after about 20 minutes of watching";
            Ui.Fill(sessions, Program.Sessions(200).Select(x => Ui.Row(null, Fmt.Local(Clock.Parse(x.Start)), x.Game, Fmt.Duration(TimeSpan.FromMinutes(x.Minutes)),
                x.Did != null && x.Did.Count > 0 ? string.Join(", ", x.Did) : "nothing needed")).ToList());
            try { Ui.Show(settings, File.Exists(AresSettings.FilePath) ? File.ReadAllText(AresSettings.FilePath) : AresSettings.Defaults); } catch (Exception) { }
        }

        // How fast a program's memory grows: MB/hour below a GB, nothing while it's flat.
        static string Growth(double mbPerHour)
        {
            if (mbPerHour < 1) return "";
            return mbPerHour >= 1024 ? "+" + (mbPerHour / 1024).ToString("0.0") + " GB/hour" : "+" + mbPerHour.ToString("0") + " MB/hour";
        }

        void EndSelected()
        {
            if (memory.SelectedItems.Count == 0) return;
            var parts = ((string)memory.SelectedItems[0].Tag).Split(new[] { ':' }, 2);
            int pid = int.Parse(parts[0]);
            if (!Ui.Confirm(this, "End " + parts[1] + " (PID " + pid + ")? Anything unsaved in it is lost.")) return;
            try
            {
                using (var p = Process.GetProcessById(pid)) if (p.ProcessName == parts[1]) p.Kill();
            }
            catch (Exception e) { Ui.Warn(this, "Couldn't end it: " + e.Message + (Elevation.IsElevated ? "" : " (it may belong to Windows or another account)")); }
            RefreshNow();
        }
    }
}
