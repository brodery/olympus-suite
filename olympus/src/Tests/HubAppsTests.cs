// The hub as an app manager: apps.ini entries, Windows' Startup-apps switch, the off list,
// the overall verdict with apps switched off, and the small text helpers.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using Olympus.Hub;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class HubAppsTests
    {
        public static void Run()
        {
            Registry();
            Startup();
            Settings();
            Verdict();
            Helpers();
        }

        static void Registry()
        {
            string dir = T.TempDir("apps");
            try
            {
                string exe = Path.Combine(dir, "Tool.exe");
                File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });
                string script = Path.Combine(dir, "go.ps1");
                File.WriteAllText(script, "'hi'");
                var builtIn = Ini.Parse(
                    "[Tool]\r\nrole = does things\r\nexe = " + exe + "\r\nstop = --exit\r\ncolor = 112233, 445566\r\n\r\n" +
                    "[Gone]\r\nexe = " + Path.Combine(dir, "nope.exe") + "\r\n\r\n" +
                    "[Go]\r\ntype = launcher\r\ncommand = powershell.exe -NoProfile -File \"" + script + "\" -X 1\r\nconfirm = Sure?\r\n\r\n" +
                    "[Argus]\r\nexe = " + exe + "\r\n\r\n" +
                    "[Odd]\r\ntype = service\r\nexe = " + exe + "\r\n");
                var none = Ini.Parse("");
                var all = AppRegistry.Registered(builtIn, none, false);
                T.Eq("Tool,Gone,Go", string.Join(",", all.Select(e => e.Name)), "apps: built-in entries in order; suite names and unknown types are left out");
                var present = AppRegistry.Registered(builtIn, none, true);
                T.Eq("Tool,Go", string.Join(",", present.Select(e => e.Name)), "apps: a built-in entry whose program is missing is hidden");

                var tool = all[0];
                T.Eq(AppKind.Startup, tool.Kind, "apps: plain entry starts at sign-in");
                T.Eq("Tool", tool.RunName, "apps: Run value named after the section");
                T.Eq("\"" + exe + "\"", tool.RunCommand, "apps: Run command defaults to the quoted exe");
                T.Eq("--exit", tool.StopArgs, "apps: stop arguments");
                T.Eq(0x11, (int)tool.Top.R, "apps: tile colour read");
                T.True(tool.CanSwitch && tool.HasStop && !tool.NeedsAdmin, "apps: a startup app can be switched and stopped without admin");

                var go = all[2];
                T.Eq(AppKind.Launcher, go.Kind, "apps: launcher type");
                T.Eq("powershell.exe", go.Exe, "apps: launcher program split off");
                T.Eq("-NoProfile -File \"" + script + "\" -X 1", go.StartArgs, "apps: launcher arguments kept as written");
                T.Eq(dir, go.Folder, "apps: launcher runs in its script's folder");
                T.Eq("Sure?", go.Confirm, "apps: confirm question");
                T.True(AppRegistry.Present(go), "apps: launcher present when its script exists");
                T.True(!go.CanSwitch && !go.HasStop, "apps: a launcher has only Run");

                var user = Ini.Parse("[tool]\r\nexe = " + exe + "\r\nargs = --quiet\r\nrole = mine\r\n\r\n[Go]\r\nremove = true\r\n\r\n[Extra]\r\nexe = " + Path.Combine(dir, "x.exe") + "\r\nrun_name = ExtraRun\r\nrun_command = \"x\" --tray\r\n");
                var merged = AppRegistry.Registered(builtIn, user, true);
                T.Eq("tool,Extra", string.Join(",", merged.Select(e => e.Name)), "apps: your entry replaces the built-in one, remove hides one, and yours show even when missing");
                T.Eq("mine", merged[0].Role, "apps: your entry's fields win");
                T.Eq("\"" + exe + "\" --quiet", merged[0].RunCommand, "apps: Run command includes the start arguments");
                T.True(!merged[0].BuiltIn && merged[1].RunName == "ExtraRun" && merged[1].RunCommand == "\"x\" --tray", "apps: run_name and run_command");
                T.True(!AppRegistry.Present(merged[1]), "apps: missing program isn't present");

                T.True(AppRegistry.Parse(Ini.Parse("[a\\b]\r\nexe = c:\\x.exe\r\n"), "a\\b", false) == null, "apps: a name with a backslash is refused");
                T.True(AppRegistry.Parse(Ini.Parse("[L]\r\ntype = launcher\r\n"), "L", false) == null, "apps: a launcher needs a command");
                T.True(AppRegistry.Parse(Ini.Parse("[A]\r\nrole = x\r\n"), "A", false) == null, "apps: an app needs an exe");

                // the hub's own list parses, and nothing in it takes a suite name
                var own = AppRegistry.Registered(Ini.Parse(AppRegistry.BuiltInList), none, false);
                T.True(own.Any(e => e.Name == "Orpheus" && e.Kind == AppKind.Startup && e.StopArgs == "--exit"), "apps: built-in Orpheus entry");
                T.True(own.Any(e => e.Name == "Iris" && e.RunCommand == "\"C:\\Claude\\iris\\Iris.exe\""), "apps: built-in Iris entry");
                T.True(own.Any(e => e.Name == "Proteus" && e.StopArgs == "--exit" && e.LogPath == "C:\\Claude\\proteus\\proteus.log"), "apps: built-in Proteus entry");
                T.Eq(5, own.Count(e => e.Kind == AppKind.Launcher), "apps: built-in launchers");
                T.True(own.All(e => AppInfo.Find(e.Name) == null), "apps: built-in names don't clash with the suite");
                T.True(Ini.Parse(AppRegistry.UserTemplate).Sections.All(s => s.Length == 0), "apps: the template is all comments");

                // the suite's own kinds
                T.Eq(AppKind.Engine, AppRegistry.FromSuite(AppInfo.Of(AppId.Cerberus)).Kind, "apps: Cerberus is an engine");
                T.Eq(AppKind.Periodic, AppRegistry.FromSuite(AppInfo.Of(AppId.Ark)).Kind, "apps: Ark runs on a timer");
                T.Eq(AppKind.Watcher, AppRegistry.FromSuite(AppInfo.Of(AppId.Atlas)).Kind, "apps: Atlas is a watcher");
                T.Eq(AppKind.OnDemand, AppRegistry.FromSuite(AppInfo.Of(AppId.Sibyl)).Kind, "apps: Sibyl is on demand");
                T.Eq(AppKind.Aegis, AppRegistry.FromSuite(AppInfo.Of(AppId.Aegis)).Kind, "apps: Aegis");
                T.True(AppRegistry.FromSuite(AppInfo.Of(AppId.Argus)).NeedsAdmin && !AppRegistry.FromSuite(AppInfo.Of(AppId.Janus)).NeedsAdmin, "apps: only the SYSTEM ones need admin");
                T.True(TaskControl.IsTaskApp("cerberus") && !TaskControl.IsTaskApp("Janus") && !TaskControl.IsTaskApp(null), "apps: the five task apps");
                T.Eq(2, TaskControl.Elevated("delete", "Argus"), "apps: the task helper refuses other actions");
                T.Eq(2, TaskControl.Elevated("disable", "Aegis DNS filter"), "apps: the task helper refuses other tasks");
            }
            finally { T.Cleanup(dir); }
        }

        static void Startup()
        {
            string key = @"Software\Olympus-tests\" + Guid.NewGuid().ToString("N");
            string run = key + @"\Run", approved = key + @"\Approved";
            var root = Microsoft.Win32.Registry.CurrentUser;
            try
            {
                T.True(StartupEntry.State(root, run, approved, "App") == null, "startup: no Run value");
                StartupEntry.Set(root, run, approved, "App", "\"C:\\a.exe\"", false);
                T.True(StartupEntry.State(root, run, approved, "App") == null, "startup: switching off nothing writes nothing");
                StartupEntry.Set(root, run, approved, "App", "\"C:\\a.exe\"", true);
                T.True(StartupEntry.State(root, run, approved, "App") == true, "startup: switched on writes the Run value");
                using (var k = root.OpenSubKey(approved)) T.True(k == null || k.GetValue("App") == null, "startup: no StartupApproved value needed when on");
                StartupEntry.Set(root, run, approved, "App", "\"C:\\other.exe\"", false);
                T.True(StartupEntry.State(root, run, approved, "App") == false, "startup: switched off");
                using (var k = root.OpenSubKey(run)) T.Eq("\"C:\\a.exe\"", k.GetValue("App") as string, "startup: switching off keeps the Run value as it was");
                using (var k = root.OpenSubKey(approved))
                {
                    var v = k.GetValue("App") as byte[];
                    T.True(v != null && v.Length == 12 && v[0] == 3 && BitConverter.ToInt64(v, 4) > 0, "startup: Windows' switched-off value with a time");
                }
                StartupEntry.Set(root, run, approved, "App", "\"C:\\other.exe\"", true);
                T.True(StartupEntry.State(root, run, approved, "App") == true, "startup: switched back on");
                using (var k = root.OpenSubKey(run)) T.Eq("\"C:\\a.exe\"", k.GetValue("App") as string, "startup: an existing Run value isn't rewritten");
                using (var k = root.OpenSubKey(approved)) T.Eq(2, (int)((byte[])k.GetValue("App"))[0], "startup: Windows' switched-on value");
                T.True(StartupEntry.ApprovedOn(null) && StartupEntry.ApprovedOn(new byte[] { 6, 0 }) && !StartupEntry.ApprovedOn(new byte[] { 7, 0 }), "startup: odd first byte means off");
            }
            finally { try { root.DeleteSubKeyTree(key, false); } catch (Exception) { } }
        }

        static void Settings()
        {
            string ini = "; settings\r\n[hub]\r\nhotkey = Ctrl+Alt+L\r\noff_apps =\r\ntoasts = true\r\n";
            string after = HubSettings.WithList(ini, "off_apps", new[] { "Janus", "Sibyl" });
            T.True(after.Contains("off_apps = Janus, Sibyl\r\n") && after.Contains("toasts = true"), "settings: off_apps replaced, line ending kept");
            T.Eq(2, Ini.Parse(after).List("hub", "off_apps").Count, "settings: off_apps reads back");
            string added = HubSettings.WithList("[hub]\r\nhotkey = Ctrl+Alt+L\r\n", "off_apps", new[] { "Atlas" });
            T.Eq("Atlas", Ini.Parse(added).Get("hub", "off_apps", null), "settings: off_apps added under [hub]");
            string twice = HubSettings.WithList(HubSettings.WithList(ini, "hidden_icons", new[] { "Ark" }), "off_apps", new[] { "Ares" });
            T.True(Ini.Parse(twice).Get("hub", "hidden_icons", null) == "Ark" && Ini.Parse(twice).Get("hub", "off_apps", null) == "Ares", "settings: two lists side by side");
            var s = new HubSettings { Off = new List<string> { "janus" } };
            T.True(s.IsOff("Janus") && !s.IsOff("Ares"), "settings: off check ignores case");
            T.True(Ini.Parse(HubSettings.Defaults).Has("hub") && Ini.Parse(HubSettings.Defaults).List("hub", "off_apps").Count == 0, "settings: defaults have an empty off list");
        }

        static AppState St(AppId id, string state, bool? enabled, bool held = false)
        {
            return new AppState { Entry = AppRegistry.FromSuite(AppInfo.Of(id)), App = AppInfo.Of(id), State = state, Present = true, Enabled = enabled, Held = held };
        }

        static void Verdict()
        {
            string text;
            var states = new List<AppState> { St(AppId.Argus, States.Ok, true), St(AppId.Cerberus, States.Off, false), St(AppId.Janus, States.Off, true, true), St(AppId.Sibyl, States.Off, true) };
            T.Eq(States.Ok, Overview.Overall(states, 0, out text), "verdict: switched-off, stopped and on-demand apps don't need a look");
            T.Eq("All quiet · 2 apps on · 2 off", text, "verdict: counts what's on and off");
            states.Add(St(AppId.Ares, States.Off, true));
            T.Eq(States.Warn, Overview.Overall(states, 0, out text), "verdict: an app that's on but not running needs a look");
            T.Eq("Ares needs a look", text, "verdict: names it");
            states.Add(St(AppId.Ark, States.Alert, true));
            T.Eq(States.Alert, Overview.Overall(states, 3, out text), "verdict: alert wins");
            T.Eq("Ark needs attention", text, "verdict: names the one in trouble");
            var allOff = new List<AppState> { St(AppId.Argus, States.Off, false), St(AppId.Atlas, States.Off, false) };
            T.Eq(States.Off, Overview.Overall(allOff, 0, out text), "verdict: everything off");
            T.Eq("Every app is switched off", text, "verdict: says so");
            var launcher = new AppState { Entry = new AppEntry { Name = "L", Kind = AppKind.Launcher }, State = States.Error, Present = false };
            T.Eq(States.Ok, Overview.Overall(new List<AppState> { St(AppId.Argus, States.Ok, true), launcher }, 0, out text), "verdict: launchers never count");
            T.Eq("—", launcher.OnWord, "verdict: a launcher has no on/off");

            var f = new Dictionary<string, string> { { "state", "paused" }, { "until", "253402300799" } };
            T.True(Overview.PausedForGood(f), "aegis: paused until turned back on");
            f["until"] = ((long)(DateTime.UtcNow.AddMinutes(10) - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
            T.True(!Overview.PausedForGood(f), "aegis: a 10-minute pause is still on");
            f["until"] = "999999999999999";
            T.True(Overview.PausedForGood(f), "aegis: a huge time doesn't overflow");
            T.True(!Overview.PausedForGood(new Dictionary<string, string> { { "state", "on" } }), "aegis: filtering");
        }

        static void Helpers()
        {
            string args;
            T.Eq("C:\\a b\\x.exe", AppRegistry.SplitCommand("\"C:\\a b\\x.exe\" -y \"z\"", out args), "split: quoted program");
            T.Eq("-y \"z\"", args, "split: rest");
            T.Eq("cmd.exe", AppRegistry.SplitCommand("cmd.exe /c x", out args), "split: bare program");
            T.Eq("x.exe", AppRegistry.SplitCommand("x.exe", out args), "split: program alone");
            T.Eq("", args, "split: no arguments");
            T.Eq("C:\\s\\b.cmd", AppRegistry.ScriptOf("cmd.exe /c \"C:\\s\\b.cmd\""), "script: found in a command");
            T.True(AppRegistry.ScriptOf("notepad.exe \"C:\\x.txt\"") == null, "script: a text file isn't a script");
            System.Drawing.Color top, bottom;
            T.True(AppRegistry.Colors("#1ED760", out top, out bottom) && top == bottom && top.G == 0xD7, "colors: one colour for both");
            T.True(!AppRegistry.Colors("green", out top, out bottom), "colors: names aren't read");
            T.Eq("Waiting for a stream (17:42)", LogTail.Tidy(DateTime.Now.ToString("yyyy-MM-dd") + " 17:42:31  Waiting for a stream"), "log: today's line shows the time");
            T.Eq("started (2026-11-23 18:31)", LogTail.Tidy("2026-11-23 18:31:52.650  started"), "log: another day shows the date");
            T.Eq("plain line", LogTail.Tidy("plain line"), "log: other lines as they are");
            string dir = T.TempDir("logtail");
            try
            {
                string log = Path.Combine(dir, "a.log");
                File.WriteAllText(log, new string('x', 6000) + "\r\nfirst\r\n2026-01-02 03:04:05  last one\r\n\r\n");
                T.Eq("last one (2026-01-02 03:04)", LogTail.Last(log), "log: last non-empty line of a long file");
                T.True(LogTail.Last(Path.Combine(dir, "none.log")) == null, "log: missing file");
            }
            finally { T.Cleanup(dir); }
        }
    }
}
