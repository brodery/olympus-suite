// Every app the hub looks after: the suite's own (Aegis and the nine Olympus apps), plus other
// programs registered in apps.ini (the built-in list below, and your own entries in the hub's
// apps.ini). For each one: how it's doing, whether it's switched on (stays on after a restart),
// and what Enable/Disable and Start/Stop do for it.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace Olympus.Hub
{
    // How an app runs, which decides what switching it on/off and starting/stopping it means.
    enum AppKind
    {
        Watcher,    // Janus, Ares, Atlas: run in your session and the hub keeps them going
        OnDemand,   // Sibyl: opens when asked; switched off = the hub lets go of its hotkey
        Periodic,   // Argus, Ark, Athena: a SYSTEM scheduled task that runs on a timer
        Engine,     // Cerberus, Arachne: a SYSTEM scheduled task that keeps running
        Aegis,      // the DNS filter: switched off = filtering paused until it's switched back on
        Startup,    // a registered program that starts at sign-in from your Run key
        Launcher,   // a registered script or tool that runs once when you click Run
    }

    sealed class AppEntry
    {
        public string Name, Role = "", Blurb = "";
        public AppKind Kind;
        public AppInfo Info;          // the suite's own apps; null for registered ones
        public string Exe;            // the program (Startup), or what Command runs (Launcher)
        public string StartArgs = "", StopArgs, RunName, RunCommand, LogPath, StatusPath, IconPath, Command, Folder, Confirm;
        public string Service;        // a Windows service it needs (a driver, say): not running = a warning while the app runs
        public bool BuiltIn;          // from the hub's own list rather than your apps.ini
        public Color Top = Color.FromArgb(0x78, 0x90, 0x9C), Bottom = Color.FromArgb(0x45, 0x5A, 0x64);

        public bool IsSuite { get { return Info != null; } }
        public string Key { get { return Name.ToLowerInvariant(); } }
        public bool CanSwitch { get { return Kind != AppKind.Launcher; } }
        public bool NeedsAdmin { get { return Kind == AppKind.Periodic || Kind == AppKind.Engine; } }
        public bool HasStop { get { return Kind == AppKind.Watcher || Kind == AppKind.Engine || Kind == AppKind.Aegis || Kind == AppKind.Startup; } }

        public string KindWord
        {
            get
            {
                switch (Kind)
                {
                    case AppKind.Watcher: return "background app";
                    case AppKind.OnDemand: return "on demand";
                    case AppKind.Periodic: return "scheduled (SYSTEM)";
                    case AppKind.Engine: return "engine (SYSTEM)";
                    case AppKind.Aegis: return "DNS filter";
                    case AppKind.Startup: return "starts at sign-in";
                    default: return "launcher";
                }
            }
        }

        // What switched on means for this app, for buttons and messages.
        public string OnMeaning
        {
            get
            {
                switch (Kind)
                {
                    case AppKind.Watcher: return "the hub keeps it running";
                    case AppKind.OnDemand: return "its hotkey works";
                    case AppKind.Periodic: case AppKind.Engine: return "its scheduled task runs";
                    case AppKind.Aegis: return "it filters";
                    case AppKind.Startup: return "it starts when you sign in";
                    default: return "";
                }
            }
        }

        public static AppKind KindOf(AppId id)
        {
            switch (id)
            {
                case AppId.Aegis: return AppKind.Aegis;
                case AppId.Janus: case AppId.Ares: case AppId.Atlas: return AppKind.Watcher;
                case AppId.Sibyl: return AppKind.OnDemand;
                case AppId.Cerberus: case AppId.Arachne: return AppKind.Engine;
                default: return AppKind.Periodic;   // Argus, Ark, Athena
            }
        }
    }

    static class AppRegistry
    {
        // Programs built for this PC outside the suite. Your own apps.ini adds to this list, and an
        // entry there with the same name replaces one here ("remove = true" hides it). Entries whose
        // program isn't on this PC are left out.
        public const string BuiltInList =
            "[Orpheus]\r\n" +
            "role = Spotify volume roller\r\n" +
            "about = Makes the keyboard's volume roller turn Spotify up and down.\r\n" +
            "exe = C:\\Claude\\orpheus\\Orpheus.exe\r\n" +
            "icon = C:\\Claude\\orpheus\\orpheus.ico\r\n" +
            "stop = --exit\r\n" +
            "log = C:\\Claude\\orpheus\\orpheus.log\r\n" +
            "color = 1ED760, 117A37\r\n" +
            "\r\n" +
            "[Iris]\r\n" +
            "role = Xbox stream fill\r\n" +
            "about = Stretches Xbox remote play across the ultrawide.\r\n" +
            "exe = C:\\Claude\\iris\\Iris.exe\r\n" +
            "icon = C:\\Claude\\iris\\iris.ico\r\n" +
            "stop = --exit\r\n" +
            "log = C:\\Claude\\iris\\iris.log\r\n" +
            "color = 7E57C2, 4527A0\r\n" +
            "\r\n" +
            "[Proteus]\r\n" +
            "role = mouse and keyboard as a controller\r\n" +
            "about = Turns mouse and keyboard into an Xbox controller for remote play.\r\n" +
            "exe = C:\\Claude\\proteus\\Proteus.exe\r\n" +
            "icon = C:\\Claude\\proteus\\proteus.ico\r\n" +
            "stop = --exit\r\n" +
            "log = C:\\Claude\\proteus\\proteus.log\r\n" +
            "service = ViGEmBus\r\n" +
            "color = 26A69A, 00695C\r\n" +
            "\r\n" +
            "[iFunny download]\r\n" +
            "type = launcher\r\n" +
            "role = saves iFunny posts\r\n" +
            "about = Saves the iFunny link you copied to Downloads\\iFunny, without the watermark.\r\n" +
            "command = powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"C:\\Claude\\ifunny-dl\\ifunny-dl.ps1\" -Gui\r\n" +
            "\r\n" +
            "[Desktop layout]\r\n" +
            "type = launcher\r\n" +
            "role = lines up desktop icons\r\n" +
            "about = Games on the left of the main screen, everything else on the right. Backs up the layout first.\r\n" +
            "command = powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File \"C:\\Claude\\desktop-layout\\Arrange-Desktop.ps1\"\r\n" +
            "confirm = Rearrange the desktop icons now? The current layout is saved first, so it can be put back.\r\n" +
            "\r\n" +
            "[Sonar backup]\r\n" +
            "type = launcher\r\n" +
            "role = saves Sonar profiles\r\n" +
            "about = Backs up your SteelSeries Sonar audio profiles.\r\n" +
            "command = cmd.exe /c \"C:\\Claude\\sonar-backup\\backup-sonar.cmd\"\r\n" +
            "\r\n" +
            "[Rock Band ultrawide fix]\r\n" +
            "type = launcher\r\n" +
            "role = 21:9 for Rock Band Simulator\r\n" +
            "about = Re-applies the ultrawide patch after a game update.\r\n" +
            "command = powershell.exe -NoProfile -File \"C:\\Claude\\rbs-trainer\\ultrawide-patch.ps1\" -Pause\r\n" +
            "icon = C:\\Program Files (x86)\\Steam\\steamapps\\common\\Rock Band Simulator\\Rock Band Simulator.exe\r\n" +
            "\r\n" +
            "[Rock Band money]\r\n" +
            "type = launcher\r\n" +
            "role = adds $350 in game\r\n" +
            "about = Adds $350 in Rock Band Simulator while it runs (achievements stay on).\r\n" +
            "command = powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File \"C:\\Claude\\rbs-trainer\\add-money.ps1\" -Amount 350\r\n" +
            "confirm = Add $350 in Rock Band Simulator? The game needs to be running.\r\n" +
            "icon = C:\\Program Files (x86)\\Steam\\steamapps\\common\\Rock Band Simulator\\Rock Band Simulator.exe\r\n";

        public const string UserTemplate =
            "; Your own apps for Olympus to list, watch and switch on and off. One [section] per app;\r\n" +
            "; the section name is the app's name. Olympus re-reads this file as you save it.\r\n" +
            ";\r\n" +
            "; An app that starts when you sign in (Run key) and stays open:\r\n" +
            ";   [Name]\r\n" +
            ";   exe = C:\\path\\to\\App.exe          the program (required)\r\n" +
            ";   role = what it does, in a few words\r\n" +
            ";   about = one sentence for its tile\r\n" +
            ";   args = arguments it starts with (optional)\r\n" +
            ";   stop = --exit                        arguments that ask it to close, or \"kill\"\r\n" +
            ";   run_name = Name                      its value in the Run key (default: the section name)\r\n" +
            ";   run_command = \"C:\\path\\to\\App.exe\"  what Enable writes there (default: the exe and args)\r\n" +
            ";   log = C:\\path\\to\\app.log            its last line shows as the app's details (optional)\r\n" +
            ";   status = C:\\path\\to\\status.json     an Olympus-style status file it writes (optional)\r\n" +
            ";   service = Name                       a Windows service it needs; flagged while it isn't running (optional)\r\n" +
            ";   icon = C:\\path\\to\\app.ico           (optional; default: the exe's icon)\r\n" +
            ";   color = RRGGBB, RRGGBB               tile colours (optional)\r\n" +
            ";\r\n" +
            "; A script or tool that runs once, with a Run button:\r\n" +
            ";   [Name]\r\n" +
            ";   type = launcher\r\n" +
            ";   command = powershell.exe -NoProfile -File \"C:\\path\\to\\script.ps1\"\r\n" +
            ";   confirm = Question to ask before it runs (optional)\r\n" +
            ";\r\n" +
            "; Olympus has a few entries of its own (Orpheus, Iris, Proteus and some launchers). A section here with\r\n" +
            "; the same name replaces one of those, and \"remove = true\" hides it.\r\n";

        public static string UserFile { get { return Path.Combine(Suite.UserDir(AppId.Olympus), "apps.ini"); } }

        // The suite's own apps first (dashboard order), then the registered ones as listed.
        public static List<AppEntry> All()
        {
            var list = AppInfo.Guardians.Select(FromSuite).ToList();
            list.AddRange(Registered(Ini.Parse(BuiltInList), Ini.LoadOrCreate(UserFile, UserTemplate), true));
            return list;
        }

        public static AppEntry Find(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            return All().FirstOrDefault(e => e.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        public static AppEntry FromSuite(AppInfo app)
        {
            return new AppEntry
            {
                Name = app.Name, Role = app.Role, Blurb = app.Blurb, Kind = AppEntry.KindOf(app.Id), Info = app,
                Top = app.Top, Bottom = app.Bottom, BuiltIn = true
            };
        }

        // The built-in list with your entries applied. onlyPresent leaves out built-in entries whose
        // program isn't on this PC (your own always show, as "not found" if need be).
        public static List<AppEntry> Registered(Ini builtIn, Ini user, bool onlyPresent)
        {
            var res = new List<AppEntry>();
            Action<AppEntry> put = e =>
            {
                int i = res.FindIndex(x => x.Name.Equals(e.Name, StringComparison.OrdinalIgnoreCase));
                if (i >= 0) res[i] = e; else res.Add(e);
            };
            foreach (var sec in builtIn.Sections.Where(s => s.Length > 0))
            {
                var e = Parse(builtIn, sec, true);
                if (e != null && (!onlyPresent || Present(e))) put(e);
            }
            foreach (var sec in user.Sections.Where(s => s.Length > 0))
            {
                if (user.Bool(sec, "remove", false)) { res.RemoveAll(x => x.Name.Equals(sec, StringComparison.OrdinalIgnoreCase)); continue; }
                var e = Parse(user, sec, false);
                if (e != null) put(e);
            }
            // a name the suite already uses can't be taken
            res.RemoveAll(e => AppInfo.Find(e.Name) != null);
            return res;
        }

        public static AppEntry Parse(Ini ini, string sec, bool builtIn)
        {
            string name = sec.Trim();
            if (name.Length == 0 || name.IndexOfAny(new[] { '"', '\\', '/', '\r', '\n' }) >= 0) return null;
            string type = ini.Get(sec, "type", "app").Trim().ToLowerInvariant();
            var e = new AppEntry
            {
                Name = name, BuiltIn = builtIn,
                Role = ini.Get(sec, "role", ""), Blurb = ini.Get(sec, "about", ""),
                IconPath = PathOrNull(ini.Get(sec, "icon", null)),
                LogPath = PathOrNull(ini.Get(sec, "log", null)),
                StatusPath = PathOrNull(ini.Get(sec, "status", null)),
                Service = NullIfEmpty(ini.Get(sec, "service", null)),
                Confirm = NullIfEmpty(ini.Get(sec, "confirm", null))
            };
            Color top, bottom;
            if (Colors(ini.Get(sec, "color", null), out top, out bottom)) { e.Top = top; e.Bottom = bottom; }
            if (type == "launcher")
            {
                e.Kind = AppKind.Launcher;
                e.Command = NullIfEmpty(ini.Get(sec, "command", null));
                if (e.Command == null) return null;
                string args;
                e.Exe = SplitCommand(FileUtil.Expand(e.Command), out args);
                e.StartArgs = args;
                e.Folder = PathOrNull(ini.Get(sec, "folder", null)) ?? ScriptFolder(e.Command) ?? SafeDir(e.Exe);
                return e;
            }
            if (type != "app") return null;
            e.Kind = AppKind.Startup;
            e.Exe = PathOrNull(ini.Get(sec, "exe", null));
            if (e.Exe == null) return null;
            e.StartArgs = ini.Get(sec, "args", "");
            e.StopArgs = NullIfEmpty(ini.Get(sec, "stop", null));
            e.RunName = NullIfEmpty(ini.Get(sec, "run_name", null)) ?? name;
            e.RunCommand = NullIfEmpty(ini.Get(sec, "run_command", null)) ?? ("\"" + e.Exe + "\"" + (e.StartArgs.Length > 0 ? " " + e.StartArgs : ""));
            e.Folder = SafeDir(e.Exe);
            return e;
        }

        // Is the program behind an entry on this PC? A launcher's command counts when its program
        // or the script it names exists.
        public static bool Present(AppEntry e)
        {
            if (e.Kind == AppKind.Launcher)
            {
                string script = ScriptOf(e.Command);
                if (script != null) return File.Exists(script);
                return e.Exe != null && (File.Exists(e.Exe) || !Path.IsPathRooted(e.Exe));
            }
            return e.Exe != null && File.Exists(e.Exe);
        }

        // The first quoted path ending in a script extension, for "powershell -File "x.ps1"".
        public static string ScriptOf(string command)
        {
            if (command == null) return null;
            var m = System.Text.RegularExpressions.Regex.Match(command, "\"([^\"]+\\.(ps1|cmd|bat|py|vbs|js))\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? FileUtil.Expand(m.Groups[1].Value) : null;
        }
        static string ScriptFolder(string command) { var s = ScriptOf(command); return s == null ? null : SafeDir(s); }

        // "C:\a b\x.exe" -args  /  x.exe -args  ->  the program and the rest.
        public static string SplitCommand(string command, out string args)
        {
            command = (command ?? "").Trim();
            args = "";
            if (command.Length == 0) return null;
            if (command[0] == '"')
            {
                int end = command.IndexOf('"', 1);
                if (end < 0) return command.Trim('"');
                args = command.Substring(end + 1).Trim();
                return command.Substring(1, end - 1);
            }
            int sp = command.IndexOf(' ');
            if (sp < 0) return command;
            args = command.Substring(sp + 1).Trim();
            return command.Substring(0, sp);
        }

        static string SafeDir(string path)
        {
            try { return path != null && Path.IsPathRooted(path) ? Path.GetDirectoryName(path) : null; } catch (Exception) { return null; }
        }
        static string NullIfEmpty(string s) { return string.IsNullOrWhiteSpace(s) ? null : s.Trim(); }
        static string PathOrNull(string s)
        {
            s = NullIfEmpty(s);
            return s == null ? null : FileUtil.Expand(s.Trim('"'));
        }

        public static bool Colors(string spec, out Color top, out Color bottom)
        {
            top = bottom = Color.Empty;
            if (string.IsNullOrWhiteSpace(spec)) return false;
            var parts = spec.Split(',', ';').Select(p => p.Trim().TrimStart('#')).ToArray();
            int a, b;
            if (parts.Length < 1 || !int.TryParse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out a)) return false;
            if (parts.Length < 2 || !int.TryParse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b)) b = a;
            top = Color.FromArgb(255, (a >> 16) & 255, (a >> 8) & 255, a & 255);
            bottom = Color.FromArgb(255, (b >> 16) & 255, (b >> 8) & 255, b & 255);
            return true;
        }

        // An app's picture: the suite's own are drawn; registered ones use their icon file or exe icon.
        public static Bitmap Picture(AppEntry e, int size)
        {
            if (e.IsSuite) return IconArt.Draw(e.Info.Id, size);
            foreach (var src in new[] { e.IconPath, e.Kind == AppKind.Launcher ? null : e.Exe })
            {
                if (src == null || !File.Exists(src)) continue;
                try
                {
                    if (src.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
                        using (var ic = new Icon(src, new Size(size, size))) return Scaled(ic.ToBitmap(), size);
                    using (var ic = Icon.ExtractAssociatedIcon(src)) if (ic != null) return Scaled(ic.ToBitmap(), size);
                }
                catch (Exception) { }
            }
            if (e.Kind == AppKind.Launcher)
            {
                try
                {
                    string script = ScriptOf(e.Command);
                    if (script != null && File.Exists(script))
                        using (var ic = Icon.ExtractAssociatedIcon(script)) if (ic != null) return Scaled(ic.ToBitmap(), size);
                }
                catch (Exception) { }
            }
            return IconArt.Draw(AppId.Olympus, size);
        }

        static Bitmap Scaled(Bitmap b, int size)
        {
            if (b.Width == size && b.Height == size) return b;
            var r = new Bitmap(size, size);
            using (var g = Graphics.FromImage(r))
            {
                g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
                g.DrawImage(b, 0, 0, size, size);
            }
            b.Dispose();
            return r;
        }
    }

    // A program's entry in your Run key, and Windows' own on/off switch for it (the one Task
    // Manager's Startup apps page uses: StartupApproved\Run, first byte odd = switched off).
    // Switching off keeps the Run value, so the program's own "start with Windows" setting and
    // Argus's record both stay; Argus notes a switched-off entry as routine.
    static class StartupEntry
    {
        public const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public const string ApprovedPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

        // null: no Run value; otherwise whether Windows starts it at sign-in.
        public static bool? State(RegistryKey root, string runPath, string approvedPath, string name)
        {
            using (var run = root.OpenSubKey(runPath))
            {
                if (run == null || run.GetValue(name) == null) return null;
            }
            using (var ap = root.OpenSubKey(approvedPath))
            {
                return ApprovedOn(ap == null ? null : ap.GetValue(name) as byte[]);
            }
        }

        public static bool ApprovedOn(byte[] v) { return v == null || v.Length == 0 || (v[0] & 1) == 0; }

        // Switches the program on (writing its Run value if there's none) or off (if it has one).
        public static void Set(RegistryKey root, string runPath, string approvedPath, string name, string command, bool on)
        {
            using (var run = root.CreateSubKey(runPath))
            {
                bool has = run.GetValue(name) != null;
                if (on && !has) run.SetValue(name, command, RegistryValueKind.String);
                if (!on && !has) return;
            }
            using (var ap = root.CreateSubKey(approvedPath))
            {
                var now = ap.GetValue(name) as byte[];
                if (on)
                {
                    if (!ApprovedOn(now)) ap.SetValue(name, new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);
                }
                else if (ApprovedOn(now))
                {
                    var v = new byte[12];
                    v[0] = 3;
                    BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(v, 4);
                    ap.SetValue(name, v, RegistryValueKind.Binary);
                }
            }
        }

        public static bool? State(string name) { return State(Registry.CurrentUser, RunPath, ApprovedPath, name); }
        public static void Set(string name, string command, bool on) { Set(Registry.CurrentUser, RunPath, ApprovedPath, name, command, on); }
    }

    // The suite's SYSTEM scheduled tasks (\Olympus\<App>). Your account can read Argus's, Ark's and
    // Athena's (install.cmd lets it start them); Cerberus's and Arachne's only admins can read, so
    // the elevated helper records what it last set in ProgramData\Olympus\olympus\tasks.json.
    static class TaskControl
    {
        public static readonly string[] Names = { "Argus", "Ark", "Athena", "Cerberus", "Arachne" };
        public static string RecordFile { get { return Path.Combine(Suite.SharedDir(AppId.Olympus), "tasks.json"); } }

        public sealed class Record
        {
            public string Updated;
            public Dictionary<string, bool> Enabled = new Dictionary<string, bool>();
        }

        public static bool IsTaskApp(string name) { return Names.Contains(name ?? "", StringComparer.OrdinalIgnoreCase); }

        // Whether the task is switched on: from Task Scheduler where your account may read it,
        // else from the helper's record; null when neither says.
        public static bool? Enabled(string name)
        {
            int state;
            bool? on = Query(name, out state);
            if (on.HasValue) return on;
            var r = J.Load<Record>(RecordFile);
            bool v;
            return r != null && r.Enabled != null && r.Enabled.TryGetValue(name, out v) ? (bool?)v : null;
        }

        // Task Scheduler's own view (state: 1 disabled, 2 queued, 3 ready, 4 running); null if unreadable.
        public static bool? Query(string name, out int state)
        {
            state = 0;
            object svc = null, folder = null, task = null;
            try
            {
                var t = Type.GetTypeFromProgID("Schedule.Service");
                if (t == null) return null;
                svc = Activator.CreateInstance(t);
                Call(svc, "Connect");
                folder = Call(svc, "GetFolder", @"\Olympus");
                task = Call(folder, "GetTask", name);
                state = Convert.ToInt32(Prop(task, "State"), CultureInfo.InvariantCulture);
                return Convert.ToBoolean(Prop(task, "Enabled"), CultureInfo.InvariantCulture);
            }
            catch (Exception) { return null; }
            finally
            {
                foreach (var o in new[] { task, folder, svc }) if (o != null && Marshal.IsComObject(o)) Marshal.ReleaseComObject(o);
            }
        }

        // Starts the task now from your account (works where install.cmd allowed it).
        public static bool RunAsUser(string name)
        {
            string o;
            return Proc.Run("schtasks.exe", "/run /tn \"\\Olympus\\" + name + "\"", out o, 20000) == 0;
        }

        static object Call(object o, string m, params object[] a) { return o.GetType().InvokeMember(m, BindingFlags.InvokeMethod, null, o, a); }
        static object Prop(object o, string p) { return o.GetType().InvokeMember(p, BindingFlags.GetProperty, null, o, null); }

        // Olympus.exe --task enable|disable|start|stop <App>, run elevated (one UAC prompt) from the
        // installed copy. Only the suite's own five tasks, nothing else.
        public static int Elevated(string action, string name)
        {
            action = (action ?? "").ToLowerInvariant();
            if (!IsTaskApp(name) || (action != "enable" && action != "disable" && action != "start" && action != "stop"))
            {
                Cli.Out("Usage: Olympus.exe --task enable|disable|start|stop " + string.Join("|", Names));
                return 2;
            }
            name = Names.First(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (!Elevation.IsElevated) { Cli.Out("This needs administrator rights."); return 2; }
            if (!Suite.Installed || !Suite.BinDir.Equals(Suite.InstallDir, StringComparison.OrdinalIgnoreCase))
            {
                Cli.Out("Only the installed Olympus (" + Suite.InstallDir + ") changes its tasks.");
                return 2;
            }
            string tn = "\"\\Olympus\\" + name + "\"", o;
            int code = 0;
            switch (action)
            {
                case "enable": code = Proc.Run("schtasks.exe", "/change /tn " + tn + " /enable", out o, 30000); break;
                case "disable":
                    code = Proc.Run("schtasks.exe", "/change /tn " + tn + " /disable", out o, 30000);
                    if (code == 0) { string o2; Proc.Run("schtasks.exe", "/end /tn " + tn, out o2, 30000); }
                    break;
                case "start": code = Proc.Run("schtasks.exe", "/run /tn " + tn, out o, 30000); break;
                default: code = Proc.Run("schtasks.exe", "/end /tn " + tn, out o, 30000); break;
            }
            if (code != 0) { Log.Warn("task " + action + " " + name + " failed (" + code + "): " + o.Trim()); Cli.Out(o.Trim()); }
            else Log.Info("task " + action + " " + name);
            SaveRecord();
            return code == 0 ? 0 : 1;
        }

        static void SaveRecord()
        {
            try
            {
                var r = new Record { Updated = Clock.NowIso() };
                foreach (var n in Names)
                {
                    int st;
                    var on = Query(n, out st);
                    if (on.HasValue) r.Enabled[n] = on.Value;
                }
                Directory.CreateDirectory(Path.GetDirectoryName(RecordFile));
                J.Save(RecordFile, r);
            }
            catch (Exception e) { Log.Error("saving tasks.json", e); }
        }
    }

    // Watchers you stopped by hand: the hub leaves them stopped until you start them again or it
    // restarts (sign-in). Shared by the hub and the command line.
    static class Held
    {
        static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Olympus), "held.txt"); } }

        public static HashSet<string> Read()
        {
            try
            {
                if (!File.Exists(FilePath)) return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                return new HashSet<string>(File.ReadAllLines(FilePath).Select(l => l.Trim()).Where(l => l.Length > 0), StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception) { return new HashSet<string>(StringComparer.OrdinalIgnoreCase); }
        }

        public static void Set(string name, bool held)
        {
            using (var m = new Mutex(false, "Local\\Olympus.held"))
            {
                bool got = false;
                try { got = m.WaitOne(3000); } catch (AbandonedMutexException) { got = true; }
                try
                {
                    var now = Read();
                    if (held ? now.Add(name) : now.Remove(name)) FileUtil.WriteAtomic(FilePath, string.Join("\r\n", now) + "\r\n");
                }
                finally { if (got) m.ReleaseMutex(); }
            }
        }

        public static void Clear() { FileUtil.TryDelete(FilePath); }
    }

    // Enable/Disable, Start/Stop and Run for every kind of app. Each returns null when it worked,
    // or a sentence saying what went wrong. They may block (an admin prompt, waiting for a program
    // to close), so the window calls them off its UI thread.
    static class AppControl
    {
        public const string ChangedSignal = "hub.apps";

        public static string Switch(AppEntry e, bool on)
        {
            try
            {
                switch (e.Kind)
                {
                    case AppKind.Watcher:
                    case AppKind.OnDemand:
                        HubSettings.SetOff(e.Name, !on);
                        if (e.Kind == AppKind.Watcher)
                        {
                            Held.Set(e.Name, false);
                            if (on) StartWatcher(e); else Sync.Poke(e.Key + ".stop");
                        }
                        Sync.Poke(ChangedSignal);
                        return null;
                    case AppKind.Periodic:
                    case AppKind.Engine:
                        return Admin(on ? "enable" : "disable", e.Name);
                    case AppKind.Aegis:
                    {
                        string exe = AegisClient.Exe;
                        if (exe == null) return "Aegis isn't installed (it has no entry in your Run key).";
                        string o;
                        int code = Proc.Run(exe, on ? "resume" : "pause forever", out o, 20000);
                        if (code != 0) return "Aegis couldn't do that" + (o.Trim().Length > 0 ? ": " + o.Trim() : " (code " + code + ")") +
                            (on ? "" : "\n\nIf it says the number is wrong, this Aegis is older than the hub: update Aegis first.");
                        return null;
                    }
                    case AppKind.Startup:
                        if (!File.Exists(e.Exe)) return "Couldn't find " + e.Exe + ".";
                        StartupEntry.Set(e.RunName, e.RunCommand, on);
                        Log.Info((on ? "switched on " : "switched off ") + e.Name + " at sign-in (Run value " + e.RunName + ")");
                        return null;
                    default:
                        return e.Name + " runs only when you click Run.";
                }
            }
            catch (Exception x) { return x.Message; }
        }

        public static string Start(AppEntry e)
        {
            try
            {
                switch (e.Kind)
                {
                    case AppKind.Watcher:
                        Held.Set(e.Name, false);
                        Sync.Poke(ChangedSignal);
                        return StartWatcher(e);
                    case AppKind.OnDemand:
                        Launch.Open(e.Info.Id, null);
                        return null;
                    case AppKind.Periodic:
                    {
                        int st;
                        if (TaskControl.Query(e.Name, out st) == false) return e.Name + " is switched off. Enable it first.";
                        // the same requests the hub's own buttons make
                        if (e.Info.Id == AppId.Argus) StartProgram(Suite.ExeOf(AppId.Argus), "--scan-now");
                        else if (e.Info.Id == AppId.Ark) StartProgram(Suite.ExeOf(AppId.Ark), "--backup-now");
                        else { TaskControl.RunAsUser(e.Name); StartProgram(Suite.ExeOf(AppId.Athena), "--report --quiet"); }
                        return null;
                    }
                    case AppKind.Engine:
                        return Admin("start", e.Name);
                    case AppKind.Aegis:
                    {
                        string exe = AegisClient.Exe;
                        if (exe == null) return "Aegis isn't installed (it has no entry in your Run key).";
                        if (!Proc.Running(exe)) StartProgram(exe, "--tray");
                        return null;
                    }
                    case AppKind.Startup:
                        if (!File.Exists(e.Exe)) return "Couldn't find " + e.Exe + ".";
                        if (!Proc.Running(e.Exe)) StartProgram(e.Exe, e.StartArgs);
                        return null;
                    default:
                        return Run(e);
                }
            }
            catch (Exception x) { return x.Message; }
        }

        public static string Stop(AppEntry e)
        {
            try
            {
                switch (e.Kind)
                {
                    case AppKind.Watcher:
                        Held.Set(e.Name, true);
                        Sync.Poke(ChangedSignal);
                        Sync.Poke(e.Key + ".stop");
                        return WaitGone(Suite.ExeOf(e.Info.Id), 8000) ? null : e.Name + " didn't close yet; it was asked to.";
                    case AppKind.Engine:
                        return Admin("stop", e.Name);
                    case AppKind.Aegis:
                    {
                        string exe = AegisClient.Exe;
                        if (exe == null) return "Aegis isn't installed.";
                        string o;
                        Proc.Run(exe, "--exit", out o, 10000);
                        return WaitGone(exe, 5000) ? null : "Aegis's tray icon didn't close.";
                    }
                    case AppKind.Startup:
                    {
                        if (!Proc.Running(e.Exe)) return null;
                        if (e.StopArgs != null && !e.StopArgs.Equals("kill", StringComparison.OrdinalIgnoreCase))
                        {
                            string o;
                            Proc.Run(e.Exe, e.StopArgs, out o, 15000);
                            if (WaitGone(e.Exe, 8000)) return null;
                            return e.Name + " didn't close when asked (" + e.StopArgs + ").";
                        }
                        foreach (var p in Matching(e.Exe))
                            using (p)
                            {
                                if (e.StopArgs == null) p.CloseMainWindow();
                                else { try { p.Kill(); } catch (Exception) { } }
                            }
                        return WaitGone(e.Exe, 6000) ? null : e.Name + " didn't close. Add \"stop = kill\" (or the arguments that close it) to its apps.ini entry.";
                    }
                    default:
                        return e.Name + " can't be stopped from Olympus.";
                }
            }
            catch (Exception x) { return x.Message; }
        }

        public static string Run(AppEntry e)
        {
            if (e.Kind != AppKind.Launcher) return Start(e);
            if (!AppRegistry.Present(e)) return "Couldn't find what " + e.Name + " runs: " + e.Command;
            var psi = new ProcessStartInfo(e.Exe, e.StartArgs ?? "") { UseShellExecute = true };
            if (e.Folder != null && Directory.Exists(e.Folder)) psi.WorkingDirectory = e.Folder;
            try { using (Process.Start(psi)) { } }
            catch (Exception x) { return x.Message; }
            Log.Info("ran " + e.Name);
            return null;
        }

        // An admin prompt for the installed Olympus to change one of its own scheduled tasks.
        static string Admin(string action, string name)
        {
            if (!Suite.Installed) return "Install Olympus first: its SYSTEM tasks only exist once it's installed.";
            string exe = Path.Combine(Suite.InstallDir, "Olympus.exe");
            if (!File.Exists(exe)) return "Couldn't find " + exe + ".";
            int r = Elevation.Run(exe, "--task " + action + " " + name, true);
            if (r == -1) return "Cancelled: Windows asked for admin rights and the request was declined.";
            if (r != 0) return "Couldn't " + action + " " + name + "'s scheduled task (code " + r + "). See Olympus's log for details.";
            return null;
        }

        static string StartWatcher(AppEntry e)
        {
            string exe = Suite.ExeOf(e.Info.Id);
            if (!File.Exists(exe)) return "Couldn't find " + exe + ".";
            if (!Proc.Running(exe)) StartProgram(exe, "--watch");
            return null;
        }

        static void StartProgram(string exe, string args)
        {
            // ShellExecute, so the program inherits no handles: started from "Olympus.exe start X | Out-String" it would
            // otherwise hold the caller's output pipe open for as long as it runs.
            var psi = new ProcessStartInfo(exe, args ?? "") { UseShellExecute = true };
            string dir = Path.GetDirectoryName(exe);
            if (Directory.Exists(dir)) psi.WorkingDirectory = dir;
            using (Process.Start(psi)) { }
        }

        static IEnumerable<Process> Matching(string exe)
        {
            foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exe)))
            {
                string pp = Native.ProcessPath(p.Id);
                if (pp != null && pp.Equals(exe, StringComparison.OrdinalIgnoreCase)) yield return p;
                else p.Dispose();
            }
        }

        static bool WaitGone(string exe, int ms)
        {
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (Proc.Running(exe))
            {
                if (DateTime.UtcNow > until) return false;
                Thread.Sleep(200);
            }
            return true;
        }
    }

    // The last line of an app's log, for its details ("2026-11-25 17:42:31  Waiting for ..." ->
    // "Waiting for ... (17:42)").
    static class LogTail
    {
        public static string Last(string path)
        {
            try
            {
                if (path == null || !File.Exists(path)) return null;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    long start = Math.Max(0, fs.Length - 4096);
                    fs.Seek(start, SeekOrigin.Begin);
                    var buf = new byte[fs.Length - start];
                    int n = fs.Read(buf, 0, buf.Length);
                    var lines = System.Text.Encoding.UTF8.GetString(buf, 0, n).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
                    return lines.Count == 0 ? null : Tidy(lines[lines.Count - 1]);
                }
            }
            catch (Exception) { return null; }
        }

        public static string Tidy(string line)
        {
            var m = System.Text.RegularExpressions.Regex.Match(line, @"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(:\d{2}(\.\d+)?)?\s+(.*)$");
            if (!m.Success) return line;
            string when = m.Groups[1].Value == DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ? m.Groups[2].Value : m.Groups[1].Value + " " + m.Groups[2].Value;
            return m.Groups[5].Value.Trim() + " (" + when + ")";
        }
    }
}
