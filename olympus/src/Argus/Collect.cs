// Argus's collectors: every spot that starts programs automatically or changes how Windows and
// your browsers behave. Running as SYSTEM it sees everything (all users' registry hives, every
// scheduled task, WMI); running as you it sees what your account can read.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Olympus.Argus
{
    // One thing that starts automatically or changes how Windows or a browser behaves.
    public sealed class Item
    {
        public string Key, Category, Name, Location, Command, Target, Signer, User, Why, Hash, HashBasis;
        public string SignerId;   // SignerInfo.Id of a validly signed target
        public bool Signed, Trusted, Microsoft, Missing, Enabled = true;

        // For lists: who signed it, or why there's no answer.
        public string SignedBy
        {
            get { return Signer ?? (Target == null ? "" : Missing ? "(file missing)" : "unsigned"); }
        }
        public Dictionary<string, string> Extra = new Dictionary<string, string>();
        public string X(string k)
        {
            string v;
            return Extra != null && Extra.TryGetValue(k, out v) ? v : null;
        }

        public Item Copy()
        {
            var c = (Item)MemberwiseClone();
            c.Extra = Extra == null ? new Dictionary<string, string>() : new Dictionary<string, string>(Extra);
            return c;
        }
    }

    static class Reg
    {
        public static RegistryKey Hklm { get { return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); } }
        public static RegistryKey Users { get { return RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64); } }

        // "HKLM\..." or "HKU\<sid>\..."
        public static RegistryKey Open(string location, bool write)
        {
            int slash = location.IndexOf('\\');
            if (slash < 0) return null;
            string hive = location.Substring(0, slash), path = location.Substring(slash + 1);
            var root = hive == "HKLM" ? Hklm : hive == "HKU" ? Users : null;
            return root == null ? null : root.OpenSubKey(path, write);
        }
        public static RegistryKey Create(string location)
        {
            int slash = location.IndexOf('\\');
            string hive = location.Substring(0, slash), path = location.Substring(slash + 1);
            var root = hive == "HKLM" ? Hklm : Users;
            return root.CreateSubKey(path);
        }

        public static string Text(object v)
        {
            if (v == null) return null;
            var arr = v as string[];
            if (arr != null) return string.Join(" ", arr.Where(s => !string.IsNullOrEmpty(s)));
            var bytes = v as byte[];
            if (bytes != null) return "(binary, " + bytes.Length + " bytes)";
            return Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
        }

        public static string Encode(object v, RegistryValueKind kind)
        {
            switch (kind)
            {
                case RegistryValueKind.Binary: return Convert.ToBase64String((byte[])v);
                case RegistryValueKind.MultiString: return Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\0", (string[])v)));
                default: return Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
            }
        }
        public static object Decode(string data, RegistryValueKind kind)
        {
            switch (kind)
            {
                case RegistryValueKind.Binary: return Convert.FromBase64String(data);
                case RegistryValueKind.MultiString: return Encoding.UTF8.GetString(Convert.FromBase64String(data)).Split('\0');
                case RegistryValueKind.DWord: return int.Parse(data, System.Globalization.CultureInfo.InvariantCulture);
                case RegistryValueKind.QWord: return long.Parse(data, System.Globalization.CultureInfo.InvariantCulture);
                default: return data;
            }
        }
    }

    static class Com
    {
        public static object Call(object o, string name, params object[] args) { return o.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, o, args); }
        public static object Get(object o, string name) { return o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, null); }
        public static object Index(object o, int i) { return o.GetType().InvokeMember("Item", BindingFlags.GetProperty, null, o, new object[] { i }); }
        public static void Release(object o) { try { if (o != null && Marshal.IsComObject(o)) Marshal.ReleaseComObject(o); } catch (Exception) { } }
    }

    static class Shortcut
    {
        public static bool Read(string lnk, out string target, out string args)
        {
            target = args = null;
            object shell = null, sc = null;
            try
            {
                shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                sc = Com.Call(shell, "CreateShortcut", lnk);
                target = Com.Get(sc, "TargetPath") as string;
                args = Com.Get(sc, "Arguments") as string;
                return !string.IsNullOrEmpty(target);
            }
            catch (Exception) { return false; }
            finally { Com.Release(sc); Com.Release(shell); }
        }
    }

    sealed class Collector
    {
        readonly List<Item> items = new List<Item>();
        public readonly List<string> Problems = new List<string>();
        public readonly HashSet<string> Failed = new HashSet<string>();   // kinds that couldn't be read this time
        // Kinds read only partly (an entry failed and Argus can't tell which), and keys of single entries that
        // failed to read. Neither may be taken as gone this time.
        public readonly HashSet<string> Partial = new HashSet<string>();
        public readonly HashSet<string> Unreadable = new HashSet<string>();
        public static readonly string[] Kinds =
        {
            "run", "startup", "task", "service", "driver", "extension", "policy", "proxy", "hosts", "dns",
            "rootcert", "authroot", "wmi", "ifeo", "winlogon", "activesetup"
        };
        List<Hive> hives;

        sealed class Hive
        {
            public string Sid, Prefix, Profile;
            public RegistryKey Root;
        }

        public List<Item> All()
        {
            hives = Hives();
            Safe("startup entries", RunKeys, "run");
            Safe("startup folders", StartupFolders, "startup");
            Safe("scheduled tasks", Tasks, "task");
            Safe("services and drivers", Services, "service", "driver");
            Safe("browser extensions", Extensions, "extension");
            Safe("browser policies", Policies, "policy");
            Safe("proxy settings", Proxy, "proxy");
            Safe("hosts file", Hosts, "hosts");
            Safe("DNS settings", Dns, "dns");
            Safe("root certificates", RootCerts, "rootcert", "authroot");
            Safe("WMI subscriptions", Wmi, "wmi");
            Safe("program hijacks (IFEO)", Ifeo, "ifeo");
            Safe("sign-in hooks", Winlogon, "winlogon");
            Safe("Active Setup", ActiveSetup, "activesetup");
            return items;
        }

        // One kind of entry, read now (for checking an entry again right before Argus changes it). Errors aren't
        // caught: a kind that can't be read can't vouch for anything.
        public List<Item> Only(string kind)
        {
            hives = Hives();
            switch (kind)
            {
                case "run": RunKeys(); break;
                case "startup": StartupFolders(); break;
                case "task": Tasks(); break;
                case "service": case "driver": Services(); break;
                case "extension": Extensions(); break;
                case "policy": Policies(); break;
                case "proxy": Proxy(); break;
                case "hosts": Hosts(); break;
                case "dns": Dns(); break;
                case "rootcert": case "authroot": RootCerts(); break;
                case "wmi": Wmi(); break;
                case "ifeo": Ifeo(); break;
                case "winlogon": Winlogon(); break;
                case "activesetup": ActiveSetup(); break;
                default: throw new InvalidOperationException("Argus doesn't know entries of kind " + kind);
            }
            return items;
        }

        void Safe(string what, Action a, params string[] kinds)
        {
            int before = items.Count;
            try { a(); }
            catch (Exception e)
            {
                Problems.Add(what + ": " + e.Message);
                foreach (var k in kinds) Failed.Add(k);
                items.RemoveRange(before, items.Count - before);   // half a list would look like removals
                Log.Warn("couldn't read " + what + ": " + e.Message);
            }
        }

        Item Add(string category, string location, string name, string command, string user)
        {
            var it = new Item { Category = category, Location = location, Name = name, Command = command ?? "", User = user ?? "" };
            it.Key = category + "|" + location + "|" + name;
            items.Add(it);
            return it;
        }

        List<Hive> Hives()
        {
            var list = new List<Hive>();
            if (Elevation.IsElevated)
            {
                using (var users = Reg.Users)
                using (var plist = Reg.Hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    foreach (var sid in users.GetSubKeyNames())
                    {
                        if (!Regex.IsMatch(sid, @"^S-1-5-21-[\d-]+$")) continue;
                        var root = users.OpenSubKey(sid);
                        if (root == null) continue;
                        string profile = null;
                        using (var p = plist == null ? null : plist.OpenSubKey(sid)) if (p != null) profile = p.GetValue("ProfileImagePath") as string;
                        list.Add(new Hive { Sid = sid, Prefix = "HKU\\" + sid, Root = root, Profile = profile });
                    }
                }
            }
            if (list.Count == 0)
            {
                var me = Suite.User;
                list.Add(new Hive { Sid = me.Sid, Prefix = "HKU\\" + me.Sid, Root = Registry.CurrentUser, Profile = me.Profile });
            }
            return list;
        }

        // ------------------------------------------------------------------ startup entries

        static readonly string[] MachineRun =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        };
        static readonly string[] UserRun =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        };

        void RunKeys()
        {
            using (var hklm = Reg.Hklm)
                foreach (var p in MachineRun) Values(hklm, "HKLM", p, "run", "", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\" + (p.Contains("WOW6432Node") ? "Run32" : "Run"), hklm);
            foreach (var h in hives)
            {
                foreach (var p in UserRun) Values(h.Root, h.Prefix, p, "run", h.Sid, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", h.Root);
                using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Windows"))
                {
                    if (k == null) continue;
                    foreach (var v in new[] { "Load", "Run" })
                    {
                        // As written (REG_EXPAND_SZ unexpanded): expanding here would use SYSTEM's environment.
                        string s = Reg.Text(k.GetValue(v, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                        if (string.IsNullOrWhiteSpace(s)) continue;
                        var it = Add("run", h.Prefix + @"\Software\Microsoft\Windows NT\CurrentVersion\Windows", v, s, h.Sid);
                        it.Extra["value"] = v;
                        it.Extra["kind"] = KindOf(k, v);
                    }
                }
            }
        }

        void Values(RegistryKey root, string prefix, string path, string cat, string user, string approvedPath, RegistryKey approvedRoot)
        {
            using (var k = root.OpenSubKey(path))
            using (var approved = approvedPath == null ? null : approvedRoot.OpenSubKey(approvedPath))
            {
                if (k == null) return;
                foreach (var name in k.GetValueNames())
                {
                    string s = Reg.Text(k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                    if (string.IsNullOrWhiteSpace(s)) continue;
                    var it = Add(cat, prefix + "\\" + path, name.Length == 0 ? "(Default)" : name, s, user);
                    it.Extra["value"] = name;
                    it.Extra["kind"] = KindOf(k, name);
                    var flag = approved == null ? null : approved.GetValue(name) as byte[];
                    if (flag != null && flag.Length > 0 && (flag[0] & 1) == 1) it.Enabled = false;   // switched off in Task Manager
                }
            }
        }

        // The registry value's type (String, ExpandString, ...): Windows expands environment variables only in
        // an ExpandString, so the same text can mean another program.
        static string KindOf(RegistryKey k, string name)
        {
            try { return k.GetValueKind(name).ToString(); }
            catch (Exception) { return "?"; }
        }

        void StartupFolders()
        {
            Files(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "");
            foreach (var h in hives)
                if (h.Profile != null)
                    Files(Path.Combine(h.Profile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), h.Sid);
        }

        void Files(string dir, string user)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            foreach (var f in Directory.GetFiles(dir))
            {
                string name = Path.GetFileName(f);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                string cmd = f;
                if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    string target, args;
                    if (Shortcut.Read(f, out target, out args)) cmd = Proc.Quote(target) + (string.IsNullOrEmpty(args) ? "" : " " + args);
                }
                var it = Add("startup", dir, name, cmd, user);
                it.Extra["file"] = f;
            }
        }

        // ------------------------------------------------------------------ scheduled tasks

        void Tasks()
        {
            object svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
            try
            {
                Com.Call(svc, "Connect");
                object root = Com.Call(svc, "GetFolder", "\\");
                WalkTasks(root);
                Com.Release(root);
            }
            finally { Com.Release(svc); }
        }

        void WalkTasks(object folder)
        {
            object tasks = Com.Call(folder, "GetTasks", 1);   // include hidden tasks
            int n = (int)Com.Get(tasks, "Count");
            for (int i = 1; i <= n; i++)
            {
                object task = null;
                string path = null;
                try { task = Com.Index(tasks, i); path = Com.Get(task, "Path") as string; OneTask(task); }
                catch (Exception e)
                {
                    // Keep what's known about a task that failed to read, rather than calling it gone.
                    if (string.IsNullOrEmpty(path)) Partial.Add("task");
                    else Unreadable.Add("task|" + path.Substring(0, Math.Max(1, path.LastIndexOf('\\'))) + "|" + path);
                    if (Problems.Count < 50) Log.Warn("reading a task: " + e.Message);
                }
                finally { Com.Release(task); }
            }
            Com.Release(tasks);
            object folders = Com.Call(folder, "GetFolders", 0);
            int fn = (int)Com.Get(folders, "Count");
            for (int i = 1; i <= fn; i++)
            {
                object f = Com.Index(folders, i);
                try { WalkTasks(f); } finally { Com.Release(f); }
            }
            Com.Release(folders);
        }

        void OneTask(object task)
        {
            string path = Com.Get(task, "Path") as string;
            bool enabled = (bool)Com.Get(task, "Enabled");
            object def = Com.Get(task, "Definition");
            object actions = Com.Get(def, "Actions");
            int n = (int)Com.Get(actions, "Count");
            var cmds = new List<string>();
            var parts = new List<string>();   // every action in full, in order, for the entry hash
            string target = null, workdir = null, firstType = null;
            string packagedClass = null, actionData = null;
            bool hasCom = false, allCom = n > 0, inbox = false, unreadableData = false;
            for (int i = 1; i <= n; i++)
            {
                object a = Com.Index(actions, i);
                try
                {
                    int type = (int)Com.Get(a, "Type");
                    if (type != 5) allCom = false;
                    if (firstType == null) firstType = type == 0 ? "exec" : type == 5 ? "com" : "other";
                    if (type == 0)
                    {
                        // tasks often store the program path with its own quotes around it
                        string exe = ((Com.Get(a, "Path") as string) ?? "").Trim().Trim('"'), args = Com.Get(a, "Arguments") as string;
                        string wd = (Com.Get(a, "WorkingDirectory") as string) ?? "";
                        cmds.Add(Proc.Quote(exe) + (string.IsNullOrEmpty(args) ? "" : " " + args));
                        parts.Add(Field("exec") + Field(exe) + Field(args) + Field(wd));
                        if (target == null && exe.Length > 0) target = Targets.Resolve(Proc.Quote(exe) + (string.IsNullOrEmpty(args) ? "" : " " + args));
                        if (workdir == null) workdir = wd;
                    }
                    else if (type == 5)
                    {
                        hasCom = true;
                        string clsid = Com.Get(a, "ClassId") as string;
                        string dll = ComServer(clsid), server = null;
                        cmds.Add("COM handler " + clsid + (dll != null ? " (" + dll + ")" : ""));
                        if (target == null && dll != null) target = Targets.Resolve(dll);
                        if (dll == null)
                        {
                            bool fromInbox;
                            server = PackagedCom.Resolve(clsid, out fromInbox);
                            if (server != null)
                            {
                                packagedClass = clsid;
                                inbox = fromInbox;
                                if (target == null) target = server;
                            }
                        }
                        // Every COM action's data counts toward the entry (a digest, or that it couldn't be read).
                        string data = null;
                        bool dataUnreadable;
                        try
                        {
                            var value = Com.Get(a, "Data");
                            data = value as string;
                            dataUnreadable = value != null && data == null;
                        }
                        catch (Exception) { dataUnreadable = true; }
                        if (n == 1) { actionData = data; unreadableData = dataUnreadable; }
                        // The class, the server it's registered to (a classic DLL as written, or the packaged
                        // server), and its data.
                        parts.Add(Field("com") + Field(clsid) + Field(dll ?? "") + Field(server ?? "")
                            + Field(dataUnreadable ? "unreadable" : FileUtil.Sha256Text(data ?? "")));
                    }
                    else
                    {
                        cmds.Add("action type " + type);
                        parts.Add(Field("type") + Field(type.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                    }
                }
                finally { Com.Release(a); }
            }
            object reg = Com.Get(def, "RegistrationInfo");
            object principal = Com.Get(def, "Principal");
            string author = Com.Get(reg, "Author") as string;
            string runAs = Com.Get(principal, "UserId") as string;
            string group = Com.Get(principal, "GroupId") as string;
            int logon = (int)Com.Get(principal, "LogonType");
            int level = (int)Com.Get(principal, "RunLevel");
            bool safeData = !unreadableData && string.IsNullOrEmpty(actionData);
            bool trustedPackage = false;
            if (n == 1 && inbox && !unreadableData)
            {
                string sid = PackagedCom.PrincipalWithoutOverride(runAs, (int)Com.Get(principal, "LogonType"), packagedClass);
                trustedPackage = sid != null && (safeData || PackagedCom.IsRoutineSoftLanding(target, packagedClass, path, sid, actionData));
            }
            Com.Release(reg); Com.Release(principal); Com.Release(actions); Com.Release(def);
            string folder = path.Substring(0, Math.Max(1, path.LastIndexOf('\\')));
            var it = Add("task", folder, path, string.Join(" ; ", cmds), "");
            it.Enabled = enabled;
            it.Target = target;
            if (allCom && target == null) it.Extra["notarget"] = "yes";
            if (trustedPackage)
            {
                it.Extra["inboxCom"] = "yes";
                it.Extra["comDataHash"] = FileUtil.Sha256Text(actionData ?? "");
            }
            // The raw data of a single COM action, verified or not, so a notice about it can tell later
            // whether the data it was raised for is still the same.
            if (hasCom && n == 1 && !unreadableData) it.Extra["comRawHash"] = FileUtil.Sha256Text(actionData ?? "");
            if (hasCom && (n != 1 || (!trustedPackage && (!safeData || packagedClass != null))))
                it.Extra["comActionsUnverified"] = "yes";
            it.Extra["path"] = path;
            it.Extra["author"] = author ?? "";
            it.Extra["runas"] = runAs ?? "";
            it.Extra["highest"] = level == 1 ? "yes" : "no";
            it.Extra["actions"] = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (firstType != null) it.Extra["action"] = firstType;
            if (!string.IsNullOrEmpty(workdir)) it.Extra["workdir"] = workdir;
            it.Extra["logon"] = logon.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!string.IsNullOrEmpty(group)) it.Extra["group"] = group;
            // Every action (program, arguments and working folder; or COM class, server and a digest of its data),
            // who it runs as and how all count as part of the entry, so changing any of them is a change to
            // review. Each field carries its length, so no text inside one can pass for a boundary.
            // (Engine.Scan moves entries hashed the older way over silently.)
            it.HashBasis = Field(parts.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)) + string.Concat(parts)
                + Field(it.Extra["runas"]) + Field(it.Extra["highest"]) + Field(it.Extra["logon"]) + Field(group ?? "");
        }

        // A field for an entry hash: its length, a colon, then the text.
        internal static string Field(string s)
        {
            s = s ?? "";
            return s.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + s;
        }

        static string ComServer(string clsid)
        {
            if (string.IsNullOrEmpty(clsid)) return null;
            using (var hklm = Reg.Hklm)
            using (var k = hklm.OpenSubKey(@"SOFTWARE\Classes\CLSID\" + clsid + @"\InprocServer32"))
                return k == null ? null : k.GetValue("", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }

        // ------------------------------------------------------------------ services and drivers

        static string StartName(int s)
        {
            switch (s) { case 0: return "boot"; case 1: return "system"; case 2: return "automatic"; case 3: return "manual"; case 4: return "disabled"; default: return "?"; }
        }

        void Services()
        {
            using (var hklm = Reg.Hklm)
            using (var root = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                foreach (var name in root.GetSubKeyNames())
                {
                    RegistryKey opened;
                    try { opened = root.OpenSubKey(name); }
                    catch (Exception)
                    {
                        // A few services hide their key from non-admins; either way, not readable isn't gone.
                        Unreadable.Add(@"service|HKLM\SYSTEM\CurrentControlSet\Services|" + name);
                        Unreadable.Add(@"driver|HKLM\SYSTEM\CurrentControlSet\Services|" + name);
                        continue;
                    }
                    using (var k = opened)
                    {
                        if (k == null) continue;
                        object typeObj = k.GetValue("Type");
                        if (!(typeObj is int)) continue;
                        int type = (int)typeObj;
                        if ((type & 0x80) != 0) continue;   // per-user copy of a service; its template is listed
                        string image = k.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                        if (string.IsNullOrWhiteSpace(image)) continue;
                        int start = k.GetValue("Start") is int ? (int)k.GetValue("Start") : -1;
                        string dll = null;
                        try
                        {
                            using (var p = k.OpenSubKey("Parameters"))
                                if (p != null) dll = p.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                        }
                        catch (Exception) { }   // hidden from non-admins on a few services
                        bool driver = (type & 0x3) != 0;
                        var it = Add(driver ? "driver" : "service", @"HKLM\SYSTEM\CurrentControlSet\Services", name, image + (dll != null ? "  [" + dll + "]" : ""), "");
                        it.Extra["service"] = name;
                        it.Extra["start"] = StartName(start);
                        it.Extra["type"] = type.ToString(System.Globalization.CultureInfo.InvariantCulture);
                        string account = k.GetValue("ObjectName") as string;
                        if (!string.IsNullOrEmpty(account)) it.Extra["account"] = account;
                        string display = k.GetValue("DisplayName") as string;
                        if (!string.IsNullOrEmpty(display) && !display.StartsWith("@")) it.Extra["display"] = display;
                        it.Enabled = start != 4;
                        it.Target = Targets.Resolve(dll ?? image);
                    }
                }
            }
        }

        // ------------------------------------------------------------------ browser extensions

        void Extensions()
        {
            foreach (var h in hives)
            {
                if (h.Profile == null) continue;
                string local = Path.Combine(h.Profile, @"AppData\Local");
                Chromium(h, "Chrome", Path.Combine(local, @"Google\Chrome\User Data"));
                Chromium(h, "Edge", Path.Combine(local, @"Microsoft\Edge\User Data"));
                Chromium(h, "Brave", Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data"));
                Firefox(h, Path.Combine(h.Profile, @"AppData\Roaming\Mozilla\Firefox\Profiles"));
            }
        }

        static readonly Regex Broad = new Regex(@"^(<all_urls>|\*://\*/\*|https?://\*/\*|\*://\*\.?/\*|file:///\*)$", RegexOptions.CultureInvariant);

        static string Localize(string name, string verDir, string locale)
        {
            if (name == null || !name.StartsWith("__MSG_") || !name.EndsWith("__")) return name;
            string key = name.Substring(6, name.Length - 8);
            foreach (var loc in new[] { locale, "en", "en_US" })
            {
                if (string.IsNullOrEmpty(loc)) continue;
                var msgs = J.Obj(J.LoadRaw(Path.Combine(verDir, "_locales", loc, "messages.json")), null);
                if (msgs == null) continue;
                foreach (var kv in msgs)
                    if (kv.Key.Equals(key, StringComparison.OrdinalIgnoreCase)) return J.Str(kv.Value, "message") ?? name;
            }
            return name;
        }

        void Chromium(Hive h, string browser, string userData)
        {
            if (!Directory.Exists(userData)) return;
            foreach (var profileDir in Directory.GetDirectories(userData))
            {
                string extDir = Path.Combine(profileDir, "Extensions");
                if (!Directory.Exists(extDir)) continue;
                string profile = Path.GetFileName(profileDir);
                foreach (var idDir in Directory.GetDirectories(extDir))
                {
                    string id = Path.GetFileName(idDir);
                    if (id.Equals("Temp", StringComparison.OrdinalIgnoreCase)) continue;
                    string ver = Directory.GetDirectories(idDir).OrderByDescending(d => d, StringComparer.Ordinal).FirstOrDefault();
                    if (ver == null) continue;
                    var manifest = J.LoadRaw(Path.Combine(ver, "manifest.json"));
                    if (manifest == null) continue;
                    string name = Localize(J.Str(manifest, "name"), ver, J.Str(manifest, "default_locale")) ?? id;
                    var perms = new HashSet<string>(J.List(manifest, "permissions").Concat(J.List(manifest, "host_permissions")).OfType<string>());
                    foreach (var cs in J.List(manifest, "content_scripts"))
                        foreach (var m in J.List(cs, "matches").OfType<string>()) perms.Add(m);
                    var sorted = perms.OrderBy(p => p, StringComparer.Ordinal).ToList();
                    var it = Add("extension", browser + " \u203A " + profile, name, string.Join(", ", sorted), h.Sid);
                    it.Key = "extension|" + browser + "|" + profile + "|" + id;
                    it.Extra["id"] = id;
                    it.Extra["browser"] = browser;
                    it.Extra["version"] = Path.GetFileName(ver).Split('_')[0];
                    it.Extra["folder"] = idDir;
                    it.Extra["broad"] = sorted.Any(p => Broad.IsMatch(p)) ? "yes" : "no";
                }
            }
        }

        void Firefox(Hive h, string profilesDir)
        {
            if (!Directory.Exists(profilesDir)) return;
            foreach (var p in Directory.GetDirectories(profilesDir))
            {
                var doc = J.LoadRaw(Path.Combine(p, "extensions.json"));
                if (doc == null) continue;
                string profile = Path.GetFileName(p);
                foreach (var a in J.List(doc, "addons"))
                {
                    if (J.Str(a, "type") != "extension") continue;
                    string loc = J.Str(a, "location") ?? "";
                    if (loc.StartsWith("app-builtin") || loc.StartsWith("app-system")) continue;
                    string id = J.Str(a, "id");
                    var perms = J.List(a, "userPermissions.permissions").Concat(J.List(a, "userPermissions.origins")).OfType<string>().Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
                    var it = Add("extension", "Firefox \u203A " + profile, J.Str(a, "defaultLocale.name") ?? id, string.Join(", ", perms), h.Sid);
                    it.Key = "extension|Firefox|" + profile + "|" + id;
                    it.Extra["id"] = id;
                    it.Extra["browser"] = "Firefox";
                    it.Extra["version"] = J.Str(a, "version") ?? "";
                    it.Extra["folder"] = p;
                    it.Extra["broad"] = perms.Any(x => Broad.IsMatch(x)) ? "yes" : "no";
                }
            }
        }

        // ------------------------------------------------------------------ browser policies

        static readonly string[] PolicyRoots =
        {
            @"SOFTWARE\Policies\Google\Chrome", @"SOFTWARE\Policies\Microsoft\Edge", @"SOFTWARE\Policies\BraveSoftware\Brave",
            @"SOFTWARE\Policies\Mozilla\Firefox", @"SOFTWARE\WOW6432Node\Policies\Google\Chrome", @"SOFTWARE\WOW6432Node\Policies\Microsoft\Edge"
        };

        void Policies()
        {
            using (var hklm = Reg.Hklm)
                foreach (var p in PolicyRoots) PolicyTree(hklm, "HKLM", p, p, "");
            foreach (var h in hives)
                foreach (var p in PolicyRoots.Where(x => !x.Contains("WOW6432Node")))
                    PolicyTree(h.Root, h.Prefix, p, p, h.Sid);
        }

        void PolicyTree(RegistryKey root, string prefix, string rootPath, string path, string user)
        {
            using (var k = root.OpenSubKey(path))
            {
                if (k == null) return;
                string browser = rootPath.Split('\\').Last();
                string sub = path.Length > rootPath.Length ? path.Substring(rootPath.Length + 1) + "\\" : "";
                foreach (var name in k.GetValueNames())
                {
                    var it = Add("policy", prefix + "\\" + path, browser + ": " + sub + (name.Length == 0 ? "(Default)" : name), Reg.Text(k.GetValue(name)) ?? "", user);
                    it.Extra["value"] = name;
                }
                foreach (var s in k.GetSubKeyNames()) PolicyTree(root, prefix, rootPath, path + "\\" + s, user);
            }
        }

        // ------------------------------------------------------------------ proxy, hosts, DNS

        void Proxy()
        {
            foreach (var h in hives)
            {
                using (var k = h.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (k == null) continue;
                    bool on = k.GetValue("ProxyEnable") is int && (int)k.GetValue("ProxyEnable") == 1;
                    string server = k.GetValue("ProxyServer") as string ?? "", pac = k.GetValue("AutoConfigURL") as string ?? "";
                    string summary = (on ? "proxy " + server : "no proxy") + (pac.Length > 0 ? "; setup script " + pac : "");
                    var it = Add("proxy", h.Prefix + @"\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "Internet proxy", summary, h.Sid);
                    it.Extra["enabled"] = on ? "yes" : "no";
                    it.Extra["server"] = server;
                    it.Extra["pac"] = pac;
                }
            }
            using (var hklm = Reg.Hklm)
            using (var k = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"))
            {
                var b = k == null ? null : k.GetValue("WinHttpSettings") as byte[];
                string summary = "no proxy";
                if (b != null && b.Length >= 16)
                {
                    int flags = BitConverter.ToInt32(b, 8), len = BitConverter.ToInt32(b, 12);
                    if ((flags & 2) != 0 && len > 0 && 16 + len <= b.Length) summary = "proxy " + Encoding.ASCII.GetString(b, 16, len);
                }
                var it = Add("proxy", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", "WinHTTP proxy (Windows services)", summary, "");
                it.Extra["enabled"] = summary == "no proxy" ? "no" : "yes";
                it.Extra["pac"] = "";
            }
        }

        public static string HostsPath { get { return Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts"); } }

        public static List<string> HostsEntries(string text)
        {
            return text.Split('\n').Select(l => { int h = l.IndexOf('#'); return (h >= 0 ? l.Substring(0, h) : l).Trim(); })
                       .Where(l => l.Length > 0).Select(l => Regex.Replace(l, @"\s+", " ")).ToList();
        }

        void Hosts()
        {
            var lines = HostsEntries(File.ReadAllText(HostsPath));
            var it = Add("hosts", HostsPath, "hosts file", lines.Count == 0 ? "(no entries)" : string.Join("; ", lines.Take(40)) + (lines.Count > 40 ? "; \u2026" : ""), "");
            it.Extra["entries"] = lines.Count.ToString();
            it.Extra["file"] = HostsPath;
            it.HashBasis = string.Join("\n", lines);
        }

        void Dns()
        {
            using (var hklm = Reg.Hklm)
            {
                foreach (var fam in new[] { "Tcpip", "Tcpip6" })
                {
                    using (var root = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + fam + @"\Parameters\Interfaces"))
                    {
                        if (root == null) continue;
                        foreach (var guid in root.GetSubKeyNames())
                        {
                            using (var k = root.OpenSubKey(guid))
                            {
                                string ns = k == null ? null : k.GetValue("NameServer") as string;
                                if (string.IsNullOrWhiteSpace(ns)) continue;
                                string adapter;
                                using (var c = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\" + guid + @"\Connection"))
                                    adapter = c == null ? null : c.GetValue("Name") as string;
                                if (adapter == null) continue;
                                var servers = ns.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                string familyName = fam == "Tcpip6" ? "IPv6" : "IPv4";
                                var it = Add("dns", @"HKLM\SYSTEM\CurrentControlSet\Services\" + fam + @"\Parameters\Interfaces\" + guid, adapter + " (" + familyName + ")", string.Join(" ", servers), "");
                                it.Extra["guid"] = guid;
                                it.Extra["family"] = familyName;
                                it.Extra["adapter"] = adapter;
                                it.Extra["loopback"] = servers.All(x => x == "127.0.0.1" || x == "::1") ? "yes" : "no";
                            }
                        }
                    }
                }
            }
        }

        // ------------------------------------------------------------------ root certificates

        void RootCerts()
        {
            using (var hklm = Reg.Hklm)
            {
                Store(hklm, "HKLM", @"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates", "rootcert", "Trusted roots (this PC)", "");
                Store(hklm, "HKLM", @"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates", "authroot", "Roots from Windows Update", "");
                Store(hklm, "HKLM", @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates", "rootcert", "Trusted roots (policy)", "");
                Store(hklm, "HKLM", @"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates", "rootcert", "Trusted roots (enterprise)", "");
            }
            foreach (var h in hives)
                Store(h.Root, h.Prefix, @"Software\Microsoft\SystemCertificates\Root\Certificates", "rootcert", "Trusted roots (your account)", h.Sid);
        }

        void Store(RegistryKey root, string prefix, string path, string cat, string store, string user)
        {
            using (var k = root.OpenSubKey(path))
            {
                if (k == null) return;
                foreach (var thumb in k.GetSubKeyNames())
                {
                    string subject = thumb, expires = "?";
                    using (var c = k.OpenSubKey(thumb))
                    {
                        var cert = CertFromBlob(c == null ? null : c.GetValue("Blob") as byte[]);
                        if (cert != null)
                        {
                            using (cert)
                            {
                                subject = cert.GetNameInfo(X509NameType.SimpleName, false);
                                if (string.IsNullOrEmpty(subject)) subject = cert.Subject;
                                expires = cert.NotAfter.ToString("yyyy-MM-dd");
                            }
                        }
                    }
                    var it = Add(cat, prefix + "\\" + path, subject, store + ": " + subject + " (expires " + expires + ")", user);
                    it.Key = cat + "|" + prefix + "\\" + path + "|" + thumb;
                    it.Extra["thumbprint"] = thumb;
                    it.Extra["store"] = store;
                    it.HashBasis = thumb;
                }
            }
        }

        // The registry keeps a certificate as a list of properties; property 32 is the certificate itself.
        public static X509Certificate2 CertFromBlob(byte[] blob)
        {
            if (blob == null) return null;
            int p = 0;
            while (p + 12 <= blob.Length)
            {
                int id = BitConverter.ToInt32(blob, p), len = BitConverter.ToInt32(blob, p + 8);
                p += 12;
                if (len < 0 || p + len > blob.Length) break;
                if (id == 32)
                {
                    var der = new byte[len];
                    Array.Copy(blob, p, der, 0, len);
                    try { return new X509Certificate2(der); } catch (Exception) { return null; }
                }
                p += len;
            }
            return null;
        }

        // ------------------------------------------------------------------ WMI, IFEO, sign-in hooks, Active Setup

        void Wmi()
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            foreach (var cls in new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer" })
            {
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls)))
                    foreach (ManagementObject o in s.Get())
                    {
                        using (o)
                        {
                            string name = o["Name"] as string ?? "?";
                            string cmd = cls == "CommandLineEventConsumer"
                                ? (o["CommandLineTemplate"] as string ?? o["ExecutablePath"] as string)
                                : (o["ScriptFileName"] as string ?? Fmt.Clip(o["ScriptText"] as string, 300));
                            var it = Add("wmi", @"root\subscription\" + cls, name, cmd ?? "", "");
                            it.Extra["class"] = cls;
                        }
                    }
            }
            using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                foreach (ManagementObject o in s.Get())
                    using (o)
                    {
                        string f = o["Filter"] as string ?? "?", c = o["Consumer"] as string ?? "?";
                        var it = Add("wmi", @"root\subscription\__FilterToConsumerBinding", c, "when " + f, "");
                        it.Extra["class"] = "__FilterToConsumerBinding";
                        it.Extra["relpath"] = o.Path.RelativePath;
                    }
        }

        void Ifeo()
        {
            using (var hklm = Reg.Hklm)
            {
                foreach (var path in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" })
                {
                    using (var root = hklm.OpenSubKey(path))
                    {
                        if (root == null) continue;
                        foreach (var exe in root.GetSubKeyNames())
                        {
                            RegistryKey opened;
                            try { opened = root.OpenSubKey(exe); }
                            catch (Exception) { continue; }
                            using (var k = opened)
                            {
                                string dbg = k == null ? null : k.GetValue("Debugger") as string;
                                if (string.IsNullOrWhiteSpace(dbg)) continue;
                                var it = Add("ifeo", @"HKLM\" + path + "\\" + exe, exe + " \u2192 Debugger", dbg, "");
                                it.Extra["value"] = "Debugger";
                            }
                        }
                    }
                }
                using (var root = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"))
                {
                    if (root == null) return;
                    foreach (var exe in root.GetSubKeyNames())
                        using (var k = root.OpenSubKey(exe))
                        {
                            string mon = k == null ? null : k.GetValue("MonitorProcess") as string;
                            if (string.IsNullOrWhiteSpace(mon)) continue;
                            var it = Add("ifeo", @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" + exe, exe + " \u2192 on exit", mon, "");
                            it.Extra["value"] = "MonitorProcess";
                        }
                }
            }
        }

        void Winlogon()
        {
            using (var hklm = Reg.Hklm)
            {
                Pick(hklm, "HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", new[] { "Shell", "Userinit", "Taskman", "AppSetup" }, "");
                Pick(hklm, "HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", new[] { "AppInit_DLLs", "LoadAppInit_DLLs" }, "");
                Pick(hklm, "HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", new[] { "AppInit_DLLs", "LoadAppInit_DLLs" }, "");
                Pick(hklm, "HKLM", @"SYSTEM\CurrentControlSet\Control\Lsa", new[] { "Authentication Packages", "Security Packages", "Notification Packages" }, "");
                Pick(hklm, "HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager", new[] { "BootExecute" }, "");
            }
            foreach (var h in hives) Pick(h.Root, h.Prefix, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", new[] { "Shell" }, h.Sid);
        }

        void Pick(RegistryKey root, string prefix, string path, string[] names, string user)
        {
            using (var k = root.OpenSubKey(path))
            {
                if (k == null) return;
                foreach (var n in names)
                {
                    var v = k.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (v == null) continue;
                    string s = Reg.Text(v) ?? "";
                    var it = Add("winlogon", prefix + "\\" + path, n, s.Length == 0 ? "(empty)" : s, user);
                    it.Extra["value"] = n;
                    if (n == "Shell" || n == "Userinit" || n == "Taskman" || n == "AppSetup") it.Target = Targets.Resolve(s.Split(',')[0]);
                    else it.Extra["notarget"] = "yes";
                }
            }
        }

        void ActiveSetup()
        {
            using (var hklm = Reg.Hklm)
            {
                foreach (var path in new[] { @"SOFTWARE\Microsoft\Active Setup\Installed Components", @"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" })
                {
                    using (var root = hklm.OpenSubKey(path))
                    {
                        if (root == null) continue;
                        foreach (var id in root.GetSubKeyNames())
                            using (var k = root.OpenSubKey(id))
                            {
                                string stub = k == null ? null : k.GetValue("StubPath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                                if (string.IsNullOrWhiteSpace(stub)) continue;
                                string name = k.GetValue("") as string;
                                var it = Add("activesetup", @"HKLM\" + path + "\\" + id, string.IsNullOrWhiteSpace(name) || name.StartsWith("@") ? id : name, stub, "");
                                it.Extra["value"] = "StubPath";
                            }
                    }
                }
            }
        }
    }

    // Working out which program a command line actually runs.
    static class Targets
    {
        static readonly string Win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        public static string Resolve(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) return null;
            string c = Environment.ExpandEnvironmentVariables(command.Trim());
            if (c.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) c = Path.Combine(Win, c.Substring(12));
            else if (c.StartsWith(@"\??\", StringComparison.Ordinal)) c = c.Substring(4);
            else if (c.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || c.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase)) c = Path.Combine(Win, c);
            string exe, rest;
            Split(c, out exe, out rest);
            if (exe == null) return null;
            if (exe.StartsWith("/") || exe.StartsWith("-") || (exe.Length <= 2 && !exe.Contains("\\"))) return null;   // just options ("/UserInstall"), no program
            exe = Rooted(exe);
            string name = Path.GetFileName(exe).ToLowerInvariant();
            // a host program: what matters is the file it's asked to run
            if ((name == "rundll32.exe" || name == "regsvr32.exe") && rest.Length > 0)
            {
                string arg = rest.Trim();
                foreach (var flag in new[] { "/s ", "/u ", "/n ", "/i " }) if (arg.StartsWith(flag, StringComparison.OrdinalIgnoreCase)) arg = arg.Substring(3).Trim();
                string dll, ignore;
                Split(arg.Split(',')[0], out dll, out ignore);
                if (dll != null && !dll.StartsWith("/") && !dll.StartsWith("-")) return Rooted(dll);
            }
            return exe;
        }

        static string Rooted(string f)
        {
            f = f.Trim().Trim('"');
            if (f.Length == 0) return null;
            if (Path.IsPathRooted(f)) return File.Exists(f) || !File.Exists(f + ".exe") ? f : f + ".exe";
            // like Windows itself: System32 and Windows first, then the PATH (powershell.exe lives in a PATH folder)
            var dirs = new List<string> { Environment.SystemDirectory, Win, Path.Combine(Environment.SystemDirectory, "drivers") };
            dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';').Select(d => Environment.ExpandEnvironmentVariables(d.Trim())).Where(d => d.Length > 0));
            foreach (var dir in dirs)
            {
                try
                {
                    string p = Path.Combine(dir, f);
                    if (File.Exists(p)) return p;
                    if (File.Exists(p + ".exe")) return p + ".exe";
                }
                catch (ArgumentException) { }   // a malformed PATH entry
            }
            return f;
        }

        // Splits a command line into the program and the rest; unquoted paths with spaces are
        // tried piece by piece ("C:\Program Files\X Y\a.exe -b").
        public static void Split(string c, out string exe, out string rest)
        {
            exe = null;
            rest = "";
            c = (c ?? "").Trim();
            if (c.Length == 0) return;
            if (c[0] == '"')
            {
                int end = c.IndexOf('"', 1);
                exe = end > 1 ? c.Substring(1, end - 1) : c.Trim('"');
                rest = end > 1 && end + 1 < c.Length ? c.Substring(end + 1) : "";
                return;
            }
            int idx = -1;
            while (true)
            {
                idx = c.IndexOf(' ', idx + 1);
                string cand = idx < 0 ? c : c.Substring(0, idx);
                if (File.Exists(cand) || File.Exists(cand + ".exe")) { exe = cand; rest = idx < 0 ? "" : c.Substring(idx + 1); return; }
                if (idx < 0) break;
            }
            int sp = c.IndexOf(' ');
            exe = sp < 0 ? c : c.Substring(0, sp);
            rest = sp < 0 ? "" : c.Substring(sp + 1);
        }
    }
}
