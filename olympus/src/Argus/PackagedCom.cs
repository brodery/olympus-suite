using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Olympus.Argus
{
    // Task Scheduler lists packaged COM actions by class ID. Resolve them without activating COM.
    static class PackagedCom
    {
        const string RegistryRoot = @"SOFTWARE\Classes\PackagedCom\";
        const int ErrorInsufficientBuffer = 122, ErrorNotFound = 1168, PackageOriginInbox = 2;
        static readonly string SystemApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SystemApps");

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern int GetStagedPackagePathByFullName(string fullName, ref uint length, StringBuilder path);

        [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern int GetStagedPackageOrigin(string fullName, out int origin);

        public static string Resolve(string clsid, out bool inbox)
        {
            inbox = false;
            Guid id;
            if (!Guid.TryParse(clsid, out id)) return null;
            string keyName = id.ToString("B");
            try
            {
                using (var machine = Reg.Hklm)
                using (var index = machine.OpenSubKey(RegistryRoot + @"ClassIndex\" + keyName))
                {
                    if (index == null) return null;
                    string target = null;
                    bool inboxCandidate = false;
                    foreach (string package in index.GetSubKeyNames())
                    {
                        uint length = 0;
                        int rc = GetStagedPackagePathByFullName(package, ref length, null);
                        if (rc == ErrorNotFound) continue; // The class index can retain old, unstaged package versions.
                        if (rc != ErrorInsufficientBuffer || length < 2 || length > 32768) return null;
                        var location = new StringBuilder((int)length);
                        if (GetStagedPackagePathByFullName(package, ref length, location) != 0) return null;
                        string root = location.ToString();

                        string registration = RegistryRoot + @"Package\" + package + @"\";
                        int serverId;
                        using (var cls = machine.OpenSubKey(registration + @"Class\" + keyName))
                        {
                            var value = cls == null ? null : cls.GetValue("ServerId");
                            if (!(value is int) || (int)value < 0) return null;
                            serverId = (int)value;
                        }
                        string executable;
                        using (var server = machine.OpenSubKey(registration + @"Server\" + serverId.ToString(CultureInfo.InvariantCulture)))
                        {
                            if (server == null || !Equals(server.GetValue("IsSystemExecutable", 0), 0)) return null;
                            executable = server.GetValue("Executable", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                        }

                        var candidate = ResolveExecutable(root, executable);
                        if (candidate == null || target != null) return null; // Unknown or ambiguous registration.
                        target = candidate;
                        int origin;
                        inboxCandidate = IsChild(SystemApps, root) && GetStagedPackageOrigin(package, out origin) == 0 && origin == PackageOriginInbox;
                    }
                    inbox = inboxCandidate;
                    return target;
                }
            }
            catch (Exception) { inbox = false; return null; }
        }

        internal static string ResolveExecutable(string root, string executable)
        {
            if (string.IsNullOrWhiteSpace(root) || string.IsNullOrWhiteSpace(executable) ||
                !Regex.IsMatch(root, @"\A[A-Za-z]:\\") || Path.IsPathRooted(executable) ||
                !string.Equals(Path.GetExtension(executable), ".exe", StringComparison.OrdinalIgnoreCase))
                return null;

            foreach (string part in executable.Split('\\', '/'))
                if (part.Length == 0 || part.EndsWith(".", StringComparison.Ordinal) || part.Trim() != part ||
                    part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                    return null;

            var target = Path.GetFullPath(Path.Combine(root, executable));
            if (!IsChild(root, target)) return null;
            try
            {
                string path = Path.GetPathRoot(target);
                var attributes = File.GetAttributes(path);
                foreach (string part in target.Substring(path.Length).Split('\\'))
                {
                    if ((attributes & FileAttributes.ReparsePoint) != 0) return null;
                    path = Path.Combine(path, part);
                    attributes = File.GetAttributes(path);
                }
                return (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0 ? target : null;
            }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }

        static bool IsChild(string root, string target)
        {
            return Path.GetFullPath(target).StartsWith(Path.GetFullPath(root).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public static string PrincipalWithoutOverride(string runAs, int logonType, string clsid)
        {
            if (string.IsNullOrWhiteSpace(runAs) || logonType < 1 || logonType > 6 || logonType == 4) return null;
            Guid id;
            if (!Guid.TryParse(clsid, out id)) return null;
            try
            {
                var sid = runAs.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                    ? new SecurityIdentifier(runAs)
                    : (SecurityIdentifier)new NTAccount(runAs).Translate(typeof(SecurityIdentifier));
                var key = id.ToString("B");
                foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                {
                    using (var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    using (var classic = machine.OpenSubKey(@"SOFTWARE\Classes\CLSID\" + key))
                    using (var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view))
                    using (var hive = users.OpenSubKey(sid.Value))
                    using (var alias = users.OpenSubKey(sid.Value + "_Classes"))
                    using (var classes = hive == null ? null : hive.OpenSubKey(@"Software\Classes"))
                    {
                        if (classic != null || hive == null || (alias == null && classes == null) ||
                            HasClass(alias, key) || HasClass(classes, key))
                            return null;
                    }
                }
                return sid.Value;
            }
            catch (Exception) { return null; }
        }

        static bool HasClass(RegistryKey root, string clsid)
        {
            if (root == null) return false;
            using (var classic = root.OpenSubKey(@"CLSID\" + clsid))
            using (var packaged = root.OpenSubKey(@"PackagedCom\ClassIndex\" + clsid))
                return classic != null || packaged != null;
        }

        static readonly Guid SoftLandingTrigger = new Guid("F47D8C53-0B74-4A66-959D-367710AB1F84");
        static readonly Regex SoftLandingTask = new Regex(@"\ASoftLandingTriggerTask-(?<creative>[0-9]{18})-render-(?<instance>\{[0-9a-fA-F-]{36}\})\z");

        public static bool IsSoftLandingRender(string target, string clsid, string taskPath, string principalSid, string data)
        {
            Guid id;
            string server = Path.Combine(SystemApps, @"MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe");
            if (!Guid.TryParse(clsid, out id) || id != SoftLandingTrigger || !string.Equals(target, server, StringComparison.OrdinalIgnoreCase))
                return false;
            string folder = @"\SoftLanding\" + principalSid + "\\";
            if (string.IsNullOrEmpty(principalSid) || taskPath == null || !taskPath.StartsWith(folder, StringComparison.OrdinalIgnoreCase))
                return false;

            string name = taskPath.Substring(folder.Length);
            var match = SoftLandingTask.Match(name);
            if (!match.Success || !Guid.TryParseExact(match.Groups["instance"].Value, "B", out id)) return false;

            // This Windows handler can take other actions. Only its observed render/noOp fields are routine.
            string prefix = "TaskName:" + name.Length.ToString(CultureInfo.InvariantCulture) + "=" + name
                + ";CreativeId:18=" + match.Groups["creative"].Value
                + ";TriggerType:6=render;ActionName:4=noOp;OverrideRule:4=none;TriggerId:0=;TriggerPredicate:0=;CorrelationId:38=";
            return data != null && data.Length == prefix.Length + 39 && data.StartsWith(prefix, StringComparison.Ordinal)
                && data.EndsWith(";", StringComparison.Ordinal) && Guid.TryParseExact(data.Substring(prefix.Length, 38), "B", out id);
        }
    }
}
