// Tells a program that updated itself from a new program, for Argus and Cerberus. An update keeps
// the program's path except for one version folder, which goes forward: Edge\Application\157.0.4341.60
// becomes 158.0.4370.33, an installed MSIX package under WindowsApps gets a newer version with the same
// name and publisher, or a driver moves to a new driver-store folder for the same INF (its DriverVer is
// compared by the caller). Callers accept such a change only together with the same verified signer and
// Protect (nobody but SYSTEM, Administrators or TrustedInstaller can change the program, what's beside it,
// or any folder above it, checked on handles held for the whole decision), so a standard user can't stage
// a signed program next to a planted DLL and have it waved through.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Olympus
{
    // Which neighbours of a program Protect checks too: none, the files in its folder (the DLLs it would
    // load first), or that whole folder tree (plug-ins and anything else it may load from below).
    enum Siblings { None, Files, Tree }

    // The handles Protect holds: while this is open, nothing in the checked chain can be renamed, deleted
    // or written. Leaf is the program, opened for reading, for verifying its signature from the same handle.
    sealed class ProtectedFile : IDisposable
    {
        readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        public bool Ok { get; internal set; }
        public SafeFileHandle Leaf { get; internal set; }
        internal void Hold(SafeFileHandle h) { handles.Add(h); }
        public void Dispose()
        {
            foreach (var h in handles) h.Dispose();
            handles.Clear();
        }
    }

    static class Versioned
    {
        // Version folders of known self-updating layouts only: a bare version (Chromium browsers, Google's
        // updater: 158.0.4370.33) or Squirrel's app-<version> (Discord, Slack). Other prefixes ("tenant-1.0",
        // "jdk-17.0.1") are usually side-by-side installs, not one program updating itself.
        static readonly Regex VersionFolder = new Regex(@"\A(?<pre>app-)?(?<v>[0-9]{1,9}(\.[0-9]{1,9}){1,3})\z");
        static readonly Regex PackageFolder = new Regex(@"\A(?<name>[A-Za-z0-9.\-]+)_(?<v>[0-9]{1,5}(\.[0-9]{1,5}){3})_(?<arch>x86|x64|arm|arm64|neutral)_(?<res>[A-Za-z0-9.\-]*)_(?<pub>[a-z0-9]{13})\z");
        static readonly Regex DriverFolder = new Regex(@"\A(?<inf>[a-z0-9_.\-]+\.inf)_(?<arch>amd64|x86|arm64|ia64)_[0-9a-f]{16}\z");
        // DOS device names Windows maps in any folder, with or without an extension; COM/LPT also take ¹²³.
        static readonly Regex DeviceName = new Regex(@"\A(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(\..*)?\z", RegexOptions.IgnoreCase);
        // DriverVer = mm/dd/yyyy (or mm-dd-yyyy), w.x.y.z: four numbers, as the INF format requires.
        static readonly Regex DriverVerLine = new Regex(@"^\s*DriverVer\s*=\s*(?<d>[0-9]{1,2}(?<sep>[/-])[0-9]{1,2}\k<sep>[0-9]{4})\s*,\s*(?<v>[0-9]{1,5}(\.[0-9]{1,5}){3})\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        static string WindowsApps
        {
            get
            {
                string pf = Environment.GetEnvironmentVariable("ProgramW6432");
                if (string.IsNullOrEmpty(pf)) pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                return Path.Combine(pf, "WindowsApps");
            }
        }
        static string DriverStore { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\DriverStore\FileRepository"); } }

        // ------------------------------------------------------------------ paths

        // True when 'now' is a newer copy of the program at 'before': plain local paths with the same
        // folders and file name except exactly one version folder that went forward (see Compare).
        public static bool IsUpdate(string before, string now)
        {
            return IsUpdate(before, now, false);
        }

        // ignoreCase: the unchanged folders, the file name and the version folders' fixed parts may differ in
        // case (Windows paths are case-insensitive). For spotting related versions, never for keeping one.
        internal static bool IsUpdate(string before, string now, bool ignoreCase)
        {
            if (!PlainLocalPath(before) || !PlainLocalPath(now)) return false;
            var a = before.Split('\\');
            var b = now.Split('\\');
            if (a.Length != b.Length || a.Length < 3) return false;
            var cmp = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            int changed = -1;
            for (int i = 0; i < a.Length; i++)
            {
                if (string.Equals(a[i], b[i], cmp)) continue;
                if (changed >= 0 || i == a.Length - 1) return false;   // one folder at most, never the file name
                changed = i;
            }
            return changed > 0 && Compare(string.Join("\\", a, 0, changed), a[changed], b[changed], cmp) > 0;
        }

        // Two paths of the same program in different versions (either one the newer), compared the way Windows
        // compares paths: for finding the versions a block applies to.
        public static bool SameFamily(string a, string b)
        {
            return IsUpdate(a, b, true) || IsUpdate(b, a, true);
        }

        // True when the path holds a folder that could be a version: worth checking for other versions (folder
        // names matched in lower case, as Windows compares paths; trust decisions still use IsUpdate).
        public static bool HasVersionFolder(string path)
        {
            if (!PlainLocalPath(path)) return false;
            var parts = path.Split('\\');
            for (int i = 1; i < parts.Length - 1; i++)
            {
                string name = parts[i].ToLowerInvariant();
                if (VersionFolder.IsMatch(name) || (SameFolder(string.Join("\\", parts, 0, i), WindowsApps) && PackageFolder.IsMatch(name))
                    || (SameFolder(string.Join("\\", parts, 0, i), DriverStore) && DriverFolder.IsMatch(name)))
                    return true;
            }
            return false;
        }

        // 1 when 'after' is a later version than 'before' in that parent folder, else 0. Package folders
        // count only directly under WindowsApps and driver-store folders only in the driver store. Driver-store
        // folders carry a hash, not a version: the same INF and architecture is accepted here and the caller
        // compares the INFs' DriverVer.
        static int Compare(string parent, string before, string after, StringComparison cmp)
        {
            Match x, y;
            // Ignoring case, the folder names are matched in lower case: the package and driver-store patterns
            // spell their fixed parts (architecture, publisher ID, .inf) the way Windows writes them.
            if (cmp == StringComparison.OrdinalIgnoreCase) { before = before.ToLowerInvariant(); after = after.ToLowerInvariant(); }
            if (SameFolder(parent, WindowsApps))
            {
                x = PackageFolder.Match(before); y = PackageFolder.Match(after);
                if (!x.Success || !y.Success) return 0;
                foreach (var g in new[] { "name", "arch", "res", "pub" })
                    if (!string.Equals(x.Groups[g].Value, y.Groups[g].Value, cmp)) return 0;
                return Later(x.Groups["v"].Value, y.Groups["v"].Value);
            }
            if (SameFolder(parent, DriverStore))
            {
                x = DriverFolder.Match(before); y = DriverFolder.Match(after);
                return x.Success && y.Success && string.Equals(x.Groups["inf"].Value, y.Groups["inf"].Value, cmp)
                    && string.Equals(x.Groups["arch"].Value, y.Groups["arch"].Value, cmp) ? 1 : 0;
            }
            x = VersionFolder.Match(before); y = VersionFolder.Match(after);
            if (!x.Success || !y.Success || !string.Equals(x.Groups["pre"].Value, y.Groups["pre"].Value, cmp)) return 0;
            return Later(x.Groups["v"].Value, y.Groups["v"].Value);
        }

        static int Later(string before, string after)
        {
            Version a, b;
            return Version.TryParse(before, out a) && Version.TryParse(after, out b) && b > a ? 1 : 0;
        }

        static bool SameFolder(string a, string b)
        {
            return string.Equals(a.TrimEnd('\\'), b.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern int GetStagedPackagePathByFullName(string fullName, ref uint length, StringBuilder path);

        // True when the path's install layout itself ties its versions together: a folder of an MSIX
        // package that Windows really has staged (its name carries the publisher's identity) or a driver-store
        // folder (only Windows' PnP service writes there).
        public static bool InPackageOrDriverStore(string path)
        {
            if (!PlainLocalPath(path)) return false;
            if (InDriverStore(path)) return true;
            string prefix = WindowsApps.TrimEnd('\\') + "\\";
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            int end = path.IndexOf('\\', prefix.Length);
            if (end < 0) return false;
            string folder = path.Substring(prefix.Length, end - prefix.Length);
            if (!PackageFolder.IsMatch(folder)) return false;
            try
            {
                uint length = 0;
                if (GetStagedPackagePathByFullName(folder, ref length, null) != 122 || length < 2 || length > 32768) return false;   // ERROR_INSUFFICIENT_BUFFER
                var sb = new StringBuilder((int)length);
                if (GetStagedPackagePathByFullName(folder, ref length, sb) != 0) return false;
                return SameFolder(sb.ToString(), path.Substring(0, end));
            }
            catch (Exception) { return false; }
        }

        public static bool InDriverStore(string path)
        {
            if (!PlainLocalPath(path)) return false;
            string prefix = DriverStore.TrimEnd('\\') + "\\";
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            int end = path.IndexOf('\\', prefix.Length);
            return end > 0 && DriverFolder.IsMatch(path.Substring(prefix.Length, end - prefix.Length));
        }

        // The DriverVer of the driver package a driver-store file belongs to, as "version,yyyy-MM-dd", or null.
        public static string DriverVer(string fileInDriverStore)
        {
            try
            {
                if (!InDriverStore(fileInDriverStore)) return null;
                string prefix = DriverStore.TrimEnd('\\') + "\\";
                int end = fileInDriverStore.IndexOf('\\', prefix.Length);
                string folder = fileInDriverStore.Substring(0, end);
                string inf = Path.Combine(folder, DriverFolder.Match(fileInDriverStore.Substring(prefix.Length, end - prefix.Length)).Groups["inf"].Value);
                if (!File.Exists(inf) || new FileInfo(inf).Length > (4 << 20)) return null;
                return DriverVerOf(File.ReadAllText(inf));
            }
            catch (Exception) { return null; }
        }

        // The package's DriverVer from an INF's text: the one in its [Version] section. Null when there isn't
        // exactly one there, or when any other section has a DriverVer of its own (an install section's
        // DriverVer overrides [Version] for that section, so the package has no single version).
        internal static string DriverVerOf(string infText)
        {
            string section = null;
            Match found = null;
            foreach (var raw in (infText ?? "").Split('\n'))
            {
                string line = raw.Trim();
                int comment = line.IndexOf(';');
                if (comment >= 0) line = line.Substring(0, comment).Trim();
                if (line.StartsWith("[", StringComparison.Ordinal) && line.EndsWith("]", StringComparison.Ordinal))
                {
                    section = line.Substring(1, line.Length - 2).Trim();
                    continue;
                }
                if (!Regex.IsMatch(line, @"\ADriverVer\s*=", RegexOptions.IgnoreCase)) continue;
                var m = DriverVerLine.Match(line);
                if (!m.Success || found != null || !string.Equals(section, "Version", StringComparison.OrdinalIgnoreCase)) return null;
                found = m;
            }
            DateTime date;
            Version v;
            if (found == null || !Version.TryParse(found.Groups["v"].Value, out v)
                || !DateTime.TryParseExact(found.Groups["d"].Value, new[] { "M/d/yyyy", "M-d-yyyy" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out date)) return null;
            // Each part 0 to 65534, and not 0.0.0.0.
            if (v.Major > 65534 || v.Minor > 65534 || v.Build > 65534 || v.Revision > 65534 || (v.Major | v.Minor | v.Build | v.Revision) == 0) return null;
            return v + "," + date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        }

        // True when the driver package went forward: a higher version, or the same version dated later.
        public static bool LaterDriver(string before, string after)
        {
            if (before == null || after == null) return false;
            var a = before.Split(','); var b = after.Split(',');
            Version va, vb;
            if (a.Length != 2 || b.Length != 2 || !Version.TryParse(a[0], out va) || !Version.TryParse(b[0], out vb)) return false;
            return vb > va || (vb == va && string.CompareOrdinal(b[1], a[1]) > 0);
        }

        // A fully qualified local path that Windows reads exactly as written: drive letter and backslashes,
        // no environment variables, device, stream or wildcard syntax, 8.3 aliases ('~'), '.'/'..', DOS device
        // names, or names that start or end with a space or end with a dot.
        public static bool PlainLocalPath(string path)
        {
            if (path == null || path.Length < 4 || path.Length >= 260 || !Regex.IsMatch(path, @"\A[A-Za-z]:\\[^\\]")) return false;
            for (int i = 0; i < path.Length; i++)
            {
                char c = path[i];
                if (c < 32 || c == '/' || c == '%' || c == '"' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|' || c == '~' || (c == ':' && i != 1))
                    return false;
            }
            foreach (var seg in path.Substring(3).Split('\\'))
                if (seg.Length == 0 || seg == "." || seg == ".." || seg.StartsWith(" ", StringComparison.Ordinal) || seg.EndsWith(" ", StringComparison.Ordinal)
                    || seg.EndsWith(".", StringComparison.Ordinal) || DeviceName.IsMatch(seg))
                    return false;
            return true;
        }

        // The program a registered command starts and the rest of the line, read the way Windows launches
        // it: a quoted path, or an unquoted path without spaces. The driver form \SystemRoot\<relative path>
        // is allowed where asked for. False for anything ambiguous.
        public static bool SplitLaunch(string command, bool allowSystemRoot, out string image, out string arguments)
        {
            image = arguments = null;
            if (string.IsNullOrEmpty(command) || char.IsWhiteSpace(command[0])) return false;
            string path, rest;
            if (command[0] == '"')
            {
                int end = command.IndexOf('"', 1);
                if (end < 2) return false;
                path = command.Substring(1, end - 1);
                rest = command.Substring(end + 1);
                if (rest.Length > 0 && rest[0] != ' ') return false;
            }
            else
            {
                int space = command.IndexOf(' ');
                path = space < 0 ? command : command.Substring(0, space);
                rest = space < 0 ? "" : command.Substring(space);
            }
            const string systemRoot = @"\SystemRoot\";
            if (allowSystemRoot && path.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
            {
                string relative = path.Substring(systemRoot.Length);
                if (relative.Length == 0 || relative[0] == '\\' || relative.IndexOf(':') >= 0) return false;
                path = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\" + relative;
            }
            if (!PlainLocalPath(path)) return false;
            image = path;
            arguments = rest;
            return true;
        }

        [DllImport("kernel32.dll", EntryPoint = "GetLongPathNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetLongPathName(string shortPath, StringBuilder longPath, int size);

        // The existing path with every component in its long form (8.3 aliases expanded, whether or not
        // they contain '~'), or the path unchanged if Windows can't.
        public static string LongPath(string path)
        {
            string full;
            return TryLongPath(path, out full) ? full : path;
        }

        // The same, reporting failure instead of handing the input back: checks that a path is its own long
        // form must fail when Windows can't say.
        static bool TryLongPath(string path, out string full)
        {
            full = null;
            if (string.IsNullOrEmpty(path)) return false;
            try
            {
                var sb = new StringBuilder(1024);
                int n = GetLongPathName(path, sb, sb.Capacity);
                if (n <= 0 || n >= sb.Capacity) return false;
                full = sb.ToString();
                return true;
            }
            catch (Exception) { return false; }
        }

        static bool IsOwnLongForm(string path)
        {
            string full;
            return TryLongPath(path, out full) && string.Equals(full, path, StringComparison.OrdinalIgnoreCase);
        }

        // ------------------------------------------------------------------ who can change it

        // Rights that let someone add, replace, change or remove something, or take over its permissions:
        // write data / add file, append / add folder, write EA, delete child, write attributes, DELETE,
        // WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL.
        const int Changes = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;
        // A drive root normally lets users create folders; above a program's own folder what matters is
        // removing or renaming what's inside (delete child) or taking the root over.
        const int RootChanges = 0x40 | 0x40000 | 0x80000 | 0x10000000;

        static readonly SecurityIdentifier TrustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        static readonly SecurityIdentifier CreatorOwner = new SecurityIdentifier("S-1-3-0");
        static readonly SecurityIdentifier OwnerRights = new SecurityIdentifier("S-1-3-4");

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, int access, int share, IntPtr security, int disposition, int flags, IntPtr template);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int GetSecurityInfo(SafeFileHandle handle, int objectType, int information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")]
        static extern int GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("advapi32.dll", EntryPoint = "GetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetFileSecurity(string fileName, int requested, byte[] descriptor, int length, out int needed);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);

        [StructLayout(LayoutKind.Sequential)]
        struct FileInformation
        {
            public uint Attributes, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        // ListDirectory (FILE_LIST_DIRECTORY = FILE_READ_DATA) matters: Windows enforces share modes only
        // against handles that hold data access, so a metadata-only handle wouldn't stop a rename.
        const int GenericRead = unchecked((int)0x80000000), ReadControl = 0x20000, ReadAttributes = 0x80, ListDirectory = 0x1;
        const int ShareRead = 1, ShareWrite = 2, OpenExisting = 3, BackupSemantics = 0x02000000, OpenReparsePoint = 0x00200000;
        const int OwnerAndDacl = 0x1 | 0x4;   // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

        // Opens the program and every folder above it, from the drive root down, without delete sharing
        // (so none of them can be renamed or removed while held) and without following reparse points, and
        // checks each one's owner and DACL on its handle: only SYSTEM, Administrators and TrustedInstaller may
        // change anything. The drive must be a fixed NTFS or ReFS volume, the path must be its own long form,
        // and 'siblings' says which neighbours must be locked down too. Dispose the result after using Leaf.
        public static ProtectedFile Protect(string file, Siblings siblings)
        {
            return Protect(file, siblings, false);
        }

        // freshNeighbours: check the neighbours now, not from a verdict up to 30 seconds old (for a decision that
        // stays made, like Cerberus treating a version as an update).
        public static ProtectedFile Protect(string file, Siblings siblings, bool freshNeighbours)
        {
            var p = new ProtectedFile();
            try
            {
                if (!PlainLocalPath(file) || !string.Equals(Path.GetFullPath(file), file, StringComparison.OrdinalIgnoreCase)) return p;
                string folder = Path.GetDirectoryName(file);   // "C:\" for a file at the root, never the drive-relative "C:"
                if (string.IsNullOrEmpty(folder) || !HoldChain(folder, p)) return p;
                var leaf = CreateFile(file, GenericRead | ReadControl, ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
                p.Hold(leaf);
                if (leaf.IsInvalid || !Kind(leaf, false) || !Locked(DescriptorOf(leaf), Changes)) return p;
                if (!IsOwnLongForm(file)) return p;   // no alias spelling, and Windows must be able to say
                if (siblings != Siblings.None && !NeighboursLocked(folder, siblings == Siblings.Tree, freshNeighbours)) return p;
                p.Leaf = leaf;
                p.Ok = true;
                return p;
            }
            catch (Exception) { return p; }
        }

        // Opens 'folder' and every folder above it, from the drive root down, and checks each (see Protect).
        // 'folder' itself gets the full mask even when it is the drive root; roots above it only the root mask.
        static bool HoldChain(string folder, ProtectedFile p)
        {
            if (folder == null || folder.Length < 3 || folder[1] != ':' || folder[2] != '\\') return false;   // "C:\..." only
            var drive = new DriveInfo(folder.Substring(0, 3));
            if (drive.DriveType != DriveType.Fixed || (drive.DriveFormat != "NTFS" && drive.DriveFormat != "ReFS")) return false;
            var parts = folder.TrimEnd('\\').Split('\\');
            string dir = parts[0] + "\\";
            for (int i = 0; i < parts.Length; i++)
            {
                if (i > 0) dir = dir.TrimEnd('\\') + "\\" + parts[i];
                bool home = i == parts.Length - 1;
                var h = OpenFolder(dir);
                p.Hold(h);
                if (h.IsInvalid || !Kind(h, true) || !Locked(DescriptorOf(h), i == 0 && !home ? RootChanges : Changes)) return false;
            }
            return true;
        }

        // A folder handle that keeps the folder where it is while open (no delete sharing, with data access so
        // the share mode is enforced) and doesn't follow a reparse point.
        internal static SafeFileHandle OpenFolder(string dir)
        {
            return CreateFile(dir, ListDirectory | ReadControl | ReadAttributes, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        }

        // Protect, for a yes/no answer.
        public static bool AdminOnlyFolder(string file, Siblings siblings)
        {
            using (var p = Protect(file, siblings)) return p.Ok;
        }

        // A folder (a task's working folder, say) and every folder above it can be changed only by SYSTEM,
        // Administrators and TrustedInstaller, and it is its own long form.
        public static bool FolderLocked(string folder)
        {
            try
            {
                string f = folder ?? "";
                // A drive root only as "C:\"; a bare "C:" means that drive's current folder, whatever it is.
                if (!Regex.IsMatch(f, @"\A[A-Za-z]:\\\z"))
                {
                    f = f.TrimEnd('\\');
                    if (!PlainLocalPath(f) || !string.Equals(Path.GetFullPath(f), f, StringComparison.OrdinalIgnoreCase) || !IsOwnLongForm(f)) return false;
                }
                using (var p = new ProtectedFile()) return HoldChain(f, p);
            }
            catch (Exception) { return false; }
        }

        // A plain folder (directory = true) or file: not a reparse point (junction, symlink, mount point).
        static bool Kind(SafeFileHandle h, bool directory)
        {
            FileInformation info;
            if (!GetFileInformationByHandle(h, out info)) return false;
            var a = (FileAttributes)info.Attributes;
            return (a & FileAttributes.ReparsePoint) == 0 && ((a & FileAttributes.Directory) != 0) == directory;
        }

        static RawSecurityDescriptor DescriptorOf(SafeFileHandle h)
        {
            IntPtr sd;
            if (GetSecurityInfo(h, 1 /* SE_FILE_OBJECT */, OwnerAndDacl, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd) != 0 || sd == IntPtr.Zero) return null;
            try
            {
                int length = GetSecurityDescriptorLength(sd);
                if (length <= 0 || length > (1 << 20)) return null;
                var bytes = new byte[length];
                Marshal.Copy(sd, bytes, 0, length);
                return new RawSecurityDescriptor(bytes, 0);
            }
            finally { LocalFree(sd); }
        }

        static RawSecurityDescriptor DescriptorOf(string path)
        {
            int needed;
            GetFileSecurity(path, OwnerAndDacl, null, 0, out needed);
            if (needed <= 0 || needed > (1 << 20)) return null;
            var buffer = new byte[needed];
            return GetFileSecurity(path, OwnerAndDacl, buffer, needed, out needed) ? new RawSecurityDescriptor(buffer, 0) : null;
        }

        static readonly Dictionary<string, KeyValuePair<DateTime, bool>> neighbourCache = new Dictionary<string, KeyValuePair<DateTime, bool>>(StringComparer.OrdinalIgnoreCase);

        // The other files in the folder (or, with tree, every file and folder below it) are locked down and
        // none is a reparse point. A verdict is reused for at most 30 seconds (big folders like System32 are
        // slow to check, and one scan checks many entries there), so it describes the folder as it was moments
        // before the decision, not before an installer that ran since.
        static readonly TimeSpan NeighbourReuse = TimeSpan.FromSeconds(30);

        static bool NeighboursLocked(string folder, bool tree, bool fresh)
        {
            string key = (tree ? "tree|" : "files|") + folder;
            lock (neighbourCache)
            {
                KeyValuePair<DateTime, bool> hit;
                if (!fresh && neighbourCache.TryGetValue(key, out hit) && DateTime.UtcNow - hit.Key < NeighbourReuse) return hit.Value;
            }
            bool ok = ScanNeighbours(folder, tree);
            lock (neighbourCache) neighbourCache[key] = new KeyValuePair<DateTime, bool>(DateTime.UtcNow, ok);
            return ok;
        }

        static bool ScanNeighbours(string folder, bool tree)
        {
            try
            {
                int count = 0;
                var todo = new Stack<string>();
                todo.Push(folder);
                while (todo.Count > 0)
                {
                    foreach (var e in new DirectoryInfo(todo.Pop()).EnumerateFileSystemInfos())
                    {
                        bool isDir = (e.Attributes & FileAttributes.Directory) != 0;
                        if (isDir && !tree) continue;
                        if (++count > 20000 || (e.Attributes & FileAttributes.ReparsePoint) != 0 || !Locked(DescriptorOf(e.FullName), Changes)) return false;
                        if (isDir) todo.Push(e.FullName);
                    }
                }
                return true;
            }
            catch (Exception) { return false; }
        }

        static bool Locked(RawSecurityDescriptor sd, int rights)
        {
            if (sd == null || !Admin(sd.Owner)) return false;
            if ((sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || sd.DiscretionaryAcl == null) return false;   // no DACL: everyone may do anything
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;   // applies only to things created inside
                switch ((int)ace.AceType)
                {
                    case 1: case 6: case 10: case 12: continue;   // deny ACEs only take rights away
                    case 0: case 4: case 5: case 9: case 11: break; // allow ACEs, conditional (callback) ones included
                    default: return false;                        // nothing else belongs in a DACL
                }
                var known = ace as KnownAce;
                if (known == null) return false;
                if ((known.AccessMask & rights) == 0) continue;
                var who = known.SecurityIdentifier;
                // CREATOR OWNER only shapes new children; OWNER RIGHTS goes to the owner, already checked.
                if (Admin(who) || who == CreatorOwner || who == OwnerRights) continue;
                return false;
            }
            return true;
        }

        static bool Admin(SecurityIdentifier id)
        {
            return id != null && (id.IsWellKnown(WellKnownSidType.LocalSystemSid) || id.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || id == TrustedInstaller);
        }
    }
}
