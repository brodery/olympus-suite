// Atlas's scanner: walks a drive or folder on several threads, reading each folder's entries in one
// call (GetFileInformationByHandleEx), and builds a tree of folders with the space they take on
// disk. Hard links count once (Ark's snapshots, Windows' WinSxS), junctions and symlinks aren't
// followed, and a folder's small files are summed instead of kept one by one. Maps are saved
// (gzip) so the window opens with the last one, and so an elevated scan can hand its map back.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Olympus.Atlas
{
    // What kind of file something is (the map's colours).
    static class Kinds
    {
        public const byte Folder = 0, Video = 1, Image = 2, Audio = 3, Archive = 4, Exe = 5, Game = 6, Doc = 7,
                          Code = 8, Sys = 9, Other = 10, Small = 11, Hidden = 12;
        public static readonly string[] Names =
        {
            "Folder", "Video", "Pictures", "Audio", "Archives and disk images", "Programs", "Game data", "Documents",
            "Code and settings", "System, logs and temp", "Other", "Smaller files", "Hidden from Atlas"
        };
        public static readonly Color[] Colors =
        {
            Color.FromArgb(0x5A, 0x4A, 0x3A),   // folder (background)
            Color.FromArgb(0xE5, 0x39, 0x35),   // video
            Color.FromArgb(0xAB, 0x47, 0xBC),   // pictures
            Color.FromArgb(0xFB, 0x8C, 0x00),   // audio
            Color.FromArgb(0xFD, 0xD8, 0x35),   // archives
            Color.FromArgb(0x1E, 0x88, 0xE5),   // programs
            Color.FromArgb(0x43, 0xA0, 0x47),   // game data
            Color.FromArgb(0x00, 0xAC, 0xC1),   // documents
            Color.FromArgb(0x8D, 0x6E, 0x63),   // code and settings
            Color.FromArgb(0x78, 0x90, 0x9C),   // system, logs, temp
            Color.FromArgb(0xC0, 0xCA, 0x33),   // other
            Color.FromArgb(0xB4, 0xB4, 0xB4),   // smaller files
            Color.FromArgb(0x50, 0x50, 0x50),   // hidden from Atlas
        };

        static readonly Dictionary<string, byte> byExt = Build();
        static Dictionary<string, byte> Build()
        {
            var d = new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
            Action<byte, string> add = (k, list) => { foreach (var e in list.Split(' ')) if (e.Length > 0) d["." + e] = k; };
            add(Video, "mp4 mkv avi mov wmv webm m4v flv mpg mpeg m2ts mts bk2 bik usm vob 3gp");
            add(Image, "jpg jpeg png gif bmp webp heic heif tif tiff raw cr2 cr3 nef arw dng psd ico svg dds tga ktx ktx2 exr hdr jxl avif");
            add(Audio, "mp3 wav flac ogg m4a aac wma opus wem bnk fsb xwm aif aiff mid");
            add(Archive, "zip 7z rar tar gz tgz bz2 xz zst lz4 iso img vhd vhdx vmdk wim esd cab wabbajack");
            add(Exe, "exe dll sys msi msp msix msixbundle appx appxbundle ocx cpl drv scr efi mui pyd so node");
            add(Game, "pak ba2 bsa esp esm esl ucas utoc sig assets ress bundle forge vpk wad rpf big pck arc uasset umap uexp ubulk gpak");
            add(Doc, "pdf doc docx xls xlsx ppt pptx odt ods odp txt md rtf csv epub mobi one");
            add(Code, "cs py js ts json xml h hpp c cpp java go rs html htm css lua ps1 psm1 bat cmd sh pdb lib obj ilk ipch class jar sln csproj vcxproj yaml yml toml ini cfg conf");
            add(Sys, "log etl evtx tmp temp dmp mdmp hdmp blf regtrans-ms old bak chk pf cache db-wal db-shm");
            return d;
        }

        public static byte Of(string name)
        {
            int dot = name.LastIndexOf('.');
            if (dot <= 0 || dot == name.Length - 1) return Other;
            byte k;
            return byExt.TryGetValue(name.Substring(dot), out k) ? k : Other;
        }

        public static string Ext(string name)
        {
            int dot = name.LastIndexOf('.');
            return dot <= 0 || dot == name.Length - 1 ? "(none)" : name.Substring(dot).ToLowerInvariant();
        }
    }

    sealed class Node
    {
        public string Name;
        public Node Parent;
        public Node[] Kids;       // subfolders and the files kept one by one, biggest first (null: none)
        public long Size;         // bytes on disk
        public long Files;        // files inside, all levels
        public int Dirs;          // folders inside, all levels
        public long SmallSize;    // this folder's own files too small to keep one by one
        public int SmallCount;
        public long Modified;     // newest change inside (FILETIME, UTC)
        public byte Kind;         // Kinds.Folder, or the file's kind
        public byte Flags;

        public const byte Denied = 1, Link = 2, HardLink = 4;   // HardLink: another link to the same file got its space
        public bool IsDir { get { return Kind == Kinds.Folder; } }
        public bool Has(byte flag) { return (Flags & flag) != 0; }

        public string FullPath
        {
            get
            {
                if (Parent == null) return Name;
                string p = Parent.FullPath;
                return p.EndsWith("\\", StringComparison.Ordinal) ? p + Name : p + "\\" + Name;
            }
        }
        public DateTime ModifiedUtc
        {
            get { return Modified > 0 && Modified < 2650467743999999999L ? DateTime.FromFileTimeUtc(Modified) : DateTime.MinValue; }
        }
    }

    sealed class ExtStat { public long Count, Size; }

    sealed class MapInfo
    {
        public Node Root;
        public string RootPath;
        public DateTime ScannedUtc;
        public TimeSpan Took;
        public bool Elevated;
        public long VolumeTotal, VolumeFree, DeniedDirs, KeepFrom;
        public Dictionary<string, ExtStat> Types = new Dictionary<string, ExtStat>(StringComparer.OrdinalIgnoreCase);

        public bool IsDrive { get { return RootPath != null && RootPath.Length == 3; } }
        // Space Windows counts as used that the scan couldn't see: restore points, the file table,
        // folders it wasn't allowed to read.
        public long Unseen
        {
            get { return IsDrive && VolumeTotal > 0 && Root != null ? Math.Max(0, VolumeTotal - VolumeFree - Root.Size) : 0; }
        }
    }

    sealed class Scanner
    {
        const int BufSize = 64 * 1024;
        public long FilesSeen, BytesSeen, DirsSeen, DeniedSeen;
        public volatile string Current;
        volatile bool cancel;

        struct Work { public Node Node; public string Path; }
        readonly Stack<Work> work = new Stack<Work>();
        readonly object gate = new object();
        int pending;
        LinkTable links;
        readonly List<LinkClaim> losers = new List<LinkClaim>();   // counted first, then lost to an earlier path
        long keepFrom;
        string rootPath;

        public bool Cancelled { get { return cancel; } }
        public void Cancel()
        {
            cancel = true;
            lock (gate) Monitor.PulseAll(gate);
        }

        // "C:" and "C:\" become "C:\"; folders lose a trailing backslash.
        public static string NormalizeRoot(string path)
        {
            string p = (path ?? "").Trim().Trim('"');
            if (p.Length == 1 && char.IsLetter(p[0])) p += ":";
            if (p.Length == 2 && p[1] == ':') p += "\\";
            p = Path.GetFullPath(p);
            if (p.Length > 3) p = p.TrimEnd('\\');
            return p;
        }

        public MapInfo Run(string path, int threads = 0)
        {
            var started = DateTime.UtcNow;
            string root = NormalizeRoot(path);
            rootPath = root;
            var map = new MapInfo { RootPath = root, ScannedUtc = started, Elevated = Elevation.IsElevated };
            bool ntfs = false;
            try
            {
                var di = new DriveInfo(Path.GetPathRoot(root));
                if (di.IsReady)
                {
                    ntfs = di.DriveFormat == "NTFS";
                    map.VolumeTotal = di.TotalSize;
                    map.VolumeFree = di.TotalFreeSpace;
                }
            }
            catch (Exception) { }
            keepFrom = root.Length == 3 ? 1L << 20 : 16 * 1024;
            map.KeepFrom = keepFrom;
            links = ntfs ? new LinkTable() : null;
            var top = new Node { Name = root, Kind = Kinds.Folder };
            map.Root = top;
            if (!Directory.Exists(root))
            {
                top.Flags |= Node.Denied;
                map.Took = DateTime.UtcNow - started;
                return map;
            }
            lock (gate)
            {
                work.Push(new Work { Node = top, Path = root });
                pending = 1;
            }
            int n = threads > 0 ? threads : Math.Max(2, Math.Min(8, Environment.ProcessorCount));
            var tables = new List<Dictionary<string, ExtStat>>();
            var running = new List<Thread>();
            for (int i = 0; i < n; i++)
            {
                var table = new Dictionary<string, ExtStat>(StringComparer.OrdinalIgnoreCase);
                tables.Add(table);
                var t = new Thread(() => Worker(table)) { IsBackground = true, Name = "atlas scan " + i };
                running.Add(t);
                t.Start();
            }
            foreach (var t in running) t.Join();
            foreach (var table in tables)
                foreach (var kv in table)
                {
                    ExtStat s;
                    if (!map.Types.TryGetValue(kv.Key, out s)) map.Types[kv.Key] = s = new ExtStat();
                    s.Count += kv.Value.Count;
                    s.Size += kv.Value.Size;
                }
            // a hard link counted before an earlier-sorting link to the same file turned up gives its space back
            foreach (var c in losers)
            {
                if (c.Kept != null) { c.Kept.Size = 0; c.Kept.Flags |= Node.HardLink; }
                else c.Folder.SmallSize -= c.Size;
                ExtStat s;
                if (map.Types.TryGetValue(Kinds.Ext(c.Name), out s)) s.Size -= c.Size;
            }
            losers.Clear();
            Finish(top);
            map.DeniedDirs = DeniedSeen;
            map.Took = DateTime.UtcNow - started;
            links = null;
            return map;
        }

        void Worker(Dictionary<string, ExtStat> types)
        {
            IntPtr buf = Marshal.AllocHGlobal(BufSize);
            try
            {
                while (true)
                {
                    Work w;
                    lock (gate)
                    {
                        while (true)
                        {
                            if (cancel || (work.Count == 0 && pending == 0)) { Monitor.PulseAll(gate); return; }
                            if (work.Count > 0) break;
                            Monitor.Wait(gate);
                        }
                        w = work.Pop();
                    }
                    try { ReadFolder(w, buf, types); }
                    catch (Exception e)
                    {
                        w.Node.Flags |= Node.Denied;
                        Log.Warn("reading " + w.Path + ": " + e.Message);
                    }
                    lock (gate)
                    {
                        pending--;
                        if (pending == 0) Monitor.PulseAll(gate);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static string Join(string dir, string name)
        {
            return dir.EndsWith("\\", StringComparison.Ordinal) ? dir + name : dir + "\\" + name;
        }

        void ReadFolder(Work w, IntPtr buf, Dictionary<string, ExtStat> types)
        {
            Current = w.Path;
            Interlocked.Increment(ref DirsSeen);
            using (var h = FsNative.OpenDir(w.Path, w.Path == rootPath))
            {
                if (h.IsInvalid)
                {
                    w.Node.Flags |= Node.Denied;
                    Interlocked.Increment(ref DeniedSeen);
                    return;
                }
                var kids = new List<Node>();
                var subs = new List<Work>();
                long smallSize = 0, newest = w.Node.Modified, files = 0, bytes = 0;
                int smallCount = 0;
                bool first = true;
                while (!cancel)
                {
                    if (!FsNative.GetFileInformationByHandleEx(h, first ? 11 : 10, buf, BufSize))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err != 18 && first)   // 18: no more files
                        {
                            w.Node.Flags |= Node.Denied;
                            Interlocked.Increment(ref DeniedSeen);
                        }
                        break;
                    }
                    first = false;
                    int off = 0;
                    while (true)
                    {
                        IntPtr e = buf + off;
                        int next = Marshal.ReadInt32(e, 0);
                        int nameLen = Marshal.ReadInt32(e, 60);
                        string name = Marshal.PtrToStringUni(e + 104, nameLen / 2);
                        if (name != "." && name != "..")
                        {
                            long write = Marshal.ReadInt64(e, 24);
                            int attrs = Marshal.ReadInt32(e, 56);
                            if ((attrs & 0x10) != 0)
                            {
                                var d = new Node { Name = name, Parent = w.Node, Kind = Kinds.Folder, Modified = write };
                                int tag = Marshal.ReadInt32(e, 64);
                                // junctions, symlinks and mount points point somewhere else: don't follow them
                                if ((attrs & 0x400) != 0 && (tag & 0x20000000) != 0) d.Flags |= Node.Link;
                                else subs.Add(new Work { Node = d, Path = Join(w.Path, name) });
                                kids.Add(d);
                            }
                            else
                            {
                                long eof = Marshal.ReadInt64(e, 40);
                                long size = Marshal.ReadInt64(e, 48);
                                // Windows-compressed (WOF) files list no allocation; ask for their real size
                                if (size == 0 && eof > 4096 && (attrs & 0x441000) == 0) size = FsNative.SizeOnDisk(Join(w.Path, name), 0);
                                // hard links share one file's space: the link with the first path keeps it,
                                // whichever thread finds which link first
                                LinkClaim claim = null;
                                byte flags = 0;
                                if (links != null && size >= 65536)
                                {
                                    claim = new LinkClaim { Folder = w.Node, Name = name, Size = size };
                                    var loser = links.Resolve(Marshal.ReadInt64(e, 96), claim);
                                    if (loser == claim) { size = 0; claim = null; flags = Node.HardLink; }
                                    else if (loser != null) lock (losers) losers.Add(loser);
                                }
                                files++;
                                bytes += size;
                                if (write > newest) newest = write;
                                string ext = Kinds.Ext(name);
                                ExtStat st;
                                if (!types.TryGetValue(ext, out st)) types[ext] = st = new ExtStat();
                                st.Count++;
                                st.Size += size;
                                if (size >= keepFrom)
                                {
                                    var f = new Node { Name = name, Parent = w.Node, Kind = Kinds.Of(name), Size = size, Files = 1, Modified = write, Flags = flags };
                                    if (claim != null) claim.Kept = f;
                                    kids.Add(f);
                                }
                                else { smallSize += size; smallCount++; }
                            }
                        }
                        if (next == 0) break;
                        off += next;
                    }
                }
                Interlocked.Add(ref FilesSeen, files);
                Interlocked.Add(ref BytesSeen, bytes);
                w.Node.SmallSize = smallSize;
                w.Node.SmallCount = smallCount;
                w.Node.Modified = newest;
                w.Node.Kids = kids.Count > 0 ? kids.ToArray() : null;
                if (subs.Count > 0)
                    lock (gate)
                    {
                        foreach (var s in subs) work.Push(s);
                        pending += subs.Count;
                        Monitor.PulseAll(gate);
                    }
            }
        }

        // Folder totals, children before parents, and every folder's contents biggest first.
        public static void Finish(Node root)
        {
            var order = new List<Node>();
            var stack = new Stack<Node>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                var n = stack.Pop();
                order.Add(n);
                if (n.Kids != null) foreach (var k in n.Kids) if (k.IsDir) stack.Push(k);
            }
            for (int i = order.Count - 1; i >= 0; i--)
            {
                var n = order[i];
                long size = n.SmallSize, files = n.SmallCount, newest = n.Modified;
                int dirs = 0;
                if (n.Kids != null)
                {
                    foreach (var k in n.Kids)
                    {
                        size += k.Size;
                        files += k.Files;
                        if (k.IsDir) dirs += 1 + k.Dirs;
                        if (k.Modified > newest) newest = k.Modified;
                    }
                    Array.Sort(n.Kids, (a, b) => b.Size.CompareTo(a.Size));
                }
                n.Size = size;
                n.Files = files;
                n.Dirs = dirs;
                n.Modified = newest;
            }
        }
    }

    // One link to a file big enough to track (files under 64 KB aren't worth it).
    sealed class LinkClaim
    {
        public Node Folder, Kept;   // Kept: the file's own node, when it's big enough to have one
        public string Name;
        public long Size;
        public string Path { get { string p = Folder.FullPath; return p.EndsWith("\\", StringComparison.Ordinal) ? p + Name : p + "\\" + Name; } }
    }

    // Which link of each file holds its space, shared by the scan threads (64 locks, so they rarely
    // wait on each other).
    sealed class LinkTable
    {
        readonly Dictionary<long, LinkClaim>[] parts = new Dictionary<long, LinkClaim>[64];
        public LinkTable() { for (int i = 0; i < parts.Length; i++) parts[i] = new Dictionary<long, LinkClaim>(); }

        // Records a link to file id. Returns the claim that doesn't get the space: null for the first
        // link seen, otherwise whichever of the two has the later path.
        public LinkClaim Resolve(long id, LinkClaim claim)
        {
            var part = parts[(int)(((ulong)id * 0x9E3779B97F4A7C15UL) >> 58)];
            lock (part)
            {
                LinkClaim prior;
                if (!part.TryGetValue(id, out prior)) { part[id] = claim; return null; }
                if (string.Compare(claim.Path, prior.Path, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    part[id] = claim;
                    return prior;
                }
                return claim;
            }
        }
    }

    static class FsNative
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, IntPtr buffer, int size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetCompressedFileSizeW(string name, out uint high);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetLongPathNameW(string shortPath, StringBuilder longPath, int size);

        // Expand short folder names in an existing path or before a wildcard so paths
        // display and compare consistently.
        public static string LongName(string path)
        {
            if (string.IsNullOrEmpty(path) || path.IndexOf('~') < 0) return path;
            int wild = path.IndexOfAny(new[] { '*', '?' });
            string head = path, tail = "";
            if (wild >= 0)
            {
                int cut = path.LastIndexOf('\\', wild);
                if (cut <= 0) return path;
                head = path.Substring(0, cut);
                tail = path.Substring(cut);
            }
            var sb = new StringBuilder(1024);
            int n = GetLongPathNameW(head, sb, sb.Capacity);
            return n > 0 && n < sb.Capacity ? sb.ToString() + tail : path;
        }

        public static string Long(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path.Substring(2);
            return @"\\?\" + path;
        }

        // A folder opened for listing: backup semantics (needed for folders; with the backup
        // privilege an admin scan can read any folder), and below the starting folder a junction is
        // opened as itself rather than followed.
        public static SafeFileHandle OpenDir(string path, bool follow)
        {
            uint flags = 0x02000000 | (follow ? 0u : 0x00200000u);
            return CreateFileW(Long(path), 0x1 /* FILE_LIST_DIRECTORY */, 0x7, IntPtr.Zero, 3, flags, IntPtr.Zero);
        }

        public static long SizeOnDisk(string path, long fallback)
        {
            uint high;
            uint low = GetCompressedFileSizeW(Long(path), out high);
            if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0) return fallback;
            return ((long)high << 32) | low;
        }
    }

    // Lets an elevated scan read every folder, the way backup programs do.
    static class Privilege
    {
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        struct TokenPrivileges { public int Count; public long Luid; public int Attributes; }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string system, string name, out long luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state, int length, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        public static bool EnableBackup()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out token)) return false;
            try
            {
                long luid;
                if (!LookupPrivilegeValue(null, "SeBackupPrivilege", out luid)) return false;
                var tp = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };
                if (!AdjustTokenPrivileges(token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() == 0;   // 1300: not all privileges were assigned
            }
            finally { Native.CloseHandle(token); }
        }
    }

    // Saved maps: %LOCALAPPDATA%\Olympus\atlas\maps\C.map for a drive, f-<hash>.map for a folder.
    static class MapFile
    {
        const string Magic = "ATLASMAP";
        const int Version = 1;

        public static string Dir { get { return Path.Combine(Suite.UserDir(AppId.Atlas), "maps"); } }

        public static string PathFor(string root)
        {
            string r = Scanner.NormalizeRoot(root);
            string key = r.Length == 3 ? r.Substring(0, 1).ToUpperInvariant() : "f-" + FileUtil.Sha256Text(r.ToLowerInvariant()).Substring(0, 16);
            return Path.Combine(Dir, key + ".map");
        }

        sealed class Frame { public Node Node; public int Next; }

        public static void Save(MapInfo m, string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string tmp = path + "." + System.Diagnostics.Process.GetCurrentProcess().Id + ".tmp";
            using (var fs = File.Create(tmp))
            using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
            using (var w = new BinaryWriter(gz, Encoding.UTF8))
            {
                w.Write(Magic);
                w.Write(Version);
                w.Write(m.RootPath);
                w.Write(m.ScannedUtc.Ticks);
                w.Write(m.Took.Ticks);
                w.Write(m.Elevated);
                w.Write(m.VolumeTotal);
                w.Write(m.VolumeFree);
                w.Write(m.DeniedDirs);
                w.Write(m.KeepFrom);
                var stack = new Stack<Node>();   // parents before children, children in order
                stack.Push(m.Root);
                while (stack.Count > 0)
                {
                    var n = stack.Pop();
                    w.Write(n.Name);
                    w.Write(n.Kind);
                    w.Write(n.Flags);
                    w.Write(n.Size);
                    w.Write(n.Files);
                    w.Write(n.Dirs);
                    w.Write(n.SmallSize);
                    w.Write(n.SmallCount);
                    w.Write(n.Modified);
                    int kids = n.Kids == null ? 0 : n.Kids.Length;
                    w.Write(kids);
                    for (int i = kids - 1; i >= 0; i--) stack.Push(n.Kids[i]);
                }
                w.Write(m.Types.Count);
                foreach (var kv in m.Types)
                {
                    w.Write(kv.Key);
                    w.Write(kv.Value.Count);
                    w.Write(kv.Value.Size);
                }
            }
            for (int i = 0; ; i++)
            {
                try
                {
                    if (File.Exists(path)) File.Replace(tmp, path, null, true);
                    else File.Move(tmp, path);
                    return;
                }
                catch (IOException)
                {
                    if (i >= 5) { FileUtil.TryDelete(tmp); throw; }
                    Thread.Sleep(50 * (i + 1));
                }
            }
        }

        public static MapInfo Load(string path)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var gz = new GZipStream(fs, CompressionMode.Decompress))
                using (var r = new BinaryReader(gz, Encoding.UTF8))
                {
                    if (r.ReadString() != Magic || r.ReadInt32() != Version) return null;
                    var m = new MapInfo
                    {
                        RootPath = r.ReadString(),
                        ScannedUtc = new DateTime(r.ReadInt64(), DateTimeKind.Utc),
                        Took = new TimeSpan(r.ReadInt64()),
                        Elevated = r.ReadBoolean(),
                        VolumeTotal = r.ReadInt64(),
                        VolumeFree = r.ReadInt64(),
                        DeniedDirs = r.ReadInt64(),
                        KeepFrom = r.ReadInt64()
                    };
                    int count;
                    m.Root = ReadNode(r, null, out count);
                    var stack = new Stack<Frame>();
                    if (count > 0) { m.Root.Kids = new Node[count]; stack.Push(new Frame { Node = m.Root }); }
                    while (stack.Count > 0)
                    {
                        var f = stack.Peek();
                        if (f.Next == f.Node.Kids.Length) { stack.Pop(); continue; }
                        var k = ReadNode(r, f.Node, out count);
                        f.Node.Kids[f.Next++] = k;
                        if (count > 0) { k.Kids = new Node[count]; stack.Push(new Frame { Node = k }); }
                    }
                    int types = r.ReadInt32();
                    for (int i = 0; i < types; i++)
                    {
                        string ext = r.ReadString();
                        m.Types[ext] = new ExtStat { Count = r.ReadInt64(), Size = r.ReadInt64() };
                    }
                    return m;
                }
            }
            catch (Exception e)
            {
                Log.Warn("couldn't read the map " + path + ": " + e.Message);
                return null;
            }
        }

        static Node ReadNode(BinaryReader r, Node parent, out int kids)
        {
            var n = new Node
            {
                Name = r.ReadString(), Parent = parent, Kind = r.ReadByte(), Flags = r.ReadByte(), Size = r.ReadInt64(),
                Files = r.ReadInt64(), Dirs = r.ReadInt32(), SmallSize = r.ReadInt64(), SmallCount = r.ReadInt32(), Modified = r.ReadInt64()
            };
            kids = r.ReadInt32();
            if (kids < 0 || kids > 50000000) throw new InvalidDataException("bad map");
            return n;
        }
    }
}
