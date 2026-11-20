using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Olympus.Atlas
{
    static class PermanentDelete
    {
        const uint DeleteAccess = 0x10000, ReadAttributes = 0x80;
        const uint ShareRead = 1, ShareWrite = 2, OpenExisting = 3;
        const uint BackupSemantics = 0x02000000, OpenReparsePoint = 0x00200000;
        const int FileDispositionInfo = 4;

        // BY_HANDLE_FILE_INFORMATION. Keep the identity from the read-only pass so a
        // different file later placed at the same path cannot be deleted by the plan.
        [StructLayout(LayoutKind.Sequential)]
        struct FileIdentity
        {
            public FileAttributes Attributes;
            public uint CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint Volume, SizeHigh, SizeLow, LinkCount, IndexHigh, IndexLow;

            public bool IsDirectory { get { return (Attributes & FileAttributes.Directory) != 0; } }
            public long LastWrite { get { return ((long)WrittenHigh << 32) | WrittenLow; } }

            public bool Matches(FileIdentity current)
            {
                return IsDirectory == current.IsDirectory && Volume == current.Volume
                    && IndexHigh == current.IndexHigh && IndexLow == current.IndexLow
                    && CreatedHigh == current.CreatedHigh && CreatedLow == current.CreatedLow
                    && (IsDirectory || (LastWrite == current.LastWrite && SizeHigh == current.SizeHigh && SizeLow == current.SizeLow));
            }
        }

        sealed class Entry
        {
            public string Path;
            public FileIdentity Identity;
            public List<Entry> Children;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileIdentity info);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref byte info, uint size);

        public static void Remove(string path, bool isDirectory, DateTime expectedModifiedUtc)
        {
            ValidatePath(path);
            string reason = Safety.Refuse(path, isDirectory);
            if (reason != null) throw new InvalidOperationException("Atlas can't delete " + path + " because " + reason + ".");

            var parents = new Stack<string>();
            for (string parent = Path.GetDirectoryName(path); parent != null; parent = Path.GetDirectoryName(parent))
                parents.Push(parent);
            var guards = new Stack<SafeFileHandle>();
            try
            {
                // Open from the drive down without sharing delete access. Each checked
                // parent stays in place until both passes finish.
                foreach (string parent in parents)
                {
                    var guard = Open(parent, false, true);
                    guards.Push(guard);
                    Verify(guard, parent, true);
                }

                Entry selection = Preview(path, isDirectory, expectedModifiedUtc);
                Delete(selection);
            }
            finally
            {
                while (guards.Count > 0) guards.Pop().Dispose();
            }
        }

        static void ValidatePath(string path)
        {
            if (path == null || path.Length <= 3 || path[1] != ':' || path[2] != '\\'
                || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
                || path.IndexOfAny(new[] { ':', '*', '?' }, 2) >= 0
                || !path.Equals(Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)
                || path.EndsWith("\\", StringComparison.Ordinal))
                throw new InvalidOperationException("Atlas needs an exact file or folder path on a drive.");
        }

        static SafeFileHandle Open(string path, bool delete, bool directory)
        {
            uint access = ReadAttributes | (delete ? DeleteAccess : 0);
            uint share = ShareRead | (directory ? ShareWrite : 0);
            var handle = CreateFileW(FsNative.Long(path), access, share, IntPtr.Zero, OpenExisting,
                BackupSemantics | OpenReparsePoint, IntPtr.Zero);
            if (!handle.IsInvalid) return handle;

            int code = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw WindowsError(path, code);
        }

        static FileIdentity Verify(SafeFileHandle handle, string path, bool directory)
        {
            FileIdentity info;
            if (!GetFileInformationByHandle(handle, out info))
                throw WindowsError(path, Marshal.GetLastWin32Error());
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Atlas can't permanently delete through " + path + " because it is a link or reparse point.");
            if (info.IsDirectory != directory)
                throw new InvalidOperationException("The file or folder type changed at " + path + ". Rescan before deleting.");
            if (!info.IsDirectory && (info.Attributes & FileAttributes.ReadOnly) != 0)
                throw new InvalidOperationException(path + " is read-only.");

            // Reject redirected drives and other aliases that would make the protected
            // folder checks look at a different path than Windows opened.
            var resolved = new StringBuilder(path.Length + 16);
            uint length = GetFinalPathNameByHandleW(handle, resolved, (uint)resolved.Capacity, 0);
            if (length == 0) throw WindowsError(path, Marshal.GetLastWin32Error());
            if (length >= resolved.Capacity ||
                !resolved.ToString().TrimEnd('\\').Equals(FsNative.Long(path).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Atlas can't confirm the exact location of " + path + ".");
            return info;
        }

        static Entry Preview(string path, bool directory, DateTime expectedModifiedUtc)
        {
            using (var handle = Open(path, !directory, directory))
            {
                var item = new Entry { Path = path, Identity = Verify(handle, path, directory) };
                if (!directory && expectedModifiedUtc != DateTime.MinValue && item.Identity.LastWrite != expectedModifiedUtc.ToFileTimeUtc())
                    throw new InvalidOperationException(path + " changed since Atlas mapped it. Rescan before deleting.");
                if (!directory) return item;

                item.Children = new List<Entry>();
                foreach (var child in new DirectoryInfo(path).EnumerateFileSystemInfos())
                    item.Children.Add(Preview(child.FullName, child is DirectoryInfo, DateTime.MinValue));
                return item;
            }
        }

        static void Delete(Entry entry)
        {
            using (var handle = Open(entry.Path, true, entry.Identity.IsDirectory))
            {
                var current = Verify(handle, entry.Path, entry.Identity.IsDirectory);
                if (!entry.Identity.Matches(current))
                    throw new InvalidOperationException(entry.Path + " changed while Atlas was preparing the deletion. Rescan before deleting.");
                if (entry.Children != null)
                    foreach (var child in entry.Children)
                        Delete(child);

                // This is nonrecursive for directories. Windows refuses the removal
                // if new entries appeared and the directory is no longer empty.
                byte delete = 1;
                if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref delete, 1))
                    throw WindowsError(entry.Path, Marshal.GetLastWin32Error());
            }
        }

        static IOException WindowsError(string path, int code)
        {
            var detail = new Win32Exception(code);
            return new IOException("Windows couldn't access or delete " + path + ". " + detail.Message, detail);
        }
    }
}
