// OlympusTests.exe: unit tests for the shared core and every app (build.ps1 runs them).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Olympus.Tests
{
    static class TestMain
    {
        static int passed, failed;
        static string current = "";

        public static void Eq<T>(T expected, T actual, string what)
        {
            if (Equals(expected, actual)) passed++;
            else { failed++; Console.WriteLine("FAIL [" + current + "] " + what + ": expected <" + expected + ">, got <" + actual + ">"); }
        }
        public static void True(bool cond, string what)
        {
            if (cond) passed++;
            else { failed++; Console.WriteLine("FAIL [" + current + "] " + what); }
        }

        public static string TempDir(string name)
        {
            string d = Path.Combine(Path.GetTempPath(), "olympus-tests", name + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(d);
            return d;
        }
        public static void Cleanup(string dir)
        {
            try
            {
                foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*", SearchOption.AllDirectories)) f.Attributes = FileAttributes.Normal;
                Directory.Delete(dir, true);
            }
            catch (Exception) { }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint Attrs, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

        public static int LinkCount(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                BY_HANDLE_FILE_INFORMATION i;
                return GetFileInformationByHandle(fs.SafeFileHandle, out i) ? (int)i.Links : -1;
            }
        }

        static int Main(string[] args)
        {
            AppStart.Init(AppId.Olympus, false);
            // Log to a scratch file, not the hub's real log: tests clean temp folders and feed bad maps on purpose.
            try { Log.Open(Path.Combine(Path.GetTempPath(), "olympus-tests"), "tests"); } catch (Exception) { }
            var suites = new List<KeyValuePair<string, Action>>
            {
                new KeyValuePair<string, Action>("core", CoreTests.Run),
                new KeyValuePair<string, Action>("ark", ArkTests.Run),
                new KeyValuePair<string, Action>("argus", ArgusTests.Run),
                new KeyValuePair<string, Action>("argus-alert-review", ArgusAlertReviewTests.Run),
                new KeyValuePair<string, Action>("packaged-com", PackagedComTests.Run),
                new KeyValuePair<string, Action>("sibyl", SibylTests.Run),
                new KeyValuePair<string, Action>("later", LaterTests.Run),
                new KeyValuePair<string, Action>("atlas", AtlasTests.Run),
            };
            foreach (var s in suites)
            {
                if (args.Length > 0 && !args.Contains(s.Key)) continue;
                current = s.Key;
                try { s.Value(); }
                catch (Exception e) { failed++; Console.WriteLine("FAIL [" + s.Key + "] threw " + e); }
            }
            Console.WriteLine("Unit tests: " + passed + " passed, " + failed + " failed.");
            return failed == 0 ? 0 : 1;
        }
    }

}
