// Who signed a program (Authenticode), including Windows files that are signed through
// security catalogs rather than inside the file.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Olympus
{
    public sealed class SignerInfo
    {
        public bool Signed, Trusted, Catalog;
        public string Publisher;
        public int Code;

        public string Describe()
        {
            if (Code == -1) return "file not found";
            if (!Signed) return "unsigned";
            return (Publisher ?? "unknown publisher") + (Trusted ? "" : " (signature not valid)");
        }
        public bool IsMicrosoft
        {
            get { return Trusted && Publisher != null && Publisher.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase); }
        }
    }

    static class Signature
    {
        static readonly Dictionary<string, KeyValuePair<long, SignerInfo>> cache =
            new Dictionary<string, KeyValuePair<long, SignerInfo>>(StringComparer.OrdinalIgnoreCase);
        static readonly object gate = new object();

        public static SignerInfo Check(string path)
        {
            if (string.IsNullOrEmpty(path)) return new SignerInfo { Code = -1 };
            long stamp;
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return new SignerInfo { Code = -1 };
                stamp = fi.LastWriteTimeUtc.Ticks ^ fi.Length;
            }
            catch (Exception) { return new SignerInfo { Code = -1 }; }
            lock (gate)
            {
                KeyValuePair<long, SignerInfo> hit;
                if (cache.TryGetValue(path, out hit) && hit.Key == stamp) return hit.Value;
            }
            var info = Embedded(path);
            if (!info.Signed)
            {
                var cat = ViaCatalog(path);
                if (cat != null) info = cat;
            }
            lock (gate) cache[path] = new KeyValuePair<long, SignerInfo>(stamp, info);
            return info;
        }

        static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_CATALOG_INFO
        {
            public int cbStruct;
            public int dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public int cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pInfo;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, int flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref int cbHash, [In, Out] byte[] hash, int flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] hash, int cbHash, int flags, IntPtr prevCatInfo);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO info, int flags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int flags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int flags);

        // No UI, no revocation checks, nothing fetched from the network: fast and quiet.
        static int Verify(int unionChoice, IntPtr info)
        {
            var d = new WINTRUST_DATA
            {
                cbStruct = Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,     // WTD_REVOKE_NONE
                dwUnionChoice = unionChoice, // 1 = file, 2 = catalog
                pInfo = info,
                dwProvFlags = 0x10 | 0x1000  // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            return WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref d);
        }

        static SignerInfo Embedded(string path)
        {
            var fi = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            try
            {
                Marshal.StructureToPtr(fi, p, false);
                int code;
                try { code = Verify(1, p); }
                finally { Marshal.DestroyStructure(p, typeof(WINTRUST_FILE_INFO)); }
                if (code == TRUST_E_NOSIGNATURE || code == TRUST_E_SUBJECT_FORM_UNKNOWN || code == TRUST_E_PROVIDER_UNKNOWN)
                    return new SignerInfo { Code = code };
                return new SignerInfo { Signed = true, Trusted = code == 0, Code = code, Publisher = PublisherOf(path) };
            }
            catch (Exception) { return new SignerInfo { Code = -2 }; }
            finally { Marshal.FreeHGlobal(p); }
        }

        static SignerInfo ViaCatalog(string path)
        {
            foreach (var alg in new[] { "SHA256", null })
            {
                var r = ViaCatalog(path, alg);
                if (r != null) return r;
            }
            return null;
        }

        static SignerInfo ViaCatalog(string path, string alg)
        {
            IntPtr admin;
            try { if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) return null; }
            catch (Exception) { return null; }
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    IntPtr h = fs.SafeFileHandle.DangerousGetHandle();
                    int n = 0;
                    CryptCATAdminCalcHashFromFileHandle2(admin, h, ref n, null, 0);
                    if (n <= 0 || n > 128) return null;
                    var hash = new byte[n];
                    if (!CryptCATAdminCalcHashFromFileHandle2(admin, h, ref n, hash, 0)) return null;
                    IntPtr cat = CryptCATAdminEnumCatalogFromHash(admin, hash, n, 0, IntPtr.Zero);
                    if (cat == IntPtr.Zero) return null;
                    try
                    {
                        var ci = new CATALOG_INFO { cbStruct = Marshal.SizeOf(typeof(CATALOG_INFO)) };
                        if (!CryptCATCatalogInfoFromContext(cat, ref ci, 0)) return null;
                        IntPtr hashPtr = Marshal.AllocHGlobal(n);
                        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                        try
                        {
                            Marshal.Copy(hash, 0, hashPtr, n);
                            var wci = new WINTRUST_CATALOG_INFO
                            {
                                cbStruct = Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)),
                                pcwszCatalogFilePath = ci.wszCatalogFile,
                                pcwszMemberTag = BitConverter.ToString(hash).Replace("-", ""),
                                pcwszMemberFilePath = path,
                                hMemberFile = h,
                                pbCalculatedFileHash = hashPtr,
                                cbCalculatedFileHash = n,
                                hCatAdmin = admin
                            };
                            Marshal.StructureToPtr(wci, p, false);
                            int code;
                            try { code = Verify(2, p); }
                            finally { Marshal.DestroyStructure(p, typeof(WINTRUST_CATALOG_INFO)); }
                            return new SignerInfo { Signed = true, Catalog = true, Trusted = code == 0, Code = code, Publisher = PublisherOf(ci.wszCatalogFile) };
                        }
                        finally { Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(hashPtr); }
                    }
                    finally { CryptCATAdminReleaseCatalogContext(admin, cat, 0); }
                }
            }
            catch (Exception) { return null; }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }

        static string PublisherOf(string signedFile)
        {
            try
            {
                using (var raw = X509Certificate.CreateFromSignedFile(signedFile))
                using (var c = new X509Certificate2(raw))
                {
                    string n = c.GetNameInfo(X509NameType.SimpleName, false);
                    return string.IsNullOrEmpty(n) ? c.Subject : n;
                }
            }
            catch (Exception) { return null; }
        }
    }
}
