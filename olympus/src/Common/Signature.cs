// Who signed a program (Authenticode), including Windows files that are signed through
// security catalogs rather than inside the file. The signer is read from WinTrust's own
// verification state, so it is the certificate that produced the verdict.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Olympus
{
    public sealed class SignerInfo
    {
        public bool Signed, Trusted, Catalog;
        public string Publisher;
        // The verified signer's identity (SHA-256, hex) over the signing certificate's subject name and its
        // issuing CA's public key, both taken from the chain WinTrust verified. It survives a renewal by the
        // same CA key and differs for a look-alike name or another CA (two CAs can share a name, not a key).
        // Null unless the signature verified.
        public string Id;
        // From the same verified chain (null unless it verified): the issuing CA's name, and the thumbprint of the
        // root it ends at.
        public string Issuer, Root;
        public int Code;

        public string Describe()
        {
            if (Code == -1) return "file not found";
            if (!Signed) return "unsigned";
            return (Publisher ?? "unknown publisher") + (Trusted ? "" : " (signature not valid)");
        }
        // Microsoft's own code: see Signature.IsMicrosoftCode.
        public bool IsMicrosoft
        {
            get { return Trusted && !string.IsNullOrEmpty(Id) && Signature.IsMicrosoftCode(Publisher, Issuer, Root); }
        }
    }

    static class Signature
    {
        // A publisher name of Microsoft's own code. Not the names Microsoft signs other companies' code under:
        // "Microsoft Windows Hardware Compatibility Publisher" (WHQL and attestation-signed third-party drivers,
        // and the catalogs of their packages; attackers have had malicious drivers signed that way) and the
        // "Third Party" / "3rd Party" component signers.
        public static bool IsMicrosoftPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher) || !publisher.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)) return false;
            return publisher.IndexOf("Hardware Compatibility", StringComparison.OrdinalIgnoreCase) < 0
                && publisher.IndexOf("Third Party", StringComparison.OrdinalIgnoreCase) < 0
                && publisher.IndexOf("3rd Party", StringComparison.OrdinalIgnoreCase) < 0;
        }

        // The roots Microsoft signs its own products under (thumbprints, checked against this PC's trusted root
        // store on 2026-11-21: every Microsoft-named signature surveyed here ends at one of the first three).
        // Not its Identity Verification root (Trusted Signing: other companies' code), its TLS or time-stamp
        // roots, nor any root an organisation adds (which could issue a certificate with any name).
        static readonly HashSet<string> MicrosoftProductRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "3B1EFD3A66EA28B16697394703A72CA340A05BD5",   // Microsoft Root Certificate Authority 2010
            "8F43288AD272F3103B6FB1428485EA3014C0BCFE",   // Microsoft Root Certificate Authority 2011
            "CDD4EEAE6000AC7F40C3802C171E30148030C072",   // Microsoft Root Certificate Authority (2001)
            "A43489159A520F0D93D032CCAF37E7FE20A8B419",   // Microsoft Root Authority (older signatures)
            "06F1AA330B927B753A40E68CDF22E34BCBEF3352"    // Microsoft ECC Product Root Certificate Authority 2018
        };

        // Microsoft's own code, judged from the verified chain: a Microsoft publisher name (not WHQL or a
        // third-party component signer), not issued by a "Third Party" CA (WHQL's chain ends at the 2010 root
        // too), and ending at one of Microsoft's product roots. The issuing CA's name isn't otherwise checked:
        // Microsoft's own vary ("Windows Production PCA 2023", "Microsoft Windows Production PCA 2026 ...").
        public static bool IsMicrosoftCode(string publisher, string issuer, string root)
        {
            return IsMicrosoftPublisher(publisher) && !string.IsNullOrEmpty(root) && MicrosoftProductRoots.Contains(root)
                && (issuer == null || issuer.IndexOf("Third Party", StringComparison.OrdinalIgnoreCase) < 0);
        }

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
            var info = Verify(path, null);
            lock (gate) cache[path] = new KeyValuePair<long, SignerInfo>(stamp, info);
            return info;
        }

        // Like Check, without the cache: for decisions that must judge the file as it is right now.
        public static SignerInfo CheckNow(string path)
        {
            try { if (string.IsNullOrEmpty(path) || !File.Exists(path)) return new SignerInfo { Code = -1 }; }
            catch (Exception) { return new SignerInfo { Code = -1 }; }
            return Verify(path, null);
        }

        // Verifies the file through a handle the caller holds open (Versioned.Protect's Leaf), so the bytes
        // judged are the ones the caller has locked against change. Uncached.
        public static SignerInfo CheckHeld(string path, SafeFileHandle handle)
        {
            if (string.IsNullOrEmpty(path) || handle == null || handle.IsInvalid || handle.IsClosed) return new SignerInfo { Code = -1 };
            return Verify(path, handle);
        }

        static SignerInfo Verify(string path, SafeFileHandle held)
        {
            var info = Embedded(path, held);
            if (!info.Signed)
            {
                var cat = ViaCatalog(path, held);
                if (cat != null) info = cat;
            }
            return info;
        }

        static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
        const int StateVerify = 1, StateClose = 2;

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

        // wintrust.h: the signer WinTrust verified and its certificate chain (leaf first).
        [StructLayout(LayoutKind.Sequential)]
        struct CRYPT_PROVIDER_SGNR
        {
            public int cbStruct;
            public System.Runtime.InteropServices.ComTypes.FILETIME sftVerifyAsOf;
            public int csCertChain;
            public IntPtr pasCertChain;
            public int dwSignerType;
            public IntPtr psSigner;
            public int dwError;
            public int csCounterSigners;
            public IntPtr pasCounterSigners;
            public IntPtr pChainContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CRYPT_PROVIDER_CERT
        {
            public int cbStruct;
            public IntPtr pCert;
            public int fCommercial, fTrustedRoot, fSelfSigned, fTestCert, dwRevokedReason, dwConfidence, dwError;
            public IntPtr pTrustListContext;
            public int fTrustListSignerCert;
            public IntPtr pCtlContext;
            public int dwCtlError, fIsCyclic;
            public IntPtr pChainElement;
        }

        [DllImport("wintrust.dll", ExactSpelling = true)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);
        [DllImport("wintrust.dll", ExactSpelling = true)]
        static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);
        [DllImport("wintrust.dll", ExactSpelling = true)]
        static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, int signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, int counterSignerIndex);
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

        // No UI, no revocation checks, nothing fetched from the network: fast and quiet. The signer and
        // its identity come from the same verification (WinTrust's state data), then the state is closed.
        static int Verify(int unionChoice, IntPtr info, out string publisher, out string id, out string issuer, out string root)
        {
            publisher = id = issuer = root = null;
            var d = new WINTRUST_DATA
            {
                cbStruct = Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,     // WTD_REVOKE_NONE
                dwUnionChoice = unionChoice, // 1 = file, 2 = catalog
                pInfo = info,
                dwStateAction = StateVerify,
                dwProvFlags = 0x10 | 0x1000  // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            int code = WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref d);
            try { ReadSigner(d.hWVTStateData, code == 0, out publisher, out id, out issuer, out root); }
            catch (Exception) { }
            finally
            {
                d.dwStateAction = StateClose;
                try { WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref d); } catch (Exception) { }
            }
            return code;
        }

        // The leaf's name always; for a verified chain also its identity, the issuing CA's name and the root's
        // thumbprint (the last certificate of the chain WinTrust built).
        static void ReadSigner(IntPtr state, bool verified, out string publisher, out string id, out string issuerName, out string root)
        {
            publisher = id = issuerName = root = null;
            if (state == IntPtr.Zero) return;
            IntPtr prov = WTHelperProvDataFromStateData(state);
            if (prov == IntPtr.Zero) return;
            IntPtr sp = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
            if (sp == IntPtr.Zero) return;
            var signer = (CRYPT_PROVIDER_SGNR)Marshal.PtrToStructure(sp, typeof(CRYPT_PROVIDER_SGNR));
            if (signer.csCertChain < 1 || signer.pasCertChain == IntPtr.Zero) return;
            var first = (CRYPT_PROVIDER_CERT)Marshal.PtrToStructure(signer.pasCertChain, typeof(CRYPT_PROVIDER_CERT));
            if (first.pCert == IntPtr.Zero) return;
            using (var leaf = new X509Certificate2(first.pCert))
            {
                string n = leaf.GetNameInfo(X509NameType.SimpleName, false);
                publisher = string.IsNullOrEmpty(n) ? leaf.Subject : n;
                if (!verified || signer.csCertChain < 2) return;
                int stride = first.cbStruct >= Marshal.SizeOf(typeof(CRYPT_PROVIDER_CERT)) ? first.cbStruct : Marshal.SizeOf(typeof(CRYPT_PROVIDER_CERT));
                var second = (CRYPT_PROVIDER_CERT)Marshal.PtrToStructure(new IntPtr(signer.pasCertChain.ToInt64() + stride), typeof(CRYPT_PROVIDER_CERT));
                if (second.pCert == IntPtr.Zero) return;
                using (var issuer = new X509Certificate2(second.pCert))
                {
                    id = IdOf(leaf.SubjectName.RawData, KeyOf(issuer));
                    issuerName = issuer.GetNameInfo(X509NameType.SimpleName, false);
                }
                var last = (CRYPT_PROVIDER_CERT)Marshal.PtrToStructure(new IntPtr(signer.pasCertChain.ToInt64() + (long)stride * (signer.csCertChain - 1)), typeof(CRYPT_PROVIDER_CERT));
                if (last.pCert != IntPtr.Zero)
                    using (var top = new X509Certificate2(last.pCert)) root = top.Thumbprint;
            }
        }

        // The issuing CA's public key with its algorithm and parameters.
        static byte[] KeyOf(X509Certificate2 ca)
        {
            var k = ca.PublicKey;
            var alg = Encoding.ASCII.GetBytes(k.Oid == null ? "" : k.Oid.Value ?? "");
            var parameters = k.EncodedParameters == null ? new byte[0] : k.EncodedParameters.RawData;
            var key = k.EncodedKeyValue.RawData;
            var all = new byte[alg.Length + 1 + parameters.Length + 1 + key.Length];
            Buffer.BlockCopy(alg, 0, all, 0, alg.Length);
            Buffer.BlockCopy(parameters, 0, all, alg.Length + 1, parameters.Length);
            Buffer.BlockCopy(key, 0, all, alg.Length + 1 + parameters.Length + 1, key.Length);
            return all;
        }

        internal static string IdOf(byte[] subject, byte[] issuerKey)
        {
            if (subject == null || issuerKey == null || subject.Length == 0 || issuerKey.Length == 0) return null;
            var both = new byte[subject.Length + 1 + issuerKey.Length];
            Buffer.BlockCopy(subject, 0, both, 0, subject.Length);
            Buffer.BlockCopy(issuerKey, 0, both, subject.Length + 1, issuerKey.Length);
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(both)).Replace("-", "").ToLowerInvariant();
        }

        static SignerInfo Embedded(string path, SafeFileHandle held)
        {
            var fi = new WINTRUST_FILE_INFO
            {
                cbStruct = Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path,
                hFile = held == null ? IntPtr.Zero : held.DangerousGetHandle()
            };
            IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            try
            {
                Marshal.StructureToPtr(fi, p, false);
                int code;
                string publisher, id, issuer, root;
                try { code = Verify(1, p, out publisher, out id, out issuer, out root); }
                finally { Marshal.DestroyStructure(p, typeof(WINTRUST_FILE_INFO)); GC.KeepAlive(held); }
                if (code == TRUST_E_NOSIGNATURE || code == TRUST_E_SUBJECT_FORM_UNKNOWN || code == TRUST_E_PROVIDER_UNKNOWN)
                    return new SignerInfo { Code = code };
                if (publisher == null) publisher = PublisherOf(path);   // display only: no identity without WinTrust's chain
                return new SignerInfo { Signed = true, Trusted = code == 0, Code = code, Publisher = publisher, Id = code == 0 ? id : null,
                    Issuer = code == 0 ? issuer : null, Root = code == 0 ? root : null };
            }
            catch (Exception) { return new SignerInfo { Code = -2 }; }
            finally { Marshal.FreeHGlobal(p); }
        }

        static SignerInfo ViaCatalog(string path, SafeFileHandle held)
        {
            foreach (var alg in new[] { "SHA256", null })
            {
                var r = ViaCatalog(path, held, alg);
                if (r != null) return r;
            }
            return null;
        }

        static SignerInfo ViaCatalog(string path, SafeFileHandle held, string alg)
        {
            IntPtr admin;
            try { if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) return null; }
            catch (Exception) { return null; }
            FileStream own = null;
            try
            {
                if (held == null) own = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                IntPtr h = held != null ? held.DangerousGetHandle() : own.SafeFileHandle.DangerousGetHandle();
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
                        string publisher, id, issuer, root;
                        try { code = Verify(2, p, out publisher, out id, out issuer, out root); }
                        finally { Marshal.DestroyStructure(p, typeof(WINTRUST_CATALOG_INFO)); }
                        if (publisher == null) publisher = PublisherOf(ci.wszCatalogFile);
                        return new SignerInfo { Signed = true, Catalog = true, Trusted = code == 0, Code = code, Publisher = publisher, Id = code == 0 ? id : null,
                            Issuer = code == 0 ? issuer : null, Root = code == 0 ? root : null };
                    }
                    finally { Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(hashPtr); }
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, cat, 0); }
            }
            catch (Exception) { return null; }
            finally
            {
                if (own != null) own.Dispose();
                GC.KeepAlive(held);
                CryptCATAdminReleaseContext(admin, 0);
            }
        }

        // A display name when WinTrust's state had no signer (an invalid signature, for instance).
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
