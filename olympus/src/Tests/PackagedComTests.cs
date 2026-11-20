using System;
using System.IO;
using Olympus.Argus;
using T = Olympus.Tests.TestMain;

namespace Olympus.Tests
{
    static class PackagedComTests
    {
        public static void Run()
        {
            string root = T.TempDir("argus-packaged-com");
            try
            {
                string package = Path.Combine(root, "package");
                string module = Path.Combine(package, @"handlers\server.exe");
                Directory.CreateDirectory(Path.GetDirectoryName(module));
                File.WriteAllText(module, "test fixture");
                T.Eq(module, PackagedCom.ResolveExecutable(package, @"handlers\server.exe"), "packaged COM: resolves an existing package-relative server");
                File.WriteAllText(Path.Combine(root, "outside.exe"), "test fixture");
                T.Eq<string>(null, PackagedCom.ResolveExecutable(package, @"..\outside.exe"), "packaged COM: rejects traversal");
                T.Eq<string>(null, PackagedCom.ResolveExecutable(package, module), "packaged COM: rejects rooted registration");
                T.Eq<string>(null, PackagedCom.ResolveExecutable(package, @"handlers\missing.exe"), "packaged COM: rejects a missing server");
                Directory.CreateDirectory(Path.Combine(package, "folder.exe"));
                T.Eq<string>(null, PackagedCom.ResolveExecutable(package, "folder.exe"), "packaged COM: rejects a directory as a server");
            }
            finally { T.Cleanup(root); }

            const string sid = "S-1-5-21-1-2-3-1001";
            const string clsid = "{F47D8C53-0B74-4A66-959D-367710AB1F84}";
            const string leaf = "SoftLandingTriggerTask-123456789012345678-render-{00000000-0000-0000-0000-000000000000}";
            string path = @"\SoftLanding\" + sid + "\\" + leaf;
            string server = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe");
            string data = "TaskName:" + leaf.Length + "=" + leaf
                + ";CreativeId:18=123456789012345678;TriggerType:6=render;ActionName:4=noOp;OverrideRule:4=none;"
                + "TriggerId:0=;TriggerPredicate:0=;CorrelationId:38={00000000-0000-0000-0000-000000000000};";
            T.True(PackagedCom.IsSoftLandingRender(server, clsid, path, sid, data), "packaged COM: permits the known SoftLanding render data");
            T.True(!PackagedCom.IsSoftLandingRender(server, clsid, path, sid, data.Replace("noOp", "open")), "packaged COM: rejects a different SoftLanding action");
            T.True(!PackagedCom.IsSoftLandingRender(server, clsid, path, sid, data.Replace("CreativeId:18=123", "CreativeId:18=321")), "packaged COM: rejects a different creative ID");
            T.True(!PackagedCom.IsSoftLandingRender(server, clsid, path, sid + "2", data), "packaged COM: rejects a mismatched principal");
        }
    }
}
