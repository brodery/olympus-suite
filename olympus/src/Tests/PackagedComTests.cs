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
            T.True(PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid, data), "packaged COM: permits the known SoftLanding render data");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid, data.Replace("noOp", "open")), "packaged COM: rejects a different SoftLanding action");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid, data.Replace("CreativeId:18=123", "CreativeId:18=321")), "packaged COM: rejects a different creative ID");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid + "2", data), "packaged COM: rejects a mismatched principal");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid, data + "Extra:1=x;"), "packaged COM: rejects an extra field");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid, data.Replace("OverrideRule:4=none", "OverrideRule:5=none")), "packaged COM: rejects a wrong field length");

            // The same render shape under the Action Center name (seen 2026-11-21).
            const string center = "ActionCenterTriggerTask-128000000001627409-render-{0f9169c8-c2dd-485a-a641-eb8896903856}";
            string centerData = "TaskName:" + center.Length + "=" + center
                + ";CreativeId:18=128000000001627409;TriggerType:6=render;ActionName:4=noOp;OverrideRule:4=none;"
                + "TriggerId:0=;TriggerPredicate:0=;CorrelationId:38={0da7cdad-146f-46cf-b0ec-6589c5801f0b};";
            T.True(PackagedCom.IsRoutineSoftLanding(server, clsid, @"\SoftLanding\" + sid + "\\" + center, sid, centerData), "packaged COM: permits the Action Center render task");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, @"\SoftLanding\" + sid + "\\Evil" + center, sid, centerData), "packaged COM: rejects another task name");

            // The tip bubble Windows shows when the device is unlocked (seen 2026-11-21).
            const string tip = "SoftLandingTriggerTask-WW_128000000006420249_EN-US-systemStateChange-{6aa68d54-75a7-4279-8c42-749983fbc41e}";
            string tipPath = @"\SoftLanding\" + sid + "\\" + tip;
            string tipData = "TaskName:" + tip.Length + "=" + tip
                + ";CreativeId:27=WW_128000000006420249_EN-US;TriggerType:17=systemStateChange;ActionName:10=ShowBubble;OverrideRule:4=none;"
                + "TriggerId:24=WNF_SHEL_DEVICE_UNLOCKED;TriggerPredicate:0=;CorrelationId:38={c69c39b2-053e-48a5-9994-ea6a4ef4aeda};";
            T.True(PackagedCom.IsRoutineSoftLanding(server, clsid, tipPath, sid, tipData), "packaged COM: permits the unlock tip bubble");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, tipPath, sid, tipData.Replace("ActionName:10=ShowBubble", "ActionName:9=LaunchUri")), "packaged COM: rejects another action on unlock");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, tipPath, sid, tipData.Replace("TriggerId:24=WNF_SHEL_DEVICE_UNLOCKED", "TriggerId:23=WNF_SHEL_LOGON_COMPLETE")), "packaged COM: rejects another trigger");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, tipPath, sid, tipData.Replace("TriggerPredicate:0=", "TriggerPredicate:1=x")), "packaged COM: rejects a trigger predicate");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, path, sid, tipData), "packaged COM: rejects tip data on a render task");
            T.True(!PackagedCom.IsRoutineSoftLanding(server.Replace("SoftLandingTask.exe", "Other.exe"), clsid, tipPath, sid, tipData), "packaged COM: rejects another server");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, tipPath, sid, tipData.Replace("OverrideRule:4=none", "OverrideRule:04=none")), "packaged COM: rejects a zero-padded length");
            T.True(!PackagedCom.IsRoutineSoftLanding(server, clsid, tipPath, sid, tipData.Replace("CorrelationId:38={c69c39b2-053e-48a5-9994-ea6a4ef4aeda}", "CorrelationId:40= {c69c39b2-053e-48a5-9994-ea6a4ef4aeda} ")),
                "packaged COM: rejects a padded correlation ID");
            var fields = PackagedCom.ParseTaskData(tipData);
            T.True(fields != null && fields.Length == 8 && fields[5] == "WNF_SHEL_DEVICE_UNLOCKED", "packaged COM: parses the task data");
            T.True(PackagedCom.ParseTaskData(tipData.Substring(0, tipData.Length - 1)) == null, "packaged COM: rejects truncated data");
            T.True(PackagedCom.ParseTaskData("TaskName:99999=x;") == null, "packaged COM: rejects an impossible length");
        }
    }
}
