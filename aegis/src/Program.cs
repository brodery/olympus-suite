// Aegis entry point. One source tree, three builds (see build.ps1):
//   Aegis.exe        tray icon + window + command line      (default build)
//   AegisEngine.exe  the background DNS filter               (/define:ENGINE)
//   AegisTests.exe   unit tests and live checks              (/define:TESTS)
using System;
using System.Reflection;
using System.Runtime.InteropServices;

#if ENGINE
[assembly: AssemblyTitle("Aegis DNS filter engine")]
#elif TESTS
[assembly: AssemblyTitle("Aegis tests")]
#else
[assembly: AssemblyTitle("Aegis DNS filter")]
#endif
[assembly: AssemblyProduct("Aegis")]
[assembly: AssemblyDescription("Blocks ad, tracker and malware sites by filtering DNS lookups")]
[assembly: AssemblyCompany("Aegis")]
[assembly: AssemblyCopyright("Built on this PC")]
[assembly: AssemblyVersion("1.0.1.0")]
[assembly: AssemblyFileVersion("1.0.1.0")]
[assembly: AssemblyInformationalVersion("1.0.1")]
[assembly: ComVisible(false)]

namespace Aegis
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
#if ENGINE
            return EngineHost.Run(args);
#elif TESTS
            return Tests.Run(args);
#else
            if (args.Length >= 2 && args[0] == "--make-icon")
            {
                IconArt.WriteIco(args[1], Shield.On, new[] { 16, 20, 24, 32, 40, 48, 64, 256 });
                return 0;
            }
            if (args.Length >= 2 && args[0] == "--make-preview")
            {
                IconArt.WritePreview(args[1]);
                return 0;
            }
            if (args.Length >= 2 && args[0] == "--snapshot")
            {
                try { NativeDpi.SetProcessDPIAware(); } catch { }
                return MainWindow.Snapshot(args[1]);
            }
            if (args.Length >= 1 && args[0] == "--exit") return TrayApp.SignalExit();
            if (args.Length >= 1 && Cli.IsCommand(args[0])) return Cli.Run(args);
            bool trayOnly = args.Length >= 1 && args[0].Equals("--tray", StringComparison.OrdinalIgnoreCase);
            return TrayApp.Run(!trayOnly);
#endif
        }
    }
}
