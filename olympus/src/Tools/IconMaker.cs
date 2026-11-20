// Build helper: writes every app's .ico and a preview sheet (used by build.ps1).
using System;
using System.IO;

namespace Olympus.Tools
{
    static class IconMaker
    {
        static int Main(string[] args)
        {
            string dir = args.Length > 0 ? args[0] : "assets";
            Directory.CreateDirectory(dir);
            foreach (var app in AppInfo.All)
                IconArt.WriteIco(Path.Combine(dir, app.Key + ".ico"), app.Id);
            IconArt.WritePreview(Path.Combine(dir, "icons-preview.png"));
            Console.WriteLine("Wrote " + AppInfo.All.Length + " icons and icons-preview.png to " + dir);
            return 0;
        }
    }
}
