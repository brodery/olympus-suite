// Sibyl.exe: the checker window (Ctrl+Alt+L in the hub opens it on whatever you copied),
// and "Sibyl.exe check TEXT" on the command line.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Olympus.Sibyl
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            string first = (a.First ?? "").ToLowerInvariant();
            bool cli = first == "check" || first == "help" || first == "--help" || first == "/?";
            AppStart.Init(AppId.Sibyl, !cli);
            if (cli) { Cli.Attach(); return SibylCli.Run(a); }
            string initial = null;
            if (a.Has("--clipboard")) { try { initial = Clipboard.GetText(); } catch (Exception) { } }
            else if (a.Count > 0 && !a.First.StartsWith("--")) initial = a.Rest(0);
            string show = a.Opt("--show");
            if (string.IsNullOrWhiteSpace(initial)) initial = null;
            return AppWindow.Run(args, initial != null ? "check:" + initial : show, () => new SibylWindow());
        }
    }

    // A link on its own gets the link checks; anything else is treated as a message
    // (and the links inside it are checked too).
    sealed class Result
    {
        public string Input, Verdict, Headline;
        public LinkReport Link;
        public MessageReport Message;
        public List<LinkReport> Inner = new List<LinkReport>();
        public List<Flag> Flags = new List<Flag>();
    }

    static class Checker
    {
        public static bool IsLink(string s)
        {
            s = (s ?? "").Trim();
            return s.Length > 0 && !Regex.IsMatch(s, @"\s") && Links.Normalize(s) != null;
        }

        public static Result Run(string input, bool network)
        {
            var r = new Result { Input = input };
            if (IsLink(input))
            {
                r.Link = Links.Check(input.Trim(), network);
                r.Flags.AddRange(r.Link.Flags);
                r.Verdict = r.Link.Verdict;
            }
            else
            {
                r.Message = Scam.Check(input);
                r.Flags.AddRange(r.Message.Flags.Where(f => f.Level != "good"));
                int worst = r.Message.Verdict == "dangerous" ? 2 : r.Message.Verdict == "suspicious" ? 1 : 0;
                foreach (var url in r.Message.Links.Take(4))
                {
                    var lr = Links.Check(url, network);
                    r.Inner.Add(lr);
                    int w = lr.Verdict == "dangerous" ? 2 : lr.Verdict == "suspicious" ? 1 : 0;
                    worst = Math.Max(worst, w);
                    r.Flags.Add(new Flag { Level = w == 2 ? "bad" : w == 1 ? "warn" : "info", Text = "Link " + (lr.FinalHost ?? url) + ": " + Word(lr.Verdict) + (lr.Flags.Count > 0 ? " — " + string.Join("; ", lr.Flags.Where(f => f.Level == "bad" || f.Level == "warn").Select(f => f.Text).Take(2)) : "") });
                }
                if (r.Flags.Count == 0) r.Flags.AddRange(r.Message.Flags);
                r.Verdict = worst == 2 ? "dangerous" : worst == 1 ? "suspicious" : "ok";
            }
            r.Headline = r.Verdict == "dangerous" ? "Dangerous — don't open it, don't reply with anything personal"
                       : r.Verdict == "suspicious" ? "Suspicious — be careful"
                       : r.Verdict == "ok" ? "No warning signs found" : "Nothing to check";
            return r;
        }

        public static string Word(string verdict)
        {
            switch (verdict) { case "dangerous": return "dangerous"; case "suspicious": return "suspicious"; case "ok": return "no warning signs"; default: return "unknown"; }
        }
    }

    static class SibylCli
    {
        public static int Run(Args a)
        {
            if (a.First.ToLowerInvariant() != "check" || a.Count < 2)
            {
                Cli.Out("Sibyl link and scam checker - commands:\n  Sibyl.exe                    open the checker\n  Sibyl.exe --clipboard        open it on whatever you copied (the hub's Ctrl+Alt+L)\n  Sibyl.exe check LINK|TEXT    check from the command line\nFrom PowerShell, add | Out-String so the output waits for the command.");
                return 0;
            }
            var r = Checker.Run(a.Rest(1), true);
            Cli.Out(r.Headline.ToUpperInvariant());
            foreach (var f in r.Flags) Cli.Out("  [" + f.Level + "] " + f.Text);
            var link = r.Link;
            if (link != null)
            {
                Cli.Out("Path:");
                foreach (var h in link.Hops) Cli.Out("  " + h.Host + "  " + (h.Note ?? "") + "  (Aegis: " + (h.Aegis ?? "-") + ")");
                if (link.Registered != DateTime.MinValue) Cli.Out("Registered: " + link.Registered.ToString("yyyy-MM-dd") + (link.Registrar != null ? " via " + link.Registrar : ""));
                if (link.CertIssuer != null) Cli.Out("Certificate: " + link.CertIssuer + ", issued " + link.CertFrom.ToString("yyyy-MM-dd"));
            }
            return r.Verdict == "dangerous" ? 2 : r.Verdict == "suspicious" ? 1 : 0;
        }
    }
}
