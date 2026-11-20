// Arachne's tripwire. Setup (run by install.cmd, elevated) turns on Windows' "File System" audit
// for successful reads and puts an audit entry on the files listed in arachne.ini (next to the
// exe): the files password-stealers go after, plus decoys nobody should ever open. Windows then
// logs event 4663, with the reading program's path, whenever one is read. The engine (SYSTEM)
// reads those events and alerts when the reader isn't one of the file's owners.
//
// The list lives in arachne.ini rather than in this program, so it can be edited and so the
// program itself doesn't carry a stealer-like list of file names (antivirus heuristics react to that).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Olympus.Arachne
{
    public sealed class Target
    {
        public string Path, Kind, Label, Content;
        public bool Folder, Decoy, CreatedByUs;
    }

    public sealed class SetupState
    {
        public string Time, PreviousAudit, User;
        public List<Target> Targets = new List<Target>();
    }

    // arachne.ini, parsed: owners per kind, readers allowed everywhere, files to watch, decoys.
    sealed class Catalog
    {
        public Dictionary<string, List<string>> Owners = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public List<string> Everyone = new List<string>();
        public List<Target> Watch = new List<Target>();     // paths still contain {tokens} and wildcards
        public List<Target> Decoys = new List<Target>();
        public Dictionary<string, string> Unless = new Dictionary<string, string>();   // decoy path -> folder that cancels it

        public static string FilePath { get { return System.IO.Path.Combine(Suite.BinDir, "arachne.ini"); } }

        public static Catalog Load() { return Parse(File.Exists(FilePath) ? File.ReadAllText(FilePath) : "", Suite.User); }

        public static Catalog Parse(string text, UserContext u)
        {
            var c = new Catalog();
            var ini = Ini.Parse(text);
            foreach (var sec in ini.Sections)
            {
                if (sec.StartsWith("kind:", StringComparison.OrdinalIgnoreCase))
                {
                    string kind = sec.Substring(5).Trim();
                    c.Owners[kind] = ini.All(sec, "owner").Select(o => Tokens(o, u)).ToList();
                    foreach (var f in ini.All(sec, "file")) c.Watch.Add(Entry(f, kind, false, u));
                    foreach (var f in ini.All(sec, "folder")) c.Watch.Add(Entry(f, kind, true, u));
                }
                else if (sec.Equals("everyone", StringComparison.OrdinalIgnoreCase))
                    c.Everyone.AddRange(ini.All(sec, "owner").Select(o => Tokens(o, u)));
                else if (sec.StartsWith("decoy:", StringComparison.OrdinalIgnoreCase))
                {
                    string f = ini.Get(sec, "file", null);
                    if (f == null) continue;
                    var t = Entry(f, "decoy", false, u);
                    t.Decoy = true;
                    t.Content = ini.Get(sec, "content", "").Replace("\\n", "\r\n");
                    c.Decoys.Add(t);
                    string unless = ini.Get(sec, "unless", null);
                    if (unless != null) c.Unless[t.Path] = Tokens(unless, u);
                }
            }
            if (!c.Owners.ContainsKey("decoy")) c.Owners["decoy"] = new List<string>();
            return c;
        }

        static Target Entry(string value, string kind, bool folder, UserContext u)
        {
            var parts = value.Split(new[] { '|' }, 2);
            return new Target { Path = Tokens(parts[0].Trim(), u), Label = parts.Length > 1 ? parts[1].Trim() : System.IO.Path.GetFileName(parts[0].Trim()), Kind = kind, Folder = folder };
        }

        public static string Tokens(string s, UserContext u)
        {
            return s.Replace("{local}", u.Local ?? "").Replace("{roaming}", u.Roaming ?? "").Replace("{documents}", u.Documents ?? "")
                    .Replace("{profile}", u.Profile ?? "").Replace("{pf}", @"C:\Program Files").Replace("{pf86}", @"C:\Program Files (x86)")
                    .Replace("{programdata}", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        }

        // A watch pattern turned into the files that exist now ({profiles} and "*" walked).
        public static List<Target> Expand(Target pattern)
        {
            var found = new List<Target>();
            var segs = pattern.Path.Split('\\');
            Walk(pattern, segs, 1, segs[0], null, found);
            return found;
        }

        static void Walk(Target pattern, string[] segs, int i, string at, string name, List<Target> found)
        {
            if (i == segs.Length)
            {
                if (pattern.Folder ? Directory.Exists(at) : File.Exists(at))
                    found.Add(new Target { Path = at, Kind = pattern.Kind, Folder = pattern.Folder, Label = pattern.Label.Replace("{name}", name ?? "") });
                return;
            }
            string seg = segs[i];
            if (seg == "{profiles}" || seg.Contains("*"))
            {
                if (!Directory.Exists(at)) return;
                foreach (var d in Directory.GetDirectories(at))
                {
                    string n = System.IO.Path.GetFileName(d);
                    bool ok = seg == "{profiles}" ? (n == "Default" || n.StartsWith("Profile ")) : Tripwire.Matches(seg, n);
                    if (ok) Walk(pattern, segs, i + 1, d, seg == "{profiles}" ? n : name, found);
                }
                return;
            }
            Walk(pattern, segs, i + 1, at + "\\" + seg, name, found);
        }

        public List<Target> Targets()
        {
            var list = new List<Target>();
            foreach (var w in Watch) list.AddRange(Expand(w));
            return list;
        }

        // A decoy is skipped where a real app of that name lives, but a folder that holds only our
        // own decoy isn't a real app (on a re-install it would otherwise hide the decoy we placed).
        public List<Target> DecoysToPlace(SetupState old = null)
        {
            return Decoys.Where(d => { string u; return !Unless.TryGetValue(d.Path, out u) || !Directory.Exists(u) || Ours(d, old); }).ToList();
        }

        // Ours: recorded as ours by the last setup, or hidden, kept out of Search and starting with our template.
        public static bool Ours(Target d, SetupState old)
        {
            if (old != null && old.Targets.Any(x => x.Decoy && x.CreatedByUs && x.Path.Equals(d.Path, StringComparison.OrdinalIgnoreCase))) return true;
            try
            {
                if (!File.Exists(d.Path)) return false;
                var attrs = File.GetAttributes(d.Path);
                if ((attrs & FileAttributes.Hidden) == 0 || (attrs & FileAttributes.NotContentIndexed) == 0) return false;
                string prefix = (d.Content ?? "").Split(new[] { "{random}" }, StringSplitOptions.None)[0];
                if (prefix.Length < 10) return false;
                using (var r = new StreamReader(d.Path))
                {
                    var buf = new char[prefix.Length];
                    int n = r.ReadBlock(buf, 0, buf.Length);
                    return new string(buf, 0, n) == prefix;
                }
            }
            catch (Exception) { return false; }
        }
    }

    static class Tripwire
    {
        public const string AuditGuid = "{0CCE921D-69AE-11D9-BED3-505054503030}";   // "File System" audit subcategory
        public static string SetupFile { get { return System.IO.Path.Combine(Suite.SharedDir(AppId.Arachne), "setup.json"); } }
        public static string AllowFile { get { return System.IO.Path.Combine(Suite.SharedDir(AppId.Arachne), "allow.json"); } }

        // "*" matches within one folder name only.
        public static bool Matches(string pattern, string path)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(pattern)) return false;
            return Regex.IsMatch(path, "^" + Regex.Escape(pattern).Replace(@"\*", @"[^\\]*") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        public static Dictionary<string, List<string>> LoadAllow()
        {
            return J.Load<Dictionary<string, List<string>>>(AllowFile) ?? new Dictionary<string, List<string>>();
        }

        public static bool Allowed(Catalog cat, string kind, string program, Dictionary<string, List<string>> extra)
        {
            if (string.IsNullOrEmpty(program) || program == "-" || program.Equals("System", StringComparison.OrdinalIgnoreCase) || program.Equals("Registry", StringComparison.OrdinalIgnoreCase)) return true;
            if (cat.Everyone.Any(p => Matches(p, program))) return true;
            List<string> owners;
            if (cat.Owners.TryGetValue(kind, out owners) && owners.Any(p => Matches(p, program))) return true;
            if (kind == "decoy" && program.EndsWith(@"\explorer.exe", StringComparison.OrdinalIgnoreCase)) return true;   // the preview pane
            List<string> mine;
            return extra != null && extra.TryGetValue(kind, out mine) && mine.Any(p => string.Equals(p, program, StringComparison.OrdinalIgnoreCase));
        }

        static string Fill(string template)
        {
            var rnd = new Random();
            var sb = new StringBuilder();
            int start = 0, at;
            while ((at = template.IndexOf("{random}", start, StringComparison.Ordinal)) >= 0)
            {
                sb.Append(template, start, at - start);
                for (int i = 0; i < 16; i++) sb.Append("0123456789abcdefghjkmnpqrstuvwxyz"[rnd.Next(33)]);
                start = at + 8;
            }
            sb.Append(template.Substring(start));
            return sb.ToString();
        }

        static FileSystemAuditRule Rule(bool folder)
        {
            return new FileSystemAuditRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadData,
                folder ? InheritanceFlags.ObjectInherit : InheritanceFlags.None, PropagationFlags.None, AuditFlags.Success);
        }

        static void Audit(Target t, bool add)
        {
            if (t.Folder)
            {
                var ds = Directory.GetAccessControl(t.Path, AccessControlSections.Audit);
                if (add) ds.AddAuditRule(Rule(true)); else ds.RemoveAuditRuleSpecific(Rule(true));
                Directory.SetAccessControl(t.Path, ds);
            }
            else
            {
                var fs = File.GetAccessControl(t.Path, AccessControlSections.Audit);
                if (add) fs.AddAuditRule(Rule(false)); else fs.RemoveAuditRuleSpecific(Rule(false));
                File.SetAccessControl(t.Path, fs);
            }
        }

        static string AuditSetting()
        {
            string o;
            Proc.Run("auditpol.exe", "/get /subcategory:" + AuditGuid + " /r", out o, 15000);
            var line = o.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.IndexOf(AuditGuid, StringComparison.OrdinalIgnoreCase) >= 0);
            if (line == null) return null;
            var parts = line.Split(',');
            return parts.Length >= 5 ? parts[4].Trim() : null;
        }

        // Elevated (install.cmd). Returns a short report.
        public static string Setup()
        {
            if (!Elevation.IsElevated) throw new InvalidOperationException("Setting up the tripwire needs admin rights.");
            if (!File.Exists(Catalog.FilePath)) throw new FileNotFoundException("arachne.ini is missing next to Arachne.exe.");
            var u = Suite.User;
            var cat = Catalog.Load();
            var old = J.Load<SetupState>(SetupFile);
            if (old != null) { try { Teardown(true); } catch (Exception e) { Log.Warn("clearing the old setup: " + e.Message); } }
            var st = new SetupState { Time = Clock.NowIso(), User = u.Name, PreviousAudit = old != null ? old.PreviousAudit : AuditSetting() };
            string o;
            int code = Proc.Run("auditpol.exe", "/set /subcategory:" + AuditGuid + " /success:enable", out o, 15000);
            if (code != 0) throw new InvalidOperationException("auditpol: " + o.Trim());
            var targets = cat.Targets();
            foreach (var d in cat.DecoysToPlace(old))
            {
                try
                {
                    if (!File.Exists(d.Path))
                    {
                        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(d.Path));
                        File.WriteAllText(d.Path, Fill(d.Content ?? ""));
                        File.SetAttributes(d.Path, FileAttributes.Hidden | FileAttributes.NotContentIndexed);
                        d.CreatedByUs = true;
                    }
                    else d.CreatedByUs = Catalog.Ours(d, old);
                    targets.Add(d);
                }
                catch (Exception e) { Log.Warn("decoy " + d.Path + ": " + e.Message); }
            }
            int ok = 0;
            foreach (var t in targets)
            {
                try { Audit(t, true); st.Targets.Add(t); ok++; }
                catch (Exception e) { Log.Warn("audit entry on " + t.Path + ": " + e.Message); }
            }
            J.Save(SetupFile, st);
            Log.Info("tripwire set on " + ok + " files (" + st.Targets.Count(x => x.Decoy) + " decoys); File System audit was '" + st.PreviousAudit + "'");
            return "Watching " + ok + " files, including " + st.Targets.Count(x => x.Decoy) + " decoys.";
        }

        // Elevated (uninstall.cmd): removes the audit entries and decoys and puts the audit policy back.
        // keepPolicy: used when setting up again, which changes the policy itself.
        public static string Teardown(bool keepPolicy = false)
        {
            if (!Elevation.IsElevated) throw new InvalidOperationException("Removing the tripwire needs admin rights.");
            var st = J.Load<SetupState>(SetupFile);
            if (st == null) return "The tripwire wasn't set up.";
            int removed = 0;
            foreach (var t in st.Targets)
            {
                try
                {
                    if (t.Folder ? Directory.Exists(t.Path) : File.Exists(t.Path)) { Audit(t, false); removed++; }
                    if (t.Decoy && t.CreatedByUs && File.Exists(t.Path) && !keepPolicy)
                    {
                        File.SetAttributes(t.Path, FileAttributes.Normal);
                        File.Delete(t.Path);
                        string dir = System.IO.Path.GetDirectoryName(t.Path);
                        string documents = Suite.User.Documents ?? "\u0000", roaming = Suite.User.Roaming ?? "\u0000";
                        while (dir != null && dir.StartsWith(roaming + "\\", StringComparison.OrdinalIgnoreCase) && Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                        {
                            Directory.Delete(dir);
                            dir = System.IO.Path.GetDirectoryName(dir);
                        }
                    }
                }
                catch (Exception e) { Log.Warn("removing the tripwire from " + t.Path + ": " + e.Message); }
            }
            if (!keepPolicy)
            {
                if (st.PreviousAudit != null && !st.PreviousAudit.StartsWith("Success", StringComparison.OrdinalIgnoreCase))
                {
                    string o;
                    Proc.Run("auditpol.exe", "/set /subcategory:" + AuditGuid + " /success:disable", out o, 15000);
                }
                FileUtil.TryDelete(SetupFile);
            }
            return "Removed the tripwire from " + removed + " files.";
        }

        // ------------------------------------------------------------------ reading event 4663

        static readonly Regex DataRx = new Regex("<Data Name='(\\w+)'>([^<]*)</Data>");

        public static Dictionary<string, string> Fields(string xml)
        {
            var d = new Dictionary<string, string>();
            foreach (Match m in DataRx.Matches(xml ?? "")) d[m.Groups[1].Value] = System.Net.WebUtility.HtmlDecode(m.Groups[2].Value);
            return d;
        }

        public static Target Find(List<Target> targets, string objectName)
        {
            if (string.IsNullOrEmpty(objectName)) return null;
            foreach (var t in targets)
                if (t.Folder ? objectName.StartsWith(t.Path.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) : objectName.Equals(t.Path, StringComparison.OrdinalIgnoreCase)) return t;
            return null;
        }
    }
}
