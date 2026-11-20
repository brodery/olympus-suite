// Sibyl's link checks: look-alike and disguised domains, wrapper links (Outlook, Google,
// Facebook...), redirects followed with plain requests (no browser, no scripts), Aegis's
// verdict on every site along the way, the domain's age (RDAP) and its certificate.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace Olympus.Sibyl
{
    public sealed class Flag
    {
        public int Weight;
        public string Level, Text;   // good | info | warn | bad
    }

    public sealed class Hop
    {
        public string Url, Host, Note, Aegis;
        public int Status;
    }

    public sealed class LinkReport
    {
        public string Input, Final, FinalHost, Registrable, Verdict, CertIssuer, Registrar;
        public int Score;
        public DateTime Registered = DateTime.MinValue, CertFrom = DateTime.MinValue;
        public bool AegisBlocks;
        public List<Hop> Hops = new List<Hop>();
        public List<Flag> Flags = new List<Flag>();

        public void Add(int weight, string level, string text)
        {
            if (Flags.Any(f => f.Text == text)) return;
            Flags.Add(new Flag { Weight = weight, Level = level, Text = text });
            Score += weight;
        }
    }

    // The public suffix list ("co.uk", "github.io"...), to find the part of a name someone registered.
    static class Psl
    {
        static HashSet<string> rules, wild, except;
        const string Builtin = "com net org edu gov mil int info biz io co me tv us uk ca au de fr jp cn ru br in it es nl se no fi dk pl ch at be cz gr pt ie nz za mx ar kr tw hk sg my id th vn ph tr ua il ae sa eg ng ke " +
                               "co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au co.nz co.jp co.kr com.br com.mx com.ar co.za com.cn com.hk com.sg com.tr co.in co.id com.my com.ph " +
                               "github.io gitlab.io blogspot.com herokuapp.com netlify.app vercel.app pages.dev web.app firebaseapp.com azurewebsites.net cloudfront.net appspot.com " +
                               "workers.dev glitch.me repl.co ngrok.io ngrok-free.app duckdns.org no-ip.org ddns.net weebly.com wixsite.com square.site myshopify.com";

        static string FilePath { get { return Path.Combine(Suite.UserDir(AppId.Sibyl), "public_suffix_list.dat"); } }

        static void Load()
        {
            if (rules != null) return;
            rules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            wild = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            except = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string text = null;
            try
            {
                var fi = new FileInfo(FilePath);
                if (!fi.Exists || DateTime.UtcNow - fi.LastWriteTimeUtc > TimeSpan.FromDays(30))
                {
                    using (var wc = new WebClient())
                    {
                        wc.Headers[HttpRequestHeader.UserAgent] = "Olympus-Sibyl/1.0";
                        string fresh = wc.DownloadString("https://publicsuffix.org/list/public_suffix_list.dat");
                        if (fresh.Length > 100000) FileUtil.WriteAtomic(FilePath, fresh);
                    }
                }
                if (File.Exists(FilePath)) text = File.ReadAllText(FilePath);
            }
            catch (Exception e) { Log.Warn("public suffix list: " + e.Message); }
            foreach (var raw in (text ?? Builtin.Replace(' ', '\n')).Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("//")) continue;
                line = line.Split(' ')[0];
                try { line = string.Join(".", line.Split('.').Select(l => l == "*" || l.StartsWith("!") ? l : new IdnMapping().GetAscii(l))); } catch (Exception) { }
                if (line.StartsWith("!")) except.Add(line.Substring(1));
                else if (line.StartsWith("*.")) wild.Add(line.Substring(2));
                else rules.Add(line);
            }
        }

        public static void UseBuiltinForTests()
        {
            rules = new HashSet<string>(Builtin.Split(' '), StringComparer.OrdinalIgnoreCase);
            wild = new HashSet<string>(new[] { "ck" }, StringComparer.OrdinalIgnoreCase);
            except = new HashSet<string>(new[] { "www.ck" }, StringComparer.OrdinalIgnoreCase);
        }

        public static string Registrable(string host)
        {
            Load();
            host = (host ?? "").ToLowerInvariant().TrimEnd('.');
            var labels = host.Split('.');
            if (labels.Length < 2) return host;
            int suffix = 1;
            for (int i = 0; i < labels.Length; i++)
            {
                string cand = string.Join(".", labels, i, labels.Length - i);
                if (except.Contains(cand)) { suffix = labels.Length - i - 1; break; }
                if (rules.Contains(cand)) { suffix = labels.Length - i; break; }
                if (i + 1 < labels.Length && wild.Contains(string.Join(".", labels, i + 1, labels.Length - i - 1))) { suffix = labels.Length - i; break; }
            }
            if (labels.Length <= suffix) return host;
            return string.Join(".", labels, labels.Length - suffix - 1, suffix + 1);
        }
    }

    static class Lookalike
    {
        // Brands scammers imitate most, with the domains they really use.
        public static readonly string[][] Brands =
        {
            new[] { "PayPal", "paypal.com", "paypal.me" }, new[] { "eBay", "ebay.com", "ebay.co.uk", "ebaystatic.com" },
            new[] { "Amazon", "amazon.com", "amazon.co.uk", "amazon.ca" }, new[] { "Apple", "apple.com", "icloud.com" },
            new[] { "Microsoft", "microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "xbox.com" },
            new[] { "Google", "google.com", "gmail.com", "youtube.com", "goo.gl" }, new[] { "Facebook", "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com" },
            new[] { "Netflix", "netflix.com" }, new[] { "Steam", "steampowered.com", "steamcommunity.com", "steamstatic.com" },
            new[] { "Discord", "discord.com", "discord.gg", "discordapp.com" }, new[] { "Roblox", "roblox.com" }, new[] { "Epic Games", "epicgames.com" },
            new[] { "Battle.net", "battle.net", "blizzard.com" }, new[] { "Riot Games", "riotgames.com", "leagueoflegends.com" }, new[] { "Twitch", "twitch.tv" },
            new[] { "Coinbase", "coinbase.com" }, new[] { "Binance", "binance.com" }, new[] { "MetaMask", "metamask.io" }, new[] { "Kraken", "kraken.com" },
            new[] { "Chase", "chase.com" }, new[] { "Bank of America", "bankofamerica.com" }, new[] { "Wells Fargo", "wellsfargo.com" },
            new[] { "Capital One", "capitalone.com" }, new[] { "American Express", "americanexpress.com" }, new[] { "Citi", "citi.com" },
            new[] { "Venmo", "venmo.com" }, new[] { "Cash App", "cash.app" }, new[] { "Zelle", "zellepay.com" },
            new[] { "USPS", "usps.com" }, new[] { "UPS", "ups.com" }, new[] { "FedEx", "fedex.com" }, new[] { "DHL", "dhl.com" },
            new[] { "IRS", "irs.gov" }, new[] { "Verizon", "verizon.com" }, new[] { "AT&T", "att.com" }, new[] { "T-Mobile", "t-mobile.com" },
            new[] { "Hinge", "hinge.co" }, new[] { "Tinder", "tinder.com" }, new[] { "LinkedIn", "linkedin.com" }, new[] { "Dropbox", "dropbox.com" },
            new[] { "DocuSign", "docusign.com", "docusign.net" }, new[] { "Adobe", "adobe.com" }, new[] { "Walmart", "walmart.com" }, new[] { "Best Buy", "bestbuy.com" }
        };

        static readonly Dictionary<char, char> Confusable = new Dictionary<char, char>
        {
            { 'а', 'a' }, { 'е', 'e' }, { 'о', 'o' }, { 'р', 'p' }, { 'с', 'c' }, { 'у', 'y' }, { 'х', 'x' },
            { 'і', 'i' }, { 'ј', 'j' }, { 'ԁ', 'd' }, { 'ӏ', 'l' }, { 'ѕ', 's' }, { 'һ', 'h' }, { 'ɡ', 'g' },
            { 'ο', 'o' }, { 'α', 'a' }, { 'ν', 'v' }, { 'ρ', 'p' }, { 'τ', 't' }, { 'ι', 'i' }, { 'κ', 'k' },
            { '0', 'o' }, { '1', 'l' }, { '3', 'e' }, { '4', 'a' }, { '5', 's' }, { '7', 't' }, { '8', 'b' }, { 'i', 'l' }, { '|', 'l' }
        };

        // What a name looks like at a glance: digits and foreign letters folded into Latin ones.
        public static string Skeleton(string s)
        {
            var sb = new StringBuilder();
            foreach (char ch in s.ToLowerInvariant())
            {
                char m;
                sb.Append(Confusable.TryGetValue(ch, out m) ? m : ch);
            }
            return sb.ToString().Replace("rn", "m").Replace("vv", "w").Replace("cl", "d").Replace("-", "");
        }

        public static int Distance(string a, string b)
        {
            var d = new int[a.Length + 1, b.Length + 1];
            for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
            for (int j = 0; j <= b.Length; j++) d[0, j] = j;
            for (int i = 1; i <= a.Length; i++)
                for (int j = 1; j <= b.Length; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                    if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
                }
            return d[a.Length, b.Length];
        }

        static string Label(string registrable) { int dot = registrable.IndexOf('.'); return dot < 0 ? registrable : registrable.Substring(0, dot); }

        // The brand a host imitates, or null. "how" explains the trick.
        public static string Imitates(string host, string unicodeHost, out string how)
        {
            how = null;
            string reg = Psl.Registrable(host);
            foreach (var b in Brands)
                for (int i = 1; i < b.Length; i++)
                    if (reg.Equals(b[i], StringComparison.OrdinalIgnoreCase)) return null;   // it IS the brand
            string label = Label(reg);
            string uniLabel = Label(Psl.Registrable(unicodeHost ?? host));
            foreach (var b in Brands)
            {
                for (int i = 1; i < b.Length; i++)
                {
                    string brandLabel = Label(b[i]);
                    if (brandLabel.Length < 4) continue;
                    if (Skeleton(uniLabel) == Skeleton(brandLabel) && uniLabel != brandLabel) { how = "it's spelled to look like " + b[i] + " (" + uniLabel + ")"; return b[0]; }
                    int dist = Distance(label, brandLabel);
                    if (dist > 0 && (dist == 1 && brandLabel.Length >= 5 || dist == 2 && brandLabel.Length >= 8)) { how = "it's one or two letters off " + b[i]; return b[0]; }
                    // the brand as one word of a longer name: paypal-secure, paypa1login, secure-ebay-help
                    string bs = Skeleton(brandLabel);
                    foreach (var token in uniLabel.Split('-', '_', '.'))
                    {
                        string ts = Skeleton(token);
                        if (ts.Length == 0 || token == uniLabel && ts == bs) continue;
                        if (ts == bs || (bs.Length >= 6 && ts.Length > bs.Length && ts.StartsWith(bs)) || (bs.Length >= 6 && Distance(ts, bs) == 1))
                        {
                            how = "it uses the " + b[0] + " name inside a different domain (" + reg + ")";
                            return b[0];
                        }
                    }
                    string sub = host.Length > reg.Length ? host.Substring(0, host.Length - reg.Length) : "";
                    if (sub.Contains(b[i] + ".") || sub.Contains(brandLabel + "-") || sub.StartsWith(brandLabel + ".")) { how = "\"" + b[i] + "\" is only the start of the address; the real site is " + reg; return b[0]; }
                }
            }
            return null;
        }
    }

    static class Links
    {
        static readonly HashSet<string> Shorteners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
            "t.ly", "s.id", "v.gd", "bl.ink", "short.io", "lnkd.in", "qrco.de", "shorturl.com", "tr.ee", "linktr.ee", "x.co", "u.to", "clck.ru"
        };
        static readonly HashSet<string> RiskyTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam", "support", "monster", "quest",
            "sbs", "cfd", "bond", "icu", "buzz", "live", "shop", "online", "site", "fun", "lol", "win", "loan", "date", "racing", "review", "cyou", "bar"
        };
        static readonly Regex Bait = new Regex(@"login|log-in|signin|sign-in|verify|verification|secure|account|update|wallet|gift|prize|claim|reward|bonus|free|nitro|unlock|suspend|confirm|billing|invoice|refund|support|recover|password", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public static string Normalize(string s)
        {
            s = (s ?? "").Trim().Trim('<', '>', '"', '\'', '(', ')', '[', ']');
            if (s.Length == 0) return null;
            if (!Regex.IsMatch(s, @"^[a-z][a-z0-9+.\-]*://", RegexOptions.IgnoreCase))
            {
                if (Regex.IsMatch(s, @"^[^\s/]+\.[a-z]{2,}([/:?#].*)?$", RegexOptions.IgnoreCase)) s = "http://" + s;
                else return null;
            }
            Uri u;
            return Uri.TryCreate(s, UriKind.Absolute, out u) && (u.Scheme == "http" || u.Scheme == "https") ? u.AbsoluteUri : null;
        }

        public static List<string> Find(string text)
        {
            var found = new List<string>();
            foreach (Match m in Regex.Matches(text ?? "", @"(https?://[^\s<>""']+|www\.[^\s<>""']+|\b[a-z0-9][a-z0-9\-]*(\.[a-z0-9\-]+)*\.(com|net|org|xyz|top|io|co|me|ru|info|app|link|ly|gg|tv|shop|site|online|live|click)(/[^\s<>""']*)?)", RegexOptions.IgnoreCase))
            {
                string n = Normalize(m.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')'));
                if (n != null && !found.Contains(n)) found.Add(n);
            }
            return found;
        }

        // Wrapper links that just point at another address: read it out without visiting.
        public static string Unwrap(Uri u)
        {
            string host = u.Host.ToLowerInvariant();
            var q = HttpUtility.ParseQueryString(u.Query);
            string inner = null;
            if (host.EndsWith("safelinks.protection.outlook.com")) inner = q["url"];
            else if ((host == "www.google.com" || host == "google.com") && u.AbsolutePath == "/url") inner = q["q"] ?? q["url"];
            else if (host == "l.facebook.com" || host == "lm.facebook.com" || host == "l.instagram.com") inner = q["u"];
            else if ((host == "www.youtube.com" || host == "youtube.com") && u.AbsolutePath == "/redirect") inner = q["q"];
            else if (host == "out.reddit.com") inner = q["url"];
            else if (host.EndsWith("urldefense.com") || host.EndsWith("urldefense.proofpoint.com")) inner = q["u"];
            else if (host == "steamcommunity.com" && u.AbsolutePath.StartsWith("/linkfilter")) inner = q["url"] ?? q["u"];
            return inner != null ? Normalize(inner) : null;
        }

        static string Ascii(string host)
        {
            try { return new IdnMapping().GetAscii(host); } catch (Exception) { return host; }
        }
        static string Unicode(string host)
        {
            try { return new IdnMapping().GetUnicode(host); } catch (Exception) { return host; }
        }

        // Everything that can be said about a link without visiting it.
        public static void Static(LinkReport r, Uri u, bool first, bool schemeTyped = true)
        {
            string host = Ascii(u.Host.ToLowerInvariant().TrimEnd('.'));
            string uni = Unicode(host);
            string reg = Psl.Registrable(host);
            if (first && u.UserInfo.Length > 0) r.Add(40, "bad", "The part before \"@\" (" + u.UserInfo + ") is a decoy: the link really goes to " + host);
            IPAddress ip;
            if (IPAddress.TryParse(host.Trim('[', ']'), out ip)) r.Add(20, "warn", "It points at a bare IP address (" + host + ") instead of a named site");
            if (host.Contains("xn--") || uni.Any(c => c > 127))
            {
                bool mixed = Regex.IsMatch(uni, @"[a-z]") && Regex.IsMatch(uni, @"[Ͱ-ϿЀ-ӿ]");
                r.Add(mixed ? 45 : 15, mixed ? "bad" : "warn", mixed ? "It mixes Latin with Greek or Cyrillic letters (" + uni + "), a classic disguise" : "It uses non-English letters: it's really " + uni);
            }
            string how;
            string brand = Lookalike.Imitates(host, uni, out how);
            if (brand != null) r.Add(50, "bad", "Looks like " + brand + " but isn't: " + how);
            string tld = host.Substring(host.LastIndexOf('.') + 1);
            if (RiskyTlds.Contains(tld)) r.Add(10, "warn", "." + tld + " domains are cheap and heavily used by scammers");
            if (host.Split('.').Length > 4) r.Add(5, "info", "Very long address with many parts (" + host + ")");
            if (u.Scheme == "http" && schemeTyped && !Shorteners.Contains(reg)) r.Add(Bait.IsMatch(u.AbsoluteUri) ? 12 : 4, "info", "Not encrypted (http, not https)");
            int bait = Bait.Matches(host + u.AbsolutePath).Count;
            if (bait > 0 && brand == null && !Lookalike.Brands.Any(b => b.Skip(1).Any(d => reg == d))) r.Add(Math.Min(15, 5 * bait), "info", "Uses bait words like login, verify, gift or account");
            if (Shorteners.Contains(reg)) r.Add(0, "info", "A link shortener (" + reg + "): Sibyl follows it to see where it really goes");
            if (Regex.IsMatch(u.AbsolutePath, @"\.(exe|scr|msi|bat|cmd|js|vbs|hta|ps1|zip|rar|7z|iso|img|apk|lnk)$", RegexOptions.IgnoreCase)) r.Add(25, "warn", "It downloads a file (" + Path.GetFileName(u.AbsolutePath) + ")");
        }

        static readonly Regex MetaRefresh = new Regex(@"<meta[^>]+http-equiv\s*=\s*[""']?refresh[^>]*content\s*=\s*[""']?\s*\d+\s*;\s*url\s*=\s*([^""'>\s]+)", RegexOptions.IgnoreCase);
        static readonly Regex JsRedirect = new Regex(@"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*[""']([^""']+)[""']|location\.replace\(\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);

        public static LinkReport Check(string input, bool network)
        {
            var r = new LinkReport { Input = input };
            string url = Normalize(input);
            if (url == null) { r.Verdict = "unknown"; r.Add(0, "info", "That doesn't look like a web address."); return r; }
            var seen = new HashSet<string>();
            X509Certificate lastCert = null;
            bool fetchFailed = false;
            bool typed = Regex.IsMatch(input.Trim(), @"^[a-z][a-z0-9+.\-]*://", RegexOptions.IgnoreCase);
            for (int hop = 0; hop < 10 && url != null; hop++)
            {
                if (!seen.Add(url)) { r.Add(10, "warn", "The redirects go round in a loop"); break; }
                var u = new Uri(url);
                Static(r, u, hop == 0, hop > 0 || typed);
                var h = new Hop { Url = url, Host = Ascii(u.Host.ToLowerInvariant()) };
                r.Hops.Add(h);
                string inner = Unwrap(u);
                if (inner != null) { h.Note = "wrapper link (read without visiting)"; url = inner; continue; }
                // Aegis first: a blocked site isn't visited at all
                string rule;
                string verdict = AegisClient.Verdict(h.Host, out rule);
                if (verdict == "block")
                {
                    h.Aegis = "blocked" + (rule != null ? " (" + rule + ")" : "");
                    r.AegisBlocks = true;
                    r.Add(60, "bad", "Aegis blocks " + h.Host + (rule != null && rule != h.Host ? " (listed as " + rule + ")" : "") + ": it's on a malware, scam or tracker list");
                    break;
                }
                h.Aegis = verdict == null ? "Aegis not answering" : verdict == "allow" ? "allowed by your list" : "not listed";
                if (!network) break;
                string next;
                int status;
                string note;
                X509Certificate cert;
                Fetch(url, out status, out next, out note, out cert);
                h.Status = status;
                h.Note = note;
                if (status == 0)
                {
                    fetchFailed = true;
                    r.Add(0, "warn", "Couldn't finish checking " + h.Host + " (" + note + ").");
                }
                if (cert != null) lastCert = cert;
                if (next == null) break;
                url = next;
            }
            var last = r.Hops.LastOrDefault();
            r.Final = last == null ? url : last.Url;
            r.FinalHost = last == null ? null : last.Host;
            if (r.FinalHost != null) r.Registrable = Psl.Registrable(r.FinalHost);
            var domains = r.Hops.Select(x => Psl.Registrable(x.Host)).Distinct().ToList();
            if (domains.Count >= 4) r.Add(10, "warn", "It bounces through " + domains.Count + " different sites before landing");
            if (network && r.Registrable != null && !r.AegisBlocks) Age(r);
            if (lastCert != null)
            {
                try
                {
                    using (var c2 = new X509Certificate2(lastCert))
                    {
                        r.CertIssuer = c2.GetNameInfo(X509NameType.SimpleName, true);
                        r.CertFrom = c2.NotBefore.ToUniversalTime();
                        double days = (DateTime.UtcNow - r.CertFrom).TotalDays;
                        if (days < 7) r.Add(10, "warn", "Its security certificate was issued only " + Math.Max(0, (int)days) + " days ago");
                    }
                }
                catch (Exception) { }
            }
            r.Verdict = r.AegisBlocks || r.Score >= 60 ? "dangerous" : fetchFailed || r.Score >= 25 ? "suspicious" : "ok";
            if (r.Verdict == "ok" && r.Flags.All(f => f.Level != "bad" && f.Level != "warn"))
                r.Add(0, "good", "No warning signs found. That isn't a guarantee, so still don't type passwords into a page you reached from a message.");
            return r;
        }

        static void Fetch(string url, out int status, out string next, out string note, out X509Certificate cert)
        {
            status = 0;
            next = null;
            note = null;
            cert = null;
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.AllowAutoRedirect = false;
                req.Method = "GET";
                req.Timeout = 8000;
                req.ReadWriteTimeout = 8000;
                req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
                req.Accept = "text/html,*/*;q=0.8";
                req.AddRange(0, 65535);
                HttpWebResponse resp;
                try { resp = (HttpWebResponse)req.GetResponse(); }
                catch (WebException we)
                {
                    resp = we.Response as HttpWebResponse;
                    if (resp == null)
                    {
                        if (we.Status == WebExceptionStatus.TrustFailure) note = "the site's HTTPS certificate could not be verified";
                        else if (we.Status == WebExceptionStatus.NameResolutionFailure) note = "the site's name could not be resolved";
                        else note = "connection failed (" + we.Status + ")";
                        return;
                    }
                }
                using (resp)
                {
                    status = (int)resp.StatusCode;
                    try { cert = req.ServicePoint.Certificate; } catch (Exception) { }
                    string loc = resp.Headers["Location"];
                    if (status >= 300 && status < 400 && !string.IsNullOrEmpty(loc))
                    {
                        next = Normalize(new Uri(new Uri(url), loc).AbsoluteUri);
                        note = "redirects (" + status + ")";
                        return;
                    }
                    string type = resp.ContentType ?? "";
                    if (type.StartsWith("text/html", StringComparison.OrdinalIgnoreCase))
                    {
                        string body;
                        using (var s = resp.GetResponseStream())
                        {
                            var buf = new byte[65536];
                            int n = 0, got;
                            while (n < buf.Length && (got = s.Read(buf, n, buf.Length - n)) > 0) n += got;
                            body = Encoding.UTF8.GetString(buf, 0, n);
                        }
                        var m = MetaRefresh.Match(body);
                        var js = m.Success ? null : JsRedirect.Match(body);
                        string target = m.Success ? m.Groups[1].Value : js != null && js.Success ? (js.Groups[1].Success && js.Groups[1].Length > 0 ? js.Groups[1].Value : js.Groups[2].Value) : null;
                        if (!string.IsNullOrEmpty(target) && !target.StartsWith("#") && !target.StartsWith("javascript", StringComparison.OrdinalIgnoreCase))
                        {
                            try { next = Normalize(new Uri(new Uri(url), WebUtility.HtmlDecode(target)).AbsoluteUri); note = m.Success ? "page refresh to another address" : "script sends you on"; } catch (Exception) { }
                        }
                        else note = "page (" + status + ")";
                        if (Regex.IsMatch(body, @"type\s*=\s*[""']?password", RegexOptions.IgnoreCase)) note += ", asks for a password";
                    }
                    else note = (type.Length > 0 ? type.Split(';')[0] : "content") + " (" + status + ")";
                }
            }
            catch (Exception e) { status = 0; note = e.Message; }
        }

        sealed class AgeCache
        {
            public Dictionary<string, string[]> Domains = new Dictionary<string, string[]>();
        }

        static void Age(LinkReport r)
        {
            string path = Path.Combine(Suite.UserDir(AppId.Sibyl), "rdap-cache.json");
            var cache = J.Load<AgeCache>(path) ?? new AgeCache();
            string[] hit;
            if (cache.Domains.TryGetValue(r.Registrable, out hit) && hit.Length >= 3 && DateTime.UtcNow - Clock.Parse(hit[2]) < TimeSpan.FromDays(7))
            {
                r.Registered = Clock.Parse(hit[0]);
                r.Registrar = hit[1];
            }
            else
            {
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create("https://rdap.org/domain/" + r.Registrable);
                    req.Timeout = 9000;
                    req.UserAgent = "Olympus-Sibyl/1.0";
                    req.Accept = "application/rdap+json, application/json";
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream()))
                    {
                        var doc = J.Parse(sr.ReadToEnd());
                        foreach (var ev in J.List(doc, "events"))
                            if (J.Str(ev, "eventAction") == "registration") r.Registered = Clock.Parse(J.Str(ev, "eventDate"));
                        foreach (var ent in J.List(doc, "entities"))
                            if (J.List(ent, "roles").OfType<string>().Contains("registrar"))
                            {
                                var vcard = J.List(ent, "vcardArray.1").FirstOrDefault(v => J.Str(v, "0") == "fn");
                                r.Registrar = vcard != null ? J.Str(vcard, "3") : J.Str(ent, "handle");
                            }
                    }
                }
                catch (Exception e) { Log.Info("RDAP " + r.Registrable + ": " + e.Message); }
                cache.Domains[r.Registrable] = new[] { Clock.Iso(r.Registered), r.Registrar ?? "", Clock.NowIso() };
                try { J.Save(path, cache); } catch (Exception) { }
            }
            if (r.Registered == DateTime.MinValue) return;
            double days = (DateTime.UtcNow - r.Registered).TotalDays;
            if (days < 30) r.Add(40, "bad", r.Registrable + " was registered only " + Math.Max(0, (int)days) + " days ago; scam sites are usually brand new");
            else if (days < 180) r.Add(15, "warn", r.Registrable + " is only " + (int)(days / 30) + " months old");
            else if (days > 730) r.Add(-10, "good", r.Registrable + " has existed since " + r.Registered.Year);
        }
    }
}
