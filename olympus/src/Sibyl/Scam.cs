// Sibyl's message checks: the wording scammers use (eBay "buyers", delivery texts, dating and
// romance scams, Steam/Discord account theft, tech support, prizes), plus an optional second
// opinion from the local AI model in LM Studio. Nothing leaves the PC.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Olympus.Sibyl
{
    public sealed class MessageReport
    {
        public List<Flag> Flags = new List<Flag>();
        public List<string> Links = new List<string>(), Phones = new List<string>(), Emails = new List<string>();
        public int Score;
        public string Verdict;
    }

    static class Scam
    {
        sealed class Rule
        {
            public int Weight;
            public Regex Rx;
            public string Text;
        }

        static Rule R(int w, string pattern, string text)
        {
            return new Rule { Weight = w, Rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Text = text };
        }

        static readonly Rule[] Rules =
        {
            R(15, @"\b(urgent(ly)?|immediately|right away|asap|final (notice|warning)|act now|within (24|48) hours|last chance|expires? today)\b", "Pressure to act fast (scammers don't want you to stop and think)"),
            R(20, @"\baccount (will be |has been |is )?(suspended|locked|closed|disabled|limited|on hold|compromised)\b", "Says your account is locked or suspended (a classic phishing hook)"),
            R(30, @"\b(gift ?cards?|steam (wallet|gift) (card|code)|itunes card|google play card|apple card|amazon card)\b", "Asks for gift cards (no real company or person takes payment in gift cards)"),
            R(20, @"\b(bitcoin|btc|usdt|tether|crypto(currency)?|ethereum|wallet address|seed phrase|recovery phrase)\b", "Mentions crypto or wallets (hard-to-reverse payments)"),
            R(20, @"\b(wire transfer|western union|moneygram|zelle|cash ?app|venmo|apple pay cash)\b", "Wants money sent in a way that can't be taken back"),
            R(25, @"\b(verify|confirm|update|validate)\b.{0,25}\b(account|identity|password|payment|billing|details|information)\b", "Asks you to verify your account or details"),
            R(35, @"\b(send|give|tell|share|read)( me)?( the| your| that)? (\d-digit |6-digit |verification |security |login |2fa |one[- ]time )?(code|otp|pin)\b", "Asks for a code sent to you (that code is the key to your account)"),
            R(20, @"\b(whats ?app|telegram|signal|kik|wechat|google voice|text me|my number is|email me at|hangouts)\b", "Wants to move the chat somewhere else (away from the app's protections)"),
            R(30, @"\b(paypal|ebay|zelle|venmo|cash app)\b.{0,60}(\b(sent|pending|on hold|held|approved|released)\b.{0,40}\b(payment|money|funds)\b|\b(payment|money|funds)\b.{0,30}\b(sent|pending|on hold|held|approved|released)\b)", "Claims a payment is \"pending\" or \"sent\": eBay payments only ever show in eBay itself"),
            R(35, @"\b(upgrade|switch)\b.{0,25}\b(business|premium|merchant) account\b", "Asks you to upgrade to a business account to \"release\" a payment (a known fake-payment scam)"),
            R(35, @"\b(over ?paid|over ?payment|extra (money|amount)|send (back|the) (difference|extra|balance)|refund the (difference|excess))\b", "Overpayment story: you'd be refunding money that was never really sent"),
            R(30, @"\b(my own|my|own|private) (courier|shipper|shipping agent|mover|pick ?up agent)\b|\bship (it )?to (my|a) (son|daughter|cousin|friend|nephew|niece|address in)\b|\bi(\'ll| will) (send|email) (you )?(a|the|my) (shipping )?label\b", "Wants their own shipping arrangement (common in eBay buyer scams: you ship, the payment vanishes)"),
            R(30, @"\b(usps|ups|fedex|dhl|royal mail|parcel|package|shipment|delivery)\b.{0,60}\b(held|undeliverable|re-?delivery|address (issue|problem|update)|customs fee|unpaid|on hold|suspended)\b", "Delivery-problem text (a top scam: real carriers don't text payment links)"),
            R(30, @"\b(you('ve| have)? won|congratulations|winner|claim (your )?(prize|reward|gift)|selected (to|for) (receive|win)|giveaway)\b", "Says you've won something"),
            R(30, @"\bfree (nitro|robux|v-?bucks|skins?|steam games?|gift)\b|\bnitro (gift|for free)\b", "Free Nitro / Robux / skins bait (account-stealing links)"),
            R(35, @"\b(accidentally|mistakenly|by mistake)\b.{0,40}\b(report(ed)?|ban(ned)?)\b|\breport(ed)? your (steam |discord )?account\b", "\"I accidentally reported your account\" (a Steam/Discord takeover script)"),
            R(25, @"\b(try|test|play) (out )?my (new )?game\b|\bbeta ?test(er|ing)?\b.{0,30}\b(download|exe|link)\b|\bvote for (me|my (team|clan|tournament))\b", "\"Try my game\" / \"vote for my team\" (spreads password-stealing malware)"),
            R(30, @"\b(investment|invest(ing)?|trading) (opportunity|platform|plan|account)\b|\bguaranteed (profit|returns|income)\b|\bdouble your (money|crypto)\b", "Investment pitch with promised returns (the usual romance-to-crypto scam)"),
            R(30, @"\b(send|lend|need) (me )?(money|cash|\$\d+)\b|\b(medical|hospital) (bill|emergency)\b|\bstuck (at|in) (the )?(airport|customs)\b|\b(deployed|deployment|oil rig|peacekeeping)\b", "Asks for money with a hard-luck story"),
            R(30, @"\b(your (computer|pc|device) (is|has been) (infected|hacked|compromised)|call (microsoft|apple|support|this number)|tech support|refund department)\b", "Fake tech support"),
            R(15, @"\b(irs|tax refund|social security|ssn|warrant|lawsuit|legal action|police)\b", "Government or legal threat"),
            R(10, @"\b(dear (customer|user|member|sir|madam)|valued customer)\b", "Generic greeting (sent to many people at once)"),
            R(15, @"\b(click|tap|open|visit|follow) (the |this )?(link|button|url)\b", "Pushes you to click a link"),
            R(25, @"\b(password|login details|bank details|card number|cvv|routing number|account number)\b", "Asks about passwords, card or bank details"),
        };

        static readonly Regex Phone = new Regex(@"(?<!\d)(\+?\d{1,2}[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)");
        static readonly Regex Email = new Regex(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}");

        public static MessageReport Check(string text)
        {
            var r = new MessageReport();
            text = text ?? "";
            foreach (var rule in Rules)
                if (rule.Rx.IsMatch(text)) { r.Flags.Add(new Flag { Weight = rule.Weight, Level = rule.Weight >= 25 ? "bad" : "warn", Text = rule.Text }); r.Score += rule.Weight; }
            r.Links = Links.Find(text);
            r.Phones = Phone.Matches(text).Cast<Match>().Select(m => m.Value.Trim()).Distinct().Take(5).ToList();
            r.Emails = Email.Matches(text).Cast<Match>().Select(m => m.Value).Distinct().Take(5).ToList();
            if (r.Links.Count > 0 && r.Score > 0) { r.Score += 10; r.Flags.Add(new Flag { Weight = 10, Level = "warn", Text = "Combines warning signs with a link" }); }
            r.Verdict = r.Score >= 50 ? "dangerous" : r.Score >= 20 ? "suspicious" : "ok";
            if (r.Flags.Count == 0) r.Flags.Add(new Flag { Level = "good", Text = "None of the usual scam wording. Scammers vary, so trust your gut too." });
            return r;
        }

        // ------------------------------------------------------------------ the local AI (LM Studio)

        const string Prompt =
            "You help a person decide whether a message they received is a scam. They may be an eBay seller, use dating apps, " +
            "and play games on Steam and Discord. Read the message and answer in plain English, briefly:\n" +
            "Verdict: one of SAFE, SUSPICIOUS, SCAM.\n" +
            "Why: up to four short bullet points naming the specific red flags (or reassuring signs).\n" +
            "What to do: one or two sentences. Never tell them to click links, call numbers, or pay anything in the message. /no_think";

        static string Host
        {
            get
            {
                string h = Environment.GetEnvironmentVariable("LMSTUDIO_HOST", EnvironmentVariableTarget.User) ?? Environment.GetEnvironmentVariable("LMSTUDIO_HOST");
                if (string.IsNullOrWhiteSpace(h)) h = "http://localhost:1234";
                if (!h.StartsWith("http")) h = "http://" + h;
                return h.TrimEnd('/');
            }
        }

        static HttpWebRequest Request(string path, int timeoutMs)
        {
            var req = (HttpWebRequest)WebRequest.Create(Host + path);
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.Proxy = null;
            string key = Environment.GetEnvironmentVariable("LMSTUDIO_API_KEY", EnvironmentVariableTarget.User) ?? Environment.GetEnvironmentVariable("LMSTUDIO_API_KEY");
            if (!string.IsNullOrWhiteSpace(key)) req.Headers["Authorization"] = "Bearer " + key.Trim();
            return req;
        }

        public static string AskAi(string message, out string error)
        {
            error = null;
            string model;
            try
            {
                using (var resp = Request("/v1/models", 4000).GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                {
                    var ids = J.List(J.Parse(sr.ReadToEnd()), "data").Select(m => J.Str(m, "id")).Where(id => id != null && !id.Contains("embed")).ToList();
                    model = ids.FirstOrDefault(id => id.IndexOf("qwen", StringComparison.OrdinalIgnoreCase) >= 0) ?? ids.FirstOrDefault();
                }
            }
            catch (Exception e)
            {
                error = "LM Studio isn't answering at " + Host + " (" + e.Message + "). Start LM Studio (or its server) and try again.";
                return null;
            }
            if (model == null) { error = "LM Studio is running but has no chat model available."; return null; }
            try
            {
                var body = new Dictionary<string, object>
                {
                    { "model", model }, { "temperature", 0.2 }, { "max_tokens", 700 },
                    { "messages", new object[]
                        {
                            new Dictionary<string, object> { { "role", "system" }, { "content", Prompt } },
                            new Dictionary<string, object> { { "role", "user" }, { "content", "Message:\n\"\"\"\n" + Fmt.Clip(message, 6000) + "\n\"\"\"" } }
                        } }
                };
                var req = Request("/v1/chat/completions", 240000);
                req.Method = "POST";
                req.ContentType = "application/json";
                var bytes = Encoding.UTF8.GetBytes(J.Write(body));
                using (var s = req.GetRequestStream()) s.Write(bytes, 0, bytes.Length);
                using (var resp = req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                {
                    string content = J.Str(J.Parse(sr.ReadToEnd()), "choices.0.message.content") ?? "";
                    content = Regex.Replace(content, @"<think>.*?</think>", "", RegexOptions.Singleline).Trim();
                    return content.Length > 0 ? content + "\n\n(" + model + ", running on this PC)" : null;
                }
            }
            catch (Exception e)
            {
                error = "The model didn't answer: " + e.Message + " (the first answer after loading a model can take a minute or two).";
                return null;
            }
        }
    }
}
