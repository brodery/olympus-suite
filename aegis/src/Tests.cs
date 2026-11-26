// Aegis tests. AegisTests.exe runs the unit tests (no network, temp folder);
// "AegisTests.exe live [server]" queries a running engine for real.
#if TESTS
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Aegis
{
    static class Tests
    {
        static int passed, failed;

        static void Check(bool ok, string what)
        {
            if (ok) passed++;
            else
            {
                failed++;
                Console.WriteLine("FAIL: " + what);
            }
        }

        static void Eq(object expected, object actual, string what)
        {
            Check(Equals(expected, actual), what + " (expected " + Show(expected) + ", got " + Show(actual) + ")");
        }

        static string Show(object o) { return o == null ? "null" : o.ToString(); }

        public static int Run(string[] args)
        {
            if (args.Length > 0 && args[0] == "live") return Live(args.Length > 1 ? args[1] : "127.0.0.1");
            App.Dir = Path.Combine(Path.GetTempPath(), "aegis-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(App.Dir);
            App.EnsureDirs();
            try
            {
                WireTests();
                ReplyTests();
                CacheTests();
                ListTests();
                RuleTests();
                NameTests();
                ConfigTests();
                EngineTests();
                UpstreamTests();
                MiscTests();
            }
            catch (Exception e)
            {
                failed++;
                Console.WriteLine("CRASH: " + e);
            }
            finally
            {
                try { Directory.Delete(App.Dir, true); } catch { }
            }
            Console.WriteLine(passed + " passed, " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }

        // ------------------------------------------------------------ message builders

        static byte[] MakeQuery(string name, int qtype, int id = 0x1234, bool edns = false, bool dnssecOk = false, int qclass = 1, int flags = Dns.RD)
        {
            var ms = new MemoryStream();
            var h = new byte[12];
            Dns.W16(h, 0, id);
            Dns.W16(h, 2, flags);
            Dns.W16(h, 4, 1);
            Dns.W16(h, 10, edns ? 1 : 0);
            ms.Write(h, 0, 12);
            byte[] qn = Reply.EncodeName(name);
            ms.Write(qn, 0, qn.Length);
            var t = new byte[4];
            Dns.W16(t, 0, qtype);
            Dns.W16(t, 2, qclass);
            ms.Write(t, 0, 4);
            if (edns)
            {
                var o = new byte[11];
                Dns.W16(o, 1, Dns.OPT);
                Dns.W16(o, 3, 1232);
                Dns.W32(o, 5, dnssecOk ? 0x8000u : 0u);
                ms.Write(o, 0, 11);
            }
            return ms.ToArray();
        }

        static byte[] AnswerA(Query q, int ttl, params string[] ips)
        {
            return Reply.Build(q, Dns.NOERROR, ips.Select(ip => new RR(Dns.A, ttl, IPAddress.Parse(ip).GetAddressBytes())).ToArray(), null, false);
        }

        // <qname> CNAME <first labels of target> + pointer to "com" in the question; then target A ip.
        static byte[] CnameReply(byte[] query, string targetPrefix, string ip)
        {
            var q = Query.Parse(query);
            int com = FindSuffix(query, "com");
            var ms = new MemoryStream();
            var h = new byte[12];
            Dns.W16(h, 0, q.Id);
            Dns.W16(h, 2, Dns.QR | Dns.RD | Dns.RA);
            Dns.W16(h, 4, 1);
            Dns.W16(h, 6, 2);
            ms.Write(h, 0, 12);
            ms.Write(query, 12, q.QEnd - 12);
            var target = new MemoryStream();
            foreach (var label in targetPrefix.Split('.'))
            {
                target.WriteByte((byte)label.Length);
                var b = Encoding.ASCII.GetBytes(label);
                target.Write(b, 0, b.Length);
            }
            target.WriteByte((byte)(0xC0 | (com >> 8)));
            target.WriteByte((byte)com);
            var t = target.ToArray();
            var rr = new byte[12];
            Dns.W16(rr, 0, 0xC00C);
            Dns.W16(rr, 2, Dns.CNAME);
            Dns.W16(rr, 4, 1);
            Dns.W32(rr, 6, 300);
            Dns.W16(rr, 10, t.Length);
            ms.Write(rr, 0, 12);
            int targetPos = (int)ms.Length;
            ms.Write(t, 0, t.Length);
            var a = new byte[12];
            Dns.W16(a, 0, 0xC000 | targetPos);
            Dns.W16(a, 2, Dns.A);
            Dns.W16(a, 4, 1);
            Dns.W32(a, 6, 60);
            Dns.W16(a, 10, 4);
            ms.Write(a, 0, 12);
            ms.Write(IPAddress.Parse(ip).GetAddressBytes(), 0, 4);
            return ms.ToArray();
        }

        static int FindSuffix(byte[] m, string label)
        {
            var needle = new byte[label.Length + 2];
            needle[0] = (byte)label.Length;
            Encoding.ASCII.GetBytes(label).CopyTo(needle, 1);
            for (int i = 12; i + needle.Length <= m.Length; i++)
            {
                bool ok = true;
                for (int k = 0; k < needle.Length && ok; k++) ok = m[i + k] == needle[k];
                if (ok) return i;
            }
            throw new Exception("suffix not found");
        }

        static int Rcode(byte[] r) { return r[3] & 0xF; }
        static int Count(byte[] r, int section) { return Dns.U16(r, 4 + 2 * section); }
        static string FirstAddress(byte[] r) { var a = Msg.Addresses(r); return a.Count == 0 ? null : a[0]; }

        // ------------------------------------------------------------ wire format

        static void WireTests()
        {
            var q = Query.Parse(MakeQuery("WwW.Example.COM", Dns.A, 0xBEEF));
            Eq("www.example.com", q.Name, "parse: name lower-cased");
            Eq(0xBEEF, q.Id, "parse: id");
            Eq(Dns.A, q.QType, "parse: qtype");
            Eq(1, q.QClass, "parse: qclass");
            Eq(12 + 17 + 4, q.QEnd, "parse: question end");
            Check(!q.Edns, "parse: no EDNS");
            Eq(512, q.UdpLimit, "parse: UDP limit without EDNS");

            var e = Query.Parse(MakeQuery("example.com", Dns.AAAA, 1, edns: true, dnssecOk: true));
            Check(e.Edns && e.Do, "parse: EDNS + DO seen");
            Eq(1232, e.UdpLimit, "parse: EDNS UDP size");

            Throws(() => Query.Parse(new byte[5]), "parse: short message");
            var resp = MakeQuery("example.com", Dns.A, flags: Dns.QR);
            Throws(() => Query.Parse(resp), "parse: QR set");
            var two = MakeQuery("example.com", Dns.A);
            Dns.W16(two, 4, 2);
            Throws(() => Query.Parse(two), "parse: two questions");
            var longLabel = MakeQuery("example.com", Dns.A);
            longLabel[12] = 70;
            Throws(() => Query.Parse(longLabel), "parse: label over 63");
            var cut = MakeQuery("example.com", Dns.A).Take(20).ToArray();
            Throws(() => Query.Parse(cut), "parse: cut-off name");

            var k1 = Query.Parse(MakeQuery("Example.com", Dns.HTTPS)).CacheKey();
            var k2 = Query.Parse(MakeQuery("example.COM", Dns.HTTPS, 99)).CacheKey();
            var k3 = Query.Parse(MakeQuery("example.com", 97)).CacheKey();
            Eq(k1, k2, "cache key ignores case and id");
            Check(k1 != k3, "cache key keeps qtype bytes exact (65 vs 97)");
            Check(k1 != Query.Parse(MakeQuery("example.com", Dns.HTTPS, edns: true)).CacheKey(), "cache key includes EDNS");
            Check(k1 != Query.Parse(MakeQuery("example.com", Dns.HTTPS, flags: 0)).CacheKey(), "cache key includes RD");

            var one = MakeQuery("example.com", Dns.A, edns: true);
            Throws(() => Query.Parse(one.Take(one.Length - 3).ToArray()), "parse: cut-off OPT record -> FORMERR");
            var twoOpt = one.Concat(one.Skip(one.Length - 11)).ToArray();
            Dns.W16(twoOpt, 10, 2);
            Throws(() => Query.Parse(twoOpt), "parse: two OPT records -> FORMERR");
            var optInAnswer = (byte[])one.Clone();
            Dns.W16(optInAnswer, 6, 1);
            Dns.W16(optInAnswer, 10, 0);
            Throws(() => Query.Parse(optInAnswer), "parse: OPT outside the additional section -> FORMERR");
            var qo = Query.Parse(WithCookie(one));
            Check(qo.Edns && qo.HasEdnsOptions, "parse: EDNS options noticed");
            var v1 = (byte[])one.Clone();
            v1[one.Length - 11 + 6] = 1;
            Eq(1, Query.Parse(v1).EdnsVersion, "parse: EDNS version read");
            var badOption = one.Concat(new byte[] { 0, 10, 0, 8, 1, 2, 3, 4 }).ToArray();   // says 8 bytes, has 4
            Dns.W16(badOption, one.Length - 2, 8);
            Throws(() => Query.Parse(badOption), "parse: cut-off EDNS option -> FORMERR");
            var withExtra = one.Concat(new byte[] { 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0 }).ToArray();   // + a TSIG-type record
            Dns.W16(withExtra, 10, 2);
            Check(Query.Parse(withExtra).HasExtraRecords, "parse: extra (non-OPT) records noticed");
        }

        // An EDNS query with an 8-byte COOKIE option added to its OPT record.
        static byte[] WithCookie(byte[] ednsQuery)
        {
            var b = ednsQuery.Concat(new byte[] { 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 }).ToArray();
            Dns.W16(b, ednsQuery.Length - 2, 12);
            return b;
        }

        static void Throws(Action a, string what)
        {
            try
            {
                a();
                Check(false, what + " should throw");
            }
            catch (DnsFormatException) { passed++; }
        }

        // ------------------------------------------------------------ made-up replies

        static void ReplyTests()
        {
            var q = Query.Parse(MakeQuery("Ads.Example.com", Dns.A, 0x4242));
            var r = Reply.Blocked(q, 5);
            Eq(0x4242, Dns.U16(r, 0), "blocked: id");
            Check((Dns.U16(r, 2) & Dns.QR) != 0 && (Dns.U16(r, 2) & Dns.RA) != 0 && (Dns.U16(r, 2) & Dns.RD) != 0, "blocked: QR RA RD");
            Eq(Dns.NOERROR, Rcode(r), "blocked: rcode");
            Eq(1, Count(r, 1), "blocked A: one answer");
            Eq("0.0.0.0", FirstAddress(r), "blocked A: 0.0.0.0");
            Check(r.Skip(12).Take(q.QEnd - 12).SequenceEqual(q.Raw.Skip(12).Take(q.QEnd - 12)), "blocked: question copied as sent");
            var rec = Dns.Records(r).First();
            Eq(5u, rec.Ttl, "blocked: TTL");

            var r6 = Reply.Blocked(Query.Parse(MakeQuery("ads.example.com", Dns.AAAA)), 5);
            Eq("::", FirstAddress(r6), "blocked AAAA: ::");

            var rh = Reply.Blocked(Query.Parse(MakeQuery("ads.example.com", Dns.HTTPS)), 5);
            Eq(0, Count(rh, 1), "blocked HTTPS: no answer");
            Eq(1, Count(rh, 2), "blocked HTTPS: SOA in authority");
            Eq(5, Msg.CacheTtl(rh, 3600), "blocked HTTPS: negative TTL from the SOA");

            var re = Reply.Blocked(Query.Parse(MakeQuery("ads.example.com", Dns.A, edns: true, dnssecOk: true)), 5);
            var opt = Dns.Records(re).Where(x => x.Type == Dns.OPT).ToList();
            Check(opt.Count == 1 && (opt[0].Ttl & 0x8000) != 0, "blocked + EDNS: OPT with DO echoed");

            var nx = Reply.NxDomain(q, 300);
            Eq(Dns.NXDOMAIN, Rcode(nx), "nxdomain rcode");

            string longText = new string('x', 300) + "end";
            var txt = Reply.Txt(Query.Parse(MakeQuery("status.aegis.invalid", Dns.TXT)), longText);
            var trec = Dns.Records(txt).First();
            Eq(Dns.TXT, trec.Type, "txt: type");
            var sb = new StringBuilder();
            for (int i = trec.Pos + 10; i < trec.Pos + 10 + trec.RdLen; ) { int n = txt[i]; sb.Append(Encoding.UTF8.GetString(txt, i + 1, n)); i += 1 + n; }
            Eq(longText, sb.ToString(), "txt: over 255 bytes round-trips");

            var raw = MakeQuery("example.com", Dns.A, 0x7777);
            Dns.W16(raw, 4, 0);
            var fe = Reply.HeaderOnly(raw, Dns.FORMERR);
            Eq(0x7777, Dns.U16(fe, 0), "header-only: id");
            Eq(Dns.FORMERR, Rcode(fe), "header-only: FORMERR");
            Check(Reply.HeaderOnly(new byte[4], Dns.FORMERR) == null, "header-only: too short -> null");
            Check(Reply.HeaderOnly(MakeQuery("x.com", Dns.A, flags: Dns.QR), Dns.FORMERR) == null, "header-only: never answer a response");

            var big = AnswerA(q, 60, Enumerable.Range(1, 40).Select(i => "10.0.0." + i).ToArray());
            var tr = Reply.Truncated(big, q);
            Check((Dns.U16(tr, 2) & Dns.TC) != 0, "truncated: TC set");
            Eq(q.QEnd, tr.Length, "truncated: header + question only");
            Eq(0, Count(tr, 1), "truncated: no answers");

            var qe = Query.Parse(MakeQuery("big.example.com", Dns.A, 0x6161, edns: true, dnssecOk: true));
            var tre = Reply.Truncated(AnswerA(qe, 60, "1.2.3.4"), qe);
            Check(Count(tre, 3) == 1 && Dns.Records(tre).Any(x => x.Type == Dns.OPT && (x.Ttl & 0x8000) != 0), "truncated + EDNS: keeps an OPT record with DO");
            var bv = Reply.BadVersion(Query.Parse(MakeQuery("example.com", Dns.A, edns: true)));
            var bopt = Dns.Records(bv).First(x => x.Type == Dns.OPT);
            Check(Rcode(bv) == 0 && (bopt.Ttl >> 24) == 1, "BADVERS: extended rcode 1 in the OPT record");
        }

        // ------------------------------------------------------------ upstream replies and the cache

        static void CacheTests()
        {
            var q = Query.Parse(MakeQuery("example.com", Dns.A));
            var two = Reply.Build(q, Dns.NOERROR, new[] { new RR(Dns.A, 300, new byte[] { 1, 2, 3, 4 }), new RR(Dns.A, 60, new byte[] { 1, 2, 3, 5 }) }, null, false);
            Eq(60, Msg.CacheTtl(two, 3600), "cache ttl: smallest answer TTL");
            Eq(30, Msg.CacheTtl(two, 30), "cache ttl: capped");

            var soa = Reply.SoaData(300);
            var nx = Reply.Build(q, Dns.NXDOMAIN, null, new[] { new RR(Dns.SOA, 900, soa) }, false);
            Eq(300, Msg.CacheTtl(nx, 3600), "cache ttl: NXDOMAIN uses min(SOA TTL, SOA minimum)");
            Eq(0, Msg.CacheTtl(Reply.Error(q, Dns.SERVFAIL), 3600), "cache ttl: SERVFAIL not cached");
            var tc = (byte[])two.Clone();
            Dns.W16(tc, 2, Dns.U16(tc, 2) | Dns.TC);
            Eq(0, Msg.CacheTtl(tc, 3600), "cache ttl: truncated not cached");
            Eq(0, Msg.CacheTtl(Reply.Build(q, Dns.NOERROR, null, null, false), 3600), "cache ttl: empty without SOA not cached");
            var cq2 = Query.Parse(MakeQuery("alias.example.com", Dns.AAAA));
            var chainNoData = Reply.Build(cq2, Dns.NOERROR, new[] { new RR(Dns.CNAME, 3600, Reply.EncodeName("target.example.net")) },
                new[] { new RR(Dns.SOA, 3600, Reply.SoaData(30)) }, false);
            Eq(30, Msg.CacheTtl(chainNoData, 3600), "cache ttl: CNAME then 'no such data' uses the shorter lifetime");
            var nxChain = Reply.Build(cq2, Dns.NXDOMAIN, new[] { new RR(Dns.CNAME, 20, Reply.EncodeName("gone.example.net")) },
                new[] { new RR(Dns.SOA, 900, Reply.SoaData(300)) }, false);
            Eq(20, Msg.CacheTtl(nxChain, 3600), "cache ttl: NXDOMAIN after a short CNAME uses the CNAME's TTL");
            var bareNx = Reply.HeaderOnly(MakeQuery("x.example.com", Dns.A), Dns.NXDOMAIN);
            Eq(0, Msg.CacheTtl(bareNx, 3600), "cache ttl: a reply without its question is never cached");
            Check(!Msg.Validate(bareNx), "validate: reply without its question rejected");
            Check(Msg.Validate(two), "validate: normal answer accepted");
            Check(!Msg.Validate(two.Take(two.Length - 2).ToArray()), "validate: cut-off record rejected");
            var badLen = Reply.Build(q, Dns.NOERROR, new[] { new RR(Dns.A, 60, new byte[] { 1, 2, 3, 4, 5 }) }, null, false);
            Check(!Msg.Validate(badLen), "validate: an A record with 5 bytes of data rejected");
            var badPtr = (byte[])two.Clone();
            badPtr[q.QEnd + 1] = 0xFF;          // the first answer's owner pointer now points past the end
            Check(!Msg.Validate(badPtr), "validate: a broken name pointer rejected");
            var capped = (byte[])two.Clone();
            Msg.CapTtl(capped, 60);
            Check(Dns.Records(capped).All(x => x.Ttl <= 60), "cap ttl: every TTL at most 60");

            var qe = Query.Parse(MakeQuery("example.com", Dns.A, edns: true, dnssecOk: true));
            var withOpt = Reply.Build(qe, Dns.NOERROR, new[] { new RR(Dns.A, 300, new byte[] { 1, 2, 3, 4 }) }, null, false);
            var aged = Msg.Aged(withOpt, 100);
            var recs = Dns.Records(aged).ToList();
            Eq(200u, recs.First(x => x.Type == Dns.A).Ttl, "aged: TTL lowered");
            Eq(0x8000u, recs.First(x => x.Type == Dns.OPT).Ttl, "aged: OPT flags (DO bit) untouched");
            Eq(0u, Dns.Records(Msg.Aged(withOpt, 1000)).First(x => x.Type == Dns.A).Ttl, "aged: never below 0");

            var cq = MakeQuery("alias.example.com", Dns.A);
            var cn = CnameReply(cq, "trk.bad", "10.9.8.7");
            var targets = Msg.CnameTargets(cn);
            Check(targets.Count == 1 && targets[0] == "trk.bad.com", "cname target read through a compression pointer (" + string.Join(",", targets) + ")");
            Eq("10.9.8.7", FirstAddress(cn), "cname reply address");

            var sent = MakeQuery("Example.com", Dns.A, 0x1111);
            var answer = AnswerA(Query.Parse(MakeQuery("EXAMPLE.com", Dns.A, 0x1111)), 60, "1.2.3.4");
            Check(Msg.Matches(answer, sent, Query.Parse(sent).QEnd), "matches: same id, question case differs");
            var wrongId = (byte[])answer.Clone();
            wrongId[1] ^= 1;
            Check(!Msg.Matches(wrongId, sent, Query.Parse(sent).QEnd), "matches: other id rejected");
            var otherType = AnswerA(Query.Parse(MakeQuery("example.com", Dns.AAAA, 0x1111)), 60, "1.2.3.4");
            Check(!Msg.Matches(otherType, sent, Query.Parse(sent).QEnd), "matches: other qtype rejected");
            var noQr = (byte[])answer.Clone();
            noQr[2] &= 0x7F;
            Check(!Msg.Matches(noQr, sent, Query.Parse(sent).QEnd), "matches: QR missing rejected");
            var bare = Reply.HeaderOnly(sent, Dns.FORMERR);
            Check(Msg.Matches(bare, sent, Query.Parse(sent).QEnd), "matches: bare FORMERR accepted");

            var cache = new Cache(2);
            cache.Put("a", new byte[] { 1 }, 60);
            cache.Put("b", new byte[] { 2 }, 60);
            int age;
            cache.Get("a", out age);            // a is now the most recently used
            cache.Put("c", new byte[] { 3 }, 60);
            Check(cache.Get("b", out age) == null, "cache: least recently used dropped");
            Check(cache.Get("a", out age) != null && cache.Get("c", out age) != null, "cache: others kept");
            cache.Put("d", new byte[] { 4 }, 0);
            Check(cache.Get("d", out age) == null, "cache: TTL 0 not stored");
        }

        // ------------------------------------------------------------ list files

        static void ListTests()
        {
            Eq("ads.example.com", One("0.0.0.0 ads.example.com"), "list: hosts line");
            Eq(null, One("127.0.0.1 localhost"), "list: localhost skipped");
            Eq(null, One("::1 ip6-localhost"), "list: ip6-localhost skipped");
            Eq("tracker.net", One("||tracker.net^"), "list: adblock line");
            Eq(null, One("||x.com^$third-party"), "list: adblock modifier skipped");
            Eq("y.com", One("||y.com^$important"), "list: $important kept");
            Eq("wild.org", One("*.wild.org"), "list: wildcard");
            Eq("plain.io", One("plain.io   # comment"), "list: inline comment");
            Eq(null, One("# a comment"), "list: comment line");
            Eq(null, One("! adblock comment"), "list: ! comment");
            Eq(null, One("@@||ok.com^"), "list: exception skipped");
            Eq("upper.example.com", One("UPPER.Example.COM."), "list: case and trailing dot");
            Eq(null, One("-bad.com"), "list: leading hyphen rejected");
            Eq(null, One("bad-.com"), "list: trailing hyphen rejected");
            Eq(null, One("com"), "list: single label rejected in lists");
            Eq("_dmarc.example.com", One("_dmarc.example.com"), "list: underscore allowed");
            var both = new List<string>();
            Names.ParseListLine("0.0.0.0 a.com b.com", false, both);
            Check(both.SequenceEqual(new[] { "a.com", "b.com" }), "list: several names on a hosts line");
            var single = new List<string>();
            Names.ParseListLine("zip", true, single);
            Check(single.SequenceEqual(new[] { "zip" }), "list: single label allowed in your own lists");

            File.WriteAllText(App.AllowPath, "# test\r\n0.0.0.0 a.com b.com # two\r\nc.com\r\n");
            UserLists.Remove(App.AllowPath, "a.com");
            var after = UserLists.Read(App.AllowPath);
            Check(after.SequenceEqual(new[] { "b.com", "c.com" }), "user lists: removing one name keeps the rest of its line (" + string.Join(",", after) + ")");
            Check(File.ReadAllText(App.AllowPath).Contains("# two"), "user lists: that line's comment survives");
            UserLists.Add(App.AllowPath, "d.com");
            Check(UserLists.Read(App.AllowPath).Contains("d.com"), "user lists: add");
            UserLists.Put(App.BlockPath, App.AllowPath, "d.com");
            Check(UserLists.Read(App.BlockPath).Contains("d.com") && !UserLists.Read(App.AllowPath).Contains("d.com"), "user lists: move between lists in one step");
            string msg = Actions.Block("www.msftconnecttest.com");
            Check(msg.Contains("can't be blocked") && !UserLists.Read(App.BlockPath).Contains("www.msftconnecttest.com"), "user lists: a protected site isn't written to block.txt (" + msg + ")");
            File.Delete(App.AllowPath);
            File.Delete(App.BlockPath);
        }

        static string One(string line)
        {
            var o = new List<string>();
            Names.ParseListLine(line, false, o);
            return o.Count == 0 ? null : o[0];
        }

        // ------------------------------------------------------------ rules

        static Rules MakeRules(string[] allow, string[] block, string blockSource = "test-list")
        {
            var a = new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>("allow.txt", new SmallSet(allow)) };
            var b = new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>(blockSource, new HashedSet(block)) };
            return new Rules(a, b);
        }

        static void RuleTests()
        {
            var r = MakeRules(new[] { "good.example.com", "site.org" }, new[] { "example.com", "ads.site.org", "same.net", "zip" });
            Verdict v;
            v = r.Decide("ads.example.com");
            Check(v != null && v.Blocked && v.Rule == "example.com" && v.Source == "test-list", "rules: parent domain blocks subdomain");
            v = r.Decide("x.good.example.com");
            Check(v != null && !v.Blocked && v.Rule == "good.example.com", "rules: more specific allow wins");
            v = r.Decide("ads.site.org");
            Check(v != null && v.Blocked, "rules: more specific block beats parent allow");
            v = r.Decide("www.site.org");
            Check(v != null && !v.Blocked, "rules: parent allow covers other subdomains");
            var tie = new Rules(
                new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>("allow.txt", new SmallSet(new[] { "same.net" })) },
                new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>("l", new HashedSet(new[] { "same.net" })) });
            Check(!tie.Decide("same.net").Blocked, "rules: tie goes to allow");
            Check(r.Decide("example.org") == null, "rules: unrelated name");
            Check(r.Decide("notexample.com") == null, "rules: no partial-label match");
            Check(r.Decide("download.zip") != null && r.Decide("download.zip").Blocked, "rules: single-label rule blocks a whole TLD");
            var hs = new HashedSet(new[] { "a.com", "b.com", "a.com" });
            Eq(2, hs.Count, "hashed set: duplicates collapsed");
            Check(hs.Contains("a.com") && hs.Contains("b.com") && !hs.Contains("c.com"), "hashed set: membership");

            var guarded = new Rules(new SmallSet(new[] { "msftconnecttest.com" }),
                new List<KeyValuePair<string, INameSet>>(),
                new List<KeyValuePair<string, INameSet>> { new KeyValuePair<string, INameSet>("list", new HashedSet(new[] { "www.msftconnecttest.com" })) });
            var gv = guarded.Decide("www.msftconnecttest.com");
            Check(gv != null && !gv.Blocked && gv.Source == Rules.ProtectedSource, "rules: built-in allow list beats a more specific blocklist entry");
        }

        // ------------------------------------------------------------ names

        static void NameTests()
        {
            Eq("www.example.com", Names.Normalize("https://WWW.Example.com:8443/path?q=1#x"), "normalize: URL");
            Eq("ads.net", Names.Normalize("*.ads.net"), "normalize: wildcard");
            Eq("mail.example.org", Names.Normalize("user@mail.example.org"), "normalize: email-ish");
            Eq("xn--mnchen-3ya.de", Names.Normalize("münchen.de"), "normalize: unicode to punycode");
            Eq("example.com", Names.Normalize("example.com."), "normalize: trailing dot");
            Eq(null, Names.Normalize("not a domain"), "normalize: spaces rejected");
            Eq(null, Names.Normalize("[::1]:53"), "normalize: IPv6 literal rejected");
            Eq(null, Names.Normalize(""), "normalize: empty");

            Check(Names.IsPrivateReverse("28.1.168.192.in-addr.arpa"), "reverse: 192.168.x");
            Check(Names.IsPrivateReverse("1.0.0.127.in-addr.arpa"), "reverse: loopback");
            Check(Names.IsPrivateReverse("20.172.in-addr.arpa"), "reverse: whole 172.20 zone");
            Check(!Names.IsPrivateReverse("172.in-addr.arpa"), "reverse: all of 172 isn't private");
            Check(!Names.IsPrivateReverse("9.5.32.172.in-addr.arpa"), "reverse: 172.32.x is public");
            Check(Names.IsPrivateReverse("9.5.20.172.in-addr.arpa"), "reverse: 172.20.x");
            Check(!Names.IsPrivateReverse("8.8.8.8.in-addr.arpa"), "reverse: public v4");
            Check(Names.IsPrivateReverse("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"), "reverse: link-local v6");
            Check(Names.IsPrivateReverse("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"), "reverse: ULA v6");
            Check(!Names.IsPrivateReverse("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.f.0.0.6.2.ip6.arpa"), "reverse: public v6");
        }

        // ------------------------------------------------------------ aegis.ini

        static void ConfigTests()
        {
            File.WriteAllText(App.IniPath,
                "[dns]\nport = 5353\nupstreams = 1.1.1.1, 2606:4700:4700::1111\nblock_ttl = 9\ncname_inspection = no\nbogus = 1\nport = abc\n" +
                "[lists]\nupdate_hours = 12\nmine = https://example.com/list.txt | https://mirror.example.com/list.txt\nbad name = https://x\n");
            var c = Config.Load();
            Eq(5353, c.Port, "config: port");
            Check(c.Upstreams.SequenceEqual(new[] { "1.1.1.1", "2606:4700:4700::1111" }), "config: upstreams");
            Eq(9, c.BlockTtl, "config: block_ttl");
            Check(!c.CnameInspection, "config: bool");
            Eq(12, c.UpdateHours, "config: update_hours");
            Check(c.Lists.Count == 1 && c.Lists[0].Name == "mine" && c.Lists[0].Mirror == "https://mirror.example.com/list.txt", "config: list with mirror");
            Eq(3, c.Problems.Count, "config: three problems reported (" + string.Join(" | ", c.Problems) + ")");

            File.WriteAllText(App.IniPath, "[dns]\nport = 53\n");
            Eq(2, Config.Load().Lists.Count, "config: no [lists] section -> default lists");
            File.Delete(App.IniPath);
            var d = Config.Load();
            Check(File.Exists(App.IniPath) && d.Lists.Count == 2 && d.Port == 53, "config: missing file -> defaults written");
            var again = Config.Load();
            Check(again.Problems.Count == 0 && again.Lists.Count == 2 && again.Upstreams.Length == 3, "config: the written default file reads back cleanly");
        }

        // ------------------------------------------------------------ the engine, with fake upstreams

        sealed class FakeUpstream : IUpstream
        {
            public int Calls;
            public bool Down;
            public Func<Query, byte[]> Handler;
            public byte[] Ask(Query q, bool tcp)
            {
                Calls++;
                if (Down) throw new UpstreamException("down");
                return Handler(q);
            }
            public double AverageMs { get { return 1; } }
        }

        static void EngineTests()
        {
            var cfg = new Config();
            cfg.Lists = new List<ListSource>();
            var engine = new Engine(cfg, false);
            var up = new FakeUpstream
            {
                Handler = q =>
                {
                    if (q.Name.StartsWith("alias", StringComparison.Ordinal)) return CnameReply(q.Raw, "trk.bad", "10.9.8.7");
                    if (q.Name.StartsWith("big", StringComparison.Ordinal)) return AnswerA(q, 60, Enumerable.Range(1, 40).Select(i => "10.0.0." + i).ToArray());
                    if (q.Name == "bare.example.com") return Reply.HeaderOnly(q.Raw, Dns.NXDOMAIN);
                    if (q.Name == "broken.example.com") { var b = AnswerA(q, 60, "1.2.3.4"); return b.Take(b.Length - 2).ToArray(); }
                    return AnswerA(q, 300, "93.184.216.34");
                }
            };
            var lan = new FakeUpstream { Handler = q => AnswerA(q, 60, "192.168.1.50") };
            engine.UseUpstreams(up, lan, "192.168.1.1");
            engine.UseRules(MakeRules(new[] { "alias-ok.example.com" }, new[] { "doubleclick.net", "bad.com" }));

            byte[] r = engine.Answer(MakeQuery("ads.doubleclick.net", Dns.A), false, true);
            Eq("0.0.0.0", FirstAddress(r), "engine: blocked name -> 0.0.0.0");
            Eq(0, up.Calls, "engine: blocked name not forwarded");
            r = engine.Answer(MakeQuery("ads.doubleclick.net", Dns.ANY), false, true);
            Check(Rcode(r) == 0 && Count(r, 1) == 0 && Count(r, 2) == 1, "engine: ANY on a blocked name -> empty answer + SOA");

            r = engine.Answer(MakeQuery("www.example.com", Dns.A, 0x0101), false, true);
            Eq("93.184.216.34", FirstAddress(r), "engine: allowed name forwarded");
            Eq(1, up.Calls, "engine: one upstream call");
            byte[] q2 = MakeQuery("WWW.EXAMPLE.COM", Dns.A, 0x0202);
            r = engine.Answer(q2, false, true);
            Eq(1, up.Calls, "engine: second lookup served from cache");
            Eq(0x0202, Dns.U16(r, 0), "engine: cached reply carries the new id");
            Check(r.Skip(12).Take(17).SequenceEqual(q2.Skip(12).Take(17)), "engine: cached reply uses the asker's spelling");
            Check(Dns.Records(r).First().Ttl <= 300, "engine: cached TTL not above the original");
            engine.Answer(MakeQuery("www.example.com", Dns.A, 3, edns: true), false, true);
            Eq(2, up.Calls, "engine: EDNS and plain lookups cached separately");

            r = engine.Answer(MakeQuery("alias.example.com", Dns.A), false, true);
            Eq("0.0.0.0", FirstAddress(r), "engine: CNAME to a blocked domain is blocked");
            r = engine.Answer(MakeQuery("alias-ok.example.com", Dns.A), false, true);
            Eq("10.9.8.7", FirstAddress(r), "engine: explicitly allowed name skips the CNAME check");

            int lanBefore = lan.Calls, upBefore = up.Calls;
            Eq("192.168.1.50", FirstAddress(engine.Answer(MakeQuery("nas.mynetworksettings.com", Dns.A), false, true)), "engine: local domain answered by the router");
            engine.Answer(MakeQuery("router", Dns.A), false, true);
            engine.Answer(MakeQuery("50.1.168.192.in-addr.arpa", Dns.PTR), false, true);
            Eq(lanBefore + 3, lan.Calls, "engine: local domain, single label and private PTR go to the router");
            Eq(upBefore, up.Calls, "engine: ... and not upstream");

            r = engine.Answer(MakeQuery("status.aegis.invalid", Dns.TXT), false, true);
            Check(Rcode(r) == 0 && Encoding.UTF8.GetString(r).Contains("app=Aegis"), "engine: status for this PC");
            r = engine.Answer(MakeQuery("status.aegis.invalid", Dns.TXT), false, false);
            Eq(Dns.NXDOMAIN, Rcode(r), "engine: control names refused for other machines");
            r = engine.Answer(MakeQuery("ads.doubleclick.net.check.aegis.invalid", Dns.TXT), false, true);
            Check(Encoding.UTF8.GetString(r).Contains("verdict=block;rule=doubleclick.net;source=test-list"), "engine: check explains the rule");

            engine.PauseUntil(DateTime.UtcNow.AddMinutes(5));
            r = engine.Answer(MakeQuery("ads.doubleclick.net", Dns.A), false, true);
            Eq("93.184.216.34", FirstAddress(r), "engine: paused -> not blocked");
            engine.PauseUntil(DateTime.MinValue);
            Eq("0.0.0.0", FirstAddress(engine.Answer(MakeQuery("ads.doubleclick.net", Dns.A), false, true)), "engine: resumed -> blocked again");
            engine.PauseUntil(App.FromUnix(Pause.ForeverUnix));
            Eq("93.184.216.34", FirstAddress(engine.Answer(MakeQuery("ads.doubleclick.net", Dns.A), false, true)), "engine: paused until turned back on -> not blocked");
            Check(Encoding.UTF8.GetString(engine.Answer(MakeQuery("status.aegis.invalid", Dns.TXT), false, true)).Contains("until=253402300799"), "engine: status reports the never-ending pause");
            Check(Pause.IsForever(App.FromUnix(Pause.ForeverUnix)) && !Pause.IsForever(DateTime.UtcNow.AddHours(24)), "pause: forever vs a day");
            Eq("until you turn it back on", Pause.Until(App.FromUnix(Pause.ForeverUnix)), "pause: wording");
            engine.PauseUntil(DateTime.MinValue);

            int chBefore = up.Calls;
            engine.Answer(MakeQuery("doubleclick.net", Dns.TXT, qclass: 3), false, true);
            Eq(chBefore + 1, up.Calls, "engine: non-IN class not filtered");

            r = engine.Answer(MakeQuery("big.example.com", Dns.A), false, true);
            Check((Dns.U16(r, 2) & Dns.TC) != 0 && Count(r, 1) == 0, "engine: oversized UDP reply truncated");
            r = engine.Answer(MakeQuery("big.example.com", Dns.A), true, true);
            Eq(40, Count(r, 1), "engine: full reply over TCP");

            Eq("127.0.0.1", FirstAddress(engine.Answer(MakeQuery("localhost", Dns.A), false, true)), "engine: localhost");
            Eq(Dns.NXDOMAIN, Rcode(engine.Answer(MakeQuery("use-application-dns.net", Dns.A), false, true)), "engine: Firefox DoH canary");

            Check(engine.Answer(new byte[5], false, true) == null, "engine: junk ignored");
            Check(engine.Answer(MakeQuery("x.com", Dns.A, flags: Dns.QR), false, true) == null, "engine: responses ignored");
            Eq(Dns.NOTIMP, Rcode(engine.Answer(MakeQuery("x.com", Dns.A, flags: 2 << 11), false, true)), "engine: other opcodes -> NOTIMP");
            var noQ = MakeQuery("x.com", Dns.A, 0x5151);
            Dns.W16(noQ, 4, 0);
            r = engine.Answer(noQ, false, true);
            Check(Rcode(r) == Dns.FORMERR && Dns.U16(r, 0) == 0x5151, "engine: no question -> FORMERR with the id");

            r = engine.Answer(MakeQuery("ttl.example.com", Dns.A), false, true);
            Check(Dns.Records(r).First().Ttl <= 60, "engine: TTL handed to Windows capped at 60 s");
            r = engine.Answer(MakeQuery("rd.example.com", Dns.A, 0x0404, flags: 0), false, true);
            Eq(0, Dns.U16(r, 2) & Dns.RD, "engine: reply carries the asker's RD bit");

            int before = up.Calls;
            byte[] cookieQ = WithCookie(MakeQuery("cookie.example.com", Dns.A, 0x0505, edns: true));
            engine.Answer(cookieQ, false, true);
            engine.Answer(cookieQ, false, true);
            Eq(before + 2, up.Calls, "engine: queries with EDNS options aren't served from the cache");

            var v1q = MakeQuery("example.com", Dns.A, 0x0606, edns: true);
            v1q[v1q.Length - 11 + 6] = 1;
            r = engine.Answer(v1q, false, true);
            Check(Rcode(r) == 0 && (Dns.Records(r).First(x => x.Type == Dns.OPT).Ttl >> 24) == 1, "engine: unknown EDNS version -> BADVERS");
            var cut = MakeQuery("example.com", Dns.A, 0x0707, edns: true);
            r = engine.Answer(cut.Take(cut.Length - 3).ToArray(), false, true);
            Eq(Dns.FORMERR, Rcode(r), "engine: cut-off OPT record -> FORMERR");

            before = up.Calls;
            r = engine.Answer(MakeQuery("bare.example.com", Dns.A), false, true);
            Eq(Dns.NXDOMAIN, Rcode(r), "engine: an NXDOMAIN without its question is passed on");
            engine.Answer(MakeQuery("bare.example.com", Dns.A), false, true);
            Eq(before + 2, up.Calls, "engine: ... but never cached");
            Eq(Dns.SERVFAIL, Rcode(engine.Answer(MakeQuery("broken.example.com", Dns.A), false, true)), "engine: malformed upstream reply -> SERVFAIL");

            engine.Answer(MakeQuery("big2.example.com", Dns.A), true, true);          // cached over TCP
            up.Down = true;
            r = engine.Answer(MakeQuery("big2.example.com", Dns.A), false, true);
            Check((Dns.U16(r, 2) & Dns.TC) != 0 && Rcode(r) == 0, "engine: oversized cache hit -> TC (retry over TCP), not SERVFAIL");

            Eq("192.168.1.50", FirstAddress(engine.Answer(MakeQuery("down.example.net", Dns.A), false, true)), "engine: Quad9 unreachable -> the router answers");
            r = engine.Answer(MakeQuery("www.example.com", Dns.A, 0x0808), false, true);
            Eq("93.184.216.34", FirstAddress(r), "engine: cached answers still served while upstream is down");
            lan.Down = true;
            Eq(Dns.SERVFAIL, Rcode(engine.Answer(MakeQuery("down2.example.net", Dns.A), false, true)), "engine: both unreachable -> SERVFAIL");
            up.Down = false;
            lan.Down = false;

            before = up.Calls;
            var tsigQ = MakeQuery("signed.example.com", Dns.A, 0x0909, edns: true).Concat(new byte[] { 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0 }).ToArray();
            Dns.W16(tsigQ, 10, 2);
            engine.Answer(tsigQ, false, true);
            engine.Answer(tsigQ, false, true);
            Eq(before + 2, up.Calls, "engine: queries with extra records (TSIG) aren't served from the cache");

            // last: a reload re-reads the (empty) list files of the test folder, replacing the test rules
            r = engine.Answer(MakeQuery("reload.aegis.invalid", Dns.TXT), false, true);
            Check(Rcode(r) == 0 && Encoding.UTF8.GetString(r).Contains("ok"), "engine: reload request answered (on the worker path)");
        }

        // ------------------------------------------------------------ the real upstream client, against fake servers

        static void UpstreamTests()
        {
            using (var a = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            using (var b = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            using (var c = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                a.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
                int port = ((IPEndPoint)a.LocalEndPoint).Port;
                b.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.3"), port));
                c.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.5"), port));
                Serve(a, q => Reply.Error(q, Dns.SERVFAIL));
                Serve(b, q => AnswerA(q, 60, "5.6.7.8"));
                Serve(c, q => { var bad = AnswerA(q, 60, "6.6.6.6"); return bad.Take(bad.Length - 2).ToArray(); });
                var sw0 = Stopwatch.StartNew();
                var good = new Upstream(new[] { "127.0.0.5", "127.0.0.3" }, 2000, port).Ask(Query.Parse(MakeQuery("m.example.com", Dns.A)), false);
                Check(FirstAddress(good) == "5.6.7.8" && sw0.ElapsedMilliseconds < 1000, "upstream: a malformed first reply loses to the good second one (" + sw0.ElapsedMilliseconds + " ms)");
                var sw = Stopwatch.StartNew();
                var resp = new Upstream(new[] { "127.0.0.2", "127.0.0.3" }, 2000, port).Ask(Query.Parse(MakeQuery("x.example.com", Dns.A, 0x7070)), false);
                Check(Rcode(resp) == 0 && FirstAddress(resp) == "5.6.7.8" && Dns.U16(resp, 0) == 0x7070, "upstream: a SERVFAIL from the first server falls through to the second");
                Check(sw.ElapsedMilliseconds < 1000, "upstream: ... at once, not after the stagger (" + sw.ElapsedMilliseconds + " ms)");
                var only = new Upstream(new[] { "127.0.0.2" }, 1000, port).Ask(Query.Parse(MakeQuery("y.example.com", Dns.A)), false);
                Eq(Dns.SERVFAIL, Rcode(only), "upstream: the SERVFAIL is returned when nobody does better");
            }
            try
            {
                new Upstream(new[] { "127.0.0.4" }, 600, 9).Ask(Query.Parse(MakeQuery("z.example.com", Dns.A)), false);
                Check(false, "upstream: nobody listening should throw");
            }
            catch (UpstreamException) { passed++; }
        }

        static void Serve(Socket s, Func<Query, byte[]> reply)
        {
            new Thread(() =>
            {
                var buf = new byte[4096];
                while (true)
                {
                    try
                    {
                        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                        int n = s.ReceiveFrom(buf, ref from);
                        s.SendTo(reply(Query.Parse(buf.Take(n).ToArray())), from);
                    }
                    catch (SocketException e) { if (e.SocketErrorCode != SocketError.ConnectionReset) return; }
                    catch (Exception) { return; }      // socket closed at the end of the test
                }
            }) { IsBackground = true }.Start();
        }

        static void MiscTests()
        {
            // the blocked log's once-a-minute rule keeps count of what it holds back
            var t = new BlockTally(TimeSpan.FromMinutes(1));
            long now = DateTime.UtcNow.Ticks, sec = TimeSpan.FromSeconds(1).Ticks;
            var local = new DateTime(2026, 11, 18, 10, 0, 0);
            Eq(1, t.Hit("a", "A", "r", "s", local, now), "tally: the first block is written at once");
            Eq(0, t.Hit("a", "A", "r", "s", local.AddSeconds(10), now + 10 * sec), "tally: a repeat within the minute is held back");
            Eq(0, t.Hit("a", "A", "r", "s", local.AddSeconds(20), now + 20 * sec), "tally: ... and so is the next");
            Eq(1, t.Hit("a", "AAAA", "r", "s", local.AddSeconds(20), now + 20 * sec), "tally: another type is written at once");
            Eq(0, t.Take(now + 30 * sec, false).Count, "tally: nothing is owed before the minute is up");
            var owed = t.Take(now + 61 * sec, false);
            Check(owed.Count == 1 && owed[0].Name == "a" && owed[0].Type == "A" && owed[0].Count == 2 && owed[0].LastHit == local.AddSeconds(20),
                "tally: the held-back repeats come out as one line counting 2, stamped with the last one's time");
            Eq(0, t.Take(now + 62 * sec, false).Count, "tally: ... only once");
            Eq(0, t.Hit("a", "A", "r", "s", local.AddSeconds(70), now + 70 * sec), "tally: the minute starts again after a held-back line");
            Eq(2, t.Hit("a", "A", "r", "s", local.AddSeconds(125), now + 125 * sec), "tally: the next line after the minute carries what was held back");
            t.Hit("a", "A", "r", "s", local.AddSeconds(130), now + 130 * sec);
            var final = t.Take(now + 131 * sec, true);
            Check(final.Count == 1 && final[0].Count == 1, "tally: everything owed comes out before the engine exits");

            var big = new BlockTally(TimeSpan.FromMinutes(1));
            big.Hit("keep", "A", "r", "s", local, now);
            big.Hit("keep", "A", "r", "s", local, now + sec);             // held back
            for (int i = 0; i < 20005; i++) big.Hit("n" + i + ".example", "A", "r", "s", local, now + 2 * sec);
            var kept = big.Take(now + 2 * sec, true);
            Check(kept.Count == 1 && kept[0].Name == "keep" && kept[0].Count == 1, "tally: trimming a full table never drops blocks still owed");

            // the window's Times column adds up each line's count (lines from before 1.0.1 have none and count once)
            Directory.CreateDirectory(App.LogDir);
            File.AppendAllLines(BlockLog.PathFor(DateTime.Today), new[] {
                "10:00:00\tcount.example\tA\tcount.example\tHaGeZi\t5",
                "10:00:30\tcount.example\tAAAA\tcount.example\tHaGeZi",
                "10:01:00\tcount.example\tA\tcount.example\tHaGeZi\tjunk",
            });
            var counted = BlockLog.Recent().Where(r => r.Name == "count.example").ToList();
            Check(counted.Count == 1 && counted[0].Count == 7 && counted[0].Types.Count == 2, "blocked log: Times adds up the counts (5 + 1 + 1)");

            // the window covers the last 7 days, today included, newest first
            File.AppendAllLines(BlockLog.PathFor(DateTime.Today.AddDays(-6)), new[] { "08:00:00\tsixdays.example\tA\tsixdays.example\tHaGeZi\t3" });
            File.AppendAllLines(BlockLog.PathFor(DateTime.Today.AddDays(-7)), new[] { "08:00:00\tsevendays.example\tA\tsevendays.example\tHaGeZi\t3" });
            File.AppendAllLines(BlockLog.PathFor(DateTime.Today.AddDays(-2)), new[] { "garbage line", "25:99:00\tbadtime.example\tA\tx\ty", "09:30:00\ttwodays.example\tAAAA\ttwodays.example\tHaGeZi" });
            var week = BlockLog.Recent();
            var six = week.FirstOrDefault(r => r.Name == "sixdays.example");
            Check(six != null && six.Count == 3 && six.Last == DateTime.Today.AddDays(-6).AddHours(8), "blocked log: blocks from 6 days ago are shown, with their date");
            Check(!week.Any(r => r.Name == "sevendays.example"), "blocked log: blocks from 7 days ago are not");
            Check(week.Any(r => r.Name == "twodays.example") && !week.Any(r => r.Name == "badtime.example"), "blocked log: lines that don't fit are skipped, the rest of the day still counts");
            Check(week.Count >= 3 && week.First().Last >= week.Last().Last && week.Last().Name == "sixdays.example", "blocked log: newest first");
            long sig = BlockLog.Signature();
            File.AppendAllLines(BlockLog.PathFor(DateTime.Today.AddDays(-3)), new[] { "07:00:00\tthreedays.example\tA\tthreedays.example\tHaGeZi" });
            Check(BlockLog.Signature() != sig, "blocked log: a change to any day of the history refreshes the window");
            Check(Engine.DownloadLooksRight(250000, 252163), "downloads: a normal update is accepted");
            Check(!Engine.DownloadLooksRight(1200, 252163), "downloads: a list that shrank to a sliver is refused");
            Check(Engine.DownloadLooksRight(5000, 0), "downloads: the first download is accepted");
            Check(!Engine.DownloadLooksRight(500, 0), "downloads: too short to be a list");
        }

        // ------------------------------------------------------------ live checks against a running engine

        static byte[] Udp(string server, byte[] msg, int timeoutMs = 3000)
        {
            var ip = IPAddress.Parse(server);
            using (var s = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                s.ReceiveTimeout = timeoutMs;
                s.Connect(new IPEndPoint(ip, 53));
                s.Send(msg);
                var buf = new byte[65535];
                try
                {
                    int n = s.Receive(buf);
                    return buf.Take(n).ToArray();
                }
                catch (SocketException) { return null; }
            }
        }

        static byte[] Tcp(string server, byte[] msg)
        {
            var ip = IPAddress.Parse(server);
            using (var s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                s.ReceiveTimeout = 3000;
                s.Connect(new IPEndPoint(ip, 53));
                var framed = new byte[msg.Length + 2];
                Dns.W16(framed, 0, msg.Length);
                msg.CopyTo(framed, 2);
                s.Send(framed);
                var deadline = DateTime.UtcNow.AddSeconds(3);
                var len = Net.ReadExact(s, 2, deadline);
                return len == null ? null : Net.ReadExact(s, Dns.U16(len, 0), deadline);
            }
        }

        static readonly string[] Important =
        {
            "store.steampowered.com", "api.steampowered.com", "steamcommunity.com", "cdn.cloudflare.steamstatic.com", "clientconfig.akamai.steamstatic.com",
            "www.epicgames.com", "launcher-public-service-prod06.ol.epicgames.com", "epicgames-download1.akamaized.net",
            "xboxlive.com", "user.auth.xboxlive.com", "login.live.com", "login.microsoftonline.com",
            "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net",
            "www.ea.com", "accounts.ea.com", "public-ubiservices.ubi.com", "us.battle.net",
            "www.nexusmods.com", "api.nexusmods.com", "www.wabbajack.org", "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
            "claude.ai", "api.anthropic.com", "www.amd.com", "lmstudio.ai", "huggingface.co",
            "ifunny.co", "img.ifunny.co", "www.ebay.com", "i.ebayimg.com", "ir.ebaystatic.com", "signin.ebay.com",
            "www.verizon.com", "mynetworksettings.com", "www.amazon.com", "m.media-amazon.com",
            "www.youtube.com", "i.ytimg.com", "www.google.com", "accounts.google.com", "fonts.googleapis.com", "fonts.gstatic.com", "www.gstatic.com",
            "www.msftconnecttest.com", "dns.msftncsi.com", "fe3cr.delivery.mp.microsoft.com", "www.bing.com", "outlook.live.com",
            "www.netflix.com", "www.twitch.tv", "static.twitchcdn.net", "www.reddit.com", "i.redd.it", "en.wikipedia.org",
            "steelseries.com", "www.coinbase.com", "duckduckgo.com", "www.paypal.com", "www.hinge.co", "tinder.com",
        };

        static int Live(string server)
        {
            Console.WriteLine("Live checks against " + server + ":53");
            byte[] r = Udp(server, MakeQuery("example.com", Dns.A, 0x1001));
            Check(r != null && Rcode(r) == 0 && Msg.Addresses(r).Count > 0, "live: example.com resolves (" + (r == null ? "no answer" : string.Join(",", Msg.Addresses(r))) + ")");
            // (HaGeZi blocks Google's ad hosts under g.doubleclick.net, not bare doubleclick.net)
            r = Udp(server, MakeQuery("googleads.g.doubleclick.net", Dns.A));
            Eq("0.0.0.0", r == null ? null : FirstAddress(r), "live: ad host A blocked");
            r = Udp(server, MakeQuery("googleads.g.doubleclick.net", Dns.AAAA));
            Eq("::", r == null ? null : FirstAddress(r), "live: ad host AAAA blocked");
            r = Udp(server, MakeQuery("googleads.g.doubleclick.net", Dns.HTTPS));
            Check(r != null && Rcode(r) == 0 && Count(r, 1) == 0, "live: ad host HTTPS record empty");
            r = Tcp(server, MakeQuery("www.wikipedia.org", Dns.A, 0x2002));
            Check(r != null && Rcode(r) == 0 && Msg.Addresses(r).Count > 0 && Dns.U16(r, 0) == 0x2002, "live: TCP lookup works");
            r = Udp(server, MakeQuery("cloudflare.com", Dns.A, edns: true, dnssecOk: true));
            Check(r != null && Dns.Records(r).Any(x => x.Type == Dns.OPT), "live: EDNS reply carries OPT");
            var junk = MakeQuery("x.com", Dns.A, 0x3003);
            Dns.W16(junk, 4, 0);
            r = Udp(server, junk);
            Check(r != null && Rcode(r) == Dns.FORMERR, "live: malformed query -> FORMERR");
            string status = EngineClient.AskTxt("status" + App.ControlSuffix, 2000);
            Check(status != null && status.Contains("app=Aegis"), "live: status " + status);
            r = Udp(server, MakeQuery("nonexistent-" + Guid.NewGuid().ToString("N") + ".com", Dns.A));
            Check(r != null && Rcode(r) == Dns.NXDOMAIN, "live: made-up name -> NXDOMAIN");
            if (server == "127.0.0.1")
            {
                r = Udp("::1", MakeQuery("example.org", Dns.A));
                Check(r != null && Rcode(r) == 0, "live: [::1] answers too");
            }

            Console.WriteLine();
            Console.WriteLine("Sites that must keep working (each needs a real address):");
            int good = 0;
            foreach (var name in Important)
            {
                r = Udp(server, MakeQuery(name, Dns.A), 4000);
                var ips = r == null || Rcode(r) != 0 ? new List<string>() : Msg.Addresses(r);
                if (ips.Count > 0 && !ips.Any(ip => ip == "0.0.0.0" || ip == "::" || ip == "::1" || ip.StartsWith("127.", StringComparison.Ordinal)))
                {
                    good++;
                    continue;
                }
                string why = r == null ? "no answer" : Rcode(r) != 0 ? Dns.RcodeName(Rcode(r)) : ips.Count == 0 ? "no address" : "BLOCKED";
                if (why == "BLOCKED")
                {
                    var check = EngineClient.Check(name);
                    why += " (" + (check == null ? "?" : Kv.Get(check, "rule", "CNAME?") + " in " + Kv.Get(check, "source", "?")) + ")";
                }
                Check(false, "live: " + name + " -> " + why);
            }
            Console.WriteLine("  " + good + " of " + Important.Length + " resolve to a real address");

            Console.WriteLine();
            string[] names = { "example.com", "www.google.com", "github.com", "www.microsoft.com", "discord.com", "www.wikipedia.org", "store.steampowered.com", "doubleclick.net" };
            foreach (var n in names) Udp(server, MakeQuery(n, Dns.A));      // warm the cache
            var lat = new List<double>();
            object gate = new object();
            var sw = Stopwatch.StartNew();
            var threads = Enumerable.Range(0, 4).Select(t => new Thread(() =>
            {
                var mine = new List<double>();
                for (int i = 0; i < 500; i++)
                {
                    var t0 = Stopwatch.GetTimestamp();
                    var resp = Udp(server, MakeQuery(names[(i + t) % names.Length], Dns.A, i));
                    if (resp != null) mine.Add((Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency);
                }
                lock (gate) lat.AddRange(mine);
            })).ToList();
            threads.ForEach(t => t.Start());
            threads.ForEach(t => t.Join());
            sw.Stop();
            lat.Sort();
            Console.WriteLine(string.Format("Speed: {0} answers in {1:0.00} s = {2:0} per second; median {3:0.00} ms, 99th percentile {4:0.00} ms, worst {5:0.00} ms",
                lat.Count, sw.Elapsed.TotalSeconds, lat.Count / sw.Elapsed.TotalSeconds, lat[lat.Count / 2], lat[(int)(lat.Count * 0.99)], lat[lat.Count - 1]));
            Check(lat.Count == 2000, "live: every speed-test query answered (" + lat.Count + ")");
            Console.WriteLine(passed + " passed, " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }
    }
}
#endif
