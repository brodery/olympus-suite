// Athena's network checks: devices on your home network (ping sweep + ARP table + names from the
// router), ports games and apps opened on the router through UPnP, and programs accepting
// connections on this PC.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Olympus.Athena
{
    public sealed class Device
    {
        public string Mac, Ip, Name, FirstSeen, LastSeen;
    }

    public sealed class PortMap
    {
        public string Protocol, Internal, Description;
        public int External, InternalPort;
        public bool Enabled;
    }

    static class LanScan
    {
        // This PC's IPv4 address and network mask on the adapter that has the default gateway.
        public static bool Local(out IPAddress ip, out IPAddress mask, out IPAddress gateway)
        {
            ip = mask = gateway = null;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = nic.GetIPProperties();
                var gw = props.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
                if (gw == null) continue;
                var uni = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
                if (uni == null) continue;
                ip = uni.Address;
                mask = uni.IPv4Mask;
                gateway = gw;
                return true;
            }
            return false;
        }

        public static Dictionary<string, string> Arp()
        {
            var map = new Dictionary<string, string>();
            string o;
            Proc.Run("arp.exe", "-a", out o, 10000);
            foreach (Match m in Regex.Matches(o, @"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(-[0-9a-f]{2}){5})\s+dynamic", RegexOptions.IgnoreCase))
                map[m.Groups[1].Value] = m.Groups[2].Value.ToLowerInvariant();
            return map;
        }

        // Pings every address on a /24 home network (all at once, ~1 s), then reads who answered from the ARP table.
        public static List<Device> Sweep()
        {
            IPAddress ip, mask, gw;
            if (!Local(out ip, out mask, out gw)) return new List<Device>();
            var b = ip.GetAddressBytes();
            var m = mask == null ? new byte[] { 255, 255, 255, 0 } : mask.GetAddressBytes();
            if (m[0] != 255 || m[1] != 255 || m[2] < 252) m = new byte[] { 255, 255, 255, 0 };   // only small home networks
            var tasks = new List<Task>();
            for (int host = 1; host < 255; host++)
            {
                var target = new IPAddress(new byte[] { b[0], b[1], b[2], (byte)host });
                var ping = new Ping();
                tasks.Add(ping.SendPingAsync(target, 400).ContinueWith(t => ping.Dispose()));
            }
            try { Task.WaitAll(tasks.ToArray(), 4000); } catch (Exception) { }
            var arp = Arp();
            var list = new List<Device>();
            foreach (var kv in arp)
            {
                var parts = kv.Key.Split('.');
                if (parts.Length != 4 || parts[3] == "255" || kv.Value == "ff-ff-ff-ff-ff-ff" || kv.Value.StartsWith("01-00-5e")) continue;
                if (parts[0] != b[0].ToString() || parts[1] != b[1].ToString() || parts[2] != b[2].ToString()) continue;
                list.Add(new Device { Ip = kv.Key, Mac = kv.Value, Name = NameOf(kv.Key) });
            }
            return list;
        }

        static string NameOf(string ip)
        {
            try
            {
                var t = Dns.GetHostEntryAsync(ip);
                if (t.Wait(700) && t.Result != null && t.Result.HostName != ip) return t.Result.HostName.Replace(".mynetworksettings.com", "");
            }
            catch (Exception) { }
            return null;
        }
    }

    static class Upnp
    {
        // Asks the router (UPnP Internet Gateway Device) which ports it forwards, and to where.
        public static List<PortMap> Mappings(out string router, out string error)
        {
            router = null;
            error = null;
            var maps = new List<PortMap>();
            string location = null;
            try
            {
                using (var udp = new UdpClient(AddressFamily.InterNetwork))
                {
                    udp.Client.ReceiveTimeout = 2500;
                    foreach (var st in new[] { "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2" })
                    {
                        var req = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n");
                        udp.Send(req, req.Length, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
                    }
                    var deadline = DateTime.UtcNow.AddSeconds(3);
                    while (DateTime.UtcNow < deadline && location == null)
                    {
                        var from = new IPEndPoint(IPAddress.Any, 0);
                        byte[] data;
                        try { data = udp.Receive(ref from); } catch (SocketException) { break; }
                        var m = Regex.Match(Encoding.ASCII.GetString(data), @"^LOCATION:\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.Multiline);
                        if (m.Success) location = m.Groups[1].Value.Trim();
                    }
                }
                if (location == null) { error = "the router didn't answer UPnP (it may have UPnP switched off, which is good)"; return maps; }
                var desc = XDocument.Parse(Download(location));
                XNamespace ns = desc.Root.Name.Namespace;
                var friendly = desc.Descendants(ns + "friendlyName").FirstOrDefault();
                router = friendly != null ? friendly.Value : new Uri(location).Host;
                var service = desc.Descendants(ns + "service").FirstOrDefault(s =>
                {
                    var t = s.Element(ns + "serviceType");
                    return t != null && (t.Value.Contains("WANIPConnection") || t.Value.Contains("WANPPPConnection"));
                });
                if (service == null) { error = "the router has no port-forwarding service"; return maps; }
                string type = service.Element(ns + "serviceType").Value;
                var control = new Uri(new Uri(location), service.Element(ns + "controlURL").Value);
                for (int i = 0; i < 128; i++)
                {
                    string resp;
                    try { resp = Soap(control, type, "GetGenericPortMappingEntry", "<NewPortMappingIndex>" + i + "</NewPortMappingIndex>"); }
                    catch (WebException) { break; }   // past the last entry
                    Func<string, string> F = tag => { var mm = Regex.Match(resp, "<" + tag + ">([^<]*)</" + tag + ">"); return mm.Success ? WebUtility.HtmlDecode(mm.Groups[1].Value) : ""; };
                    int ext, port;
                    int.TryParse(F("NewExternalPort"), out ext);
                    int.TryParse(F("NewInternalPort"), out port);
                    maps.Add(new PortMap { External = ext, Protocol = F("NewProtocol"), Internal = F("NewInternalClient"), InternalPort = port, Description = F("NewPortMappingDescription"), Enabled = F("NewEnabled") != "0" });
                }
            }
            catch (Exception e) { error = e.Message; }
            return maps;
        }

        static string Download(string url)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = 4000;
            req.Proxy = null;
            using (var resp = req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream())) return sr.ReadToEnd();
        }

        static string Soap(Uri control, string type, string action, string args)
        {
            var req = (HttpWebRequest)WebRequest.Create(control);
            req.Method = "POST";
            req.Timeout = 4000;
            req.Proxy = null;
            req.ContentType = "text/xml; charset=\"utf-8\"";
            req.Headers["SOAPACTION"] = "\"" + type + "#" + action + "\"";
            var body = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:" + action + " xmlns:u=\"" + type + "\">" + args + "</u:" + action + "></s:Body></s:Envelope>");
            using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            using (var resp = req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream())) return sr.ReadToEnd();
        }
    }

    static class Listening
    {
        // Programs accepting connections from other machines (not just this PC itself).
        public static List<string> Open()
        {
            var names = new Dictionary<int, string>();
            foreach (var p in Process.GetProcesses()) using (p) names[p.Id] = p.ProcessName;
            var rows = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in NetTables.Tcp(true))
            {
                if (IPAddress.IsLoopback(c.LocalIp)) continue;
                string name;
                if (!names.TryGetValue(c.Pid, out name)) name = "pid " + c.Pid;
                if (c.LocalPort >= 49152 && (name == "svchost" || name == "lsass" || name == "wininit" || name == "services" || name == "spoolsv")) continue;   // Windows' own RPC ports
                rows.Add(name + " (TCP " + c.LocalPort + ")");
            }
            return rows.ToList();
        }
    }
}
