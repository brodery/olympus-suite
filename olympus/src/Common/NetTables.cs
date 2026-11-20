// TCP connections and listening ports with the process that owns each (Windows IP Helper).
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Olympus
{
    public sealed class TcpConn
    {
        public IPAddress LocalIp, RemoteIp;
        public int LocalPort, RemotePort, State, Pid;
    }

    public sealed class UdpPort
    {
        public IPAddress LocalIp;
        public int LocalPort, Pid;
    }

    static class NetTables
    {
        [DllImport("iphlpapi.dll")]
        static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, int reserved);
        [DllImport("iphlpapi.dll")]
        static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, int reserved);

        const int AF_INET = 2, AF_INET6 = 23;
        public const int Listen = 2, SynSent = 3, Established = 5;

        static int Port(int raw) { return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF); }
        static IPAddress V4(IntPtr p) { return new IPAddress((long)(uint)Marshal.ReadInt32(p)); }
        static IPAddress V6(IntPtr p)
        {
            var b = new byte[16];
            Marshal.Copy(p, b, 0, 16);
            return new IPAddress(b);
        }

        public static List<TcpConn> Tcp(bool listenersOnly)
        {
            var list = new List<TcpConn>();
            int cls = listenersOnly ? 3 : 5; // TCP_TABLE_OWNER_PID_LISTENER / _ALL
            Read(true, AF_INET, cls, (buf, n) =>
            {
                for (int i = 0; i < n; i++)
                {
                    IntPtr r = buf + 4 + i * 24;
                    list.Add(new TcpConn
                    {
                        State = Marshal.ReadInt32(r), LocalIp = V4(r + 4), LocalPort = Port(Marshal.ReadInt32(r, 8)),
                        RemoteIp = V4(r + 12), RemotePort = Port(Marshal.ReadInt32(r, 16)), Pid = Marshal.ReadInt32(r, 20)
                    });
                }
            });
            Read(true, AF_INET6, cls, (buf, n) =>
            {
                for (int i = 0; i < n; i++)
                {
                    IntPtr r = buf + 4 + i * 56;
                    list.Add(new TcpConn
                    {
                        LocalIp = V6(r), LocalPort = Port(Marshal.ReadInt32(r, 20)),
                        RemoteIp = V6(r + 24), RemotePort = Port(Marshal.ReadInt32(r, 44)),
                        State = Marshal.ReadInt32(r, 48), Pid = Marshal.ReadInt32(r, 52)
                    });
                }
            });
            return list;
        }

        public static List<UdpPort> Udp()
        {
            var list = new List<UdpPort>();
            Read(false, AF_INET, 1, (buf, n) =>
            {
                for (int i = 0; i < n; i++)
                {
                    IntPtr r = buf + 4 + i * 12;
                    list.Add(new UdpPort { LocalIp = V4(r), LocalPort = Port(Marshal.ReadInt32(r, 4)), Pid = Marshal.ReadInt32(r, 8) });
                }
            });
            Read(false, AF_INET6, 1, (buf, n) =>
            {
                for (int i = 0; i < n; i++)
                {
                    IntPtr r = buf + 4 + i * 28;
                    list.Add(new UdpPort { LocalIp = V6(r), LocalPort = Port(Marshal.ReadInt32(r, 20)), Pid = Marshal.ReadInt32(r, 24) });
                }
            });
            return list;
        }

        static void Read(bool tcp, int af, int cls, Action<IntPtr, int> parse)
        {
            int size = 0;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                if (tcp) GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, cls, 0);
                else GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, cls, 0);
                if (size <= 0) return;
                size += 4096;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    uint r = tcp ? GetExtendedTcpTable(buf, ref size, false, af, cls, 0) : GetExtendedUdpTable(buf, ref size, false, af, cls, 0);
                    if (r == 0) { parse(buf, Marshal.ReadInt32(buf)); return; }
                    if (r != 122) return; // anything but "buffer too small": give up
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }

        // Is this an address on the internet (not this PC, the home network, link-local or multicast)?
        public static bool IsPublic(IPAddress ip)
        {
            if (ip == null || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 10 || b[0] == 127 || b[0] == 0) return false;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
                if (b[0] == 192 && b[1] == 168) return false;
                if (b[0] == 169 && b[1] == 254) return false;
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
                if (b[0] >= 224) return false;
                return true;
            }
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
            if ((b[0] & 0xFE) == 0xFC) return false; // unique local fc00::/7
            return true;
        }

        public static string Show(IPAddress ip)
        {
            if (ip == null) return "";
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            return ip.ToString();
        }
    }
}
