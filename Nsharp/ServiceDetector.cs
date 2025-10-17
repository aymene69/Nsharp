using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Nsharp
{
    public class ServiceInfo
    {
        public string ServiceName { get; set; } = "unknown";
        public string Version { get; set; } = string.Empty;
        public string Banner { get; set; } = string.Empty;
    }

    public static class ServiceDetector
    {
        private static readonly Dictionary<int, string> WellKnownPorts = new()
        {
            { 21, "ftp" },
            { 22, "ssh" },
            { 23, "telnet" },
            { 25, "smtp" },
            { 53, "dns" },
            { 80, "http" },
            { 110, "pop3" },
            { 135, "msrpc" },
            { 139, "netbios-ssn" },
            { 143, "imap" },
            { 443, "https" },
            { 445, "microsoft-ds" },
            { 993, "imaps" },
            { 995, "pop3s" },
            { 1433, "ms-sql-s" },
            { 1521, "oracle" },
            { 3306, "mysql" },
            { 3389, "ms-wbt-server" },
            { 5432, "postgresql" },
            { 5900, "vnc" },
            { 6379, "redis" },
            { 8080, "http-proxy" },
            { 8443, "https-alt" },
            { 27017, "mongodb" }
        };

        public static ServiceInfo DetectService(string host, int port, int timeout)
        {
            var serviceInfo = new ServiceInfo();

            // First, check well-known ports
            if (WellKnownPorts.TryGetValue(port, out var knownService))
            {
                serviceInfo.ServiceName = knownService;
            }

            // Try to grab banner
            try
            {
                var banner = GrabBanner(host, port, timeout);
                if (!string.IsNullOrEmpty(banner))
                {
                    serviceInfo.Banner = banner;
                    
                    // Parse banner for service and version information
                    var parsedInfo = ParseBanner(banner, port);
                    if (!string.IsNullOrEmpty(parsedInfo.ServiceName) && parsedInfo.ServiceName != "unknown")
                    {
                        serviceInfo.ServiceName = parsedInfo.ServiceName;
                    }
                    serviceInfo.Version = parsedInfo.Version;
                }
            }
            catch
            {
                // Banner grabbing failed, keep the well-known port service name
            }

            return serviceInfo;
        }

        private static string GrabBanner(string host, int port, int timeout)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                
                if (!connectTask.Wait(timeout))
                {
                    return string.Empty;
                }

                if (!client.Connected)
                {
                    return string.Empty;
                }

                using var stream = client.GetStream();
                stream.ReadTimeout = timeout;
                stream.WriteTimeout = timeout;

                var buffer = new byte[4096];
                var banner = new StringBuilder();

                // Some services send data immediately
                if (stream.DataAvailable)
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    banner.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                }
                else
                {
                    // For HTTP and other services, send a probe
                    var probe = GetProbeForPort(port);
                    if (!string.IsNullOrEmpty(probe))
                    {
                        var probeBytes = Encoding.ASCII.GetBytes(probe);
                        stream.Write(probeBytes, 0, probeBytes.Length);
                        stream.Flush();

                        System.Threading.Thread.Sleep(100); // Give server time to respond

                        if (stream.DataAvailable)
                        {
                            int bytesRead = stream.Read(buffer, 0, buffer.Length);
                            banner.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                        }
                    }
                }

                return banner.ToString().Trim();
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string GetProbeForPort(int port)
        {
            return port switch
            {
                80 or 8080 or 8443 => "GET / HTTP/1.0\r\n\r\n",
                443 => "GET / HTTP/1.0\r\n\r\n",
                21 => "USER anonymous\r\n",
                25 => "EHLO test\r\n",
                110 => "USER test\r\n",
                143 => "A001 CAPABILITY\r\n",
                _ => string.Empty
            };
        }

        private static ServiceInfo ParseBanner(string banner, int port)
        {
            var info = new ServiceInfo();

            if (string.IsNullOrEmpty(banner))
            {
                return info;
            }

            var lowerBanner = banner.ToLower();

            // HTTP detection
            if (lowerBanner.Contains("http/"))
            {
                info.ServiceName = "http";
                
                if (lowerBanner.Contains("apache"))
                {
                    info.ServiceName = "apache";
                    var match = System.Text.RegularExpressions.Regex.Match(banner, @"Apache/([\d\.]+)");
                    if (match.Success)
                        info.Version = match.Groups[1].Value;
                }
                else if (lowerBanner.Contains("nginx"))
                {
                    info.ServiceName = "nginx";
                    var match = System.Text.RegularExpressions.Regex.Match(banner, @"nginx/([\d\.]+)");
                    if (match.Success)
                        info.Version = match.Groups[1].Value;
                }
                else if (lowerBanner.Contains("microsoft-iis"))
                {
                    info.ServiceName = "microsoft-iis";
                    var match = System.Text.RegularExpressions.Regex.Match(banner, @"IIS/([\d\.]+)");
                    if (match.Success)
                        info.Version = match.Groups[1].Value;
                }
            }
            // FTP detection
            else if (lowerBanner.Contains("ftp") || banner.StartsWith("220"))
            {
                info.ServiceName = "ftp";
                
                if (lowerBanner.Contains("vsftpd"))
                {
                    var match = System.Text.RegularExpressions.Regex.Match(banner, @"vsftpd ([\d\.]+)");
                    if (match.Success)
                        info.Version = match.Groups[1].Value;
                }
                else if (lowerBanner.Contains("proftpd"))
                {
                    var match = System.Text.RegularExpressions.Regex.Match(banner, @"ProFTPD ([\d\.]+)");
                    if (match.Success)
                        info.Version = match.Groups[1].Value;
                }
            }
            // SSH detection
            else if (lowerBanner.Contains("ssh"))
            {
                info.ServiceName = "ssh";
                var match = System.Text.RegularExpressions.Regex.Match(banner, @"SSH-([\d\.]+)");
                if (match.Success)
                    info.Version = match.Groups[1].Value;
                    
                if (lowerBanner.Contains("openssh"))
                {
                    match = System.Text.RegularExpressions.Regex.Match(banner, @"OpenSSH_([\d\.p\d]+)");
                    if (match.Success)
                        info.Version = match.Groups[1].Value;
                }
            }
            // SMTP detection
            else if (lowerBanner.Contains("smtp") || banner.StartsWith("220") && lowerBanner.Contains("mail"))
            {
                info.ServiceName = "smtp";
            }
            // MySQL detection
            else if (lowerBanner.Contains("mysql"))
            {
                info.ServiceName = "mysql";
                var match = System.Text.RegularExpressions.Regex.Match(banner, @"([\d\.]+)-");
                if (match.Success)
                    info.Version = match.Groups[1].Value;
            }

            return info;
        }
    }
}
