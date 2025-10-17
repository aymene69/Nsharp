using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;

namespace Nsharp
{
    public class OSInfo
    {
        public string OSFamily { get; set; } = "Unknown";
        public int Confidence { get; set; } = 0;
        public string Details { get; set; } = string.Empty;
    }

    public static class OSDetector
    {
        public static OSInfo DetectOS(string host, List<ScanResult> openPorts)
        {
            var osInfo = new OSInfo();
            var indicators = new Dictionary<string, int>();

            // Analyze open ports for OS fingerprinting
            var ports = openPorts.Select(p => p.Port).ToList();

            // Windows indicators
            if (ports.Contains(135) || ports.Contains(139) || ports.Contains(445))
            {
                indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 30;
            }
            if (ports.Contains(3389))
            {
                indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 25;
            }
            if (ports.Contains(1433))
            {
                indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 20;
            }

            // Linux indicators
            if (ports.Contains(22))
            {
                indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 20;
            }

            // Check for MySQL (common on Linux servers)
            if (ports.Contains(3306))
            {
                indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 15;
            }

            // Check for PostgreSQL
            if (ports.Contains(5432))
            {
                indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 15;
            }

            // Check service banners for OS information
            foreach (var portResult in openPorts)
            {
                if (!string.IsNullOrEmpty(portResult.Banner))
                {
                    var banner = portResult.Banner.ToLower();
                    
                    if (banner.Contains("ubuntu"))
                    {
                        indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 40;
                        osInfo.Details = "Likely Ubuntu";
                    }
                    else if (banner.Contains("debian"))
                    {
                        indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 40;
                        osInfo.Details = "Likely Debian";
                    }
                    else if (banner.Contains("centos") || banner.Contains("redhat"))
                    {
                        indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 40;
                        osInfo.Details = "Likely CentOS/RedHat";
                    }
                    else if (banner.Contains("windows") || banner.Contains("microsoft"))
                    {
                        indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 40;
                    }
                    else if (banner.Contains("win32"))
                    {
                        indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 35;
                    }
                }

                if (!string.IsNullOrEmpty(portResult.Service))
                {
                    var service = portResult.Service.ToLower();
                    
                    if (service.Contains("microsoft") || service.Contains("ms-"))
                    {
                        indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 30;
                    }
                }
            }

            // TTL-based detection
            try
            {
                var ttl = GetTTL(host);
                if (ttl > 0)
                {
                    if (ttl <= 64)
                    {
                        indicators["Linux"] = indicators.GetValueOrDefault("Linux", 0) + 25;
                    }
                    else if (ttl <= 128)
                    {
                        indicators["Windows"] = indicators.GetValueOrDefault("Windows", 0) + 25;
                    }
                    else if (ttl <= 255)
                    {
                        indicators["Unix"] = indicators.GetValueOrDefault("Unix", 0) + 20;
                    }
                }
            }
            catch
            {
                // TTL detection failed
            }

            // Determine most likely OS
            if (indicators.Any())
            {
                var mostLikely = indicators.OrderByDescending(x => x.Value).First();
                osInfo.OSFamily = mostLikely.Key;
                osInfo.Confidence = Math.Min(mostLikely.Value, 100);
            }

            return osInfo;
        }

        private static int GetTTL(string host)
        {
            try
            {
                using var ping = new Ping();
                var reply = ping.Send(host, 1000);
                
                if (reply.Status == IPStatus.Success)
                {
                    return reply.Options?.Ttl ?? 0;
                }
            }
            catch
            {
                // Ping failed
            }

            return 0;
        }
    }
}
