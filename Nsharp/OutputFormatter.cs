using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Xml.Linq;

namespace Nsharp
{
    public static class OutputFormatter
    {
        public static void SaveAsXML(List<ScanResult> results, string target, string filename)
        {
            var xml = new XDocument(
                new XElement("nsharp",
                    new XAttribute("scanner", "Nsharp"),
                    new XAttribute("time", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                    new XElement("host",
                        new XAttribute("address", target),
                        new XElement("ports",
                            from result in results.OrderBy(r => r.Port)
                            where result.IsOpen
                            select new XElement("port",
                                new XAttribute("portid", result.Port),
                                new XElement("state", "open"),
                                new XElement("service",
                                    new XAttribute("name", result.Service),
                                    new XAttribute("version", result.Version ?? string.Empty)),
                                !string.IsNullOrEmpty(result.Banner) ? new XElement("banner", result.Banner) : null,
                                !string.IsNullOrEmpty(result.VulnerabilityInfo) ? new XElement("vulnerability", result.VulnerabilityInfo) : null
                            )
                        )
                    )
                )
            );

            xml.Save(filename);
        }

        public static void SaveAsJSON(List<ScanResult> results, string target, string filename)
        {
            var output = new
            {
                scanner = "Nsharp",
                time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                target = target,
                results = results.Where(r => r.IsOpen).OrderBy(r => r.Port).Select(r => new
                {
                    port = r.Port,
                    state = "open",
                    service = r.Service,
                    version = r.Version,
                    banner = r.Banner,
                    vulnerability = r.VulnerabilityInfo
                }).ToList()
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(output, options);
            File.WriteAllText(filename, json);
        }
    }
}
