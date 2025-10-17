using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Nsharp
{
    public class NetworkScanner
    {
        private readonly ScanOptions _options;
        private readonly List<ScanResult> _results;

        public NetworkScanner(ScanOptions options)
        {
            _options = options;
            _results = new List<ScanResult>();
        }

        public void Run()
        {
            Console.WriteLine($"Starting Nsharp scan on {_options.Target}");
            Console.WriteLine($"Scan Type: {_options.ScanType}");
            Console.WriteLine($"Ports: {_options.Ports}");
            Console.WriteLine($"Threads: {_options.MaxThreads}");
            Console.WriteLine();

            var ports = ParsePorts(_options.Ports);
            
            if (ports.Count == 0)
            {
                Console.WriteLine("No valid ports specified.");
                return;
            }

            Console.WriteLine($"Scanning {ports.Count} ports...\n");

            var startTime = DateTime.Now;
            
            // Perform port scan
            PortScan(ports);

            var endTime = DateTime.Now;
            var duration = endTime - startTime;

            Console.WriteLine($"\nScan completed in {duration.TotalSeconds:F2} seconds");
            Console.WriteLine($"Found {_results.Count(r => r.IsOpen)} open ports\n");

            // Print results
            PrintResults();

            // Service detection
            if (_options.ServiceDetection && _results.Any(r => r.IsOpen))
            {
                Console.WriteLine("\n[*] Performing service detection...");
                PerformServiceDetection();
                PrintResults();
            }

            // OS detection
            if (_options.OSDetection)
            {
                Console.WriteLine("\n[*] Performing OS detection...");
                PerformOSDetection();
            }

            // Run exploitation scripts
            if (_options.Scripts.Length > 0 && _results.Any(r => r.IsOpen))
            {
                Console.WriteLine("\n[*] Running exploitation scripts...");
                RunScripts();
            }

            // Save output
            if (!string.IsNullOrEmpty(_options.OutputXML))
            {
                OutputFormatter.SaveAsXML(_results, _options.Target, _options.OutputXML);
                Console.WriteLine($"\n[+] Results saved to {_options.OutputXML}");
            }

            if (!string.IsNullOrEmpty(_options.OutputJSON))
            {
                OutputFormatter.SaveAsJSON(_results, _options.Target, _options.OutputJSON);
                Console.WriteLine($"[+] Results saved to {_options.OutputJSON}");
            }
        }

        private List<int> ParsePorts(string portString)
        {
            var ports = new List<int>();

            foreach (var part in portString.Split(','))
            {
                if (part.Contains('-'))
                {
                    var range = part.Split('-');
                    if (range.Length == 2 && 
                        int.TryParse(range[0], out int start) && 
                        int.TryParse(range[1], out int end))
                    {
                        for (int i = start; i <= end && i <= 65535; i++)
                        {
                            ports.Add(i);
                        }
                    }
                }
                else if (int.TryParse(part, out int port) && port > 0 && port <= 65535)
                {
                    ports.Add(port);
                }
            }

            return ports.Distinct().OrderBy(p => p).ToList();
        }

        private void PortScan(List<int> ports)
        {
            var options = new ParallelOptions { MaxDegreeOfParallelism = _options.MaxThreads };
            
            Parallel.ForEach(ports, options, port =>
            {
                var result = ScanPort(port);
                
                lock (_results)
                {
                    _results.Add(result);
                }

                if (result.IsOpen && _options.Verbose)
                {
                    Console.WriteLine($"[+] Port {port} is OPEN");
                }
            });
        }

        private ScanResult ScanPort(int port)
        {
            var result = new ScanResult
            {
                Port = port,
                IsOpen = false
            };

            try
            {
                if (_options.ScanType == ScanType.TCPConnect)
                {
                    result.IsOpen = TCPConnectScan(port);
                }
                else if (_options.ScanType == ScanType.SYN)
                {
                    // SYN scan requires raw sockets (admin privileges)
                    // For simplicity, fall back to TCP connect
                    Console.WriteLine("[!] SYN scan requires administrator privileges, using TCP connect instead");
                    result.IsOpen = TCPConnectScan(port);
                }
            }
            catch (Exception ex)
            {
                if (_options.Verbose)
                    Console.WriteLine($"[!] Error scanning port {port}: {ex.Message}");
            }

            return result;
        }

        private bool TCPConnectScan(int port)
        {
            try
            {
                using var client = new TcpClient();
                var task = client.ConnectAsync(_options.Target, port);
                
                if (task.Wait(_options.Timeout))
                {
                    return client.Connected;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private void PerformServiceDetection()
        {
            var openPorts = _results.Where(r => r.IsOpen).ToList();
            
            foreach (var result in openPorts)
            {
                var service = ServiceDetector.DetectService(_options.Target, result.Port, _options.Timeout);
                result.Service = service.ServiceName;
                result.Version = service.Version;
                result.Banner = service.Banner;

                if (_options.Verbose)
                {
                    Console.WriteLine($"[+] Port {result.Port}: {result.Service} {result.Version}");
                }
            }
        }

        private void PerformOSDetection()
        {
            var osInfo = OSDetector.DetectOS(_options.Target, _results.Where(r => r.IsOpen).ToList());
            
            Console.WriteLine($"\n[*] OS Detection Results:");
            Console.WriteLine($"    OS Family: {osInfo.OSFamily}");
            Console.WriteLine($"    Confidence: {osInfo.Confidence}%");
            
            if (!string.IsNullOrEmpty(osInfo.Details))
            {
                Console.WriteLine($"    Details: {osInfo.Details}");
            }
        }

        private void RunScripts()
        {
            var openPorts = _results.Where(r => r.IsOpen).ToList();
            
            foreach (var script in _options.Scripts)
            {
                Console.WriteLine($"\n[*] Running script: {script}");
                
                var scriptResults = ExploitationScripts.RunScript(script, _options.Target, openPorts, _options.Timeout);
                
                foreach (var scriptResult in scriptResults)
                {
                    var portResult = _results.FirstOrDefault(r => r.Port == scriptResult.Port);
                    if (portResult != null)
                    {
                        portResult.VulnerabilityInfo = scriptResult.VulnerabilityInfo;
                    }

                    Console.WriteLine($"    Port {scriptResult.Port}: {scriptResult.VulnerabilityInfo}");
                }
            }
        }

        private void PrintResults()
        {
            Console.WriteLine("PORT     STATE    SERVICE         VERSION");
            Console.WriteLine("------------------------------------------------");
            
            foreach (var result in _results.OrderBy(r => r.Port))
            {
                if (result.IsOpen)
                {
                    var service = string.IsNullOrEmpty(result.Service) ? "unknown" : result.Service;
                    var version = string.IsNullOrEmpty(result.Version) ? "" : result.Version;
                    
                    Console.WriteLine($"{result.Port,-8} OPEN     {service,-15} {version}");
                    
                    if (!string.IsNullOrEmpty(result.VulnerabilityInfo))
                    {
                        Console.WriteLine($"         [!] {result.VulnerabilityInfo}");
                    }
                }
            }
        }
    }
}
