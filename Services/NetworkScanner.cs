using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.Http;
using System.Net.NetworkInformation;
using Nsharp.Models;

namespace Nsharp.Services;

public class NetworkScanner
{
    private const int MaxConcurrentScans = 100;
    private const int ConnectTimeoutMs = 2000;
    private readonly AdvancedServiceDetector _advancedDetector;
    
    public NetworkScanner()
    {
        _advancedDetector = new AdvancedServiceDetector();
    }

    public async Task<ScanResponse> ScanAsync(string target, string? ports, bool verbose, bool aggressive)
    {
        var response = new ScanResponse();

        try
        {
            var portList = ParsePorts(ports);
            var openPorts = new List<PortInfo>();

            // Scan exclusivement en TCP Connect
            var openPortNumbers = await ScanTcpConnect(target, portList, verbose);
            
            openPorts = openPortNumbers.Select(p => new PortInfo 
            { 
                Port = p, 
                IsOpen = true, 
                Service = "" 
            }).ToList();

            foreach (var port in openPorts.OrderBy(p => p.Port))
            {
                var fingerprint = await _advancedDetector.DetectServiceAdvanced(target, port.Port);
                
                var detailsBuilder = new StringBuilder();
                detailsBuilder.AppendLine($"Service detecte : {fingerprint.ServiceName}");
                detailsBuilder.AppendLine($"Confiance : {fingerprint.Confidence}%");
                detailsBuilder.AppendLine();
                detailsBuilder.AppendLine(fingerprint.Details);
                
                if (fingerprint.DetectionMethods.Count > 0)
                {
                    detailsBuilder.AppendLine();
                    detailsBuilder.AppendLine("Methodes de detection utilisees :");
                    foreach (var method in fingerprint.DetectionMethods.Take(3))
                    {
                        detailsBuilder.AppendLine($"- {method}");
                    }
                }
                
                var scanResult = new ScanResult
                {
                    Port = port.Port,
                    Service = fingerprint.ServiceName,
                    Details = detailsBuilder.ToString().TrimEnd(),
                    Protocol = DetermineProtocol(fingerprint),
                    Status = "OUVERT",
                    StateDescription = GenerateStateDescription(fingerprint),
                    Advice = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris."
                };
                
                response.Results.Add(scanResult);
            }

            if (aggressive && response.Results.Count > 0)
            {
                try
                {
                    response.OsDetection = await DetectOperatingSystem(target, openPorts);
                }
                catch
                {
                    response.OsDetection = null;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors du scan : {ex.Message}");
        }

        return response;
    }

    private async Task<List<int>> ScanTcpConnect(string target, List<int> portList, bool verbose)
    {
        var openPorts = new List<int>();
        using var semaphore = new SemaphoreSlim(MaxConcurrentScans);
        
        var scanTasks = portList.Select(async port =>
        {
            await semaphore.WaitAsync();
            try
            {
                return await ScanSinglePort(target, port, verbose);
            }
            finally
            {
                semaphore.Release();
            }
        }).ToList();

        var results = await Task.WhenAll(scanTasks);

        foreach (var portResult in results)
        {
            if (portResult.IsOpen)
            {
                openPorts.Add(portResult.Port);
            }
        }
        
        return openPorts;
    }

    private string DetermineProtocol(ServiceFingerprint fingerprint)
    {
        if (fingerprint.IsTls)
            return fingerprint.TlsVersion != null ? $"TLS {fingerprint.TlsVersion}" : "TLS/SSL";
        
        if (fingerprint.IsHttp)
            return "HTTP";
        
        if (fingerprint.IsSsh)
            return "SSH";
        
        if (fingerprint.IsFtp)
            return "FTP";
        
        if (fingerprint.IsSmtp)
            return "SMTP";
        
        return "TCP";
    }

    private string GenerateStateDescription(ServiceFingerprint fingerprint)
    {
        var desc = new StringBuilder();
        
        desc.Append($"Port {fingerprint.Port} ouvert");
        
        if (fingerprint.Confidence >= 80)
        {
            desc.Append($" - Service {fingerprint.ServiceName} identifie avec haute confiance");
        }
        else if (fingerprint.Confidence >= 50)
        {
            desc.Append($" - Service {fingerprint.ServiceName} identifie avec confiance moyenne");
        }
        else if (fingerprint.TcpConnectable)
        {
            desc.Append(" - Service actif mais identification incertaine");
        }
        
        if (fingerprint.ConnectionTimeMs > 0)
        {
            desc.Append($" (temps de reponse: {fingerprint.ConnectionTimeMs:F0}ms)");
        }
        
        return desc.ToString();
    }

    private async Task<string> DetectOperatingSystem(string target, List<PortInfo> openPorts)
    {
        try
        {
            var ping = new Ping();
            var reply = await ping.SendPingAsync(target, 2000);
            
            if (reply.Status == IPStatus.Success)
            {
                var ttl = reply.Options?.Ttl ?? 0;
                
                if (ttl >= 120 && ttl <= 128)
                {
                    return "Windows (TTL: " + ttl + ")";
                }
                else if (ttl >= 60 && ttl <= 70)
                {
                    return "Linux/Unix (TTL: " + ttl + ")";
                }
                else if (ttl >= 250)
                {
                    return "Cisco/Network Device (TTL: " + ttl + ")";
                }
                else
                {
                    return "OS inconnu (TTL: " + ttl + ")";
                }
            }

            var serviceBasedGuess = EstimateOsFromServices(openPorts);
            if (!string.IsNullOrEmpty(serviceBasedGuess))
            {
                return serviceBasedGuess + " (basé sur les services)";
            }

            return "Détection OS impossible";
        }
        catch
        {
            return "Détection OS échouée";
        }
    }

    private string EstimateOsFromServices(List<PortInfo> openPorts)
    {
        var ports = openPorts.Select(p => p.Port).ToList();
        
        if (ports.Contains(3389))
            return "Windows";
        
        if (ports.Contains(445) && !ports.Contains(22))
            return "Windows";
        
        if (ports.Contains(22))
        {
            if (ports.Contains(80) || ports.Contains(443))
                return "Linux/Unix";
        }

        return "";
    }

    private List<int> ParsePorts(string? ports)
    {
        if (string.IsNullOrWhiteSpace(ports))
        {
            return new List<int> { 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443 };
        }

        var portList = new List<int>();
        var parts = ports.Split(',');

        foreach (var part in parts)
        {
            if (part.Contains('-'))
            {
                var range = part.Split('-');
                if (range.Length == 2 && int.TryParse(range[0], out int start) && int.TryParse(range[1], out int end))
                {
                    portList.AddRange(Enumerable.Range(start, end - start + 1));
                }
            }
            else if (int.TryParse(part.Trim(), out int port))
            {
                portList.Add(port);
            }
        }

        return portList;
    }

    private async Task<PortInfo> ScanSinglePort(string target, int port, bool verbose)
    {
        try
        {
            using var tcpClient = new TcpClient();
            var connectTask = tcpClient.ConnectAsync(target, port);
            
            if (await Task.WhenAny(connectTask, Task.Delay(ConnectTimeoutMs)) == connectTask)
            {
                if (tcpClient.Connected)
                {
                    tcpClient.Close();
                    return new PortInfo
                    {
                        Port = port,
                        IsOpen = true,
                        Service = ""
                    };
                }
            }
            
            tcpClient.Close();
            return new PortInfo { Port = port, IsOpen = false };
        }
        catch (SocketException)
        {
            return new PortInfo { Port = port, IsOpen = false };
        }
        catch
        {
            return new PortInfo { Port = port, IsOpen = false, IsFiltered = true };
        }
    }

    private class PortInfo
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public bool IsFiltered { get; set; }
        public string Service { get; set; } = "Inconnu";
    }
}
