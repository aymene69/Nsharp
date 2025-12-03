using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Data.Sqlite;
using Nsharp.Models;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Nsharp.Services;

public class NetworkScanner
{
    private const int MaxConcurrentScans = 100;
    private const int ConnectTimeoutMs = 2000;
    private readonly AdvancedServiceDetector _advancedDetector;
    private readonly PortServiceLookup? _portLookup;
    
    public NetworkScanner(IServiceProvider serviceProvider)
    {
        _advancedDetector = new AdvancedServiceDetector();
        // Résolution manuelle optionnelle pour éviter le crash au démarrage si le service manque
        _portLookup = serviceProvider.GetService<PortServiceLookup>();
    }

    public async Task<ScanResponse> ScanAsync(string target, string? ports, bool aggressive)
    {
        var response = new ScanResponse();

        using var conn = new SqliteConnection("Data Source=scans.sqlite");
        conn.Open();

        var createTable = conn.CreateCommand();

        // On créé 2 table 1 pour l'ensemble des informations d'un scan et l'autre pour faire une corrélation entre le scan et l'OS detecté
        createTable.CommandText = @"
        CREATE TABLE IF NOT EXISTS ScanGroups (
            GroupScanId INTEGER PRIMARY KEY,
            OS TEXT DEFAULT 'Aucun'
        );

        CREATE TABLE IF NOT EXISTS ScanResults (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            GroupScanId INTEGER,
            Target TEXT,
            Port INTEGER,
            Service TEXT,
            Protocol TEXT,
            Status TEXT
        );
        ";
        createTable.ExecuteNonQuery();

        // génération d'un ID de groupe pour ce scan (nous permettera de faire un groupement plus tard)
        var groupScanId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        try
        {
            var portList = ParsePorts(ports);
            var openPorts = new List<PortInfo>();

            // Scan exclusivement en TCP Connect
            var openPortNumbers = await ScanTcpConnect(target, portList);
            
            openPorts = openPortNumbers.Select(p => new PortInfo 
            { 
                Port = p, 
                IsOpen = true, 
                // Pré-remplir avec le nom standard NMAP si dispo
                Service = _portLookup?.GetServiceName(p, "tcp") ?? ""
            }).ToList();

            foreach (var port in openPorts.OrderBy(p => p.Port))
            {
                var fingerprint = await _advancedDetector.DetectServiceAdvanced(target, port.Port);
                
                // Si la détection avancée échoue ou est générique, on garde le nom NMAP
                var finalServiceName = fingerprint.ServiceName;
                
                // Critères élargis pour utiliser le nom NMAP
                if (string.IsNullOrEmpty(finalServiceName) || 
                    finalServiceName == "Inconnu" || 
                    finalServiceName.Contains("Service TCP actif") || 
                    finalServiceName.Contains("Service inconnu") ||
                    finalServiceName.Contains("probablement"))
                {
                    // Utiliser le nom du fichier nmap-services si la détection active n'a rien trouvé de mieux
                    if (_portLookup != null)
                    {
                        var nmapName = _portLookup.GetServiceName(port.Port, "tcp");
                        if (nmapName != "unknown")
                        {
                            finalServiceName = nmapName;
                            fingerprint.ServiceName = nmapName; // MAJ pour cohérence
                        }
                    }
                }

                var detailsBuilder = new StringBuilder();
                detailsBuilder.AppendLine($"Service détecté : {finalServiceName}");
                detailsBuilder.AppendLine($"Confiance : {fingerprint.Confidence}%");
                detailsBuilder.AppendLine();
                detailsBuilder.AppendLine(fingerprint.Details);
                
                if (fingerprint.DetectionMethods.Count > 0)
                {
                    detailsBuilder.AppendLine();
                    detailsBuilder.AppendLine("Méthodes de détection utilisées :");
                    foreach (var method in fingerprint.DetectionMethods.Take(3))
                    {
                        detailsBuilder.AppendLine($"- {method}");
                    }
                }
                
                var scanResult = new ScanResult
                {
                    Port = port.Port,
                    Service = finalServiceName,
                    Details = detailsBuilder.ToString().TrimEnd(),
                    Protocol = DetermineProtocol(fingerprint),
                    Status = "OUVERT",
                    StateDescription = GenerateStateDescription(fingerprint),
                    Advice = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris."
                };

                // On prépare la commande pour inserer les valeurs
                var insertTable = conn.CreateCommand();
                insertTable.CommandText =
                @"
                INSERT INTO ScanResults 
                (GroupScanID, Target, Port, Service, Protocol, Status)
                VALUES ($groupId, $t, $p, $s, $proto, $status);
                ";

                // Insertion des valeurs dans la table ScanResults
                insertTable.Parameters.AddWithValue("$groupId", groupScanId);
                insertTable.Parameters.AddWithValue("$t", target);
                insertTable.Parameters.AddWithValue("$p", scanResult.Port);
                insertTable.Parameters.AddWithValue("$s", scanResult.Service);
                insertTable.Parameters.AddWithValue("$proto", scanResult.Protocol);
                insertTable.Parameters.AddWithValue("$status", scanResult.Status);

                insertTable.ExecuteNonQuery(); // Exécution de la requête


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

            // Insertion des valeurs dans la table ScanResults
            var insertGroup = conn.CreateCommand();
            insertGroup.CommandText = @"
                INSERT INTO ScanGroups (GroupScanId, OS)
                VALUES ($groupId, $os);
            ";
            insertGroup.Parameters.AddWithValue("$groupId", groupScanId);
            insertGroup.Parameters.AddWithValue("$os", response.OsDetection);
            insertGroup.ExecuteNonQuery();

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors du scan : {ex.Message}");
        }

        return response;
    }

    private async Task<List<int>> ScanTcpConnect(string target, List<int> portList)
    {
        var openPorts = new List<int>();
        using var semaphore = new SemaphoreSlim(MaxConcurrentScans);
        
        var scanTasks = portList.Select(async port =>
        {
            await semaphore.WaitAsync();
            try
            {
                return await ScanSinglePort(target, port);
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
            desc.Append($" - Service {fingerprint.ServiceName} identifié avec haute confiance");
        }
        else if (fingerprint.Confidence >= 50)
        {
            desc.Append($" - Service {fingerprint.ServiceName} identifié avec confiance moyenne");
        }
        else if (fingerprint.TcpConnectable)
        {
            desc.Append(" - Service actif mais identification incertaine");
        }
        
        if (fingerprint.ConnectionTimeMs > 0)
        {
            desc.Append($" (temps de réponse: {fingerprint.ConnectionTimeMs:F0}ms)");
        }
        
        return desc.ToString();
    }

    private async Task<string> DetectOperatingSystem(string target, List<PortInfo> openPorts)
    {
        string pingResult = "";
        
        try
        {
            var ping = new Ping();
            var reply = await ping.SendPingAsync(target, 2000);
            
            if (reply.Status == IPStatus.Success)
            {
                var ttl = reply.Options?.Ttl ?? 0;
                
                if (ttl >= 120 && ttl <= 128)
                {
                    pingResult = "Windows (TTL: " + ttl + ")";
                }
                else if (ttl >= 60 && ttl <= 70)
                {
                    pingResult = "Linux/Unix (TTL: " + ttl + ")";
                }
                else if (ttl >= 250)
                {
                    pingResult = "Cisco/Network Device (TTL: " + ttl + ")";
                }
                else
                {
                    pingResult = "OS inconnu (TTL: " + ttl + ")";
                }
            }
        }
        catch
        {
            // Ignorer l'erreur de ping, on continue avec les services
        }

        var serviceBasedGuess = EstimateOsFromServices(openPorts);
        
        if (!string.IsNullOrEmpty(pingResult) && !pingResult.Contains("inconnu"))
        {
            return pingResult;
        }
        
        if (!string.IsNullOrEmpty(serviceBasedGuess))
        {
            if (!string.IsNullOrEmpty(pingResult))
            {
                return $"{serviceBasedGuess} (basé sur services) - Ping: {pingResult}";
            }
            return $"{serviceBasedGuess} (basé sur services)";
        }

        return !string.IsNullOrEmpty(pingResult) ? pingResult : "Détection OS impossible";
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
            // Liste par défaut "Top ports" si aucun port spécifié
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

    private async Task<PortInfo> ScanSinglePort(string target, int port)
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
