using System.Collections.Concurrent;

namespace Nsharp.Services;

public class PortServiceLookup
{
    // Dictionnaire (Port, Protocole) -> Nom du Service
    private readonly Dictionary<(int, string), string> _services = new();
    private readonly ILogger<PortServiceLookup> _logger;

    public PortServiceLookup(ILogger<PortServiceLookup> logger)
    {
        _logger = logger;
        LoadServices();
    }

    private void LoadServices()
    {
        var filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Services", "nmap-services.txt");
        
        // Fallback si le fichier n'est pas copié dans le dossier de sortie, on cherche à la racine du projet en dev
        if (!File.Exists(filePath))
        {
            filePath = Path.Combine(Directory.GetCurrentDirectory(), "Services", "nmap-services.txt");
        }

        if (!File.Exists(filePath))
        {
            _logger.LogWarning("nmap-services.txt not found at {Path}. Port lookup will be disabled.", filePath);
            return;
        }

        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                // Ignorer les commentaires et les lignes vides
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;

                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                var serviceName = parts[0];
                var portProtocol = parts[1].Split('/');

                if (portProtocol.Length == 2 && int.TryParse(portProtocol[0], out int port))
                {
                    var protocol = portProtocol[1].ToLower(); // tcp ou udp
                    var key = (port, protocol);

                    // On garde le premier (souvent le plus fréquent/standard) s'il y a des doublons
                    if (!_services.ContainsKey(key))
                    {
                        _services[key] = serviceName;
                    }
                }
            }
            _logger.LogInformation("Loaded {Count} services from nmap-services.txt", _services.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading nmap-services.txt");
        }
    }

    public string GetServiceName(int port, string protocol = "tcp")
    {
        if (_services.TryGetValue((port, protocol.ToLower()), out var serviceName))
        {
            return serviceName;
        }
        return "unknown";
    }
}

