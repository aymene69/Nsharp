using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Nsharp.Services;

public class AdvancedServiceDetector
{
    private const int TimeoutMs = 1500;
    
    public async Task<ServiceFingerprint> DetectServiceAdvanced(string target, int port)
    {
        var fingerprint = new ServiceFingerprint
        {
            Port = port,
            DetectionMethods = new List<string>()
        };

        try
        {
            await DetectServiceOptimized(target, port, fingerprint);
            
            AnalyzePortBehaviorPattern(port, fingerprint);
            
            DetermineServiceFromFingerprint(fingerprint);
        }
        catch (Exception ex)
        {
            fingerprint.DetectionMethods.Add($"Erreur: {ex.Message}");
        }

        return fingerprint;
    }

    private async Task DetectServiceOptimized(string target, int port, ServiceFingerprint fingerprint)
    {
        try
        {
            using var client = new TcpClient();
            var startTime = DateTime.Now;
            
            var connectTask = client.ConnectAsync(target, port);
            if (await Task.WhenAny(connectTask, Task.Delay(TimeoutMs)) != connectTask)
            {
                return;
            }

            var connectTime = (DateTime.Now - startTime).TotalMilliseconds;
            fingerprint.ConnectionTimeMs = connectTime;
            fingerprint.TcpConnectable = true;
            fingerprint.DetectionMethods.Add($"Connexion: {connectTime:F0}ms");
            
            if (!client.Connected) return;

            using var stream = client.GetStream();
            stream.ReadTimeout = 800;
            stream.WriteTimeout = 800;

            await Task.Delay(150);
            
            if (stream.DataAvailable)
            {
                var buffer = new byte[1024];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var banner = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                
                fingerprint.SendsDataFirst = true;
                AnalyzeBanner(banner, fingerprint);
                return;
            }

            await SendSmartProbe(stream, port, fingerprint);
            
        }
        catch
        {
        }
    }

    private async Task SendSmartProbe(NetworkStream stream, int port, ServiceFingerprint fingerprint)
    {
        byte[] probe;
        string probeType;

        switch (port)
        {
            case 80:
            case 8080:
            case 8000:
            case 3000:
                probe = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n");
                probeType = "HTTP";
                break;

            case 631:
                probe = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
                probeType = "IPP";
                break;

            case 443:
            case 8443:
                probe = CreateTlsClientHello();
                probeType = "TLS";
                break;

            case 21:
                probe = Encoding.ASCII.GetBytes("USER anonymous\r\n");
                probeType = "FTP";
                break;

            case 25:
            case 587:
                probe = Encoding.ASCII.GetBytes("EHLO test\r\n");
                probeType = "SMTP";
                break;

            case 22:
                probe = Encoding.ASCII.GetBytes("SSH-2.0-Test\r\n");
                probeType = "SSH";
                break;

            case 3306:
                probe = new byte[] { 0x00 };
                probeType = "MySQL";
                break;

            default:
                probe = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n");
                probeType = "HTTP_GENERIC";
                break;
        }

        try
        {
            await stream.WriteAsync(probe, 0, probe.Length);
            await Task.Delay(200);

            if (stream.DataAvailable)
            {
                var buffer = new byte[2048];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                
                if (bytesRead > 0)
                {
                    var response = Encoding.ASCII.GetString(buffer, 0, Math.Min(bytesRead, 500));
                    AnalyzeProbeResponseOptimized(probeType, response, buffer, bytesRead, fingerprint);
                }
            }
            else
            {
                fingerprint.DetectionMethods.Add($"Pas de reponse au probe {probeType}");
            }
        }
        catch
        {
        }
    }

    private void AnalyzeBanner(string banner, ServiceFingerprint fingerprint)
    {
        banner = banner.ToLower();

        if (banner.Contains("ssh"))
        {
            fingerprint.IsSsh = true;
            fingerprint.SshVersion = banner.Split('\n')[0].Trim();
            fingerprint.DetectionMethods.Add("SSH via banner spontane");
        }
        else if (banner.Contains("ftp") || banner.Contains("220"))
        {
            fingerprint.IsFtp = true;
            fingerprint.DetectionMethods.Add("FTP via banner spontane");
        }
        else if (banner.Contains("smtp") || banner.Contains("mail"))
        {
            fingerprint.IsSmtp = true;
            fingerprint.DetectionMethods.Add("SMTP via banner spontane");
        }
        else if (banner.Contains("mysql"))
        {
            fingerprint.DetectionMethods.Add("MySQL via banner spontane");
        }
        else
        {
            fingerprint.DetectionMethods.Add("Banner detecte mais non identifie");
        }
    }

    private void AnalyzeProbeResponseOptimized(string probeType, string response, byte[] rawBuffer, int length, ServiceFingerprint fingerprint)
    {
        response = response.ToLower();
        
        switch (probeType)
        {
            case "IPP":
                if (response.Contains("http/"))
                {
                    if (response.Contains("cups") || response.Contains("ipp"))
                    {
                        fingerprint.ServerHeader = "CUPS/IPP";
                        fingerprint.DetectionMethods.Add("CUPS/IPP detecte (service d'impression)");
                    }
                    else
                    {
                        fingerprint.IsHttp = true;
                        fingerprint.ServerHeader = "IPP (Printing Service)";
                        fingerprint.DetectionMethods.Add("IPP detecte via port 631");
                    }
                }
                break;
                
            case "HTTP":
            case "HTTP_GENERIC":
                if (response.Contains("http/"))
                {
                    if (response.Contains("cups") || response.Contains("ipp"))
                    {
                        fingerprint.ServerHeader = "CUPS/IPP";
                        fingerprint.DetectionMethods.Add("CUPS/IPP detecte (pas HTTP standard)");
                    }
                    else
                    {
                        fingerprint.IsHttp = true;
                        
                        var lines = response.Split('\n');
                        foreach (var line in lines)
                        {
                            if (line.ToLower().Contains("server:"))
                            {
                                fingerprint.ServerHeader = line.Substring(line.IndexOf(':') + 1).Trim();
                                break;
                            }
                        }
                        
                        fingerprint.DetectionMethods.Add("HTTP detecte via GET");
                    }
                }
                break;
                
            case "TLS":
                if (length > 5 && rawBuffer[0] == 0x16)
                {
                    fingerprint.IsTls = true;
                    fingerprint.TlsVersion = $"{rawBuffer[1]}.{rawBuffer[2]}";
                    fingerprint.DetectionMethods.Add($"TLS {fingerprint.TlsVersion} detecte");
                }
                break;
                
            case "SMTP":
                if (response.Contains("220") || response.Contains("smtp") || response.Contains("mail"))
                {
                    fingerprint.IsSmtp = true;
                    fingerprint.DetectionMethods.Add("SMTP detecte via EHLO");
                }
                break;
                
            case "FTP":
                if (response.Contains("220") || response.Contains("ftp") || response.Contains("331"))
                {
                    fingerprint.IsFtp = true;
                    fingerprint.DetectionMethods.Add("FTP detecte via USER");
                }
                break;
                
            case "SSH":
                if (response.Contains("ssh"))
                {
                    fingerprint.IsSsh = true;
                    fingerprint.SshVersion = response.Trim();
                    fingerprint.DetectionMethods.Add("SSH detecte via version");
                }
                break;
                
            case "MySQL":
                if (length > 0)
                {
                    fingerprint.DetectionMethods.Add("MySQL (reponse detectee)");
                }
                break;
        }
    }

    private void AnalyzePortBehaviorPattern(int port, ServiceFingerprint fingerprint)
    {
        fingerprint.CommonPortAssociation = port switch
        {
            21 => "FTP (standard)",
            22 => "SSH (standard)",
            23 => "Telnet (standard)",
            25 => "SMTP (standard)",
            80 => "HTTP (standard)",
            443 => "HTTPS (standard)",
            631 => "IPP/CUPS (impression)",
            3306 => "MySQL (standard)",
            5432 => "PostgreSQL (standard)",
            6379 => "Redis (standard)",
            8080 => "HTTP-Alt (standard)",
            8443 => "HTTPS-Alt (standard)",
            _ => "Port non-standard"
        };
    }

    private void DetermineServiceFromFingerprint(ServiceFingerprint fingerprint)
    {
        var confidence = 0;
        var serviceName = "Service inconnu";
        var details = new StringBuilder();

        if (!string.IsNullOrEmpty(fingerprint.ServerHeader) && 
            (fingerprint.ServerHeader.Contains("CUPS") || fingerprint.ServerHeader.Contains("IPP")))
        {
            serviceName = "CUPS/IPP (Impression)";
            confidence = 95;
            details.AppendLine("Service d'impression CUPS/IPP detecte");
            details.AppendLine("Protocol base sur HTTP mais pas un serveur web standard");
        }
        else if (fingerprint.IsHttp)
        {
            serviceName = fingerprint.IsTls ? "HTTPS" : "HTTP";
            confidence = 95;
            details.AppendLine("Service HTTP detecte par probe");
            if (!string.IsNullOrEmpty(fingerprint.ServerHeader))
            {
                details.AppendLine($"Serveur: {fingerprint.ServerHeader}");
            }
        }
        else if (fingerprint.IsSsh)
        {
            serviceName = "SSH";
            confidence = 95;
            details.AppendLine("Service SSH detecte");
            if (!string.IsNullOrEmpty(fingerprint.SshVersion))
            {
                details.AppendLine($"Version: {fingerprint.SshVersion}");
            }
        }
        else if (fingerprint.IsFtp)
        {
            serviceName = "FTP";
            confidence = 90;
            details.AppendLine("Service FTP detecte par probe");
        }
        else if (fingerprint.IsSmtp)
        {
            serviceName = "SMTP";
            confidence = 90;
            details.AppendLine("Service SMTP detecte par probe");
        }
        else if (fingerprint.IsTls)
        {
            serviceName = "TLS/SSL";
            confidence = 85;
            details.AppendLine($"Service TLS detecte (version {fingerprint.TlsVersion})");
        }
        else if (fingerprint.TcpConnectable)
        {
            if (fingerprint.SendsDataFirst)
            {
                serviceName = "Service actif (envoie banner)";
                confidence = 50;
                details.AppendLine("Service envoie des donnees spontanement");
            }
            else
            {
                serviceName = "Service TCP actif";
                confidence = 40;
                details.AppendLine("Service ecoute mais n'envoie pas de banner");
            }
            
            if (!fingerprint.CommonPortAssociation.Contains("non-standard"))
            {
                details.AppendLine($"Port couramment utilise pour: {fingerprint.CommonPortAssociation}");
                serviceName += $" (probablement {fingerprint.CommonPortAssociation.Split(' ')[0]})";
                confidence += 20;
            }
        }

        if (fingerprint.ConnectionTimeMs > 0)
        {
            details.AppendLine($"Temps de connexion: {fingerprint.ConnectionTimeMs:F0}ms");
        }

        fingerprint.ServiceName = serviceName;
        fingerprint.Confidence = confidence;
        fingerprint.Details = details.ToString().TrimEnd();
    }

    private byte[] CreateTlsClientHello()
    {
        var clientHello = new List<byte>
        {
            0x16, 0x03, 0x01, 0x00, 0x5d, 0x01, 0x00, 0x00, 0x59, 0x03, 0x03
        };
        
        clientHello.AddRange(new byte[32]);
        clientHello.AddRange(new byte[] { 0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x00 });
        
        return clientHello.ToArray();
    }
}

public class ServiceFingerprint
{
    public int Port { get; set; }
    public string ServiceName { get; set; } = "Inconnu";
    public string Details { get; set; } = "";
    public int Confidence { get; set; } = 0;
    public List<string> DetectionMethods { get; set; } = new();
    
    public bool TcpConnectable { get; set; }
    public double ConnectionTimeMs { get; set; }
    public double AverageResponseTimeMs { get; set; }
    public double TimingConsistency { get; set; }
    public bool SendsDataFirst { get; set; }
    
    public bool IsHttp { get; set; }
    public bool IsTls { get; set; }
    public bool IsSsh { get; set; }
    public bool IsFtp { get; set; }
    public bool IsSmtp { get; set; }
    
    public string? ServerHeader { get; set; }
    public string? TlsVersion { get; set; }
    public string? SshVersion { get; set; }
    public string CommonPortAssociation { get; set; } = "";
}

