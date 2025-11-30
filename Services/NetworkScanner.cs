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
