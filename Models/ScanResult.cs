namespace Nsharp.Models;

public class ScanResult
{
    public int Port { get; set; }
    public string Service { get; set; } = "Inconnu";
    public string Details { get; set; } = "Aucun détail disponible";
    public string Protocol { get; set; } = "TCP";
    public string Status { get; set; } = "OUVERT";
    public string StateDescription { get; set; } = "Le port répond aux connexions";
    public string Advice { get; set; } = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
    
    // Nouveau champ pour l'explication de l'IA
    public string? AiExplanation { get; set; }
    
    public string PortLabel => $"Port {Port}";
}
