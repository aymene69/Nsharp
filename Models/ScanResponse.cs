namespace Nsharp.Models;

public class ScanResponse
{
    public List<ScanResult> Results { get; set; } = new();
    public string? OsDetection { get; set; }
}

