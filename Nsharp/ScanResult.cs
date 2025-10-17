namespace Nsharp
{
    public class ScanResult
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public string Service { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Banner { get; set; } = string.Empty;
        public string VulnerabilityInfo { get; set; } = string.Empty;
    }
}
