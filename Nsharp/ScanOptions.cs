namespace Nsharp
{
    public enum ScanType
    {
        TCPConnect,
        SYN
    }

    public class ScanOptions
    {
        public string Target { get; set; } = string.Empty;
        public string Ports { get; set; } = "1-1024";
        public ScanType ScanType { get; set; } = ScanType.TCPConnect;
        public bool ServiceDetection { get; set; } = false;
        public bool OSDetection { get; set; } = false;
        public string[] Scripts { get; set; } = Array.Empty<string>();
        public bool Verbose { get; set; } = false;
        public string OutputXML { get; set; } = string.Empty;
        public string OutputJSON { get; set; } = string.Empty;
        public int MaxThreads { get; set; } = 10;
        public int Timeout { get; set; } = 1000;
    }
}
