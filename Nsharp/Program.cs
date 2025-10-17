using System;
using System.Linq;
using Nsharp;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Nsharp - Network Scanner for Exploitation");
        Console.WriteLine("==========================================\n");

        if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
        {
            ShowHelp();
            return;
        }

        var options = ParseArguments(args);
        
        if (options == null)
        {
            Console.WriteLine("Invalid arguments. Use -h for help.");
            return;
        }

        var scanner = new NetworkScanner(options);
        scanner.Run();
    }

    static ScanOptions? ParseArguments(string[] args)
    {
        var options = new ScanOptions();
        
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-t":
                case "--target":
                    if (i + 1 < args.Length)
                        options.Target = args[++i];
                    break;
                case "-p":
                case "--ports":
                    if (i + 1 < args.Length)
                        options.Ports = args[++i];
                    break;
                case "-sS":
                    options.ScanType = ScanType.SYN;
                    break;
                case "-sT":
                    options.ScanType = ScanType.TCPConnect;
                    break;
                case "-sV":
                    options.ServiceDetection = true;
                    break;
                case "-O":
                    options.OSDetection = true;
                    break;
                case "--script":
                    if (i + 1 < args.Length)
                        options.Scripts = args[++i].Split(',');
                    break;
                case "-v":
                    options.Verbose = true;
                    break;
                case "-oX":
                    if (i + 1 < args.Length)
                        options.OutputXML = args[++i];
                    break;
                case "-oJ":
                    if (i + 1 < args.Length)
                        options.OutputJSON = args[++i];
                    break;
                case "--threads":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int threads))
                        options.MaxThreads = threads;
                    break;
                case "--timeout":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int timeout))
                        options.Timeout = timeout;
                    break;
            }
        }

        if (string.IsNullOrEmpty(options.Target))
            return null;

        return options;
    }

    static void ShowHelp()
    {
        Console.WriteLine("Usage: Nsharp [options]");
        Console.WriteLine("\nTarget Specification:");
        Console.WriteLine("  -t, --target <host>     Target IP address or hostname");
        Console.WriteLine("\nPort Specification:");
        Console.WriteLine("  -p, --ports <ports>     Port ranges (e.g., 1-1000, 80,443,8080)");
        Console.WriteLine("                          Default: 1-1024");
        Console.WriteLine("\nScan Techniques:");
        Console.WriteLine("  -sT                     TCP Connect scan (default)");
        Console.WriteLine("  -sS                     SYN scan (stealth scan)");
        Console.WriteLine("\nService/Version Detection:");
        Console.WriteLine("  -sV                     Probe open ports for service/version info");
        Console.WriteLine("\nOS Detection:");
        Console.WriteLine("  -O                      Enable OS detection");
        Console.WriteLine("\nExploitation Scripts:");
        Console.WriteLine("  --script <scripts>      Run exploitation scripts (e.g., smb-vuln,ftp-anon)");
        Console.WriteLine("\nOutput:");
        Console.WriteLine("  -oX <file>              Output results to XML file");
        Console.WriteLine("  -oJ <file>              Output results to JSON file");
        Console.WriteLine("\nTiming and Performance:");
        Console.WriteLine("  --threads <num>         Number of parallel threads (default: 10)");
        Console.WriteLine("  --timeout <ms>          Timeout for connections in milliseconds (default: 1000)");
        Console.WriteLine("\nMisc:");
        Console.WriteLine("  -v                      Verbose output");
        Console.WriteLine("  -h, --help              Show this help message");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  Nsharp -t 192.168.1.1 -p 1-1000");
        Console.WriteLine("  Nsharp -t scanme.nmap.org -sV -O");
        Console.WriteLine("  Nsharp -t 10.0.0.1 -p 80,443 --script smb-vuln,ftp-anon");
    }
}
