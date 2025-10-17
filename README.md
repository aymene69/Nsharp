# Nsharp

**Network Scanner for Exploitation** - An enhanced Nmap-like tool written in C# with limited features, oriented towards exploitation and security assessment.

## Features

Nsharp provides essential network scanning capabilities with a focus on exploitation:

### Core Scanning
- **TCP Connect Scan** (`-sT`) - Full TCP connection to target ports
- **SYN Scan** (`-sS`) - Stealth scanning (requires admin privileges, falls back to TCP connect)
- **Port Specification** - Flexible port ranges (e.g., 1-1000, 80,443,8080)
- **Multi-threaded Scanning** - Configurable thread count for fast scanning

### Detection Capabilities
- **Service Detection** (`-sV`) - Identifies services and versions through banner grabbing
- **OS Fingerprinting** (`-O`) - Basic OS detection using TTL, open ports, and service banners
- **Banner Grabbing** - Captures service banners for analysis

### Exploitation-Oriented Features
Nsharp includes built-in scripts for vulnerability assessment:

- **ftp-anon** - Checks for anonymous FTP login
- **smb-vuln** - Identifies SMB services and potential vulnerabilities (EternalBlue, SMBGhost)
- **ssh-auth** - Analyzes SSH banners for known vulnerable versions
- **http-methods** - Tests HTTP methods and identifies dangerous ones (PUT, DELETE)
- **mysql-empty-password** - Flags MySQL instances for credential testing
- **default-creds** - Suggests services to test for default credentials

### Output Options
- **Console Output** - Clear, formatted results
- **XML Export** (`-oX`) - Nmap-compatible XML output
- **JSON Export** (`-oJ`) - JSON format for easy parsing

## Installation

### Prerequisites
- .NET 8.0 SDK or later

### Build from Source
```bash
git clone https://github.com/aymene69/Nsharp.git
cd Nsharp/Nsharp
dotnet build -c Release
```

### Run
```bash
dotnet run --project Nsharp -- [options]
```

Or after building:
```bash
cd bin/Release/net8.0
./Nsharp [options]
```

## Usage

### Basic Syntax
```bash
Nsharp -t <target> [options]
```

### Command-Line Options

#### Target Specification
- `-t, --target <host>` - Target IP address or hostname (required)

#### Port Specification
- `-p, --ports <ports>` - Port ranges (default: 1-1024)
  - Single port: `80`
  - Multiple ports: `80,443,8080`
  - Range: `1-1000`
  - Mixed: `22,80-100,443,8080-8090`

#### Scan Techniques
- `-sT` - TCP Connect scan (default)
- `-sS` - SYN scan (stealth, requires admin privileges)

#### Detection
- `-sV` - Service/version detection
- `-O` - OS detection

#### Exploitation Scripts
- `--script <scripts>` - Comma-separated list of scripts to run
  - Available: `ftp-anon`, `smb-vuln`, `ssh-auth`, `http-methods`, `mysql-empty-password`, `default-creds`

#### Output
- `-oX <file>` - Save results as XML
- `-oJ <file>` - Save results as JSON
- `-v` - Verbose output

#### Performance
- `--threads <num>` - Number of parallel threads (default: 10)
- `--timeout <ms>` - Connection timeout in milliseconds (default: 1000)

#### Help
- `-h, --help` - Display help message

### Examples

#### Basic port scan
```bash
Nsharp -t 192.168.1.1 -p 1-1000
```

#### Service detection on common ports
```bash
Nsharp -t scanme.nmap.org -p 21-25,80,443,3306,3389 -sV
```

#### Full scan with OS detection
```bash
Nsharp -t 10.0.0.1 -sV -O
```

#### Exploitation-oriented scan
```bash
Nsharp -t 192.168.1.100 -p 21,22,80,139,445 --script ftp-anon,smb-vuln,ssh-auth
```

#### Fast scan with custom threads and timeout
```bash
Nsharp -t example.com -p 1-65535 --threads 50 --timeout 500
```

#### Export results
```bash
Nsharp -t 10.0.0.1 -sV -O -oJ results.json -oX results.xml
```

#### Verbose scan with all features
```bash
Nsharp -t target.local -p 1-1000 -sV -O --script ftp-anon,smb-vuln -v
```

## Sample Output

```
Nsharp - Network Scanner for Exploitation
==========================================

Starting Nsharp scan on 192.168.1.1
Scan Type: TCPConnect
Ports: 1-1024
Threads: 10

Scanning 1024 ports...

Scan completed in 12.34 seconds
Found 5 open ports

PORT     STATE    SERVICE         VERSION
------------------------------------------------
22       OPEN     ssh             OpenSSH_7.9p1
80       OPEN     http            Apache/2.4.41
139      OPEN     netbios-ssn     
445      OPEN     microsoft-ds    
3306     OPEN     mysql           5.7.30

[*] Performing OS detection...

[*] OS Detection Results:
    OS Family: Linux
    Confidence: 85%
    Details: Likely Ubuntu

[*] Running exploitation scripts...

[*] Running script: smb-vuln
    Port 445: SMB detected - Potential targets: EternalBlue (MS17-010), SMBGhost (CVE-2020-0796)
```

## Architecture

The project is structured with the following key components:

- **Program.cs** - Entry point, argument parsing, and help system
- **ScanOptions.cs** - Configuration and scan options
- **NetworkScanner.cs** - Core scanning engine and orchestration
- **ScanResult.cs** - Data model for scan results
- **ServiceDetector.cs** - Service and version detection logic
- **OSDetector.cs** - Operating system fingerprinting
- **ExploitationScripts.cs** - Vulnerability assessment scripts
- **OutputFormatter.cs** - XML and JSON output generation

## Limitations

This is a limited-feature network scanner compared to Nmap:

- No UDP scanning support
- SYN scan falls back to TCP connect on most systems
- Basic OS fingerprinting (not as accurate as Nmap)
- Limited service detection database
- No NSE (Nmap Scripting Engine) compatibility
- No traceroute or advanced timing templates
- Limited IPv6 support

## Security & Legal Notice

⚠️ **WARNING**: This tool is designed for authorized security testing only.

- Only scan networks and systems you own or have explicit permission to test
- Unauthorized port scanning may be illegal in your jurisdiction
- Some features may trigger IDS/IPS systems
- The exploitation scripts are for assessment purposes only
- Use responsibly and ethically

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is provided as-is for educational and authorized security testing purposes.

## Acknowledgments

Inspired by Nmap (Network Mapper) by Gordon Lyon.