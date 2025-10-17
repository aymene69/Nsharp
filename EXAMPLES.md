# Nsharp Examples

This document provides comprehensive examples of using Nsharp for various network scanning and security assessment scenarios.

## Basic Scanning

### Scan a single host with default ports
```bash
Nsharp -t 192.168.1.1
```
Scans ports 1-1024 on the target host.

### Scan specific ports
```bash
Nsharp -t 10.0.0.1 -p 80,443,8080
```
Scans only ports 80, 443, and 8080.

### Scan a port range
```bash
Nsharp -t example.com -p 1-1000
```
Scans ports 1 through 1000.

### Scan with mixed port specification
```bash
Nsharp -t target.local -p 22,80-100,443,8000-9000
```
Scans port 22, ports 80-100, port 443, and ports 8000-9000.

## Service Detection

### Basic service detection
```bash
Nsharp -t 192.168.1.100 -p 20-25,80,443 -sV
```
Performs service version detection on the specified ports.

### Verbose service detection
```bash
Nsharp -t scanme.nmap.org -p 1-100 -sV -v
```
Shows detailed output during the scan including each open port as it's found.

## Operating System Detection

### OS fingerprinting
```bash
Nsharp -t 10.0.0.1 -O
```
Attempts to determine the target's operating system.

### Combined service and OS detection
```bash
Nsharp -t example.com -p 1-1000 -sV -O
```
Performs both service detection and OS fingerprinting.

## Exploitation Scripts

### Check for FTP anonymous login
```bash
Nsharp -t 192.168.1.50 -p 21 --script ftp-anon
```
Tests if anonymous FTP login is allowed.

### Check for SMB vulnerabilities
```bash
Nsharp -t 10.0.0.10 -p 445 --script smb-vuln
```
Checks for common SMB vulnerabilities like EternalBlue.

### SSH authentication analysis
```bash
Nsharp -t server.example.com -p 22 --script ssh-auth
```
Analyzes SSH banner for known vulnerable versions.

### HTTP methods testing
```bash
Nsharp -t website.com -p 80,443,8080 --script http-methods
```
Tests which HTTP methods are enabled on web servers.

### Multiple scripts
```bash
Nsharp -t 192.168.1.100 -p 21,22,80,139,445 --script ftp-anon,smb-vuln,ssh-auth,http-methods
```
Runs multiple exploitation scripts against the target.

### MySQL credential testing
```bash
Nsharp -t database.local -p 3306 --script mysql-empty-password
```
Flags MySQL instances for credential testing.

### Default credentials check
```bash
Nsharp -t 10.0.0.5 -p 21,22,23 -sV --script default-creds
```
Suggests services to test for default credentials.

## Output Options

### Save results to JSON
```bash
Nsharp -t 192.168.1.1 -p 1-1000 -sV -oJ results.json
```
Saves scan results in JSON format.

### Save results to XML
```bash
Nsharp -t example.com -p 1-100 -sV -oX results.xml
```
Saves scan results in XML format (Nmap-compatible).

### Save to both formats
```bash
Nsharp -t 10.0.0.1 -sV -O -oJ scan.json -oX scan.xml
```
Outputs results to both JSON and XML files.

## Performance Tuning

### Fast scan with more threads
```bash
Nsharp -t 192.168.1.1 -p 1-65535 --threads 50
```
Uses 50 parallel threads for faster scanning.

### Reduce timeout for faster results
```bash
Nsharp -t 10.0.0.1 -p 1-10000 --timeout 500 --threads 30
```
Sets connection timeout to 500ms with 30 threads.

### Balanced scan
```bash
Nsharp -t example.com -p 1-5000 --threads 20 --timeout 1000
```
Balanced approach with 20 threads and 1000ms timeout.

## Comprehensive Scans

### Full security assessment
```bash
Nsharp -t 192.168.1.100 -p 1-1024 -sV -O --script ftp-anon,smb-vuln,ssh-auth,http-methods,mysql-empty-password,default-creds -oJ full_scan.json -v
```
Complete scan with all features enabled.

### Web server assessment
```bash
Nsharp -t website.com -p 80,443,8080,8443 -sV --script http-methods -oJ web_scan.json
```
Focuses on web server ports with HTTP testing.

### Database server scan
```bash
Nsharp -t db.example.com -p 1433,3306,5432,27017 -sV --script mysql-empty-password -O
```
Targets common database ports.

### Windows server assessment
```bash
Nsharp -t windows-server.local -p 135,139,445,3389,1433 -sV -O --script smb-vuln,default-creds
```
Scans Windows-specific ports with relevant scripts.

### Linux server assessment
```bash
Nsharp -t linux-server.local -p 20-25,80,443,3306,5432 -sV -O --script ftp-anon,ssh-auth,http-methods
```
Scans Linux-specific ports with relevant scripts.

## Real-World Scenarios

### Internal network discovery
```bash
Nsharp -t 192.168.1.1 -p 1-1000 -sV -O --threads 30 -oJ internal_scan.json
```
Quick internal network scan with service detection.

### External perimeter scan
```bash
Nsharp -t external-ip.com -p 21,22,25,80,443,3389,8080 -sV --script ftp-anon,ssh-auth,http-methods -oJ perimeter.json
```
Scans common external-facing ports.

### Vulnerability assessment
```bash
Nsharp -t target.local -p 21,22,23,80,139,445,3306,3389 -sV -O --script ftp-anon,smb-vuln,ssh-auth,mysql-empty-password,default-creds -v -oJ vuln_assessment.json -oX vuln_assessment.xml
```
Comprehensive vulnerability assessment with all scripts.

### Quick port check
```bash
Nsharp -t server.com -p 22,80,443 --timeout 300
```
Fast check of specific ports with reduced timeout.

## Tips and Best Practices

1. **Start with a small port range** to test connectivity before running full scans
2. **Use verbose mode (-v)** when debugging or learning
3. **Adjust threads and timeout** based on network conditions
4. **Save results** to files for later analysis
5. **Combine service detection (-sV) with OS detection (-O)** for better fingerprinting
6. **Run exploitation scripts** on specific services rather than all ports
7. **Be patient with large port ranges** - scanning 65535 ports takes time
8. **Always get permission** before scanning systems you don't own

## Common Issues and Solutions

### Scan is too slow
- Increase threads: `--threads 50`
- Reduce timeout: `--timeout 500`
- Scan smaller port ranges

### Too many false positives
- Increase timeout: `--timeout 2000`
- Reduce threads to avoid network congestion

### No services detected
- Ensure `-sV` flag is used for service detection
- Some services may not respond to banner grabs
- Try verbose mode to see what's happening

### Permission denied
- SYN scan requires admin/root privileges
- Use TCP connect scan (default) instead
- Run with appropriate permissions for your OS

## Legal and Ethical Considerations

⚠️ **IMPORTANT**: Only scan systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

- Always obtain written permission before scanning
- Stay within the scope of your authorization
- Document all scans and findings
- Follow responsible disclosure practices
- Be aware of local laws and regulations
