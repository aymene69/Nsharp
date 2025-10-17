# Nsharp Quick Reference

## Command Syntax
```
Nsharp -t <target> [options]
```

## Essential Options

| Option | Description | Example |
|--------|-------------|---------|
| `-t, --target` | Target host (required) | `-t 192.168.1.1` |
| `-p, --ports` | Port specification | `-p 1-1000` or `-p 80,443` |
| `-sT` | TCP Connect scan (default) | `-sT` |
| `-sS` | SYN scan (requires admin) | `-sS` |
| `-sV` | Service/version detection | `-sV` |
| `-O` | OS detection | `-O` |
| `-v` | Verbose output | `-v` |

## Exploitation Scripts

| Script | Description | Usage |
|--------|-------------|-------|
| `ftp-anon` | Check FTP anonymous login | `--script ftp-anon` |
| `smb-vuln` | Check SMB vulnerabilities | `--script smb-vuln` |
| `ssh-auth` | Analyze SSH banner | `--script ssh-auth` |
| `http-methods` | Test HTTP methods | `--script http-methods` |
| `mysql-empty-password` | MySQL credential check | `--script mysql-empty-password` |
| `default-creds` | Default credentials check | `--script default-creds` |

## Output Options

| Option | Format | Example |
|--------|--------|---------|
| `-oJ` | JSON output | `-oJ results.json` |
| `-oX` | XML output | `-oX results.xml` |

## Performance Tuning

| Option | Default | Description |
|--------|---------|-------------|
| `--threads` | 10 | Number of parallel threads |
| `--timeout` | 1000 | Connection timeout (ms) |

## Port Specification Examples

| Format | Description |
|--------|-------------|
| `80` | Single port |
| `80,443` | Multiple ports |
| `1-1000` | Port range |
| `22,80-100,443` | Mixed |

## Common Commands

### Quick Scan
```bash
Nsharp -t 192.168.1.1 -p 1-1000
```

### Full Scan
```bash
Nsharp -t target.com -p 1-1024 -sV -O
```

### Vulnerability Scan
```bash
Nsharp -t 10.0.0.1 -p 21,22,80,445 --script ftp-anon,smb-vuln,ssh-auth
```

### Fast Scan
```bash
Nsharp -t server.local -p 1-65535 --threads 50 --timeout 500
```

### Export Results
```bash
Nsharp -t example.com -sV -O -oJ scan.json -oX scan.xml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error occurred |

## Tips

1. **Always start with:** `-t <target> -p <ports>`
2. **Add service detection:** append `-sV`
3. **Add OS detection:** append `-O`
4. **Run scripts:** append `--script <name>`
5. **Save results:** append `-oJ file.json`
6. **Debug issues:** append `-v`

## Security Notice

⚠️ **Only scan authorized systems!**
- Get written permission
- Follow local laws
- Document all activity
- Use responsibly

## See Also

- [README.md](README.md) - Full documentation
- [EXAMPLES.md](EXAMPLES.md) - Detailed examples
- [LICENSE](LICENSE) - License information
