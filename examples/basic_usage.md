# CyberTool - Basic Usage Examples

This guide provides step-by-step examples for using each tool in CyberTool.

## 🚀 Getting Started

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run CyberTool:**
   ```bash
   python main.py
   ```

3. **Navigate the menu** using the numbered options.

## 🔍 Subdomain Enumeration

### Basic Enumeration
```
1. Select option "1" from main menu
2. Enter domain: example.com
3. Choose enumeration method: "4" (All Methods)
4. Wait for results
5. Check example.com_subdomains.txt for saved results
```

### Custom Wordlist
```
1. Select option "1" from main menu
2. Enter domain: your-domain.com
3. Choose method: "1" (DNS Brute Force)
4. Create custom wordlist file: custom_subdomains.txt
5. Modify the script to use your wordlist (advanced)
```

## 🔒 PDF Protection

### Protect a PDF File
```
1. Select option "2" from main menu
2. Select "1" (Protect a new PDF)
3. Enter path to PDF: /path/to/document.pdf
4. Enter password: YourSecurePassword123
5. Confirm password: YourSecurePassword123
6. Choose encryption level: "3" (128-bit AES)
7. Configure permissions as needed
8. Check document_protected.pdf for output
```

### Verify Protection
```
1. Select option "2" from main menu
2. Select "2" (Verify existing protection)
3. Enter path to protected PDF
4. Enter password to verify
5. View protection status
```

## 🔓 PDF Cracking

### Dictionary Attack
```
1. Select option "3" from main menu
2. Enter path to encrypted PDF
3. Select "1" (Dictionary Attack)
4. Use built-in wordlist or provide custom one
5. Wait for password recovery
6. Check PDF_crack_results.txt for findings
```

### Quick Common Password Attack
```
1. Select option "3" from main menu
2. Enter PDF file path
3. Select "4" (Common Passwords Attack)
4. Review results quickly
```

## 🌐 Network Scanner

### Quick Network Scan
```
1. Select option "4" from main menu
2. Select "1" (Quick Scan)
3. Use default network range or specify: 192.168.1.0/24
4. Wait for ping sweep results
5. Check network_scan_results.txt for output
```

### Detailed Network Scan
```
1. Select option "4" from main menu
2. Select "2" (Detailed Scan)
3. Enter network range
4. Wait for comprehensive results including:
   - Host discovery
   - Open ports
   - OS detection
   - Service identification
```

## 🚪 Port Scanner

### Common Ports Scan
```
1. Select option "5" from main menu
2. Select "1" (Common Ports Scan)
3. Enter target IP: 192.168.1.100
4. Use default timeout: 3 seconds
5. Review found services
```

### Custom Port Range
```
1. Select option "5" from main menu
2. Select "5" (Custom Port Range)
3. Enter target: example.com
4. Start port: 1
5. End port: 1000
6. Wait for comprehensive scan
```

## 💣 Password Cracker

### Single Hash Cracking
```
1. Select option "6" from main menu
2. Select "1" (Crack Single Hash)
3. Enter hash: 5f4dcc3b5aa765d61d8327deb882cf99
4. Tool detects: MD5
5. Select "1" (Dictionary Attack)
6. Use built-in wordlist
7. Password found: password
```

### Multiple Hashes
```
1. Select option "6" from main menu
2. Select "2" (Crack Multiple Hashes)
3. Enter hashes (one per line):
   5f4dcc3b5aa765d61d8327deb882cf99
   25d55ad283aa400af464c76d713c07ad
4. Wait for batch processing
5. Review cracked passwords
```

## 🔐 SSH Cracker

### Dictionary Attack
```
1. Select option "7" from main menu
2. Enter target: 192.168.1.50
3. Port: 22 (default)
4. Select "1" (Dictionary Attack)
5. Use built-in username/password lists
6. Monitor progress bar
7. Test found credentials
```

### Single Username Test
```
1. Select option "7" from main menu
2. Enter target
3. Select "3" (Password Bruteforce)
4. Enter username: admin
5. Use built-in password list
6. Focus on one account
```

## 📁 FTP Cracker

### Test Anonymous Access
```
1. Select option "8" from main menu
2. Enter FTP server: ftp.example.com
3. Port: 21 (default)
4. Select "2" (Test Anonymous Access)
5. Check if anonymous login works
6. Explore server if accessible
```

### Credential Testing
```
1. Select option "8" from main menu
2. Enter target FTP server
3. Select "1" (Dictionary Attack)
4. Use wordlists
5. Explore server with valid credentials
6. List files and directories
```

## ℹ️ Information Stealer

### Full System Scan
```
1. Select option "9" from main menu
2. Select "1" (Full System Information Gathering)
3. Wait for comprehensive scan including:
   - System details
   - Hardware information
   - Network configuration
   - Running processes
   - Security settings
4. Save results as JSON
```

### Network Scan Only
```
1. Select option "9" from main menu
2. Select "4" (Network Information Only)
3. Review network interfaces
4. Check active connections
5. View public IP address
```

## 📊 Result Files

All tools create output files with timestamps:

- `*_subdomains.txt` - Subdomain enumeration results
- `*_protected.pdf` - Protected PDF files
- `*_crack_results.txt` - Password cracking results
- `network_scan_*.txt` - Network scan results
- `*_port_scan_*.txt` - Port scan results
- `ssh_crack_results_*.txt` - SSH cracking results
- `ftp_crack_results_*.txt` - FTP cracking results
- `info_gathering_*.json` - System information results

## 🛡️ Safety Tips

1. **Start with Quick Scans** - Use quick scan modes before comprehensive ones
2. **Use Appropriate Timeouts** - Increase timeouts for slow networks
3. **Monitor System Resources** - Watch CPU and memory usage during scans
4. **Save Results Often** - Export results for analysis and documentation
5. **Test on Known Systems** - Practice on systems you own or lab environments

## 🔧 Advanced Configuration

### Custom Wordlists
Create your own wordlist files:
```bash
# Create custom passwords
echo -e "admin123\npassword2024\nmysecretpass" > custom_passwords.txt

# Use in tools (modify scripts or copy to wordlists directory)
cp custom_passwords.txt wordlists/
```

### Performance Tuning
- Adjust thread counts in individual tools
- Modify timeout values for network operations
- Limit port ranges for faster scanning

## ❓ Troubleshooting

### Common Issues

**Tool fails to start:**
```bash
# Check Python version
python --version  # Should be 3.6+

# Install missing dependencies
pip install -r requirements.txt

# Check permissions (may need admin for network operations)
```

**Network scans timeout:**
- Increase timeout values
- Check firewall settings
- Verify target connectivity

**Permission denied errors:**
- Run with appropriate privileges
- Check system permissions
- Some operations require admin rights

**Import errors:**
```bash
# Reinstall dependencies
pip uninstall -y -r requirements.txt
pip install -r requirements.txt

# Check Python path
echo $PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

## 📚 Next Steps

After mastering these basics:

1. **Study the source code** - Understand how each tool works
2. **Create custom wordlists** - Build targeted password lists
3. **Automate workflows** - Chain tools together
4. **Analyze results** - Use the data for security assessments
5. **Contribute improvements** - Add features or fix issues

Remember: Always use these tools ethically and legally!