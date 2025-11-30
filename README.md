# CyberTool - All-in-One Cybersecurity Toolkit

A comprehensive command-line cybersecurity toolkit designed for educational purposes and ethical security testing. This tool provides beginners with an easy-to-use interface for various cybersecurity tasks.

## ⚠️ IMPORTANT DISCLAIMER

**This tool is intended for educational and ethical purposes only.** 
- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with applicable laws and regulations
- The authors are not responsible for any misuse of this software

## 🚀 Features

### 🔍 Subdomain Enumeration
- DNS brute force attack
- DNS zone transfer attempts
- Search engine simulation
- HTTP response verification
- Export results to file

### 🔒 PDF Protection Tool
- Add password protection to PDF files
- Multiple encryption levels (40-bit to 256-bit AES)
- Configurable user permissions
- Verify existing protection

### 🔓 PDF Cracker
- Dictionary attack
- Brute force attack
- Mask-based attacks
- Progress tracking
- Password verification

### 🌐 Network Scanner
- Discover hosts on network
- Quick scan (ping only)
- Detailed scan (ports, services, OS detection)
- Network interface information
- Export scan results

### 🚪 Port Scanner
- TCP port scanning
- Common ports database
- Service detection
- Banner grabbing
- Web technology detection

### 💣 Password Cracker
- Multiple hash support (MD5, SHA1, SHA256, etc.)
- Dictionary attacks
- Brute force attacks
- Mask attacks
- Hash type detection

### 🔐 SSH Cracker
- SSH credential testing
- Dictionary attacks
- Username/password bruteforce
- Connection verification
- Service information gathering

### 📁 FTP Cracker
- FTP credential testing
- Anonymous access detection
- Server exploration
- File/directory listing
- Upload/download capabilities

### ℹ️ Information Stealer
- System information gathering
- Hardware details
- Network configuration
- Running processes
- Security settings

## 📋 Requirements

- Python 3.6 or higher
- Required packages listed in `requirements.txt`

## 🛠️ Installation

1. Clone or download this repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the main script:
   ```bash
   python main.py
   ```

## 📖 Usage

### Main Interface

Launch the tool and navigate through the intuitive menu system:

```bash
python main.py
```

The main menu provides access to all tools with numbered options for easy selection.

### Individual Tools

Each tool can also be run individually:

```bash
# Subdomain enumeration
python -m tools.subdomain_enum

# PDF protection
python -m tools.pdf_protector

# And so on for other tools...
```

## 🔧 Configuration

### Wordlists

Most tools support custom wordlists. Place your wordlist files in a directory and specify the path when prompted.

### Settings

Tools are designed with sensible defaults but can be customized during runtime:
- Timeout values
- Thread counts
- Port ranges
- Attack parameters

## 📊 Output Formats

Results can be saved in various formats:
- Text files (.txt)
- JSON files (.json)
- CSV files for port scans
- Custom formats for specific tools

## 🛡️ Safety Features

- **User confirmation** for potentially destructive operations
- **Timeout protection** to prevent hanging
- **Progress indicators** for long-running operations
- **Error handling** with informative messages
- **Interrupt support** (Ctrl+C) for graceful exit

## 🎯 Educational Value

This toolkit is perfect for:
- **Learning cybersecurity concepts**
- **Understanding network protocols**
- **Practicing ethical hacking techniques**
- **Security awareness training**
- ** penetration testing practice**

## 📚 Tool Descriptions

### Subdomain Enumeration
Discover hidden subdomains using multiple techniques including DNS brute force, zone transfers, and search engine queries.

### PDF Protection & Cracking
Learn about PDF security by both protecting and cracking PDF files using various attack methods.

### Network & Port Scanning
Understand network reconnaissance by scanning for hosts, services, and open ports.

### Password Cracking
Learn about password security and hash cracking techniques.

### Service Cracking
Practice credential testing against SSH and FTP services.

### Information Gathering
Understand system enumeration and intelligence gathering techniques.

## 🔒 Security Notes

- All network operations use reasonable timeouts
- No persistent backdoors or modifications are made
- Temporary files are cleaned up automatically
- Sensitive information is filtered from logs
- Operations require explicit user confirmation

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows Python best practices
- Error handling is comprehensive
- Educational value is maintained
- Security implications are considered

## 📄 License

This project is intended for educational use. Please refer to the LICENSE file for specific terms.

## ⚡ Performance Tips

- Use appropriate thread counts for your system
- Limit port ranges for faster scans
- Use custom wordlists for better results
- Monitor system resources during intensive operations

## 🆘 Troubleshooting

### Common Issues

1. **Import errors**: Ensure all dependencies are installed
2. **Permission denied**: Run with appropriate permissions for network operations
3. **Timeout issues**: Increase timeout values for slow networks
4. **Large scans**: Break large scans into smaller chunks

### Debug Mode

Enable verbose output by setting environment variable:
```bash
export DEBUG=1
python main.py
```

## 📞 Support

For educational support and questions:
- Check the README and inline documentation
- Review tool-specific help menus
- Ensure you understand the concepts before use

---

**Remember**: With great power comes great responsibility. Use these tools ethically and responsibly!