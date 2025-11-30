#!/usr/bin/env python3
"""
Port Scanner Tool
Scan for open ports on target hosts
"""

import os
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from tqdm import tqdm
import ipaddress

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.lock = threading.Lock()
        self.stop_scan = False
        
        # Common port mappings
        self.port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL',
            3306: 'MySQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            11211: 'Memcached', 5984: 'CouchDB', 1521: 'Oracle', 5601: 'Kibana',
            5060: 'SIP', 5061: 'SIPS', 161: 'SNMP', 162: 'SNMP-Trap',
            389: 'LDAP', 636: 'LDAPS', 88: 'Kerberos', 464: 'Kerberos-PWD',
            445: 'SMB', 992: 'TelnetS', 5900: 'VNC', 5433: 'PostgreSQL-Alt'
        }
        
        # Port lists for different scan types
        self.common_ports = list(self.port_services.keys())
        self.web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9090]
        self.database_ports = [3306, 5432, 1433, 1521, 27017, 6379, 11211, 5984]
        self.remote_ports = [22, 23, 3389, 5900, 5433, 5060, 5061]
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           🚪 PORT SCANNER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Scan for open ports on target hosts")
        print(Fore.RED + "⚠️  Scan only hosts you own or have permission to test!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def validate_target(self, target):
        """Validate IP address or hostname"""
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True, "Valid IP address"
        except ValueError:
            # Try to resolve as hostname
            try:
                socket.gethostbyname(target)
                return True, "Valid hostname"
            except socket.gaierror:
                return False, "Invalid hostname or IP address"
    
    def scan_port(self, target, port, timeout=3):
        """Scan a single port"""
        if self.stop_scan:
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                # Port is open, get service info
                service = self.get_service_info(target, port)
                return {
                    'port': port,
                    'service': service,
                    'state': 'open',
                    'banner': self.get_banner(target, port) if port in [21, 22, 25, 80, 110, 143, 443] else None
                }
            else:
                return None
        except Exception:
            return None
    
    def get_service_info(self, target, port):
        """Get service information for port"""
        if port in self.port_services:
            return self.port_services[port]
        else:
            return "Unknown"
    
    def get_banner(self, target, port, timeout=5):
        """Grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send appropriate request based on port
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 443 or port == 8443:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:
                # FTP server usually sends banner immediately
                pass
            elif port == 22:
                # SSH server usually sends banner immediately
                pass
            elif port == 25:
                # SMTP server usually sends banner immediately
                pass
            
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner[:100] if banner else None
            except:
                sock.close()
                return None
                
        except Exception:
            return None
    
    def scan_ports_range(self, target, ports, timeout=3, max_threads=100):
        """Scan a range of ports"""
        print(Fore.CYAN + f"[*] Scanning {len(ports)} ports on {target}")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port, timeout): port for port in ports}
            
            with tqdm(total=len(futures), desc="Scanning ports", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                
                for future in as_completed(futures):
                    if self.stop_scan:
                        break
                    
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.open_ports.append(result)
                            print(Fore.GREEN + f"\n[+] Port {result['port']}/{result['service']} is OPEN" + Style.RESET_ALL)
                    except Exception:
                        pass
                    
                    pbar.update(1)
        
        return self.open_ports
    
    def tcp_scan(self, target, start_port, end_port, timeout=3):
        """Perform TCP connect scan"""
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports_range(target, ports, timeout)
    
    def syn_scan_warning(self):
        """Show SYN scan warning (requires root)"""
        print(Fore.YELLOW + "\n[*] SYN Scan Notice:")
        print("    SYN scanning requires root/administrator privileges")
        print("    This implementation uses TCP connect scan instead")
        print("    which is less stealthy but doesn't require root")
        print(Style.RESET_ALL)
    
    def detect_web_technologies(self, target):
        """Detect web technologies on HTTP ports"""
        web_info = {}
        http_ports = [80, 443, 8080, 8443]
        
        for port in http_ports:
            if any(p['port'] == port for p in self.open_ports):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, port))
                    
                    request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                    sock.send(request.encode())
                    
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    # Parse headers
                    headers = {}
                    lines = response.split('\n')
                    for line in lines:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()
                    
                    web_info[port] = {
                        'server': headers.get('server', 'Unknown'),
                        'powered_by': headers.get('x-powered-by', 'Unknown'),
                        'status_code': response.split()[1] if len(response.split()) > 1 else 'Unknown'
                    }
                    
                except Exception:
                    pass
        
        return web_info
    
    def save_results(self, target, results, scan_type, duration):
        """Save scan results to file"""
        try:
            filename = f"{target}_port_scan_{int(time.time())}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Port Scan Results\n")
                f.write(f"==================\n\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scan Type: {scan_type}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Open Ports: {len(results)}\n\n")
                
                if results:
                    f.write("Port\tService\tState\tBanner\n")
                    f.write("-" * 60 + "\n")
                    
                    for port_info in results:
                        banner = port_info.get('banner', '')
                        if banner:
                            banner = banner.replace('\n', ' ').replace('\r', '')[:50]
                        
                        f.write(f"{port_info['port']}\t{port_info['service']}\t{port_info['state']}\t{banner}\n")
                else:
                    f.write("No open ports found.\n")
            
            print(Fore.GREEN + f"[+] Results saved to: {filename}")
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def display_results(self, results, target):
        """Display scan results in a formatted table"""
        if not results:
            print(Fore.YELLOW + f"[*] No open ports found on {target}")
            return
        
        print(Fore.GREEN + f"\n[+] Found {len(results)} open ports on {target}:")
        print()
        
        # Sort ports by number
        results.sort(key=lambda x: x['port'])
        
        # Table header
        print(f"{'Port':<8} {'Service':<20} {'State':<8} {'Banner'}")
        print("-" * 70)
        
        for port_info in results:
            banner = port_info.get('banner', '')
            if banner:
                banner = banner.replace('\n', ' ').replace('\r', '')[:40]
            else:
                banner = ''
            
            print(f"{port_info['port']:<8} {port_info['service']:<20} {port_info['state']:<8} {banner}")
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] Port Scanner Menu:")
                print("1. Common Ports Scan")
                print("2. Web Ports Scan")
                print("3. Database Ports Scan")
                print("4. Remote Access Ports Scan")
                print("5. Custom Port Range")
                print("6. Quick Scan (Top 10 ports)")
                print("7. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect scan type (1-7): " + Style.RESET_ALL).strip()
                
                if choice == '7':
                    return
                
                # Get target
                target = input(Fore.YELLOW + "\nEnter target IP or hostname: " + Style.RESET_ALL).strip()
                
                if not target:
                    print(Fore.RED + "[-] Please enter a target!")
                    continue
                
                is_valid, message = self.validate_target(target)
                if not is_valid:
                    print(Fore.RED + f"[-] {message}")
                    continue
                
                print(Fore.GREEN + f"[+] Target validated: {target}")
                
                # Determine ports to scan
                if choice == '1':
                    ports = self.common_ports
                    scan_type = "Common Ports"
                elif choice == '2':
                    ports = self.web_ports
                    scan_type = "Web Ports"
                elif choice == '3':
                    ports = self.database_ports
                    scan_type = "Database Ports"
                elif choice == '4':
                    ports = self.remote_ports
                    scan_type = "Remote Access Ports"
                elif choice == '5':
                    try:
                        start_port = int(input(Fore.YELLOW + "Enter start port (1-65535): " + Style.RESET_ALL))
                        end_port = int(input(Fore.YELLOW + "Enter end port (1-65535): " + Style.RESET_ALL))
                        
                        if start_port < 1 or end_port > 65535 or start_port > end_port:
                            print(Fore.RED + "[-] Invalid port range!")
                            continue
                        
                        ports = list(range(start_port, end_port + 1))
                        scan_type = f"Custom Range {start_port}-{end_port}"
                        
                        # Warn about large ranges
                        if len(ports) > 1000:
                            print(Fore.YELLOW + f"[*] Warning: Scanning {len(ports)} ports may take a while!")
                            proceed = input(Fore.YELLOW + "Continue? (y/n): " + Style.RESET_ALL).strip().lower()
                            if proceed != 'y':
                                continue
                        
                    except ValueError:
                        print(Fore.RED + "[-] Invalid port number!")
                        continue
                elif choice == '6':
                    ports = self.common_ports[:10]  # Top 10 ports
                    scan_type = "Quick Scan (Top 10)"
                else:
                    print(Fore.RED + "[-] Invalid choice!")
                    continue
                
                # Get timeout
                timeout_input = input(Fore.YELLOW + "Enter timeout in seconds (default=3): " + Style.RESET_ALL).strip()
                try:
                    timeout = float(timeout_input) if timeout_input else 3
                    timeout = max(0.5, min(timeout, 10))  # Clamp between 0.5 and 10
                except ValueError:
                    timeout = 3
                
                # Reset for new scan
                self.open_ports = []
                self.stop_scan = False
                
                print(Fore.CYAN + f"\n[*] Starting {scan_type} scan on {target}")
                print(Fore.CYAN + f"[*] Timeout: {timeout}s, Ports: {len(ports)}")
                start_time = time.time()
                
                # Start scan
                results = self.scan_ports_range(target, ports, timeout)
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Display results
                print(Fore.CYAN + f"\n[*] Scan completed in {duration:.2f} seconds")
                self.display_results(results, target)
                
                # Detect web technologies if web ports are open
                web_ports_found = [p['port'] for p in results if p['port'] in [80, 443, 8080, 8443]]
                if web_ports_found:
                    print(Fore.CYAN + "\n[*] Detecting web technologies...")
                    web_info = self.detect_web_technologies(target)
                    
                    if web_info:
                        print(Fore.GREEN + "[+] Web Technologies Found:")
                        for port, info in web_info.items():
                            print(f"    Port {port}: Server={info['server']}, Powered-By={info['powered_by']}")
                
                # Save results
                if results:
                    self.save_results(target, results, scan_type, duration)
                
                print()
                another = input(Fore.YELLOW + "Scan another target? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Scan interrupted by user")
                self.stop_scan = True
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue