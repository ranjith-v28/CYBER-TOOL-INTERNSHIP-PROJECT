#!/usr/bin/env python3
"""
Network Scanner Tool
Discover hosts and services on a network
"""

import os
import socket
import subprocess
import platform
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from tqdm import tqdm
import ipaddress

class NetworkScanner:
    def __init__(self):
        self.discovered_hosts = []
        self.lock = threading.Lock()
        self.stop_scan = False
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           🌐 NETWORK SCANNER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Discover hosts and services on your network")
        print(Fore.RED + "⚠️  Scan only networks you own or have permission to test!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_range(self, ip):
        """Generate network range from IP"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network)
        except Exception:
            return f"{ip}/24"
    
    def ping_host(self, host, timeout=1):
        """Ping a host to check if it's responsive"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return "Unknown"
    
    def scan_host_info(self, ip):
        """Gather detailed information about a host"""
        if self.stop_scan:
            return None
        
        try:
            host_info = {
                'ip': ip,
                'responsive': False,
                'hostname': 'Unknown',
                'mac': 'Unknown',
                'open_ports': [],
                'os_guess': 'Unknown'
            }
            
            # Check if host is responsive
            if self.ping_host(ip):
                host_info['responsive'] = True
                host_info['hostname'] = self.get_hostname(ip)
                
                # Try to get MAC address (ARP table)
                mac = self.get_mac_address(ip)
                if mac:
                    host_info['mac'] = mac
                
                # Quick port scan on common ports
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 3306]
                open_ports = self.scan_ports(ip, common_ports, timeout=0.5)
                host_info['open_ports'] = open_ports
                
                # Simple OS detection based on TTL
                os_guess = self.guess_os(ip)
                if os_guess:
                    host_info['os_guess'] = os_guess
                
                return host_info
            else:
                return host_info
                
        except Exception:
            return None
    
    def get_mac_address(self, ip):
        """Get MAC address from ARP table"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['arp', '-a', ip]
            else:
                cmd = ['arp', '-n', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout
            
            # Parse ARP output
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and '-' in part:
                            return part
                        elif len(part) == 17 and part.count(':') == 5:
                            return part.upper()
            
            return None
        except Exception:
            return None
    
    def scan_ports(self, ip, ports, timeout=1):
        """Scan specific ports on a host"""
        open_ports = []
        
        for port in ports:
            if self.stop_scan:
                break
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        
        return open_ports
    
    def guess_os(self, ip):
        """Simple OS detection based on ping TTL"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', ip]
            else:
                cmd = ['ping', '-c', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout.lower()
            
            # TTL-based OS detection (simplified)
            if 'ttl=' in output:
                # Extract TTL value
                import re
                ttl_match = re.search(r'ttl=(\d+)', output)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    elif ttl <= 255:
                        return "Cisco/Network Device"
            
            # Fallback based on open ports
            # This is very basic and not always accurate
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def scan_network(self, network_range, scan_type='quick'):
        """Main network scanning function"""
        print(Fore.CYAN + f"[*] Scanning network: {network_range}")
        
        # Generate list of IPs to scan
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except Exception as e:
            print(Fore.RED + f"[-] Invalid network range: {e}")
            return []
        
        print(Fore.CYAN + f"[*] Total hosts to scan: {len(ips)}")
        
        if scan_type == 'quick':
            # Quick scan - just ping
            print(Fore.YELLOW + "[*] Performing quick scan (ping only)...")
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(self.ping_host, ip): ip for ip in ips}
                
                with tqdm(total=len(futures), desc="Pinging hosts", 
                         bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                    
                    for future in as_completed(futures):
                        if self.stop_scan:
                            break
                        
                        ip = futures[future]
                        try:
                            if future.result():
                                host_info = {
                                    'ip': ip,
                                    'responsive': True,
                                    'hostname': self.get_hostname(ip),
                                    'mac': 'Unknown',
                                    'open_ports': [],
                                    'os_guess': 'Unknown'
                                }
                                with self.lock:
                                    self.discovered_hosts.append(host_info)
                        except Exception:
                            pass
                        
                        pbar.update(1)
        
        elif scan_type == 'detailed':
            # Detailed scan - ping + port scan + hostname
            print(Fore.YELLOW + "[*] Performing detailed scan...")
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.scan_host_info, ip): ip for ip in ips}
                
                with tqdm(total=len(futures), desc="Scanning hosts", 
                         bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                    
                    for future in as_completed(futures):
                        if self.stop_scan:
                            break
                        
                        try:
                            host_info = future.result()
                            if host_info and host_info['responsive']:
                                with self.lock:
                                    self.discovered_hosts.append(host_info)
                        except Exception:
                            pass
                        
                        pbar.update(1)
        
        return self.discovered_hosts
    
    def save_results(self, hosts, filename, scan_type):
        """Save scan results to file"""
        try:
            with open(filename, 'w') as f:
                f.write(f"Network Scan Results\n")
                f.write(f"====================\n")
                f.write(f"Scan Type: {scan_type}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Hosts Found: {len(hosts)}\n\n")
                
                f.write("IP Address\tHostname\tMAC Address\tOS Guess\tOpen Ports\n")
                f.write("-" * 80 + "\n")
                
                for host in hosts:
                    ports_str = ','.join(map(str, host['open_ports'])) if host['open_ports'] else 'None'
                    f.write(f"{host['ip']}\t{host['hostname']}\t{host['mac']}\t{host['os_guess']}\t{ports_str}\n")
            
            print(Fore.GREEN + f"[+] Results saved to: {filename}")
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def display_results(self, hosts):
        """Display scan results in a formatted table"""
        if not hosts:
            print(Fore.YELLOW + "[*] No hosts found on network")
            return
        
        print(Fore.GREEN + f"\n[+] Found {len(hosts)} responsive hosts:")
        print()
        
        # Table header
        print(f"{'IP Address':<15} {'Hostname':<20} {'MAC Address':<18} {'OS':<12} {'Open Ports'}")
        print("-" * 80)
        
        for host in hosts:
            ports_str = ','.join(map(str, host['open_ports'])) if host['open_ports'] else 'None'
            mac_str = host['mac'][:17] if host['mac'] != 'Unknown' else 'Unknown'
            
            print(f"{host['ip']:<15} {host['hostname'][:19]:<20} {mac_str:<18} "
                  f"{host['os_guess']:<12} {ports_str}")
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ipconfig', '/all']
            else:
                cmd = ['ip', 'addr', 'show']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except Exception:
            return ""
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] Network Scanner Menu:")
                print("1. Quick Scan (ping only)")
                print("2. Detailed Scan (ping + ports + info)")
                print("3. Show Local Network Info")
                print("4. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect scan type (1-4): " + Style.RESET_ALL).strip()
                
                if choice == '4':
                    return
                
                if choice == '3':
                    # Show network info
                    local_ip = self.get_local_ip()
                    network_range = self.get_network_range(local_ip)
                    
                    print(Fore.GREEN + f"\n[*] Local Network Information:")
                    print(f"    Local IP: {local_ip}")
                    print(f"    Network Range: {network_range}")
                    print(f"    Platform: {platform.system()}")
                    
                    print(Fore.CYAN + "\n[*] Network Interfaces:")
                    interfaces = self.get_network_interfaces()
                    print(interfaces[:500] + "..." if len(interfaces) > 500 else interfaces)
                    
                    input(Fore.YELLOW + "\nPress Enter to continue..." + Style.RESET_ALL)
                    continue
                
                # Get network range
                default_range = self.get_network_range(self.get_local_ip())
                network_input = input(Fore.YELLOW + f"\nEnter network range (e.g., 192.168.1.0/24, default={default_range}): " + Style.RESET_ALL).strip()
                
                if not network_input:
                    network_input = default_range
                
                scan_type = 'quick' if choice == '1' else 'detailed'
                
                # Reset for new scan
                self.discovered_hosts = []
                self.stop_scan = False
                
                print(Fore.CYAN + f"\n[*] Starting {scan_type} scan...")
                start_time = time.time()
                
                # Start scan in a separate thread to allow interruption
                def scan_thread():
                    return self.scan_network(network_input, scan_type)
                
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(scan_thread)
                    try:
                        hosts = future.result(timeout=300)  # 5 minute timeout
                    except concurrent.futures.TimeoutError:
                        print(Fore.RED + "[-] Scan timed out!")
                        self.stop_scan = True
                        hosts = []
                
                end_time = time.time()
                
                # Display results
                print(Fore.CYAN + f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
                self.display_results(hosts)
                
                if hosts:
                    # Save results
                    filename = f"network_scan_{int(time.time())}.txt"
                    self.save_results(hosts, filename, scan_type)
                
                print()
                another = input(Fore.YELLOW + "Scan another network? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Scan interrupted by user")
                self.stop_scan = True
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue