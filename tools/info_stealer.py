#!/usr/bin/env python3
"""
Information Stealer Tool
Gather system and network information for security analysis
"""

import os
import platform
import socket
import subprocess
import time
import json
import hashlib
from colorama import Fore, Style
try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

class InfoStealer:
    def __init__(self):
        self.gathered_info = {}
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           ℹ️  INFORMATION STEALER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Gather system and network information for analysis")
        print(Fore.RED + "⚠️  Use only on systems you own or have permission to analyze!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def get_system_info(self):
        """Gather basic system information"""
        print(Fore.CYAN + "[*] Gathering system information...")
        
        try:
            system_info = {
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'architecture': platform.architecture(),
                'hostname': socket.gethostname(),
                'python_version': platform.python_version(),
                'current_user': os.getlogin() if hasattr(os, 'getlogin') else 'Unknown'
            }
            
            # Get system uptime
            if psutil:
                try:
                    uptime = psutil.boot_time()
                    system_info['boot_time'] = time.ctime(uptime)
                    system_info['uptime_seconds'] = time.time() - uptime
                except:
                    system_info['boot_time'] = 'Unknown'
                    system_info['uptime_seconds'] = 0
            else:
                system_info['boot_time'] = 'psutil not available'
                system_info['uptime_seconds'] = 0
            
            return system_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_hardware_info(self):
        """Gather hardware information"""
        print(Fore.CYAN + "[*] Gathering hardware information...")
        
        try:
            hardware_info = {}
            
            # CPU information
            if psutil:
                try:
                    cpu_info = {
                        'physical_cores': psutil.cpu_count(logical=False),
                        'logical_cores': psutil.cpu_count(logical=True),
                        'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
                        'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else 0,
                        'cpu_percent': psutil.cpu_percent(interval=1),
                        'brand': platform.processor()
                    }
                    hardware_info['cpu'] = cpu_info
                except Exception as e:
                    hardware_info['cpu'] = {'error': str(e)}
            else:
                hardware_info['cpu'] = {'error': 'psutil not available'}
            
            # Memory information
            if psutil:
                try:
                    memory = psutil.virtual_memory()
                    memory_info = {
                        'total_gb': round(memory.total / (1024**3), 2),
                        'available_gb': round(memory.available / (1024**3), 2),
                        'used_gb': round(memory.used / (1024**3), 2),
                        'percentage': memory.percent
                    }
                    hardware_info['memory'] = memory_info
                except Exception as e:
                    hardware_info['memory'] = {'error': str(e)}
            else:
                hardware_info['memory'] = {'error': 'psutil not available'}
            
            # Disk information
            if psutil:
                try:
                    disk_partitions = psutil.disk_partitions()
                    disk_info = []
                    
                    for partition in disk_partitions:
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            disk_info.append({
                                'device': partition.device,
                                'mountpoint': partition.mountpoint,
                                'fstype': partition.fstype,
                                'total_gb': round(usage.total / (1024**3), 2),
                                'used_gb': round(usage.used / (1024**3), 2),
                                'free_gb': round(usage.free / (1024**3), 2),
                                'percentage': round((usage.used / usage.total) * 100, 2)
                            })
                        except:
                            continue
                    
                    hardware_info['disk'] = disk_info
                except Exception as e:
                    hardware_info['disk'] = {'error': str(e)}
            else:
                hardware_info['disk'] = {'error': 'psutil not available'}
            
            # Network interfaces
            if psutil:
                try:
                    net_if_addrs = psutil.net_if_addrs()
                    network_info = {}
                    
                    for interface_name, addresses in net_if_addrs.items():
                        interface_info = []
                        for addr in addresses:
                            if addr.family == socket.AF_INET:
                                interface_info.append({
                                    'family': 'IPv4',
                                    'address': addr.address,
                                    'netmask': addr.netmask,
                                    'broadcast': addr.broadcast
                                })
                            elif addr.family == socket.AF_INET6:
                                interface_info.append({
                                    'family': 'IPv6',
                                    'address': addr.address,
                                    'netmask': addr.netmask
                                })
                        
                        if interface_info:
                            network_info[interface_name] = interface_info
                    
                    hardware_info['network_interfaces'] = network_info
                except Exception as e:
                    hardware_info['network_interfaces'] = {'error': str(e)}
            else:
                hardware_info['network_interfaces'] = {'error': 'psutil not available'}
            
            return hardware_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_network_info(self):
        """Gather network information"""
        print(Fore.CYAN + "[*] Gathering network information...")
        
        try:
            network_info = {}
            
            # Get local IP addresses
            try:
                hostname = socket.gethostname()
                local_ips = socket.gethostbyname_ex(hostname)
                network_info['local_ips'] = {
                    'hostname': hostname,
                    'aliases': local_ips[1],
                    'ip_addresses': local_ips[2]
                }
            except Exception as e:
                network_info['local_ips'] = {'error': str(e)}
            
            # Get public IP
            if requests:
                try:
                    response = requests.get('https://api.ipify.org?format=json', timeout=5)
                    public_ip = response.json()
                    network_info['public_ip'] = public_ip['ip']
                except Exception as e:
                    network_info['public_ip'] = {'error': str(e)}
            else:
                network_info['public_ip'] = {'error': 'requests not available'}
            
            # Get network connections
            if psutil:
                try:
                    connections = psutil.net_connections()
                    active_connections = []
                    
                    for conn in connections[:50]:  # Limit to first 50 connections
                        if conn.status == 'ESTABLISHED':
                            active_connections.append({
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'Unknown',
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'Unknown',
                                'status': conn.status,
                                'pid': conn.pid
                            })
                    
                    network_info['active_connections'] = active_connections
                except Exception as e:
                    network_info['active_connections'] = {'error': str(e)}
            else:
                network_info['active_connections'] = {'error': 'psutil not available'}
            
            # Network IO statistics
            if psutil:
                try:
                    net_io = psutil.net_io_counters()
                    network_info['network_io'] = {
                        'bytes_sent': net_io.bytes_sent,
                        'bytes_recv': net_io.bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv
                    }
                except Exception as e:
                    network_info['network_io'] = {'error': str(e)}
            else:
                network_info['network_io'] = {'error': 'psutil not available'}
            
            return network_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_process_info(self):
        """Gather running processes information"""
        print(Fore.CYAN + "[*] Gathering process information...")
        
        try:
            processes = []
            
            if psutil:
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                    try:
                        process_info = proc.info
                        processes.append({
                            'pid': process_info['pid'],
                            'name': process_info['name'],
                            'username': process_info['username'],
                            'cpu_percent': round(process_info['cpu_percent'], 2),
                            'memory_percent': round(process_info['memory_percent'], 2)
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            else:
                return {'error': 'psutil not available'}
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            
            return {
                'total_processes': len(processes),
                'top_processes': processes[:20]  # Return top 20 by CPU usage
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_user_info(self):
        """Gather user and environment information"""
        print(Fore.CYAN + "[*] Gathering user information...")
        
        try:
            user_info = {}
            
            # Environment variables
            try:
                env_vars = {}
                sensitive_keys = ['password', 'secret', 'key', 'token', 'credential']
                
                for key, value in os.environ.items():
                    # Filter out potentially sensitive information
                    if not any(sensitive in key.lower() for sensitive in sensitive_keys):
                        env_vars[key] = value[:100] + '...' if len(str(value)) > 100 else value
                
                user_info['environment_variables'] = env_vars
            except Exception as e:
                user_info['environment_variables'] = {'error': str(e)}
            
            # Current working directory
            try:
                user_info['current_directory'] = os.getcwd()
            except:
                user_info['current_directory'] = 'Unknown'
            
            # Home directory
            try:
                user_info['home_directory'] = os.path.expanduser('~')
            except:
                user_info['home_directory'] = 'Unknown'
            
            # List files in current directory (non-sensitive)
            try:
                current_dir = os.getcwd()
                files = []
                for item in os.listdir(current_dir)[:50]:  # Limit to first 50 items
                    try:
                        item_path = os.path.join(current_dir, item)
                        stat = os.stat(item_path)
                        files.append({
                            'name': item,
                            'size': stat.st_size,
                            'is_directory': os.path.isdir(item_path),
                            'modified': time.ctime(stat.st_mtime)
                        })
                    except:
                        continue
                
                user_info['current_directory_files'] = files
            except Exception as e:
                user_info['current_directory_files'] = {'error': str(e)}
            
            return user_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_security_info(self):
        """Gather security-related information"""
        print(Fore.CYAN + "[*] Gathering security information...")
        
        try:
            security_info = {}
            
            # Running services (simplified)
            try:
                if platform.system().lower() == 'windows':
                    # Windows services
                    result = subprocess.run(['sc', 'query'], capture_output=True, text=True, timeout=10)
                    services_output = result.stdout
                    security_info['services'] = services_output[:1000] + '...' if len(services_output) > 1000 else services_output
                else:
                    # Linux services
                    result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                          capture_output=True, text=True, timeout=10)
                    services_output = result.stdout
                    security_info['services'] = services_output[:1000] + '...' if len(services_output) > 1000 else services_output
            except Exception as e:
                security_info['services'] = {'error': str(e)}
            
            # Open ports
            try:
                if platform.system().lower() == 'windows':
                    result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
                else:
                    result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True, timeout=10)
                
                netstat_output = result.stdout
                security_info['open_ports'] = netstat_output[:1500] + '...' if len(netstat_output) > 1500 else netstat_output
            except Exception as e:
                security_info['open_ports'] = {'error': str(e)}
            
            # Firewall status
            try:
                if platform.system().lower() == 'windows':
                    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                          capture_output=True, text=True, timeout=10)
                    security_info['firewall'] = result.stdout[:1000] + '...' if len(result.stdout) > 1000 else result.stdout
                else:
                    # Check ufw or iptables
                    try:
                        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                        security_info['firewall'] = result.stdout
                    except:
                        result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=10)
                        security_info['firewall'] = result.stdout[:1000] + '...' if len(result.stdout) > 1000 else result.stdout
            except Exception as e:
                security_info['firewall'] = {'error': str(e)}
            
            return security_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def scan_network_range(self, network_range):
        """Scan a network range for active hosts"""
        print(Fore.CYAN + f"[*] Scanning network range: {network_range}")
        
        try:
            import ipaddress
            
            network = ipaddress.IPv4Network(network_range, strict=False)
            active_hosts = []
            
            for ip in network.hosts():
                if str(ip).endswith('.255') or str(ip).endswith('.0'):
                    continue  # Skip broadcast and network addresses
                
                try:
                    # Simple ping check
                    if platform.system().lower() == 'windows':
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                              capture_output=True, text=True, timeout=2)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                              capture_output=True, text=True, timeout=2)
                    
                    if result.returncode == 0:
                        active_hosts.append({
                            'ip': str(ip),
                            'hostname': socket.gethostbyaddr(str(ip))[0] if 'reply from' in result.stdout.lower() else 'Unknown',
                            'status': 'Active'
                        })
                except:
                    continue
            
            return {
                'network_range': str(network),
                'total_ips': network.num_addresses - 2,
                'active_hosts': active_hosts,
                'active_count': len(active_hosts)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def save_results(self, filename, format='json'):
        """Save gathered information to file"""
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump(self.gathered_info, f, indent=2, default=str)
            elif format.lower() == 'txt':
                with open(filename, 'w') as f:
                    f.write("System Information Gathering Results\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    for category, data in self.gathered_info.items():
                        f.write(f"{category.upper()}\n")
                        f.write("-" * len(category) + "\n")
                        f.write(f"{json.dumps(data, indent=2, default=str)}\n\n")
            
            print(Fore.GREEN + f"[+] Results saved to: {filename}")
            
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def display_summary(self):
        """Display a summary of gathered information"""
        print(Fore.GREEN + "\n[+] INFORMATION GATHERING SUMMARY")
        print("=" * 50)
        
        for category, data in self.gathered_info.items():
            if 'error' not in data:
                print(Fore.CYAN + f"\n[*] {category.replace('_', ' ').title()}:")
                
                if category == 'system_info':
                    print(f"    System: {data.get('system', 'Unknown')}")
                    print(f"    Hostname: {data.get('hostname', 'Unknown')}")
                    print(f"    Platform: {data.get('platform', 'Unknown')}")
                    print(f"    User: {data.get('current_user', 'Unknown')}")
                
                elif category == 'hardware_info':
                    if 'cpu' in data:
                        cpu = data['cpu']
                        print(f"    CPU Cores: {cpu.get('physical_cores', 'Unknown')} physical, {cpu.get('logical_cores', 'Unknown')} logical")
                        print(f"    CPU Usage: {cpu.get('cpu_percent', 0)}%")
                    
                    if 'memory' in data:
                        mem = data['memory']
                        print(f"    Memory: {mem.get('total_gb', 0)} GB total, {mem.get('used_gb', 0)} GB used ({mem.get('percentage', 0)}%)")
                    
                    if 'disk' in data:
                        disk_count = len(data['disk']) if isinstance(data['disk'], list) else 0
                        print(f"    Disk Partitions: {disk_count}")
                    
                    if 'network_interfaces' in data:
                        iface_count = len(data['network_interfaces']) if isinstance(data['network_interfaces'], dict) else 0
                        print(f"    Network Interfaces: {iface_count}")
                
                elif category == 'network_info':
                    print(f"    Local IPs: {len(data.get('local_ips', {}).get('ip_addresses', []))}")
                    print(f"    Public IP: {data.get('public_ip', {}).get('ip', 'Unknown')}")
                    print(f"    Active Connections: {len(data.get('active_connections', []))}")
                
                elif category == 'process_info':
                    print(f"    Total Processes: {data.get('total_processes', 0)}")
                    print(f"    Top 20 by CPU usage listed")
                
                elif category == 'security_info':
                    print(f"    Services information gathered")
                    print(f"    Open ports information gathered")
                    print(f"    Firewall status gathered")
                
                elif category == 'network_scan':
                    scan_data = data
                    print(f"    Network Range: {scan_data.get('network_range', 'Unknown')}")
                    print(f"    Active Hosts: {scan_data.get('active_count', 0)}/{scan_data.get('total_ips', 0)}")
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] Information Stealer Menu:")
                print("1. Full System Information Gathering")
                print("2. System Information Only")
                print("3. Hardware Information Only")
                print("4. Network Information Only")
                print("5. Process Information Only")
                print("6. Security Information Only")
                print("7. Network Range Scan")
                print("8. Custom Gathering")
                print("9. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect option (1-9): " + Style.RESET_ALL).strip()
                
                if choice == '9':
                    return
                
                # Reset for new gathering
                self.gathered_info = {}
                
                if choice == '1':
                    # Full gathering
                    self.gathered_info['system_info'] = self.get_system_info()
                    self.gathered_info['hardware_info'] = self.get_hardware_info()
                    self.gathered_info['network_info'] = self.get_network_info()
                    self.gathered_info['process_info'] = self.get_process_info()
                    self.gathered_info['user_info'] = self.get_user_info()
                    self.gathered_info['security_info'] = self.get_security_info()
                    gathering_type = "Full System Information"
                
                elif choice == '2':
                    self.gathered_info['system_info'] = self.get_system_info()
                    gathering_type = "System Information"
                
                elif choice == '3':
                    self.gathered_info['hardware_info'] = self.get_hardware_info()
                    gathering_type = "Hardware Information"
                
                elif choice == '4':
                    self.gathered_info['network_info'] = self.get_network_info()
                    gathering_type = "Network Information"
                
                elif choice == '5':
                    self.gathered_info['process_info'] = self.get_process_info()
                    gathering_type = "Process Information"
                
                elif choice == '6':
                    self.gathered_info['security_info'] = self.get_security_info()
                    gathering_type = "Security Information"
                
                elif choice == '7':
                    # Network range scan
                    network_range = input(Fore.YELLOW + "Enter network range (e.g., 192.168.1.0/24): " + Style.RESET_ALL).strip()
                    if not network_range:
                        print(Fore.RED + "[-] Please enter a network range!")
                        continue
                    
                    self.gathered_info['network_scan'] = self.scan_network_range(network_range)
                    gathering_type = "Network Range Scan"
                
                elif choice == '8':
                    # Custom gathering
                    print(Fore.CYAN + "\n[*] Select information to gather (separate with commas):")
                    print("1. System Info")
                    print("2. Hardware Info")
                    print("3. Network Info")
                    print("4. Process Info")
                    print("5. User Info")
                    print("6. Security Info")
                    
                    custom_choice = input(Fore.YELLOW + "Enter choices (e.g., 1,3,5): " + Style.RESET_ALL).strip()
                    
                    choices = [c.strip() for c in custom_choice.split(',')]
                    gathering_parts = []
                    
                    for c in choices:
                        if c == '1':
                            self.gathered_info['system_info'] = self.get_system_info()
                            gathering_parts.append("System")
                        elif c == '2':
                            self.gathered_info['hardware_info'] = self.get_hardware_info()
                            gathering_parts.append("Hardware")
                        elif c == '3':
                            self.gathered_info['network_info'] = self.get_network_info()
                            gathering_parts.append("Network")
                        elif c == '4':
                            self.gathered_info['process_info'] = self.get_process_info()
                            gathering_parts.append("Process")
                        elif c == '5':
                            self.gathered_info['user_info'] = self.get_user_info()
                            gathering_parts.append("User")
                        elif c == '6':
                            self.gathered_info['security_info'] = self.get_security_info()
                            gathering_parts.append("Security")
                    
                    gathering_type = f"Custom: {', '.join(gathering_parts)}"
                
                else:
                    print(Fore.RED + "[-] Invalid choice!")
                    continue
                
                # Display summary
                print(Fore.GREEN + f"\n[+] {gathering_type} Gathering Completed!")
                self.display_summary()
                
                # Save results
                if self.gathered_info:
                    save_option = input(Fore.YELLOW + "\nSave results? (y/n): " + Style.RESET_ALL).strip().lower()
                    if save_option == 'y':
                        filename = f"info_gathering_{int(time.time())}.json"
                        format_choice = input(Fore.YELLOW + "Format (json/txt, default=json): " + Style.RESET_ALL).strip()
                        self.save_results(filename, format_choice if format_choice else 'json')
                
                print()
                another = input(Fore.YELLOW + "Gather more information? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Information gathering interrupted by user")
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue