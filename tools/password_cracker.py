#!/usr/bin/env python3
"""
Password Cracker Tool
Crack various types of password hashes
"""

import os
import hashlib
import time
import string
from colorama import Fore, Style
from tqdm import tqdm
import itertools

class PasswordCracker:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', '123123', 'qwerty123', 'password!',
            'admin123', 'root', 'toor', 'pass', 'test', 'guest',
            'user', 'login', 'default', 'changeme', 'secret',
            'master', 'freedom', 'whatever', 'qazwsx', 'trustno1',
            '123qwe', '1q2w3e4r', 'zxcvbnm', 'iloveyou', 'starwars',
            'football', 'baseball', 'shadow', 'superman', 'azerty'
        ]
        
        self.hash_types = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           💣 PASSWORD CRACKER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Crack various types of password hashes")
        print(Fore.RED + "⚠️  Use only for authorized password recovery!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def detect_hash_type(self, hash_value):
        """Detect hash type based on length and format"""
        hash_value = hash_value.lower().strip()
        
        # Remove common prefixes
        if hash_value.startswith('$'):
            # Handle Unix-style hashes (simplified detection)
            if hash_value.startswith('$1$'):
                return 'md5_unix'
            elif hash_value.startswith('$2$') or hash_value.startswith('$2a$'):
                return 'bcrypt'
            elif hash_value.startswith('$5$'):
                return 'sha256_unix'
            elif hash_value.startswith('$6$'):
                return 'sha512_unix'
        
        # Simple length-based detection
        length = len(hash_value)
        
        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        elif length == 128:
            return 'sha512'
        elif length == 56:
            return 'sha224'
        elif length == 96:
            return 'sha384'
        else:
            return 'unknown'
    
    def hash_password(self, password, hash_type):
        """Hash a password using specified algorithm"""
        if hash_type in self.hash_types:
            hash_func = self.hash_types[hash_type]()
            hash_func.update(password.encode('utf-8'))
            return hash_func.hexdigest()
        else:
            return None
    
    def dictionary_attack(self, target_hash, hash_type, wordlist=None):
        """Perform dictionary attack on hash"""
        if wordlist is None:
            wordlist = self.common_passwords
        
        print(Fore.CYAN + f"[*] Starting dictionary attack with {len(wordlist)} passwords...")
        
        for password in tqdm(wordlist, desc="Testing passwords", 
                           bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
            
            if hash_type == 'md5_unix':
                # Simplified MD5 Unix (would need crypt.crypt for real implementation)
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == 'sha256_unix':
                # Simplified SHA256 Unix
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            elif hash_type == 'sha512_unix':
                # Simplified SHA512 Unix
                test_hash = hashlib.sha512(password.encode()).hexdigest()
            elif hash_type in ['bcrypt']:
                # Skip bcrypt in this simplified implementation
                continue
            else:
                test_hash = self.hash_password(password, hash_type)
            
            if test_hash and test_hash.lower() == target_hash.lower():
                return password
        
        return None
    
    def brute_force_attack(self, target_hash, hash_type, min_length=1, max_length=6, charset=None):
        """Perform brute force attack"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(Fore.CYAN + f"[*] Starting brute force attack...")
        print(Fore.CYAN + f"    Charset: {charset}")
        print(Fore.CYAN + f"    Length range: {min_length}-{max_length}")
        
        total_combinations = 0
        for length in range(min_length, max_length + 1):
            total_combinations += len(charset) ** length
        
        print(Fore.YELLOW + f"[*] Total combinations: {total_combinations:,}")
        
        if total_combinations > 1000000:
            print(Fore.RED + "[-] Warning: This may take a very long time!")
            proceed = input(Fore.YELLOW + "Continue? (y/n): " + Style.RESET_ALL).strip().lower()
            if proceed != 'y':
                return None
        
        with tqdm(total=total_combinations, desc="Brute forcing", 
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
            
            for length in range(min_length, max_length + 1):
                for attempt in itertools.product(charset, repeat=length):
                    password = ''.join(attempt)
                    pbar.update(1)
                    
                    test_hash = self.hash_password(password, hash_type)
                    if test_hash and test_hash.lower() == target_hash.lower():
                        return password
        
        return None
    
    def mask_attack(self, target_hash, hash_type, mask):
        """Perform mask-based attack"""
        print(Fore.CYAN + f"[*] Starting mask attack with pattern: {mask}")
        
        # Simple mask implementation
        mask_map = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation,
            '?a': string.ascii_letters + string.digits + string.punctuation
        }
        
        # Parse mask (simplified)
        charset = string.ascii_lowercase + string.digits
        for key, chars in mask_map.items():
            if key in mask:
                charset = chars
                mask = mask.replace(key, '')
                break
        
        fixed_length = len(mask) if mask else 4
        
        return self.brute_force_attack(target_hash, hash_type, fixed_length, fixed_length, charset)
    
    def load_wordlist(self, filepath):
        """Load passwords from wordlist file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            return passwords
        except Exception as e:
            print(Fore.RED + f"[-] Error loading wordlist: {e}")
            return None
    
    def crack_multiple_hashes(self, hashes, hash_type, wordlist=None):
        """Crack multiple hashes"""
        results = {}
        
        print(Fore.CYAN + f"[*] Cracking {len(hashes)} hashes...")
        
        if wordlist is None:
            wordlist = self.common_passwords
        
        # Create hash dictionary for quick lookup
        hash_dict = {h.lower(): i for i, h in enumerate(hashes)}
        
        for password in tqdm(wordlist, desc="Testing passwords"):
            # Generate hash for current password
            test_hash = self.hash_password(password, hash_type)
            
            if test_hash and test_hash.lower() in hash_dict:
                original_hash = hashes[hash_dict[test_hash.lower()]]
                results[original_hash] = password
                print(Fore.GREEN + f"\n[+] Found: {original_hash} -> {password}" + Style.RESET_ALL)
                
                # Remove cracked hash from dictionary
                del hash_dict[test_hash.lower()]
                
                # Stop if all hashes are cracked
                if not hash_dict:
                    break
        
        return results
    
    def save_results(self, target_hash, password, attack_type, duration, hash_type):
        """Save cracking results to file"""
        try:
            filename = f"password_crack_results_{int(time.time())}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Password Cracking Results\n")
                f.write(f"=========================\n\n")
                f.write(f"Target Hash: {target_hash}\n")
                f.write(f"Hash Type: {hash_type}\n")
                f.write(f"Attack Type: {attack_type}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            print(Fore.GREEN + f"[+] Results saved to: {filename}")
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def generate_hash(self, password, hash_type):
        """Generate hash for testing purposes"""
        if hash_type in self.hash_types:
            return self.hash_password(password, hash_type)
        return None
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] Password Cracker Menu:")
                print("1. Crack Single Hash")
                print("2. Crack Multiple Hashes")
                print("3. Generate Test Hash")
                print("4. Hash Information")
                print("5. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect option (1-5): " + Style.RESET_ALL).strip()
                
                if choice == '5':
                    return
                
                if choice == '3':
                    # Generate test hash
                    password = input(Fore.YELLOW + "Enter password to hash: " + Style.RESET_ALL).strip()
                    
                    print(Fore.CYAN + "\n[*] Available hash types:")
                    for i, hash_type in enumerate(self.hash_types.keys(), 1):
                        print(f"{i}. {hash_type.upper()}")
                    
                    hash_choice = input(Fore.YELLOW + "Select hash type: " + Style.RESET_ALL).strip()
                    hash_types_list = list(self.hash_types.keys())
                    
                    try:
                        hash_index = int(hash_choice) - 1
                        if 0 <= hash_index < len(hash_types_list):
                            hash_type = hash_types_list[hash_index]
                            result_hash = self.generate_hash(password, hash_type)
                            if result_hash:
                                print(Fore.GREEN + f"\n[+] {hash_type.upper()}: {result_hash}")
                            else:
                                print(Fore.RED + "[-] Error generating hash")
                        else:
                            print(Fore.RED + "[-] Invalid choice")
                    except ValueError:
                        print(Fore.RED + "[-] Invalid input")
                    
                    input(Fore.YELLOW + "\nPress Enter to continue..." + Style.RESET_ALL)
                    continue
                
                elif choice == '4':
                    # Hash information
                    hash_input = input(Fore.YELLOW + "Enter hash to analyze: " + Style.RESET_ALL).strip()
                    
                    if hash_input:
                        detected_type = self.detect_hash_type(hash_input)
                        print(Fore.GREEN + f"\n[*] Hash Analysis:")
                        print(f"    Input: {hash_input}")
                        print(f"    Length: {len(hash_input)}")
                        print(f"    Detected Type: {detected_type}")
                        
                        if detected_type in self.hash_types:
                            print(f"    Cracking Support: {Fore.GREEN}Available{Style.RESET_ALL}")
                        else:
                            print(f"    Cracking Support: {Fore.RED}Not supported{Style.RESET_ALL}")
                    
                    input(Fore.YELLOW + "\nPress Enter to continue..." + Style.RESET_ALL)
                    continue
                
                # Get hash input
                if choice == '1':
                    hash_input = input(Fore.YELLOW + "\nEnter hash to crack: " + Style.RESET_ALL).strip()
                    if not hash_input:
                        print(Fore.RED + "[-] Please enter a hash!")
                        continue
                    
                    target_hash = hash_input
                    hashes = [target_hash]
                elif choice == '2':
                    hash_input = input(Fore.YELLOW + "\nEnter hashes (one per line, empty line to finish): " + Style.RESET_ALL)
                    hashes = []
                    while hash_input.strip():
                        hashes.append(hash_input.strip())
                        hash_input = input()
                    
                    if not hashes:
                        print(Fore.RED + "[-] No hashes provided!")
                        continue
                    
                    target_hash = hashes[0]  # Use first hash for type detection
                else:
                    print(Fore.RED + "[-] Invalid choice!")
                    continue
                
                # Detect hash type
                detected_type = self.detect_hash_type(target_hash)
                print(Fore.GREEN + f"[+] Detected hash type: {detected_type}")
                
                if detected_type == 'unknown' or detected_type not in self.hash_types:
                    print(Fore.RED + "[-] Unsupported or unrecognized hash type!")
                    continue
                
                # Select attack method
                print(Fore.CYAN + "\n[*] Select attack method:")
                print("1. Dictionary Attack")
                print("2. Brute Force Attack")
                print("3. Mask Attack")
                print("4. Common Passwords Attack")
                
                attack_choice = input(Fore.YELLOW + "Choose method (1-4): " + Style.RESET_ALL).strip()
                
                # Load wordlist if needed
                wordlist = None
                if attack_choice in ['1', '4']:
                    wordlist_file = input(Fore.YELLOW + "Enter wordlist file (press Enter for built-in): " + Style.RESET_ALL).strip()
                    
                    if wordlist_file and os.path.exists(wordlist_file):
                        loaded = self.load_wordlist(wordlist_file)
                        if loaded:
                            wordlist = loaded
                            print(Fore.GREEN + f"[+] Loaded {len(wordlist)} passwords")
                        else:
                            wordlist = self.common_passwords if attack_choice == '4' else None
                    else:
                        wordlist = self.common_passwords if attack_choice == '4' else None
                        if attack_choice == '4':
                            print(Fore.YELLOW + "[*] Using built-in common passwords")
                
                start_time = time.time()
                
                if choice == '1':
                    # Single hash
                    if attack_choice == '1':
                        result = self.dictionary_attack(target_hash, detected_type, wordlist)
                        attack_type = "Dictionary Attack"
                    elif attack_choice == '2':
                        try:
                            min_len = int(input(Fore.YELLOW + "Min length (1-6): " + Style.RESET_ALL) or "1")
                            max_len = int(input(Fore.YELLOW + "Max length (1-10): " + Style.RESET_ALL) or "6")
                            
                            charset_choice = input(Fore.YELLOW + "Charset (1=lowercase, 2=uppercase, 3=digits, 4=letters+digits): " + Style.RESET_ALL).strip()
                            
                            charset_map = {
                                '1': string.ascii_lowercase,
                                '2': string.ascii_uppercase,
                                '3': string.digits,
                                '4': string.ascii_letters + string.digits
                            }
                            
                            charset = charset_map.get(charset_choice, charset_map['1'])
                        except ValueError:
                            charset = string.ascii_lowercase
                            min_len, max_len = 1, 6
                        
                        result = self.brute_force_attack(target_hash, detected_type, min_len, max_len, charset)
                        attack_type = "Brute Force Attack"
                    elif attack_choice == '3':
                        mask = input(Fore.YELLOW + "Enter mask (e.g., ?l?l?d?d): " + Style.RESET_ALL).strip() or "?l?l?l?l"
                        result = self.mask_attack(target_hash, detected_type, mask)
                        attack_type = "Mask Attack"
                    elif attack_choice == '4':
                        result = self.dictionary_attack(target_hash, detected_type, wordlist)
                        attack_type = "Common Passwords Attack"
                    else:
                        print(Fore.RED + "[-] Invalid choice!")
                        continue
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    print(Fore.CYAN + f"\n[*] Attack completed in {duration:.2f} seconds")
                    
                    if result:
                        print(Fore.GREEN + f"[+] PASSWORD FOUND: {result}" + Style.RESET_ALL)
                        
                        # Verify
                        verify_hash = self.hash_password(result, detected_type)
                        if verify_hash and verify_hash.lower() == target_hash.lower():
                            print(Fore.GREEN + "[+] Password verified successfully!")
                            self.save_results(target_hash, result, attack_type, duration, detected_type)
                        else:
                            print(Fore.RED + "[-] Password verification failed!")
                    else:
                        print(Fore.RED + "[-] Password not found")
                
                elif choice == '2':
                    # Multiple hashes
                    if attack_choice in ['1', '4']:
                        results = self.crack_multiple_hashes(hashes, detected_type, wordlist)
                        attack_type = "Dictionary Attack (Multiple)"
                    else:
                        print(Fore.RED + "[-] For multiple hashes, only dictionary attack is supported!")
                        continue
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    print(Fore.CYAN + f"\n[*] Attack completed in {duration:.2f} seconds")
                    print(Fore.GREEN + f"[+] Cracked {len(results)}/{len(hashes)} hashes:")
                    
                    for hash_val, password in results.items():
                        print(Fore.GREEN + f"    {hash_val} -> {password}" + Style.RESET_ALL)
                
                print()
                another = input(Fore.YELLOW + "Crack another hash? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Attack interrupted by user")
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue