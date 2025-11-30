#!/usr/bin/env python3
"""
PDF Cracker Tool
Attempt to crack PDF passwords using dictionary and brute force attacks
"""

import os
import getpass
import time
import hashlib
from PyPDF2 import PdfReader, PdfWriter
from colorama import Fore, Style
from tqdm import tqdm
import itertools
import string
import threading

class PDFCracker:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', '123123', 'qwerty123', 'password!',
            'admin123', 'root', 'toor', 'pass', 'test', 'guest',
            'user', 'login', 'default', 'changeme', 'secret',
            'master', 'freedom', 'whatever', 'qazwsx', 'trustno1',
            '123qwe', '1q2w3e4r', 'zxcvbnm', 'iloveyou', 'starwars'
        ]
        
        self.found_password = None
        self.stop_attack = False
        self.lock = threading.Lock()
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           🔓 PDF CRACKER TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Attempt to crack PDF passwords using various methods")
        print(Fore.RED + "⚠️  Use only on PDFs you own or have permission to test!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def validate_pdf_file(self, filepath):
        """Validate if file exists and is a PDF"""
        if not os.path.exists(filepath):
            return False, "File does not exist"
        
        if not filepath.lower().endswith('.pdf'):
            return False, "File is not a PDF"
        
        try:
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                if not reader.is_encrypted:
                    return False, "PDF is not encrypted"
                return True, "Valid encrypted PDF"
        except Exception as e:
            return False, f"Error reading PDF: {str(e)}"
    
    def test_password(self, filepath, password):
        """Test if password unlocks the PDF"""
        try:
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                if reader.decrypt(password) != 0:
                    return True
                return False
        except Exception:
            return False
    
    def dictionary_attack(self, filepath, wordlist=None, show_progress=True):
        """Perform dictionary attack"""
        passwords = wordlist if wordlist else self.common_passwords
        
        if show_progress:
            print(Fore.CYAN + f"[*] Starting dictionary attack with {len(passwords)} passwords...")
        
        if show_progress:
            pbar = tqdm(passwords, desc="Testing passwords", 
                        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")
        else:
            pbar = passwords
        
        for password in pbar:
            if self.stop_attack:
                break
            
            if self.test_password(filepath, password):
                with self.lock:
                    self.found_password = password
                    self.stop_attack = True
                break
        
        return self.found_password
    
    def brute_force_attack(self, filepath, min_length=1, max_length=6, charset=None):
        """Perform brute force attack"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(Fore.CYAN + f"[*] Starting brute force attack...")
        print(Fore.CYAN + f"    Charset: {charset}")
        print(Fore.CYAN + f"    Length range: {min_length}-{max_length}")
        
        total_combinations = 0
        for length in range(min_length, max_length + 1):
            total_combinations += len(charset) ** length
        
        print(Fore.YELLOW + f"[*] Total combinations to try: {total_combinations:,}")
        
        if total_combinations > 1000000:
            print(Fore.RED + "[-] Warning: This may take a very long time!")
            proceed = input(Fore.YELLOW + "Continue? (y/n): " + Style.RESET_ALL).strip().lower()
            if proceed != 'y':
                return None
        
        with tqdm(total=total_combinations, desc="Brute forcing", 
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
            
            for length in range(min_length, max_length + 1):
                if self.stop_attack:
                    break
                
                for attempt in itertools.product(charset, repeat=length):
                    if self.stop_attack:
                        break
                    
                    password = ''.join(attempt)
                    pbar.update(1)
                    
                    if self.test_password(filepath, password):
                        with self.lock:
                            self.found_password = password
                            self.stop_attack = True
                        break
        
        return self.found_password
    
    def create_mask_attack(self, filepath, mask):
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
        
        fixed_length = len(mask)
        if fixed_length == 0:
            fixed_length = 4
        
        return self.brute_force_attack(filepath, fixed_length, fixed_length, charset)
    
    def load_wordlist(self, filepath):
        """Load passwords from wordlist file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            return passwords
        except Exception as e:
            print(Fore.RED + f"[-] Error loading wordlist: {e}")
            return None
    
    def get_pdf_info(self, filepath):
        """Get information about the PDF"""
        try:
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                info = {
                    'pages': len(reader.pages),
                    'encrypted': reader.is_encrypted,
                    'size_mb': os.path.getsize(filepath) / (1024 * 1024)
                }
                
                if reader.metadata:
                    info['title'] = reader.metadata.get('/Title', 'Unknown')
                    info['author'] = reader.metadata.get('/Author', 'Unknown')
                    info['creator'] = reader.metadata.get('/Creator', 'Unknown')
                
                return info
        except Exception as e:
            return {'error': str(e)}
    
    def save_results(self, filepath, password, attack_type, duration):
        """Save cracking results to file"""
        try:
            base_name = os.path.splitext(filepath)[0]
            result_file = f"{base_name}_cracked.txt"
            
            with open(result_file, 'w') as f:
                f.write(f"PDF Cracking Results\n")
                f.write(f"====================\n\n")
                f.write(f"File: {filepath}\n")
                f.write(f"Attack Type: {attack_type}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            print(Fore.GREEN + f"[+] Results saved to: {result_file}")
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] PDF Cracking Menu:")
                print("1. Dictionary Attack")
                print("2. Brute Force Attack")
                print("3. Mask Attack")
                print("4. Common Passwords Attack")
                print("5. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect attack type (1-5): " + Style.RESET_ALL).strip()
                
                if choice == '5':
                    return
                
                # Get PDF file
                input_file = input(Fore.YELLOW + "\nEnter path to encrypted PDF: " + Style.RESET_ALL).strip()
                
                if not input_file:
                    print(Fore.RED + "[-] Please enter a file path!")
                    continue
                
                is_valid, message = self.validate_pdf_file(input_file)
                if not is_valid:
                    print(Fore.RED + f"[-] {message}")
                    continue
                
                # Show PDF info
                pdf_info = self.get_pdf_info(input_file)
                if 'error' not in pdf_info:
                    print(Fore.GREEN + f"\n[*] PDF Information:")
                    print(f"    File: {input_file}")
                    print(f"    Size: {pdf_info['size_mb']:.2f} MB")
                    print(f"    Pages: {pdf_info['pages']}")
                    print(f"    Encrypted: {Fore.GREEN}{pdf_info['encrypted']}{Style.RESET_ALL}")
                
                # Reset for new attack
                self.found_password = None
                self.stop_attack = False
                
                if choice == '1':
                    # Dictionary attack
                    wordlist_file = input(Fore.YELLOW + "Enter wordlist file path (press Enter for built-in): " + Style.RESET_ALL).strip()
                    
                    if wordlist_file and os.path.exists(wordlist_file):
                        passwords = self.load_wordlist(wordlist_file)
                        if passwords:
                            print(Fore.GREEN + f"[+] Loaded {len(passwords)} passwords from wordlist")
                        else:
                            passwords = self.common_passwords
                    else:
                        passwords = self.common_passwords
                        print(Fore.YELLOW + "[*] Using built-in common passwords list")
                    
                    start_time = time.time()
                    result = self.dictionary_attack(input_file, passwords)
                    end_time = time.time()
                    attack_type = "Dictionary Attack"
                
                elif choice == '2':
                    # Brute force attack
                    try:
                        min_len = int(input(Fore.YELLOW + "Minimum password length (default=1): " + Style.RESET_ALL) or "1")
                        max_len = int(input(Fore.YELLOW + "Maximum password length (default=6): " + Style.RESET_ALL) or "6")
                        
                        print(Fore.CYAN + "\n[*] Select character set:")
                        print("1. Lowercase letters")
                        print("2. Uppercase letters")
                        print("3. Numbers only")
                        print("4. Letters + numbers")
                        print("5. All printable characters")
                        
                        charset_choice = input(Fore.YELLOW + "Choose (1-5, default=4): " + Style.RESET_ALL).strip()
                        
                        charset_map = {
                            '1': string.ascii_lowercase,
                            '2': string.ascii_uppercase,
                            '3': string.digits,
                            '4': string.ascii_letters + string.digits,
                            '5': string.ascii_letters + string.digits + string.punctuation
                        }
                        
                        charset = charset_map.get(charset_choice, charset_map['4'])
                        
                    except ValueError:
                        print(Fore.RED + "[-] Invalid input! Using default values.")
                        min_len, max_len = 1, 6
                        charset = string.ascii_letters + string.digits
                    
                    start_time = time.time()
                    result = self.brute_force_attack(input_file, min_len, max_len, charset)
                    end_time = time.time()
                    attack_type = "Brute Force Attack"
                
                elif choice == '3':
                    # Mask attack
                    mask = input(Fore.YELLOW + "Enter mask pattern (e.g., ?l?l?d?d for 2 letters + 2 digits): " + Style.RESET_ALL).strip()
                    if not mask:
                        mask = "?l?l?l?l"  # Default: 4 lowercase letters
                    
                    start_time = time.time()
                    result = self.create_mask_attack(input_file, mask)
                    end_time = time.time()
                    attack_type = "Mask Attack"
                
                elif choice == '4':
                    # Common passwords attack
                    start_time = time.time()
                    result = self.dictionary_attack(input_file, self.common_passwords)
                    end_time = time.time()
                    attack_type = "Common Passwords Attack"
                
                else:
                    print(Fore.RED + "[-] Invalid choice!")
                    continue
                
                duration = end_time - start_time
                
                # Display results
                print(Fore.CYAN + f"\n[*] Attack completed in {duration:.2f} seconds")
                
                if result:
                    print(Fore.GREEN + f"[+] PASSWORD FOUND: {result}" + Style.RESET_ALL)
                    print(Fore.GREEN + "[+] Attempting to decrypt PDF with found password...")
                    
                    # Verify password works
                    if self.test_password(input_file, result):
                        print(Fore.GREEN + "[+] Password verified successfully!")
                        self.save_results(input_file, result, attack_type, duration)
                        
                        # Ask if user wants to decrypt
                        decrypt = input(Fore.YELLOW + "\nDecrypt PDF now? (y/n): " + Style.RESET_ALL).strip().lower()
                        if decrypt == 'y':
                            self.decrypt_pdf(input_file, result)
                    else:
                        print(Fore.RED + "[-] Password verification failed!")
                else:
                    print(Fore.RED + "[-] Password not found with current attack method")
                
                print()
                another = input(Fore.YELLOW + "Try another attack? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Attack interrupted by user")
                self.stop_attack = True
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue
    
    def decrypt_pdf(self, input_file, password):
        """Decrypt PDF and save unprotected version"""
        try:
            base_name = os.path.splitext(input_file)[0]
            output_file = f"{base_name}_decrypted.pdf"
            
            with open(input_file, 'rb') as input_pdf:
                reader = PdfReader(input_pdf)
                writer = PdfWriter()
                
                # Decrypt and copy pages
                if reader.decrypt(password) != 0:
                    for page in reader.pages:
                        writer.add_page(page)
                    
                    # Copy metadata
                    if reader.metadata:
                        writer.add_metadata(reader.metadata)
                    
                    # Save decrypted PDF
                    with open(output_file, 'wb') as output_pdf:
                        writer.write(output_pdf)
                    
                    print(Fore.GREEN + f"[+] PDF decrypted and saved as: {output_file}")
                else:
                    print(Fore.RED + "[-] Failed to decrypt PDF with provided password!")
        
        except Exception as e:
            print(Fore.RED + f"[-] Error decrypting PDF: {e}")