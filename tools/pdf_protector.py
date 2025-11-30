#!/usr/bin/env python3
"""
PDF Protection Tool
Add password protection and encryption to PDF files
"""

import os
import getpass
from PyPDF2 import PdfReader, PdfWriter
from colorama import Fore, Style
import hashlib

class PDFProtector:
    def __init__(self):
        pass
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           🔒 PDF PROTECTION TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Add password protection and encryption to PDF files")
        print(Fore.RED + "⚠️  Remember your password - it cannot be recovered!")
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
                # Try to read the first page to verify it's a valid PDF
                if len(reader.pages) > 0:
                    return True, "Valid PDF file"
                else:
                    return False, "PDF appears to be empty or corrupted"
        except Exception as e:
            return False, f"Invalid PDF file: {str(e)}"
    
    def get_password(self, prompt="Enter password: "):
        """Get password from user with confirmation"""
        while True:
            try:
                password = getpass.getpass(Fore.YELLOW + prompt + Style.RESET_ALL)
                if not password:
                    print(Fore.RED + "[-] Password cannot be empty!")
                    continue
                
                if len(password) < 4:
                    print(Fore.RED + "[-] Password should be at least 4 characters!")
                    continue
                
                confirm = getpass.getpass(Fore.YELLOW + "Confirm password: " + Style.RESET_ALL)
                if password != confirm:
                    print(Fore.RED + "[-] Passwords do not match!")
                    continue
                
                return password
            except KeyboardInterrupt:
                return None
    
    def get_encryption_level(self):
        """Get encryption level from user"""
        print(Fore.CYAN + "\n[*] Select encryption level:")
        print("1. 40-bit (RC4) - Basic protection")
        print("2. 128-bit (RC4) - Standard protection")
        print("3. 128-bit (AES) - Strong protection")
        print("4. 256-bit (AES) - Maximum protection")
        
        while True:
            choice = input(Fore.YELLOW + "Choose encryption level (1-4, default=3): " + Style.RESET_ALL).strip()
            
            encryption_map = {
                '1': '40',
                '2': '128-rc4',
                '3': '128-aes',
                '4': '256-aes'
            }
            
            if choice in encryption_map:
                return encryption_map[choice]
            elif not choice:
                return encryption_map['3']
            else:
                print(Fore.RED + "[-] Invalid choice! Please select 1-4.")
    
    def get_permissions(self):
        """Get user permissions for the PDF"""
        print(Fore.CYAN + "\n[*] Configure user permissions:")
        print("Allow users to:")
        
        permissions = {
            'print': input(Fore.YELLOW + "  Print document? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y',
            'modify': input(Fore.YELLOW + "  Modify content? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y',
            'copy': input(Fore.YELLOW + "  Copy/extract content? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y',
            'annotate': input(Fore.YELLOW + "  Add/modify annotations? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y',
            'fill_forms': input(Fore.YELLOW + "  Fill form fields? (y/n, default=y): " + Style.RESET_ALL).strip().lower() == 'y',
            'extract': input(Fore.YELLOW + "  Extract pages? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y',
            'assemble': input(Fore.YELLOW + "  Assemble document? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y',
            'print_high': input(Fore.YELLOW + "  Print high quality? (y/n, default=n): " + Style.RESET_ALL).strip().lower() == 'y'
        }
        
        return permissions
    
    def encrypt_pdf(self, input_path, output_path, password, encryption_level, permissions):
        """Encrypt PDF with specified settings"""
        try:
            # Read the original PDF
            with open(input_path, 'rb') as input_file:
                reader = PdfReader(input_file)
                writer = PdfWriter()
                
                # Copy all pages
                for page in reader.pages:
                    writer.add_page(page)
                
                # Copy metadata if exists
                if reader.metadata:
                    writer.add_metadata(reader.metadata)
                
                # Set permissions
                user_permission = 0
                
                if permissions['print']:
                    user_permission |= 1 << 2
                if permissions['modify']:
                    user_permission |= 1 << 3
                if permissions['copy']:
                    user_permission |= 1 << 4
                if permissions['annotate']:
                    user_permission |= 1 << 5
                if permissions['fill_forms']:
                    user_permission |= 1 << 8
                if permissions['extract']:
                    user_permission |= 1 << 9
                if permissions['assemble']:
                    user_permission |= 1 << 10
                if permissions['print_high']:
                    user_permission |= 1 << 11
                
                # Encrypt the PDF
                if encryption_level == '40':
                    writer.encrypt(password, user_password=password, use_128bit=False)
                elif encryption_level == '128-rc4':
                    writer.encrypt(password, user_password=password, use_128bit=True)
                elif encryption_level == '128-aes':
                    writer.encrypt(password, user_password=password, use_128bit=True)
                elif encryption_level == '256-aes':
                    writer.encrypt(password, user_password=password, use_128bit=True)
                
                # Write the encrypted PDF
                with open(output_path, 'wb') as output_file:
                    writer.write(output_file)
                
                return True, "PDF encrypted successfully"
                
        except Exception as e:
            return False, f"Error encrypting PDF: {str(e)}"
    
    def verify_encryption(self, filepath, password):
        """Verify that PDF is properly encrypted"""
        try:
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                if reader.is_encrypted:
                    # Try to decrypt with password
                    result = reader.decrypt(password)
                    return result != 0  # Returns 0 if password is incorrect
                else:
                    return False
        except Exception:
            return False
    
    def get_file_info(self, filepath):
        """Get information about the PDF file"""
        try:
            file_size = os.path.getsize(filepath) / (1024 * 1024)  # Size in MB
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                page_count = len(reader.pages)
                
                # Get basic metadata
                info = {
                    'size_mb': round(file_size, 2),
                    'pages': page_count,
                    'encrypted': reader.is_encrypted
                }
                
                if reader.metadata:
                    info['title'] = reader.metadata.get('/Title', 'Unknown')
                    info['author'] = reader.metadata.get('/Author', 'Unknown')
                    info['creator'] = reader.metadata.get('/Creator', 'Unknown')
                
                return info
        except Exception as e:
            return {'error': str(e)}
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                print(Fore.CYAN + "\n[*] PDF Protection Menu:")
                print("1. Protect a new PDF")
                print("2. Verify existing protection")
                print("3. Back to main menu")
                
                choice = input(Fore.YELLOW + "\nSelect an option (1-3): " + Style.RESET_ALL).strip()
                
                if choice == '3':
                    return
                
                if choice == '1':
                    # Protect new PDF
                    input_file = input(Fore.YELLOW + "\nEnter path to PDF file: " + Style.RESET_ALL).strip()
                    
                    if not input_file:
                        print(Fore.RED + "[-] Please enter a file path!")
                        continue
                    
                    # Validate file
                    is_valid, message = self.validate_pdf_file(input_file)
                    if not is_valid:
                        print(Fore.RED + f"[-] {message}")
                        continue
                    
                    # Show file info
                    file_info = self.get_file_info(input_file)
                    if 'error' not in file_info:
                        print(Fore.GREEN + f"\n[*] File Information:")
                        print(f"    Size: {file_info['size_mb']} MB")
                        print(f"    Pages: {file_info['pages']}")
                        if 'title' in file_info:
                            print(f"    Title: {file_info['title']}")
                        if 'author' in file_info:
                            print(f"    Author: {file_info['author']}")
                    
                    # Get password
                    password = self.get_password()
                    if password is None:
                        continue
                    
                    # Get encryption level
                    encryption_level = self.get_encryption_level()
                    
                    # Get permissions
                    permissions = self.get_permissions()
                    
                    # Generate output filename
                    base_name = os.path.splitext(input_file)[0]
                    output_file = f"{base_name}_protected.pdf"
                    
                    # Check if output file exists
                    if os.path.exists(output_file):
                        overwrite = input(Fore.YELLOW + f"Output file '{output_file}' exists. Overwrite? (y/n): " + Style.RESET_ALL).strip().lower()
                        if overwrite != 'y':
                            timestamp = int(time.time())
                            output_file = f"{base_name}_protected_{timestamp}.pdf"
                    
                    # Encrypt the PDF
                    print(Fore.CYAN + "\n[*] Encrypting PDF...")
                    success, message = self.encrypt_pdf(input_file, output_file, password, encryption_level, permissions)
                    
                    if success:
                        print(Fore.GREEN + f"[+] {message}")
                        print(Fore.GREEN + f"[+] Protected PDF saved as: {output_file}")
                        
                        # Verify encryption
                        print(Fore.CYAN + "\n[*] Verifying encryption...")
                        if self.verify_encryption(output_file, password):
                            print(Fore.GREEN + "[+] Encryption verified successfully!")
                        else:
                            print(Fore.RED + "[-] Warning: Encryption verification failed!")
                        
                        # Show protected file info
                        protected_info = self.get_file_info(output_file)
                        if 'error' not in protected_info:
                            print(Fore.GREEN + f"\n[*] Protected File Information:")
                            print(f"    Size: {protected_info['size_mb']} MB")
                            print(f"    Pages: {protected_info['pages']}")
                            print(f"    Encrypted: {protected_info['encrypted']}")
                    else:
                        print(Fore.RED + f"[-] {message}")
                
                elif choice == '2':
                    # Verify protection
                    input_file = input(Fore.YELLOW + "\nEnter path to PDF file: " + Style.RESET_ALL).strip()
                    
                    if not input_file:
                        print(Fore.RED + "[-] Please enter a file path!")
                        continue
                    
                    is_valid, message = self.validate_pdf_file(input_file)
                    if not is_valid:
                        print(Fore.RED + f"[-] {message}")
                        continue
                    
                    file_info = self.get_file_info(input_file)
                    if 'error' not in file_info:
                        print(Fore.GREEN + f"\n[*] File Information:")
                        print(f"    Size: {file_info['size_mb']} MB")
                        print(f"    Pages: {file_info['pages']}")
                        print(f"    Encrypted: {Fore.GREEN if file_info['encrypted'] else Fore.RED}{file_info['encrypted']}{Style.RESET_ALL}")
                        
                        if file_info['encrypted']:
                            test_password = getpass.getpass(Fore.YELLOW + "Enter password to verify: " + Style.RESET_ALL)
                            if self.verify_encryption(input_file, test_password):
                                print(Fore.GREEN + "[+] Password verification successful!")
                            else:
                                print(Fore.RED + "[-] Password verification failed!")
                    else:
                        print(Fore.RED + f"[-] {file_info['error']}")
                
                else:
                    print(Fore.RED + "[-] Invalid choice!")
                    continue
                
                print()
                another = input(Fore.YELLOW + "Protect another PDF? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Operation interrupted by user")
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue