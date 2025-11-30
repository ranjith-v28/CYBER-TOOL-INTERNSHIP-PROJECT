#!/usr/bin/env python3
"""
All-in-One Cybersecurity Tool
A comprehensive CLI toolkit for cybersecurity enthusiasts and professionals
"""

import os
import sys
import time
import subprocess
from colorama import init, Fore, Style
from pyfiglet import Figlet

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class CyberTool:
    def __init__(self):
        self.fig = Figlet(font='slant')
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display the main banner"""
        self.clear_screen()
        print(Fore.CYAN + self.fig.renderText('CyberTool'))
        print(Fore.YELLOW + "=" * 60)
        print(Fore.GREEN + "    All-in-One Cybersecurity Toolkit")
        print(Fore.GREEN + "    For Educational and Ethical Purposes Only")
        print(Fore.YELLOW + "=" * 60)
        print(Fore.RED + "    ⚠️  WARNING: Use only on systems you own or have permission to test!")
        print(Fore.YELLOW + "=" * 60 + Style.RESET_ALL)
        print()
    
    def display_menu(self):
        """Display the main menu"""
        menu_options = [
            ("1", "🔍 Subdomain Enumeration", "subdomain"),
            ("2", "🔒 PDF Protection Tool", "pdf_protect"),
            ("3", "🔓 PDF Cracker", "pdf_crack"),
            ("4", "🌐 Network Scanner", "network_scan"),
            ("5", "🚪 Port Scanner", "port_scan"),
            ("6", "💣 Password Cracker", "password_crack"),
            ("7", "🔐 SSH Cracker", "ssh_crack"),
            ("8", "📁 FTP Cracker", "ftp_crack"),
            ("9", "ℹ️  Information Stealer", "info_steal"),
            ("0", "❌ Exit", "exit")
        ]
        
        print(Fore.CYAN + "┌" + "─" * 58 + "┐")
        print(Fore.CYAN + "│" + Fore.WHITE + "                    MAIN MENU" + " " * 35 + "│")
        print(Fore.CYAN + "├" + "─" * 58 + "┤")
        
        for num, desc, _ in menu_options:
            print(Fore.CYAN + "│" + Fore.WHITE + f"  {num}. {desc:<50}" + Fore.CYAN + "│")
        
        print(Fore.CYAN + "└" + "─" * 58 + "┘" + Style.RESET_ALL)
        print()
    
    def get_user_choice(self):
        """Get user input for menu selection"""
        while True:
            try:
                choice = input(Fore.YELLOW + "Select an option (0-9): " + Style.RESET_ALL)
                if choice in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
                    return choice
                else:
                    print(Fore.RED + "Invalid choice! Please select 0-9." + Style.RESET_ALL)
                    time.sleep(1)
            except KeyboardInterrupt:
                print(Fore.RED + "\nExiting..." + Style.RESET_ALL)
                sys.exit(0)
    
    def run_tool(self, tool_name):
        """Execute the selected tool"""
        try:
            if tool_name == "subdomain":
                from tools.subdomain_enum import SubdomainEnumerator
                tool = SubdomainEnumerator()
                tool.run()
            elif tool_name == "pdf_protect":
                from tools.pdf_protector import PDFProtector
                tool = PDFProtector()
                tool.run()
            elif tool_name == "pdf_crack":
                from tools.pdf_cracker import PDFCracker
                tool = PDFCracker()
                tool.run()
            elif tool_name == "network_scan":
                from tools.network_scanner import NetworkScanner
                tool = NetworkScanner()
                tool.run()
            elif tool_name == "port_scan":
                from tools.port_scanner import PortScanner
                tool = PortScanner()
                tool.run()
            elif tool_name == "password_crack":
                from tools.password_cracker import PasswordCracker
                tool = PasswordCracker()
                tool.run()
            elif tool_name == "ssh_crack":
                from tools.ssh_cracker import SSHCracker
                tool = SSHCracker()
                tool.run()
            elif tool_name == "ftp_crack":
                from tools.ftp_cracker import FTPCracker
                tool = FTPCracker()
                tool.run()
            elif tool_name == "info_steal":
                from tools.info_stealer import InfoStealer
                tool = InfoStealer()
                tool.run()
            elif tool_name == "exit":
                print(Fore.GREEN + "Thank you for using CyberTool! Stay ethical!" + Style.RESET_ALL)
                sys.exit(0)
        except ImportError as e:
            print(Fore.RED + f"Error importing tool: {e}" + Style.RESET_ALL)
            print(Fore.YELLOW + "Please ensure all tool modules are properly installed." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error running tool: {e}" + Style.RESET_ALL)
        
        input(Fore.YELLOW + "\nPress Enter to return to main menu..." + Style.RESET_ALL)
    
    def run(self):
        """Main application loop"""
        while True:
            self.display_banner()
            self.display_menu()
            choice = self.get_user_choice()
            
            tool_mapping = {
                '1': 'subdomain',
                '2': 'pdf_protect',
                '3': 'pdf_crack',
                '4': 'network_scan',
                '5': 'port_scan',
                '6': 'password_crack',
                '7': 'ssh_crack',
                '8': 'ftp_crack',
                '9': 'info_steal',
                '0': 'exit'
            }
            
            self.run_tool(tool_mapping.get(choice))

def main():
    """Main entry point for the application"""
    try:
        app = CyberTool()
        app.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nExiting CyberTool. Goodbye!" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()