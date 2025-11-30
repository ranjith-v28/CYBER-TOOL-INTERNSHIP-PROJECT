#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Discover subdomains for a given domain using multiple techniques
"""

import dns.resolver
import requests
import socket
import threading
import time
from colorama import Fore, Style
from tqdm import tqdm
import concurrent.futures

class SubdomainEnumerator:
    def __init__(self):
        self.wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod',
            'api', 'blog', 'shop', 'news', 'support', 'help', 'docs', 'forum',
            'community', 'cdn', 'static', 'assets', 'media', 'images', 'files',
            'download', 'upload', 'backup', 'db', 'database', 'sql', 'mysql',
            'postgres', 'redis', 'cache', 'search', 'elastic', 'log', 'logs',
            'monitor', 'metrics', 'stats', 'analytics', 'report', 'dashboard',
            'vpn', 'remote', 'secure', 'ssl', 'tls', 'cert', 'certificate',
            'auth', 'oauth', 'login', 'signin', 'register', 'signup',
            'account', 'profile', 'user', 'users', 'member', 'members',
            'portal', 'intranet', 'extranet', 'internal', 'external',
            'staging', 'development', 'production', 'live', 'demo',
            'beta', 'alpha', 'preview', 'sandbox', 'testing', 'qa',
            'mobile', 'm', 'app', 'application', 'service', 'services',
            'microservice', 'micro', 'server', 'servers', 'host', 'hosts',
            'node', 'nodes', 'cluster', 'cloud', 'aws', 'azure', 'gcp'
        ]
        
        self.found_subdomains = set()
        self.lock = threading.Lock()
    
    def clear_screen(self):
        """Clear the terminal screen"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display tool banner"""
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "           🔍 SUBDOMAIN ENUMERATION TOOL")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "Discover subdomains using multiple techniques")
        print(Fore.RED + "⚠️  Use only for authorized testing!")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        print()
    
    def validate_domain(self, domain):
        """Validate domain format"""
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            # Domain might not resolve but could still be valid
            if '.' in domain and len(domain.split('.')) >= 2:
                return True
            return False
    
    def dns_brute_force(self, domain, subdomain, timeout=2):
        """Attempt to resolve subdomain via DNS"""
        try:
            full_domain = f"{subdomain}.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            result = resolver.resolve(full_domain, 'A')
            if result:
                ip_address = result[0].address
                with self.lock:
                    if full_domain not in self.found_subdomains:
                        self.found_subdomains.add(full_domain)
                        return (full_domain, ip_address)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
        return None
    
    def check_http_response(self, domain):
        """Check if domain responds to HTTP requests"""
        try:
            protocols = ['http', 'https']
            for protocol in protocols:
                url = f"{protocol}://{domain}"
                try:
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    if response.status_code < 500:
                        return (url, response.status_code)
                except requests.RequestException:
                    continue
        except Exception:
            pass
        return None
    
    def dns_transfer(self, domain):
        """Attempt DNS zone transfer"""
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    if zone:
                        subdomains = []
                        for name, node in zone.nodes.items():
                            if name.to_text() != '@':
                                full_name = f"{name.to_text()}.{domain}"
                                subdomains.append(full_name)
                        return subdomains
                except Exception:
                    continue
        except Exception:
            pass
        return []
    
    def search_engines_query(self, domain):
        """Simulate search engine queries (conceptual)"""
        print(Fore.YELLOW + "[*] Performing search engine simulation...")
        time.sleep(1)
        # This would normally use search APIs - simplified for demo
        return []
    
    def enumerate_subdomains(self, domain, method='all'):
        """Main enumeration function"""
        print(Fore.GREEN + f"[*] Starting enumeration for: {domain}")
        print()
        
        if method in ['all', 'dns']:
            print(Fore.CYAN + "[*] DNS Brute Force Enumeration...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for subdomain in self.wordlist:
                    future = executor.submit(self.dns_brute_force, domain, subdomain)
                    futures.append(future)
                
                with tqdm(total=len(futures), desc="Scanning", 
                         bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result:
                            print(Fore.GREEN + f"[+] Found: {result[0]} -> {result[1]}")
                        pbar.update(1)
        
        if method in ['all', 'transfer']:
            print(Fore.CYAN + "\n[*] Attempting DNS Zone Transfer...")
            zone_subdomains = self.dns_transfer(domain)
            for subdomain in zone_subdomains:
                print(Fore.GREEN + f"[+] Zone Transfer: {subdomain}")
                self.found_subdomains.add(subdomain)
        
        if method in ['all', 'search']:
            search_subdomains = self.search_engines_query(domain)
            for subdomain in search_subdomains:
                self.found_subdomains.add(subdomain)
        
        print(Fore.CYAN + "\n[*] Checking HTTP responses...")
        working_domains = []
        for subdomain in tqdm(list(self.found_subdomains), desc="HTTP Check"):
            http_result = self.check_http_response(subdomain)
            if http_result:
                working_domains.append((subdomain, http_result[1]))
        
        return working_domains
    
    def save_results(self, results, filename):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                f.write("Subdomain,Status_Code\n")
                for domain, status in results:
                    f.write(f"{domain},{status}\n")
            print(Fore.GREEN + f"[+] Results saved to: {filename}")
        except Exception as e:
            print(Fore.RED + f"[-] Error saving results: {e}")
    
    def run(self):
        """Main tool execution"""
        self.clear_screen()
        self.display_banner()
        
        while True:
            try:
                domain = input(Fore.YELLOW + "Enter domain to enumerate (or 'back' to return): " + Style.RESET_ALL).strip()
                
                if domain.lower() == 'back':
                    return
                
                if not domain:
                    print(Fore.RED + "[-] Please enter a valid domain!")
                    continue
                
                if not self.validate_domain(domain):
                    print(Fore.RED + f"[-] Invalid domain: {domain}")
                    continue
                
                print(Fore.CYAN + "\n[*] Select enumeration method:")
                print("1. DNS Brute Force")
                print("2. DNS Zone Transfer")
                print("3. Search Engines")
                print("4. All Methods")
                
                method_choice = input(Fore.YELLOW + "Choose method (1-4, default=4): " + Style.RESET_ALL).strip()
                
                method_map = {
                    '1': 'dns',
                    '2': 'transfer',
                    '3': 'search',
                    '4': 'all'
                }
                
                method = method_map.get(method_choice, 'all')
                
                print(Fore.GREEN + "\n[*] Starting enumeration...")
                start_time = time.time()
                
                results = self.enumerate_subdomains(domain, method)
                
                end_time = time.time()
                
                print(Fore.CYAN + f"\n[*] Enumeration completed in {end_time - start_time:.2f} seconds")
                print(Fore.GREEN + f"[+] Total subdomains found: {len(self.found_subdomains)}")
                print(Fore.GREEN + f"[+] Active HTTP services: {len(results)}")
                
                if results:
                    print(Fore.CYAN + "\n[*] Active Subdomains:")
                    for domain, status in results[:20]:  # Show first 20
                        status_color = Fore.GREEN if status < 400 else Fore.YELLOW
                        print(f"    {domain} - {status_color}HTTP {status}{Style.RESET_ALL}")
                    
                    if len(results) > 20:
                        print(f"    ... and {len(results) - 20} more")
                
                # Save results
                filename = f"{domain}_subdomains.txt"
                self.save_results([(d, s) for d, s in results], filename)
                
                print()
                another = input(Fore.YELLOW + "Enumerate another domain? (y/n): " + Style.RESET_ALL).strip().lower()
                if another != 'y':
                    break
                    
            except KeyboardInterrupt:
                print(Fore.RED + "\n[*] Enumeration interrupted by user")
                break
            except Exception as e:
                print(Fore.RED + f"[-] Error: {e}")
                continue