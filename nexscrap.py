import requests
import shodan
import censys.search
import time
import random
import asyncio
import aiohttp
import json
import sys
from datetime import datetime
import os
import dns.resolver
import socket
import concurrent.futures
import re
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.style import Style
import ipaddress
from bs4 import BeautifulSoup
from typing import Set, List, Dict
from collections import defaultdict

urllib3.disable_warnings()
console = Console()

class ConfigHandler:
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = self.load_config()

    def load_config(self):
        try:
            if not os.path.exists(self.config_path):
                self.create_default_config()
                console.print("[yellow]Config file created. Please fill in your API keys in config.json[/yellow]")
                return {}
            
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            return config

        except json.JSONDecodeError:
            console.print("[red]Error: Invalid JSON in config file[/red]")
            return {}
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            return {}

    def create_default_config(self):
        default_config = {
            "shodan": {
                "api_key": "your_shodan_api_key_here"
            },
            "censys": {
                "api_id": "your_censys_api_id_here",
                "api_secret": "your_censys_api_secret_here"
            },
            "virustotal": {
                "api_key": "your_virustotal_api_key_here"
            },
            "securitytrails": {
                "api_key": "your_securitytrails_api_key_here"
            },
            "binaryedge": {
                "api_key": "your_binaryedge_api_key_here"
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(default_config, f, indent=4)

    def get_available_sources(self):
        available_sources = []
        api_configs = {
            'shodan': ['api_key'],
            'censys': ['api_id', 'api_secret'],
            'virustotal': ['api_key'],
            'securitytrails': ['api_key'],
            'binaryedge': ['api_key']
        }

        for source, keys in api_configs.items():
            if source in self.config:
                all_keys_valid = all(
                    key in self.config[source] and 
                    self.config[source][key] and 
                    self.config[source][key] != f"your_{source}_{key}_here"
                    for key in keys
                )
                if all_keys_valid:
                    available_sources.append(source)

        return available_sources

    def get_api_keys(self):
        return {
            'shodan': self.config.get('shodan', {}).get('api_key'),
            'censys_id': self.config.get('censys', {}).get('api_id'),
            'censys_secret': self.config.get('censys', {}).get('api_secret'),
            'virustotal': self.config.get('virustotal', {}).get('api_key'),
            'securitytrails': self.config.get('securitytrails', {}).get('api_key'),
            'binaryedge': self.config.get('binaryedge', {}).get('api_key')
        }

class DomainValidator:
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 2
        self.dns_resolver.lifetime = 2
        self.nameservers = [
            '8.8.8.8', '8.8.4.4',  # Google
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '9.9.9.9', '149.112.112.112'  # Quad9
        ]
        self.dns_resolver.nameservers = self.nameservers

    async def is_valid_domain(self, domain):
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-._]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', domain):
                return False
                
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(None, 
                lambda: self.dns_resolver.resolve(domain, 'A'))
            
            ip = str(records[0])
            return ipaddress.ip_address(ip).is_global
            
        except Exception as e:
            return False

    async def normalize_domain(self, domain: str) -> str:
        return domain.lower().strip()
    
    async def get_domain_ip(self, domain: str) -> str:
        """Get IP address for a domain using DNS resolution"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(None, 
                lambda: self.dns_resolver.resolve(domain, 'A'))
            return str(records[0])
        except Exception as e:
            return None

class ReverseLookup:
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        self.sources = {
            'hackertarget': 'https://api.hackertarget.com/reverseiplookup/?q={ip}',
            'rapiddns': 'https://rapiddns.io/sameip/{ip}?full=1#result',
            'viewdns': 'https://viewdns.info/reverseip/?host={ip}&t=1'
        }
        
        # Add API-based sources if keys are available
        if self.api_keys.get('securitytrails'):
            self.sources['securitytrails'] = 'https://api.securitytrails.com/v1/domains/list?ip={ip}'
        if self.api_keys.get('binaryedge'):
            self.sources['binaryedge'] = 'https://api.binaryedge.io/v2/query/domains/ip/{ip}'
        if self.api_keys.get('shodan'):
            self.sources['shodan'] = f"shodan_api:{self.api_keys.get('shodan')}" # Special handling for Shodan

    async def get_ip_for_domain(self, domain):
        try:
            answers = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, domain)
            return answers
        except:
            return None

    async def fetch_domains_from_ip(self, session, ip, source_url, source_name):
        headers = self.get_headers_for_source(source_name)
        
        # Special handling for Shodan API
        if source_name == 'shodan':
            try:
                api_key = source_url.split(':')[1]
                api = shodan.Shodan(api_key)
                results = await asyncio.to_thread(api.host, ip)
                domains = []
                if 'domains' in results:
                    domains.extend(results['domains'])
                if 'hostnames' in results:
                    domains.extend(results['hostnames'])
                return list(set(domains))
            except Exception as e:
                console.print(f"[yellow]Info: Error with Shodan API for IP {ip}: {e}")
                return []
        
        # Regular HTTP APIs
        try:
            async with session.get(source_url.format(ip=ip), headers=headers, ssl=False, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    return self.parse_response(source_name, text)
                    
        except Exception as e:
            console.print(f"[yellow]Info: Error with {source_name} for IP {ip}: {e}")
        return []

    def get_headers_for_source(self, source_name):
        base_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        if source_name == 'securitytrails':
            base_headers['apikey'] = self.api_keys.get('securitytrails')
        elif source_name == 'binaryedge':
            base_headers['X-Key'] = self.api_keys.get('binaryedge')
            
        return base_headers

    def parse_response(self, source_name, text):
        domains = set()
        try:
            if source_name == 'hackertarget':
                domains.update(line.strip() for line in text.split('\n') 
                            if line.strip() and not line.startswith('API'))
            
            elif source_name == 'rapiddns':
                soup = BeautifulSoup(text, 'html.parser')
                domains.update(td.get_text(strip=True) 
                             for td in soup.select('td.col-md-4'))
            
            elif source_name == 'viewdns':
                soup = BeautifulSoup(text, 'html.parser')
                domains.update(td.get_text(strip=True) 
                             for td in soup.select('table#null tr td:first-child'))
            
            elif source_name == 'securitytrails':
                data = json.loads(text)
                domains.update(domain['hostname'] for domain in data.get('records', []))
            
            elif source_name == 'binaryedge':
                data = json.loads(text)
                domains.update(data.get('domains', []))
                
        except Exception as e:
            console.print(f"[yellow]Warning: Error parsing {source_name} response: {e}")
            
        return list(domains)

    async def perform_reverse_lookup(self, ip, tld):
        """Perform reverse lookup on an IP address and filter by TLD"""
        domains = set()
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for source_name, source_url in self.sources.items():
                task = asyncio.create_task(
                    self.fetch_domains_from_ip(session, ip, source_url, source_name)
                )
                tasks.append(task)
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                    
                if isinstance(result, list):
                    # Filter domains by TLD
                    filtered_domains = [domain for domain in result if domain.endswith(f'.{tld}')]
                    domains.update(filtered_domains)
                    
        return list(domains)

class AdvancedDomainScraper:
    def __init__(self, config_handler):
        self.config_handler = config_handler
        self.api_keys = config_handler.get_api_keys()
        self.available_sources = config_handler.get_available_sources()
        
        # Initialize APIs for available sources
        if 'shodan' in self.available_sources:
            self.shodan_api = shodan.Shodan(self.api_keys['shodan'])
        
        if 'censys' in self.available_sources:
            self.censys_api = censys.search.CensysSearch(
                api_id=self.api_keys['censys_id'],
                api_secret=self.api_keys['censys_secret']
            )
        
        self.domains = set()
        self.verified_domains = set()
        self.reverse_domains = set()
        self.domain_ips = {}  # Store IP addresses for verified domains
        self.session = requests.Session()
        self.domain_validator = DomainValidator()
        self.reverse_lookup = ReverseLookup(self.api_keys)
        self.progress = None
        self.tasks = {}
        self.semaphore = asyncio.Semaphore(20)
        self.domain_metadata = defaultdict(dict)
        self.tld = None  # Will be set during execution

    def create_progress(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(style="cyan", complete_style="green"),
            TaskProgressColumn(),
            console=console
        )
        
        # Create tasks based on available sources
        self.tasks = {'total': self.progress.add_task("[cyan]Total Progress", total=self.target_count)}
        
        if 'shodan' in self.available_sources:
            self.tasks['shodan'] = self.progress.add_task("[magenta]Shodan Search", total=self.target_count//2)
        if 'censys' in self.available_sources:
            self.tasks['censys'] = self.progress.add_task("[blue]Censys Search", total=self.target_count//2)
        self.tasks['crt'] = self.progress.add_task("[yellow]Certificate Search", total=self.target_count//2)
        self.tasks['validation'] = self.progress.add_task("[green]Domain Validation", total=self.target_count)
        self.tasks['reverse'] = self.progress.add_task("[red]Reverse IP Lookup", total=100)

    async def search_shodan_async(self, tld):
        if 'shodan' not in self.available_sources:
            return
            
        try:
            page = 1
            while len(self.domains) < self.target_count:
                async with self.semaphore:
                    query = f'ssl.cert.subject.CN:*.{tld}'
                    results = await asyncio.to_thread(self.shodan_api.search, query, page=page)
                    
                    if not results['matches']:
                        break

                    for result in results['matches']:
                        if 'ssl' in result and 'cert' in result['ssl']:
                            domain = result['ssl']['cert']['subject']['CN']
                            if domain.endswith(f'.{tld}'):
                                self.domains.add(domain)
                                self.progress.update(self.tasks['shodan'], advance=1)
                                
                    page += 1
                    await asyncio.sleep(0.2)
                    
        except Exception as e:
            console.print(f"\n[yellow]Shodan search error: {e}")

    async def search_censys(self, tld):
        if 'censys' not in self.available_sources:
            return
            
        try:
            query = f"parsed.names: *.{tld}"
            async with self.semaphore:
                for cert in self.censys_api.search("certificates", query, fields=["parsed.names"]):
                    for domain in cert["parsed.names"]:
                        if domain.endswith(f'.{tld}'):
                            self.domains.add(domain.lower())
                            self.progress.update(self.tasks['censys'], advance=1)
                    await asyncio.sleep(0.2)
        except Exception as e:
            console.print(f"\n[yellow]Censys search error: {e}")

    async def search_crt_sh(self, tld):
        url = f"https://crt.sh/?q=%.{tld}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            domain = entry.get('name_value', '').lower()
                            if domain.endswith(f'.{tld}'):
                                self.domains.add(domain)
                                self.progress.update(self.tasks['crt'], advance=1)
        except Exception as e:
            console.print(f"\n[yellow]crt.sh search error: {e}")

    async def search_virustotal(self, domain):
        if 'virustotal' not in self.available_sources:
            return []
            
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': self.api_keys['virustotal'], 'domain': domain}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.domain_metadata[domain]['vt_score'] = data.get('positives', 0)
                        return data.get('subdomains', [])
        except Exception as e:
            console.print(f"\n[yellow]VirusTotal API error: {e}")
        return []

    async def validate_domains(self, domains):
        tasks = []
        for domain in domains:
            task = asyncio.create_task(self.validate_domain(domain))
            tasks.append(task)
            
        await asyncio.gather(*tasks)

    async def validate_domain(self, domain):
        try:
            is_valid = await self.domain_validator.is_valid_domain(domain)
            if is_valid:
                self.verified_domains.add(domain)
                # Get and store IP for future reverse lookup
                ip = await self.domain_validator.get_domain_ip(domain)
                if ip:
                    self.domain_ips[domain] = ip
                self.progress.update(self.tasks['validation'], advance=1)
        except Exception as e:
            pass  # Silently handle validation errors
            
    async def perform_reverse_lookups(self):
        """Perform reverse IP lookups on verified domains without limiting IP count"""
        if not self.verified_domains:
            return
            
        console.print("\n[bold yellow]Performing reverse IP lookups on verified domains...")
        
        # Get unique IPs from verified domains
        unique_ips = set(self.domain_ips.values())
        total_ips = len(unique_ips)
        
        if total_ips == 0:
            console.print("[yellow]No valid IPs found for reverse lookup")
            return
            
        self.progress.update(self.tasks['reverse'], total=total_ips)
        
        # Process all IPs without limitation, just using delay to prevent rate limiting
        for ip in unique_ips:
            try:
                domains = await self.reverse_lookup.perform_reverse_lookup(ip, self.tld)
                
                # Add new domains to our collection
                for domain in domains:
                    if domain not in self.domains and domain not in self.verified_domains:
                        self.reverse_domains.add(domain)
                        
                self.progress.update(self.tasks['reverse'], advance=1)
                await asyncio.sleep(0.5)  # Prevent rate limiting
                
            except Exception as e:
                console.print(f"[yellow]Error in reverse lookup for IP {ip}: {e}")
                
        # Validate new domains found via reverse lookup
        if self.reverse_domains:
            console.print(f"\n[bold green]Found {len(self.reverse_domains)} new domains via reverse lookup")
            await self.validate_domains(list(self.reverse_domains))

    async def deduplicate_domains(self):
        unique_domains = set()
        domain_scores = {}

        for domain in self.verified_domains:
            normalized = await self.domain_validator.normalize_domain(domain)
            
            score = 0
            metadata = self.domain_metadata.get(domain, {})
            
            score += 100 - len(domain)
            score -= metadata.get('vt_score', 0) * 10
            
            if normalized not in domain_scores or score > domain_scores[normalized][1]:
                domain_scores[normalized] = (domain, score)

        self.verified_domains = {domain for domain, score in domain_scores.values()}

    def save_results(self, filename=None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"verified_domains_{timestamp}.txt"
            
        with open(filename, 'w') as f:
            for domain in sorted(self.verified_domains):
                f.write(f"{domain}\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Sources Used", style="yellow")
        
        table.add_row(
            "Total Domains Found (Initial)",
            str(len(self.domains)),
            ", ".join(self.available_sources)
        )
        table.add_row(
            "Additional Domains (Reverse Lookup)",
            str(len(self.reverse_domains)),
            "Reverse IP Lookup"
        )
        table.add_row(
            "Total Verified Domains",
            str(len(self.verified_domains)),
            f"Output saved to: {filename}"
        )

        console.print("\n")
        console.print(Panel(table, title="[bold cyan]Scanning Results", border_style="cyan"))

    async def run_scraper(self, tld, target_count):
        self.target_count = target_count
        self.tld = tld
        
        with console.status("[bold green]Initializing scanner...") as status:
            console.print(f"[cyan]Available sources: {', '.join(self.available_sources)}")
            
        self.create_progress()
        
        with self.progress:
            search_tasks = []
            
            if 'shodan' in self.available_sources:
                search_tasks.append(self.search_shodan_async(tld))
            if 'censys' in self.available_sources:
                search_tasks.append(self.search_censys(tld))
            search_tasks.append(self.search_crt_sh(tld))
            
            await asyncio.gather(*search_tasks)
            
            console.print("\n[bold yellow]Starting domain validation...")
            domain_list = list(self.domains)
            chunk_size = 100
            for i in range(0, len(domain_list), chunk_size):
                chunk = domain_list[i:i + chunk_size]
                await self.validate_domains(chunk)
            
            # Perform reverse lookups on verified domains
            await self.perform_reverse_lookups()
        
        console.print("\n[bold yellow]Deduplicating domains...")
        await self.deduplicate_domains()
        
        self.save_results()

def display_banner():
    banner = """
    [cyan]╔══════════════════════════════════════════════╗
    ║        [bold white]Advanced Domain Scrapper v1.0[/bold white]         ║
    ║        [bold yellow]Created by Joel Indra - Anonre[/bold yellow]        ║
    ║        [bold red]With Reverse IP Lookup[/bold red]                ║
    ╚══════════════════════════════════════════════╝[/cyan]
    """
    console.print(banner)

def main():
    display_banner()
    
    try:
        # Initialize config handler
        config_handler = ConfigHandler()
        available_sources = config_handler.get_available_sources()
        
        if not available_sources:
            console.print("[yellow]Warning: No API keys configured. The scanner will use only free sources.[/yellow]")
        else:
            console.print("[green]Available sources:[/green]", ", ".join(available_sources))
        
        tld = console.input("[bold cyan]Enter TLD (e.g., ac.id): [/bold cyan]").strip()
        
        while True:
            try:
                target_count = int(console.input("[bold cyan]Enter number of domains to scan (1-10000): [/bold cyan]"))
                if 1 <= target_count <= 10000:
                    break
                console.print("[bold red]Error: Please enter a number between 1 and 10000![/bold red]")
            except ValueError:
                console.print("[bold red]Error: Please enter a valid number![/bold red]")
        
        # Ask about enabling reverse IP lookup
        reverse_enabled = console.input("[bold cyan]Enable reverse IP lookup? (y/n): [/bold cyan]").strip().lower() == 'y'
        
        scraper = AdvancedDomainScraper(config_handler)
        
        # Conditionally disable reverse lookups if user says no
        if not reverse_enabled:
            original_perform_reverse_lookups = scraper.perform_reverse_lookups
            scraper.perform_reverse_lookups = lambda: asyncio.sleep(0)
        
        asyncio.run(scraper.run_scraper(tld, target_count))
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Process interrupted by user.[/bold red]")
        try:
            scraper.save_results()
        except:
            pass
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error: {e}[/bold red]")
        try:
            scraper.save_results()
        except:
            pass

if __name__ == "__main__":
    main()