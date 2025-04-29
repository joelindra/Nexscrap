# NexScrap - Advanced Domain Discovery Tool

NexScrap is a powerful and comprehensive domain discovery tool designed to find and validate domains across various top-level domains (TLDs). With capabilities for certificate transparency log monitoring, reverse IP lookups, and domain validation, NexScrap provides security researchers and penetration testers with a robust solution for reconnaissance activities.

## Features

- **Multi-Source Domain Discovery** - Searches for domains across multiple sources:
  - Certificate Transparency logs via crt.sh
  - Shodan SSL certificate database
  - Censys certificate database
  - Reverse IP lookups from multiple sources

- **Domain Validation** - Automatically validates discovered domains through DNS resolution

- **Reverse IP Lookup** - Discovers additional domains sharing the same IP addresses

- **Metadata Collection** - Gathers and scores domains based on various metrics

- **Rich Progress Visualization** - Real-time progress bars and status updates

- **Configurable API Integration** - Supports multiple intelligence APIs:
  - Shodan
  - Censys
  - VirusTotal
  - SecurityTrails
  - BinaryEdge

## Installation

```bash
# Clone the repository
git clone https://github.com/joelindra/nexscrap.git
cd nexscrap

# Install dependencies
pip install -r requirements.txt
```

## Dependencies

- requests
- shodan
- censys
- aiohttp
- bs4 (BeautifulSoup)
- dnspython
- rich

## Configuration

NexScrap requires API keys for various services to maximize its potential. On first run, a config.json file will be created where you can add your API keys:

```json
{
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
```

Note: While API keys enhance functionality, NexScrap can still operate with limited capabilities using free sources if no API keys are provided.

## Usage

```bash
./nexscrap.py
```

You'll be prompted to:
1. Enter the target TLD (e.g., ac.id)
2. Specify the number of domains to scan (1-10000)
3. Enable/disable reverse IP lookup functionality

## Example Output

```
╔══════════════════════════════════════════════╗
║        Advanced Domain Scrapper v1.0         ║
║        Created by Joel Indra - Anonre        ║
║        With Reverse IP Lookup                ║
╚══════════════════════════════════════════════╝

Available sources: shodan, censys
Enter TLD (e.g., ac.id): example.com
Enter number of domains to scan (1-10000): 100
Enable reverse IP lookup? (y/n): y

[•] Total Progress ━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[•] Shodan Search ━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[•] Censys Search ━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[•] Certificate Search ━━━━━━━━━━━━━━━━━━━━━ 100%
[•] Domain Validation ━━━━━━━━━━━━━━━━━━━━━━ 100%
[•] Reverse IP Lookup ━━━━━━━━━━━━━━━━━━━━━━ 100%

┌─────────────────── Scanning Results ───────────────────┐
│ Metric                        │ Value │ Sources Used   │
│ Total Domains Found (Initial) │ 143   │ shodan, censys │
│ Additional Domains (Reverse)  │ 27    │ Reverse IP     │
│ Total Verified Domains        │ 118   │ Output saved   │
└──────────────────────────────────────────────────────┘
```

## Output Files

Verified domains are saved to a text file with a timestamp:

```
verified_domains_YYYYMMDD_HHMMSS.txt
```

## Use Cases

- Bug bounty hunting
- Asset discovery for security assessments
- Mapping organizational web infrastructure
- Identifying shadow IT assets
- Educational purposes for network reconnaissance techniques

![image](https://github.com/user-attachments/assets/9870ee8b-b537-4a75-8ee0-d79392d8cf5b)

## Disclaimer

This tool is meant for security research and penetration testing with proper authorization. Users are responsible for complying with applicable laws and regulations. The creators assume no liability for misuse.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created by Joel Indra (Anonre)
