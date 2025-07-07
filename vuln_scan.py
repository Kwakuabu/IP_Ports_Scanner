#!/usr/bin/env python3
"""
Internal Network Vulnerability Scanner - Enhanced Version
A comprehensive tool for discovering hosts, scanning ports, and identifying vulnerabilities
Enhanced with advanced hostname detection for consumer devices
Author: Silas Asani Abudu
Version: 1.1
"""

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import nmap
import requests
from tabulate import tabulate

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f'vuln_scan_{datetime.now().strftime("%Y%m%d")}.log'),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class NetworkScanner:
    """Core scanning engine for host discovery and port scanning"""

    def __init__(self, max_threads: int = 10):
        self.nm = nmap.PortScanner()
        self.max_threads = max_threads
        self.scan_results = []

    def discover_hosts(self, subnet: str) -> List[str]:
        """
        Discover live hosts in the given subnet using ping sweep
        """
        logger.info(f"Discovering hosts in subnet: {subnet}")
        try:
            # Validate subnet format
            network = ipaddress.ip_network(subnet, strict=False)

            # Enhanced host discovery with hostname detection
            result = self.nm.scan(
                hosts=subnet, arguments="-sn -R --dns-servers 8.8.8.8,1.1.1.1"
            )

            live_hosts = []
            for host in result["scan"]:
                if result["scan"][host]["status"]["state"] == "up":
                    live_hosts.append(host)

                    # Try to get hostname during discovery
                    hostname = self._get_hostname(result, host)
                    if hostname:
                        logger.info(f"Live host found: {host} ({hostname})")
                    else:
                        logger.info(f"Live host found: {host}")

            # Additional mDNS discovery for Apple devices
            mdns_hosts = self._discover_mdns_hosts(subnet)
            for mdns_host in mdns_hosts:
                if mdns_host not in live_hosts:
                    live_hosts.append(mdns_host)

            logger.info(f"Found {len(live_hosts)} live hosts in {subnet}")
            return live_hosts

        except Exception as e:
            logger.error(f"Error during host discovery: {e}")
            return []

    def _discover_mdns_hosts(self, subnet: str) -> List[str]:
        """Discover hosts using mDNS/Bonjour (for Apple devices)"""
        discovered_hosts = []
        try:
            import subprocess
            import ipaddress

            network = ipaddress.ip_network(subnet, strict=False)

            # Try to discover .local hostnames
            common_names = [
                "iPhone.local",
                "iPad.local",
                "MacBook.local",
                "iMac.local",
                "Apple-TV.local",
                "router.local",
                "gateway.local",
            ]

            for name in common_names:
                try:
                    cmd = ["dig", "+short", name, "@224.0.0.251"]
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=2
                    )

                    if result.stdout.strip():
                        ip = result.stdout.strip()
                        # Check if IP is in our target subnet
                        if ipaddress.ip_address(ip) in network:
                            discovered_hosts.append(ip)
                            logger.info(f"mDNS discovery: {ip} ({name})")
                except:
                    continue

        except Exception as e:
            logger.debug(f"mDNS discovery error: {e}")

        return discovered_hosts

    def scan_host_ports(self, host: str) -> Dict:
        """
        Perform comprehensive port scan on a single host
        """
        logger.info(f"Scanning ports on {host}")
        try:
            # Comprehensive TCP scan with enhanced hostname detection
            result = self.nm.scan(
                hosts=host,
                arguments="-sV -sS -O --version-intensity 5 -p- --max-retries 2 --host-timeout 300 -R --dns-servers 8.8.8.8,1.1.1.1",
            )

            host_info = {
                "ip": host,
                "hostname": self._get_hostname(result, host),
                "os": self._get_os_info(result, host),
                "ports": [],
            }

            if host in result["scan"]:
                scan_data = result["scan"][host]

                if "tcp" in scan_data:
                    for port, port_info in scan_data["tcp"].items():
                        if port_info["state"] == "open":
                            port_data = {
                                "port": port,
                                "protocol": "tcp",
                                "service": port_info.get("name", "unknown"),
                                "product": port_info.get("product", ""),
                                "version": port_info.get("version", ""),
                                "extrainfo": port_info.get("extrainfo", ""),
                                "banner": self._extract_banner(port_info),
                            }
                            host_info["ports"].append(port_data)
                            logger.info(
                                f"Open port found: {host}:{port} ({port_info.get('name', 'unknown')})"
                            )

            return host_info

        except Exception as e:
            logger.error(f"Error scanning {host}: {e}")
            return {"ip": host, "hostname": "", "os": "", "ports": []}

    def _get_hostname(self, result: Dict, host: str) -> str:
        """Extract hostname from scan result with multiple methods"""
        hostname = ""

        try:
            # Method 1: Nmap hostname detection
            if host in result["scan"] and "hostnames" in result["scan"][host]:
                hostnames = result["scan"][host]["hostnames"]
                if hostnames and len(hostnames) > 0:
                    hostname = hostnames[0].get("name", "")
                    if hostname:
                        return hostname

            # Method 2: Try reverse DNS lookup
            try:
                import socket

                hostname = socket.gethostbyaddr(host)[0]
                if hostname and hostname != host:
                    return hostname
            except:
                pass

            # Method 3: Try mDNS/Bonjour lookup
            try:
                import subprocess

                # Try to resolve .local addresses (macOS/Linux)
                cmd = ["dig", "+short", "-x", host, "@224.0.0.251"]
                result_dns = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=2
                )
                if result_dns.stdout.strip():
                    mdns_name = result_dns.stdout.strip().rstrip(".")
                    if mdns_name and mdns_name != host:
                        return mdns_name
            except:
                pass

            # Method 4: Try NetBIOS name resolution (Windows/SMB devices)
            try:
                import subprocess

                # Try nmblookup for Windows/SMB devices
                cmd = ["nmblookup", "-A", host]
                result_nb = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=3
                )
                if result_nb.stdout:
                    lines = result_nb.stdout.split("\n")
                    for line in lines:
                        if "<00>" in line and "GROUP" not in line:
                            parts = line.split()
                            if parts and not parts[0].startswith("<"):
                                return parts[0].strip()
            except:
                pass

            # Method 5: Try SNMP if it's a network device
            if self._is_network_device(host):
                snmp_name = self._get_snmp_hostname(host)
                if snmp_name:
                    return snmp_name

        except Exception as e:
            logger.debug(f"Hostname detection error for {host}: {e}")

        return hostname

    def _get_os_info(self, result: Dict, host: str) -> str:
        """Extract OS information from scan result"""
        try:
            if host in result["scan"] and "osmatch" in result["scan"][host]:
                os_matches = result["scan"][host]["osmatch"]
                if os_matches and len(os_matches) > 0:
                    return os_matches[0].get("name", "")
        except:
            pass
        return ""

    def _extract_banner(self, port_info: Dict) -> str:
        """Extract service banner information"""
        banner_parts = []
        for field in ["product", "version", "extrainfo"]:
            value = port_info.get(field, "")
            if value:
                banner_parts.append(value)
        return " ".join(banner_parts)

    def _is_network_device(self, host: str) -> bool:
        """Check if host might be a network device (router, switch, etc.)"""
        try:
            # Quick port check for common network device ports
            common_network_ports = [22, 23, 80, 161, 443, 8080]
            result = self.nm.scan(
                host, arguments=f'-p{",".join(map(str, common_network_ports))} --open'
            )

            if host in result["scan"] and "tcp" in result["scan"][host]:
                open_ports = result["scan"][host]["tcp"].keys()
                # If it has SNMP (161) or web management, likely a network device
                return 161 in open_ports or (80 in open_ports and 22 in open_ports)
        except:
            pass
        return False

    def _get_snmp_hostname(self, host: str) -> str:
        """Try to get hostname via SNMP"""
        try:
            import subprocess

            # Try SNMP sysName query (OID 1.3.6.1.2.1.1.5.0)
            cmd = ["snmpget", "-v2c", "-c", "public", host, "1.3.6.1.2.1.1.5.0"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.stdout and "STRING:" in result.stdout:
                # Extract hostname from SNMP response
                hostname = result.stdout.split("STRING:")[-1].strip().strip('"')
                if hostname and hostname != host:
                    return hostname
        except:
            pass
        return ""


class CVELookup:
    """Handle CVE lookups using external APIs"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Internal-Vuln-Scanner/1.0"})

    def lookup_vulnerabilities(
        self, service: str, product: str, version: str
    ) -> List[Dict]:
        """
        Look up known vulnerabilities for a service
        """
        if not product:
            return []

        vulnerabilities = []

        # Try Vulners API first
        vulners_cves = self._query_vulners(product, version)
        vulnerabilities.extend(vulners_cves)

        # Could add more sources here (NVD, etc.)

        return vulnerabilities[:5]  # Limit to top 5 CVEs

    def _query_vulners(self, product: str, version: str) -> List[Dict]:
        """Query Vulners API for CVEs"""
        try:
            query = f"{product}"
            if version:
                query += f" {version}"

            url = "https://vulners.com/api/v3/search/lucene/"
            params = {
                "query": query,
                "fields": ["id", "title", "cvss", "published", "type"],
                "size": 10,
            }

            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()

                cves = []
                for item in data.get("data", {}).get("search", []):
                    if item.get("_source", {}).get("type") == "cve":
                        source = item["_source"]
                        cves.append(
                            {
                                "cve_id": source.get("id", ""),
                                "title": source.get("title", ""),
                                "cvss": source.get("cvss", {}).get("score", 0),
                                "published": source.get("published", ""),
                                "url": f"https://vulners.com/cve/{source.get('id', '')}",
                            }
                        )

                return sorted(cves, key=lambda x: x["cvss"], reverse=True)

        except Exception as e:
            logger.warning(f"CVE lookup failed for {product}: {e}")

        return []


class ReportGenerator:
    """Generate reports in various formats"""

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def display_results(self, scan_results: List[Dict]):
        """Display results in tabular format"""
        if not scan_results:
            print("No scan results to display.")
            return

        # Prepare data for tabulation
        table_data = []
        for host in scan_results:
            if not host["ports"]:
                table_data.append(
                    [
                        host["ip"],
                        host["hostname"],
                        host["os"],
                        "No open ports",
                        "",
                        "",
                        "",
                        "",
                    ]
                )
            else:
                for port in host["ports"]:
                    cve_info = ""
                    if "vulnerabilities" in port and port["vulnerabilities"]:
                        top_cve = port["vulnerabilities"][0]
                        cve_info = f"{top_cve['cve_id']} (CVSS: {top_cve['cvss']})"

                    table_data.append(
                        [
                            host["ip"],
                            host["hostname"],
                            host["os"],
                            f"{port['port']}/{port['protocol']}",
                            port["service"],
                            port["product"],
                            port["version"],
                            cve_info,
                        ]
                    )

        headers = [
            "IP",
            "Hostname",
            "OS",
            "Port",
            "Service",
            "Product",
            "Version",
            "Top CVE",
        ]
        print("\n" + "=" * 120)
        print("VULNERABILITY SCAN RESULTS")
        print("=" * 120)
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def export_csv(self, scan_results: List[Dict], filename: Optional[str] = None):
        """Export results to CSV file"""
        if filename is None:
            filename = f"scan_results_{self.timestamp}.csv"

        try:
            import csv

            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow(
                    [
                        "IP",
                        "Hostname",
                        "OS",
                        "Port",
                        "Protocol",
                        "Service",
                        "Product",
                        "Version",
                        "Banner",
                        "CVE_ID",
                        "CVE_Title",
                        "CVSS_Score",
                        "CVE_URL",
                    ]
                )

                # Write data
                for host in scan_results:
                    if not host["ports"]:
                        writer.writerow(
                            [
                                host["ip"],
                                host["hostname"],
                                host["os"],
                                "",
                                "",
                                "No open ports",
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                            ]
                        )
                    else:
                        for port in host["ports"]:
                            # Write one row per vulnerability, or one row if no vulnerabilities
                            if "vulnerabilities" in port and port["vulnerabilities"]:
                                for vuln in port["vulnerabilities"]:
                                    writer.writerow(
                                        [
                                            host["ip"],
                                            host["hostname"],
                                            host["os"],
                                            port["port"],
                                            port["protocol"],
                                            port["service"],
                                            port["product"],
                                            port["version"],
                                            port["banner"],
                                            vuln["cve_id"],
                                            vuln["title"],
                                            vuln["cvss"],
                                            vuln["url"],
                                        ]
                                    )
                            else:
                                writer.writerow(
                                    [
                                        host["ip"],
                                        host["hostname"],
                                        host["os"],
                                        port["port"],
                                        port["protocol"],
                                        port["service"],
                                        port["product"],
                                        port["version"],
                                        port["banner"],
                                        "",
                                        "",
                                        "",
                                        "",
                                    ]
                                )

            logger.info(f"Results exported to {filename}")
            print(f"\nResults exported to: {filename}")

        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")


class VulnerabilityScanner:
    """Main scanner orchestrator"""

    def __init__(self, max_threads: int = 10, enable_cve_lookup: bool = True):
        self.scanner = NetworkScanner(max_threads)
        self.cve_lookup = CVELookup() if enable_cve_lookup else None
        self.reporter = ReportGenerator()
        self.max_threads = max_threads

    def scan_subnets(self, subnets: List[str]) -> List[Dict]:
        """
        Perform comprehensive scan across multiple subnets
        """
        logger.info(f"Starting vulnerability scan for subnets: {subnets}")
        all_results = []

        # Phase 1: Host Discovery
        all_hosts = []
        for subnet in subnets:
            hosts = self.scanner.discover_hosts(subnet)
            all_hosts.extend(hosts)

        if not all_hosts:
            logger.warning("No live hosts found!")
            return []

        logger.info(f"Total hosts to scan: {len(all_hosts)}")

        # Phase 2: Port Scanning (with threading)
        scan_results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_host = {
                executor.submit(self.scanner.scan_host_ports, host): host
                for host in all_hosts
            }

            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    scan_results.append(result)
                except Exception as e:
                    logger.error(f"Failed to scan {host}: {e}")

        # Phase 3: CVE Lookup (if enabled)
        if self.cve_lookup:
            logger.info("Performing CVE lookups...")
            self._enrich_with_cves(scan_results)

        return scan_results

    def _enrich_with_cves(self, scan_results: List[Dict]):
        """Add CVE information to scan results"""
        for host in scan_results:
            for port in host["ports"]:
                if port["product"]:
                    vulnerabilities = self.cve_lookup.lookup_vulnerabilities(
                        port["service"], port["product"], port["version"]
                    )
                    port["vulnerabilities"] = vulnerabilities
                    if vulnerabilities:
                        logger.info(
                            f"Found {len(vulnerabilities)} CVEs for {host['ip']}:{port['port']}"
                        )


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Internal Network Vulnerability Scanner - Enhanced",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vuln_scan.py -t 192.168.1.0/24
  python vuln_scan.py -t 192.168.1.0/24 192.168.2.0/24 --no-cve
  python vuln_scan.py -t 10.0.0.0/16 --threads 20 --output my_scan.csv
        """,
    )

    parser.add_argument(
        "-t",
        "--targets",
        nargs="+",
        required=True,
        help="Target subnets in CIDR format (e.g., 192.168.1.0/24)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Maximum number of concurrent threads (default: 10)",
    )

    parser.add_argument("--no-cve", action="store_true", help="Disable CVE lookup")

    parser.add_argument(
        "-o",
        "--output",
        help="Output CSV filename (default: scan_results_TIMESTAMP.csv)",
    )

    parser.add_argument(
        "--quiet", action="store_true", help="Suppress console output except errors"
    )

    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    # Validate targets
    for target in args.targets:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            print(f"Error: Invalid subnet format: {target}")
            sys.exit(1)

    # Check if nmap is available
    try:
        nm = nmap.PortScanner()
        nm.nmap_version()
    except Exception as e:
        print(f"Error: Nmap not found or not accessible: {e}")
        print("Please ensure nmap is installed and accessible.")
        sys.exit(1)

    # Initialize scanner
    scanner = VulnerabilityScanner(
        max_threads=args.threads, enable_cve_lookup=not args.no_cve
    )

    try:
        # Perform scan
        start_time = time.time()
        results = scanner.scan_subnets(args.targets)
        end_time = time.time()

        if results:
            # Display results
            if not args.quiet:
                scanner.reporter.display_results(results)

            # Export to CSV
            scanner.reporter.export_csv(results, args.output)

            # Summary
            total_hosts = len(results)
            total_open_ports = sum(len(host["ports"]) for host in results)
            hosts_with_names = sum(1 for host in results if host["hostname"])

            print(f"\nScan Summary:")
            print(f"- Total hosts scanned: {total_hosts}")
            print(f"- Hosts with hostnames: {hosts_with_names}")
            print(f"- Total open ports found: {total_open_ports}")
            print(f"- Scan duration: {end_time - start_time:.2f} seconds")
        else:
            print("No results to display.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
