#!/usr/bin/env python3

import socket
import ssl
import json
import csv
import argparse
import ipaddress
import re
import subprocess
import platform
import threading
from datetime import datetime
from collections import defaultdict
import time
import sys # For checking if output is a TTY

# Rich library imports
try:
    from rich.console import Console
    from rich.table import Table, Column
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.live import Live
    from rich.style import Style
    from rich.box import ROUNDED, HEAVY_HEAD
    from rich.padding import Padding
    from rich.markup import escape
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Basic fallback if Rich is not installed
    class ConsoleFallback:
        def __init__(self, record=False, force_terminal=None): # Add force_terminal to match Rich Console
            pass
        def print(self, *args, **kwargs):
            plain_text = []
            for arg in args:
                if hasattr(arg, 'plain') and callable(arg.plain): # For Text objects if used in fallback
                    plain_text.append(arg.plain)
                elif isinstance(arg, (PanelFallback, TableFallback)): # If we pass our fallback objects
                    arg.display() # Call their display method
                    continue
                else:
                    plain_text.append(str(arg))
            if plain_text: # Only print if there's something to print
                 print(" ".join(plain_text))
        def rule(self, title=""):
            print(f"\n--- {title} ---" if title else "\n" + "-" * 70)

    class PanelFallback:
        def __init__(self, content, title="", subtitle="", **kwargs):
            self.content = content
            self.title = title
            self.subtitle = subtitle
        def display(self):
            _title = f"{self.title}" if self.title else ""
            _subtitle = f" ({self.subtitle})" if self.subtitle else ""
            print(f"\n--- {_title}{_subtitle} ---")
            if isinstance(self.content, str):
                print(self.content)
            elif hasattr(self.content, 'display'): # For nested TableFallback
                self.content.display()


    class TableFallback:
        def __init__(self, title="", **kwargs):
            self.title = title
            self.columns = []
            self.rows = []
            self.show_header = True
            self.box = None # To match Rich Table attributes

        def add_column(self, header, **kwargs):
            self.columns.append(header)

        def add_row(self, *args):
            self.rows.append(args)
        
        def display(self):
            if self.title:
                print(f"\n=== {self.title} ===")
            if self.show_header and self.columns:
                print(" | ".join(str(c) for c in self.columns))
                print("-" * (sum(len(str(c)) for c in self.columns) + (len(self.columns) -1) * 3))
            for row in self.rows:
                print(" | ".join(str(item) for item in row))


    console_instance = ConsoleFallback() # Use a consistent name
    Panel = PanelFallback # type: ignore
    Table = TableFallback # type: ignore
    Text = str # Fallback Text to simple string
    Padding = lambda text, pad: text # No padding for fallback

# --- Global console instance ---
# Determine if we should force Rich to believe it's a terminal (e.g., for consistent output in CI/pipes if desired)
# By default, Rich auto-detects. This setup allows overriding if needed.
force_rich_terminal = None # Set to True/False to override, None for auto-detection
if RICH_AVAILABLE:
    console = Console(record=False, force_terminal=force_rich_terminal)
else:
    console = console_instance # Use the fallback

# --- Configuration ---
DEFAULT_TCP_TIMEOUT = 1.0
DEFAULT_UDP_TIMEOUT = 2.0
MAX_BANNER_SIZE = 1024
COMMON_TCP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP (Submission)",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt"
}
COMMON_UDP_PORTS = {
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP", 123: "NTP",
    161: "SNMP", 162: "SNMP Trap", 500: "ISAKMP (IKE)", 514: "Syslog",
    1900: "SSDP", 4500: "IPsec NAT Traversal", 5353: "MDNS"
}
INSECURE_SSL_VERSIONS = {
    "SSLv2": ssl.PROTOCOL_SSLv23,
    "SSLv3": ssl.PROTOCOL_SSLv23,
    "TLSv1.0": ssl.PROTOCOL_TLSv1,
    "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
}
WEAK_CIPHERS = [
    ("NULL", "Null encryption"), ("EXPORT", "Export-grade ciphers"),
    ("LOW", "Low-strength ciphers (<56-bit)"), ("DES", "Single DES"),
    ("3DES", "Triple DES (weak by modern standards)"), ("RC4", "RC4 stream cipher"),
    ("MD5", "Ciphers using MD5 for auth"), ("SEED", "SEED block cipher"),
    ("IDEA", "IDEA block cipher"), ("PSK", "Pre-Shared Key (if not strong)"),
    ("ADH", "Anonymous Diffie-Hellman"), ("AECDH", "Anonymous ECDH"),
]

# --- Helper Functions ---
def rich_print(*args, **kwargs):
    """Wrapper to use Rich console or fallback print."""
    if use_rich_output: # Global flag based on RICH_AVAILABLE and --no-rich
        console.print(*args, **kwargs)
    else:
        # Convert Rich objects to strings for fallback_console
        processed_args = []
        for arg in args:
            if RICH_AVAILABLE: # Check again in case use_rich_output was false but Rich is there
                if isinstance(arg, (Panel, Table, Text, Padding)): # Add other Rich types as needed
                    # For Rich objects, we might want to capture their string representation
                    # This is tricky as Rich objects are complex.
                    # Simplest is to let the fallback Console handle its own PanelFallback etc.
                    if isinstance(arg, Panel) and not isinstance(arg, PanelFallback):
                         processed_args.append(PanelFallback(str(arg.renderable), title=str(arg.title) if arg.title else ""))
                    elif isinstance(arg, Table) and not isinstance(arg, TableFallback):
                        # This conversion is too complex for a simple fallback.
                        # The fallback TableFallback should be used directly.
                        processed_args.append(f"[Rich Table: {arg.title or 'Untitled'}]")
                    elif isinstance(arg, Text):
                        processed_args.append(arg.plain)
                    else:
                         processed_args.append(str(arg)) # Fallback for other Rich objects
                    continue
            processed_args.append(str(arg))
        console_instance.print(*processed_args)


def resolve_host(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        rich_print(f"[bold red]Error:[/bold red] Could not resolve hostname '{escape(hostname)}'.")
        return None

def parse_ports(port_string):
    ports = set()
    if not port_string: return []
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            try:
                start, end = int(start_str), int(end_str)
                if start <= end: ports.update(range(start, end + 1))
                else: rich_print(f"[orange3]Warning:[/orange3] Invalid port range '{escape(part)}' ignored (start > end).")
            except ValueError: rich_print(f"[orange3]Warning:[/orange3] Invalid port range value in '{escape(part)}' ignored.")
        else:
            try: ports.add(int(part))
            except ValueError: rich_print(f"[orange3]Warning:[/orange3] Invalid port value '{escape(part)}' ignored.")
    return sorted(list(ports))

# --- Scanning Functions ---
def tcp_scan_port(target_ip, port, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = None
            try:
                if port == 80: sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nConnection: close\r\n\r\n")
                elif port == 443: pass
                elif port == 21: sock.settimeout(1.0)
                
                if port != 443:
                    current_timeout = sock.gettimeout(); sock.settimeout(min(0.5, current_timeout))
                    banner_bytes = sock.recv(MAX_BANNER_SIZE)
                    banner = banner_bytes.decode(errors='ignore').strip()
                    sock.settimeout(current_timeout)
            except socket.timeout: banner = "N/A (Timeout receiving banner)"
            except Exception as e: banner = f"N/A (Error: {escape(str(e))[:30]})"
            return "Open", banner
        else: return "Closed", None
    except socket.timeout: return "Filtered (Timeout)", None
    except socket.error as e: return f"Error ({escape(e.strerror)})", None
    finally:
        if sock: sock.close()

def udp_scan_port(target_ip, port, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (target_ip, port))
        try:
            sock.recvfrom(1024); return "Open"
        except socket.timeout: return "Open|Filtered"
        except ConnectionRefusedError: return "Closed"
        except socket.error as e:
            if hasattr(e, 'winerror') and e.winerror == 10054: return "Closed"
            if hasattr(e, 'errno') and e.errno in [111, 104]: return "Closed"
            return f"Error ({escape(str(e))})"
    except socket.error as e: return f"Error creating socket ({escape(str(e))})"
    finally:
        if sock: sock.close()

def get_service_name(port, protocol, banner=None):
    service_map = COMMON_TCP_PORTS if protocol.lower() == 'tcp' else COMMON_UDP_PORTS
    service = service_map.get(port, "Unknown")
    if banner:
        banner_lower = banner.lower()
        if any(kw in banner_lower for kw in ["http", "apache", "nginx", "iis", "server:"]): service = "HTTP" if port != 443 and "https" not in banner_lower else "HTTPS"
        elif "ftp" in banner_lower: service = "FTP"
        elif "ssh" in banner_lower: service = "SSH"
        elif "smtp" in banner_lower: service = "SMTP"
    return service

def check_ssl_tls(hostname, port, results_dict):
    ssl_timeout = max(DEFAULT_TCP_TIMEOUT, 2.0)
    ssl_info = {"enabled": False, "certificate": None, "insecure_protocols_supported": [],
                "weak_ciphers_supported_by_server": [], "negotiated_cipher_details": None,
                "negotiated_cipher_is_weak": False, "error": None}
    try:
        context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=ssl_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_info["enabled"] = True; cert = ssock.getpeercert()
                if cert:
                    ssl_info["certificate"] = {k: (dict(x[0] for x in cert[k]) if k in ["subject", "issuer"] else cert[k]) for k in ["subject", "issuer", "version", "serialNumber", "notBefore", "notAfter"]}
                    try:
                        not_after_str = cert["notAfter"]
                        if not not_after_str.endswith("Z"): not_after_str = not_after_str.replace(" GMT","Z") if " GMT" in not_after_str else not_after_str
                        parsed_date = None
                        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S%z"):
                            try:
                                parsed_date = datetime.strptime(not_after_str, fmt)
                                if parsed_date.tzinfo is None: parsed_date = parsed_date.replace(tzinfo=datetime.timezone.utc)
                                break
                            except ValueError: continue
                        ssl_info["certificate"]["expired"] = parsed_date < datetime.now(datetime.timezone.utc) if parsed_date else "Error parsing date"
                    except Exception as e_date: ssl_info["certificate"]["expired"] = f"Error parsing date ({escape(str(e_date))})"
                
                nc = ssock.cipher()
                if nc:
                    ssl_info["negotiated_cipher_details"] = {"name": nc[0], "protocol_version": nc[1], "secret_bits": nc[2]}
                    for pattern, desc in WEAK_CIPHERS:
                        if pattern.lower() in nc[0].lower():
                            ssl_info["negotiated_cipher_is_weak"] = True
                            ssl_info["weak_ciphers_supported_by_server"].append(f"{nc[0]} (Negotiated - {escape(desc)})")
                            break
    except ssl.SSLError as e: ssl_info["error"] = f"SSL Error: {escape(str(e))}"
    except socket.timeout: ssl_info["error"] = "Timeout during SSL/TLS handshake."
    except ConnectionRefusedError: ssl_info["error"] = "Connection refused for SSL/TLS."
    except Exception as e: ssl_info["error"] = f"Generic SSL setup error: {escape(str(e))}"

    if not ssl_info["enabled"] and ssl_info["error"]: results_dict["ssl_tls"] = ssl_info; return

    for proto_name, proto_val in INSECURE_SSL_VERSIONS.items():
        test_context = None
        try:
            if proto_name == "SSLv2": test_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23); test_context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            elif proto_name == "SSLv3": test_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23); test_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            else: test_context = ssl.SSLContext(proto_val)
            if not test_context: continue
            test_context.check_hostname = False; test_context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=ssl_timeout) as tsock:
                with test_context.wrap_socket(tsock, server_hostname=hostname) as tssock:
                    ssl_info["insecure_protocols_supported"].append(f"{proto_name} (Server accepted: {tssock.version()})")
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, ValueError): pass
        except Exception: pass
    results_dict["ssl_tls"] = ssl_info

def get_os_guess_ttl(target_ip):
    try:
        sys_platform = platform.system().lower()
        if sys_platform == 'windows': command = ['ping', '-n', '1', '-w', '1000', target_ip]
        elif sys_platform == 'linux': command = ['ping', '-c', '1', '-W', '1', target_ip]
        elif sys_platform == 'darwin': command = ['ping', '-c', '1', '-t', '1', target_ip]
        else: command = ['ping', '-c', '1', '-W', '1', target_ip]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(timeout=2.5)
        output = stdout.decode(errors='ignore').lower()
        ttl_match = re.search(r"ttl=(\d+)", output)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl > 128 and ttl <= 255 : return f"Solaris/AIX/Cisco (TTL: {ttl}, Original ~255)"
            elif ttl > 64 and ttl <= 128: return f"Windows (TTL: {ttl}, Original ~128)"
            elif ttl > 32 and ttl <= 64 : return f"Linux/Unix (TTL: {ttl}, Original ~64)"
            else: return f"Linux/Unix (TTL: {ttl}, Original <=32 or many hops)"
        error_output = stderr.decode(errors='ignore').lower().strip()
        if "host unreachable" in error_output: return "Unknown (Host Unreachable)"
        if "request timed out" in output or "timed out" in error_output : return "Unknown (Ping Request Timed Out)"
        return f"Unknown (Ping failed: {escape(error_output[:40])})"
    except subprocess.TimeoutExpired: return "Unknown (Ping command timed out)"
    except FileNotFoundError: return "Unknown (Ping command not found)"
    except Exception as e: return f"Unknown (Ping error: {escape(str(e)[:40])})"

# --- Reporting Functions ---
def generate_json_report(data, filename):
    try:
        with open(filename, 'w') as f: json.dump(data, f, indent=4, default=str)
        rich_print(f"[green]JSON report saved to[/green] [cyan]{escape(filename)}[/cyan]")
    except IOError as e: rich_print(f"[red]Error saving JSON report to {escape(filename)}:[/red] {escape(str(e))}")

def generate_csv_report(data, filename):
    if not data.get("ports"): rich_print("[yellow]No port data to generate CSV report.[/yellow]"); return
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            header = ["Host", "Port", "Protocol", "Status", "Service", "Banner"]
            has_ssl = any("ssl_tls" in pi for pi in data["ports"].values() if isinstance(pi, dict))
            if has_ssl: header.extend(["SSL Enabled", "SSL Error", "Cert Subject CN", "Cert Issuer CN", "Cert Expired", "Cert NotAfter", "Insecure Protocols", "Negotiated Cipher", "Negotiated Cipher Weak"])
            writer.writerow(header)
            for pk, pi in data["ports"].items():
                if not isinstance(pi, dict): continue
                pv = str(pk).split("/")[0] if "/" in str(pk) else str(pk)
                row = [data.get("target_host", "N/A"), pv, pi.get("protocol", "N/A"), pi.get("status", "N/A"), pi.get("service", "N/A"), pi.get("banner", "N/A")]
                if has_ssl:
                    if "ssl_tls" in pi:
                        sd, ci, nc = pi["ssl_tls"], sd.get("certificate",{}), sd.get("negotiated_cipher_details",{})
                        row.extend([sd.get("enabled", False), sd.get("error", "N/A"), ci.get("subject",{}).get("commonName","N/A"), ci.get("issuer",{}).get("commonName","N/A"), ci.get("expired","N/A"), ci.get("notAfter","N/A"), ", ".join(sd.get("insecure_protocols_supported",[])), nc.get("name","N/A"), sd.get("negotiated_cipher_is_weak",False)])
                    else: row.extend(["N/A"] * 9)
                writer.writerow(row)
        rich_print(f"[green]CSV report saved to[/green] [cyan]{escape(filename)}[/cyan]")
    except IOError as e: rich_print(f"[red]Error saving CSV report to {escape(filename)}:[/red] {escape(str(e))}")
    except Exception as e_csv: rich_print(f"[red]Unexpected CSV error:[/red] {escape(str(e_csv))}")

def generate_html_report(data, filename):
    # HTML generation remains largely the same, as it's self-contained markup
    html_content = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SocketSniper Report: {escape(data.get('target_host', 'N/A'))}</title><style>body{{font-family: 'Segoe UI',sans-serif;margin:0;padding:0;background-color:#f0f2f5;color:#333;font-size:14px}}.container{{max-width:1200px;margin:20px auto;padding:20px;background-color:#fff;box-shadow:0 0 15px rgba(0,0,0,0.1);border-radius:8px}}h1,h2{{color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:10px}}h1{{font-size:24px}}h2{{font-size:20px;margin-top:25px}}table{{width:100%;border-collapse:collapse;margin-top:15px}}th,td{{border:1px solid #ddd;padding:10px 12px;text-align:left;vertical-align:top}}th{{background-color:#3498db;color:white;font-weight:600}}tr:nth-child(even){{background-color:#f9f9f9}}.status-open{{color:#27ae60;font-weight:bold}}.status-closed{{color:#c0392b}}.status-filtered,.status-openfiltered{{color:#f39c12}}.status-error{{color:#e74c3c;font-weight:bold}}.ssl-details{{margin-top:8px;padding-left:15px;border-left:3px solid #bdc3c7;font-size:0.95em}}.ssl-details p{{margin:4px 0}}.ssl-details strong{{color:#555}}.banner-pre{{background-color:#ecf0f1;padding:8px;border-radius:4px;white-space:pre-wrap;word-wrap:break-word;font-family:'Courier New',monospace;font-size:0.9em;max-height:150px;overflow-y:auto}}.warning{{color:#e67e22;font-weight:bold}}.summary-item{{margin-bottom:8px}}.summary-item strong{{color:#34495e}}</style></head><body><div class="container">
    <h1>SocketSniper Scan Report</h1><div class="summary-item"><strong>Target Host:</strong> {escape(data.get('target_host', 'N/A'))}</div><div class="summary-item"><strong>Resolved IP:</strong> {escape(data.get('resolved_ip', 'N/A'))}</div><div class="summary-item"><strong>Scan Timestamp:</strong> {escape(data.get('scan_timestamp', 'N/A'))}</div>
    <h2>OS Guess (via Ping TTL)</h2><p>{escape(data.get('os_guess', 'Not performed or failed'))}</p><h2>Port Scan Results</h2>"""
    if not data.get("ports") or not any(isinstance(p_info, dict) for p_info in data["ports"].values()): html_content += "<p>No port data available.</p>"
    else:
        html_content += """<table><thead><tr><th>Port</th><th>Protocol</th><th>Status</th><th>Service</th><th>Banner</th><th>SSL/TLS Info</th></tr></thead><tbody>"""
        sorted_ports = sorted(data["ports"].items(), key=lambda item: (isinstance(item[0], int), item[0]))
        for port_key, info in sorted_ports:
            if not isinstance(info, dict): continue
            status_class = "status-" + info.get('status','unknown').lower().replace("|","").replace(" (timeout)","filtered").replace(" (error)","error")
            html_content += f"""<tr><td>{escape(str(port_key))}</td><td>{escape(info.get('protocol','N/A'))}</td><td class="{status_class}">{escape(info.get('status','N/A'))}</td><td>{escape(info.get('service','N/A'))}</td><td><pre class="banner-pre">{escape(info.get('banner','N/A'))}</pre></td><td>"""
            if "ssl_tls" in info:
                ssl_data = info["ssl_tls"]; html_content += "<div class='ssl-details'>"
                if isinstance(ssl_data, dict):
                    if ssl_data.get("enabled"):
                        html_content+=f"<p><strong>SSL/TLS Enabled:</strong> Yes</p>"
                        if ssl_data.get("negotiated_cipher_details"): nc=ssl_data["negotiated_cipher_details"]; html_content+=f"<p><strong>Negotiated:</strong> {escape(nc.get('name','N/A'))} ({escape(nc.get('protocol_version','N/A'))})</p>"; html_content+=f"<p class='warning'><strong>Warning: Negotiated cipher potentially weak.</strong></p>" if ssl_data.get("negotiated_cipher_is_weak") else ""
                        if ssl_data.get("certificate"): cert=ssl_data["certificate"]; html_content+=f"<p><strong>Cert Subject:</strong> {escape(cert.get('subject',{}).get('commonName','N/A'))}</p><p><strong>Cert Issuer:</strong> {escape(cert.get('issuer',{}).get('commonName','N/A'))}</p><p><strong>Cert Valid:</strong> Not Before: {escape(cert.get('notBefore','N/A'))}, Not After: {escape(cert.get('notAfter','N/A'))}</p>"; html_content+=f"<p class='warning'><strong>Cert Expired: Yes</strong></p>" if cert.get('expired') is True else (f"<p><strong>Cert Expired:</strong> No</p>" if cert.get('expired') is False else f"<p><strong>Cert Expired:</strong> {escape(str(cert.get('expired','N/A')))}</p>")
                        insec_p = ssl_data.get("insecure_protocols_supported",[]); html_content+=f"<p class='warning'><strong>Insecure Protocols:</strong> {escape(', '.join(insec_p))}</p>" if insec_p else f"<p><strong>Insecure Protocols:</strong> None detected</p>"
                        weak_c = ssl_data.get("weak_ciphers_supported_by_server",[]); html_content+=f"<p class='warning'><strong>Potentially Weak Ciphers:</strong> {escape(', '.join(weak_c))}</p>" if weak_c else ""
                        if ssl_data.get("error"): html_content+=f"<p><strong>SSL Note/Error:</strong> {escape(ssl_data['error'])}</p>"
                    elif ssl_data.get("error"): html_content+=f"<p>SSL/TLS Check Error: {escape(ssl_data['error'])}</p>"
                    else: html_content+="N/A (Not SSL/TLS or check inconclusive)"
                else: html_content+="SSL data format error."
                html_content+="</div>"
            else: html_content+="N/A"
            html_content+="</td></tr>"
        html_content+="</tbody></table>"
    html_content+="</div></body></html>"
    try:
        with open(filename, 'w', encoding='utf-8') as f: f.write(html_content)
        rich_print(f"[green]HTML report saved to[/green] [cyan]{escape(filename)}[/cyan]")
    except IOError as e: rich_print(f"[red]Error saving HTML report to {escape(filename)}:[/red] {escape(str(e))}")

# --- Main ---
# Global flag to control Rich output, can be overridden by --no-rich
use_rich_output = RICH_AVAILABLE

def main():
    global use_rich_output # Allow main to modify this based on args

    parser = argparse.ArgumentParser(
        description="SocketSniper - Deep Port Scanner & Fingerprinter. Use responsibly.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target hostname or IP address.")
    parser.add_argument("-p", "--ports", help="Ports/ranges for TCP & UDP (e.g., '21-23,80,443').", default=None)
    parser.add_argument("-t", "--tcp-ports", help="Specific TCP ports/ranges.")
    parser.add_argument("-u", "--udp-ports", help="Specific UDP ports/ranges.")
    parser.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT, help=f"TCP timeout (sec, default: {DEFAULT_TCP_TIMEOUT}).")
    parser.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT, help=f"UDP timeout (sec, default: {DEFAULT_UDP_TIMEOUT}).")
    parser.add_argument("--no-os-detect", action="store_true", help="Disable OS detection.")
    parser.add_argument("--no-ssl-check", action="store_true", help="Disable SSL/TLS checks.")
    parser.add_argument("--json", metavar="FILE", help="Export to JSON file.")
    parser.add_argument("--csv", metavar="FILE", help="Export to CSV file.")
    parser.add_argument("--html", metavar="FILE", help="Export to HTML file.")
    parser.add_argument("--threads", type=int, default=10, help="TCP scan threads (default: 10, max: 50).")
    parser.add_argument("--no-rich", action="store_true", help="Disable Rich CLI output (uses plain text).")

    args = parser.parse_args()

    if args.no_rich:
        use_rich_output = False
        # Re-initialize console if --no-rich is used and Rich was available
        if RICH_AVAILABLE: # Check if Rich was initially available
            global console
            console = ConsoleFallback()


    # ASCII Art Banner for SocketSniper - now with Rich styling
    banner_text = r"""
    ███████╗ ██████╗  ██████╗██╗  ██╗███████╗████████╗███████╗███╗   ██╗██╗██████╗ ███████╗██████╗ 
    ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
    ███████╗██║   ██║██║     █████╔╝ █████╗     ██║   ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
    ╚════██║██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
    ███████║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   ███████║██║ ╚████║██║██║     ███████╗██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                    Deep Port Scanner & Fingerprinter
                    [italic]Version 1.0.0 - 2025[/italic]
                    Developed by [bold]0verWatchO5[/bold]
    """
    if use_rich_output:
        console.print(Text(banner_text, style="bold red"), justify="center")
        console.rule("[bold cyan]SocketSniper Initializing[/bold cyan]")
    else:
        print(banner_text) # Plain print for fallback
        print("--- SocketSniper Initializing ---")


    rich_print(Padding(Text("Disclaimer: Use responsibly. Only scan targets you have explicit permission to test.", style="italic yellow"), (0,1)))
    
    args.threads = max(1, min(args.threads, 50))
    target_host = args.target
    resolved_ip = resolve_host(target_host)

    if not resolved_ip: return

    scan_info_text = Text.assemble(
        ("Scanning Target: ", "bold white"), (target_host, "bold cyan"),
        (" (Resolved IP: ", "white"), (resolved_ip, "bold cyan"), (")", "white")
    )
    rich_print(Panel(scan_info_text, title="[bold]Target Information[/bold]", border_style="blue", expand=False))

    scan_results = {"tool_name": "SocketSniper", "target_host": target_host, "resolved_ip": resolved_ip,
                    "scan_timestamp": datetime.now().isoformat(), "os_guess": "Not performed", "ports": {}}

    tcp_ports_to_scan, udp_ports_to_scan = set(), set()
    if args.ports: parsed_general = parse_ports(args.ports); tcp_ports_to_scan.update(parsed_general); udp_ports_to_scan.update(parsed_general)
    if args.tcp_ports: tcp_ports_to_scan.update(parse_ports(args.tcp_ports))
    if args.udp_ports: udp_ports_to_scan.update(parse_ports(args.udp_ports))
    
    if not tcp_ports_to_scan and not udp_ports_to_scan:
        rich_print("[italic]No specific ports given, using common TCP and UDP ports.[/italic]")
        tcp_ports_to_scan.update(COMMON_TCP_PORTS.keys()); udp_ports_to_scan.update(COMMON_UDP_PORTS.keys())

    final_tcp_ports, final_udp_ports = sorted(list(tcp_ports_to_scan)), sorted(list(udp_ports_to_scan))

    if not args.no_os_detect:
        rich_print(Panel(Text("Performing OS detection (via Ping TTL)...", style="yellow"), title="[bold]OS Detection[/bold]", border_style="dim blue", expand=False))
        start_time_os = time.monotonic()
        os_guess = get_os_guess_ttl(resolved_ip)
        scan_results["os_guess"] = os_guess
        elapsed_time_os = time.monotonic() - start_time_os
        rich_print(f"  [bold]OS Guess:[/bold] {escape(os_guess)} ([italic]completed in {elapsed_time_os:.2f}s[/italic])")
    else: rich_print(Panel("[italic]OS detection skipped by user.[/italic]", title="[bold]OS Detection[/bold]", border_style="dim blue"))

    # Progress bar setup
    progress_columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), TimeElapsedColumn()] if use_rich_output else []
    
    # --- TCP Scan with Rich Progress ---
    if final_tcp_ports:
        section_title = f"TCP Scan ({len(final_tcp_ports)} ports, {args.threads} threads)"
        rich_print(Panel(f"Starting TCP scan for {len(final_tcp_ports)} port(s)...", title=f"[bold]{section_title}[/bold]", border_style="green", expand=False))
        
        tcp_results_intermediate = {} # Store results before adding to main dict to avoid thread issues with Rich updates
        results_lock = threading.Lock()

        def worker_tcp(progress, task_id):
            while True:
                port_to_scan = None
                with results_lock:
                    if not final_tcp_ports_q: break
                    port_to_scan = final_tcp_ports_q.pop(0)
                
                if port_to_scan is None: break
                
                status, banner = tcp_scan_port(resolved_ip, port_to_scan, args.tcp_timeout)
                port_key = f"{port_to_scan}/TCP"
                port_details = {"protocol": "TCP", "status": status, "banner": banner or "N/A", "service": "N/A"}

                if status == "Open":
                    port_details["service"] = get_service_name(port_to_scan, "TCP", banner)
                    if not args.no_ssl_check:
                        is_ssl = (port_to_scan in [443,465,993,995,8443] or any(s in port_details["service"].lower() for s in ["https","smtps","imaps","pop3s"]) or (banner and "starttls" in banner.lower()))
                        if is_ssl:
                            # SSL check can be slow, consider if it should update progress description
                            if use_rich_output and RICH_AVAILABLE: progress.update(task_id, description=f"TCP Scan: Port {port_to_scan} (SSL Check...)")
                            check_ssl_tls(resolved_ip, port_to_scan, port_details)
                
                with results_lock: # Protect access to intermediate results
                    tcp_results_intermediate[port_key] = port_details
                if use_rich_output and RICH_AVAILABLE: progress.update(task_id, advance=1, description=f"TCP Scan: Port {port_to_scan}")


        final_tcp_ports_q = final_tcp_ports[:] # Thread-safe queue copy
        
        if use_rich_output and RICH_AVAILABLE:
            with Progress(*progress_columns, console=console, transient=True) as progress:
                task_id = progress.add_task(f"TCP Scan ({args.threads} threads)", total=len(final_tcp_ports))
                tcp_threads = [threading.Thread(target=worker_tcp, args=(progress, task_id)) for _ in range(args.threads)]
                for thread in tcp_threads: thread.start()
                for thread in tcp_threads: thread.join()
        else: # Fallback without Rich progress
            tcp_threads = [threading.Thread(target=worker_tcp, args=(None, None)) for _ in range(args.threads)] # Pass None for progress and task_id
            for thread in tcp_threads: thread.start()
            for thread in tcp_threads: thread.join()
            rich_print(f"[+] TCP scan finished.")

        scan_results["ports"].update(tcp_results_intermediate) # Add collected results

    # --- UDP Scan with Rich Progress ---
    if final_udp_ports:
        section_title = f"UDP Scan ({len(final_udp_ports)} ports)"
        rich_print(Panel(f"Starting UDP scan for {len(final_udp_ports)} port(s)...", title=f"[bold]{section_title}[/bold]", border_style="magenta", expand=False))
        
        if use_rich_output and RICH_AVAILABLE:
            with Progress(*progress_columns, console=console, transient=True) as progress:
                task_id = progress.add_task("UDP Scan", total=len(final_udp_ports))
                for port in final_udp_ports:
                    status = udp_scan_port(resolved_ip, port, args.udp_timeout)
                    service = get_service_name(port, "UDP")
                    scan_results["ports"][f"{port}/UDP"] = {"protocol": "UDP", "status": status, "service": service}
                    progress.update(task_id, advance=1, description=f"UDP Scan: Port {port}")
        else: # Fallback without Rich progress
            for i, port in enumerate(final_udp_ports):
                status = udp_scan_port(resolved_ip, port, args.udp_timeout)
                service = get_service_name(port, "UDP")
                scan_results["ports"][f"{port}/UDP"] = {"protocol": "UDP", "status": status, "service": service}
                if (i + 1) % 10 == 0 or i + 1 == len(final_udp_ports): # Print progress occasionally
                     rich_print(f"  UDP Scan: {i+1}/{len(final_udp_ports)} ports scanned...")
            rich_print(f"[+] UDP scan finished.")


    # --- Reporting & Summary ---
    rich_print(Panel("Generating reports and final summary...", title="[bold]Reporting[/bold]", border_style="blue", expand=False))
    if args.json: generate_json_report(scan_results, args.json)
    if args.csv: generate_csv_report(scan_results, args.csv)
    if args.html: generate_html_report(scan_results, args.html)

    # Rich Table for Summary
    summary_table = Table(title=f"SocketSniper Scan Summary for [bold cyan]{escape(target_host)}[/bold cyan] ([italic]{escape(resolved_ip)}[/italic])",
                          box=HEAVY_HEAD if use_rich_output and RICH_AVAILABLE else None,
                          header_style="bold magenta" if use_rich_output and RICH_AVAILABLE else "",
                          show_lines=True if use_rich_output and RICH_AVAILABLE else False,
                          expand=True)
    if use_rich_output and RICH_AVAILABLE:
        summary_table.add_column("Port", style="dim cyan", width=12)
        summary_table.add_column("Protocol", width=8)
        summary_table.add_column("Status", width=15)
        summary_table.add_column("Service", style="yellow", width=20)
        summary_table.add_column("Banner / SSL Details", no_wrap=False) # Allow wrapping for details
    else: # Fallback table columns
        summary_table.add_column("Port")
        summary_table.add_column("Protocol")
        summary_table.add_column("Status")
        summary_table.add_column("Service")
        summary_table.add_column("Banner / SSL Details")


    open_ports_found = False
    sorted_port_items = sorted(scan_results["ports"].items(), key=lambda item: (int(str(item[0]).split('/')[0]), item[1].get("protocol", "")))

    for port_key, details in sorted_port_items:
        if not isinstance(details, dict): continue
        status = details.get("status", "")
        if "Open" in status: # Open or Open|Filtered
            open_ports_found = True
            port_str = escape(str(port_key))
            protocol_str = escape(details.get("protocol", "N/A"))
            status_str = escape(status)
            service_str = escape(details.get("service", "N/A"))
            
            # Style status
            if use_rich_output and RICH_AVAILABLE:
                if "Open" == status: status_str = Text(status, style="bold green")
                elif "Open|Filtered" == status: status_str = Text(status, style="bold yellow")
                elif "Closed" in status: status_str = Text(status, style="bold red")
                else: status_str = Text(status, style="dim")


            banner_ssl_info = Text() if use_rich_output and RICH_AVAILABLE else [] # Use Text for Rich, list of strings for fallback
            
            banner = details.get('banner', 'N/A')
            if banner != 'N/A':
                display_banner = escape(banner[:70]) + ('...' if len(banner) > 70 else '')
                if use_rich_output and RICH_AVAILABLE: banner_ssl_info.append(f"Banner: {display_banner}\n", style="italic dim")
                else: banner_ssl_info.append(f"Banner: {display_banner}")

            if "ssl_tls" in details and isinstance(details["ssl_tls"], dict) and details["ssl_tls"].get("enabled"):
                ssl = details["ssl_tls"]
                if use_rich_output and RICH_AVAILABLE:
                    banner_ssl_info.append("SSL/TLS Enabled:\n", style="bold")
                    if ssl.get("negotiated_cipher_details"): nc = ssl["negotiated_cipher_details"]; banner_ssl_info.append(f"  Cipher: {escape(nc.get('name','N/A'))} ({escape(nc.get('protocol_version','N/A'))})\n")
                    if ssl.get("negotiated_cipher_is_weak"): banner_ssl_info.append("  WARNING: Negotiated cipher is WEAK.\n", style="bold orange_red1")
                    if ssl.get("certificate") and isinstance(ssl["certificate"], dict):
                        cert = ssl["certificate"]
                        if cert.get("expired") is True: banner_ssl_info.append(f"  WARNING: Cert EXPIRED! (NotAfter: {escape(cert.get('notAfter','N/A'))})\n", style="bold red")
                        elif cert.get("expired") is False: banner_ssl_info.append(f"  Cert Valid (NotAfter: {escape(cert.get('notAfter','N/A'))})\n", style="green")
                    if ssl.get("insecure_protocols_supported"): banner_ssl_info.append(f"  WARNING: Insecure protocols: {escape(', '.join(ssl['insecure_protocols_supported']))}\n", style="orange_red1")
                    if ssl.get("error"): banner_ssl_info.append(f"  SSL Note: {escape(ssl['error'])}\n", style="dim")
                else: # Fallback SSL info
                    banner_ssl_info.append("SSL/TLS Enabled.")
                    if ssl.get("negotiated_cipher_details"): nc = ssl["negotiated_cipher_details"]; banner_ssl_info.append(f"Cipher: {nc.get('name','N/A')} ({nc.get('protocol_version','N/A')})")
                    if ssl.get("negotiated_cipher_is_weak"): banner_ssl_info.append("WARNING: Negotiated cipher WEAK.")
                    # Add more fallback SSL details if needed

            elif "ssl_tls" in details and isinstance(details["ssl_tls"], dict) and details["ssl_tls"].get("error"):
                if use_rich_output and RICH_AVAILABLE: banner_ssl_info.append(f"SSL Check Error: {escape(details['ssl_tls']['error'])}\n", style="red")
                else: banner_ssl_info.append(f"SSL Check Error: {details['ssl_tls']['error']}")

            summary_table.add_row(port_str, protocol_str, status_str, service_str, banner_ssl_info if use_rich_output and RICH_AVAILABLE else "\n".join(banner_ssl_info) )

    if use_rich_output:
        os_panel_content = Text(escape(scan_results['os_guess']), style="white")
        os_panel = Panel(os_panel_content, title="[bold]OS Guess[/bold]", border_style="blue", expand=False)
        rich_print(os_panel)
    else:
        rich_print(f"OS Guess: {scan_results['os_guess']}") # Fallback print

    if not open_ports_found:
        no_ports_text = Text("No open or open|filtered ports found among scanned ports.", style="yellow")
        if use_rich_output and RICH_AVAILABLE: summary_table.add_row(no_ports_text, span=5 if RICH_AVAILABLE else 1) # Span across columns if Rich
        else: rich_print(str(no_ports_text))


    rich_print(summary_table)
    rich_print(Panel("[bold green]Scan Complete[/bold green]", border_style="green", expand=False, text_align="center"))

if __name__ == "__main__":
    # This check ensures Rich is only fully utilized if available AND not disabled by user
    # The global `use_rich_output` is set in main() after parsing args.
    # The initial `console` object (Rich or Fallback) is determined at the top.
    main()
