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
from rich.console import Console
from rich.text import Text

# --- Configuration ---
DEFAULT_TCP_TIMEOUT = 1.0  # Default timeout for TCP connections in seconds
DEFAULT_UDP_TIMEOUT = 2.0  # Default timeout for UDP probes in seconds
MAX_BANNER_SIZE = 1024     # Max size of banner to grab
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

# List of known weak/insecure SSL/TLS protocols
INSECURE_SSL_VERSIONS = {
    "SSLv2": ssl.PROTOCOL_SSLv23, # Placeholder, actual SSLv2 often disabled at compile time
    "SSLv3": ssl.PROTOCOL_SSLv23,
    "TLSv1.0": ssl.PROTOCOL_TLSv1,
    "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
}

# List of some known weak cipher suites (OpenSSL names)
WEAK_CIPHERS = [
    ("NULL", "Null encryption"),
    ("EXPORT", "Export-grade ciphers"),
    ("LOW", "Low-strength ciphers (less than 56-bit)"),
    ("DES", "Single DES"),
    ("3DES", "Triple DES (considered weak by modern standards)"),
    ("RC4", "RC4 stream cipher"),
    ("MD5", "Ciphers using MD5 for message authentication"),
    ("SEED", "SEED block cipher (less common, potentially weaker)"),
    ("IDEA", "IDEA block cipher"),
    ("PSK", "Pre-Shared Key ciphers (if not intentionally used with strong keys)"),
    ("ADH", "Anonymous Diffie-Hellman"),
    ("AECDH", "Anonymous Elliptic Curve Diffie-Hellman"),
]


# --- Helper Functions ---

def resolve_host(hostname):
    """Resolves a hostname to an IP address."""
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{hostname}'.")
        return None

def parse_ports(port_string):
    """Parses a port string (e.g., "80,443,8000-8100") into a list of integers."""
    ports = set()
    if not port_string:
        return []
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            try:
                start = int(start_str)
                end = int(end_str)
                if start <= end:
                    ports.update(range(start, end + 1))
                else:
                    print(f"Warning: Invalid port range '{part}' ignored (start > end).")
            except ValueError:
                print(f"Warning: Invalid port range value in '{part}' ignored.")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"Warning: Invalid port value '{part}' ignored.")
    return sorted(list(ports))

# --- Scanning Functions ---

def tcp_scan_port(target_ip, port, timeout):
    """
    Scans a single TCP port.
    Returns: (status, banner)
    status: "Open", "Closed", "Filtered" (or error string)
    banner: Service banner if port is open, else None
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = None
            try:
                if port == 80: # HTTP
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nConnection: close\r\n\r\n")
                elif port == 443: # HTTPS - banner grabbing handled by SSL check
                    pass # Banner will be "N/A" here, SSL check will provide protocol details
                elif port == 21: # FTP
                    sock.settimeout(1.0) # FTP servers usually send banner immediately
                # For other services, just try to receive immediately
                if port != 443:
                    # Short timeout for banner recv, as some services send it immediately
                    # and others might wait for client input.
                    current_timeout = sock.gettimeout()
                    sock.settimeout(min(0.5, current_timeout)) # Don't exceed original timeout
                    banner_bytes = sock.recv(MAX_BANNER_SIZE)
                    banner = banner_bytes.decode(errors='ignore').strip()
                    sock.settimeout(current_timeout) # Restore original timeout
            except socket.timeout:
                banner = "N/A (Timeout receiving banner)"
            except Exception as e:
                banner = f"N/A (Error receiving banner: {e})"
            return "Open", banner
        else:
            return "Closed", None
    except socket.timeout:
        return "Filtered (Timeout)", None
    except socket.error as e:
        return f"Error ({e.strerror})", None
    finally:
        if sock:
            sock.close()

def udp_scan_port(target_ip, port, timeout):
    """
    Scans a single UDP port. This is less reliable than TCP scanning.
    Returns: status ("Open|Filtered", "Closed", or error string)
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (target_ip, port)) # Send empty UDP packet
        try:
            # For some common UDP services, a specific probe might elicit a better response.
            # Example: DNS query for port 53
            # if port == 53:
            #    sock.sendto(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01', (target_ip, port))
            
            sock.recvfrom(1024) # buffer size
            return "Open"
        except socket.timeout:
            return "Open|Filtered" # No response, could be open or filtered
        except ConnectionRefusedError:
            return "Closed" # ICMP Port Unreachable received
        except socket.error as e:
            if hasattr(e, 'winerror') and e.winerror == 10054: # WSAECONNRESET (Windows)
                return "Closed"
            if hasattr(e, 'errno') and e.errno in [111, 104]: # Connection refused / reset (Linux)
                 return "Closed"
            return f"Error ({str(e)})"

    except socket.error as e:
        return f"Error creating socket ({str(e)})"
    finally:
        if sock:
            sock.close()

def get_service_name(port, protocol, banner=None):
    """Guess service name based on port and protocol, refine with banner if available."""
    service_map = COMMON_TCP_PORTS if protocol.lower() == 'tcp' else COMMON_UDP_PORTS
    service = service_map.get(port, "Unknown")

    if banner: # Try to refine based on banner content
        banner_lower = banner.lower()
        if any(kw in banner_lower for kw in ["http", "apache", "nginx", "iis", "server:"]):
            service = "HTTP" if port != 443 and "https" not in banner_lower else "HTTPS"
        elif "ftp" in banner_lower: service = "FTP"
        elif "ssh" in banner_lower: service = "SSH"
        elif "smtp" in banner_lower: service = "SMTP"
        elif "pop3" in banner_lower: service = "POP3"
        elif "imap" in banner_lower: service = "IMAP"
        elif "telnet" in banner_lower: service = "Telnet"
        # Add more banner checks as needed
    return service


def check_ssl_tls(hostname, port, results_dict):
    """
    Performs SSL/TLS checks on a given host and port.
    Updates results_dict with SSL/TLS information.
    """
    # Use a specific timeout for SSL/TLS checks, can be longer than general TCP connect
    ssl_timeout = max(DEFAULT_TCP_TIMEOUT, 2.0) # Ensure at least 2s for SSL handshake

    ssl_info = {
        "enabled": False,
        "certificate": None,
        "insecure_protocols_supported": [],
        "weak_ciphers_supported_by_server": [], # Ciphers server might support (advanced)
        "negotiated_cipher_details": None,
        "negotiated_cipher_is_weak": False,
        "error": None
    }

    # Standard connection to get cert and negotiated cipher
    try:
        context = ssl.create_default_context()
        # Allow connection even if cert is self-signed for info gathering
        context.check_hostname = False 
        context.verify_mode = ssl.CERT_NONE 

        with socket.create_connection((hostname, port), timeout=ssl_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_info["enabled"] = True
                cert = ssock.getpeercert()
                if cert:
                    ssl_info["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serialNumber": cert.get("serialNumber"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                    }
                    try:
                        # Ensure Z is appended if missing for UTC, strptime can be picky
                        not_after_str = cert["notAfter"]
                        if not not_after_str.endswith("Z"): # some certs might not have Z
                             if " GMT" in not_after_str: # Handle "GMT"
                                 not_after_str = not_after_str.replace(" GMT","Z")
                             # else assume UTC if no timezone info and no Z
                        
                        # Try multiple formats for date parsing
                        parsed_date = None
                        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S%z"):
                            try:
                                parsed_date = datetime.strptime(not_after_str, fmt)
                                if parsed_date.tzinfo is None: # If naive, assume UTC
                                     parsed_date = parsed_date.replace(tzinfo=datetime.timezone.utc)
                                break
                            except ValueError:
                                continue
                        
                        if parsed_date:
                            if parsed_date < datetime.now(datetime.timezone.utc):
                                ssl_info["certificate"]["expired"] = True
                            else:
                                ssl_info["certificate"]["expired"] = False
                        else:
                             ssl_info["certificate"]["expired"] = "Error parsing date"

                    except Exception as e_date:
                        ssl_info["certificate"]["expired"] = f"Error parsing date ({e_date})"
                
                negotiated_cipher = ssock.cipher()
                if negotiated_cipher:
                    ssl_info["negotiated_cipher_details"] = {
                        "name": negotiated_cipher[0],
                        "protocol_version": negotiated_cipher[1],
                        "secret_bits": negotiated_cipher[2]
                    }
                    for weak_pattern, desc in WEAK_CIPHERS:
                        if weak_pattern.lower() in negotiated_cipher[0].lower():
                            ssl_info["negotiated_cipher_is_weak"] = True
                            ssl_info["weak_ciphers_supported_by_server"].append(f"{negotiated_cipher[0]} (Negotiated - {desc})") # Mark as negotiated
                            break
    except ssl.SSLError as e:
        ssl_info["error"] = f"SSL Error: {e}"
    except socket.timeout:
        ssl_info["error"] = "Timeout during SSL/TLS handshake."
    except ConnectionRefusedError:
        ssl_info["error"] = "Connection refused for SSL/TLS."
    except Exception as e:
        ssl_info["error"] = f"Generic error during SSL/TLS setup: {e}"

    if not ssl_info["enabled"] and ssl_info["error"]: # If initial connection failed, don't try protocols
        results_dict["ssl_tls"] = ssl_info
        return

    # Test for insecure protocols
    for proto_name, proto_val_or_const in INSECURE_SSL_VERSIONS.items():
        # For PROTOCOL_SSLv23, we need to set options to limit to SSLv2 or SSLv3
        # For specific versions like PROTOCOL_TLSv1, it's more direct.
        test_context = None
        try:
            if proto_name == "SSLv2": # SSLv2 is tricky, often disabled. PROTOCOL_SSLv2 is usually not available.
                                     # Try to force via options on SSLv23 if possible.
                test_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                test_context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            elif proto_name == "SSLv3":
                test_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) # Start with broader context
                test_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
                # Or try specific if available:
                # test_context = ssl.SSLContext(ssl.PROTOCOL_SSLv3) # This might fail if SSLv3 support is compiled out
            else: # For TLSv1.0, TLSv1.1
                 test_context = ssl.SSLContext(proto_val_or_const)

            if not test_context: continue

            test_context.check_hostname = False
            test_context.verify_mode = ssl.CERT_NONE
            # Optionally, try to set only very basic ciphers to increase chance of protocol acceptance if ciphers are an issue
            # test_context.set_ciphers('DEFAULT') # or even 'ALL:@SECLEVEL=0' if desperate, but be careful

            with socket.create_connection((hostname, port), timeout=ssl_timeout) as test_sock:
                with test_context.wrap_socket(test_sock, server_hostname=hostname) as test_ssock:
                    # If connection succeeds, the server supports this protocol
                    ssl_info["insecure_protocols_supported"].append(f"{proto_name} (Server accepted: {test_ssock.version()})")
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, ValueError) as e_proto:
            # ValueError can happen if protocol constant is bad or options are conflicting
            # print(f"Note: Could not test {proto_name} for {hostname}:{port} - {type(e_proto).__name__}: {e_proto}")
            pass # Expected if server doesn't support it, or other SSL issue like no common ciphers
        except Exception as e_generic_proto:
            # print(f"Note: Generic error testing {proto_name} for {hostname}:{port} - {e_generic_proto}")
            pass

    results_dict["ssl_tls"] = ssl_info


def get_os_guess_ttl(target_ip):
    """
    Guesses OS based on TTL value from a ping response.
    This is a heuristic and can be unreliable.
    Returns: OS guess string or "Unknown"
    """
    try:
        # Determine ping parameters based on OS
        system = platform.system().lower()
        if system == 'windows':
            command = ['ping', '-n', '1', '-w', '1000', target_ip] # 1 packet, 1000ms timeout
        elif system == 'linux':
            command = ['ping', '-c', '1', '-W', '1', target_ip]    # 1 packet, 1s timeout
        elif system == 'darwin': # macOS
            command = ['ping', '-c', '1', '-t', '1', target_ip]    # 1 packet, 1s timeout
        else: # Other OS (e.g. BSD) might use -c and -t or -W. Defaulting to Linux-like.
            command = ['ping', '-c', '1', '-W', '1', target_ip]

        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(timeout=2.5) # Process timeout slightly longer than ping timeout
        
        output = stdout.decode(errors='ignore').lower()
        
        ttl_match = re.search(r"ttl=(\d+)", output)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            # Common TTL starting points (these can vary due to hops)
            if ttl > 128 and ttl <= 255 : return f"Solaris/AIX/Cisco (TTL: {ttl}, Original ~255)"
            elif ttl > 64 and ttl <= 128: return f"Windows (TTL: {ttl}, Original ~128)"
            elif ttl > 32 and ttl <= 64 : return f"Linux/Unix (TTL: {ttl}, Original ~64)"
            elif ttl <= 32             : return f"Linux/Unix (TTL: {ttl}, Original ~32 or many hops)"
            else: return f"Unknown (TTL: {ttl})"
        else:
            # Fallback for different ping output formats if regex fails
            if "ttl=" in output:
                return "OS (TTL found, specific value parsing failed)"
            if proc.returncode == 0: # Ping succeeded but no TTL? Unlikely but possible.
                return "Unknown (Ping success, but no TTL in output)"
            else: # Ping failed
                error_output = stderr.decode(errors='ignore').lower().strip()
                if "host unreachable" in error_output: return "Unknown (Host Unreachable)"
                if "request timed out" in output: return "Unknown (Ping Request Timed Out)" # Some pings output timeout to stdout
                return f"Unknown (Ping failed: {error_output[:50]})"


    except subprocess.TimeoutExpired:
        return "Unknown (Ping command timed out)"
    except FileNotFoundError:
        return "Unknown (Ping command not found. Is it in PATH?)"
    except Exception as e:
        return f"Unknown (Ping error: {str(e)[:50]})"


# --- Reporting Functions ---

def generate_json_report(data, filename):
    """Generates a JSON report."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4, default=str) # default=str for datetime
        print(f"JSON report saved to {filename}")
    except IOError as e:
        print(f"Error saving JSON report to {filename}: {e}")

def generate_csv_report(data, filename):
    """Generates a CSV report."""
    if not data.get("ports"):
        print("No port data to generate CSV report.")
        return
    
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            # Define header, including SSL fields conditionally
            header = ["Host", "Port", "Protocol", "Status", "Service", "Banner"]
            # Check if any port has SSL info to decide if SSL columns are needed
            has_ssl_info = any("ssl_tls" in port_info for port_info in data["ports"].values() if isinstance(port_info, dict))

            if has_ssl_info:
                header.extend([
                    "SSL Enabled", "SSL Error", 
                    "Cert Subject CN", "Cert Issuer CN", "Cert Expired", "Cert NotAfter", 
                    "Insecure Protocols Supported", "Negotiated Cipher", "Negotiated Cipher Weak"
                ])
            writer.writerow(header)

            for port_num_key, port_info in data["ports"].items():
                if not isinstance(port_info, dict): continue # Skip if port_info is not a dict (e.g. malformed)

                # Handle combined keys like "80/TCP" or just port numbers
                port_num_str = str(port_num_key)
                if "/" in port_num_str:
                    port_val = port_num_str.split("/")[0]
                else:
                    port_val = port_num_str

                row = [
                    data.get("target_host", "N/A"), port_val, port_info.get("protocol", "N/A"),
                    port_info.get("status", "N/A"), port_info.get("service", "N/A"),
                    port_info.get("banner", "N/A")
                ]
                if has_ssl_info:
                    if "ssl_tls" in port_info:
                        ssl_data = port_info["ssl_tls"]
                        cert_info = ssl_data.get("certificate", {})
                        negotiated_cipher = ssl_data.get("negotiated_cipher_details", {})
                        row.extend([
                            ssl_data.get("enabled", False),
                            ssl_data.get("error", "N/A"),
                            cert_info.get("subject", {}).get("commonName", "N/A"),
                            cert_info.get("issuer", {}).get("commonName", "N/A"),
                            cert_info.get("expired", "N/A"),
                            cert_info.get("notAfter", "N/A"),
                            ", ".join(ssl_data.get("insecure_protocols_supported", [])),
                            negotiated_cipher.get("name", "N/A"),
                            ssl_data.get("negotiated_cipher_is_weak", False)
                        ])
                    else:
                        row.extend(["N/A"] * 9) # Pad with N/A for SSL columns
                writer.writerow(row)
        print(f"CSV report saved to {filename}")
    except IOError as e:
        print(f"Error saving CSV report to {filename}: {e}")
    except Exception as e_csv:
        print(f"An unexpected error occurred during CSV generation: {e_csv}")


def generate_html_report(data, filename):
    """Generates an HTML report."""
    # Basic HTML structure and styling
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SocketSniper Scan Report: {data.get('target_host', 'N/A')}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f0f2f5; color: #333; font-size: 14px; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 0 15px rgba(0,0,0,0.1); border-radius: 8px; }}
            h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h1 {{ font-size: 24px; }}
            h2 {{ font-size: 20px; margin-top: 25px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px 12px; text-align: left; vertical-align: top; }}
            th {{ background-color: #3498db; color: white; font-weight: 600; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .status-open {{ color: #27ae60; font-weight: bold; }}
            .status-closed {{ color: #c0392b; }}
            .status-filtered, .status-openfiltered {{ color: #f39c12; }}
            .status-error {{ color: #e74c3c; font-weight: bold; }}
            .ssl-details {{ margin-top: 8px; padding-left: 15px; border-left: 3px solid #bdc3c7; font-size: 0.95em; }}
            .ssl-details p {{ margin: 4px 0; }}
            .ssl-details strong {{ color: #555; }}
            .banner-pre {{ background-color: #ecf0f1; padding: 8px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; font-size: 0.9em; max-height: 150px; overflow-y: auto; }}
            .warning {{ color: #e67e22; font-weight: bold; }}
            .summary-item {{ margin-bottom: 8px; }}
            .summary-item strong {{ color: #34495e; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SocketSniper Scan Report</h1>
            <div class="summary-item"><strong>Target Host:</strong> {data.get('target_host', 'N/A')}</div>
            <div class="summary-item"><strong>Resolved IP:</strong> {data.get('resolved_ip', 'N/A')}</div>
            <div class="summary-item"><strong>Scan Timestamp:</strong> {data.get('scan_timestamp', 'N/A')}</div>
            
            <h2>OS Guess (via Ping TTL)</h2>
            <p>{data.get('os_guess', 'Not performed or failed')}</p>

            <h2>Port Scan Results</h2>
    """

    if not data.get("ports") or not any(isinstance(p_info, dict) for p_info in data["ports"].values()):
        html_content += "<p>No port data available or no ports were successfully scanned.</p>"
    else:
        html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Banner</th>
                        <th>SSL/TLS Information</th>
                    </tr>
                </thead>
                <tbody>
        """
        # Sort ports: numeric first, then string keys (like "80/UDP")
        sorted_ports = sorted(data["ports"].items(), key=lambda item: (isinstance(item[0], int), item[0]))

        for port_key, info in sorted_ports:
            if not isinstance(info, dict): continue # Ensure info is a dictionary

            status_class = "status-" + info.get('status', 'unknown').lower().replace("|", "").replace(" (timeout)", "filtered").replace(" (error)", "error")
            
            port_display = str(port_key) # Default display for port key

            html_content += f"""
                <tr>
                    <td>{port_display}</td>
                    <td>{info.get('protocol', 'N/A')}</td>
                    <td class="{status_class}">{info.get('status', 'N/A')}</td>
                    <td>{info.get('service', 'N/A')}</td>
                    <td><pre class="banner-pre">{info.get('banner', 'N/A')}</pre></td>
                    <td>
            """
            if "ssl_tls" in info:
                ssl_data = info["ssl_tls"]
                if isinstance(ssl_data, dict): # Ensure ssl_data is a dictionary
                    html_content += "<div class='ssl-details'>"
                    if ssl_data.get("enabled"):
                        html_content += f"<p><strong>SSL/TLS Enabled:</strong> Yes</p>"
                        if ssl_data.get("negotiated_cipher_details"):
                            nc = ssl_data["negotiated_cipher_details"]
                            html_content += f"<p><strong>Negotiated:</strong> {nc.get('name','N/A')} ({nc.get('protocol_version','N/A')})</p>"
                            if ssl_data.get("negotiated_cipher_is_weak"):
                                html_content += f"<p class='warning'><strong>Warning: Negotiated cipher is potentially weak.</strong></p>"
                        
                        if ssl_data.get("certificate"):
                            cert = ssl_data["certificate"]
                            if isinstance(cert, dict): # Ensure cert is a dictionary
                                html_content += f"<p><strong>Cert Subject:</strong> {cert.get('subject', {}).get('commonName', 'N/A')}</p>"
                                html_content += f"<p><strong>Cert Issuer:</strong> {cert.get('issuer', {}).get('commonName', 'N/A')}</p>"
                                html_content += f"<p><strong>Cert Valid:</strong> Not Before: {cert.get('notBefore', 'N/A')}, Not After: {cert.get('notAfter', 'N/A')}</p>"
                                if cert.get('expired') is True:
                                    html_content += f"<p class='warning'><strong>Cert Expired: Yes</strong></p>"
                                elif cert.get('expired') is False:
                                    html_content += f"<p><strong>Cert Expired:</strong> No</p>"
                                else:
                                     html_content += f"<p><strong>Cert Expired:</strong> {cert.get('expired', 'N/A')}</p>"

                        insec_protos = ssl_data.get("insecure_protocols_supported", [])
                        if insec_protos:
                            html_content += f"<p class='warning'><strong>Insecure Protocols Supported:</strong> {', '.join(insec_protos)}</p>"
                        else:
                            html_content += f"<p><strong>Insecure Protocols Supported:</strong> None detected</p>"
                        
                        weak_ciphers_list = ssl_data.get("weak_ciphers_supported_by_server", [])
                        if weak_ciphers_list:
                             html_content += f"<p class='warning'><strong>Potentially Weak Ciphers (Server List/Negotiated):</strong> {', '.join(weak_ciphers_list)}</p>"

                        if ssl_data.get("error"):
                             html_content += f"<p><strong>SSL Note/Error:</strong> {ssl_data['error']}</p>"
                    elif ssl_data.get("error"):
                         html_content += f"<p>SSL/TLS Check Error: {ssl_data['error']}</p>"
                    else:
                        html_content += "N/A (Not an SSL/TLS service or check inconclusive)"
                    html_content += "</div>"
                else:
                    html_content += "SSL data format error."
            else:
                html_content += "N/A"
            html_content += "</td></tr>"
        html_content += "</tbody></table>"

    html_content += """
        </div>
    </body>
    </html>
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report saved to {filename}")
    except IOError as e:
        print(f"Error saving HTML report to {filename}: {e}")


# --- Main ---
def main():
    # Setup Rich Console
    console = Console()

    # ASCII Art Banner for SocketSniper (Red)
    banner = r"""
    ███████╗ ██████╗  ██████╗██╗  ██╗███████╗████████╗███████╗███╗   ██╗██╗██████╗ ███████╗██████╗ 
    ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
    ███████╗██║   ██║██║     █████╔╝ █████╗     ██║   ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
    ╚════██║██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
    ███████║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   ███████║██║ ╚████║██║██║     ███████╗██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                        Deep Port Scanner & Fingerprinter
                    Use responsibly and only on systems you have explicit permission to scan.
                    Developed by: 0verWatchO5
    """
    console.print(Text(banner, style="bold red"))

    parser = argparse.ArgumentParser(
        description="SocketSniper - Deep Port Scanner & Fingerprinter. Use responsibly and only on systems you have explicit permission to scan.",
        formatter_class=argparse.RawTextHelpFormatter # To keep banner formatting in help
    )
    parser.add_argument("target", help="Target hostname or IP address.")
    parser.add_argument("-p", "--ports", help="Comma-separated ports/ranges to scan for both TCP and UDP (e.g., '21-23,80,443,1000-1005'). Overrides common ports.", default=None)
    parser.add_argument("-t", "--tcp-ports", help="Specific TCP ports/ranges to scan (e.g., '22,80,443'). Appends to -p if both used.")
    parser.add_argument("-u", "--udp-ports", help="Specific UDP ports/ranges to scan (e.g., '53,161'). Appends to -p if both used.")
    parser.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT, help=f"Timeout for TCP connections in seconds (default: {DEFAULT_TCP_TIMEOUT}).")
    parser.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT, help=f"Timeout for UDP probes in seconds (default: {DEFAULT_UDP_TIMEOUT}).")
    parser.add_argument("--no-os-detect", action="store_true", help="Disable OS detection via ping.")
    parser.add_argument("--no-ssl-check", action="store_true", help="Disable SSL/TLS checks for identified services.")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file.")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV file.")
    parser.add_argument("--html", metavar="FILE", help="Export results to HTML file.")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for TCP scanning (default: 10). Max 50 for safety.")


    args = parser.parse_args()

    # Cap threads for safety/stability
    args.threads = max(1, min(args.threads, 50))


    print("Disclaimer: Use responsibly. Only scan targets you have explicit permission to test.")
    print("-" * 70) # Adjusted separator length

    target_host = args.target
    resolved_ip = resolve_host(target_host)

    if not resolved_ip:
        return

    print(f"Scanning Target: {target_host} (Resolved IP: {resolved_ip})")

    scan_results = {
        "tool_name": "SocketSniper",
        "target_host": target_host,
        "resolved_ip": resolved_ip,
        "scan_timestamp": datetime.now().isoformat(),
        "os_guess": "Not performed",
        "ports": {} # Keyed by "port/protocol" e.g. "80/TCP"
    }

    # Determine ports to scan
    tcp_ports_to_scan = set()
    udp_ports_to_scan = set()

    if args.ports: # General ports for both TCP and UDP
        parsed_general_ports = parse_ports(args.ports)
        tcp_ports_to_scan.update(parsed_general_ports)
        udp_ports_to_scan.update(parsed_general_ports)
    
    if args.tcp_ports: # Specific TCP ports
        tcp_ports_to_scan.update(parse_ports(args.tcp_ports))
    
    if args.udp_ports: # Specific UDP ports
        udp_ports_to_scan.update(parse_ports(args.udp_ports))
    
    # If no ports specified via any flag, use common defaults
    if not tcp_ports_to_scan and not udp_ports_to_scan:
        print("No specific ports given, using common TCP and UDP ports.")
        tcp_ports_to_scan.update(COMMON_TCP_PORTS.keys())
        udp_ports_to_scan.update(COMMON_UDP_PORTS.keys())
    elif not tcp_ports_to_scan and (args.ports or args.udp_ports) and not args.tcp_ports:
        # If -p or -u were used, but not -t, and tcp_ports_to_scan is still empty,
        # it means user might only want UDP from -p, or only specified UDP.
        # So, we don't add default TCP in this case.
        pass
    elif not udp_ports_to_scan and (args.ports or args.tcp_ports) and not args.udp_ports:
        # Similar logic for UDP.
        pass


    final_tcp_ports = sorted(list(tcp_ports_to_scan))
    final_udp_ports = sorted(list(udp_ports_to_scan))


    # --- OS Detection ---
    if not args.no_os_detect:
        print("\n[+] Performing OS detection (via Ping TTL)...")
        start_time_os = time.monotonic()
        os_guess = get_os_guess_ttl(resolved_ip)
        scan_results["os_guess"] = os_guess
        elapsed_time_os = time.monotonic() - start_time_os
        print(f"  OS Guess: {os_guess} (completed in {elapsed_time_os:.2f}s)")
    else:
        print("\n[*] OS detection skipped by user.")

    # --- TCP Scan ---
    if final_tcp_ports:
        print(f"\n[+] Starting TCP scan for {len(final_tcp_ports)} port(s) using {args.threads} thread(s)...")
        start_time_tcp = time.monotonic()
        
        tcp_port_q = final_tcp_ports[:] # Queue of ports to scan
        results_lock = threading.Lock() # Lock for updating shared scan_results

        def worker_tcp():
            while True:
                port_to_scan = None
                try:
                    # Get port from queue (thread-safe due to list.pop() GIL behavior for simple ops)
                    # For more complex queue management, use queue.Queue
                    with results_lock: # Though pop itself is atomic, better to lock if list is small
                        if not tcp_port_q: break
                        port_to_scan = tcp_port_q.pop(0)
                except IndexError:
                    break # No more ports
                
                if port_to_scan is None: break


                # print(f"  Scanning TCP port {port_to_scan}...") # Verbose
                status, banner = tcp_scan_port(resolved_ip, port_to_scan, args.tcp_timeout)
                
                port_key = f"{port_to_scan}/TCP"
                port_details = {
                    "protocol": "TCP",
                    "status": status,
                    "banner": banner if banner else "N/A",
                    "service": "N/A"
                }

                if status == "Open":
                    port_details["service"] = get_service_name(port_to_scan, "TCP", banner)
                    print(f"  TCP Port {port_to_scan}: {status} - {port_details['service']} - Banner: {banner[:60] if banner else 'N/A'}{'...' if banner and len(banner) > 60 else ''}")

                    if not args.no_ssl_check:
                        # Heuristic for SSL/TLS services
                        is_ssl_service = (
                            port_to_scan in [443, 465, 993, 995, 8443] or
                            "https" in port_details["service"].lower() or
                            "smtps" in port_details["service"].lower() or
                            "imaps" in port_details["service"].lower() or
                            "pop3s" in port_details["service"].lower() or
                            (banner and "starttls" in banner.lower() and port_to_scan in [25, 110, 143]) # STARTTLS hint
                        )
                        if is_ssl_service:
                            print(f"    Performing SSL/TLS check for {resolved_ip}:{port_to_scan}...")
                            check_ssl_tls(resolved_ip, port_to_scan, port_details) # Updates port_details directly
                
                with results_lock:
                    scan_results["ports"][port_key] = port_details

        tcp_threads = []
        for _ in range(args.threads):
            thread = threading.Thread(target=worker_tcp)
            tcp_threads.append(thread)
            thread.start()

        for thread in tcp_threads:
            thread.join()
        
        elapsed_time_tcp = time.monotonic() - start_time_tcp
        print(f"[+] TCP scan finished in {elapsed_time_tcp:.2f}s.")


    # --- UDP Scan ---
    if final_udp_ports:
        print(f"\n[+] Starting UDP scan for {len(final_udp_ports)} port(s)... (Note: UDP scanning can be slow and less reliable)")
        start_time_udp = time.monotonic()
        # UDP scanning is often slower and done sequentially here for simplicity.
        # Can be threaded similarly to TCP if desired, but each probe already has a timeout.
        for port in final_udp_ports:
            # print(f"  Scanning UDP port {port}...") # Verbose
            status = udp_scan_port(resolved_ip, port, args.udp_timeout)
            service = get_service_name(port, "UDP")
            
            port_key = f"{port}/UDP"
            scan_results["ports"][port_key] = { # UDP results are simpler for now
                "protocol": "UDP", "status": status, "service": service
            }
            if "Open" in status: # Includes "Open" and "Open|Filtered"
                 print(f"  UDP Port {port}: {status} - {service}")
        elapsed_time_udp = time.monotonic() - start_time_udp
        print(f"[+] UDP scan finished in {elapsed_time_udp:.2f}s.")
    else:
        print("\n[*] No UDP ports selected for scanning.")


    # --- Reporting ---
    print("\n[+] Generating reports and summary...")
    if args.json:
        generate_json_report(scan_results, args.json)
    if args.csv:
        generate_csv_report(scan_results, args.csv)
    if args.html:
        generate_html_report(scan_results, args.html)

    # Always print a summary to console
    print(f"\n--- SocketSniper Scan Summary for {target_host} ({resolved_ip}) ---")
    print(f"OS Guess: {scan_results['os_guess']}")
    
    open_ports_found = False
    # Sort results for display: by port number, then by protocol (TCP before UDP if same port num)
    sorted_port_items = sorted(
        scan_results["ports"].items(),
        key=lambda item: (
            int(item[0].split('/')[0]) if '/' in item[0] else int(item[0]), # Port number
            item[1].get("protocol", "") # Protocol
        )
    )

    for port_key, details in sorted_port_items:
        if not isinstance(details, dict): continue

        if "Open" in details.get("status", ""): # Covers "Open" and "Open|Filtered"
            open_ports_found = True
            print(f"  Port {port_key}: {details['status']} - Service: {details.get('service', 'N/A')}")
            if details.get('banner') and details['banner'] != 'N/A':
                print(f"    Banner: {details['banner'][:70]}{'...' if len(details['banner']) > 70 else ''}")
            
            if "ssl_tls" in details and isinstance(details["ssl_tls"], dict) and details["ssl_tls"].get("enabled"):
                ssl_summary = details["ssl_tls"]
                print(f"    SSL/TLS: Enabled")
                if ssl_summary.get("negotiated_cipher_details"):
                    nc = ssl_summary["negotiated_cipher_details"]
                    print(f"      Cipher: {nc.get('name','N/A')} ({nc.get('protocol_version','N/A')})")
                    if ssl_summary.get("negotiated_cipher_is_weak"):
                        print("      WARNING: Negotiated cipher is potentially WEAK.")
                
                if ssl_summary.get("certificate") and isinstance(ssl_summary["certificate"], dict):
                    cert_expired = ssl_summary["certificate"].get("expired")
                    if cert_expired is True:
                        print("      WARNING: Certificate EXPIRED! (NotAfter: {ssl_summary['certificate'].get('notAfter','N/A')})")
                    elif cert_expired is False:
                         print(f"      Certificate Valid (NotAfter: {ssl_summary['certificate'].get('notAfter','N/A')})")


                insec_protos = ssl_summary.get("insecure_protocols_supported", [])
                if insec_protos:
                    print(f"      WARNING: Insecure protocols supported: {', '.join(insec_protos)}")
                
                # weak_ciphers_list = ssl_summary.get("weak_ciphers_supported_by_server", [])
                # if weak_ciphers_list and not ssl_summary.get("negotiated_cipher_is_weak"): # Avoid redundant if negotiated was already weak
                #      print(f"      INFO: Server might support other weak ciphers: {', '.join(c.split('(')[0] for c in weak_ciphers_list if '(Negotiated' not in c)}")


                if ssl_summary.get("error"):
                    print(f"      SSL Note/Error: {ssl_summary['error']}")
            elif "ssl_tls" in details and isinstance(details["ssl_tls"], dict) and details["ssl_tls"].get("error"):
                 print(f"    SSL/TLS Check Error: {details['ssl_tls']['error']}")


    if not open_ports_found:
        print("  No open or open|filtered ports found among scanned ports.")


    print("\n--- Scan Complete ---")


if __name__ == "__main__":
    main()
