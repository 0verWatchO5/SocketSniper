# SocketSniper

![SocketSniper Banner](https://raw.githubusercontent.com/yourusername/socketsniper/main/assets/banner.png) <!-- Optional: Replace with actual image or remove -->

**SocketSniper** is a powerful deep port scanner and service fingerprinter written in Python. It performs TCP and UDP scanning, SSL/TLS analysis, banner grabbing, OS guessing (via TTL), and generates detailed reports in JSON, CSV, and HTML formats.

> ⚠️ **Disclaimer:** Use SocketSniper **only** on systems you own or have explicit permission to scan. Unauthorized use is illegal and unethical.

---

## 🚀 Features

- ✅ TCP and UDP port scanning (custom or common ports)
- ✅ Multithreaded TCP scanning for performance
- ✅ SSL/TLS fingerprinting:
  - Certificate inspection
  - Insecure protocol support detection (e.g. SSLv3, TLS 1.0)
  - Weak cipher suite detection
- ✅ Service banner grabbing and guessing
- ✅ OS fingerprinting via TTL
- ✅ Report generation:
  - HTML (with styled summary)
  - JSON (machine-readable)
  - CSV (spreadsheet-ready)

---

## 📦 Installation

```bash
git clone https://github.com/0verWatchO5/socketsniper.git
cd socketsniper
python3 socketsniper.py --help
```

## ⚙️ Usage

```bash
python3 socketsniper.py <target> [options]

#Basic Example
python3 socketsniper.py scanme.nmap.org

#Advance Example
python3 socketsniper.py 192.168.1.1 -p 22,80,443,8000-8100 --json results.json --html report.html --csv ports.csv --threads 20
```

## 🔧 Options
```bash
__________________________________________________________________________________________________
| Option              | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `-p`, `--ports`     | Ports/ranges to scan for **both TCP and UDP** (e.g., `80,443,8000-8100`) |
| `-t`, `--tcp-ports` | TCP-only ports/ranges to scan                                            |
| `-u`, `--udp-ports` | UDP-only ports/ranges to scan                                            |
| `--tcp-timeout`     | Timeout for TCP connections (default: 1s)                                |
| `--udp-timeout`     | Timeout for UDP probes (default: 2s)                                     |
| `--no-os-detect`    | Skip OS detection via TTL                                                |
| `--no-ssl-check`    | Skip SSL/TLS analysis                                                    |
| `--json FILE`       | Output scan results to JSON                                              |
| `--csv FILE`        | Output scan results to CSV                                               |
| `--html FILE`       | Output scan results to styled HTML                                       |
| `--threads N`       | Number of TCP scan threads (default: 10, max: 50)                        |
| `--help`            | Show this help message and exit                                          |
__________________________________________________________________________________________________
```

## 📄 Output Sample
```bash 
Port 443/TCP: Open - Service: HTTPS
  Banner: HTTP/1.1 200 OK ...
  SSL/TLS: Enabled
    Cipher: TLS_AES_256_GCM_SHA384 (TLSv1.3)
    Certificate Valid (NotAfter: Sep 10 12:00:00 2025 GMT)
```
## 🛡️ License
MIT License. See LICENSE file for details.

## 🙌 Acknowledgements
Inspired by nmap, sslscan, and ping analysis techniques.

Developed with ❤️ by *Mayuresh[0verWatchO5]*. Feel free to contribute! 🤝