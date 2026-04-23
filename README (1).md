# LINNET — Linux Network VAPT Framework

```
██╗     ██╗███╗   ██╗███╗   ██╗███████╗████████╗
██║     ██║████╗  ██║████╗  ██║██╔════╝╚══██╔══╝
██║     ██║██╔██╗ ██║██╔██╗ ██║█████╗     ██║   
██║     ██║██║╚██╗██║██║╚██╗██║██╔══╝     ██║   
███████╗██║██║ ╚████║██║ ╚████║███████╗   ██║   
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

> **Service-Based Enumeration · Controlled Brute-Force · CVE Lookup · Auto Post-Exploitation · HTML Report**

LINNET is a modular, Python-based Vulnerability Assessment & Penetration Testing framework for Linux networks. It chains enumeration, credential brute-force, CVE correlation, and automated post-exploitation into a single command — then compiles everything into a professional dark-themed HTML report.

---

## Features

- **7 Service Modules** — SSH, FTP, SMB, HTTP, DNS, SNMP, SMTP, MySQL
- **Automated Brute-Force** — Medusa (SSH/FTP/MySQL) + CrackMapExec (SMB) with structured credential logging
- **Proof-of-Access Verification** — SSH shell identity, FTP directory listings, MySQL database enumeration, SMB share listings
- **Auto SSH Post-Exploitation** — Automatically uploads and runs **linPEAS** + **LaZagne** via SFTP when SSH credentials are found; polls and fetches output in a background thread
- **Live CVE Lookup** — Queries NVD REST API v2 with CVSS scoring + searchsploit correlation
- **Professional HTML Report** — Dark-themed, sidebar-navigated report with severity dashboard, credentials table, proof-of-access blocks, CVE findings table, and command audit trail
- **Thread-Safe Parallel Execution** — Modules run concurrently using `ThreadPoolExecutor`; all state protected by `threading.Lock`
- **Non-Blocking I/O** — All subprocesses use `stdin=DEVNULL` to prevent interactive hangs

---

## Requirements

### System
- **Kali Linux 2023+** (recommended) or any Debian-based Linux
- **Python 3.8+**

### Required Tools
Install with:
```bash
sudo apt update && sudo apt install -y nmap medusa crackmapexec enum4linux nikto \
  onesixtyone snmp smbclient default-mysql-client exploitdb
pip install paramiko --break-system-packages
```

### Optional (for Post-Exploitation)
```bash
# linPEAS
sudo mkdir -p /usr/share/peass/linpeas
sudo wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \
  -O /usr/share/peass/linpeas/linpeas.sh

# LaZagne
git clone https://github.com/AlessandroZ/LaZagne.git /root/LaZagne
```

---

## Installation

```bash
git clone https://github.com/AnmolIsOffline/linnet.git
cd linnet
pip install paramiko --break-system-packages
```

### Wordlists
Place `username.txt` and `password.txt` in the project directory before running brute-force modules.

```bash
# Example: use Metasploit wordlists
cp /usr/share/wordlists/metasploit/unix_users.txt username.txt
cp /usr/share/wordlists/metasploit/unix_passwords.txt password.txt
```

---

## Usage

```
python3 linnet.py -t <TARGET_IP> [OPTIONS]
```

### Flags

| Flag | Description |
|------|-------------|
| `-t / --target` | **Target IP address (required)** |
| `--ssh` | SSH enumeration + brute-force + proof of access |
| `--ftp` | FTP enumeration + brute-force + directory listing proof |
| `--smb` | SMB enumeration (enum4linux + CrackMapExec) + share proof |
| `--http` | HTTP enumeration (Nmap scripts + Nikto parallel scan) |
| `--dns` | DNS brute-force + zone transfer attempts |
| `--snmp` | SNMP community string brute-force + targeted OID walk |
| `--smtp` | SMTP user enumeration on port 25 |
| `--mysql` | MySQL enumeration + brute-force + database proof |
| `--linuxprivesc` | Auto-upload & run **linPEAS** via SSH when creds found |
| `--lazagne` | Auto-upload & run **LaZagne** via SSH when creds found |
| `--cve auto` | Auto-detect service versions (nmap -sV) and query NVD |
| `--cve 'KEYWORD'` | Manual CVE keyword search (e.g., `'OpenSSH 8.2'`) |
| `--cve CVE-ID` | Direct CVE ID lookup (e.g., `CVE-2021-44228`) |
| `--nmap 'FLAGS'` | Run a custom Nmap scan |
| `--all` | Run **all** modules + auto-generate HTML report |
| `--report` | Generate HTML report after scan completes |

---

## Example Commands

```bash
# Full automated assessment with report
python3 linnet.py -t 192.168.1.10 --all

# SSH + FTP + auto CVE + report
python3 linnet.py -t 192.168.1.10 --ssh --ftp --cve auto --report

# Full scan with post-exploitation (linPEAS + LaZagne)
python3 linnet.py -t 192.168.1.10 --all --linuxprivesc --lazagne

# MySQL only
python3 linnet.py -t 192.168.1.10 --mysql --report

# Custom Nmap scan + HTTP enumeration
python3 linnet.py -t 192.168.1.10 --nmap '-sV -p 1-65535 -T4' --http

# Direct CVE lookup
python3 linnet.py -t 192.168.1.10 --cve CVE-2009-0542

# SMB + CVE keyword + report
python3 linnet.py -t 192.168.1.10 --smb --cve 'Samba 3.0' --report
```

---

## Report

After a scan, LINNET generates a timestamped HTML file:
```
linnet_report_<target>_<YYYYMMDD_HHMMSS>.html
```

Open it in any browser:
```bash
firefox linnet_report_172_20_10_2_20260420_105634.html
```

The report includes:
- **Overview** — Target, start/end time, report ID
- **Severity Dashboard** — Critical / High / Medium / Low CVE counts, modules run, credentials found
- **Modules Executed** — Per-module findings with run/skip status
- **Credentials Found** — Full table with service, username, password, target, timestamp
- **Proof of Access** — Service-specific proof blocks (SSH identity, FTP listings, MySQL databases, etc.)
- **Auto SSH Post-Exploitation** — linPEAS and LaZagne output file links
- **CVE Findings** — Sorted by CVSS score with severity badges, score bars, and NVD reference links
- **Commands Executed** — Complete audit trail of every command run

---

## Test Results (Metasploitable 2 — 172.20.10.2)

| Metric | Result |
|--------|--------|
| Credentials Found | 10 (4 SSH · 4 FTP · 1 SMB · 1 MySQL) |
| CVEs Identified | 16 total |
| Critical (CVSS ≥ 9.0) | 2 |
| High (CVSS 7.0–8.9) | 5 |
| Medium (CVSS 4.0–6.9) | 6 |
| Proof-of-Access Entries | 10 |
| Scan Duration | ~8 minutes |

Top CVEs identified: `CVE-2021-27171` (9.8 CRITICAL), `CVE-2020-1938` (9.8 CRITICAL), `CVE-2024-54141` (8.6 HIGH), `CVE-2009-0542` (7.5 HIGH)

---

## Project Structure

```
linnet/
├── linnet.py          # Main framework script
├── username.txt       # Brute-force username wordlist (user-provided)
├── password.txt       # Brute-force password wordlist (user-provided)
└── README.md
```

Output files generated during a scan:
```
linnet_report_<target>_<timestamp>.html    # Full VAPT report
linpeas_<target>_<user>.txt               # linPEAS output (if --linuxprivesc)
lazagne_<target>_<user>.txt               # LaZagne output (if --lazagne)
lazagne_local_<timestamp>.txt             # Local LaZagne run output
```

---

## ⚠️ Legal Disclaimer

**LINNET is intended for authorised security assessments only.**

Only use this tool against systems you own or have explicit written permission to test. Unauthorised use against systems you do not own is illegal and unethical. The author assumes no liability for misuse.

---

## Author

**Anmol Mahajan** 

---

## Acknowledgements

- [Nmap](https://nmap.org) · [Medusa](http://foofus.net) · [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) · [Nikto](https://github.com/sullo/nikto)
- [linPEAS / PEASS-ng](https://github.com/carlospolop/PEASS-ng) · [LaZagne](https://github.com/AlessandroZ/LaZagne)
- [NVD REST API](https://nvd.nist.gov/developers) · [Paramiko](https://www.paramiko.org)
