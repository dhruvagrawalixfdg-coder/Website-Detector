#!/usr/bin/env python3
"""
Advanced Port Scanner with Risk Assessment — PhishGuard AI
Supports two modes:
  1. CLI interactive mode   : python app1.py
  2. JSON API mode (Node)   : python app1.py --target google.com --json
"""

import sys
import json
import socket
import subprocess
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Try to import nmap (optional) ────────────────────────────────────────────
try:
    import nmap as nmap_lib
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ── Risk Database ─────────────────────────────────────────────────────────────
RISK_LEVELS = {
    'CRITICAL': [23, 135, 139, 445, 3389, 5900],
    'HIGH':     [21, 1433, 3306, 5432, 6379, 27017, 9200, 11211],
    'MEDIUM':   [22, 25, 110, 143, 993, 995, 1723, 5432, 587],
    'LOW':      [53, 80, 443, 8080, 8443, 69, 123, 161, 389],
}

PORT_INFO = {
    21:    {'service': 'FTP',          'description': 'File Transfer Protocol',            'risk': 'HIGH',     'tip': 'Disable FTP; use SFTP/FTPS instead.',             'exploit': 'Anonymous login, plaintext credential theft.'},
    22:    {'service': 'SSH',          'description': 'Secure Shell',                      'risk': 'MEDIUM',   'tip': 'Use key-based auth; disable root login; use fail2ban.', 'exploit': 'Brute-force attacks on weak passwords.'},
    23:    {'service': 'Telnet',       'description': 'Telnet (unencrypted remote)',        'risk': 'CRITICAL', 'tip': 'Disable Telnet immediately; use SSH.',              'exploit': 'Plaintext credential interception via MITM.'},
    25:    {'service': 'SMTP',         'description': 'Mail Transfer Protocol',             'risk': 'MEDIUM',   'tip': 'Restrict relay; require auth; use TLS.',           'exploit': 'Open relay abuse, spam propagation.'},
    53:    {'service': 'DNS',          'description': 'Domain Name System',                'risk': 'LOW',      'tip': 'Restrict zone transfers; enable DNSSEC.',          'exploit': 'DNS amplification DDoS, cache poisoning.'},
    80:    {'service': 'HTTP',         'description': 'Web (Unencrypted)',                  'risk': 'LOW',      'tip': 'Redirect all traffic to HTTPS (443).',             'exploit': 'Plaintext data exposure, web app vulns.'},
    110:   {'service': 'POP3',         'description': 'Mail Retrieval',                    'risk': 'MEDIUM',   'tip': 'Use POP3S (995) instead.',                        'exploit': 'Credential sniffing on unencrypted sessions.'},
    135:   {'service': 'RPC',          'description': 'Windows RPC Endpoint Mapper',       'risk': 'CRITICAL', 'tip': 'Block at firewall; apply all MS patches.',         'exploit': 'DCOM exploits, malware propagation (Conficker).'},
    139:   {'service': 'NetBIOS',      'description': 'NetBIOS Session Service',            'risk': 'CRITICAL', 'tip': 'Disable NetBIOS over TCP/IP; restrict access.',    'exploit': 'SMB relay attacks, information leakage.'},
    143:   {'service': 'IMAP',         'description': 'Internet Mail Access Protocol',     'risk': 'MEDIUM',   'tip': 'Use IMAPS (993); enforce TLS.',                    'exploit': 'Credential interception, mailbox hijacking.'},
    443:   {'service': 'HTTPS',        'description': 'Web (Encrypted TLS)',                'risk': 'LOW',      'tip': 'Keep TLS certs updated; disable old SSL/TLS versions.', 'exploit': 'Heartbleed, POODLE, MITM on weak ciphers.'},
    445:   {'service': 'SMB',          'description': 'Windows File Sharing',              'risk': 'CRITICAL', 'tip': 'Disable SMBv1; apply MS17-010 patch; block at firewall.', 'exploit': 'EternalBlue (WannaCry), SMBGhost ransomware.'},
    587:   {'service': 'SMTP/TLS',     'description': 'Secure Mail Submission',            'risk': 'MEDIUM',   'tip': 'Require SASL auth; enforce TLS.',                  'exploit': 'Credential brute-force if auth is weak.'},
    993:   {'service': 'IMAPS',        'description': 'Secure IMAP (TLS)',                 'risk': 'LOW',      'tip': 'Keep certificates valid and ciphers strong.',      'exploit': 'Weak cipher exploitation.'},
    995:   {'service': 'POP3S',        'description': 'Secure POP3 (TLS)',                 'risk': 'LOW',      'tip': 'Keep certificates valid.',                         'exploit': 'Weak cipher exploitation.'},
    1433:  {'service': 'MSSQL',        'description': 'Microsoft SQL Server',              'risk': 'HIGH',     'tip': 'Bind to localhost; use strong SA passwords.',      'exploit': 'SA brute-force, xp_cmdshell RCE.'},
    3306:  {'service': 'MySQL',        'description': 'MySQL Database',                    'risk': 'HIGH',     'tip': 'Bind to 127.0.0.1; restrict remote root login.',   'exploit': 'SQL injection, unauthorized DB access.'},
    3389:  {'service': 'RDP',          'description': 'Remote Desktop Protocol',           'risk': 'CRITICAL', 'tip': 'Use RD Gateway + NLA; restrict by IP; patch.',     'exploit': 'BlueKeep (CVE-2019-0708), brute-force.'},
    5432:  {'service': 'PostgreSQL',   'description': 'PostgreSQL Database',               'risk': 'HIGH',     'tip': 'Restrict pg_hba.conf; use strong passwords.',      'exploit': 'Unauthorized DB access, privilege escalation.'},
    5900:  {'service': 'VNC',          'description': 'Virtual Network Computing',         'risk': 'CRITICAL', 'tip': 'Use SSH tunneling for VNC; strong password required.', 'exploit': 'Weak VNC passwords allow full remote control.'},
    6379:  {'service': 'Redis',        'description': 'Redis In-Memory Database',          'risk': 'HIGH',     'tip': 'Require AUTH; bind to localhost; never expose publicly.', 'exploit': 'No-auth RCE; used in cryptomining attacks.'},
    8080:  {'service': 'HTTP-Alt',     'description': 'Alternate HTTP / Proxy',            'risk': 'LOW',      'tip': 'Same precautions as port 80; disable if unused.',  'exploit': 'Web app vulnerabilities, proxy bypass.'},
    8443:  {'service': 'HTTPS-Alt',    'description': 'Alternate HTTPS',                   'risk': 'LOW',      'tip': 'Same as 443; keep certs and ciphers up to date.',  'exploit': 'Weak cipher exploitation.'},
    9200:  {'service': 'Elasticsearch','description': 'Elasticsearch REST API',            'risk': 'HIGH',     'tip': 'Enable X-Pack security; never expose publicly.',   'exploit': 'Unauthenticated data access, data deletion.'},
    11211: {'service': 'Memcached',    'description': 'Memcached Caching Service',         'risk': 'HIGH',     'tip': 'Bind to localhost; disable UDP; use firewall.',     'exploit': 'Amplification DDoS, data exposure.'},
    27017: {'service': 'MongoDB',      'description': 'MongoDB NoSQL Database',            'risk': 'HIGH',     'tip': 'Enable auth; bind to 127.0.0.1; use TLS.',         'exploit': 'No-auth data dumps; ransomware wipe attacks.'},
}

# Top common ports to scan (fast mode)
COMMON_PORTS = sorted(PORT_INFO.keys())


# ── TCP connect scanner (no external tool needed) ─────────────────────────────
def tcp_check(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return True if port is open (TCP connect)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tcp_scan(host: str, ports: list, timeout: float = 1.5, workers: int = 50) -> list:
    """Scan a list of ports in parallel using TCP connect. Returns list of dicts."""
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(tcp_check, host, p, timeout): p for p in ports}
        for future in as_completed(future_map):
            port = future_map[future]
            open_ = future.result()
            info = PORT_INFO.get(port, {})
            results.append({
                'port':        port,
                'service':     info.get('service', 'unknown'),
                'description': info.get('description', ''),
                'risk':        info.get('risk', 'UNKNOWN'),
                'tip':         info.get('tip', ''),
                'exploit':     info.get('exploit', ''),
                'open':        open_,
                'state':       'open' if open_ else 'closed',
            })
    return sorted(results, key=lambda x: x['port'])


# ── Nmap deep scanner ─────────────────────────────────────────────────────────
def nmap_scan(host: str, port_list: list) -> list:
    """
    Deep scan with nmap: version detection + safe vuln scripts.
    Falls back to TCP scan if nmap is unavailable or fails.
    """
    if not NMAP_AVAILABLE:
        return tcp_scan(host, port_list)

    nm = nmap_lib.PortScanner()
    ports_str = ','.join(str(p) for p in port_list)
    args = f'-sV -sC --open -p {ports_str} -T4'
    try:
        nm.scan(hosts=host, arguments=args, timeout=120)
    except Exception as e:
        print(f'[!] Nmap failed ({e}), falling back to TCP scan…', file=sys.stderr)
        return tcp_scan(host, port_list)

    results = []
    if host not in nm.all_hosts():
        return results

    for proto in nm[host].all_protocols():
        for port, svc in nm[host][proto].items():
            open_ = svc.get('state') == 'open'
            info = PORT_INFO.get(port, {})
            results.append({
                'port':        port,
                'service':     svc.get('name', info.get('service', 'unknown')),
                'description': info.get('description', svc.get('extrainfo', '')),
                'product':     svc.get('product', ''),
                'version':     svc.get('version', ''),
                'risk':        info.get('risk', 'UNKNOWN'),
                'tip':         info.get('tip', ''),
                'exploit':     info.get('exploit', ''),
                'open':        open_,
                'state':       svc.get('state', 'closed'),
                'scripts':     svc.get('script', {}),
            })
    return sorted(results, key=lambda x: x['port'])


# ── Resolve hostname ──────────────────────────────────────────────────────────
def resolve_host(target: str) -> str:
    """Strip protocol/path and resolve hostname → IP."""
    host = target.strip()
    for prefix in ('https://', 'http://', 'ftp://'):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split('/')[0].split(':')[0]
    return host


# ── JSON API entry (called from Node.js) ─────────────────────────────────────
def api_mode(target: str, use_nmap: bool = False):
    host = resolve_host(target)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(json.dumps({'error': f'Cannot resolve hostname: {host}'}))
        sys.exit(1)

    if use_nmap and NMAP_AVAILABLE:
        ports = nmap_scan(ip, COMMON_PORTS)
    else:
        ports = tcp_scan(ip, COMMON_PORTS)

    open_ports = [p for p in ports if p['open']]
    output = {
        'host':      host,
        'ip':        ip,
        'scannedAt': datetime.utcnow().isoformat() + 'Z',
        'scanner':   'nmap' if (use_nmap and NMAP_AVAILABLE) else 'tcp-connect',
        'total':     len(ports),
        'openCount': len(open_ports),
        'ports':     ports,
        'openPorts': open_ports,
    }
    print(json.dumps(output))


# ── Interactive CLI entry ─────────────────────────────────────────────────────
def cli_mode():
    print('=' * 70)
    print(' ADVANCED PORT SCANNER WITH RISK ASSESSMENT — PhishGuard AI')
    print('=' * 70)

    target = input('Enter target IP / hostname / URL: ').strip()
    if not target:
        print('[!] No target provided. Exiting.')
        return

    host = resolve_host(target)
    print(f'[*] Resolved host: {host}')

    try:
        ip = socket.gethostbyname(host)
        print(f'[*] IP address  : {ip}')
    except socket.gaierror as e:
        print(f'[!] Cannot resolve hostname: {e}')
        return

    use_nmap = False
    if NMAP_AVAILABLE:
        ans = input('Use Nmap for deep scan? (y/n) [default: n]: ').strip().lower()
        use_nmap = ans == 'y'
    else:
        print('[!] python-nmap not installed. Using fast TCP connect scanner.')

    print(f'\n[*] Scanning {len(COMMON_PORTS)} common ports on {host} ({ip})…')
    if use_nmap:
        results = nmap_scan(ip, COMMON_PORTS)
    else:
        results = tcp_scan(ip, COMMON_PORTS)

    open_ports = [r for r in results if r['open']]
    closed = len(results) - len(open_ports)

    print(f'\n{"="*70}')
    print(f' SCAN RESULTS FOR: {host} ({ip})')
    print(f' TIME: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'{"="*70}')
    print(f'\n  Ports scanned : {len(results)}')
    print(f'  Open          : {len(open_ports)}')
    print(f'  Closed        : {closed}\n')

    if not open_ports:
        print('[+] No open ports found — host appears well-firewalled.')
    else:
        print(f'{"PORT":<8} {"SERVICE":<14} {"RISK":<10} {"DESCRIPTION"}')
        print('-' * 70)
        for p in open_ports:
            print(f'{p["port"]:<8} {p["service"]:<14} {p["risk"]:<10} {p["description"]}')

        high_risk = [p for p in open_ports if p['risk'] in ('CRITICAL', 'HIGH')]
        if high_risk:
            print(f'\n{"="*70}')
            print(' ⚠️  HIGH / CRITICAL RISK PORTS — ACTION REQUIRED')
            print('='*70)
            for p in high_risk:
                print(f'\n  Port {p["port"]} — {p["service"]} [{p["risk"]}]')
                print(f'  Prevention : {p["tip"]}')
                print(f'  Exploits   : {p["exploit"]}')

    print(f'\n{"="*70}\n')


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PhishGuard AI Port Scanner')
    parser.add_argument('--target', type=str, help='Target hostname/IP/URL (API mode)')
    parser.add_argument('--json',   action='store_true', help='Output JSON (API mode)')
    parser.add_argument('--nmap',   action='store_true', help='Use Nmap for deep scan')
    args = parser.parse_args()

    if args.json and args.target:
        api_mode(args.target, use_nmap=args.nmap)
    else:
        cli_mode()