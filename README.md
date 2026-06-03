# SHOWDOWN — Pentest Framework

Modular bash framework for authorised office network penetration testing.

## Quick Start

```bash
# 1. Install dependencies (run once, as root)
sudo ./install_deps.sh

# 2. Create your target file
echo "192.168.1.0/24" > targets.txt

# 3. Launch
./showdown.sh -t targets.txt
```

## Modes

| Mode | Flag | Description |
|------|------|-------------|
| Assisted | *(default)* | Step-by-step, explains each tool, prompts before running |
| Manual | `-m manual` | Module picker — run specific phases |
| Auto | `-m auto` | Full pipeline, single confirm |

```bash
./showdown.sh -t targets.txt                        # assisted
./showdown.sh -t targets.txt -m manual              # module picker
./showdown.sh -t targets.txt -m auto -s clientname  # full run, named session
```

## Modules

| Phase | Module | Tools |
|-------|--------|-------|
| Recon (passive) | `passive_recon` | whois, dig, dnsrecon, theHarvester, crt.sh, Shodan |
| Recon (active) | `active_recon` | nmap -sn, arp-scan, netdiscover, fping, nbtscan |
| Port scan | `port_scan` | nmap (4 intensity profiles), masscan |
| Vuln scan | `vuln_scan` | Nuclei, nmap --script vuln, Nikto, searchsploit |
| Web enum | `web_enum` | whatweb, gobuster/feroxbuster, ffuf, WPScan, sslscan |
| Webcam/IoT | `webcam_attack` | Camera discovery, default creds, RTSP access, CVE checks |
| SMB | `smb_attacks` | enum4linux-ng, smbclient, smbmap, CrackMapExec, EternalBlue |
| Brute force | `brute_force` | Hydra — SSH, FTP, HTTP, RDP, SMB, SNMP, VNC |
| Lateral move | `lateral_movement` | Responder, CME, Impacket, Kerberoasting, BloodHound |
| Post-exploit | `post_exploit` | secretsdump, file hunting, LDAP AD enumeration |

## Shodan Integration

Shodan runs automatically during passive recon (step 6 of 7) if `SHODAN_API_KEY` is set. It queries Shodan's public database for each target IP — no packets are sent to the target.

**What it retrieves:**
- Open ports and service banners visible from the internet
- Known CVEs associated with exposed services
- ISP and organisation info

**Setup:**
```bash
export SHODAN_API_KEY=your_key_here   # get a free key at account.shodan.io
shodan init $SHODAN_API_KEY           # initialise the CLI
```

If the key is not set, Shodan is skipped silently and the rest of recon continues normally.

**Output:** Results saved to `sessions/*/recon/shodan_<IP>.txt`. Any result containing CVE references is automatically flagged as a `HIGH` severity finding in `findings.md`.

---

## Session Output

Results saved to `sessions/<name>_<timestamp>/`:
- `findings.md` — auto-generated findings report
- `loot/credentials.txt` — all captured credentials
- `loot/ntlm_hashes.txt` — NTLM hashes for offline cracking
- `showdown.log` — full timestamped command log

## SOP

Full methodology, tool cheatsheet, and findings classification:
→ `sop/SOP.md`

---

> **For authorised penetration testing only.**
> Confirm written scope before running any module.
