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

---

## Hidden Folders in This Directory

> ⚠ **Reminder:** There is a hidden `.claude/` folder inside this project directory
> (`showdown/.claude/`). It contains Claude Code project settings (`settings.local.json`).
> If you copy or archive this folder, **include hidden files** or you will lose those settings.
>
> Claude Code's session memory (context across conversations) lives **outside** this folder at:
> `~/.claude/projects/-home-ev-Documents-clault-showdown/memory/`
> That directory is not included when you copy the showdown folder — back it up separately
> if you want to preserve AI session notes.
>
> To include all hidden files when copying:
> ```bash
> cp -r showdown/ destination/            # cp includes hidden dirs by default
> tar -czf showdown.tar.gz showdown/      # tar includes hidden dirs by default
> rsync -av showdown/ destination/        # rsync includes hidden dirs by default
> ```
