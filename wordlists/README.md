# Wordlists

SHOWDOWN looks for wordlists in these locations (in order):
1. `/usr/share/seclists/`
2. `/usr/share/wordlists/`
3. `/opt/SecLists/`
4. `./wordlists/` (this directory)

## Install SecLists (recommended)

```bash
# Kali/Parrot (APT)
sudo apt install seclists

# Any Linux
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists --depth=1
```

## Key wordlists used by SHOWDOWN

| Module | Wordlist path (relative to SecLists root) |
|--------|-------------------------------------------|
| Web dirs | `Discovery/Web-Content/raft-medium-directories.txt` |
| Web files | `Discovery/Web-Content/raft-medium-files.txt` |
| Passwords | `Passwords/Common-Credentials/10k-most-common.txt` |
| Usernames | `Usernames/Names/names.txt` |
| rockyou | `/usr/share/wordlists/rockyou.txt` (decompress: `gunzip rockyou.txt.gz`) |

## Fallback wordlists (for air-gapped environments)

Place your wordlists here with these names and SHOWDOWN will find them:

```
wordlists/
├── dirs.txt         → web directory brute force
├── files.txt        → web file brute force
├── passwords.txt    → credential brute force
└── usernames.txt    → username enumeration
```

## Recommended additional lists

- `Discovery/Web-Content/api/api-endpoints.txt` — REST API fuzzing
- `Discovery/Web-Content/CMS/wordpress.fuzz.txt` — WordPress paths
- `Passwords/Leaked-Databases/rockyou.txt.tar.gz` — Full rockyou
- `Discovery/DNS/subdomains-top1million-110000.txt` — Subdomain brute
- `Usernames/top-usernames-shortlist.txt` — Top 100 usernames (fast)
