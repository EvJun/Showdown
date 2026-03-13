#!/usr/bin/env bash
# install_deps.sh — Install all SHOWDOWN dependencies
# Tested on: Kali Linux, Parrot OS, Ubuntu 22.04+
# Run as root: sudo ./install_deps.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}Run as root: sudo $0${NC}"
    exit 1
fi

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════╗"
echo "  ║  SHOWDOWN Dependency Installer   ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${NC}"

# ─── APT packages ─────────────────────────────────────────────────────────────
info "Updating APT..."
apt-get update -qq

APT_TOOLS=(
    # Core scanning
    nmap masscan

    # Host discovery
    fping netdiscover arp-scan nbtscan

    # SMB/Windows
    smbclient smbmap enum4linux crackmapexec

    # Web
    nikto gobuster feroxbuster whatweb wpscan sslscan testssl.sh curl

    # Brute force
    hydra medusa

    # SNMP
    snmp onesixtyone

    # Wordlists
    seclists wordlists

    # DNS/OSINT
    dnsrecon whois

    # Hash cracking
    hashcat john

    # Python3 + impacket
    python3 python3-pip python3-impacket impacket-scripts

    # Misc
    netcat-openbsd nc ffuf jq git wget curl libssl-dev
)

info "Installing APT packages..."
FAILED_APT=()
for tool in "${APT_TOOLS[@]}"; do
    if apt-get install -y -qq "${tool}" 2>/dev/null; then
        ok "  ${tool}"
    else
        fail "  ${tool} (not found in apt — will try alternative)"
        FAILED_APT+=("${tool}")
    fi
done

# ─── pip3 packages ────────────────────────────────────────────────────────────
info "Installing Python tools via pip3..."
PIP_TOOLS=(
    impacket
    bloodhound
    "git+https://github.com/CiscoCXSecurity/enum4linux-ng.git#egg=enum4linux-ng"
)

for tool in "${PIP_TOOLS[@]}"; do
    if pip3 install "${tool}" --quiet 2>/dev/null; then
        ok "  ${tool}"
    else
        fail "  ${tool}"
    fi
done

# ─── nuclei ───────────────────────────────────────────────────────────────────
info "Installing nuclei..."
if ! command -v nuclei &>/dev/null; then
    local_arch=$(uname -m)
    case "${local_arch}" in
        x86_64) arch_str="amd64" ;;
        aarch64) arch_str="arm64" ;;
        *) arch_str="amd64" ;;
    esac

    NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | \
        grep tag_name | cut -d'"' -f4 | tr -d 'v' 2>/dev/null || echo "3.2.0")
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${arch_str}.zip"

    if wget -q "${NUCLEI_URL}" -O /tmp/nuclei.zip 2>/dev/null; then
        unzip -qo /tmp/nuclei.zip -d /tmp/nuclei_bin/
        mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei
        chmod +x /usr/local/bin/nuclei
        nuclei -update-templates -silent 2>/dev/null || true
        ok "nuclei v${NUCLEI_VER}"
    else
        fail "nuclei (manual install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
    fi
else
    ok "nuclei (already installed)"
fi

# ─── theHarvester ─────────────────────────────────────────────────────────────
info "Installing theHarvester..."
if ! command -v theHarvester &>/dev/null; then
    if apt-get install -y -qq theharvester 2>/dev/null; then
        ok "theHarvester"
    else
        pip3 install theHarvester --quiet 2>/dev/null && ok "theHarvester (pip)" || fail "theHarvester"
    fi
else
    ok "theHarvester (already installed)"
fi

# ─── responder ────────────────────────────────────────────────────────────────
info "Installing Responder..."
if ! command -v responder &>/dev/null; then
    if apt-get install -y -qq responder 2>/dev/null; then
        ok "Responder"
    elif [[ ! -d /opt/Responder ]]; then
        git clone https://github.com/lgandx/Responder.git /opt/Responder --quiet 2>/dev/null
        ln -sf /opt/Responder/Responder.py /usr/local/bin/responder
        ok "Responder (from git → /opt/Responder)"
    fi
else
    ok "Responder (already installed)"
fi

# ─── ffuf ─────────────────────────────────────────────────────────────────────
info "Installing ffuf..."
if ! command -v ffuf &>/dev/null; then
    if apt-get install -y -qq ffuf 2>/dev/null; then
        ok "ffuf"
    else
        # Try go install
        if command -v go &>/dev/null; then
            go install github.com/ffuf/ffuf/v2@latest && ok "ffuf (go)" || fail "ffuf"
        else
            fail "ffuf (install go or: apt install ffuf)"
        fi
    fi
else
    ok "ffuf (already installed)"
fi

# ─── bloodhound ───────────────────────────────────────────────────────────────
info "Installing BloodHound..."
apt-get install -y -qq bloodhound 2>/dev/null && ok "BloodHound" || warn "BloodHound apt failed — install manually from github.com/BloodHoundAD"

# ─── ffprobe (for RTSP testing) ───────────────────────────────────────────────
info "Installing ffprobe..."
apt-get install -y -qq ffmpeg 2>/dev/null && ok "ffmpeg/ffprobe" || warn "ffmpeg not installed — RTSP stream testing will be limited"

# ─── shodan CLI ───────────────────────────────────────────────────────────────
info "Installing shodan CLI..."
pip3 install shodan --quiet 2>/dev/null && ok "shodan CLI" || fail "shodan CLI"
echo ""
warn "To enable Shodan: shodan init YOUR_API_KEY  (free key at account.shodan.io)"

# ─── hashcat ──────────────────────────────────────────────────────────────────
if ! command -v hashcat &>/dev/null; then
    apt-get install -y -qq hashcat 2>/dev/null && ok "hashcat" || fail "hashcat"
fi

# ─── Wordlist setup ───────────────────────────────────────────────────────────
echo ""
info "Setting up wordlists..."

# Decompress rockyou if needed
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && [[ ! -f /usr/share/wordlists/rockyou.txt ]]; then
    gunzip /usr/share/wordlists/rockyou.txt.gz
    ok "Decompressed rockyou.txt"
fi

# Check seclists
if [[ -d /usr/share/seclists ]]; then
    ok "SecLists found at /usr/share/seclists"
elif [[ -d /opt/SecLists ]]; then
    ok "SecLists found at /opt/SecLists"
else
    info "Downloading SecLists (this is large, ~1GB)..."
    if confirm_install; then
        git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists --depth=1 --quiet 2>/dev/null && \
            ok "SecLists → /opt/SecLists" || fail "SecLists"
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Installation Summary:${NC}"
TOOLS_CHECK=(nmap masscan nmap fping arp-scan netdiscover nbtscan smbclient smbmap
             crackmapexec nikto gobuster feroxbuster whatweb wpscan sslscan
             hydra medusa onesixtyone nuclei theHarvester responder ffuf
             hashcat shodan bloodhound-python ldapsearch)

for t in "${TOOLS_CHECK[@]}"; do
    if command -v "${t}" &>/dev/null; then
        printf "  ${GREEN}✓${NC} %-25s %s\n" "${t}" "$(command -v "${t}")"
    else
        printf "  ${RED}✗${NC} %-25s not found\n" "${t}"
    fi
done

echo ""
echo -e "${BOLD}Impacket tools:${NC}"
for t in secretsdump.py psexec.py wmiexec.py GetUserSPNs.py GetNPUsers.py lookupsid.py; do
    command -v "${t}" &>/dev/null && printf "  ${GREEN}✓${NC} %s\n" "${t}" || \
        printf "  ${RED}✗${NC} %s\n" "${t}"
done

echo ""
ok "Installation complete. Run ./showdown.sh to start."

confirm_install() {
    local yn
    echo -n "Download SecLists (~1GB)? [y/N] "
    read -r yn
    [[ "${yn}" =~ ^[Yy]$ ]]
}
