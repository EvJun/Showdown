#!/usr/bin/env bash
# lib/assisted.sh — Assisted mode engine: explains every tool before running

assisted_mode() {
    section "ASSISTED MODE"
    echo -e "${DIM}  Each phase is explained before execution."
    echo -e "  You confirm what runs. Nothing fires without your say-so.${NC}"
    echo ""

    assisted_phase_recon
    assisted_phase_scan
    assisted_phase_web
    assisted_phase_exploit
    assisted_phase_lateral
    assisted_phase_post
    assisted_summary
}

# ─── Phase 0: Recon ───────────────────────────────────────────────────────────
assisted_phase_recon() {
    phase_header "0" "RECONNAISSANCE"
    cat << 'HELP'
  Goal: Understand the target before touching it.
  Passive recon leaves zero footprint. Active recon confirms live hosts.
  Always run passive first on stealth engagements.
HELP
    echo ""

    echo -e "${BOLD}  A) Passive Reconnaissance${NC}"
    explain "OSINT, DNS, WHOIS, certificate transparency, Shodan"
    explain "No packets sent to the target — completely silent"
    explain "Good for: gathering domain intel, finding subdomains, leaked creds"
    echo ""
    if confirm "  Run passive recon?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/00_recon/passive_recon.sh"
        run_module_main
    fi

    echo ""
    echo -e "${BOLD}  B) Active Host Discovery${NC}"
    explain "ICMP ping sweep, ARP scan, TCP probe to find live hosts"
    explain "Leaves traces — will appear in firewall/IDS logs"
    explain "Essential before port scanning to avoid wasting time on dead IPs"
    echo ""
    if confirm "  Run active host discovery?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/00_recon/active_recon.sh"
        run_module_main
    fi
}

# ─── Phase 1: Scan ────────────────────────────────────────────────────────────
assisted_phase_scan() {
    phase_header "1" "SCANNING & ENUMERATION"
    cat << 'HELP'
  Goal: Map every open port, identify services, detect vulnerabilities.
  Port scanning is the loudest phase — expect IDS/SIEM alerts on monitored networks.
HELP
    echo ""

    echo -e "${BOLD}  Port Scanning Intensity:${NC}"
    echo -e "  ${CYAN}1)${NC} Quick    — top 1000 TCP ports, fast timing"
    echo -e "  ${CYAN}2)${NC} Standard — top 1000 TCP + version + default scripts  ${DIM}[recommended]${NC}"
    echo -e "  ${CYAN}3)${NC} Full     — all 65535 TCP ports (slow, thorough)"
    echo -e "  ${CYAN}4)${NC} Stealth  — SYN scan, lower timing, OS detect"
    echo -e "  ${CYAN}5)${NC} Skip"
    echo ""
    local sc; sc=$(choose_number 5)
    if [[ "$sc" != "5" ]]; then
        export SCAN_INTENSITY="$sc"
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/01_scan/port_scan.sh"
        run_module_main
    fi

    echo ""
    echo -e "${BOLD}  Vulnerability Scanning${NC}"
    explain "Automated CVE/misconfiguration detection against open ports"
    explain "Tools: Nuclei (templates), Nmap --script vuln, Nikto (web)"
    explain "Noisy — will generate IDS alerts and may stress services"
    echo ""
    if confirm "  Run vulnerability scanning?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/01_scan/vuln_scan.sh"
        run_module_main
    fi
}

# ─── Phase 2: Web ─────────────────────────────────────────────────────────────
assisted_phase_web() {
    phase_header "2" "WEB & IOT EXPLOITATION"
    echo ""

    echo -e "${BOLD}  Web Enumeration${NC}"
    explain "Fingerprint tech stack, brute-force directories, check for CMS"
    explain "Tools: Whatweb, Gobuster/Feroxbuster, FFUF, WPScan, Nikto, sslscan"
    explain "Look for: admin panels, backup files, API endpoints, dev/staging paths"
    echo ""
    if confirm "  Run web enumeration on discovered HTTP services?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/02_web/web_enum.sh"
        run_module_main
    fi

    echo ""
    echo -e "${BOLD}  Webcam & IoT Attacks${NC}"
    explain "Discover IP cameras, DVRs, NVRs, and IoT devices"
    explain "Test for: default creds, unauthenticated RTSP streams, known CVEs"
    explain "Targets: Hikvision, Dahua, Axis, Foscam, generic ONVIF devices"
    explain "RTSP streams can prove unauthorised camera access during pentest"
    echo ""
    if confirm "  Run webcam/IoT enumeration and exploitation?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/02_web/webcam_attack.sh"
        run_module_main
    fi
}

# ─── Phase 3: Exploit ─────────────────────────────────────────────────────────
assisted_phase_exploit() {
    phase_header "3" "EXPLOITATION"
    echo ""

    echo -e "${BOLD}  SMB / Windows Attacks${NC}"
    explain "Enumerate shares, users, policies; test null sessions"
    explain "Check for EternalBlue (MS17-010), PrintNightmare (CVE-2021-34527)"
    explain "Tools: enum4linux-ng, smbclient, CrackMapExec, Nmap SMB scripts"
    echo ""
    if confirm "  Run SMB enumeration and attacks?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/03_exploit/smb_attacks.sh"
        run_module_main
    fi

    echo ""
    echo -e "${BOLD}  Credential Brute Forcing${NC}"
    explain "Test SSH, FTP, HTTP, RDP, SMB, SNMP, Telnet, VNC for weak creds"
    explain "Tools: Hydra, Medusa"
    warn   "  CHECK LOCKOUT POLICIES — brute forcing can lock accounts!"
    explain "Confirm account lockout threshold with client before running"
    echo ""
    if confirm "  Run credential brute force (confirm lockout policy first)?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/03_exploit/brute_force.sh"
        run_module_main
    fi
}

# ─── Phase 4: Lateral ─────────────────────────────────────────────────────────
assisted_phase_lateral() {
    phase_header "4" "LATERAL MOVEMENT"
    cat << 'HELP'
  Goal: Demonstrate how an attacker moves from one host to others.
  Requires credentials or a foothold from previous phases.
HELP
    echo ""
    explain "LLMNR/NBT-NS poisoning with Responder → capture NTLMv2 hashes"
    explain "Pass-the-Hash / Pass-the-Ticket with CrackMapExec + Impacket"
    explain "BloodHound AD graph to find shortest privilege escalation path"
    explain "Kerberoasting: request service tickets, crack offline"
    echo ""
    warn   "  Lateral movement generates significant domain event log noise"
    echo ""
    if confirm "  Run lateral movement modules?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/04_lateral/lateral_movement.sh"
        run_module_main
    fi
}

# ─── Phase 5: Post-exploit ────────────────────────────────────────────────────
assisted_phase_post() {
    phase_header "5" "POST-EXPLOITATION"
    cat << 'HELP'
  Goal: Demonstrate impact — what an attacker could do with access.
  Strictly within agreed rules of engagement.
HELP
    echo ""
    explain "Dump credentials: SAM/NTDS via secretsdump, LSASS via Mimikatz"
    explain "Hunt for sensitive files: config files, SSH keys, password stores"
    explain "Check for cleartext creds in environment variables, scripts, DBs"
    echo ""
    warn   "  Document every action — post-exploit evidence must be preserved"
    echo ""
    if confirm "  Run post-exploitation modules (within RoE)?"; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/modules/05_post/post_exploit.sh"
        run_module_main
    fi
}

# ─── Summary ──────────────────────────────────────────────────────────────────
assisted_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  ENGAGEMENT COMPLETE                   ${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
    echo ""
    table_row "Session dir"  "${SESSION_DIR}"
    table_row "Log"          "${LOG_FILE}"
    table_row "Findings"     "${SESSION_DIR}/findings.md"
    echo ""

    if [[ -f "${SESSION_DIR}/findings.md" ]]; then
        local crit high med low inf
        crit=$(grep -c '\[CRITICAL\]' "${SESSION_DIR}/findings.md" 2>/dev/null || true)
        high=$(grep -c '\[HIGH\]'     "${SESSION_DIR}/findings.md" 2>/dev/null || true)
        med=$(grep -c  '\[MEDIUM\]'  "${SESSION_DIR}/findings.md" 2>/dev/null || true)
        low=$(grep -c  '\[LOW\]'     "${SESSION_DIR}/findings.md" 2>/dev/null || true)
        inf=$(grep -c  '\[INFO\]'    "${SESSION_DIR}/findings.md" 2>/dev/null || true)
        echo -e "${BOLD}  Finding Summary:${NC}"
        echo -e "  ${RED}Critical: ${crit:-0}${NC}"
        echo -e "  ${YELLOW}High:     ${high:-0}${NC}"
        echo -e "  ${YELLOW}Medium:   ${med:-0}${NC}"
        echo -e "  ${GREEN}Low:      ${low:-0}${NC}"
        echo -e "  ${BLUE}Info:     ${inf:-0}${NC}"
    fi
    echo ""
}

# ─── Helpers ──────────────────────────────────────────────────────────────────
phase_header() {
    local num="$1" name="$2"
    echo ""
    echo -e "${CYAN}${BOLD}════════════════════════════════════════${NC}"
    printf "${CYAN}${BOLD}  PHASE %s: %-30s  ${NC}\n" "${num}" "${name}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════${NC}"
    echo ""
}
