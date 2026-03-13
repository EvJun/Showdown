#!/usr/bin/env bash
# modules/01_scan/port_scan.sh
#
# PORT SCANNING & SERVICE ENUMERATION
# Maps open ports, detects service versions, and fingerprints the OS.
#
# Tools used:
#   nmap     — The gold standard. SYN scan, version detection, OS fingerprint,
#              script engine. Set intensity via SCAN_INTENSITY env var.
#   masscan  — Fastest port scanner. Scans all 65535 ports quickly.
#              WARNING: very loud — use rate limiting on production networks.
#
# SCAN_INTENSITY values (set by assisted mode or override manually):
#   1 = Quick    — top 1000 TCP, T4 timing
#   2 = Standard — top 1000 TCP, -sV, default scripts  [recommended]
#   3 = Full     — all 65535 TCP ports
#   4 = Stealth  — SYN + OS detect, T2 (slower, quieter)

SCAN_INTENSITY="${SCAN_INTENSITY:-2}"

run_module_main() {
    local outdir="${SESSION_DIR}/scan"
    section "Port Scanning"

    # Use alive hosts if previous recon ran, else use all targets
    local target_file="${SESSION_DIR}/recon/hosts_alive.txt"
    if [[ ! -s "${target_file}" ]]; then
        target_file="${SESSION_DIR}/targets.txt"
        warn "No alive hosts file found — scanning all targets from scope"
    else
        info "Using alive hosts from: ${target_file}"
        info "$(wc -l < "${target_file}") host(s) to scan"
    fi
    echo ""

    # Build target string for nmap from file
    local nmap_targets="-iL ${target_file}"

    # ── Intensity selection ───────────────────────────────────────────────────
    if [[ "${SCAN_INTENSITY}" == "0" ]]; then
        echo -e "${BOLD}Select scan intensity:${NC}"
        echo -e "  ${CYAN}1)${NC} Quick    — top 1000 TCP, fast timing"
        echo -e "  ${CYAN}2)${NC} Standard — version detection + default scripts  ${DIM}[recommended]${NC}"
        echo -e "  ${CYAN}3)${NC} Full     — all 65535 TCP ports"
        echo -e "  ${CYAN}4)${NC} Stealth  — SYN scan, T2, OS fingerprint"
        echo ""
        SCAN_INTENSITY=$(choose_number 4)
    fi

    # ── Phase A: Fast masscan (all ports) ────────────────────────────────────
    if tool_or_skip masscan "fast full-port pre-scan"; then
        divider
        echo -e "${BOLD}[A] masscan — Fast Port Discovery${NC}"
        explain "Scans all 65535 TCP ports at high speed to find open ports first"
        explain "Then nmap does targeted service detection only on open ports"
        explain "Rate: 1000 pps — adjust MASSCAN_RATE env var for faster networks"
        echo ""

        local rate="${MASSCAN_RATE:-1000}"
        local out="${outdir}/masscan_all.txt"
        local out_xml="${outdir}/masscan_all.xml"

        warn "masscan requires root for raw socket access"
        if [[ "${EUID}" -eq 0 ]]; then
            # Build masscan target list
            local masscan_targets=()
            while IFS= read -r h; do
                [[ -n "$h" ]] && masscan_targets+=("$h")
            done < "${target_file}"

            run_cmd "${out}" masscan \
                "${masscan_targets[@]}" \
                -p 1-65535 \
                --rate "${rate}" \
                --open-only \
                -oX "${out_xml}" \
                2>/dev/null || true

            # Extract open ports per host for targeted nmap
            if [[ -f "${out_xml}" ]] && command -v python3 &>/dev/null; then
                python3 << 'PYEOF'
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1] if len(sys.argv)>1 else '/dev/stdin')
    hosts = {}
    for host in tree.findall('.//host'):
        addr = host.find('address')
        if addr is None: continue
        ip = addr.get('addr', '')
        for port in host.findall('.//port'):
            if port.find('state') is not None and port.find('state').get('state') == 'open':
                hosts.setdefault(ip, []).append(port.get('portid',''))
    for ip, ports in sorted(hosts.items()):
        print(f"{ip}:{','.join(ports)}")
except Exception as e:
    print(f"Parse error: {e}", file=sys.stderr)
PYEOF
            fi
        else
            warn "masscan skipped — requires root. Run sudo ./showdown.sh for masscan."
        fi
    fi

    # ── Phase B: Nmap ─────────────────────────────────────────────────────────
    if tool_or_skip nmap "port scanning"; then
        divider
        echo -e "${BOLD}[B] Nmap Scan — Intensity ${SCAN_INTENSITY}${NC}"

        local nmap_flags=()
        local scan_label=""

        case "${SCAN_INTENSITY}" in
            1)
                scan_label="Quick (top 1000 TCP)"
                nmap_flags=(-sS -T4 --top-ports 1000 --open)
                explain "-sS: SYN scan | T4: aggressive timing | top 1000 common ports"
                ;;
            2)
                scan_label="Standard (top 1000 + service/scripts)"
                nmap_flags=(-sS -sV -sC -T4 --top-ports 1000 --open)
                explain "-sV: version detection | -sC: default scripts (e.g. banner grab, http-title)"
                explain "Recommended for most engagements — good coverage without being excessive"
                ;;
            3)
                scan_label="Full (all 65535 TCP)"
                nmap_flags=(-sS -sV -sC -p- -T4 --open)
                explain "Full port scan: -p- covers every TCP port"
                warn "This is slow on large scopes — may take hours"
                ;;
            4)
                scan_label="Stealth (SYN, T2, OS detect)"
                nmap_flags=(-sS -O --osscan-guess -T2 --top-ports 1000 --open)
                explain "-T2: polite timing | -O: OS fingerprinting"
                explain "Slower and quieter — better evasion on monitored networks"
                ;;
        esac

        echo ""
        info "Scan profile: ${scan_label}"
        echo ""

        local out_txt="${outdir}/nmap_scan.txt"
        local out_xml="${outdir}/nmap_scan.xml"
        local out_gnmap="${outdir}/nmap_scan.gnmap"

        run_cmd "${out_txt}" nmap \
            "${nmap_flags[@]}" \
            -oA "${outdir}/nmap_scan" \
            ${nmap_targets} \
            2>/dev/null || true

        # ── Parse and report findings ────────────────────────────────────────
        parse_nmap_results "${out_gnmap}"
    fi

    # ── Phase C: UDP scan (top ports) ────────────────────────────────────────
    if confirm "Run UDP scan? (top 200 UDP ports — requires root, slower)"; then
        if tool_or_skip nmap "UDP scanning"; then
            divider
            echo -e "${BOLD}[C] UDP Top-200 Scan${NC}"
            explain "-sU: UDP scan — finds DNS (53), SNMP (161), NTP (123), TFTP (69), etc."
            explain "UDP is often overlooked and contains misconfigured services"
            warn "Requires root"
            echo ""

            local out_udp="${outdir}/nmap_udp.txt"
            run_cmd "${out_udp}" nmap \
                -sU --top-ports 200 -T4 --open \
                -oA "${outdir}/nmap_udp" \
                ${nmap_targets} \
                2>/dev/null || true

            parse_nmap_udp "${out_udp}"
        fi
    fi

    success "Port scanning complete → ${outdir}"
    log "Port scan complete, intensity ${SCAN_INTENSITY}"
}

# ─── Parse nmap gnmap and record findings ────────────────────────────────────
parse_nmap_results() {
    local gnmap="$1"
    [[ ! -f "${gnmap}" ]] && return

    echo ""
    echo -e "${BOLD}Open Port Summary:${NC}"
    divider

    while IFS= read -r line; do
        [[ "${line}" =~ ^Host: ]] || continue
        local ip; ip=$(echo "${line}" | awk '{print $2}')
        local ports; ports=$(echo "${line}" | grep -oP '\d+/open[^\s]*' | tr '\n' ' ')
        [[ -z "${ports}" ]] && continue

        echo -e "  ${GREEN}${ip}${NC}"
        echo "${line}" | grep -oP '\d+/open/[^/]*/[^/]*/[^/]*' | while IFS= read -r port; do
            echo -e "    ${CYAN}→${NC} ${port}"
        done

        # Flag interesting ports
        check_interesting_ports "${ip}" "${line}"
    done < "${gnmap}"
}

check_interesting_ports() {
    local ip="$1" line="$2"

    # SMB
    if echo "${line}" | grep -qE "139/open|445/open"; then
        append_finding "INFO" "SMB open on ${ip}" \
            "Ports 139/445 open — run smb_attacks module"
    fi

    # RDP
    if echo "${line}" | grep -q "3389/open"; then
        append_finding "MEDIUM" "RDP exposed on ${ip}" \
            "Port 3389 open — check for credential brute force / CVE-2019-0708 (BlueKeep)"
    fi

    # Telnet
    if echo "${line}" | grep -q "23/open"; then
        append_finding "HIGH" "Telnet open on ${ip}" \
            "Telnet transmits credentials in cleartext"
    fi

    # FTP
    if echo "${line}" | grep -q "21/open"; then
        append_finding "MEDIUM" "FTP open on ${ip}" \
            "Check for anonymous login and cleartext credential exposure"
    fi

    # SNMP
    if echo "${line}" | grep -q "161/open"; then
        append_finding "MEDIUM" "SNMP open on ${ip}" \
            "Check for default community strings (public/private)"
    fi

    # WinRM / PSRemoting
    if echo "${line}" | grep -qE "5985/open|5986/open"; then
        append_finding "INFO" "WinRM open on ${ip}" \
            "Port 5985/5986 — Windows Remote Management, useful with valid creds"
    fi

    # Database ports
    if echo "${line}" | grep -qE "1433/open|3306/open|5432/open|1521/open|27017/open"; then
        append_finding "HIGH" "Database port exposed on ${ip}" \
            "DB ports should not be internet-facing — check for weak auth"
    fi

    # VNC
    if echo "${line}" | grep -qE "590[0-9]/open"; then
        append_finding "MEDIUM" "VNC open on ${ip}" \
            "VNC may have weak/no authentication"
    fi
}

parse_nmap_udp() {
    local out="$1"
    [[ ! -f "${out}" ]] && return

    if grep -q "161/open" "${out}"; then
        append_finding "MEDIUM" "SNMP UDP/161 open" \
            "Attempt default community strings: public, private, community, snmp"
    fi
    if grep -q "53/open" "${out}"; then
        append_finding "INFO" "DNS UDP/53 open" \
            "Test for DNS zone transfer and recursive resolver misconfiguration"
    fi
}
