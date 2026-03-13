#!/usr/bin/env bash
# modules/00_recon/active_recon.sh
#
# ACTIVE HOST DISCOVERY
# Sends packets to discover which hosts are live before deeper scanning.
#
# Tools used:
#   nmap -sn        — ICMP + TCP SYN/ACK ping sweep (no port scan)
#   masscan --ping  — Fast ICMP sweep for large ranges
#   arp-scan        — ARP-based discovery (requires root, same subnet only)
#   netdiscover     — Passive/active ARP discovery
#   nbtscan         — NetBIOS name scan (finds Windows hosts)
#   fping           — Fast parallel ICMP ping
#
# Output: ${SESSION_DIR}/recon/hosts_alive.txt (one IP per line)

run_module_main() {
    local outdir="${SESSION_DIR}/recon"
    local alive_file="${outdir}/hosts_alive.txt"
    : > "${alive_file}"  # clear/create

    section "Active Host Discovery"
    warn "Packets will be sent to target networks — check you are in scope"
    echo ""

    # ── Nmap Ping Sweep ───────────────────────────────────────────────────────
    if tool_or_skip nmap "host discovery"; then
        divider
        echo -e "${BOLD}[1/5] Nmap Ping Sweep (-sn)${NC}"
        explain "-sn: skip port scan, just discover live hosts"
        explain "Uses ICMP echo, TCP SYN to 443, TCP ACK to 80, ICMP timestamp"
        explain "Works without root (falls back to TCP connect instead of SYN)"
        echo ""

        local out="${outdir}/nmap_pingsweep.txt"
        # shellcheck disable=SC2046
        run_cmd "${out}" nmap -sn --open -T4 \
            --reason \
            -oG "${outdir}/nmap_pingsweep.gnmap" \
            $(targets_nmap_list) 2>/dev/null || true

        # Extract IPs from gnmap
        grep "^Host:" "${outdir}/nmap_pingsweep.gnmap" 2>/dev/null | \
            awk '{print $2}' >> "${alive_file}" || true
    fi

    # ── ARP Scan ─────────────────────────────────────────────────────────────
    if [[ "${EUID}" -eq 0 ]] && tool_or_skip arp-scan "ARP host discovery"; then
        divider
        echo -e "${BOLD}[2/5] arp-scan (ARP layer — requires root, same subnet)${NC}"
        explain "ARP cannot be blocked by host firewalls — very reliable on LAN"
        explain "Reveals hosts that block ICMP"
        echo ""

        local out="${outdir}/arpscan.txt"
        local interfaces
        interfaces=$(ip link show | awk -F': ' '/^[0-9]+: [^lo]/{print $2}' | head -5)

        while IFS= read -r iface; do
            [[ -z "${iface}" ]] && continue
            info "ARP scan on interface: ${iface}"
            run_cmd "${out}" arp-scan --interface="${iface}" --localnet 2>/dev/null || true
        done <<< "${interfaces}"

        # Also target specific ranges
        for target in "${TARGETS[@]}"; do
            if [[ "${target}" =~ / ]]; then
                run_cmd "${out}" arp-scan "${target}" 2>/dev/null || true
            fi
        done

        # Extract IPs
        grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${out}" 2>/dev/null >> "${alive_file}" || true

    elif [[ "${EUID}" -ne 0 ]]; then
        warn "ARP scan skipped — requires root. Run: sudo ${0}"
    fi

    # ── Netdiscover ──────────────────────────────────────────────────────────
    if [[ "${EUID}" -eq 0 ]] && tool_or_skip netdiscover "ARP discovery"; then
        divider
        echo -e "${BOLD}[3/5] netdiscover (passive + active ARP)${NC}"
        explain "Active mode: sends ARP requests; passive: listens for ARP traffic"
        explain "Good for finding hosts on local subnets quickly"
        echo ""

        for target in "${TARGETS[@]}"; do
            [[ "${target}" =~ / ]] || continue
            local safe; safe="${target//\//_}"
            local out="${outdir}/netdiscover_${safe}.txt"
            info "netdiscover → ${target}"
            timeout 30 netdiscover -r "${target}" -P 2>/dev/null | tee "${out}" || true
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${out}" 2>/dev/null >> "${alive_file}" || true
        done
    fi

    # ── fping ────────────────────────────────────────────────────────────────
    if tool_or_skip fping "fast parallel ICMP ping"; then
        divider
        echo -e "${BOLD}[4/5] fping — fast parallel ICMP${NC}"
        explain "Pings many hosts simultaneously, much faster than sequential ping"
        echo ""

        local out="${outdir}/fping.txt"
        # shellcheck disable=SC2046
        fping -a -g $(targets_nmap_list) 2>/dev/null | tee "${out}" || true
        cat "${out}" >> "${alive_file}" 2>/dev/null || true
    fi

    # ── NBT Scan ─────────────────────────────────────────────────────────────
    if tool_or_skip nbtscan "NetBIOS name scanning"; then
        divider
        echo -e "${BOLD}[5/5] nbtscan — NetBIOS Names${NC}"
        explain "Finds Windows workstations/servers by querying NetBIOS name service"
        explain "Reveals hostname, domain/workgroup, and MAC address"
        echo ""

        local out="${outdir}/nbtscan.txt"
        for target in "${TARGETS[@]}"; do
            run_cmd "${out}" nbtscan -r "${target}" 2>/dev/null || true
        done

        if [[ -s "${out}" ]]; then
            append_finding "INFO" "NetBIOS names discovered" \
                "Windows hosts identified — see ${out}"
        fi
    fi

    # ── Consolidate alive hosts ───────────────────────────────────────────────
    sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n "${alive_file}" > "${outdir}/hosts_alive_sorted.txt" 2>/dev/null || true
    mv "${outdir}/hosts_alive_sorted.txt" "${alive_file}"

    local count; count=$(wc -l < "${alive_file}" 2>/dev/null || echo 0)
    echo ""
    success "Host discovery complete — ${count} live host(s) found"
    info "Live hosts list: ${alive_file}"

    if [[ "${count}" -gt 0 ]]; then
        echo ""
        echo -e "${BOLD}Live hosts:${NC}"
        while IFS= read -r host; do
            echo -e "  ${GREEN}●${NC} ${host}"
        done < "${alive_file}"

        append_finding "INFO" "Host discovery: ${count} live hosts" \
            "Live host list at ${alive_file}"
    fi

    echo ""
    log "Active recon complete. Alive hosts: ${count}"
}
