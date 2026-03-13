#!/usr/bin/env bash
# modules/01_scan/vuln_scan.sh
#
# VULNERABILITY SCANNING
# Automated CVE and misconfiguration detection.
#
# Tools used:
#   nuclei      — Fast template-based scanner. 9000+ templates covering CVEs,
#                 misconfigs, exposed panels, default creds, etc.
#   nmap --script vuln — Nmap's built-in vuln detection scripts
#   nikto       — Web server vulnerability scanner (HTTP-specific)
#   searchsploit— Offline exploit-db search for discovered service versions

run_module_main() {
    local outdir="${SESSION_DIR}/scan"
    section "Vulnerability Scanning"
    warn "This phase is loud — expect IDS/SIEM alerts on monitored networks"
    echo ""

    # Use alive hosts
    local target_file="${SESSION_DIR}/recon/hosts_alive.txt"
    [[ ! -s "${target_file}" ]] && target_file="${SESSION_DIR}/targets.txt"

    # Read nmap results to find web hosts for nikto
    local nmap_xml="${outdir}/nmap_scan.xml"

    # ── Nuclei ────────────────────────────────────────────────────────────────
    if tool_or_skip nuclei "template-based vuln scanner"; then
        divider
        echo -e "${BOLD}[1/4] Nuclei — CVE & Misconfiguration Templates${NC}"
        explain "Runs thousands of YAML templates against targets"
        explain "Detects: CVEs, default creds, exposed panels, misconfigs, takeovers"
        explain "Template categories: cves, exposures, misconfigurations, default-logins"
        echo ""

        echo -e "${BOLD}  Select nuclei template set:${NC}"
        echo -e "  ${CYAN}1)${NC} Critical + High CVEs only  ${DIM}[fast, low noise]${NC}"
        echo -e "  ${CYAN}2)${NC} CVEs + Misconfigs + Exposures  ${DIM}[recommended]${NC}"
        echo -e "  ${CYAN}3)${NC} Full scan (all templates)  ${DIM}[slow, comprehensive]${NC}"
        echo -n "  Choice [1-3]: "
        local nchoice; read -r nchoice

        local nuclei_tags=""
        case "${nchoice}" in
            1) nuclei_tags="cves,severity:critical,severity:high" ;;
            2) nuclei_tags="cves,misconfigurations,exposures,default-logins" ;;
            3) nuclei_tags="" ;;  # all
        esac

        local out="${outdir}/nuclei_results.txt"
        local nuclei_cmd=(nuclei -l "${target_file}" -o "${out}" -markdown-export "${outdir}/nuclei_md")

        if [[ -n "${nuclei_tags}" ]]; then
            nuclei_cmd+=(-tags "${nuclei_tags}")
        fi

        # Update templates first
        info "Updating nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
        echo ""

        run_cmd "${out}" "${nuclei_cmd[@]}" 2>/dev/null || true

        # Parse and report
        if [[ -s "${out}" ]]; then
            local crit; crit=$(grep -c '\[critical\]' "${out}" 2>/dev/null || echo 0)
            local high; high=$(grep -c '\[high\]' "${out}" 2>/dev/null || echo 0)
            local med; med=$(grep -c '\[medium\]' "${out}" 2>/dev/null || echo 0)

            [[ "${crit}" -gt 0 ]] && append_finding "CRITICAL" \
                "Nuclei: ${crit} critical findings" "See ${out}"
            [[ "${high}" -gt 0 ]] && append_finding "HIGH" \
                "Nuclei: ${high} high-severity findings" "See ${out}"
            [[ "${med}" -gt 0 ]] && append_finding "MEDIUM" \
                "Nuclei: ${med} medium-severity findings" "See ${out}"
        fi
    fi

    # ── Nmap Vuln Scripts ─────────────────────────────────────────────────────
    if tool_or_skip nmap "vulnerability scripts"; then
        divider
        echo -e "${BOLD}[2/4] Nmap Vulnerability Scripts${NC}"
        explain "Runs nmap's 'vuln' script category against all targets"
        explain "Includes: smb-vuln-ms17-010 (EternalBlue), http-shellshock,"
        explain "          ssl-heartbleed, ssl-poodle, ms-sql-info, many more"
        echo ""

        local out="${outdir}/nmap_vulns.txt"
        # shellcheck disable=SC2046
        run_cmd "${out}" nmap \
            --script vuln \
            -sV \
            -T4 \
            --open \
            -oA "${outdir}/nmap_vulns" \
            -iL "${target_file}" \
            2>/dev/null || true

        # Flag critical vulns
        if grep -qi "VULNERABLE\|CVE-2017-0144\|EternalBlue\|ms17-010" "${out}" 2>/dev/null; then
            append_finding "CRITICAL" "EternalBlue (MS17-010) — hosts appear VULNERABLE" \
                "See ${out}. Run smb_attacks module."
        fi
        if grep -qi "HEARTBLEED\|ssl-heartbleed" "${out}" 2>/dev/null; then
            append_finding "CRITICAL" "OpenSSL Heartbleed detected" "See ${out}"
        fi
        if grep -qi "shellshock\|SHELLSHOCK" "${out}" 2>/dev/null; then
            append_finding "CRITICAL" "Shellshock (CVE-2014-6271) detected" "See ${out}"
        fi
    fi

    # ── Nikto ─────────────────────────────────────────────────────────────────
    if tool_or_skip nikto "web server vulnerability scanner"; then
        divider
        echo -e "${BOLD}[3/4] Nikto — Web Server Checks${NC}"
        explain "Scans HTTP/HTTPS services for: outdated software, misconfigs,"
        explain "dangerous files, default pages, SSL issues, injection vectors"
        explain "Not stealthy — Nikto is very loud and easily detected"
        echo ""

        # Find web hosts from nmap results
        local web_hosts=()
        if [[ -f "${outdir}/nmap_scan.gnmap" ]]; then
            # Extract hosts with web ports open
            while IFS= read -r line; do
                [[ "${line}" =~ ^Host: ]] || continue
                local ip; ip=$(echo "${line}" | awk '{print $2}')
                echo "${line}" | grep -qE "80/open|443/open|8080/open|8443/open" && web_hosts+=("${ip}")
            done < "${outdir}/nmap_scan.gnmap"
        fi

        if [[ ${#web_hosts[@]} -eq 0 ]]; then
            info "No nmap results to parse — running nikto against all targets on common web ports"
            while IFS= read -r h; do
                [[ -n "$h" ]] && web_hosts+=("$h")
            done < "${target_file}"
        fi

        for host in "${web_hosts[@]}"; do
            for port in 80 443 8080 8443; do
                local ssl_flag=""
                [[ "${port}" == "443" ]] || [[ "${port}" == "8443" ]] && ssl_flag="-ssl"
                local out="${outdir}/nikto_${host}_${port}.txt"

                # Check if port responds before running nikto
                if timeout 3 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
                    info "nikto → ${host}:${port}"
                    run_cmd "${out}" nikto \
                        -host "${host}" \
                        -port "${port}" \
                        ${ssl_flag} \
                        -output "${outdir}/nikto_${host}_${port}.html" \
                        -Format html \
                        -Tuning 013579bx \
                        2>/dev/null || true

                    if grep -qi "OSVDB\|CVE\|Shellshock\|XSS\|SQL\|RFI\|LFI" "${out}" 2>/dev/null; then
                        append_finding "MEDIUM" "Nikto findings on ${host}:${port}" \
                            "Review ${out}"
                    fi
                fi
            done
        done
    fi

    # ── searchsploit ──────────────────────────────────────────────────────────
    if tool_or_skip searchsploit "offline exploit-db search"; then
        divider
        echo -e "${BOLD}[4/4] searchsploit — Exploit-DB Match on Discovered Services${NC}"
        explain "Searches local copy of Exploit-DB for exploits matching service banners"
        explain "Requires nmap XML output from port_scan module"
        echo ""

        if [[ -f "${nmap_xml}" ]]; then
            local out="${outdir}/searchsploit_matches.txt"
            run_cmd "${out}" searchsploit --nmap "${nmap_xml}" 2>/dev/null || true

            if [[ -s "${out}" ]]; then
                append_finding "HIGH" "searchsploit: exploit matches found" \
                    "See ${out} — cross-reference with nuclei and nmap vuln results"
            fi
        else
            warn "searchsploit skipped — no nmap XML found. Run port_scan first."
        fi
    fi

    success "Vulnerability scanning complete → ${outdir}"
    log "Vuln scan complete"
}
