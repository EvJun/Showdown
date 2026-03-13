#!/usr/bin/env bash
# modules/00_recon/passive_recon.sh
#
# PASSIVE RECONNAISSANCE
# Gathers intelligence without sending packets to target systems.
#
# Tools used:
#   whois       — domain/IP registration info
#   dig         — DNS record enumeration (A, MX, TXT, SOA, NS, AXFR)
#   dnsrecon    — comprehensive DNS enumeration including zone transfer attempt
#   theHarvester— OSINT: emails, hostnames, IPs from search engines
#   curl        — crt.sh certificate transparency query
#   shodan      — search Shodan (requires API key in SHODAN_API_KEY env var)
#   amass       — subdomain enumeration (passive mode)
#   nmap -sL    — list scan: resolves hostnames without sending probes

run_module_main() {
    local outdir="${SESSION_DIR}/recon"
    section "Passive Reconnaissance"
    info "No packets will be sent to target systems"
    echo ""

    # Extract unique domains from target list (skip pure IPs for OSINT)
    local -a domains ips
    for t in "${TARGETS[@]}"; do
        if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
            ips+=("${t%%/*}")
        else
            domains+=("$t")
        fi
    done

    # ── WHOIS ────────────────────────────────────────────────────────────────
    if tool_or_skip whois "WHOIS lookups"; then
        divider
        echo -e "${BOLD}[1/7] WHOIS${NC}"
        explain "Queries domain registrar/IP block owner info. No target contact."
        echo ""

        for target in "${domains[@]:-}" "${ips[@]:-}"; do
            [[ -z "$target" ]] && continue
            local safe; safe="${target//\//_}"
            local out="${outdir}/whois_${safe}.txt"
            info "whois → ${target}"
            run_cmd "${out}" whois "${target}" 2>/dev/null || true
        done
    fi

    # ── DNS Enumeration ───────────────────────────────────────────────────────
    divider
    echo -e "${BOLD}[2/7] DNS Record Enumeration${NC}"
    explain "Queries DNS for A, AAAA, MX, NS, TXT, SOA, and CNAME records."
    explain "Zone transfer (AXFR) attempts can reveal all DNS entries if misconfigured."
    echo ""

    for domain in "${domains[@]:-}"; do
        [[ -z "$domain" ]] && continue
        local out="${outdir}/dns_${domain}.txt"
        {
            echo "=== DNS Records for ${domain} ==="
            echo ""
            for rtype in A AAAA MX NS TXT SOA CNAME; do
                echo "--- ${rtype} ---"
                dig +noall +answer "${rtype}" "${domain}" 2>/dev/null || true
                echo ""
            done

            echo "--- Zone Transfer Attempt (AXFR) ---"
            # Get nameservers first
            local ns_list
            ns_list=$(dig +short NS "${domain}" 2>/dev/null || true)
            if [[ -n "${ns_list}" ]]; then
                while IFS= read -r ns; do
                    echo "  Trying AXFR from: ${ns}"
                    dig AXFR "@${ns}" "${domain}" 2>/dev/null || echo "  Transfer refused (expected)"
                done <<< "${ns_list}"
            fi
        } | tee "${out}"

        if grep -q "^[^;]" "${out}" 2>/dev/null; then
            append_finding "INFO" "DNS records collected for ${domain}" \
                "See ${out} for full record set"
        fi

        # Check for zone transfer success
        if grep -qiE "(SOA|NS|A|MX)\s+\d+\s+IN" "${out}" 2>/dev/null; then
            if wc -l < "${out}" | awk '{if($1>50) exit 0; else exit 1}'; then
                append_finding "HIGH" "DNS Zone Transfer (AXFR) possible on ${domain}" \
                    "Nameserver returned full zone data — see ${out}"
            fi
        fi
    done

    # ── dnsrecon ─────────────────────────────────────────────────────────────
    if tool_or_skip dnsrecon "DNS brute force/enumeration"; then
        divider
        echo -e "${BOLD}[3/7] dnsrecon${NC}"
        explain "Comprehensive DNS enumeration: standard records, reverse, brute, zone transfer."
        echo ""

        for domain in "${domains[@]:-}"; do
            [[ -z "$domain" ]] && continue
            local out="${outdir}/dnsrecon_${domain}.txt"
            run_cmd "${out}" dnsrecon -d "${domain}" -t std,axfr,brt \
                --xml "${outdir}/dnsrecon_${domain}.xml" 2>/dev/null || true
        done
    fi

    # ── theHarvester ─────────────────────────────────────────────────────────
    if tool_or_skip theHarvester "OSINT email/hostname harvesting"; then
        divider
        echo -e "${BOLD}[4/7] theHarvester — OSINT${NC}"
        explain "Scrapes search engines for emails, subdomains, IPs linked to the target."
        explain "Sources: Google, Bing, DuckDuckGo, LinkedIn, Shodan, crt.sh"
        echo ""

        for domain in "${domains[@]:-}"; do
            [[ -z "$domain" ]] && continue
            local out="${outdir}/harvester_${domain}.txt"
            run_cmd "${out}" theHarvester \
                -d "${domain}" \
                -b google,bing,duckduckgo,crtsh \
                -f "${outdir}/harvester_${domain}" \
                -l 500 2>/dev/null || true
        done
    fi

    # ── Certificate Transparency ──────────────────────────────────────────────
    divider
    echo -e "${BOLD}[5/7] Certificate Transparency (crt.sh)${NC}"
    explain "Queries crt.sh for all SSL certs issued to the domain."
    explain "Often reveals subdomains that don't appear in DNS."
    echo ""

    if tool_or_skip curl "crt.sh queries"; then
        for domain in "${domains[@]:-}"; do
            [[ -z "$domain" ]] && continue
            local out="${outdir}/crtsh_${domain}.txt"
            info "crt.sh → ${domain}"
            curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
                python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = sorted(set(
        n.strip().lstrip('*.')
        for e in data
        for n in e.get('name_value','').split('\n')
    ))
    for n in names: print(n)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" | tee "${out}" 2>/dev/null || true

            local count; count=$(wc -l < "${out}" 2>/dev/null || echo 0)
            if [[ "${count}" -gt 0 ]]; then
                append_finding "INFO" "crt.sh: ${count} subdomains for ${domain}" \
                    "Full list in ${out}"
            fi
        done
    fi

    # ── Shodan ────────────────────────────────────────────────────────────────
    if [[ -n "${SHODAN_API_KEY:-}" ]] && tool_or_skip shodan "Shodan lookup"; then
        divider
        echo -e "${BOLD}[6/7] Shodan${NC}"
        explain "Queries Shodan's database for target IPs — shows banners, ports, vulns."
        echo ""

        for ip in "${ips[@]:-}"; do
            [[ -z "$ip" ]] && continue
            local out="${outdir}/shodan_${ip}.txt"
            run_cmd "${out}" shodan host "${ip}" 2>/dev/null || true

            if grep -qi "vulnerabilities\|CVE" "${out}" 2>/dev/null; then
                append_finding "HIGH" "Shodan: vulnerabilities listed for ${ip}" \
                    "Review ${out} for CVE details"
            fi
        done
    elif [[ -z "${SHODAN_API_KEY:-}" ]]; then
        warn "Shodan skipped — set SHODAN_API_KEY environment variable to enable"
        explain "Get a free key at: https://account.shodan.io"
    fi

    # ── Nmap List Scan (hostname resolution only) ─────────────────────────────
    if tool_or_skip nmap "hostname resolution"; then
        divider
        echo -e "${BOLD}[7/7] Nmap List Scan (hostname resolution, no probe)${NC}"
        explain "Resolves IPs to hostnames using DNS. Sends NO packets to targets."
        echo ""
        local out="${outdir}/nmap_listscan.txt"
        # shellcheck disable=SC2046
        run_cmd "${out}" nmap -sL -R \
            $(targets_nmap_list) 2>/dev/null || true
    fi

    success "Passive recon complete → ${outdir}"
    log "Passive recon complete"
}
