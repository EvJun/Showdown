#!/usr/bin/env bash
# modules/02_web/web_enum.sh
#
# WEB APPLICATION ENUMERATION
# Fingerprints web apps, brute-forces directories, checks for CMS, SSL issues.
#
# Tools used:
#   whatweb       — Technology fingerprinting (CMS, framework, server, plugins)
#   gobuster      — Directory/file/vhost brute-forcer
#   feroxbuster   — Recursive directory brute-force (smarter than gobuster for deep paths)
#   ffuf          — Fast web fuzzer (directories, parameters, virtual hosts)
#   wpscan        — WordPress-specific vulnerability scanner
#   nikto         — General web server vuln scanner (also run in vuln_scan but useful here)
#   sslscan       — SSL/TLS cipher suite analysis
#   testssl.sh    — Comprehensive TLS testing
#   curl          — Manual inspection of specific responses

run_module_main() {
    local outdir="${SESSION_DIR}/web"
    section "Web Application Enumeration"
    echo ""

    # Discover web hosts: nmap results first, then fallback to targets
    local -a web_targets  # "http://ip:port" or "https://ip:port"
    web_targets=()
    discover_web_targets

    if [[ ${#web_targets[@]} -eq 0 ]]; then
        warn "No web targets discovered. Add targets manually?"
        if confirm "Enter web targets manually?"; then
            local manual
            ask "Enter URLs comma-separated (e.g. http://192.168.1.1,https://192.168.1.2:8443):"
            read -r manual
            IFS=',' read -ra web_targets <<< "${manual}"
        else
            info "Skipping web enumeration"
            return
        fi
    fi

    echo ""
    info "Web targets to enumerate:"
    for wt in "${web_targets[@]}"; do echo -e "  ${CYAN}→${NC} ${wt}"; done
    echo ""

    for target_url in "${web_targets[@]}"; do
        local host_label; host_label=$(echo "${target_url}" | sed 's|[:/]|_|g')
        local tdir="${outdir}/${host_label}"
        mkdir -p "${tdir}"

        echo ""
        divider
        echo -e "${BOLD}Target: ${CYAN}${target_url}${NC}"
        divider

        # ── whatweb ──────────────────────────────────────────────────────────
        if tool_or_skip whatweb "tech fingerprinting"; then
            echo -e "\n${BOLD}[1] whatweb — Technology Fingerprint${NC}"
            explain "Identifies: web server, CMS, programming language, plugins, jQuery version"
            explain "Useful for knowing which vuln scanner or exploit to use next"
            run_cmd "${tdir}/whatweb.txt" whatweb \
                --color=never \
                -v \
                -a 3 \
                "${target_url}" \
                2>/dev/null || true
        fi

        # ── SSL Check ─────────────────────────────────────────────────────────
        if [[ "${target_url}" =~ ^https ]]; then
            echo -e "\n${BOLD}[2] SSL/TLS Analysis${NC}"
            explain "Checks for: weak ciphers, SSLv3/TLSv1.0, expired certs, POODLE, BEAST"
            ssl_check "${target_url}" "${tdir}"
        fi

        # ── Directory Brute Force ──────────────────────────────────────────────
        echo -e "\n${BOLD}[3] Directory Enumeration${NC}"
        explain "Brute-forces directory and file names to find hidden paths"
        explain "Look for: /admin, /backup, /.git, /api, /config, /wp-admin"
        echo ""

        local wl_dirs; wl_dirs=$(wl_web_dirs)
        if [[ -z "${wl_dirs}" ]]; then
            warn "No wordlist found. Install seclists: apt install seclists"
        else
            # Prefer feroxbuster (recursive) over gobuster
            if tool_or_skip feroxbuster "recursive directory brute-force"; then
                echo -e "${DIM}  Using feroxbuster (recursive)${NC}"
                run_cmd "${tdir}/feroxbuster.txt" feroxbuster \
                    --url "${target_url}" \
                    --wordlist "${wl_dirs}" \
                    --no-recursion \
                    --depth 3 \
                    --threads 30 \
                    --status-codes 200,204,301,302,307,401,403 \
                    --output "${tdir}/feroxbuster.txt" \
                    --quiet \
                    2>/dev/null || true

            elif tool_or_skip gobuster "directory brute-force"; then
                echo -e "${DIM}  Using gobuster${NC}"
                run_cmd "${tdir}/gobuster_dirs.txt" gobuster dir \
                    --url "${target_url}" \
                    --wordlist "${wl_dirs}" \
                    --threads 30 \
                    --status-codes 200,204,301,302,307,401,403 \
                    --no-error \
                    --output "${tdir}/gobuster_dirs.txt" \
                    2>/dev/null || true
            fi

            # Check for interesting paths
            flag_interesting_paths "${tdir}"
        fi

        # ── FFUF — Parameter fuzzing ──────────────────────────────────────────
        if tool_or_skip ffuf "web fuzzing"; then
            echo -e "\n${BOLD}[4] ffuf — Parameter & Path Fuzzing${NC}"
            explain "Fuzzes query parameters, hidden endpoints, and vhosts"
            if confirm "  Run ffuf parameter fuzzing on ${target_url}?"; then
                local wl_files; wl_files=$(wl_web_files)
                [[ -z "${wl_files}" ]] && wl_files="${wl_dirs}"

                run_cmd "${tdir}/ffuf_files.txt" ffuf \
                    -u "${target_url}/FUZZ" \
                    -w "${wl_dirs}" \
                    -mc 200,204,301,302,307,401,403 \
                    -t 40 \
                    -o "${tdir}/ffuf_output.json" \
                    -of json \
                    -s \
                    2>/dev/null || true
            fi
        fi

        # ── WPScan ────────────────────────────────────────────────────────────
        # Only if WordPress detected
        if grep -qi "wordpress\|wp-content\|wp-login" "${tdir}/whatweb.txt" 2>/dev/null || \
           curl -sk --max-time 5 "${target_url}/wp-login.php" 2>/dev/null | grep -qi "wordpress"; then
            echo -e "\n${BOLD}[5] WPScan — WordPress Specific${NC}"
            explain "Enumerates: WP version, plugins, themes, users, known CVEs"
            explain "Can enumerate users for password spraying"
            if tool_or_skip wpscan "WordPress scanner"; then
                local wpscan_cmd=(wpscan
                    --url "${target_url}"
                    --enumerate u,p,t,cb,dbe
                    --detection-mode aggressive
                    --output "${tdir}/wpscan.txt"
                    --format cli-no-colour)

                [[ -n "${WPSCAN_API_TOKEN:-}" ]] && \
                    wpscan_cmd+=(--api-token "${WPSCAN_API_TOKEN}")

                run_cmd "${tdir}/wpscan.txt" "${wpscan_cmd[@]}" 2>/dev/null || true

                append_finding "INFO" "WordPress detected at ${target_url}" \
                    "WPScan results in ${tdir}/wpscan.txt"
            fi
        fi

        # ── robots.txt / sitemap ──────────────────────────────────────────────
        echo -e "\n${BOLD}[6] Quick Manual Checks${NC}"
        for path in robots.txt sitemap.xml .htaccess crossdomain.xml security.txt \
                    server-status server-info phpinfo.php admin/ administrator/ \
                    backup/ .git/HEAD .env web.config; do
            local url="${target_url}/${path}"
            local code; code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "${url}" 2>/dev/null || echo 0)
            if [[ "${code}" != "404" ]] && [[ "${code}" != "0" ]]; then
                echo -e "  ${GREEN}[${code}]${NC} ${url}"
                curl -sk --max-time 5 "${url}" >> "${tdir}/manual_checks.txt" 2>/dev/null || true
                if [[ "${code}" == "200" ]]; then
                    append_finding "MEDIUM" "Sensitive path accessible: ${path} on ${target_url}" \
                        "HTTP ${code} — manual review needed. File: ${tdir}/manual_checks.txt"
                fi
            fi
        done
    done

    success "Web enumeration complete → ${outdir}"
    log "Web enum complete"
}

# ─── Discover web targets from nmap results and targets list ──────────────────
discover_web_targets() {
    local gnmap="${SESSION_DIR}/scan/nmap_scan.gnmap"

    if [[ -f "${gnmap}" ]]; then
        while IFS= read -r line; do
            [[ "${line}" =~ ^Host: ]] || continue
            local ip; ip=$(echo "${line}" | awk '{print $2}')
            for hp in "${HTTP_PORTS[@]}"; do
                if echo "${line}" | grep -q "${hp}/open"; then
                    local proto; proto=$(proto_for_port "${hp}")
                    web_targets+=("${proto}://${ip}:${hp}")
                fi
            done
        done < "${gnmap}"
    else
        # No nmap data — try common ports on all targets
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            for hp in 80 443 8080 8443; do
                if timeout 3 bash -c "echo > /dev/tcp/${host}/${hp}" 2>/dev/null; then
                    local proto; proto=$(proto_for_port "${hp}")
                    web_targets+=("${proto}://${host}:${hp}")
                fi
            done
        done < "${SESSION_DIR}/targets.txt"
    fi
}

# ─── SSL/TLS check ────────────────────────────────────────────────────────────
ssl_check() {
    local url="$1" tdir="$2"
    local host; host=$(echo "${url}" | sed 's|https\?://||' | cut -d: -f1)
    local port; port=$(echo "${url}" | grep -oP ':\d+$' | tr -d ':')
    port="${port:-443}"

    if tool_or_skip sslscan "SSL cipher analysis"; then
        run_cmd "${tdir}/sslscan.txt" sslscan \
            --no-colour \
            "${host}:${port}" \
            2>/dev/null || true

        if grep -qi "SSLv3\|TLSv1\.0\|3DES\|RC4\|NULL\|EXPORT" "${tdir}/sslscan.txt" 2>/dev/null; then
            append_finding "HIGH" "Weak SSL/TLS on ${host}:${port}" \
                "Weak ciphers or old protocol versions found — see ${tdir}/sslscan.txt"
        fi
        if grep -qi "Heartbleed" "${tdir}/sslscan.txt" 2>/dev/null; then
            append_finding "CRITICAL" "Heartbleed on ${host}:${port}" \
                "OpenSSL Heartbleed vulnerability detected"
        fi
    elif tool_or_skip testssl.sh "comprehensive TLS test"; then
        run_cmd "${tdir}/testssl.txt" testssl.sh --quiet --color 0 \
            "${host}:${port}" 2>/dev/null || true
    fi
}

# ─── Flag interesting discovered paths ────────────────────────────────────────
flag_interesting_paths() {
    local tdir="$1"
    local results_file
    results_file=$(ls "${tdir}"/feroxbuster.txt "${tdir}"/gobuster_dirs.txt 2>/dev/null | head -1)
    [[ -z "${results_file}" ]] && return

    local interesting=(admin administrator login wp-admin phpmyadmin panel
                        dashboard api config backup db database .git .env
                        console webmin cpanel manager test dev staging)
    for pattern in "${interesting[@]}"; do
        if grep -qi "/${pattern}" "${results_file}" 2>/dev/null; then
            local url; url=$(grep -i "/${pattern}" "${results_file}" | head -1 | grep -oP 'https?://[^\s]+' | head -1)
            append_finding "MEDIUM" "Interesting path found: /${pattern}" \
                "URL: ${url} — manual investigation required"
        fi
    done
}
