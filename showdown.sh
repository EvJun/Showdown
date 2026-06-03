#!/usr/bin/env bash
#
# ███████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
# ██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██║    ██║████╗  ██║
# ███████╗███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
# ╚════██║██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║
# ███████║██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
# ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
#
# Professional Pentest Framework v1.0
# FOR AUTHORIZED PENETRATION TESTING ONLY
#
# Usage:
#   ./showdown.sh                              # Interactive setup
#   ./showdown.sh -t targets.txt              # Load target list
#   ./showdown.sh -t targets.txt -m assisted  # Guided mode (default)
#   ./showdown.sh -t targets.txt -m manual    # Module picker
#   ./showdown.sh -t targets.txt -m auto      # Full pipeline, no prompts

# Note: strict mode (set -euo pipefail) is intentionally not used here.
# Many pentest tools return non-zero when finding nothing (nmap, grep, etc.)
# Modules handle their own errors explicitly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/assisted.sh
source "${SCRIPT_DIR}/lib/assisted.sh"

VERSION="1.0.0"
MODE="assisted"
TARGET_FILE=""
SESSION_NAME="pentest"
ENGAGEMENT_TYPE=""

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${RED}${BOLD}"
    cat << 'BANNER'
 ███████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
 ██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██║    ██║████╗  ██║
 ███████╗███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
 ╚════██║██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║
 ███████║██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
BANNER
    echo -e "${NC}${DIM}  Professional Pentest Framework v${VERSION}${NC}"
    echo -e "${RED}  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠${NC}"
    divider
}

# ─── Legal ────────────────────────────────────────────────────────────────────
legal_warning() {
    echo ""
    echo -e "${RED}${BOLD}  AUTHORIZATION REQUIRED${NC}"
    echo ""
    echo -e "${YELLOW}  This tool generates active network traffic, credential brute force,"
    echo -e "  exploit payloads, and other attack techniques."
    echo ""
    echo -e "  Unauthorized use is ILLEGAL under the Computer Fraud and Abuse Act,"
    echo -e "  Computer Misuse Act, and equivalent legislation worldwide."
    echo ""
    echo -e "  By continuing you confirm:${NC}"
    echo -e "  ${CYAN}[1]${NC} You hold written authorization for all target systems"
    echo -e "  ${CYAN}[2]${NC} You will operate within the agreed Rules of Engagement"
    echo -e "  ${CYAN}[3]${NC} You accept full legal responsibility for your actions"
    echo ""
    if ! confirm "  I confirm authorization and will operate within RoE. Continue?"; then
        echo "  Exiting. Obtain written authorization before testing."
        exit 0
    fi
    echo ""
}

# ─── Args ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}SHOWDOWN Pentest Framework${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    table_row "-t, --targets <file>"  "Target IPs/CIDRs (one per line, # for comments)"
    table_row "-m, --mode <mode>"     "assisted | manual | auto  (default: assisted)"
    table_row "-s, --session <name>"  "Session name for output directory"
    table_row "-i, --internal"        "Internal engagement (on-LAN; enables broadcast tools)"
    table_row "-e, --external"        "External engagement (internet-facing; disables broadcast tools)"
    table_row "-h, --help"            "This help"
    echo ""
    echo -e "${BOLD}Modes:${NC}"
    table_row "assisted"  "Step-by-step with explanations and per-step confirmation"
    table_row "manual"    "Pick and run specific modules from a menu"
    table_row "auto"      "Run full recon→scan→exploit pipeline automatically"
    echo ""
    echo -e "${BOLD}Target file format:${NC}"
    echo "  # Comments supported"
    echo "  192.168.1.0/24"
    echo "  10.0.0.1"
    echo "  10.0.0.50-100"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--targets)  TARGET_FILE="$2";       shift 2 ;;
            -m|--mode)     MODE="$2";             shift 2 ;;
            -s|--session)  SESSION_NAME="$2";     shift 2 ;;
            -i|--internal) ENGAGEMENT_TYPE="internal"; shift ;;
            -e|--external) ENGAGEMENT_TYPE="external"; shift ;;
            -h|--help)     usage; exit 0 ;;
            *) error "Unknown argument: $1"; usage; exit 1 ;;
        esac
    done
}

# ─── Engagement type ──────────────────────────────────────────────────────────
setup_engagement() {
    if [[ -z "${ENGAGEMENT_TYPE}" ]]; then
        echo ""
        section "ENGAGEMENT TYPE"
        echo -e "  ${CYAN}1)${NC} ${BOLD}Internal${NC}  - machine is on (or VPN'd into) the target's LAN"
        echo -e "             ${DIM}Enables broadcast tools: Responder, LLMNR/NBT-NS poisoning${NC}"
        echo -e "  ${CYAN}2)${NC} ${BOLD}External${NC}  - testing internet-facing systems from outside"
        echo -e "             ${DIM}Broadcast/LAN tools will be blocked - not applicable${NC}"
        echo ""
        while true; do
            echo -n "  Choice [1-2]: "
            read -r _eng_choice
            case "${_eng_choice}" in
                1) ENGAGEMENT_TYPE="internal";  break ;;
                2) ENGAGEMENT_TYPE="external";  break ;;
                *) warn "Enter 1 or 2" ;;
            esac
        done
    fi

    echo ""
    if [[ "${ENGAGEMENT_TYPE}" == "internal" ]]; then
        echo -e "${RED}${BOLD}  ⚠  INTERNAL ENGAGEMENT - NETWORK IMPACT WARNING${NC}"
        echo ""
        echo -e "${YELLOW}  Some modules (Responder, LLMNR/NBT-NS poisoning) broadcast on your local"
        echo -e "  network segment and will affect EVERY host on that segment - not only the"
        echo -e "  declared targets. Running these from your own office or home network will"
        echo -e "  capture hashes from your colleagues and disrupt normal operations."
        echo ""
        echo -e "  Before running any broadcast module confirm:"
        echo -e "${NC}  ${CYAN}[1]${NC} Your machine is physically or via VPN on the CLIENT'S network"
        echo -e "  ${CYAN}[2]${NC} The agreed scope covers this network segment"
        echo -e "  ${CYAN}[3]${NC} You have read the remediation guide: ${BOLD}sop/REMEDIATION.md${NC}"
        echo ""
        if ! confirm "  Confirmed - I am on the target network. Continue?"; then
            echo "  Connect to the target network first, then rerun."
            exit 0
        fi
    else
        info "External engagement - broadcast and LAN-only modules will be blocked."
    fi
    echo ""
}

# ─── Target setup ─────────────────────────────────────────────────────────────
setup_targets() {
    if [[ -n "${TARGET_FILE}" ]]; then
        load_targets "${TARGET_FILE}"
    else
        echo ""
        ask "Path to targets file (one IP/CIDR per line):"
        read -r TARGET_FILE
        if [[ -f "${TARGET_FILE}" ]]; then
            load_targets "${TARGET_FILE}"
        else
            ask "Or enter targets manually (comma-separated):"
            read -r raw
            IFS=',' read -ra TARGETS <<< "${raw}"
            success "Loaded ${#TARGETS[@]} target(s)"
        fi
    fi

    echo ""
    info "Targets:"
    for t in "${TARGETS[@]}"; do echo -e "  ${CYAN}→${NC} ${t}"; done
    echo ""
}

# ─── Module registry ──────────────────────────────────────────────────────────
declare -A MODULE_SCRIPT
declare -A MODULE_DESC
declare -A MODULE_PHASE

register_modules() {
    local b="${SCRIPT_DIR}/modules"

    MODULE_SCRIPT[passive_recon]="${b}/00_recon/passive_recon.sh"
    MODULE_DESC[passive_recon]="OSINT, DNS, WHOIS, Shodan, cert transparency"
    MODULE_PHASE[passive_recon]="Recon"

    MODULE_SCRIPT[active_recon]="${b}/00_recon/active_recon.sh"
    MODULE_DESC[active_recon]="Ping sweep, ARP scan, host discovery"
    MODULE_PHASE[active_recon]="Recon"

    MODULE_SCRIPT[port_scan]="${b}/01_scan/port_scan.sh"
    MODULE_DESC[port_scan]="TCP/UDP port scan, service/OS detection"
    MODULE_PHASE[port_scan]="Scan"

    MODULE_SCRIPT[vuln_scan]="${b}/01_scan/vuln_scan.sh"
    MODULE_DESC[vuln_scan]="Nuclei, Nmap vuln scripts, Nikto"
    MODULE_PHASE[vuln_scan]="Scan"

    MODULE_SCRIPT[web_enum]="${b}/02_web/web_enum.sh"
    MODULE_DESC[web_enum]="Dir brute, tech detection, WPScan, SSL check"
    MODULE_PHASE[web_enum]="Web"

    MODULE_SCRIPT[webcam_attack]="${b}/02_web/webcam_attack.sh"
    MODULE_DESC[webcam_attack]="Camera discovery, default creds, RTSP, CVEs"
    MODULE_PHASE[webcam_attack]="Web/IoT"

    MODULE_SCRIPT[smb_attacks]="${b}/03_exploit/smb_attacks.sh"
    MODULE_DESC[smb_attacks]="SMB enum, null sessions, EternalBlue, CME"
    MODULE_PHASE[smb_attacks]="Exploit"

    MODULE_SCRIPT[brute_force]="${b}/03_exploit/brute_force.sh"
    MODULE_DESC[brute_force]="Hydra credential attacks: SSH FTP HTTP RDP SMB"
    MODULE_PHASE[brute_force]="Exploit"

    MODULE_SCRIPT[lateral_movement]="${b}/04_lateral/lateral_movement.sh"
    MODULE_DESC[lateral_movement]="Responder, Pass-the-Hash, BloodHound, CME"
    MODULE_PHASE[lateral_movement]="Lateral"

    MODULE_SCRIPT[post_exploit]="${b}/05_post/post_exploit.sh"
    MODULE_DESC[post_exploit]="Secretsdump, cred hunt, sensitive file search"
    MODULE_PHASE[post_exploit]="Post"
}

run_module() {
    local name="$1"
    local script="${MODULE_SCRIPT[$name]:-}"
    if [[ -z "${script}" ]] || [[ ! -f "${script}" ]]; then
        error "Module not found: ${name}"
        return 1
    fi
    # shellcheck source=/dev/null
    source "${script}"
    run_module_main
}

# ─── Manual mode ──────────────────────────────────────────────────────────────
manual_mode() {
    section "MANUAL MODE - Module Picker"
    info "Select modules individually. Results saved to session directory."

    while true; do
        echo ""
        divider
        echo -e "${BOLD}  Available Modules:${NC}"
        echo ""

        local i=1
        local -a keys
        mapfile -t keys < <(printf '%s\n' "${!MODULE_SCRIPT[@]}" | sort)

        for name in "${keys[@]}"; do
            local phase="${MODULE_PHASE[$name]}"
            local desc="${MODULE_DESC[$name]}"
            printf "  ${CYAN}%2d)${NC} ${BOLD}%-20s${NC} ${DIM}[%-9s]${NC} %s\n" \
                "$i" "$name" "$phase" "$desc"
            ((i++))
        done

        echo ""
        echo -e "  ${CYAN} 0)${NC} Exit"
        echo ""
        echo -n "  Choice [0-$((i-1))]: "
        read -r choice

        [[ "$choice" == "0" ]] && break

        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#keys[@]}" ]]; then
            local sel="${keys[$((choice-1))]}"
            section "Running: ${sel}"
            info "${MODULE_DESC[$sel]}"
            echo ""
            run_module "${sel}"
        else
            warn "Invalid choice: ${choice}"
        fi
    done
}

# ─── Auto mode ────────────────────────────────────────────────────────────────
auto_mode() {
    section "AUTO MODE - Full Pipeline"
    warn "This runs the full attack chain against all targets."
    warn "All phases fire automatically."
    echo ""
    if ! confirm "Run full pipeline on ${#TARGETS[@]} target(s)?"; then
        info "Cancelled."
        return
    fi

    local pipeline=(
        passive_recon
        active_recon
        port_scan
        vuln_scan
        web_enum
        webcam_attack
        smb_attacks
        brute_force
    )

    for mod in "${pipeline[@]}"; do
        section "▶ ${mod}"
        info "${MODULE_DESC[$mod]}"
        echo ""
        run_module "${mod}" || warn "Module ${mod} reported errors - continuing"
        echo ""
    done

    success "Pipeline complete → ${SESSION_DIR}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    print_banner
    parse_args "$@"
    legal_warning
    setup_engagement
    setup_targets
    init_session "${SESSION_NAME}"
    register_modules

    # Copy/save target list into session
    printf '%s\n' "${TARGETS[@]}" > "${SESSION_DIR}/targets.txt"
    [[ -f "${TARGET_FILE:-}" ]] && cp "${TARGET_FILE}" "${SESSION_DIR}/targets_original.txt"

    echo ""
    section "SESSION READY"
    table_row "Session"    "${SESSION_DIR}"
    table_row "Mode"       "${MODE}"
    table_row "Engagement" "${ENGAGEMENT_TYPE}"
    table_row "Targets"    "${#TARGETS[@]}"
    echo ""

    case "${MODE}" in
        assisted) assisted_mode ;;
        manual)   manual_mode ;;
        auto)     auto_mode ;;
        *)
            error "Unknown mode: ${MODE}"
            usage
            exit 1
            ;;
    esac

    echo ""
    success "Done. Session data: ${SESSION_DIR}"
    info   "Findings report:   ${SESSION_DIR}/findings.md"
}

main "$@"
