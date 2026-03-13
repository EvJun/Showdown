#!/usr/bin/env bash
# lib/common.sh — Shared utilities for SHOWDOWN framework

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Print helpers ────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*" >&2; }
explain() { echo -e "    ${DIM}ℹ  $*${NC}"; }
ask()     { echo -e "${YELLOW}${BOLD}[?]${NC} $*"; }
divider() { echo -e "${DIM}────────────────────────────────────────────────────${NC}"; }
section() { echo -e "\n${MAGENTA}${BOLD}▶ $*${NC}\n"; }
table_row() { printf "  ${CYAN}%-24s${NC} %s\n" "$1" "$2"; }

# ─── Session ──────────────────────────────────────────────────────────────────
SESSION_DIR=""
LOG_FILE=""

init_session() {
    local name="${1:-pentest}"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    SESSION_DIR="${SCRIPT_DIR}/sessions/${name}_${ts}"
    mkdir -p "${SESSION_DIR}"/{recon,scan,web,exploit,lateral,post,loot,creds}
    LOG_FILE="${SESSION_DIR}/showdown.log"
    printf '# SHOWDOWN SESSION\nStarted: %s\nTargets: %s\n\n' \
        "$(date)" "${TARGETS[*]}" > "${SESSION_DIR}/findings.md"
    echo "SESSION: ${name}_${ts} started at $(date)" >> "${LOG_FILE}"
    success "Session: ${SESSION_DIR}"
}

log() { if [[ -n "${LOG_FILE}" ]]; then echo "[$(date +%H:%M:%S)] $*" >> "${LOG_FILE}"; fi; }

# ─── Targets ──────────────────────────────────────────────────────────────────
TARGET_FILE=""
TARGETS=()

load_targets() {
    TARGET_FILE="$1"
    if [[ ! -f "$TARGET_FILE" ]]; then error "File not found: $TARGET_FILE"; return 1; fi
    mapfile -t TARGETS < <(grep -v '^#' "$TARGET_FILE" | grep -v '^[[:space:]]*$' | tr -d '[:space:]')
    success "Loaded ${#TARGETS[@]} target(s) from ${TARGET_FILE}"
    log "Targets: ${TARGETS[*]}"
}

targets_nmap_list() {
    # Returns space-separated list safe for nmap
    printf '%s ' "${TARGETS[@]}"
}

# ─── Tool checks ──────────────────────────────────────────────────────────────
check_tool()   { command -v "$1" &>/dev/null; }
require_tool() {
    if ! command -v "$1" &>/dev/null; then
        error "Tool not found: $1  (run ./install_deps.sh)"
        return 1
    fi
}

tool_or_skip() {
    # tool_or_skip <tool> <description>
    if ! command -v "$1" &>/dev/null; then
        warn "Skipping — $1 not installed ($2)"
        return 1
    fi
    return 0
}

# ─── Command runner ───────────────────────────────────────────────────────────
# run_cmd <outfile> <cmd...>  — runs, tees to screen+log+outfile
run_cmd() {
    local outfile="$1"; shift
    info "CMD: $*"
    log "CMD: $*  OUT: ${outfile}"
    # shellcheck disable=SC2068
    "$@" 2>&1 | tee -a "${outfile}"
    local rc="${PIPESTATUS[0]}"
    log "EXIT: ${rc}"
    [[ $rc -eq 0 ]] && success "Done → $(basename "${outfile}")" \
                    || warn "Exited ${rc}: $*"
    return $rc
}

# run_bg <outfile> <cmd...>  — runs in background, prints PID
run_bg() {
    local outfile="$1"; shift
    info "BG: $*"
    log "BG: $*  OUT: ${outfile}"
    "$@" &>> "${outfile}" &
    echo $!
}

# ─── Prompts ──────────────────────────────────────────────────────────────────
confirm() {
    local msg="${1:-Continue?}"
    local yn
    echo -ne "${YELLOW}[?]${NC} ${msg} ${DIM}[y/N]${NC} "
    read -r yn
    [[ "$yn" =~ ^[Yy]$ ]]
}

choose_number() {
    local max="$1"
    local choice
    while true; do
        echo -n "Choice [1-${max}]: "
        read -r choice
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$max" ]] && break
        warn "Enter a number between 1 and ${max}"
    done
    echo "$choice"
}

prompt_creds() {
    # Sets CRED_USER and CRED_PASS
    echo -n "Username: "; read -r CRED_USER
    echo -n "Password: "; read -rs CRED_PASS; echo
}

pause() { echo -e "${DIM}  [Enter to continue]${NC}"; read -r; }

# ─── Wordlists ────────────────────────────────────────────────────────────────
find_wordlist() {
    local name="$1"
    local paths=(
        "/usr/share/seclists/${name}"
        "/usr/share/wordlists/${name}"
        "/opt/SecLists/${name}"
        "${SCRIPT_DIR}/wordlists/${name}"
    )
    for p in "${paths[@]}"; do
        [[ -f "$p" ]] && { echo "$p"; return 0; }
    done
    return 1
}

wl_web_dirs() {
    find_wordlist "Discovery/Web-Content/raft-medium-directories.txt" 2>/dev/null ||
    find_wordlist "Discovery/Web-Content/common.txt" 2>/dev/null ||
    find_wordlist "dirb/common.txt" 2>/dev/null || echo ""
}

wl_web_files() {
    find_wordlist "Discovery/Web-Content/raft-medium-files.txt" 2>/dev/null ||
    find_wordlist "Discovery/Web-Content/raft-small-files.txt" 2>/dev/null || echo ""
}

wl_passwords() {
    find_wordlist "Passwords/Common-Credentials/10k-most-common.txt" 2>/dev/null ||
    find_wordlist "Passwords/Leaked-Databases/rockyou.txt.tar.gz" 2>/dev/null ||
    find_wordlist "rockyou.txt" 2>/dev/null || echo "/usr/share/wordlists/rockyou.txt"
}

wl_usernames() {
    find_wordlist "Usernames/Names/names.txt" 2>/dev/null ||
    find_wordlist "Usernames/top-usernames-shortlist.txt" 2>/dev/null || echo ""
}

# ─── Findings report ──────────────────────────────────────────────────────────
append_finding() {
    local severity="$1"  # CRITICAL HIGH MEDIUM LOW INFO
    local title="$2"
    local detail="$3"
    local report="${SESSION_DIR}/findings.md"
    {
        echo "## [${severity}] ${title}"
        echo "- **Time**: $(date)"
        echo "- **Detail**: ${detail}"
        echo ""
    } >> "${report}"
    case "${severity}" in
        CRITICAL) error  "FINDING [${severity}] ${title}" ;;
        HIGH)     warn   "FINDING [${severity}] ${title}" ;;
        MEDIUM)   warn   "FINDING [${severity}] ${title}" ;;
        *)        info   "FINDING [${severity}] ${title}" ;;
    esac
}

# ─── Port/service helpers ─────────────────────────────────────────────────────
HTTP_PORTS=(80 443 8080 8443 8008 8888 9090 9443 3000 5000 7080 7443)
SMB_PORTS=(139 445)
CAMERA_PORTS=(554 8554 80 8080 8443 37777 34567 8000 10554 4550 7070 88 8888 2000 56000)

is_http_port() {
    local p="$1"
    for hp in "${HTTP_PORTS[@]}"; do [[ "$p" == "$hp" ]] && return 0; done
    return 1
}

proto_for_port() {
    case "$1" in
        443|8443|9443|7443) echo "https" ;;
        *) echo "http" ;;
    esac
}
