#!/usr/bin/env bash
# --------------------------------------------
# Bug Bounty Recon Framework (fixed)
# Author: Inayat Hussain (Security Researcher)
# Maintainer: cleaned by assistant
# --------------------------------------------

set -euo pipefail
IFS=$'\n\t'

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
CYAN="\033[1;36m"
RESET="\033[0m"

BANNER() {
    echo -e "${GREEN}"
    cat <<'B'
╔══════════════════════════════════════════════════╗
║     Bug Bounty Recon Framework                   ║
║     Author: Inayat Hussain (Security Researcher) ║
╚══════════════════════════════════════════════════╝
B
    echo -e "${RESET}"
}

# install_if_missing <binary-name> [go-package]
# If binary missing, try to `go install <go-package>@latest`.
# If go-package omitted, use binary-name as package (best-effort).
install_if_missing() {
    local bin="$1"
    local pkg="${2:-$1}"

    if command -v "$bin" &>/dev/null; then
        echo -e "${GREEN}[-] $bin already installed.${RESET}"
        return 0
    fi

    if ! command -v go &>/dev/null; then
        echo -e "${YELLOW}[!] 'go' not found; skipping auto-install of $bin. Please install Go and run this script again to auto-install missing tools.${RESET}"
        return 1
    fi

    echo -e "${YELLOW}[+] Installing $bin from $pkg ...${RESET}"

    # try to use GOBIN if set, else GOPATH/bin, else default to $(go env GOPATH)/bin
    local gobin
    gobin="$(go env GOBIN 2>/dev/null || true)"
    if [ -z "$gobin" ]; then
        local gopath
        gopath="$(go env GOPATH 2>/dev/null || true)"
        if [ -n "$gopath" ]; then
            gobin="$gopath/bin"
        else
            # fallback to $HOME/go/bin which is usual default
            gobin="$HOME/go/bin"
        fi
    fi

    # ensure dir exists
    mkdir -p "$gobin"

    # attempt install; do not fail the whole script if install fails
    if go install "${pkg}@latest"; then
        export PATH="$PATH:$gobin"
        echo -e "${GREEN}[+] Installed $bin (ensure $gobin is in your PATH permanently).${RESET}"
        return 0
    else
        echo -e "${RED}[!] Failed to install $bin from $pkg. Please install it manually.${RESET}"
        return 1
    fi
}

setup_tools() {
    echo -e "${CYAN}[*] Checking required tools...${RESET}"

    # Minimal required commands for the script to work sensibly
    local required=(git)
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${YELLOW}[!] $cmd is not installed. Some features may be skipped. Please install $cmd if you plan to use all features.${RESET}"
        fi
    done

    # Try to auto-install common Go-based tools (best-effort)
    install_if_missing waybackurls github.com/tomnomnom/waybackurls
    install_if_missing gau github.com/lc/gau/v2/cmd/gau || install_if_missing gau github.com/lc/gau
    install_if_missing gf github.com/tomnomnom/gf
    install_if_missing qsreplace github.com/tomnomnom/qsreplace
    install_if_missing httpx github.com/projectdiscovery/httpx/cmd/httpx
    install_if_missing nuclei github.com/projectdiscovery/nuclei/v2/cmd/nuclei
    install_if_missing dalfox github.com/hahwul/dalfox/v2

    # GF patterns
    if [ ! -d "${HOME}/.gf" ]; then
        if command -v git &>/dev/null; then
            echo -e "${YELLOW}[+] Cloning GF patterns...${RESET}"
            git clone https://github.com/1ndianl33t/Gf-Patterns "${HOME}/.gf" || echo -e "${YELLOW}[!] Failed to clone GF patterns. You can clone manually to ${HOME}/.gf${RESET}"
        else
            echo -e "${YELLOW}[!] git not available: skipping GF pattern clone.${RESET}"
        fi
    else
        echo -e "${GREEN}[-] GF patterns already present at ${HOME}/.gf${RESET}"
    fi
}

collect_urls() {
    echo -e "${CYAN}[*] Collecting URLs for $DOMAIN...${RESET}"

    if ! command -v waybackurls &>/dev/null && ! command -v gau &>/dev/null; then
        echo -e "${RED}[!] neither waybackurls nor gau installed — cannot collect historical URLs.${RESET}"
        return 1
    fi

    if command -v waybackurls &>/dev/null; then
        waybackurls "$DOMAIN" > "$OUTDIR/wayback.txt" || true
    else
        : > "$OUTDIR/wayback.txt"
    fi

    if command -v gau &>/dev/null; then
        gau "$DOMAIN" > "$OUTDIR/gau.txt" || true
    else
        : > "$OUTDIR/gau.txt"
    fi

    # combine and keep only parameterized URLs (containing '=')
    cat "$OUTDIR/wayback.txt" "$OUTDIR/gau.txt" 2>/dev/null | sort -u | grep "=" > "$OUTDIR/params.txt" || : 
    echo -e "${GREEN}[+] Found $(wc -l < "$OUTDIR/params.txt" 2>/dev/null || echo 0) parameterized URLs.${RESET}"
}

run_gf_scans() {
    echo -e "${CYAN}[*] Scanning with GF patterns...${RESET}"

    if ! command -v gf &>/dev/null; then
        echo -e "${YELLOW}[!] gf not installed — skipping GF scans.${RESET}"
        return 0
    fi

    declare -A vulns=(
        ["XSS"]="xss"
        ["SQLi"]="sqli"
        ["SSRF"]="ssrf"
        ["LFI"]="lfi"
        ["RCE"]="rce"
        ["IDOR"]="idor"
        ["Open Redirect"]="redirect"
    )

    for vuln in "${!vulns[@]}"; do
        pattern="${vulns[$vuln]}"
        out="$OUTDIR/$pattern.txt"
        # run gf only if params file exists and is non-empty
        if [ -s "$OUTDIR/params.txt" ]; then
            gf "$pattern" < "$OUTDIR/params.txt" >"$out" 2>/dev/null || true
            count=0
            if [ -f "$out" ]; then
                count=$(wc -l < "$out" || echo 0)
            fi
            if [ "$count" -gt 0 ]; then
                echo -e "${RED}[!] $vuln: $count possible findings (saved to $out)${RESET}"
            else
                rm -f "$out" || true
            fi
        else
            echo -e "${YELLOW}[!] No parameterized URLs to scan for GF patterns.${RESET}"
            break
        fi
    done
}

run_active_scans() {
    echo -e "${CYAN}[*] Running httpx for live host detection...${RESET}"

    if ! command -v httpx &>/dev/null; then
        echo -e "${YELLOW}[!] httpx not found. Skipping live detection.${RESET}"
    else
        if [ -s "$OUTDIR/params.txt" ]; then
            httpx -l "$OUTDIR/params.txt" -silent -o "$OUTDIR/live.txt" || : 
        else
            : > "$OUTDIR/live.txt"
        fi
    fi

    if command -v nuclei &>/dev/null && [ -s "$OUTDIR/live.txt" ]; then
        echo -e "${CYAN}[*] Running nuclei on live URLs...${RESET}"
        nuclei -l "$OUTDIR/live.txt" -o "$OUTDIR/nuclei-results.txt" || :
    else
        echo -e "${YELLOW}[!] nuclei not installed or no live URLs found — skipping nuclei.${RESET}"
    fi

    if command -v dalfox &>/dev/null && [ -s "$OUTDIR/params.txt" ]; then
        echo -e "${CYAN}[*] Running dalfox for XSS scanning...${RESET}"
        dalfox file "$OUTDIR/params.txt" -o "$OUTDIR/dalfox-xss.txt" || :
    else
        echo -e "${YELLOW}[!] dalfox not installed or no params file — skipping dalfox.${RESET}"
    fi
}

run_shodan_scan() {
    if command -v shodan &>/dev/null; then
        echo -e "${CYAN}[*] Running Shodan scan (requires API key)...${RESET}"
        if command -v dig &>/dev/null; then
            IP=$(dig +short "$DOMAIN" | head -n 1 || true)
            if [ -n "$IP" ]; then
                shodan host "$IP" > "$OUTDIR/shodan.txt" || :
            else
                echo -e "${YELLOW}[!] Could not resolve domain to IP — skipping shodan.${RESET}"
            fi
        else
            echo -e "${YELLOW}[!] dig not found — cannot resolve IP for Shodan scan.${RESET}"
        fi
    else
        echo -e "${YELLOW}[!] Shodan CLI not found. Skipping Shodan scan.${RESET}"
    fi
}

run_amass() {
    if command -v amass &>/dev/null; then
        echo -e "${CYAN}[*] Running Amass subdomain enumeration...${RESET}"
        amass enum -d "$DOMAIN" -o "$OUTDIR/amass.txt" || :
    else
        echo -e "${YELLOW}[!] Amass not found. Skipping subdomain enumeration.${RESET}"
    fi
}

main_menu() {
    echo ""
    echo -e "${CYAN}Choose scan type:${RESET}"
    echo "1. Passive Recon Only"
    echo "2. Passive + GF Pattern Scan"
    echo "3. Full Scan (Active Tools + GF + Shodan/Amass)"
    echo "4. Exit"
    read -r -p "Select an option: " choice

    case "$choice" in
        1) collect_urls ;;
        2) collect_urls; run_gf_scans ;;
        3) collect_urls; run_gf_scans; run_active_scans; run_amass; run_shodan_scan ;;
        4) exit 0 ;;
        *) echo -e "${RED}Invalid choice${RESET}"; exit 1 ;;
    esac
}

# === MAIN EXECUTION ===
BANNER
setup_tools

# parse -d domain
DOMAIN=""
while getopts ":d:" flag; do
  case "${flag}" in
    d) DOMAIN=${OPTARG} ;;
    *) echo -e "${YELLOW}Usage: $0 -d example.com${RESET}"; exit 1 ;;
  esac
done
shift $((OPTIND -1))

if [ -z "${DOMAIN}" ]; then
    read -r -p "Enter target domain (e.g., example.com): " DOMAIN
fi

OUTDIR="output/${DOMAIN}"
mkdir -p "$OUTDIR"

main_menu

echo -e "${GREEN}[✓] Recon complete! Results saved in: $OUTDIR${RESET}"
