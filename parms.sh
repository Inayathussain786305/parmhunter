
#!/usr/bin/env bash
# --------------------------------------------
# Bug Bounty Recon Framework
# Tool: Bug Bounty Recon Framework (BBRecon)
# Author: Inayat Hussain (Security Researcher)
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
╔════════════════════════════════════════════════════════╗
║      Bug Bounty Recon Framework (BBRecon)              ║
║      Tool: Bug Bounty Recon Framework                  ║
║      Author: Inayat Hussain (Security Researcher)      ║
╚════════════════════════════════════════════════════════╝
B
    echo -e "${RESET}"
}

# install_if_missing <binary-name> <go-module-path>
# Uses exact module path to reduce ambiguity.
install_if_missing() {
    local bin="$1"
    local mod="$2"

    if command -v "$bin" &>/dev/null; then
        echo -e "${GREEN}[-] $bin already installed.${RESET}"
        return 0
    fi

    if ! command -v go &>/dev/null; then
        echo -e "${YELLOW}[!] 'go' not found; skipping auto-install of $bin. Install Go to enable auto install.${RESET}"
        return 1
    fi

    echo -e "${YELLOW}[+] Installing $bin from $mod ...${RESET}"

    # choose GOBIN or GOPATH/bin or default $HOME/go/bin
    local gobin
    gobin="$(go env GOBIN 2>/dev/null || true)"
    if [ -z "$gobin" ]; then
        local gopath
        gopath="$(go env GOPATH 2>/dev/null || true)"
        if [ -n "$gopath" ]; then
            gobin="$gopath/bin"
        else
            gobin="$HOME/go/bin"
        fi
    fi
    mkdir -p "$gobin"

    if go install "${mod}@latest"; then
        export PATH="$PATH:$gobin"
        echo -e "${GREEN}[+] Installed $bin. Ensure $gobin is in your shell PATH permanently.${RESET}"
        return 0
    else
        echo -e "${RED}[!] Failed to install $bin from $mod. Please install manually.${RESET}"
        return 1
    fi
}

setup_tools() {
    echo -e "${CYAN}[*] Checking & auto-installing known Go-based tools (best-effort)...${RESET}"

    # Use precise module paths to avoid ambiguity
    install_if_missing waybackurls github.com/tomnomnom/waybackurls
    install_if_missing gau github.com/lc/gau/v2/cmd/gau
    install_if_missing gf github.com/tomnomnom/gf
    install_if_missing qsreplace github.com/tomnomnom/qsreplace
    install_if_missing httpx github.com/projectdiscovery/httpx/cmd/httpx
    install_if_missing nuclei github.com/projectdiscovery/nuclei/v2/cmd/nuclei
    install_if_missing dalfox github.com/hahwul/dalfox/v2/cmd/dalfox

    # GF patterns clone
    if [ ! -d "${HOME}/.gf" ]; then
        if command -v git &>/dev/null; then
            echo -e "${YELLOW}[+] Cloning GF patterns...${RESET}"
            git clone https://github.com/1ndianl33t/Gf-Patterns "${HOME}/.gf" || echo -e "${YELLOW}[!] Failed to clone GF patterns. Clone manually to ${HOME}/.gf${RESET}"
        else
            echo -e "${YELLOW}[!] git not available: skipping GF pattern clone.${RESET}"
        fi
    else
        echo -e "${GREEN}[-] GF patterns present at ${HOME}/.gf${RESET}"
    fi
}

collect_urls() {
    echo -e "${CYAN}[*] Collecting URLs for ${DOMAIN}...${RESET}"

    # run waybackurls only if present
    local wb_count=0
    local gau_count=0

    if command -v waybackurls &>/dev/null; then
        waybackurls "$DOMAIN" > "$OUTDIR/wayback.txt" || true
        wb_count=$(wc -l < "$OUTDIR/wayback.txt" 2>/dev/null || echo 0)
    else
        : > "$OUTDIR/wayback.txt"
    fi

    # run gau with stderr suppressed to hide config warnings
    if command -v gau &>/dev/null; then
        # suppress gau warnings printed to stderr by redirecting them
        gau "$DOMAIN" > "$OUTDIR/gau.txt" 2>/dev/null || true
        gau_count=$(wc -l < "$OUTDIR/gau.txt" 2>/dev/null || echo 0)
    else
        : > "$OUTDIR/gau.txt"
    fi

    # combine and keep only parameterized URLs (containing '=')
    cat "$OUTDIR/wayback.txt" "$OUTDIR/gau.txt" 2>/dev/null | sort -u | grep "=" > "$OUTDIR/params.txt" || : 

    local params_count
    params_count=$(wc -l < "$OUTDIR/params.txt" 2>/dev/null || echo 0)

    echo -e "${GREEN}[+] waybackurls: ${wb_count} URLs, gau: ${gau_count} URLs, parameterized (with '='): ${params_count}.${RESET}"

    # show sample data to the user (first 50 param URLs) so Recon Only shows output
    if [ "$params_count" -gt 0 ]; then
        echo -e "${CYAN}[*] Showing first 50 parameterized URLs (saved in $OUTDIR/params.txt):${RESET}"
        head -n 50 "$OUTDIR/params.txt" || true
        echo -e "${YELLOW}... (full list is in $OUTDIR/params.txt)${RESET}"
    else
        echo -e "${YELLOW}[!] No parameterized URLs found.${RESET}"
    fi
}

run_gf_scans() {
    echo -e "${CYAN}[*] Scanning with GF patterns...${RESET}"
    if ! command -v gf &>/dev/null; then
        echo -e "${YELLOW}[!] gf not installed — skipping GF scans.${RESET}"
        return 0
    fi

    if [ ! -s "$OUTDIR/params.txt" ]; then
        echo -e "${YELLOW}[!] No params to scan with GF patterns.${RESET}"
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
        gf "$pattern" < "$OUTDIR/params.txt" >"$out" 2>/dev/null || true
        count=$(wc -l < "$out" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            echo -e "${RED}[!] $vuln: $count possible findings (saved to $out)${RESET}"
            # show up to 10 examples for quick inspection
            echo -e "${CYAN}    Example(s):${RESET}"
            head -n 10 "$out" || true
        else
            rm -f "$out" || true
        fi
    done
}

run_active_scans() {
    echo -e "${CYAN}[*] Running httpx for live host detection...${RESET}"

    if command -v httpx &>/dev/null; then
        if [ -s "$OUTDIR/params.txt" ]; then
            httpx -l "$OUTDIR/params.txt" -silent -o "$OUTDIR/live.txt" || : 
            echo -e "${GREEN}[+] Live URLs saved to $OUTDIR/live.txt (count: $(wc -l < "$OUTDIR/live.txt" 2>/dev/null || echo 0)).${RESET}"
            # show first 20 live
            echo -e "${CYAN}[*] First 20 live URLs:${RESET}"
            head -n 20 "$OUTDIR/live.txt" || true
        else
            : > "$OUTDIR/live.txt"
            echo -e "${YELLOW}[!] No params to probe with httpx.${RESET}"
        fi
    else
        echo -e "${YELLOW}[!] httpx not found — skipping live detection.${RESET}"
    fi

    if command -v nuclei &>/dev/null && [ -s "$OUTDIR/live.txt" ]; then
        echo -e "${CYAN}[*] Running nuclei on live URLs...${RESET}"
        nuclei -l "$OUTDIR/live.txt" -o "$OUTDIR/nuclei-results.txt" || :
        echo -e "${GREEN}[+] nuclei results saved to $OUTDIR/nuclei-results.txt (showing first 10 lines):${RESET}"
        head -n 10 "$OUTDIR/nuclei-results.txt" || true
    else
        echo -e "${YELLOW}[!] nuclei not installed or no live URLs — skipping nuclei.${RESET}"
    fi

    if command -v dalfox &>/dev/null && [ -s "$OUTDIR/params.txt" ]; then
        echo -e "${CYAN}[*] Running dalfox for XSS scanning...${RESET}"
        dalfox file "$OUTDIR/params.txt" -o "$OUTDIR/dalfox-xss.txt" || :
        echo -e "${GREEN}[+] dalfox results saved to $OUTDIR/dalfox-xss.txt (showing first 10 lines):${RESET}"
        head -n 10 "$OUTDIR/dalfox-xss.txt" || true
    else
        echo -e "${YELLOW}[!] dalfox not installed or no params — skipping dalfox.${RESET}"
    fi
}

run_shodan_scan() {
    if command -v shodan &>/dev/null; then
        echo -e "${CYAN}[*] Running Shodan scan (requires API key)...${RESET}"
        if command -v dig &>/dev/null; then
            IP=$(dig +short "$DOMAIN" | head -n 1 || true)
            if [ -n "$IP" ]; then
                shodan host "$IP" > "$OUTDIR/shodan.txt" || :
                echo -e "${GREEN}[+] Shodan output saved to $OUTDIR/shodan.txt (showing top 10 lines):${RESET}"
                head -n 10 "$OUTDIR/shodan.txt" || true
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
        echo -e "${GREEN}[+] amass results saved to $OUTDIR/amass.txt (showing first 20):${RESET}"
        head -n 20 "$OUTDIR/amass.txt" || true
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

# === MAIN ===
BANNER
setup_tools

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
