#!/usr/bin/env bash
#
# REKON — Interactive All-in-One Recon Tool
# subdomain enum + http probing + fast port scan + CVE lookup + dirb + nuclei + screenshots + HTML report
#
# Use only on targets you are authorized to test (CTF labs / bug bounty scope / your own systems).
#
set -uo pipefail

# ================= API credentials (optional) =================
# Fill in your OWN API keys here if you have them. The tool works fine without them —
# the vulners nmap script can run unauthenticated (rate-limited), this just raises limits.
VULNERS_API_KEY=""     # https://vulners.com/ -> account -> API key
SHODAN_API_KEY=""      # https://www.shodan.io/ -> account -> API key (reserved for future use)

# ================= colors / ui =================
B='\033[1m'; DIM='\033[2m'; NC='\033[0m'
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAG='\033[0;35m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
hr()   { echo -e "${DIM}────────────────────────────────────────────────────${NC}"; }

banner() {
clear
echo -e "${CYAN}${B}"
cat <<'EOF'
                 d8b
                 ?88
                  88b
  88bd88b d8888b  888  d88' d8888b   88bd88b
  88P'  `d8b_,dP  888bd8P' d8P' ?88  88P' ?8b
 d88     88b     d88888b   88b  d88 d88   88P
d88'     `?888P'd88' `?88b,`?8888P'd88'   88b
  Ahmed-kori @masturbyte

EOF
echo -e "${NC}${DIM}        All-in-One Recon • subdomains -> ports -> http -> CVEs -> report${NC}"
hr
}

# ================= global config =================
TARGET=""
TARGET_TYPE=""
OUTDIR=""
THREADS=1000
RATE=1000
SUB_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DIRB_WORDLIST="/usr/share/wordlists/dirb/common.txt"
DIRB_EXTENSIONS="php,html,asp,aspx,js,txt,bak,zip"   # comma-separated, no dots
PAR_JOBS=10
SUB_BRUTEFORCE=1   # active subdomain brute-force (uses SUB_WORDLIST) in addition to passive sources
LIVE_REPORT=1      # regenerate report.html after every module so you can watch it fill in live

# Keywords that mark a subdomain/directory/path as worth a closer look (case-insensitive, substring match).
# The report highlights anything matching these at the top, instead of mixing it in with everything else.
INTERESTING_KEYWORDS="admin,api,backup,config,customer,user,login,upload,secret,key,token,\
db,sql,dump,env,git,internal,private,staging,dev,test,debug,old,bak,phpmyadmin,wp-admin,\
dashboard,panel,account,payment,order,invoice,export,import,swagger,graphql"

# Ports that usually deserve a manual look regardless of what nmap/nuclei say about them.
RISKY_PORTS="21,23,25,110,135,139,445,1433,1521,3306,3389,5432,5900,6379,8009,9200,11211,27017,27018,50000"

declare -A RUN_MODULE=( [subs]=1 [httpx]=1 [ports]=1 [cve]=1 [dirb]=1 [nuclei]=1 [shots]=0 [report]=1 )
MODULE_ORDER=(subs httpx ports cve dirb nuclei shots report)
declare -A MODULE_LABEL=(
  [subs]="Subdomain Enumeration (subfinder/assetfinder/amass/crt.sh)"
  [httpx]="HTTP Probing (httpx: status/title/tech)"
  [ports]="Fast Port Scan (rustscan/nmap)"
  [cve]="CVE / Service Version Lookup (nmap vulners + searchsploit)"
  [dirb]="Directory Brute-force (ffuf/gobuster)"
  [nuclei]="Vulnerability Scan (nuclei)"
  [shots]="Screenshots (gowitness) - optional"
  [report]="HTML Report Generation"
)

TOOLS=(subfinder assetfinder amass httpx rustscan nmap searchsploit nuclei gobuster ffuf gowitness jq curl go)
declare -A TOOL_STATUS

# ================= tool check / install =================
need() { command -v "$1" >/dev/null 2>&1; }

check_tools() {
  log "Checking available tools..."
  for t in "${TOOLS[@]}"; do
    if need "$t"; then TOOL_STATUS[$t]="ok"; else TOOL_STATUS[$t]="missing"; fi
  done
  printf "  %-12s %-10s\n" "TOOL" "STATUS"
  for t in "${TOOLS[@]}"; do
    if [[ "${TOOL_STATUS[$t]}" == "ok" ]]; then
      printf "  %-12s ${GREEN}%-10s${NC}\n" "$t" "found"
    else
      printf "  %-12s ${RED}%-10s${NC}\n" "$t" "missing"
    fi
  done
}

ensure_vulners_script() {
  # nmap's vulners.nse script ships separately in some distros; try to fetch it into the user nmap scripts dir if missing.
  local nse_dir="$HOME/.nmap/scripts"
  if ! nmap --script-help vulners >/dev/null 2>&1; then
    mkdir -p "$nse_dir"
    if need curl; then
      curl -s -o "$nse_dir/vulners.nse" \
        "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" 2>/dev/null
      nmap --script-updatedb >/dev/null 2>&1 || true
    fi
  fi
}

install_tool() {
  local t="$1"
  case "$t" in
    subfinder)   need go && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
    httpx)       need go && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
    nuclei)      need go && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ;;
    assetfinder) need go && go install -v github.com/tomnomnom/assetfinder@latest ;;
    ffuf)        need go && go install -v github.com/ffuf/ffuf/v2@latest ;;
    gowitness)   need go && go install -v github.com/sensepost/gowitness@latest ;;
    rustscan)    warn "rustscan needs cargo/apt — try: sudo apt install rustscan  or  cargo install rustscan" ;;
    amass)       sudo apt-get install -y amass 2>/dev/null || (need go && go install -v github.com/owasp-amass/amass/v4/...@master) ;;
    searchsploit) sudo apt-get install -y exploitdb 2>/dev/null ;;
    nmap|gobuster|jq|curl) sudo apt-get install -y "$t" 2>/dev/null ;;
    *) warn "No known install method for $t" ;;
  esac
}

offer_install() {
  local missing=()
  for t in "${TOOLS[@]}"; do
    [[ "${TOOL_STATUS[$t]}" == "missing" && "$t" != "go" ]] && missing+=("$t")
  done
  [[ "${#missing[@]}" -eq 0 ]] && { ok "All important tools are installed :)"; return; }

  echo
  warn "Missing tools: ${missing[*]}"
  read -rp "$(echo -e ${YELLOW}'Try to install them now? [y/N]: '${NC})" ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    if ! need go; then
      warn "Go must be installed first to get ProjectDiscovery tools (subfinder/httpx/nuclei...)"
      warn "Install it from: https://go.dev/doc/install  then re-run this script"
    fi
    for t in "${missing[@]}"; do
      log "Trying to install $t ..."
      install_tool "$t"
    done
    echo
    log "Re-checking tools after install..."
    check_tools
  else
    warn "OK, any step needing a missing tool will be skipped automatically."
  fi
}

# ================= menu helpers =================
pause() { read -rp "$(echo -e ${DIM}'[Press Enter to continue]'${NC})"; }

ask_target() {
  echo
  read -rp "$(echo -e ${B}'Enter target (domain or IP): '${NC})" TARGET
  if [[ -z "$TARGET" ]]; then err "You must enter a target"; exit 1; fi
  if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    TARGET_TYPE="ip"
    RUN_MODULE[subs]=0
    log "Detected as IP -> subdomain enumeration will be skipped automatically"
  else
    TARGET_TYPE="domain"
  fi
}

select_modules_menu() {
  while true; do
    echo
    hr
    echo -e "${B}Select modules to run (type the number to toggle, 'a' to enable all, 'c' to continue):${NC}"
    local i=1
    for m in "${MODULE_ORDER[@]}"; do
      local state="${RUN_MODULE[$m]}"
      local mark="${RED}OFF${NC}"
      [[ "$state" == "1" ]] && mark="${GREEN}ON${NC}"
      printf "  %d) %-60s [%b]\n" "$i" "${MODULE_LABEL[$m]}" "$mark"
      i=$((i+1))
    done
    hr
    read -rp "$(echo -e ${B}'Choice: '${NC})" choice
    case "$choice" in
      a|A) for m in "${MODULE_ORDER[@]}"; do RUN_MODULE[$m]=1; done ;;
      c|C) break ;;
      [0-9]*)
        local idx=1
        for m in "${MODULE_ORDER[@]}"; do
          if [[ "$idx" == "$choice" ]]; then
            if [[ "${RUN_MODULE[$m]}" == "1" ]]; then RUN_MODULE[$m]=0; else RUN_MODULE[$m]=1; fi
          fi
          idx=$((idx+1))
        done
        ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

settings_menu() {
  while true; do
    echo
    hr
    echo -e "${B}Current settings:${NC}"
    echo "  1) Rustscan/Port threads : $THREADS"
    echo "  2) Nuclei rate limit     : $RATE"
    echo "  3) Dirb wordlist         : $DIRB_WORDLIST"
    echo "  4) Parallel jobs         : $PAR_JOBS"
    echo "  5) Vulners API key       : ${VULNERS_API_KEY:-<empty>}"
    echo "  6) Subdomain wordlist    : $SUB_WORDLIST"
    echo "  7) Dirb/content wordlist : $DIRB_WORDLIST"
    echo "  8) Dirb file extensions  : $DIRB_EXTENSIONS"
    echo "  9) Subdomain brute-force : $([[ "$SUB_BRUTEFORCE" == "1" ]] && echo ON || echo OFF)"
    echo " 10) Live report updates  : $([[ "$LIVE_REPORT" == "1" ]] && echo ON || echo OFF)"
    echo " 11) Interesting keywords : $INTERESTING_KEYWORDS"
    echo " 12) Back"
    hr
    read -rp "Choose a number to edit (or 12 to go back): " s
    case "$s" in
      1) read -rp "New threads value: " THREADS ;;
      2) read -rp "New rate value: " RATE ;;
      3) read -rp "Dirb/content wordlist path (shortcut, same as 7): " DIRB_WORDLIST ;;
      4) read -rp "Parallel jobs count: " PAR_JOBS ;;
      5) read -rp "Vulners API key: " VULNERS_API_KEY ;;
      6) read -rp "Subdomain wordlist path: " SUB_WORDLIST ;;
      7) read -rp "Dirb/content wordlist path: " DIRB_WORDLIST ;;
      8) read -rp "File extensions, comma-separated, no dots (e.g. php,html,asp,txt): " DIRB_EXTENSIONS ;;
      9) [[ "$SUB_BRUTEFORCE" == "1" ]] && SUB_BRUTEFORCE=0 || SUB_BRUTEFORCE=1 ;;
      10) [[ "$LIVE_REPORT" == "1" ]] && LIVE_REPORT=0 || LIVE_REPORT=1 ;;
      11) read -rp "Keywords, comma-separated: " INTERESTING_KEYWORDS ;;
      12) break ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

# ================= recon functions =================
enumerate_subdomains() {
  local domain="$1"
  log "Enumerating subdomains for $domain ..."
  local raw="$OUTDIR/subdomains/all_raw.txt"
  : > "$raw"
  need subfinder   && subfinder -d "$domain" -all -silent 2>/dev/null >> "$raw"
  need assetfinder && assetfinder --subs-only "$domain" 2>/dev/null >> "$raw"
  need amass        && timeout 60 amass enum -passive -d "$domain" 2>/dev/null >> "$raw"
  if need curl && need jq; then
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
      | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$raw"
  fi

  # active brute-force on top of passive sources, using its own dedicated wordlist
  if [[ "$SUB_BRUTEFORCE" == "1" ]]; then
    if [[ ! -f "$SUB_WORDLIST" ]]; then
      warn "Subdomain wordlist not found: $SUB_WORDLIST (skipping brute-force, check Settings)"
    elif need gobuster; then
      log "Brute-forcing subdomains with gobuster dns (wordlist: $SUB_WORDLIST)..."
      gobuster dns -d "$domain" -w "$SUB_WORDLIST" -q -t 50 2>/dev/null \
        | awk '{print $2}' >> "$raw"
    else
      warn "gobuster not found, skipping active subdomain brute-force (install gobuster to enable it)"
    fi
  fi

  echo "$domain" >> "$raw"
  sort -u "$raw" | grep -F "$domain" | sed '/^\s*$/d' > "$OUTDIR/subdomains/all.txt"
  ok "Found $(wc -l < "$OUTDIR/subdomains/all.txt") subdomains"
}

probe_http() {
  log "Probing HTTP services (httpx)..."
  local input="$1" out="$OUTDIR/httpx/alive.txt" out_json="$OUTDIR/httpx/alive.json"
  if need httpx; then
    httpx -l "$input" -silent -sc -title -tech-detect -server -json -o "$out_json" 2>/dev/null
    jq -r '.url' "$out_json" 2>/dev/null | sort -u > "$out"
  else
    warn "httpx not found, falling back to curl (slower)"
    : > "$out"
    while read -r h; do
      for scheme in https http; do
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 4 "$scheme://$h" 2>/dev/null)
        [[ -n "$code" && "$code" != "000" ]] && { echo "$scheme://$h" >> "$out"; break; }
      done
    done < "$input"
  fi
  ok "Alive hosts: $(wc -l < "$out" 2>/dev/null || echo 0)"
}

scan_ports() {
  local target="$1" safe_name out
  safe_name=$(echo "$target" | tr -c 'a-zA-Z0-9.' '_')
  out="$OUTDIR/ports/${safe_name}.txt"
  if need rustscan; then
    rustscan -a "$target" -b "$THREADS" --ulimit 5000 -g 2>/dev/null > "$out" || true
  elif need nmap; then
    nmap -T4 --min-rate 2000 -p- "$target" -oN "$out" >/dev/null 2>&1
  else
    echo "no scanner available" > "$out"
  fi
}

# extract a comma-separated port list from either rustscan -g output or nmap -oN output
extract_ports() {
  local portfile="$1"
  local ports=""
  if grep -q '\->' "$portfile" 2>/dev/null; then
    # rustscan -g format: "1.2.3.4 -> [80,443,22]"
    ports=$(grep -oP '(?<=\[)[^\]]+' "$portfile" | tr -d ' ' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
  else
    # nmap -oN format: lines like "80/tcp   open  http"
    ports=$(grep -oP '^\d+(?=/tcp)' "$portfile" | sort -un | tr '\n' ',' | sed 's/,$//')
  fi
  echo "$ports"
}

# ----- CVE / service-version lookup on discovered open ports -----
cve_scan() {
  local host="$1" portfile="$2"
  local safe_name out
  safe_name=$(echo "$host" | tr -c 'a-zA-Z0-9.' '_')
  out="$OUTDIR/cve/${safe_name}.txt"

  local ports
  ports=$(extract_ports "$portfile")
  if [[ -z "$ports" ]]; then
    echo "No open ports found to scan for $host" > "$out"
    return
  fi

  : > "$out"
  if need nmap; then
    ensure_vulners_script
    echo "== nmap -sV --script vulners,vuln on $host (ports: $ports) ==" >> "$out"
    local script_args="vulners"
    [[ -n "$VULNERS_API_KEY" ]] && script_args="vulners.apikey=${VULNERS_API_KEY}"
    nmap -sV --script "vulners,vuln" --script-args "$script_args" -p "$ports" "$host" >> "$out" 2>/dev/null
  else
    echo "nmap not available — cannot do version/CVE detection" >> "$out"
  fi

  # Extract "PORT STATE SERVICE VERSION" lines to feed into searchsploit as well
  if need searchsploit; then
    echo >> "$out"
    echo "== searchsploit matches (based on detected service/version banners) ==" >> "$out"
    grep -E '^[0-9]+/tcp\s+open' "$out" | sed -E 's#^[0-9]+/tcp\s+open\s+\S+\s+##' | sort -u | while read -r banner; do
      [[ -z "$banner" ]] && continue
      echo "--- searchsploit: $banner ---" >> "$out"
      searchsploit "$banner" 2>/dev/null >> "$out"
      echo >> "$out"
    done
  fi
}

is_interesting_word() {
  local word="${1,,}"
  IFS=',' read -ra kws <<< "$INTERESTING_KEYWORDS"
  for k in "${kws[@]}"; do
    k=$(echo "$k" | tr -d ' \n')
    [[ -n "$k" && "$word" == *"$k"* ]] && return 0
  done
  return 1
}

# One level of brute-force under a given base URL path, appended to $out with a header.
dirb_level() {
  local url="$1" out="$2" label="$3"
  echo "== $label ==" >> "$out"
  if need ffuf; then
    local ext_args=()
    if [[ -n "$DIRB_EXTENSIONS" ]]; then
      local ext_csv=""
      IFS=',' read -ra exts <<< "$DIRB_EXTENSIONS"
      for e in "${exts[@]}"; do ext_csv+=".${e},"; done
      ext_args=(-e "${ext_csv%,}")
    fi
    ffuf -u "${url}/FUZZ" -w "$DIRB_WORDLIST" -mc 200,301,302,403 -t 60 -of json -o "$OUTDIR/dirs/.tmp_ffuf.json" "${ext_args[@]}" 2>/dev/null
    if [[ -f "$OUTDIR/dirs/.tmp_ffuf.json" ]]; then
      jq -r '.results[] | "\(.status)\t\(.input.FUZZ)\t\(.url)"' "$OUTDIR/dirs/.tmp_ffuf.json" 2>/dev/null >> "$out"
      rm -f "$OUTDIR/dirs/.tmp_ffuf.json"
    fi
  elif need gobuster; then
    local gb_args=()
    [[ -n "$DIRB_EXTENSIONS" ]] && gb_args=(-x "$DIRB_EXTENSIONS")
    gobuster dir -u "$url" -w "$DIRB_WORDLIST" -t 30 -q "${gb_args[@]}" 2>/dev/null >> "$out"
  fi
}

# Smart directory brute-force: one flat pass, then automatically goes one level deeper
# into any hit that looks interesting (matches INTERESTING_KEYWORDS, or is a redirect/
# directory-style hit) instead of treating every result the same way.
dirb_scan() {
  local url="$1" safe_name out
  safe_name=$(echo "$url" | sed 's#https\?://##; s#/#_#g')
  out="$OUTDIR/dirs/${safe_name}.txt"
  : > "$out"

  if [[ ! -f "$DIRB_WORDLIST" ]]; then
    warn "Content wordlist not found: $DIRB_WORDLIST (skipping dirb for $url, check Settings)"
    return
  fi
  if ! need ffuf && ! need gobuster; then
    warn "Neither ffuf nor gobuster found, skipping directory brute-force for $url"
    return
  fi

  dirb_level "$url" "$out" "Level 1: $url"

  # pick follow-up candidates: interesting keyword match, or a 301/302 (usually a real directory)
  local followups=()
  while IFS=$'\t' read -r status word path; do
    [[ -z "$word" ]] && continue
    if is_interesting_word "$word" || [[ "$status" == "301" || "$status" == "302" ]]; then
      followups+=("$word")
    fi
  done < <(grep -P '^\d{3}\t' "$out" 2>/dev/null | sort -u -t$'\t' -k2,2)

  # de-dup and cap how deep we go, so this stays fast
  mapfile -t followups < <(printf '%s\n' "${followups[@]}" | sort -u | head -n 8)

  for w in "${followups[@]}"; do
    [[ -z "$w" ]] && continue
    log "  -> '$w' under $url looks interesting, going one level deeper..."
    dirb_level "${url}/${w}" "$out" "Level 2 (follow-up on '$w'): ${url}/${w}"
  done
}

run_nuclei() {
  local input="$1"
  if ! need nuclei; then warn "nuclei not found, skipping"; return; fi
  log "Running nuclei..."
  nuclei -l "$input" -silent -rl "$RATE" \
    -tags exposure,misconfig,default-login,tech \
    -severity info,low,medium,high,critical \
    -o "$OUTDIR/nuclei/results.txt" 2>/dev/null
  ok "nuclei finished"
}

take_screenshots() {
  local input="$1"
  need gowitness || { warn "gowitness not found, skipping screenshots"; return; }
  log "Taking screenshots..."
  (cd "$OUTDIR/screenshots" && gowitness file -f "../../$input" --no-http 2>/dev/null) || true
}

generate_report() {
  local report="$OUTDIR/report.html"
  local target="$1"
  local status="${2:-running}"   # "running" or "complete"
  [[ "$status" == "complete" ]] && log "Building final HTML report..." || true
  REKON_KEYWORDS="$INTERESTING_KEYWORDS" REKON_RISKY_PORTS="$RISKY_PORTS" \
  python3 - "$OUTDIR" "$target" "$report" "$status" <<'PYEOF'
import sys, os, json, html, glob, datetime, re

outdir, target, report_path, status = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
keywords = [k.strip().lower() for k in os.environ.get("REKON_KEYWORDS","").replace("\\\n","").split(",") if k.strip()]
risky_ports = set(p.strip() for p in os.environ.get("REKON_RISKY_PORTS","").split(",") if p.strip())

def read(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return ""

subs = read(os.path.join(outdir, "subdomains", "all.txt")).strip().splitlines()
alive = read(os.path.join(outdir, "httpx", "alive.txt")).strip().splitlines()
nuclei = read(os.path.join(outdir, "nuclei", "results.txt")).strip().splitlines()

alive_json_path = os.path.join(outdir, "httpx", "alive.json")
alive_details = []
if os.path.exists(alive_json_path):
    for line in read(alive_json_path).strip().splitlines():
        try: alive_details.append(json.loads(line))
        except Exception: pass

port_files = sorted(glob.glob(os.path.join(outdir, "ports", "*.txt")))
ports_data = {os.path.basename(p).replace(".txt",""): read(p).strip() for p in port_files}
ports_data = {k:v for k,v in ports_data.items() if v}

dir_files = sorted(glob.glob(os.path.join(outdir, "dirs", "*.txt")))
dirs_data = {os.path.basename(p).replace(".txt",""): read(p).strip() for p in dir_files}
dirs_data = {k:v for k,v in dirs_data.items() if v}

cve_files = sorted(glob.glob(os.path.join(outdir, "cve", "*.txt")))
cve_data = {os.path.basename(p).replace(".txt",""): read(p).strip() for p in cve_files}
cve_data = {k:v for k,v in cve_data.items() if v}
total_cves = sum(len(re.findall(r'CVE-\d{4}-\d+', c)) for c in cve_data.values())

now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def esc(s): return html.escape(str(s))

rows_alive = ""
if alive_details:
    for d in alive_details:
        tech = d.get('tech', [])
        tech_s = ', '.join(tech) if isinstance(tech, list) else esc(tech)
        sc = d.get('status_code','')
        badge_color = "#22c55e" if str(sc).startswith("2") else ("#eab308" if str(sc).startswith("3") else "#ef4444")
        rows_alive += f"""<tr>
<td><a href="{esc(d.get('url',''))}" target="_blank" style="color:#22d3ee">{esc(d.get('url',''))}</a></td>
<td><span class="badge" style="background:{badge_color}">{esc(sc)}</span></td>
<td>{esc(d.get('title',''))}</td>
<td>{esc(d.get('webserver',''))}</td>
<td>{esc(tech_s)}</td>
</tr>"""
else:
    for u in alive:
        rows_alive += f"<tr><td>{esc(u)}</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>"

rows_subs = "".join(f"<li>{esc(s)}</li>" for s in subs)

ports_html = "".join(f"<h4>Host: {esc(n)}</h4><pre>{esc(c)}</pre>" for n,c in ports_data.items())
dirs_html = "".join(f"<h4>Path: {esc(n)}</h4><pre>{esc(c)}</pre>" for n,c in dirs_data.items())

def highlight_cves(text):
    escaped = esc(text)
    return re.sub(r'(CVE-\d{4}-\d+)', r'<span class="cve-tag">\1</span>', escaped)

cve_html = "".join(f"<h4>Host: {esc(n)}</h4><pre>{highlight_cves(c)}</pre>" for n,c in cve_data.items())

# ---------- smart highlights: pull out what actually deserves a look first ----------
def matched_keywords(text):
    low = text.lower()
    return sorted({k for k in keywords if k and k in low})

highlight_items = []  # (priority:int, category, text, note)

for s in subs:
    m = matched_keywords(s)
    if m:
        highlight_items.append((2, "Subdomain", s, "matches: " + ", ".join(m)))

for n, content in dirs_data.items():
    for line in content.splitlines():
        parts = line.split("\t")
        word = parts[1] if len(parts) >= 2 else line
        m = matched_keywords(word)
        if m:
            urlpart = parts[2] if len(parts) >= 3 else f"{n}/{word}"
            highlight_items.append((1, "Path", urlpart, "matches: " + ", ".join(m)))

for n, content in ports_data.items():
    for pm in re.finditer(r'\b(\d{1,5})(?:/tcp|\])', content):
        p = pm.group(1)
        if p in risky_ports:
            highlight_items.append((1, "Open Port", f"{n}:{p}", "commonly risky service, worth a manual check"))

for n, content in cve_data.items():
    for cve in set(re.findall(r'CVE-\d{4}-\d+', content)):
        highlight_items.append((0, "CVE", f"{n}", cve))

for line in nuclei:
    if "[critical]" in line or "[high]" in line:
        sevtag = "critical" if "[critical]" in line else "high"
        highlight_items.append((0, "Nuclei", line[:140], sevtag))

# priority 0 = most urgent (critical/CVE) ... 2 = least urgent, dedupe, cap list so it stays a quick skim
seen = set()
deduped = []
for item in sorted(highlight_items, key=lambda x: x[0]):
    key = (item[1], item[2])
    if key in seen:
        continue
    seen.add(key)
    deduped.append(item)
highlight_items = deduped[:60]

prio_colors = {0: "#e11d48", 1: "#f97316", 2: "#eab308"}
prio_labels = {0: "HIGH", 1: "MED", 2: "LOW"}
highlights_html = ""
for prio, cat, text, note in highlight_items:
    color = prio_colors.get(prio, "#64748b")
    highlights_html += f"""<div class="hl-row" style="border-left:4px solid {color}">
<span class="hl-prio" style="background:{color}">{prio_labels.get(prio,'')}</span>
<span class="hl-cat">{esc(cat)}</span>
<span class="hl-text">{esc(text)}</span>
<span class="hl-note">{esc(note)}</span>
</div>"""
if not highlight_items:
    highlights_html = "<div class='empty'>Nothing flagged as high-priority yet — check back as more modules finish, or widen the keyword list in Settings.</div>"

sev_colors = {"critical":"#e11d48","high":"#f97316","medium":"#eab308","low":"#3b82f6","info":"#64748b"}
nuclei_html = ""
sev_counts = {s:0 for s in sev_colors}
for line in nuclei:
    sev = "info"
    for s in sev_colors:
        if f"[{s}]" in line:
            sev = s; break
    sev_counts[sev]+=1
    color = sev_colors.get(sev, "#64748b")
    nuclei_html += f'<div class="nuclei-line" style="border-left:4px solid {color}">{esc(line)}</div>'

sev_badges = "".join(
    f'<span class="sevbadge" style="background:{sev_colors[s]}">{s}: {sev_counts[s]}</span>'
    for s in sev_colors if sev_counts[s] > 0
)

html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{'<meta http-equiv="refresh" content="6">' if status != "complete" else ''}
<title>REKON Report - {esc(target)}</title>
<style>
  :root {{
    --bg:#0b0d12; --panel:#141821; --border:#232936; --text:#e5e7eb;
    --muted:#8b93a7; --accent:#22d3ee; --accent2:#a78bfa;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    background:radial-gradient(circle at top right, #141a2e, var(--bg) 60%);
    color:var(--text); font-family:'Segoe UI',Tahoma,sans-serif; margin:0; padding:28px; line-height:1.6;
  }}
  .header {{ display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; margin-bottom:6px; }}
  h1 {{ color:var(--accent); margin:0; font-size:26px; }}
  .meta {{ color:var(--muted); margin-bottom:26px; font-size:14px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:28px; }}
  .stat {{ background:linear-gradient(145deg,var(--panel),#0e1117); border:1px solid var(--border); border-radius:12px; padding:18px; text-align:center; }}
  .stat .num {{ font-size:30px; font-weight:800; color:var(--accent); }}
  .stat .label {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  nav.tabs {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:18px; }}
  nav.tabs button {{
    background:var(--panel); color:var(--text); border:1px solid var(--border); border-radius:8px;
    padding:9px 16px; cursor:pointer; font-size:14px; transition:.15s;
  }}
  nav.tabs button.active {{ background:var(--accent); color:#06222a; font-weight:700; border-color:var(--accent); }}
  section {{ display:none; background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:20px 22px; margin-bottom:20px; }}
  section.active {{ display:block; animation:fade .25s ease; }}
  @keyframes fade {{ from{{opacity:0; transform:translateY(4px);}} to{{opacity:1; transform:translateY(0);}} }}
  section h2 {{ margin-top:0; border-bottom:1px solid var(--border); padding-bottom:10px; color:var(--accent2); }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); word-break:break-all; }}
  th {{ color:var(--accent); }}
  .badge {{ padding:2px 10px; border-radius:20px; font-size:12px; color:#06120f; font-weight:700; }}
  .sevbadge {{ padding:3px 12px; border-radius:20px; font-size:12px; color:#06120f; font-weight:700; margin-right:6px; }}
  .cve-tag {{ background:#e11d48; color:#fff; padding:1px 6px; border-radius:4px; font-weight:700; }}
  ul.subs {{ columns:3; -webkit-columns:3; list-style:none; padding:0; font-size:14px; }}
  ul.subs li {{ padding:3px 0; color:var(--muted); }}
  pre {{ background:#070910; border:1px solid var(--border); border-radius:8px; padding:10px; overflow-x:auto; font-size:13px; }}
  .nuclei-line {{ padding:7px 10px; margin-bottom:5px; background:#070910; border-radius:6px; font-size:13px; }}
  .empty {{ color:var(--muted); font-style:italic; }}
  footer {{ color:var(--muted); font-size:12px; text-align:center; margin-top:30px; }}
  .status-banner {{ display:inline-flex; align-items:center; gap:8px; padding:6px 14px; border-radius:20px; font-size:13px; font-weight:700; }}
  .status-running {{ background:#422006; color:#fbbf24; }}
  .status-complete {{ background:#052e1a; color:#4ade80; }}
  .dot {{ width:8px; height:8px; border-radius:50%; background:currentColor; display:inline-block; }}
  .status-running .dot {{ animation:pulse 1.2s infinite; }}
  @keyframes pulse {{ 0%,100% {{opacity:1;}} 50% {{opacity:.3;}} }}
  .hl-row {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; padding:9px 12px; margin-bottom:6px; background:#070910; border-radius:6px; font-size:13px; }}
  .hl-prio {{ padding:2px 8px; border-radius:4px; font-size:11px; font-weight:800; color:#06120f; }}
  .hl-cat {{ color:var(--accent2); font-weight:700; min-width:80px; }}
  .hl-text {{ word-break:break-all; flex:1; }}
  .hl-note {{ color:var(--muted); font-size:12px; }}
  @media (max-width:700px) {{ ul.subs {{ columns:1; }} }}
</style>
</head>
<body>
  <div class="header">
    <h1>REKON Report</h1>
    <div style="display:flex; gap:10px; align-items:center;">
      {f'<div>{sev_badges}</div>' if sev_badges else ''}
      {'<span class="status-banner status-running"><span class="dot"></span>Scan running — this page refreshes itself</span>' if status != 'complete' else '<span class="status-banner status-complete"><span class="dot"></span>Scan complete</span>'}
    </div>
  </div>
  <div class="meta">Target: <b>{esc(target)}</b> &nbsp;|&nbsp; Last updated: {now}</div>

  <div class="grid">
    <div class="stat"><div class="num">{len(highlight_items)}</div><div class="label">Priority Findings</div></div>
    <div class="stat"><div class="num">{len(subs)}</div><div class="label">Subdomains</div></div>
    <div class="stat"><div class="num">{len(alive_details) or len(alive)}</div><div class="label">Alive Hosts</div></div>
    <div class="stat"><div class="num">{len(ports_data)}</div><div class="label">Hosts Port-Scanned</div></div>
    <div class="stat"><div class="num">{total_cves}</div><div class="label">CVEs Found</div></div>
    <div class="stat"><div class="num">{len(nuclei)}</div><div class="label">Nuclei Findings</div></div>
  </div>

  <nav class="tabs">
    <button class="tab-btn active" data-tab="t-highlights">⚡ Highlights</button>
    <button class="tab-btn" data-tab="t-subs">Subdomains</button>
    <button class="tab-btn" data-tab="t-alive">Alive Hosts</button>
    <button class="tab-btn" data-tab="t-ports">Ports</button>
    <button class="tab-btn" data-tab="t-cve">CVE / Notes</button>
    <button class="tab-btn" data-tab="t-dirs">Directories</button>
    <button class="tab-btn" data-tab="t-nuclei">Nuclei</button>
  </nav>

  <section id="t-highlights" class="active">
    <h2>Priority Findings — things worth checking first</h2>
    {highlights_html}
  </section>

  <section id="t-subs">
    <h2>Subdomains ({len(subs)})</h2>
    {"<ul class='subs'>" + rows_subs + "</ul>" if subs else "<div class='empty'>No data</div>"}
  </section>

  <section id="t-alive">
    <h2>Alive Hosts</h2>
    <table>
      <tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th></tr>
      {rows_alive if rows_alive else "<tr><td colspan='5' class='empty'>No data</td></tr>"}
    </table>
  </section>

  <section id="t-ports">
    <h2>Open Ports</h2>
    {ports_html if ports_html else "<div class='empty'>No results</div>"}
  </section>

  <section id="t-cve">
    <h2>CVE / Service Version Notes ({total_cves} CVEs found)</h2>
    {cve_html if cve_html else "<div class='empty'>Skipped or no results</div>"}
  </section>

  <section id="t-dirs">
    <h2>Directory Brute-force</h2>
    {dirs_html if dirs_html else "<div class='empty'>Skipped or no results</div>"}
  </section>

  <section id="t-nuclei">
    <h2>Nuclei Findings</h2>
    {nuclei_html if nuclei_html else "<div class='empty'>No data</div>"}
  </section>

  <footer>Generated by REKON - use only on authorized targets.</footer>

<script>
  document.querySelectorAll('.tab-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
      document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
      document.querySelectorAll('section').forEach(s=>s.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    }});
  }});
</script>
</body>
</html>
"""
with open(report_path, "w", encoding="utf-8") as f:
    f.write(html_out)
print(f"Report written: {report_path}")
PYEOF
  [[ "$status" == "complete" ]] && ok "Report ready: $report"
}

# called after each module when LIVE_REPORT=1, so the HTML fills in as the scan progresses
live_report() {
  [[ "$LIVE_REPORT" == "1" && "${RUN_MODULE[report]}" == "1" ]] && generate_report "$TARGET" "running"
}

# ================= pipeline runner =================
run_pipeline() {
  TS=$(date +%Y%m%d_%H%M%S)
  OUTDIR="rekon_${TARGET//[^a-zA-Z0-9.-]/_}_${TS}"
  mkdir -p "$OUTDIR"/{subdomains,httpx,ports,cve,nuclei,dirs,screenshots,raw}

  echo; hr; echo -e "${B}Starting recon for: $TARGET${NC}"; hr

  mkdir -p "$OUTDIR"/cve  # harmless if already created above
  [[ "$LIVE_REPORT" == "1" && "${RUN_MODULE[report]}" == "1" ]] && ok "Live report: $OUTDIR/report.html (refreshes itself while the scan runs)"

  if [[ "${RUN_MODULE[subs]}" == "1" && "$TARGET_TYPE" == "domain" ]]; then
    enumerate_subdomains "$TARGET"
  else
    echo "$TARGET" > "$OUTDIR/subdomains/all.txt"
  fi
  live_report

  if [[ "${RUN_MODULE[httpx]}" == "1" ]]; then
    probe_http "$OUTDIR/subdomains/all.txt"
  else
    cp "$OUTDIR/subdomains/all.txt" "$OUTDIR/httpx/alive.txt"
  fi
  live_report

  mapfile -t ALIVE_HOSTS < "$OUTDIR/httpx/alive.txt" 2>/dev/null || ALIVE_HOSTS=("$TARGET")
  [[ "${#ALIVE_HOSTS[@]}" -eq 0 ]] && ALIVE_HOSTS=("$TARGET")

  : > "$OUTDIR/raw/hosts_only.txt"
  for u in "${ALIVE_HOSTS[@]}"; do
    echo "$u" | sed -E 's#https?://##; s#/.*##' >> "$OUTDIR/raw/hosts_only.txt"
  done
  sort -u "$OUTDIR/raw/hosts_only.txt" -o "$OUTDIR/raw/hosts_only.txt"

  if [[ "${RUN_MODULE[ports]}" == "1" ]]; then
    echo; log "Scanning ports (parallel)..."
    while read -r h; do
      [[ -z "$h" ]] && continue
      scan_ports "$h" &
      while [[ "$(jobs -r | wc -l)" -ge "$PAR_JOBS" ]]; do wait -n; done
    done < "$OUTDIR/raw/hosts_only.txt"
    wait
    ok "Port scanning done"
    live_report
  fi

  if [[ "${RUN_MODULE[cve]}" == "1" ]]; then
    echo; log "Looking up CVEs / service versions for open ports (parallel)..."
    while read -r h; do
      [[ -z "$h" ]] && continue
      safe_name=$(echo "$h" | tr -c 'a-zA-Z0-9.' '_')
      pf="$OUTDIR/ports/${safe_name}.txt"
      [[ -f "$pf" ]] || continue
      cve_scan "$h" "$pf" &
      while [[ "$(jobs -r | wc -l)" -ge "$PAR_JOBS" ]]; do wait -n; done
    done < "$OUTDIR/raw/hosts_only.txt"
    wait
    ok "CVE lookup done"
    live_report
  fi

  if [[ "${RUN_MODULE[dirb]}" == "1" ]]; then
    echo; log "Directory brute-force (parallel, prioritizing interesting paths first)..."
    for u in "${ALIVE_HOSTS[@]}"; do
      dirb_scan "$u" &
      while [[ "$(jobs -r | wc -l)" -ge "$PAR_JOBS" ]]; do wait -n; done
    done
    wait
    ok "Directory brute-force done"
    live_report
  fi

  [[ "${RUN_MODULE[nuclei]}" == "1" ]] && { echo; run_nuclei "$OUTDIR/httpx/alive.txt"; live_report; }
  [[ "${RUN_MODULE[shots]}" == "1" ]]  && { echo; take_screenshots "$OUTDIR/httpx/alive.txt"; live_report; }
  [[ "${RUN_MODULE[report]}" == "1" ]] && { echo; generate_report "$TARGET" "complete"; }

  echo; hr
  ok "Done! Results are in: $OUTDIR"
  [[ "${RUN_MODULE[report]}" == "1" ]] && ok "Open the report: $OUTDIR/report.html"
  hr
}

# ================= main menu =================
main_menu() {
  while true; do
    banner
    echo -e "${B}Main Menu${NC}"
    echo "  1) Run Full Recon (all modules)"
    echo "  2) Select specific modules (Custom)"
    echo "  3) Check / install tools"
    echo "  4) Settings (threads/rate/wordlist/API key)"
    echo "  5) Exit"
    hr
    read -rp "$(echo -e ${B}'Choice: '${NC})" opt
    case "$opt" in
      1)
        for m in "${MODULE_ORDER[@]}"; do RUN_MODULE[$m]=1; done
        ask_target
        run_pipeline
        pause
        ;;
      2)
        ask_target
        select_modules_menu
        run_pipeline
        pause
        ;;
      3)
        check_tools
        offer_install
        pause
        ;;
      4)
        settings_menu
        ;;
      5)
        echo -e "${CYAN}Good luck!${NC}"
        exit 0
        ;;
      *)
        warn "Invalid choice"
        pause
        ;;
    esac
  done
}

# ================= entry =================
banner
check_tools
main_menu
