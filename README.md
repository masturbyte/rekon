# REKON

**All-in-One Interactive Recon Tool** — subdomains → HTTP probing → fast port scan → CVE lookup → directory brute-force → vulnerability scan → a live, self-updating HTML report.

Built for CTF labs (TryHackMe / HackTheBox style), bug bounty recon on in-scope targets, and authorized pentest engagements. One script, one menu, no juggling ten different tools by hand.

> ⚠️ **Use only on targets you are authorized to test.** Running this against systems you don't own or don't have explicit permission to test is illegal in most jurisdictions.

---

## Features

- 🧭 **Interactive menu** — run a full recon, or pick exactly which modules you want
- 🔍 **Subdomain enumeration** — passive (subfinder, assetfinder, amass, crt.sh) **+** active brute-force (gobuster dns) with its own dedicated wordlist
- 🌐 **HTTP probing** — status codes, titles, server headers, detected tech (httpx)
- ⚡ **Fast port scanning** — rustscan first, nmap fallback, fully parallelized across hosts
- 🛡️ **CVE / service-version lookup** — `nmap --script vulners,vuln` + `searchsploit` run automatically on every open port found
- 📁 **Smart directory brute-force** — one flat pass, then automatically goes one level deeper into anything that looks interesting (matches your keyword list, or returns a redirect) instead of treating every hit the same way — with its own separate wordlist and configurable file extensions (`.php`, `.html`, `.asp`, ...)
- 🧨 **Vulnerability scanning** — nuclei (exposures, misconfigs, default logins, tech detection)
- 📸 **Optional screenshots** — gowitness, off by default
- ⚡ **Priority Highlights tab** — automatically flags CVEs, critical/high nuclei findings, risky open ports (FTP, SMB, MySQL, Redis, MongoDB...), and paths/subdomains matching a configurable keyword list (`admin`, `api`, `backup`, `customer`, `config`, `.git`, ...) — so you see what's worth checking *first*
- 🔴 **Live HTML report** — regenerates after every module finishes and auto-refreshes in your browser while the scan is still running, so you watch results fill in in real time instead of waiting for the whole thing to finish
- 🧰 **Built-in tool checker + auto-installer** — detects missing tools and offers to install them for you
- 🧩 **Fully configurable** — threads, rate limits, parallel jobs, wordlists (separate for subdomains vs. content), file extensions, keyword list, and your own API keys — all from the in-app Settings menu

---

## What it actually does, step by step

```
Target (domain or IP)
   │
   ├─▶ Subdomain Enumeration  (passive sources + active brute-force)
   │        │
   ├─▶ HTTP Probing           (which subdomains are actually alive, and what's on them)
   │        │
   ├─▶ Fast Port Scan         (parallel, rustscan/nmap)
   │        │
   ├─▶ CVE / Version Lookup   (nmap vulners + searchsploit on every open port)
   │        │
   ├─▶ Smart Directory Brute-force  (digs deeper into "interesting" hits automatically)
   │        │
   ├─▶ Nuclei Vulnerability Scan
   │        │
   └─▶ Live HTML Report       (updates after every stage above)
```

---

## Requirements

REKON orchestrates existing, well-known recon tools — it doesn't reinvent them. Install what you can; anything missing is skipped automatically and the tool tells you so.

| Tool | Used for | Install |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | passive subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | passive subdomain enum | `go install github.com/tomnomnom/assetfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | passive subdomain enum | `sudo apt install amass` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [rustscan](https://github.com/RustScan/RustScan) | fast port scan | `sudo apt install rustscan` / `cargo install rustscan` |
| [nmap](https://nmap.org/) | port scan fallback + CVE/version lookup | `sudo apt install nmap` |
| [searchsploit](https://www.exploit-db.com/searchsploit) | offline exploit-DB lookup | `sudo apt install exploitdb` |
| [gobuster](https://github.com/OJ/gobuster) | subdomain brute-force + dir brute-force | `sudo apt install gobuster` |
| [ffuf](https://github.com/ffuf/ffuf) | dir brute-force | `go install github.com/ffuf/ffuf/v2@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [gowitness](https://github.com/sensepost/gowitness) | screenshots (optional) | `go install github.com/sensepost/gowitness@latest` |
| `jq`, `curl` | glue | `sudo apt install jq curl` |

You can also just run the tool — option **3) Check / install tools** in the main menu detects what's missing and offers to install it for you.

---

## Installation

```bash
git clone https://github.com/masturbyte/rekon.git
cd rekon
chmod +x rekon.sh
./rekon.sh
```

Or, if you just have the single script:

```bash
chmod +x rekon.sh
./rekon.sh
```

---

## Usage

Everything is menu-driven — no flags to memorize.

```bash
./rekon.sh
```

```
Main Menu
  1) Run Full Recon (all modules)
  2) Select specific modules (Custom)
  3) Check / install tools
  4) Settings (threads/rate/wordlist/API key)
  5) Exit
```

- **Full Recon** — enter a target, everything runs automatically start to finish.
- **Custom** — toggle individual modules on/off (subdomains, httpx, ports, CVE lookup, dirb, nuclei, screenshots, report) before running.
- **Settings** — tune:
  - port scan threads / nuclei rate limit / parallel jobs
  - a **separate wordlist for subdomain brute-force** and another for **directory/content brute-force**
  - file extensions for the content brute-force (`php,html,asp,aspx,js,txt,bak,zip`, ...)
  - your own Vulners API key (optional — raises rate limits, not required)
  - the keyword list used to flag "interesting" findings
  - live report updates on/off

Results land in a timestamped folder:

```
rekon_<target>_<timestamp>/
├── subdomains/
├── httpx/
├── ports/
├── cve/
├── dirs/
├── nuclei/
├── screenshots/
└── report.html   ← open this, it updates itself while the scan runs
```

---

## The report

`report.html` opens with an **⚡ Highlights** tab first — a short, prioritized list of what's actually worth your time (CVEs, critical/high nuclei hits, risky open ports, interesting paths/subdomains) — before you ever get to the raw dumps in the Subdomains / Ports / CVE / Directories / Nuclei tabs. While a scan is running, the page auto-refreshes every few seconds so you can watch it fill in live.

---

## Configuration reference

All of these live at the top of `rekon.sh` and are also editable live from the **Settings** menu:

| Variable | Default | Purpose |
|---|---|---|
| `THREADS` | `1000` | rustscan batch size |
| `RATE` | `1000` | nuclei request rate |
| `PAR_JOBS` | `10` | parallel scans across hosts |
| `SUB_WORDLIST` | seclists DNS 5000 | subdomain brute-force wordlist |
| `DIRB_WORDLIST` | dirb common.txt | content/directory brute-force wordlist |
| `DIRB_EXTENSIONS` | `php,html,asp,aspx,js,txt,bak,zip` | extensions appended during dirb |
| `SUB_BRUTEFORCE` | `1` | active subdomain brute-force on/off |
| `LIVE_REPORT` | `1` | regenerate `report.html` after every module |
| `INTERESTING_KEYWORDS` | `admin,api,backup,customer,config,...` | what gets flagged in Highlights |
| `RISKY_PORTS` | `21,23,445,1433,3306,3389,6379,...` | ports flagged regardless of CVE results |
| `VULNERS_API_KEY` | *(empty)* | optional, raises `nmap --script vulners` rate limit |

---

## Disclaimer

This tool is intended for **educational use, CTF/lab environments, and authorized security testing only**. The author takes no responsibility for misuse. Always get explicit written permission before scanning any system you do not own.

---

## Credits

**Author:** Ahmed Kori
**GitHub:** [@masturbyte](https://github.com/masturbyte)

---

## Keywords

recon tool, reconnaissance automation, subdomain enumeration, subdomain brute force, fast port scanner, rustscan automation, nmap vulners CVE scan, searchsploit automation, directory brute force, content discovery, ffuf gobuster automation, nuclei vulnerability scanner, bug bounty recon tool, CTF recon script, TryHackMe recon, HackTheBox recon, pentest automation, bash recon script, HTML recon report, automated attack surface mapping
