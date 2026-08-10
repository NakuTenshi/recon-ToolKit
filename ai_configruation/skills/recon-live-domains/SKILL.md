# Recon Live Domains

## Description
This skill takes a list of domains, tests them for live HTTP/HTTPS services using `httpx`, then tests remaining non-HTTP domains for DNS resolution using `dnsx`. Results are saved in separate files with a final summary table.

## Trigger
When user says `/recon-live-domains` followed by a filename, e.g.:
/recon-live-domains domains.txt
/recon-live-domains subs.txt
/recon-live-domains /path/to/targets.txt

## Instructions

### Step 1: Parse Input
- Extract the filename from the user's command
- Verify the file exists and contains domains (one per line)
- If file doesn't exist, tell user and stop

### Step 2: Run httpx with Full Detail
Execute httpx on the input file with extended fields to capture complete response details, and save this full output to `httpx_detail_live.txt`. Then extract only the live URLs (first column) into `live_httpx.txt` for easy use in later steps.

```bash
# Run httpx with rich detail
echo <input_file> | httpx -td -sc -title -silent -o httpx_detail_live.txt

# Extract just the URLs (first column) to live_httpx.txt
awk '{print $1}' httpx_detail_live.txt > live_httpx.txt

```

This will:
- Test each domain for HTTP/HTTPS services
- Show status code, title, and technology detection
- Save ONLY domains with active HTTP/HTTPS to live_httpx.txt

`httpx_detail_live.txt` – contains all probed URLs with status code, title, technology, server, CDN, IP, and response time.

`live_httpx.txt` – one live URL per line (used as input for hunting skill and for counting).

### Step 3: Filter Non-HTTP Domains
- Read the original input file
- Read live_httpx.txt and extract just the domain names (first column, stripping protocol)
- Create a list of domains that are in the input file but NOT in live_httpx.txt
- Save this filtered list to a temporary file for dnsx

### Step 4: Run dnsx
Execute on the filtered list (domains without HTTP services):
echo <filtered_domains> | dnsx -silent -t 10 -r ~/resolvers.txt -o live_dnsx.txt

This will:
- Check DNS resolution for remaining domains
- Use resolvers from ~/resolvers.txt
- Save domains that resolve successfully to live_dnsx.txt

If ~/resolvers.txt doesn't exist, fall back to system defaults by omitting the -r flag.

### Step 5: Generate Summary Table

**Overall Summary:**

| Category | Count |
|----------|-------|
| Total Input Domains | X |
| Alive (HTTP/HTTPS) | Y |
| Alive (DNS Only) | Z |
| Dead/Unreachable | X - (Y + Z) |

**HTTP Status Code Breakdown (from live_httpx.txt):**

| Status Code | Meaning | Count |
|-------------|---------|-------|
| 200 | OK | A |
| 301 | Moved Permanently | B |
| 302 | Found | C |
| 403 | Forbidden | D |
| 404 | Not Found | E |
| 500 | Internal Server Error | F |
| ... | ... | ... |

(Add rows for each status code found; omit any that don't appear.)

**Top Technologies Detected (from httpx -td):**

| Technology | Domains Using It |
|------------|------------------|
| WordPress | G |
| Cloudflare | H |
| nginx | I |
| PHP | J |
| jQuery | K |
| ... | ... |

(Show top 10 by frequency. Helps spot common stacks and potential targets.)

**Output files created:**
- `live_httpx.txt` — Domains with active HTTP/HTTPS services (status code, title, technologies)
- `live_dnsx.txt` — Domains alive via DNS only

**Quick Insight (optional one-liner):**  
If many 403/401 appear — possible admin panels or restricted areas worth investigating. If outdated tech is widespread, flag it.