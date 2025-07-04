import os
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import builtins
print = lambda *args, **kwargs: builtins.print(*args, **kwargs, flush=True)

REPO_URL = "https://raw.githubusercontent.com/sparksbenjamin/dnstwist-filters/main"
INPUT_FILE = "domains.txt"
OUTPUT_DIR = "domains"
README_FILE = "README.md"
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 4))  # Safe default for GitHub Actions
DNS_SERVERS = "1.1.1.1,8.8.8.8"

def read_watchlist(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def run_dnstwist(domain):
    try:
        start = datetime.now()
        print(f"[{start.isoformat()}] → Starting {domain}")
        result = subprocess.run(
            #["dnstwist", "--nameservers", DNS_SERVERS, "--registered", "--format", "json", domain],
            ["dnstwist", "--registered", "--format", "json", domain],
            #["python", "-m","dnstwist", "--nameservers", DNS_SERVERS, "--registered", "--format", "json", domain],
            capture_output=True,
            text=True,
            timeout=120  # Reduced timeout
        )
        end = datetime.now()
        print(f"[{end.isoformat()}] ✓ Finished {domain} in {(end - start).seconds}s")

        if result.returncode != 0:
            raise RuntimeError(f"dnstwist error: {result.stderr.strip()}")
        return domain, json.loads(result.stdout)
    except Exception as e:
        print(f"[!] Error for {domain}: {e}")
        return domain, e

def save_blocklist(domain, entries):
    filename = domain.replace(".", "_") + ".txt"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        for entry in entries:
            f.write(f"0.0.0.0 {entry}\n")
    print(f"✔ Wrote {len(entries)} domains to {path}")
    return filename

def update_readme(domains):
    header = """# DNS Threat Lists

These lists are automatically generated using [dnstwist](https://github.com/dnstwist/dnstwist)
to detect typosquatting and lookalike phishing domains.

## ✅ Usage with Pi-hole or AdGuard

Paste any of the raw list URLs below into your blocklist settings.

## Single File
To use just a single file you can import one list 
https://raw.githubusercontent.com/sparksbenjamin/dnstwist-filters/main/all_domains.txt

## 📄 Available Blocklists
"""

    entries = []
    for domain in domains:
        safe_name = domain.replace(".", "_")
        url = f"{REPO_URL}/domains/{safe_name}.txt"
        entries.append(f"- [{domain}]({url})")

    footer = """

## 🛠️ To Modify

Edit `domains.txt` and commit your changes. GitHub Actions will automatically regenerate blocklists.

## ⏱️ This file is auto-updated weekly.
"""

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(entries) + footer)
    print("📝 README.md updated.")

def process_domain(domain):
    domain, result = run_dnstwist(domain)

    if isinstance(result, Exception):
        return domain, []

    active_domains = [r["domain"] for r in result if r.get("dns_a")]
    save_blocklist(domain, active_domains)
    return domain, active_domains

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    domains = read_watchlist(INPUT_FILE)

    print(f"[+] Processing {len(domains)} domains with {MAX_WORKERS} workers...\n")

    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(process_domain, d): d for d in domains}
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                d, active_domains = future.result()
                results[d] = active_domains
            except Exception as e:
                print(f"[!] Unexpected failure on {domain}: {e}")

    update_readme(domains)
    print("\n✅ All done.")

if __name__ == "__main__":
    main()
