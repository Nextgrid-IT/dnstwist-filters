import os
import subprocess
import json

REPO_URL = "https://raw.githubusercontent.com/sparksbenjamin/dnstwist-filters/main"
INPUT_FILE = "domains.txt"
OUTPUT_DIR = "domains"
README_FILE = "README.md"

def read_watchlist(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def run_dnstwist(domain):
    result = subprocess.run(
        ["dnstwist", "--format", "json", domain],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"dnstwist error for {domain}: {result.stderr}")
    return json.loads(result.stdout)

def save_blocklist(domain, entries):
    filename = domain.replace(".", "_") + ".txt"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        for entry in entries:
            f.write(f"0.0.0.0 {entry}\n")
    print(f"Saved {len(entries)} entries to {path}")
    return filename

def update_readme(domains):
    header = """# DNS Threat Lists

Automatically generated DNS blocklists for use with [Pi-hole](https://pi-hole.net) and [AdGuard Home](https://adguard.com/en/adguard-home/overview.html).

These lists are generated using [dnstwist](https://github.com/dnstwist/dnstwist) to identify potential phishing, typosquatting, and lookalike domains.

## ✅ Usage

Add the raw URL of any list to your Pi-hole or AdGuard installation.

## 📄 Available Blocklists
"""

    entries = []
    for domain in domains:
        safe_name = domain.replace(".", "_")
        url = f"{REPO_URL}/domains/{safe_name}.txt"
        entries.append(f"- [{domain}]({url})")

    footer = """

## 🛠️ Add/Remove Domains

To change the domains being watched:

- Edit `domains.txt`
- Push the update to GitHub
- GitHub Actions will regenerate the lists

## ⚙️ Automated With GitHub Actions

This repo automatically regenerates DNS blocklists every Sunday.
"""

    with open(README_FILE, "w") as f:
        f.write(header + "\n".join(entries) + footer)
    print("README.md updated.")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    domains = read_watchlist(INPUT_FILE)

    for domain in domains:
        try:
            print(f"[*] Processing {domain}...")
            results = run_dnstwist(domain)

            active_domains = [
                r["domain-name"] for r in results
                if r.get("dns-a")
            ]

            save_blocklist(domain, active_domains)

        except Exception as e:
            print(f"[!] Error processing {domain}: {e}")

    update_readme(domains)

if __name__ == "__main__":
    main()
