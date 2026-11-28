import gzip
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

OUTPUT = "Blacklist_hosts.txt"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

SOURCES = [
    "https://adaway.org/hosts.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
    "https://gitlab.com/nobodysu/spyware-hosts/raw/master/lists/android-basic.txt",
    "https://gitlab.com/AuroraOSS/AppWarden/-/raw/master/hosts/warden_trackers.txt",
    "https://perflyst.github.io/PiHoleBlocklist/SmartTV.txt",
    "https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/black.list",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt",
]

DOWNLOAD_ATTEMPTS = 4
DOWNLOAD_TIMEOUT = 120
RETRY_DELAY = 5

# Blocking IP prefixes used in hosts-style sources.
BLOCK_PREFIXES = {"0.0.0.0", "127.0.0.1", "::1"}

# Service and reserved hostnames that must not be treated as blocked domains.
SKIP_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6.localnet",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "ip6-mcastprefix",
    "0.0.0.0",
    "255.255.255.255",
    "fe00::0",
}

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def download(url):
    """Download one source and return its text, or None on failure."""
    last_error = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            )
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
                data = response.read()
                content_encoding = (response.headers.get("Content-Encoding") or "").lower()
            if "gzip" in content_encoding:
                data = gzip.decompress(data)
            text = data.decode("utf-8-sig", errors="replace")
            if text.lstrip().startswith("<"):
                raise ValueError("HTML page received instead of plain text")
            return text
        except Exception as error:
            last_error = error
            print(f"  attempt {attempt}/{DOWNLOAD_ATTEMPTS} failed: {error}", flush=True)
            if attempt < DOWNLOAD_ATTEMPTS:
                time.sleep(RETRY_DELAY * attempt)
    print(f"WARNING: failed to download {url}: {last_error}", flush=True)
    return None


def looks_like_domain(domain):
    """Check that the token is a valid hostname and not a service name."""
    if not domain or len(domain) > 253 or ":" in domain:
        return False
    if domain in SKIP_DOMAINS:
        return False
    if IPV4_RE.match(domain):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or not LABEL_RE.match(label):
            return False
    return True


def extract_domains(text):
    """Extract blocking domains from hosts-style or plain domain list text."""
    domains = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            if parts[0].lower() not in BLOCK_PREFIXES:
                continue
            candidates = parts[1:]
        else:
            # Plain domain list line without an IP prefix.
            candidates = parts[:1]
        for token in candidates:
            domain = token.lower().rstrip(".")
            if looks_like_domain(domain):
                domains.add(domain)
    return domains


def build_output(domains):
    """Return the final hosts file content with the project header."""
    now = datetime.now(timezone.utc)
    last_modified = (
        f"{now.day:02d} {MONTHS[now.month - 1]} {now.year} "
        f"{now.hour:02d}:{now.minute:02d} UTC"
    )
    records = len(domains) + 2  # blocking domains + localhost entries
    lines = [
        "!Title: Meta Gen hosts blacklist",
        f"!Last modified: {last_modified}",
        "!Expires: 1 day",
        f"!Records: {records}",
        "",
        "127.0.0.1 localhost",
        "::1 localhost",
    ]
    lines.extend(f"0.0.0.0 {domain}" for domain in domains)
    return "\n".join(lines) + "\n"


def main():
    sources_ok = 0
    merged = set()
    print(f"Downloading {len(SOURCES)} sources...", flush=True)
    for url in SOURCES:
        text = download(url)
        if text is None:
            continue
        domains = extract_domains(text)
        if not domains:
            print(f"WARNING: no domains found in {url}, skipping", flush=True)
            continue
        merged |= domains
        sources_ok += 1
        print(f"OK: {url} -> {len(domains)} domains", flush=True)
    if sources_ok == 0:
        print("ERROR: all sources failed to download", flush=True)
        return 1
    sorted_domains = sorted(merged)
    tmp_path = OUTPUT + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", newline="\n") as file:
        file.write(build_output(sorted_domains))
    os.replace(tmp_path, OUTPUT)
    print(
        f"Written {OUTPUT}: {len(sorted_domains)} unique domains "
        f"from {sources_ok}/{len(SOURCES)} sources",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())