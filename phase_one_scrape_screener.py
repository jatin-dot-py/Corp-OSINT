#!/usr/bin/env python3
"""Archive a Screener screen and linked company pages as raw HTML."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener, urlopen

import certifi

BASE = "https://www.screener.in/screens/357649/all-listed-companies/"
ROOT = Path(__file__).resolve().parent / "data" / "phase_one" / "screener_output"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ResearchArchive/1.0)", "Accept": "text/html"}
PAGE_RE = re.compile(r"(\d+) results found: Showing page (\d+) of (\d+)")
SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def proxy_url() -> str:
    value = os.environ.get("BRIGHTDATA_PROXY", "")
    if not value and Path(".env").exists():
        for line in Path(".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("BRIGHTDATA_PROXY="):
                value = line.split("=", 1)[1].strip().strip('"\'')
                break
    return value


def make_opener():
    proxy = proxy_url()
    if not proxy:
        return build_opener(HTTPSHandler(context=SSL_CONTEXT))
    parts = urlsplit(proxy)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("BRIGHTDATA_PROXY must be an HTTP or HTTPS proxy URL")
    # Keep credentials out of URL strings, errors and log messages.
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    sanitized = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    opener = build_opener(ProxyHandler({"http": sanitized, "https": sanitized}), HTTPSHandler(context=SSL_CONTEXT))
    if parts.username is not None:
        from urllib.parse import unquote
        token = base64.b64encode(f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()).decode()
        opener.addheaders = [("Proxy-Authorization", f"Basic {token}")]
    return opener


OPENER = make_opener()


class RateLimiter:
    def __init__(self, interval: float):
        self.interval = interval
        self.next_at = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
        if delay:
            time.sleep(delay)


class ScreenParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_table = False
        self.in_row = False
        self.cell = None
        self.rows = []
        self.row = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table" and "data-table" in attrs.get("class", "").split():
            self.in_table = True
        elif self.in_table and tag == "tr":
            self.in_row = True
            self.row = []
        elif self.in_row and tag in ("td", "th"):
            self.cell = {"text": "", "href": ""}
        elif self.cell is not None and tag == "a" and attrs.get("href", "").startswith("/company/"):
            self.cell["href"] = attrs["href"]

    def handle_data(self, data):
        if self.cell is not None:
            self.cell["text"] += data

    def handle_endtag(self, tag):
        if self.cell is not None and tag in ("td", "th"):
            self.cell["text"] = " ".join(self.cell["text"].split())
            self.row.append(self.cell)
            self.cell = None
        elif self.in_row and tag == "tr":
            if self.row:
                self.rows.append(self.row)
            self.in_row = False
        elif self.in_table and tag == "table":
            self.in_table = False


class WebsiteParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.current_href = None
        self.current_has_icon = False
        self.websites = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            self.current_href = attrs.get("href")
            self.current_has_icon = False
        elif tag == "i" and self.current_href and "icon-link" in attrs.get("class", "").split():
            self.current_has_icon = True

    def handle_endtag(self, tag):
        if tag == "a" and self.current_href:
            if self.current_has_icon:
                self.websites.append(self.current_href)
            self.current_href = None
            self.current_has_icon = False


def normalize_website(raw: str) -> str:
    candidates = [raw] + re.findall(r"https?://[^\s\"<>]+", raw)
    for candidate in candidates:
        try:
            parts = urlparse(candidate)
            if parts.scheme in ("http", "https") and parts.hostname and " " not in parts.netloc:
                return candidate
        except ValueError:
            pass
    return ""


def fetch(url: str, limiter: RateLimiter) -> bytes:
    for attempt in range(5):
        limiter.wait()
        try:
            with OPENER.open(Request(url, headers=HEADERS), timeout=40) as response:
                if response.status != 200 or "text/html" not in response.headers.get("Content-Type", ""):
                    raise ValueError(f"Unexpected response: {response.status} {response.headers.get('Content-Type')}")
                body = response.read()
            if len(body) < 1000 or b"<html" not in body[:5000].lower():
                raise ValueError("Response does not look like a complete HTML page")
            return body
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            if "Auth Failed" in str(exc) or "ip_blacklisted" in str(exc):
                raise
            if isinstance(exc, HTTPError) and exc.code not in (429, 500, 502, 503, 504):
                raise
            if attempt == 4:
                raise
            time.sleep(min(60, 2 ** (attempt + 1)))
    raise RuntimeError("Unreachable")


def save_atomic(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_bytes(body)
    tmp.replace(path)


def page_url(page: int) -> str:
    return BASE if page == 1 else f"{BASE}?page={page}"


def parse_page(body: bytes, expected_page: int):
    html = body.decode("utf-8", errors="replace")
    match = PAGE_RE.search(html)
    if not match:
        raise ValueError(f"Page {expected_page}: result count absent")
    total, actual_page, page_count = map(int, match.groups())
    if actual_page != expected_page:
        raise ValueError(f"Expected page {expected_page}, got page {actual_page}")
    parser = ScreenParser()
    parser.feed(html)
    rows = []
    for row in parser.rows:
        if len(row) > 1 and row[1]["href"]:
            rows.append({
                "rank": row[0]["text"].rstrip("."),
                "company": row[1]["text"],
                "company_url": urljoin(BASE, row[1]["href"]),
                "values": [cell["text"] for cell in row[2:]],
            })
    if not rows or (len(rows) != 25 and expected_page != page_count):
        raise ValueError(f"Page {expected_page}: expected 25 company rows, got {len(rows)}")
    return total, page_count, rows


def company_filename(url: str) -> str:
    path = urlparse(url).path.strip("/").removeprefix("company/")
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", path).strip("_")
    return f"{slug}_{hashlib.sha1(url.encode()).hexdigest()[:8]}.html"


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".csv.part")
    with tmp.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def collect_listings(limiter: RateLimiter, max_pages: int | None) -> list[dict]:
    first_path = ROOT / "listings" / "page_0001.html"
    first = first_path.read_bytes() if first_path.exists() else fetch(BASE, limiter)
    total, page_count, _ = parse_page(first, 1)
    if not first_path.exists():
        save_atomic(first_path, first)
    print(f"Screen reports {total} companies on {page_count} pages", flush=True)
    selected = min(page_count, max_pages) if max_pages else page_count
    all_rows = []
    for page in range(1, selected + 1):
        path = ROOT / "listings" / f"page_{page:04d}.html"
        body = path.read_bytes() if path.exists() else fetch(page_url(page), limiter)
        found_total, found_pages, rows = parse_page(body, page)
        if (found_total, found_pages) != (total, page_count):
            raise ValueError(f"Page {page}: screen changed during collection")
        if not path.exists():
            save_atomic(path, body)
        for row in rows:
            row["page"] = page
            row["listing_html"] = str(path.relative_to(ROOT))
            row["values"] = json.dumps(row["values"], ensure_ascii=False)
            all_rows.append(row)
        if page % 25 == 0 or page == selected:
            print(f"Listings: {page}/{selected} pages, {len(all_rows)} rows", flush=True)
    write_csv(ROOT / "listings.csv", ["rank", "company", "company_url", "values", "page", "listing_html"], all_rows)
    (ROOT / "snapshot.json").write_text(json.dumps({
        "source": BASE, "reported_companies": total, "reported_pages": page_count,
        "captured_pages": selected, "captured_rows": len(all_rows),
        "snapshot_at_utc": datetime.now(timezone.utc).isoformat(),
    }, indent=2) + "\n", encoding="utf-8")
    return all_rows


def collect_company(row: dict, limiter: RateLimiter) -> dict:
    url = row["company_url"]
    path = ROOT / "companies" / company_filename(url)
    result = {"rank": row["rank"], "company": row["company"], "company_url": url,
              "company_html": str(path.relative_to(ROOT)), "website_source_href": "", "website_url": "", "website_domain": "",
              "sha256": "", "bytes": "", "status": "", "error": ""}
    try:
        body = path.read_bytes() if path.exists() else fetch(url, limiter)
        parser = WebsiteParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        if not path.exists():
            save_atomic(path, body)
        raw_website = parser.websites[0] if parser.websites else ""
        website = normalize_website(raw_website)
        result.update({"website_source_href": raw_website, "website_url": website,
                       "website_domain": (urlparse(website).hostname or "").removeprefix("www."),
                       "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "status": "ok"})
    except Exception as exc:
        result.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
    return result


def collect_companies(rows: list[dict], limiter: RateLimiter, workers: int, max_companies: int | None) -> None:
    unique = list({row["company_url"]: row for row in rows}.values())
    if max_companies:
        unique = unique[:max_companies]
    results = []
    fields = ["rank", "company", "company_url", "company_html", "website_source_href", "website_url", "website_domain", "sha256", "bytes", "status", "error"]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(unique), 100):
            batch = unique[start:start + 100]
            futures = [pool.submit(collect_company, row, limiter) for row in batch]
            blocked = False
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result["status"] == "error":
                    if "Auth Failed" in result["error"] or "ip_blacklisted" in result["error"]:
                        blocked = True
                    else:
                        print(f"ERROR {result['company_url']}: {result['error']}", flush=True)
            write_csv(ROOT / "companies.csv", fields, sorted(results, key=lambda r: int(r["rank"])))
            good = sum(r["status"] == "ok" for r in results)
            print(f"Companies: {len(results)}/{len(unique)} processed, {good} saved", flush=True)
            if blocked:
                raise RuntimeError("Proxy authentication was blocked; stopped after current batch")


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--stage", choices=["all", "listings", "companies"], default="all")
    cli.add_argument("--interval", type=float, default=0.5, help="Minimum seconds between request starts (default: 0.5)")
    cli.add_argument("--workers", type=int, default=3)
    cli.add_argument("--max-pages", type=int)
    cli.add_argument("--max-companies", type=int)
    args = cli.parse_args()
    if args.interval < 0 or args.workers < 1:
        cli.error("interval must be nonnegative and workers must be positive")
    limiter = RateLimiter(args.interval)
    try:
        if args.stage in ("all", "listings"):
            rows = collect_listings(limiter, args.max_pages)
        else:
            with (ROOT / "listings.csv").open(encoding="utf-8", newline="") as file:
                rows = list(csv.DictReader(file))
        if args.stage in ("all", "companies"):
            collect_companies(rows, limiter, args.workers, args.max_companies)
    except KeyboardInterrupt:
        print("Interrupted. Saved HTML can be reused on the next run.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
