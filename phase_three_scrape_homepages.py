#!/usr/bin/env python3
"""Save Phase 2 homepages and discover same-site links from their HTML.

Uses curl_cffi Chrome impersonation with TLS verification disabled. Each
homepage is attempted through BRIGHTDATA_PROXY first; failures are retried
directly. Reruns resume from the fixed CSV and saved HTML files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from curl_cffi import requests


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "data/phase_two/domain_analysis/direct_scrape_sites.csv"
OUTPUT = ROOT / "data/phase_three"
HTML_DIR = OUTPUT / "homepages"
RESULTS = OUTPUT / "homepages.csv"
LINKS = OUTPUT / "links.csv"
SUMMARY = OUTPUT / "summary.json"
MAX_HTML_BYTES = 16 * 1024 * 1024
MAX_LINKS_PER_PAGE = 5000
BLOCK_TITLES = ("just a moment", "verify you are human", "access denied",
                "checking your browser", "making sure you're not a bot", "captcha challenge")
RESULT_FIELDS = ("domain", "seed_url", "request_url", "saved_url", "html_file", "status", "route",
                 "proxy_status", "proxy_error", "direct_status", "direct_error",
                 "https_proxy_status", "https_proxy_error", "https_direct_status", "https_direct_error",
                 "link_retry_status", "link_retry_error",
                 "http_status", "content_type", "html_bytes", "sha256", "title",
                 "anchor_links", "embedded_links", "internal_links", "external_links",
                 "discovery_status", "crawl_review_reason", "redirected_off_seed",
                 "url_provenance", "checked_at_utc")
LINK_FIELDS = ("domain", "url", "source", "internal")
_LOCAL = threading.local()


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_suffix(path.suffix + ".part")
    with part.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in fields} for row in rows)
    part.replace(path)


def proxy_url() -> str:
    import os
    value = os.environ.get("BRIGHTDATA_PROXY", "")
    if value:
        return value
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("BRIGHTDATA_PROXY="):
                return line.split("=", 1)[1].strip().strip('"\'')
    return ""


def session() -> requests.Session:
    if not hasattr(_LOCAL, "session"):
        # Disables ambient HTTP(S)_PROXY, including on direct retries.
        _LOCAL.session = requests.Session(trust_env=False)
    return _LOCAL.session


def hostname(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except (ValueError, UnicodeError):
        return ""
    return host[4:] if host.startswith("www.") else host


def normalize_link(raw: str, base: str) -> str:
    raw = unescape(raw).strip()
    if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
        return ""
    try:
        parts = urlsplit(urljoin(base, raw))
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            return ""
        host = parts.hostname.lower().rstrip(".")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return ""
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            return ""
        host = host.encode("idna").decode("ascii")
        netloc = f"[{host}]" if ":" in host else host
        port = parts.port
        if port and port != (443 if parts.scheme == "https" else 80):
            netloc += f":{port}"
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="=&?/%:@!$'()*+,;+-._~")
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    except (ValueError, UnicodeError):
        return ""


class AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.navigation_refs: list[tuple[str, str]] = []
        self.base_href = ""
        self.title_parts: list[str] = []
        self.in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs = dict(attrs)
        if tag in ("a", "area") and attrs.get("href"):
            self.hrefs.append(attrs["href"])
        elif tag == "frame" and attrs.get("src"):
            self.navigation_refs.append((attrs["src"], "frame"))
        elif tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            match = re.search(r"(?:^|;)\s*url\s*=\s*['\"]?([^'\";]+)", attrs.get("content") or "", re.I)
            if match:
                self.navigation_refs.append((match.group(1), "meta_refresh"))
        elif tag == "base" and attrs.get("href") and not self.base_href:
            self.base_href = attrs["href"]
        elif tag == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def decode_html(body: bytes, content_type: str) -> str:
    header = re.search(r"charset\s*=\s*['\"]?([^;\s'\"]+)", content_type, re.I)
    head = body[:4096].decode("ascii", "ignore")
    meta = re.search(r"<meta[^>]+charset\s*=\s*['\"]?([^;\s'\"/>]+)", head, re.I)
    for encoding in (header.group(1) if header else "", meta.group(1) if meta else "", "utf-8"):
        if encoding:
            try:
                return body.decode(encoding, "replace")
            except LookupError:
                pass
    return body.decode("utf-8", "replace")


def discover(domain: str, final_url: str, body: bytes, content_type: str) -> tuple[list[dict], dict]:
    html = decode_html(body, content_type)
    parser = AnchorParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    base = normalize_link(parser.base_href, final_url) if parser.base_href else final_url
    if not base:
        base = final_url
    found: dict[str, dict] = {}
    anchor_count = embedded_count = 0

    def add(raw: str, source: str) -> None:
        nonlocal anchor_count, embedded_count
        if len(found) >= MAX_LINKS_PER_PAGE:
            return
        url = normalize_link(raw, base)
        if not url or url == normalize_link(final_url, final_url) or url in found:
            return
        host = hostname(url)
        site = hostname(final_url)
        internal = host == site or host.endswith("." + site)
        found[url] = {"domain": domain, "url": url, "source": source,
                      "internal": "true" if internal else "false"}
        if source == "anchor":
            anchor_count += 1
        else:
            embedded_count += 1

    for raw in parser.hrefs:
        add(raw, "anchor")
    for raw, source in parser.navigation_refs:
        add(raw, source)
    links = list(found.values())
    internal = sum(row["internal"] == "true" for row in links)
    title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()[:250]
    return links, {"title": title, "anchor_links": anchor_count,
                   "embedded_links": embedded_count, "internal_links": internal,
                   "external_links": len(links) - internal,
                   "discovery_status": "links_found" if internal else "no_internal_links"}


def fetch(url: str, proxy: str | None, timeout: float) -> dict:
    result = {"http_status": "", "content_type": "", "final_url": "", "body": b"", "error": ""}
    response = None
    try:
        response = session().get(url, proxy=proxy, impersonate="chrome", verify=False,
                                 timeout=timeout, allow_redirects=True, max_redirects=6,
                                 stream=True, headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"})
        result["http_status"] = str(response.status_code)
        result["content_type"] = response.headers.get("content-type", "")
        result["final_url"] = response.url
        chunks = []
        size = 0
        for chunk in response.iter_content(chunk_size=65536):
            size += len(chunk)
            if size > MAX_HTML_BYTES:
                result["error"] = "html_exceeds_16_mib"
                return result
            chunks.append(chunk)
        body = b"".join(chunks)
        result["body"] = body
        head = body[:8192].decode("utf-8", "ignore").lower()
        title_match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", head, re.I | re.S)
        title = re.sub(r"\s+", " ", unescape(title_match.group(1))) if title_match else ""
        looks_html = ("html" in result["content_type"].lower() or
                      "<html" in head or "<!doctype html" in head)
        if not 200 <= response.status_code < 300:
            result["error"] = f"http_{response.status_code}"
        elif response.headers.get("cf-mitigated", "").lower() == "challenge":
            result["error"] = "cloudflare_challenge"
        elif not looks_html:
            result["error"] = "not_html"
        elif "window.gokuprops" in head or any(marker in title for marker in BLOCK_TITLES):
            result["error"] = "block_page"
        elif not body:
            result["error"] = "empty_html"
    except Exception as exc:
        # Never put the proxy URL (which contains credentials) into output.
        message = str(exc)
        if proxy:
            message = message.replace(proxy, "[proxy]")
        result["error"] = f"{type(exc).__name__}: {message}"[:300]
    finally:
        if response is not None:
            response.close()
    return result


def save_html(domain: str, body: bytes) -> str:
    HTML_DIR.mkdir(parents=True, exist_ok=True)
    path = HTML_DIR / f"{domain}.html"
    part = path.with_suffix(".html.part")
    part.write_bytes(body)
    part.replace(path)
    return str(path.relative_to(ROOT))


def run_one(item: dict, route: str, proxy: str | None, timeout: float) -> dict:
    attempt = fetch(item["url"], proxy, timeout)
    result = {"domain": item["domain"], "seed_url": item["url"], "request_url": item["url"],
              "route": route, "http_status": attempt["http_status"],
              "content_type": attempt["content_type"], "saved_url": attempt["final_url"],
              "checked_at_utc": datetime.now(timezone.utc).isoformat()}
    result[f"{route}_status"] = attempt["http_status"]
    result[f"{route}_error"] = attempt["error"]
    if attempt["error"]:
        result["status"] = "failed"
        return result
    body = attempt["body"]
    result["html_file"] = save_html(item["domain"], body)
    result["html_bytes"] = len(body)
    result["sha256"] = hashlib.sha256(body).hexdigest()
    result["status"] = "saved"
    result["redirected_off_seed"] = str(hostname(item["url"]) != hostname(attempt["final_url"])).lower()
    result["url_provenance"] = "observed_response"
    return result


def retry_https(row: dict, proxy: str, timeout: float) -> dict:
    parts = urlsplit(row["seed_url"])
    https_url = urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))
    result = {"domain": row["domain"], "request_url": https_url}
    successful = None
    used_route = ""
    for route, route_proxy in (("https_proxy", proxy), ("https_direct", None)):
        attempt = fetch(https_url, route_proxy, timeout)
        result[f"{route}_status"] = attempt["http_status"]
        result[f"{route}_error"] = attempt["error"]
        if not attempt["error"]:
            successful, used_route = attempt, "proxy" if route_proxy else "direct"
            break
    if successful is None:
        return result
    body = successful["body"]
    result.update({"status": "saved", "route": used_route, "saved_url": successful["final_url"],
                   "html_file": save_html(row["domain"], body), "http_status": successful["http_status"],
                   "content_type": successful["content_type"], "html_bytes": len(body),
                   "sha256": hashlib.sha256(body).hexdigest(), "url_provenance": "observed_response",
                   "redirected_off_seed": str(hostname(row["seed_url"]) != hostname(successful["final_url"])).lower(),
                   "checked_at_utc": datetime.now(timezone.utc).isoformat()})
    return result


def retry_zero_links(row: dict, timeout: float) -> dict:
    attempt = fetch(row["seed_url"], None, timeout)
    result = {"domain": row["domain"], "link_retry_status": "failed" if attempt["error"] else "not_better",
              "link_retry_error": attempt["error"], "direct_status": attempt["http_status"],
              "direct_error": attempt["error"]}
    if attempt["error"]:
        return result
    new_links, counts = discover(row["domain"], attempt["final_url"], attempt["body"], attempt["content_type"])
    if counts["internal_links"] <= int(row.get("internal_links") or 0):
        return result
    body = attempt["body"]
    result.update({"link_retry_status": "improved", "status": "saved", "route": "direct",
                   "saved_url": attempt["final_url"], "html_file": save_html(row["domain"], body),
                   "http_status": attempt["http_status"], "content_type": attempt["content_type"],
                   "html_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                   "redirected_off_seed": str(hostname(row["seed_url"]) != hostname(attempt["final_url"])).lower(),
                   "url_provenance": "observed_response", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                   **counts})
    return result


def crawl_review_reason(row: dict, body: bytes) -> str:
    if row.get("status") != "saved":
        return "fetch_failed"
    head = body[:65536].decode("utf-8", "ignore").lower()
    title = row.get("title", "").lower()
    if any(marker in head for marker in ("window.gokuprops", "cf-chl-", "checking your browser before redirecting",
                                       "making sure you're not a bot", "verify you are human")):
        return "challenge_or_interstitial"
    if any(marker in title for marker in ("domain expired", "domain for sale", "suspended domain",
                                          "website under development", "website temporarily unavailable",
                                          "welcome to nginx", "iis windows server", "web server's default page")):
        return "parked_or_placeholder"
    if int(row.get("internal_links") or 0) > 0:
        return ""
    if re.search(r"<(?:frame|iframe)\b|http-equiv\s*=\s*['\"]?refresh", head, re.I):
        return "frame_or_redirect_shell"
    if int(row.get("external_links") or 0) > 0:
        return "external_links_only"
    parser = AnchorParser()
    try:
        parser.feed(decode_html(body, row.get("content_type", "")))
    except Exception:
        pass
    if parser.hrefs:
        if any(href.strip().lower().startswith("javascript:") for href in parser.hrefs):
            return "javascript_navigation"
        return "anchors_without_deep_urls"
    if len(body) < 1000:
        return "thin_html"
    if "<script" in head:
        return "no_static_navigation_js_present"
    return "no_links_found"


def rebuild_links(rows: list[dict]) -> dict:
    all_links = []
    for row in rows:
        if row.get("status") != "saved":
            row["crawl_review_reason"] = "fetch_failed"
            continue
        if not row.get("url_provenance") and row.get("saved_url"):
            row["url_provenance"] = "observed_response"
        path = ROOT / row["html_file"]
        if not path.exists():
            row["crawl_review_reason"] = "missing_html_file"
            continue
        body = path.read_bytes()
        links, counts = discover(row["domain"], row["saved_url"], body, row["content_type"])
        row.update(counts)
        row["crawl_review_reason"] = crawl_review_reason(row, body)
        all_links.extend(links)
    write_csv(LINKS, all_links, LINK_FIELDS)
    write_csv(RESULTS, rows, RESULT_FIELDS)
    summary = {"source_sites": len(read_csv(SOURCE)), "saved_homepages": sum(r.get("status") == "saved" for r in rows),
               "failed_homepages": sum(r.get("status") == "failed" for r in rows),
               "saved_by_route": dict(Counter(r.get("route") for r in rows if r.get("status") == "saved")),
               "url_provenance": dict(Counter(r.get("url_provenance") for r in rows if r.get("status") == "saved")),
               "zero_link_direct_retries": dict(Counter(r.get("link_retry_status") for r in rows if r.get("link_retry_status"))),
               "discovery_status": dict(Counter(r.get("discovery_status") for r in rows if r.get("status") == "saved")),
               "crawl_review_reasons": dict(Counter(r.get("crawl_review_reason") for r in rows if r.get("crawl_review_reason"))),
               "internal_links": sum(int(r.get("internal_links") or 0) for r in rows),
               "external_links": sum(int(r.get("external_links") or 0) for r in rows),
               "generated_at_utc": datetime.now(timezone.utc).isoformat()}
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    part = SUMMARY.with_suffix(".json.part")
    part.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    part.replace(SUMMARY)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--timeout", type=float, default=25)
    parser.add_argument("--limit", type=int, default=0, help="First N source sites, for a pilot")
    parser.add_argument("--rebuild-only", action="store_true", help="Parse saved HTML without network requests")
    parser.add_argument("--skip-zero-retry", action="store_true", help="Do not retry zero-link proxy pages directly")
    parser.add_argument("--retry-zero-only", action="store_true", help="Only retry saved zero-link pages directly")
    parser.add_argument("--https-only", action="store_true", help="Only retry failed HTTP seeds as HTTPS")
    parser.add_argument("--force", action="store_true", help="Refetch even saved homepages")
    args = parser.parse_args()
    items = read_csv(SOURCE)
    if args.limit:
        items = items[:args.limit]
    indexed = {row["domain"]: row for row in read_csv(RESULTS)}
    if args.rebuild_only:
        print(json.dumps(rebuild_links(list(indexed.values())), indent=2))
        return
    # A previous interrupted run may have atomically saved HTML before its
    # next CSV checkpoint. Phase 2's seed was itself a final response URL.
    recovered = 0
    for item in items:
        if item["domain"] in indexed:
            continue
        path = HTML_DIR / f"{item['domain']}.html"
        if not path.exists():
            continue
        body = path.read_bytes()
        indexed[item["domain"]] = {
            "domain": item["domain"], "seed_url": item["url"], "saved_url": item["url"],
            "html_file": str(path.relative_to(ROOT)), "status": "saved", "route": "proxy",
            "proxy_status": "2xx", "http_status": "2xx", "content_type": "text/html",
            "html_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "redirected_off_seed": "unknown", "url_provenance": "phase2_final_url",
            "checked_at_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
        }
        recovered += 1
    if recovered:
        write_csv(RESULTS, list(indexed.values()), RESULT_FIELDS)
        print(f"Recovered {recovered} saved HTML files from interrupted checkpoint", flush=True)
    proxy = proxy_url()
    if not proxy:
        raise SystemExit("BRIGHTDATA_PROXY is required for the proxy-first sweep")
    if args.workers < 1:
        raise SystemExit("--workers must be positive")
    pending = [] if args.retry_zero_only or args.https_only else [
        item for item in items if args.force or indexed.get(item["domain"], {}).get("status") != "saved"
        or not (ROOT / indexed[item["domain"]].get("html_file", "missing")).exists()
    ]
    print(f"Phase 3: {len(items)} source sites, {len(pending)} pending, {args.workers} workers", flush=True)
    for route, targets, route_proxy in (("proxy", pending, proxy),
                                        ("direct", [], None)):
        if route == "direct":
            targets = [item for item in pending if indexed.get(item["domain"], {}).get("status") != "saved"]
        if not targets:
            continue
        print(f"{route}: {len(targets)} requests", flush=True)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(run_one, item, route, route_proxy, args.timeout): item for item in targets}
            for n, future in enumerate(as_completed(futures), 1):
                item = futures[future]
                try:
                    fresh = future.result()
                except Exception as exc:
                    fresh = {"domain": item["domain"], "seed_url": item["url"], "route": route,
                             "status": "failed", f"{route}_error": f"{type(exc).__name__}: {exc}"[:300]}
                prior = indexed.get(item["domain"], {})
                indexed[item["domain"]] = {**prior, **fresh}
                if n % 25 == 0 or n == len(targets):
                    write_csv(RESULTS, list(indexed.values()), RESULT_FIELDS)
                    print(f"{route}: completed {n}/{len(targets)}", flush=True)
    if not args.retry_zero_only:
        https_rows = [row for row in indexed.values() if row.get("status") == "failed"
                      and row.get("seed_url", "").startswith("http://")
                      and (args.force or not row.get("https_proxy_status") and not row.get("https_proxy_error"))]
        print(f"HTTPS upgrade retry: {len(https_rows)} sites", flush=True)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(retry_https, row, proxy, args.timeout): row for row in https_rows}
            for n, future in enumerate(as_completed(futures), 1):
                row = futures[future]
                indexed[row["domain"]].update(future.result())
                if n % 10 == 0 or n == len(https_rows):
                    write_csv(RESULTS, list(indexed.values()), RESULT_FIELDS)
                    print(f"HTTPS upgrade retry: completed {n}/{len(https_rows)}", flush=True)
    rebuild_links(list(indexed.values()))
    if not args.skip_zero_retry:
        zero_rows = [row for row in indexed.values() if row.get("status") == "saved"
                     and row.get("route") == "proxy" and row.get("discovery_status") == "no_internal_links"
                     and (args.force or not row.get("link_retry_status"))]
        print(f"direct zero-link retry: {len(zero_rows)} requests", flush=True)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(retry_zero_links, row, args.timeout): row for row in zero_rows}
            for n, future in enumerate(as_completed(futures), 1):
                row = futures[future]
                fresh = future.result()
                indexed[row["domain"]].update(fresh)
                if n % 25 == 0 or n == len(zero_rows):
                    write_csv(RESULTS, list(indexed.values()), RESULT_FIELDS)
                    print(f"direct zero-link retry: completed {n}/{len(zero_rows)}", flush=True)
    print(json.dumps(rebuild_links(list(indexed.values())), indent=2))


if __name__ == "__main__":
    main()
