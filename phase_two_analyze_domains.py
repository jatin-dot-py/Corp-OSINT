#!/usr/bin/env python3
"""Analyze listed-company domains, retry HTTP 403s, and maintain four fixed outputs."""

from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from datetime import datetime, timezone
from html import unescape
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlparse, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

import certifi
from curl_cffi import requests



ROOT = Path(__file__).resolve().parent


SOURCE = ROOT / "data" / "phase_one" / "screener_output" / "companies.csv"


OUTPUT = ROOT / "data" / "phase_two" / "domain_analysis"


MAX_BODY = 16384


MAX_REDIRECTS = 5


GENERIC_BASES = (
    "google.com", "google.co.in", "youtube.com", "youtu.be", "facebook.com",
    "instagram.com", "linkedin.com", "twitter.com", "x.com", "wikipedia.org",
    "bit.ly", "tinyurl.com", "linktr.ee",
)


PARKED_PHRASES = (
    "domain for sale", "buy this domain", "this domain is for sale",
    "domain has expired", "this domain has expired", "account suspended",
    "under construction", "coming soon",
)


BLOCKED_PHRASES = ("access denied", "captcha", "just a moment", "verify you are human")


OPENER = None


SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def proxy_url() -> str:
    value = os.environ.get("BRIGHTDATA_PROXY", "")
    env_file = ROOT / ".env"
    if not value and env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("BRIGHTDATA_PROXY="):
                return line.split("=", 1)[1].strip().strip('"\'')
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class RateLimiter:
    def __init__(self, interval: float):
        self.interval = interval
        self.next_at = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
        if delay:
            time.sleep(delay)


def make_proxy_opener():
    raw = proxy_url()
    if not raw:
        raise SystemExit("BRIGHTDATA_PROXY is required; phase two never falls back to direct traffic")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is None:
        raise SystemExit("BRIGHTDATA_PROXY must be an authenticated HTTP(S) proxy URL")
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    sanitized = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    opener = build_opener(ProxyHandler({"http": sanitized, "https": sanitized}),
                          HTTPSHandler(context=SSL_CONTEXT), NoRedirect())
    credentials = f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()
    opener.addheaders = [("Proxy-Authorization", "Basic " + base64.b64encode(credentials).decode())]
    return opener


def canonical_host(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def generic_base(host: str) -> str:
    host = canonical_host(host)
    return next((base for base in GENERIC_BASES if host == base or host.endswith("." + base)), "")


def source_host_warning(url: str) -> tuple[str, str]:
    try:
        parsed = urlparse(url)
        raw_host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return "", "malformed_source_url"
    if parsed.scheme not in ("http", "https") or not raw_host:
        return "", "malformed_source_url"
    host = raw_host.rstrip(",;")
    warnings = []
    if host != raw_host:
        warnings.append("trailing_host_punctuation")
    if parsed.username or parsed.password:
        warnings.append("source_url_has_userinfo")
    if port and port not in (80, 443):
        warnings.append("nonstandard_port")
    return host, ";".join(warnings)


def validate_url(url: str) -> tuple[str, str]:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return "", "malformed_url"
    if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
        return "", "malformed_url"
    if port and port not in (80, 443):
        return "", "nonstandard_port"
    host = canonical_host(host)
    if host in ("localhost",) or host.endswith((".local", ".localhost", ".internal")):
        return host, "nonpublic_host"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return host, "ip_address_url" if address.is_global else "nonpublic_host"
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return host, "invalid_domain_syntax"
    if len(ascii_host) > 253 or "." not in ascii_host or any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", part) or len(part) > 63
        for part in ascii_host.split(".")
    ):
        return host, "invalid_domain_syntax"
    return host, ""


def response_record(url: str, status: int | str = "", headers=None, body: bytes = b"", error: str = "") -> dict:
    parsed = urlparse(url)
    title_match = re.search(rb"<title\b[^>]*>(.*?)</title\s*>", body, re.I | re.S)
    title = unescape(re.sub(r"\s+", " ", title_match.group(1).decode("utf-8", "replace")).strip()) if title_match else ""
    content_type = (headers.get("Content-Type", "") if headers else "").split(";", 1)[0].lower().strip()
    return {"http_status": status, "final_url": url, "final_domain": canonical_host(parsed.hostname or ""),
            "content_type": content_type, "content_length": headers.get("Content-Length", "") if headers else "",
            "body_bytes": len(body), "title": title[:250], "error": error,
            "body_signal": " ".join(body[:MAX_BODY].decode("utf-8", "replace").lower().split())[:1000]}


def request_homepage(start_url: str, limiter: RateLimiter, timeout: float) -> dict:
    current = start_url
    redirects = []
    for _ in range(MAX_REDIRECTS + 1):
        host, problem = validate_url(current)
        if problem:
            result = response_record(current, error=problem)
            result["redirects"] = json.dumps(redirects)
            return result
        limiter.wait()
        request = Request(current, headers={
            "User-Agent": "Mozilla/5.0 (compatible; CompanyDomainPreflight/1.0)",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity",
        })
        try:
            response = OPENER.open(request, timeout=timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError, ssl.SSLError, OSError, HTTPException, ValueError) as exc:
            message = str(exc)
            kind = "proxy_blocked" if "ip_blacklisted" in message or "Auth Failed" in message else type(exc).__name__
            result = response_record(current, error=kind + (":" + message[:120] if kind != "proxy_blocked" else ""))
            result["redirects"] = json.dumps(redirects)
            return result
        with response:
            status = response.status or response.code
            if status in (301, 302, 303, 307, 308) and response.headers.get("Location"):
                current = urljoin(current, response.headers["Location"])
                redirects.append(current)
                continue
            try:
                body = response.read(MAX_BODY)
            except (TimeoutError, OSError, HTTPException):
                body = b""
            result = response_record(current, status, response.headers, body)
            result["redirects"] = json.dumps(redirects)
            return result
    result = response_record(current, error="redirect_limit")
    result["redirects"] = json.dumps(redirects)
    return result


def probe(domain: str, source_url: str, limiter: RateLimiter, timeout: float) -> dict:
    started = time.monotonic()
    record = {"domain": domain, "source_url": source_url,
              "checked_at_utc": datetime.now(timezone.utc).isoformat(), "proxy_used": "true"}
    original_host, source_warning = source_host_warning(source_url)
    source_host, invalid = validate_url(f"https://{original_host}/") if original_host else ("", "malformed_url")
    record["source_warning"] = source_warning
    if generic_base(domain):
        result = response_record(source_url, error="generic_destination:" + generic_base(domain))
        result["redirects"] = "[]"
        record["probe_url"] = ""
    elif invalid:
        result = response_record(source_url, error=invalid)
        result["redirects"] = "[]"
        record["probe_url"] = ""
    else:
        candidates = [f"https://{original_host}/", f"http://{original_host}/"]
        best = None
        best_url = ""
        for candidate in candidates:
            observed = request_homepage(candidate, limiter, timeout)
            if best is None or (str(observed["http_status"]).startswith("2") and not str(best["http_status"]).startswith("2")):
                best, best_url = observed, candidate
            if str(observed["http_status"]).startswith("2") or observed["error"] == "proxy_blocked":
                break
        result = best or response_record(candidates[0], error="no_response")
        record["probe_url"] = best_url
    record.update(result)
    record["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return record


def classify(row: dict, result: dict, count: int) -> tuple[str, str]:
    error = result["error"]
    status = str(result["http_status"])
    original_host, source_warning = source_host_warning(row["website_url"])
    source_domain = canonical_host(original_host)
    final_domain = result["final_domain"]
    reasons = []
    if generic_base(source_domain):
        return "exclude", "generic_destination:" + generic_base(source_domain)
    if error.startswith("generic_destination:"):
        return "exclude", error
    if error in ("malformed_url", "invalid_domain_syntax", "nonpublic_host", "ip_address_url", "nonstandard_port"):
        return "exclude", error
    if error == "proxy_blocked":
        return "unverified", "proxy_blocked"
    if error:
        reasons.append("homepage_probe_error")
    if not status.startswith("2"):
        reasons.append("homepage_not_2xx")
    if status.startswith("2") and result["content_type"] not in ("text/html", "application/xhtml+xml"):
        reasons.append("non_html_homepage")
    if generic_base(final_domain):
        return "exclude", "redirects_to_generic:" + generic_base(final_domain)
    if final_domain and final_domain != source_domain:
        reasons.append("cross_domain_redirect")
    if count > 1:
        reasons.append("duplicate_domain")
    if source_warning:
        reasons.extend(source_warning.split(";"))
    title_and_excerpt = (result["title"] + " " + result["body_signal"]).lower()
    if any(phrase in title_and_excerpt for phrase in PARKED_PHRASES):
        reasons.append("parked_or_incomplete")
    if any(phrase in title_and_excerpt for phrase in BLOCKED_PHRASES):
        reasons.append("access_challenge")
    if reasons:
        return "review", ";".join(dict.fromkeys(reasons))
    return "ready", "homepage_2xx_html"


def run_scan():
    global OPENER
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--workers", type=int, default=20)
    cli.add_argument("--interval", type=float, default=0.1, help="Minimum seconds between proxy request starts")
    cli.add_argument("--timeout", type=float, default=10.0)
    cli.add_argument("--max-domains", type=int, help="Small validation run")
    args = cli.parse_args()
    if args.workers < 1 or args.interval < 0 or args.timeout <= 0:
        cli.error("invalid workers, interval, or timeout")
    OPENER = make_proxy_opener()
    with SOURCE.open(encoding="utf-8", newline="") as file:
        companies = list(csv.DictReader(file))
    output = OUTPUT / "_sample" if args.max_domains else OUTPUT
    domain_sources = {}
    for row in companies:
        domain = canonical_host(source_host_warning(row["website_url"])[0])
        domain_sources.setdefault(domain, row["website_url"])
    selected = list(domain_sources.items())[:args.max_domains] if args.max_domains else list(domain_sources.items())
    checks_path = output / "checks.csv"
    cached = {}
    for check in read_checks(checks_path):
        if check["route"] != "initial" or check["error"] in ("proxy_blocked", "malformed_url"):
            continue
        if check["error"].startswith("generic_destination:") and not generic_base(check["domain"]):
            continue
        domain = check["domain"]
        source = domain_sources.get(domain, "")
        cached[domain] = {"domain": domain, "source_url": source,
                          "source_warning": source_host_warning(source)[1],
                          "checked_at_utc": check["checked_at_utc"], "proxy_used": check["proxy_used"],
                          "probe_url": check["request_url"], "http_status": check["http_status"],
                          "final_url": check["final_url"], "final_domain": check["final_domain"],
                          "content_type": check["content_type"], "content_length": "",
                          "body_bytes": check["body_bytes"], "title": check["title"], "error": check["error"],
                          "body_signal": check["body_signal"], "redirects": check["redirects"],
                          "elapsed_ms": check["elapsed_ms"]}
    results = {domain: cached[domain] for domain, _ in selected if domain in cached}
    remaining = [(domain, source) for domain, source in selected if domain not in results]
    limiter = RateLimiter(args.interval)
    pool = ThreadPoolExecutor(max_workers=args.workers)
    pending = {}
    iterator = iter(remaining)

    def submit_one():
        try:
            domain, source = next(iterator)
        except StopIteration:
            return False
        pending[pool.submit(probe, domain, source, limiter, args.timeout)] = domain
        return True

    try:
        for _ in range(min(args.workers * 2, len(remaining))):
            submit_one()
        blocked = False
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                domain = pending.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"domain": domain, "source_url": domain_sources[domain],
                              "checked_at_utc": datetime.now(timezone.utc).isoformat(), "proxy_used": "true",
                              "source_warning": "",
                              "probe_url": "", **response_record(domain_sources[domain], error=type(exc).__name__),
                              "redirects": "[]", "elapsed_ms": ""}
                results[domain] = result
                if result["error"] == "proxy_blocked":
                    blocked = True
                if not blocked:
                    submit_one()
            if len(results) % 100 < len(done) or not pending or blocked:
                upsert_checks([initial_check(results[d]) for d, _ in selected if d in results], checks_path)
                print(f"Domains checked: {len(results)}/{len(selected)}", flush=True)
            if blocked:
                for future in pending:
                    future.cancel()
                break
    finally:
        pool.shutdown(wait=not blocked, cancel_futures=blocked)
    if blocked:
        raise SystemExit("Bright Data rejected proxy authentication; saved progress without marking domains invalid")
    upsert_checks([initial_check(results[d]) for d, _ in selected if d in results], checks_path)
    summary = build_outputs(output)
    print(json.dumps(summary, indent=2), flush=True)


ROUTES = ("initial", "proxy_curl", "india_proxy", "direct", "direct_noverify")


CHECK_FIELDS = ("domain", "route", "client", "impersonate", "proxy_used", "proxy_exit_country", "tls_verified",
                "checked_at_utc", "request_url", "http_status", "final_url", "final_domain",
                "content_type", "body_bytes", "title", "error", "body_signal", "redirects",
                "elapsed_ms", "outcome")


DOMAIN_FIELDS = ("domain", "source_url", "source_warning", "companies_on_domain", "initial_status",
                 "proxy_curl_status", "india_proxy_status", "direct_status", "direct_noverify_status",
                 "scrape_mode", "scrape_url", "route_evidence",
                 "selected_status", "selected_route", "selected_url", "selected_domain",
                 "selected_content_type", "selected_title", "reachability", "tls_verified",
                 "decision", "reasons", "checks_count")


COMPANY_FIELDS = ("rank", "company", "company_url", "website_url", "domain", "companies_on_domain",
                  "scrape_mode", "scrape_url", "route_evidence",
                  "decision", "reasons", "homepage_status", "final_url", "final_domain", "title",
                  "probe_error", "selected_route", "reachability", "tls_verified")


DIRECT_SITE_FIELDS = ("domain", "url", "direct_status", "evidence")


CHECKS = OUTPUT / "checks.csv"
DIRECTORY = OUTPUT


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".part")
    with temp.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in fields} for row in rows)
    temp.replace(path)


def outcome(status: str, content_type: str, error: str) -> str:
    if error:
        return "request_error"
    if status == "403":
        return "still_403"
    if status.startswith("2") and content_type in ("text/html", "application/xhtml+xml"):
        return "recovered_2xx_html"
    if status.startswith("2"):
        return "2xx_non_html"
    return "other_http_status" if status else "not_requested"


def initial_check(row: dict) -> dict:
    status = str(row.get("http_status", ""))
    requested = bool(row.get("probe_url", ""))
    check_outcome = outcome(status, row.get("content_type", ""), row.get("error", "")) if requested else "not_requested"
    return {"domain": row["domain"], "route": "initial", "client": "urllib",
            "impersonate": "",
            "proxy_used": row.get("proxy_used", "true") if requested else "false", "proxy_exit_country": "",
            "tls_verified": "true", "checked_at_utc": row.get("checked_at_utc", ""),
            "request_url": row.get("probe_url", ""), "http_status": status,
            "final_url": row.get("final_url", ""), "final_domain": row.get("final_domain", ""),
            "content_type": row.get("content_type", ""), "body_bytes": row.get("body_bytes", ""),
            "title": row.get("title", ""), "error": row.get("error", ""),
            "body_signal": row.get("body_signal", ""), "redirects": row.get("redirects", ""),
            "elapsed_ms": row.get("elapsed_ms", ""),
            "outcome": check_outcome}


def curl_check(row: dict, route: str) -> dict:
    final_url = row.get("curl_final_url", "")
    return {"domain": row["domain"], "route": route, "client": "curl_cffi",
            "impersonate": "chrome",
            "proxy_used": row.get("proxy_used", ""),
            "proxy_exit_country": "IN" if route == "india_proxy" else "",
            "tls_verified": "false" if route == "direct_noverify" else "true",
            "checked_at_utc": row.get("checked_at_utc", ""),
            "request_url": row.get("original_url", ""),
            "http_status": row.get("curl_status", ""), "final_url": final_url,
            "final_domain": canonical_host(urlparse(final_url).hostname or ""),
            "content_type": row.get("content_type", ""), "body_bytes": row.get("body_bytes", ""),
            "title": row.get("title", ""), "error": row.get("error", ""),
            "body_signal": "", "redirects": "", "elapsed_ms": "",
            "outcome": row.get("outcome", "")}


def read_checks(path: Path = CHECKS) -> list[dict]:
    return read_csv(path)


def upsert_checks(new_rows: list[dict], path: Path = CHECKS):
    indexed = {(row["domain"], row["route"]): row for row in read_checks(path)}
    indexed.update({(row["domain"], row["route"]): row for row in new_rows})
    rows = sorted(indexed.values(), key=lambda row: (row["domain"], ROUTES.index(row["route"])))
    write_csv(path, rows, CHECK_FIELDS)


def select_check(checks: dict[str, dict]) -> dict:
    for route in reversed(ROUTES):
        check = checks.get(route)
        if check and check["outcome"] == "recovered_2xx_html" and check["tls_verified"] == "true":
            return check
    for route in reversed(ROUTES):
        check = checks.get(route)
        if check and check["outcome"] == "recovered_2xx_html":
            return check
    return next(checks[route] for route in reversed(ROUTES) if route in checks)


def reachability(check: dict) -> str:
    if check["outcome"] == "recovered_2xx_html":
        if check["tls_verified"] != "true":
            return "direct_tls_unverified"
        return "direct_only" if check["route"] == "direct" else "proxy_reachable"
    if check["outcome"] == "still_403":
        return "http_403"
    if check["outcome"] == "request_error":
        return "probe_error"
    return check["outcome"]


def fetchable_html(check: dict | None) -> bool:
    if not check or check.get("outcome") != "recovered_2xx_html":
        return False
    if generic_base(check.get("final_domain", "")):
        return False
    content = (check.get("title", "") + " " + check.get("body_signal", "")).lower()
    return not any(phrase in content for phrase in PARKED_PHRASES + BLOCKED_PHRASES)


def route_assessment(stages: dict[str, dict]) -> tuple[str, str, str]:
    for route in ("direct_noverify", "direct"):
        check = stages.get(route)
        if fetchable_html(check):
            return "direct_cffi", check["final_url"], route
    for route in ("india_proxy", "proxy_curl"):
        check = stages.get(route)
        if fetchable_html(check):
            return "proxy_cffi", check["final_url"], route
    check = stages.get("initial")
    if fetchable_html(check):
        return "proxy_baseline", check["final_url"], "urllib_initial"
    return "unavailable", "", ""


def build_outputs(directory: Path = OUTPUT):
    checks = read_checks(directory / "checks.csv")
    by_domain: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in checks:
        by_domain[row["domain"]][row["route"]] = row
    companies = read_csv(SOURCE)
    counts = Counter(canonical_host(source_host_warning(row["website_url"])[0]) for row in companies)
    output_companies = []
    domain_decisions = defaultdict(list)
    for row in companies:
        domain = canonical_host(source_host_warning(row["website_url"])[0])
        if domain not in by_domain:
            continue
        selected = select_check(by_domain[domain])
        mode, scrape_url, evidence = route_assessment(by_domain[domain])
        result = {"http_status": selected["http_status"], "final_url": selected["final_url"],
                  "final_domain": selected["final_domain"], "content_type": selected["content_type"],
                  "title": selected["title"], "error": selected["error"],
                  "body_signal": selected["body_signal"]}
        decision, reasons = classify(row, result, counts[domain])
        if (decision != "exclude" and selected["outcome"] == "recovered_2xx_html"
                and selected["tls_verified"] != "true"):
            decision = "review"
            reasons = ";".join(filter(None, (reasons if reasons != "homepage_2xx_html" else "", "tls_unverified")))
        if (decision != "exclude" and selected["route"] == "direct"
                and selected["outcome"] == "recovered_2xx_html"):
            decision = "review" if decision == "ready" else decision
            reasons = ";".join(filter(None, (reasons if reasons != "homepage_2xx_html" else "", "proxy_403_direct_2xx")))
        output_row = {"rank": row["rank"], "company": row["company"],
                      "company_url": row["company_url"], "website_url": row["website_url"],
                      "domain": domain, "companies_on_domain": counts[domain],
                      "scrape_mode": mode, "scrape_url": scrape_url, "route_evidence": evidence,
                      "decision": decision, "reasons": reasons, "homepage_status": selected["http_status"],
                      "final_url": selected["final_url"], "final_domain": selected["final_domain"],
                      "title": selected["title"], "probe_error": selected["error"],
                      "selected_route": selected["route"], "reachability": reachability(selected),
                      "tls_verified": selected["tls_verified"]}
        output_companies.append(output_row)
        domain_decisions[domain].append(output_row)
    write_csv(directory / "companies.csv", output_companies, COMPANY_FIELDS)

    source_urls = {canonical_host(source_host_warning(row["website_url"])[0]): row["website_url"]
                   for row in companies}
    output_domains = []
    for domain, stages in sorted(by_domain.items()):
        selected = select_check(stages)
        mode, scrape_url, evidence = route_assessment(stages)
        decisions = domain_decisions[domain]
        reasons = list(dict.fromkeys(reason for row in decisions for reason in row["reasons"].split(";") if reason))
        decision = "review" if any(row["decision"] == "review" for row in decisions) else (
            "exclude" if any(row["decision"] == "exclude" for row in decisions) else "ready")
        output_domains.append({"domain": domain, "source_url": source_urls.get(domain, ""),
                               "source_warning": source_host_warning(source_urls.get(domain, ""))[1],
                               "companies_on_domain": counts[domain],
                               "scrape_mode": mode, "scrape_url": scrape_url, "route_evidence": evidence,
                               **{f"{route}_status": stages.get(route, {}).get("http_status", "") for route in ROUTES},
                               "selected_status": selected["http_status"], "selected_route": selected["route"],
                               "selected_url": selected["final_url"], "selected_domain": selected["final_domain"],
                               "selected_content_type": selected["content_type"], "selected_title": selected["title"],
                               "reachability": reachability(selected), "tls_verified": selected["tls_verified"],
                               "decision": decision, "reasons": ";".join(reasons), "checks_count": len(stages)})
    write_csv(directory / "domains.csv", output_domains, DOMAIN_FIELDS)

    # Static shortlist for a no-proxy scraper. A proxy response supplies a
    # candidate URL; only a direct response proves that route works.
    direct_sites = [
        {"domain": row["domain"], "url": row["scrape_url"],
         "direct_status": "confirmed" if row["scrape_mode"] == "direct_cffi" else "candidate",
         "evidence": row["route_evidence"]}
        for row in output_domains if row["scrape_mode"] != "unavailable"
    ]
    write_csv(directory / "direct_scrape_sites.csv", direct_sites, DIRECT_SITE_FIELDS)

    route_counts = {route: dict(Counter(row["outcome"] for row in checks if row["route"] == route))
                    for route in ROUTES if any(row["route"] == route for row in checks)}
    summary = {"source_companies": len(companies), "unique_domains": len(counts),
               "classified_companies": len(output_companies),
               "company_decisions": dict(Counter(row["decision"] for row in output_companies)),
               "domain_decisions": dict(Counter(row["decision"] for row in output_domains)),
               "domain_reachability": dict(Counter(row["reachability"] for row in output_domains)),
               "domain_scrape_modes": dict(Counter(row["scrape_mode"] for row in output_domains)),
               "direct_site_status": dict(Counter(row["direct_status"] for row in direct_sites)),
               "company_scrape_modes": dict(Counter(row["scrape_mode"] for row in output_companies)),
               "checks_by_route": route_counts,
               "duplicate_domain_groups": sum(count > 1 for count in counts.values()),
               "companies_on_duplicate_domains": sum(count for count in counts.values() if count > 1),
               "non_generic_duplicate_domain_groups": sum(count > 1 and not generic_base(domain)
                                                          for domain, count in counts.items()),
               "generated_at_utc": datetime.now(timezone.utc).isoformat()}
    temp = directory / "summary.json.part"
    temp.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    temp.replace(directory / "summary.json")
    return summary


FIELDS = ["domain", "original_url", "original_status", "checked_at_utc", "proxy_used",
          "client", "impersonate", "curl_status", "curl_final_url", "content_type",
          "body_bytes", "title", "outcome", "error"]


def redact(message: str, proxy: str | None) -> str:
    parsed = urlparse(proxy or "")
    for secret in (proxy or "", parsed.username or "", parsed.password or ""):
        if secret:
            message = message.replace(secret, "[redacted]")
    return message[:300]


def check(row: dict, proxy: str | None, limiter: RateLimiter, timeout: float,
          verify: bool = True) -> dict:
    url = row["final_url"] or row["probe_url"]
    result = {key: "" for key in FIELDS}
    result.update(domain=row["domain"], original_url=url, original_status="403",
                  checked_at_utc=datetime.now(timezone.utc).isoformat(),
                  proxy_used="true" if proxy else "false",
                  client="curl_cffi", impersonate="chrome")
    with requests.Session(trust_env=False) as session:
        for _ in range(MAX_REDIRECTS + 1):
            _, problem = validate_url(url)
            if problem:
                result.update(outcome="invalid_url", error=problem)
                return result
            limiter.wait()
            try:
                response = session.get(url, proxy=proxy, impersonate="chrome", timeout=timeout,
                                       verify=verify, allow_redirects=False, stream=True)
                try:
                    status = response.status_code
                    result["curl_status"] = str(status)
                    result["curl_final_url"] = response.url
                    if status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if not location:
                            result["outcome"] = "redirect_without_location"
                            return result
                        url = urljoin(response.url, location)
                        continue
                    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
                    result["content_type"] = content_type
                    body = next(response.iter_content(chunk_size=MAX_BODY), b"")[:MAX_BODY]
                    result["body_bytes"] = str(len(body))
                    title = re.search(rb"<title\b[^>]*>(.*?)</title\s*>", body, re.I | re.S)
                    if title:
                        result["title"] = unescape(re.sub(r"\s+", " ", title.group(1).decode("utf-8", "replace")).strip())[:250]
                    if status == 403:
                        result["outcome"] = "still_403"
                    elif 200 <= status < 300 and content_type in ("text/html", "application/xhtml+xml"):
                        result["outcome"] = "recovered_2xx_html"
                    elif 200 <= status < 300:
                        result["outcome"] = "2xx_non_html"
                    else:
                        result["outcome"] = "other_http_status"
                    return result
                finally:
                    response.close()
            except Exception as exc:
                result.update(outcome="request_error", error=redact(f"{type(exc).__name__}: {exc}", proxy))
                return result
    result["outcome"] = "too_many_redirects"
    return result


def run_recheck():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--interval", type=float, default=0.2)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--retry-still-403", action="store_true",
                        help="Retry only the first pass's remaining HTTP 403 domains with the current proxy")
    mode.add_argument("--direct-retry", action="store_true",
                      help="Retry the second pass's remaining HTTP 403 domains without any proxy")
    mode.add_argument("--direct-noverify-retry", action="store_true",
                      help="Retry direct certificate errors without TLS certificate verification")
    parser.add_argument("--force", action="store_true", help="Rerun this stage with the current connection settings")
    args = parser.parse_args()
    direct = args.direct_retry or args.direct_noverify_retry
    if direct:
        # libcurl can honor proxy environment variables even when no proxy argument is passed.
        for key in list(os.environ):
            if key.lower().endswith("_proxy"):
                os.environ.pop(key, None)
    proxy = None if direct else proxy_url()
    if not proxy and not direct:
        raise SystemExit("BRIGHTDATA_PROXY is required; this check never falls back to direct traffic")
    if args.direct_noverify_retry:
        route, prior_route = "direct_noverify", "direct"
    elif args.direct_retry:
        route, prior_route = "direct", "india_proxy"
    elif args.retry_still_403:
        route, prior_route = "india_proxy", "proxy_curl"
    else:
        route, prior_route = "proxy_curl", "initial"
    checks = read_checks()
    prior = {row["domain"]: row for row in checks if row["route"] == prior_route}
    existing = {row["domain"]: row for row in checks if row["route"] == route}
    if args.direct_noverify_retry:
        source_rows = [row for row in prior.values() if row["outcome"] == "request_error"
                       and row["error"].startswith("CertificateVerifyError:")]
    else:
        source_rows = [row for row in prior.values() if row["http_status"] == "403"]
    targets = [{"domain": row["domain"], "final_url": row["final_url"] or row["request_url"],
                "probe_url": row["request_url"]} for row in source_rows]
    limiter = RateLimiter(args.interval)
    pending = [row for row in targets if args.force or row["domain"] not in existing]
    batch = []
    recovered = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check, row, proxy, limiter, args.timeout,
                               not args.direct_noverify_retry): row["domain"] for row in pending}
        for completed, future in enumerate(as_completed(futures), 1):
            result = future.result()
            batch.append(curl_check(result, route))
            recovered += result["outcome"] == "recovered_2xx_html"
            if completed % 10 == 0 or completed == len(pending):
                upsert_checks(batch)
                batch.clear()
                print(f"Checked {completed}/{len(pending)}; recovered {recovered}", flush=True)
    summary = build_outputs(DIRECTORY)
    print(json.dumps({"route": route, "new_checks": len(pending),
                      "route_outcomes": summary["checks_by_route"].get(route, {}),
                      "company_decisions": summary["company_decisions"]}, indent=2))


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("scan", "recheck", "rebuild"):
        command = sys.argv.pop(1)
    else:
        command = "scan"
    if command == "scan":
        run_scan()
    elif command == "recheck":
        run_recheck()
    else:
        print(json.dumps(build_outputs(), indent=2))


if __name__ == "__main__":
    main()
