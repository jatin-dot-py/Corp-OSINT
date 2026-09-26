#!/usr/bin/env python3
"""Resumable, direct curl_cffi crawler for public company document links.

Commands: init, run, status, export. Phase 4 does not save HTML or
document bytes. Its SQLite database is the authoritative crawl ledger.
"""

from __future__ import annotations

import argparse
import codecs
import csv
import fcntl
import ipaddress
import json
import os
import random
import re
import signal
import sqlite3
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from itertools import chain
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

import tldextract
from curl_cffi import requests


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "data/phase_two/domain_analysis/direct_scrape_sites.csv"
PHASE3 = ROOT / "data/phase_three/homepages.csv"
OUTPUT = ROOT / "data/phase_four"
DB = OUTPUT / "crawl.sqlite"
PSL = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True,
    extra_suffixes=("bank.in", "fin.in", "nbfc.in", "insurance.in", "wordpress.com"),
)
THREAD = threading.local()
DOC_EXTENSIONS = frozenset("pdf doc docx docm dot dotx dotm docs rtf odt xls xlsx xlsm xlsb xlt xltx xltm xla xlam xlw csv ods".split())
NON_HTML_EXTENSIONS = frozenset("jpg jpeg png gif webp avif svg ico bmp tif tiff mp3 mp4 m4a mov avi webm wav ogg flac woff woff2 ttf otf eot css js mjs json xml zip rar 7z gz tar exe dmg apk".split())
PARKING_ROOTS = frozenset(("hugedomains.com", "daaz.com", "sedo.com", "afternic.com"))
TRACKING_KEYS = frozenset("fbclid gclid dclid msclkid mc_cid mc_eid igshid yclid _ga _gl".split())
MAX_BODY = 8 * 1024 * 1024
MAX_SITEMAPS_PER_SITE = 100
MAX_SITEMAP_URLS = 50000
MAX_ATTEMPTS = 3
LEASE_SECONDS = 180
OUTAGE_PROBE_INTERVAL = 60


@dataclass
class Link:
    raw_href: str
    anchor_text: str
    source_kind: str


@dataclass
class FetchResult:
    request_url: str
    final_url: str = ""
    status: int = 0
    content_type: str = ""
    body: bytes = b""
    error: str = ""
    retry_after: float = 0.0
    transport_error: bool = False
    out_of_scope_redirect: str = ""
    links: list[Link] = field(default_factory=list)
    base_url: str = ""
    html_parsed: bool = False
    non_html_response: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def root_domain(host: str) -> str:
    result = PSL(host.lower().rstrip("."))
    return result.top_domain_under_public_suffix or ""


def public_url(raw: str, base: str = "") -> str:
    raw = unescape(raw).strip()
    if not raw or raw.startswith("#"):
        return ""
    try:
        parts = urlsplit(urljoin(base, raw))
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            return ""
        host = parts.hostname.lower().rstrip(".")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return ""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and not ip.is_global:
            return ""
        host = host.encode("idna").decode("ascii")
        port = parts.port
        netloc = f"[{host}]" if ":" in host else host
        if port and port != (443 if parts.scheme.lower() == "https" else 80):
            netloc += f":{port}"
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="=&?/%:@!$'()*+,;+-._~")
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    except (ValueError, UnicodeError):
        return ""


def page_key(url: str) -> str:
    parts = urlsplit(url)
    items = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
             if not key.lower().startswith("utm_") and key.lower() not in TRACKING_KEYS]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(items, doseq=True), ""))


def document_extension(url: str) -> str:
    path = unquote(urlsplit(url).path).lower()
    extension = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    return extension if extension in DOC_EXTENSIONS else ""


def document_key(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def non_html_extension(url: str) -> bool:
    name = unquote(urlsplit(url).path).rsplit("/", 1)[-1].lower()
    return name.rsplit(".", 1)[-1] in NON_HTML_EXTENSIONS if "." in name else False


def in_scope(url: str, site_root: str) -> bool:
    host = urlsplit(url).hostname or ""
    return root_domain(host) == site_root


def link_priority(url: str, text: str, parent_priority: int = 2) -> int:
    if "investor" in (url + " " + text).lower():
        return 0
    return 1 if parent_priority <= 1 else 2


class NavigationParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.base_href = ""
        self.anchor: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and values.get("href") and not self.base_href:
            self.base_href = values["href"] or ""
        elif tag in ("a", "area") and values.get("href"):
            if tag == "area":
                label = values.get("aria-label") or values.get("alt") or values.get("title") or ""
                self.links.append(Link(values["href"] or "", label, "area"))
            else:
                self.anchor = {"href": values["href"] or "", "parts": [],
                               "aria": values.get("aria-label") or "", "title": values.get("title") or "",
                               "img_alt": ""}
        elif tag == "img" and self.anchor is not None and values.get("alt"):
            self.anchor["img_alt"] += " " + (values["alt"] or "")
        elif tag == "frame" and values.get("src"):
            self.links.append(Link(values["src"] or "", "", "frame"))
        elif tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            match = re.search(r"(?:^|;)\s*url\s*=\s*['\"]?([^'\";]+)", values.get("content") or "", re.I)
            if match:
                self.links.append(Link(match.group(1), "", "meta_refresh"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self.anchor is not None:
            a = self.anchor
            visible = re.sub(r"\s+", " ", " ".join(a["parts"])).strip()
            label = visible or a["aria"] or a["title"] or a["img_alt"].strip()
            self.links.append(Link(a["href"], label[:500], "anchor"))
            self.anchor = None

    def handle_data(self, data: str) -> None:
        if self.anchor is not None:
            self.anchor["parts"].append(data)


def parse_html(body: bytes, response_url: str, content_type: str = "") -> tuple[list[Link], str]:
    encoding_match = re.search(r"charset\s*=\s*['\"]?([^;\s'\"]+)", content_type, re.I)
    encoding = encoding_match.group(1) if encoding_match else "utf-8"
    try:
        html = body.decode(encoding, "replace")
    except LookupError:
        html = body.decode("utf-8", "replace")
    parser = NavigationParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    if parser.anchor is not None:
        parser.handle_endtag("a")
    base = public_url(parser.base_href, response_url) if parser.base_href else response_url
    return parser.links, base or response_url


def open_db(path: Path | None = None) -> sqlite3.Connection:
    if path is None:
        path = DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=60000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA wal_autocheckpoint=1000")
    conn.execute("PRAGMA journal_size_limit=67108864")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  root TEXT PRIMARY KEY,
  page_cap INTEGER NOT NULL DEFAULT 5000, pages_attempted INTEGER NOT NULL DEFAULT 0,
  next_allowed_at REAL NOT NULL DEFAULT 0, seed_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS seeds (
  source_domain TEXT PRIMARY KEY, site_root TEXT NOT NULL, seed_url TEXT NOT NULL,
  FOREIGN KEY(site_root) REFERENCES sites(root)
);
CREATE TABLE IF NOT EXISTS frontier (
  id INTEGER PRIMARY KEY, site_root TEXT NOT NULL, url_key TEXT NOT NULL,
  fetch_url TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 2, depth INTEGER NOT NULL DEFAULT 0,
  parent_url TEXT NOT NULL DEFAULT '', source_kind TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0, first_attempted INTEGER NOT NULL DEFAULT 0,
  due_at REAL NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
  http_status INTEGER NOT NULL DEFAULT 0, final_url TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL DEFAULT '',
  UNIQUE(site_root, url_key), FOREIGN KEY(site_root) REFERENCES sites(root)
);
CREATE INDEX IF NOT EXISTS frontier_ready ON frontier(site_root,state,due_at,priority,depth,id);
CREATE TABLE IF NOT EXISTS page_edges (
  site_root TEXT NOT NULL, parent_url TEXT NOT NULL, child_url TEXT NOT NULL,
  raw_href TEXT NOT NULL, anchor_text TEXT NOT NULL, source_kind TEXT NOT NULL,
  UNIQUE(site_root,parent_url,child_url,raw_href,anchor_text,source_kind)
);
CREATE TABLE IF NOT EXISTS documents (
  site_root TEXT NOT NULL, doc_key TEXT NOT NULL, extension TEXT NOT NULL,
  first_url TEXT NOT NULL, first_seen TEXT NOT NULL,
  PRIMARY KEY(site_root,doc_key)
);
CREATE TABLE IF NOT EXISTS document_occurrences (
  site_root TEXT NOT NULL, doc_key TEXT NOT NULL, parent_url TEXT NOT NULL,
  raw_href TEXT NOT NULL, observed_url TEXT NOT NULL, anchor_text TEXT NOT NULL,
  source_kind TEXT NOT NULL, discovered_at TEXT NOT NULL,
  UNIQUE(site_root,doc_key,parent_url,raw_href,observed_url,anchor_text,source_kind),
  FOREIGN KEY(site_root,doc_key) REFERENCES documents(site_root,doc_key)
);
CREATE TABLE IF NOT EXISTS redirects_outside_scope (
  site_root TEXT NOT NULL, source_url TEXT NOT NULL, target_url TEXT NOT NULL,
  seen_at TEXT NOT NULL, UNIQUE(site_root,source_url,target_url)
);
CREATE TABLE IF NOT EXISTS fetch_attempts (
  id INTEGER PRIMARY KEY, frontier_id INTEGER NOT NULL, attempted_at TEXT NOT NULL,
  status INTEGER NOT NULL, final_url TEXT NOT NULL, error TEXT NOT NULL,
  FOREIGN KEY(frontier_id) REFERENCES frontier(id)
);
"""


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def add_frontier(conn: sqlite3.Connection, site: str, url: str, kind: str, priority: int,
                 depth: int, parent_url: str, source_kind: str) -> None:
    key = page_key(url) if kind == "html" else url
    conn.execute("""INSERT INTO frontier(site_root,url_key,fetch_url,kind,priority,depth,parent_url,source_kind)
                    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(site_root,url_key) DO UPDATE SET
                    priority=min(priority,excluded.priority),depth=min(depth,excluded.depth)""",
                 (site, key, url, kind, priority, depth, parent_url, source_kind))


def record_link(conn: sqlite3.Connection, site: str, parent: str, base: str,
                link: Link, depth: int, parent_priority: int) -> None:
    url = public_url(link.raw_href, base)
    if not url:
        return
    ext = document_extension(url)
    if ext:
        key = document_key(url)
        conn.execute("INSERT OR IGNORE INTO documents VALUES(?,?,?,?,?)", (site, key, ext, url, utc_now()))
        conn.execute("""INSERT OR IGNORE INTO document_occurrences
                    VALUES(?,?,?,?,?,?,?,?)""",
                     (site, key, parent, link.raw_href, url, link.anchor_text, link.source_kind, utc_now()))
        return
    if non_html_extension(url):
        return
    if not in_scope(url, site):
        if link.source_kind in ("frame", "meta_refresh"):
            conn.execute("INSERT OR IGNORE INTO redirects_outside_scope VALUES(?,?,?,?)",
                         (site, parent, url, utc_now()))
        return
    conn.execute("INSERT OR IGNORE INTO page_edges VALUES(?,?,?,?,?,?)",
                 (site, parent, url, link.raw_href, link.anchor_text, link.source_kind))
    add_frontier(conn, site, url, "html", link_priority(url, link.anchor_text, parent_priority),
                 depth + 1, parent, link.source_kind)


def valid_archived_html(row: dict, site: str) -> bool:
    if row.get("status") != "saved" or not in_scope(row.get("saved_url", ""), site):
        return False
    title = row.get("title", "").lower()
    if re.search(r"\b404\b|page not found|domain expired|domain for sale|suspended domain", title):
        return False
    if row.get("crawl_review_reason") in ("challenge_or_interstitial", "parked_or_placeholder"):
        return False
    path = ROOT / row.get("html_file", "")
    if not path.is_file():
        return False
    head = path.open("rb").read(2048).lower()
    return b"fatal error" not in head and b"uncaught error" not in head


def command_init(args: argparse.Namespace) -> None:
    seeds = read_csv(SOURCE)
    phase3 = {row["domain"]: row for row in read_csv(PHASE3)}
    if not seeds:
        raise SystemExit(f"Missing Phase 2 seed file: {SOURCE}")
    conn = open_db()
    create_schema(conn)
    imported_html = 0
    for index, row in enumerate(seeds, 1):
        url = public_url(row["url"])
        if not url:
            continue
        site = root_domain(urlsplit(url).hostname or "")
        if not site or site in PARKING_ROOTS:
            continue
        origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
        with conn:
            conn.execute("INSERT OR IGNORE INTO sites(root,page_cap) VALUES(?,?)", (site, args.page_cap))
            conn.execute("INSERT OR IGNORE INTO seeds VALUES(?,?,?)", (row["domain"], site, url))
            add_frontier(conn, site, url, "html", 2, 0, "", "seed")
            add_frontier(conn, site, origin + "/robots.txt", "robots", 2, 0, "", "robots_seed")
            add_frontier(conn, site, origin + "/sitemap.xml", "sitemap", 2, 0, "", "sitemap_seed")
            archived = phase3.get(row["domain"])
            if archived and valid_archived_html(archived, site):
                parent = archived["saved_url"]
                body = (ROOT / archived["html_file"]).read_bytes()
                links, base = parse_html(body, parent, archived.get("content_type", ""))
                for link in links:
                    record_link(conn, site, parent, base, link, 0, 2)
                imported_html += 1
        if index % 500 == 0:
            print(f"Initialized {index}/{len(seeds)} seed rows", flush=True)
    with conn:
        conn.execute("UPDATE sites SET seed_count=(SELECT count(*) FROM seeds WHERE site_root=sites.root)")
        conn.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('initialization_complete','1')")
    site_count = conn.execute("SELECT count(*) FROM sites").fetchone()[0]
    print(json.dumps({"seed_rows": len(seeds), "site_groups": site_count,
                      "archived_homepages_parsed": imported_html,
                      "frontier_rows": conn.execute("SELECT count(*) FROM frontier").fetchone()[0],
                      "document_occurrences": conn.execute("SELECT count(*) FROM document_occurrences").fetchone()[0]}, indent=2))
    conn.close()


def initialization_complete(conn: sqlite3.Connection) -> bool:
    ready = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone()
    if not ready:
        return False
    marker = conn.execute("SELECT value FROM metadata WHERE key='initialization_complete'").fetchone()
    return bool(marker and marker[0] == "1")


def ensure_initialized(page_cap: int) -> None:
    if DB.exists():
        conn = open_db()
        try:
            if initialization_complete(conn):
                return
        finally:
            conn.close()
    print("Initializing Phase 4 from Phase 2 seeds and Phase 3 homepages", flush=True)
    command_init(argparse.Namespace(page_cap=page_cap))


def thread_session() -> requests.Session:
    if not hasattr(THREAD, "session"):
        THREAD.session = requests.Session(trust_env=False)
    return THREAD.session


def retry_after_seconds(value: str) -> float:
    if not value:
        return 0.0
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime
            return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return 0.0


def fetch(task: dict, site: str, timeout: float, delay: float) -> FetchResult:
    requested = task["fetch_url"]
    current = requested
    result = FetchResult(request_url=requested)
    for hop in range(6):
        response = None
        try:
            response = thread_session().get(
                current, impersonate="chrome", verify=False, proxy=None,
                timeout=timeout, allow_redirects=False, stream=True,
                headers={"Accept": "text/html,application/xhtml+xml,application/xml,text/xml,*/*;q=0.8"},
            )
            result.status = response.status_code
            result.final_url = public_url(response.url) or current
            result.content_type = response.headers.get("content-type", "")
            result.retry_after = retry_after_seconds(response.headers.get("retry-after", ""))
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                target = public_url(location, current)
                if not target:
                    result.error = "redirect_without_public_location"
                    return result
                if not in_scope(target, site):
                    result.out_of_scope_redirect = target
                    result.final_url = target
                    return result
                current = target
                if hop == 5:
                    result.error = "too_many_redirects"
                    return result
                time.sleep(delay)
                continue
            if task["kind"] == "html" and document_extension(result.final_url) and 200 <= result.status < 300:
                # A page URL redirected to a document. Its URL is evidence;
                # the document body is never downloaded into Phase 4.
                return result
            if not 200 <= result.status < 300:
                return result
            body_chunks = response.iter_content(chunk_size=65536)
            if task["kind"] == "html":
                if non_html_extension(result.final_url):
                    result.non_html_response = True
                    return result
                first = next((chunk for chunk in body_chunks if chunk), b"")
                if not first:
                    result.error = "empty_body"
                    return result
                mime = result.content_type.split(";", 1)[0].strip().lower()
                head = first[:4096].lower()
                if mime not in ("text/html", "application/xhtml+xml") and b"<html" not in head and b"<!doctype html" not in head:
                    result.non_html_response = True
                    return result
                encoding_match = re.search(r"charset\s*=\s*['\"]?([^;\s'\"]+)", result.content_type, re.I)
                encoding = encoding_match.group(1) if encoding_match else "utf-8"
                try:
                    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
                except LookupError:
                    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                parser = NavigationParser()
                length = 0
                for chunk in chain((first,), body_chunks):
                    length += len(chunk)
                    if length > MAX_BODY:
                        result.error = "body_exceeds_8_mib"
                        return result
                    parser.feed(decoder.decode(chunk))
                parser.feed(decoder.decode(b"", final=True))
                parser.close()
                if parser.anchor is not None:
                    parser.handle_endtag("a")
                result.links = parser.links
                result.base_url = public_url(parser.base_href, result.final_url) if parser.base_href else result.final_url
                result.html_parsed = True
                return result
            chunks: list[bytes] = []
            length = 0
            for chunk in body_chunks:
                length += len(chunk)
                if length > MAX_BODY:
                    result.error = "body_exceeds_8_mib"
                    return result
                chunks.append(chunk)
            result.body = b"".join(chunks)
            if not result.body:
                result.error = "empty_body"
            return result
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"[:300]
            result.transport_error = True
            return result
        finally:
            if response is not None:
                response.close()
    result.error = "too_many_redirects"
    return result


def sitemap_links(body: bytes, source_url: str) -> list[tuple[str, str]]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    is_index = root.tag.lower().endswith("sitemapindex")
    found = []
    for item in root:
        for child in item:
            if child.tag.lower().endswith("loc") and child.text:
                url = public_url(child.text.strip(), source_url)
                if url:
                    found.append((url, "sitemap" if is_index else "html"))
                break
        if len(found) >= MAX_SITEMAP_URLS:
            break
    return found


def process_discoveries(conn: sqlite3.Connection, task: dict, result: FetchResult) -> None:
    site = task["site_root"]
    if task["kind"] == "html":
        final = result.final_url or task["fetch_url"]
        if document_extension(final):
            parents = list(conn.execute("SELECT parent_url,raw_href,anchor_text,source_kind FROM page_edges WHERE site_root=? AND child_url=?",
                                        (site, task["fetch_url"])))
            if not parents:
                parents = [{"parent_url": task["parent_url"] or task["fetch_url"],
                            "raw_href": task["fetch_url"], "anchor_text": "", "source_kind": "redirect_document"}]
            for parent in parents:
                record_link(conn, site, parent["parent_url"], final,
                            Link(final, parent["anchor_text"], "redirect_document"),
                            task["depth"], task["priority"])
            return
        for link in result.links:
            record_link(conn, site, final, result.base_url or final, link, task["depth"], task["priority"])
        return
    if task["kind"] == "robots":
        text = result.body.decode("utf-8", "replace")
        for line in text.splitlines():
            match = re.match(r"\s*sitemap\s*:\s*(\S+)", line, re.I)
            if not match:
                continue
            url = public_url(match.group(1), result.final_url)
            if url and in_scope(url, site):
                count = conn.execute("SELECT count(*) FROM frontier WHERE site_root=? AND kind='sitemap'", (site,)).fetchone()[0]
                if count < MAX_SITEMAPS_PER_SITE:
                    add_frontier(conn, site, url, "sitemap", 2, 0, result.final_url, "robots_sitemap")
        return
    if task["kind"] == "sitemap":
        for url, kind in sitemap_links(result.body, result.final_url):
            if document_extension(url):
                record_link(conn, site, result.final_url, result.final_url,
                            Link(url, "", "sitemap"), 0, 2)
            elif in_scope(url, site):
                if kind == "sitemap":
                    count = conn.execute("SELECT count(*) FROM frontier WHERE site_root=? AND kind='sitemap'", (site,)).fetchone()[0]
                    if count < MAX_SITEMAPS_PER_SITE:
                        add_frontier(conn, site, url, "sitemap", 2, 0, result.final_url, "sitemap_index")
                else:
                    conn.execute("INSERT OR IGNORE INTO page_edges VALUES(?,?,?,?,?,?)",
                                 (site, result.final_url, url, url, "", "sitemap"))
                    add_frontier(conn, site, url, "html", link_priority(url, ""), 1, result.final_url, "sitemap")


def retry_delay(attempts: int, retry_after: float) -> float:
    return max(retry_after, (30, 120, 600)[min(attempts - 1, 2)] + random.uniform(0, 5))


def finish_task(conn: sqlite3.Connection, task: dict, result: FetchResult) -> str:
    now = time.time()
    status = result.status
    error = result.error
    is_success = 200 <= status < 300 and not error
    retryable = result.transport_error or status in (408, 429) or 500 <= status < 600 or error == "empty_body"
    non_html = task["kind"] == "html" and is_success and (
        bool(document_extension(result.final_url)) or result.non_html_response or
        (not result.html_parsed and not result.body and bool(result.content_type) and
         "html" not in result.content_type.lower())
    )
    with conn:
        conn.execute("INSERT INTO fetch_attempts(frontier_id,attempted_at,status,final_url,error) VALUES(?,?,?,?,?)",
                     (task["id"], utc_now(), status, result.final_url, error))
        if result.out_of_scope_redirect:
            conn.execute("INSERT OR IGNORE INTO redirects_outside_scope VALUES(?,?,?,?)",
                         (task["site_root"], task["fetch_url"], result.out_of_scope_redirect, utc_now()))
            if task["kind"] == "html" and document_extension(result.out_of_scope_redirect):
                process_discoveries(conn, task, result)
            state, due = "skipped_external_redirect", 0.0
        elif non_html:
            if document_extension(result.final_url):
                process_discoveries(conn, task, result)
                state = "done_document_redirect"
            else:
                state = "skipped_nonhtml"
            due = 0.0
            if not task["first_attempted"]:
                conn.execute("UPDATE sites SET pages_attempted=pages_attempted-1 WHERE root=?", (task["site_root"],))
                conn.execute("UPDATE frontier SET first_attempted=0 WHERE id=?", (task["id"],))
        elif is_success:
            process_discoveries(conn, task, result)
            state, due = "done", 0.0
        elif retryable and task["attempts"] < MAX_ATTEMPTS:
            state, due = "queued", now + retry_delay(task["attempts"], result.retry_after)
        elif retryable:
            state, due = "retry_later", 0.0
        else:
            state, due = "failed", 0.0
        conn.execute("""UPDATE frontier SET state=?,due_at=?,lease_until=0,http_status=?,final_url=?,
                       content_type=?,error=?,checked_at=? WHERE id=?""",
                     (state, due, status, result.final_url, result.content_type,
                      error or (f"http_{status}" if not is_success else ""), utc_now(), task["id"]))
    return state


def select_sites(conn: sqlite3.Connection, names: list[str]) -> list[str]:
    if names:
        selected = sorted(set(names))
        known = {row[0] for row in conn.execute("SELECT root FROM sites WHERE root IN (%s)" % ",".join("?" * len(selected)), selected)}
        missing = set(selected) - known
        if missing:
            raise SystemExit(f"Unknown site groups: {', '.join(sorted(missing))}")
        return selected
    return [row[0] for row in conn.execute("SELECT root FROM sites ORDER BY root")]


def claim_task(conn: sqlite3.Connection, site: str, delay: float) -> dict | None:
    now = time.time()
    site_row = conn.execute("SELECT pages_attempted,page_cap,next_allowed_at FROM sites WHERE root=?", (site,)).fetchone()
    if site_row is None or now < site_row["next_allowed_at"]:
        return None
    if site_row["pages_attempted"] >= site_row["page_cap"]:
        with conn:
            conn.execute("""UPDATE frontier SET state='skipped_cap' WHERE site_root=? AND state='queued'
                         AND kind='html' AND first_attempted=0""", (site,))
    row = conn.execute("""SELECT * FROM frontier WHERE site_root=? AND state='queued' AND due_at<=?
                          ORDER BY priority,depth,id LIMIT 1""", (site, now)).fetchone()
    if row is None:
        return None
    task = dict(row)
    first = not task["first_attempted"] and task["kind"] == "html"
    with conn:
        conn.execute("""UPDATE frontier SET state='leased',attempts=attempts+1,first_attempted=1,
                       lease_until=? WHERE id=?""", (now + LEASE_SECONDS, task["id"]))
        conn.execute("UPDATE sites SET next_allowed_at=?,pages_attempted=pages_attempted+? WHERE root=?",
                     (now + delay, int(first), site))
    task["attempts"] += 1
    return task


def run_locked(args: argparse.Namespace) -> None:
    if not DB.exists():
        raise SystemExit("Run init before run")
    conn = open_db()
    roots = select_sites(conn, args.site)
    if not roots:
        raise SystemExit("No sites selected")
    with conn:
        if args.site:
            marks = ",".join("?" * len(roots))
            conn.execute(f"UPDATE frontier SET state='queued',lease_until=0 WHERE state='leased' AND site_root IN ({marks})", roots)
            conn.execute(f"UPDATE frontier SET state='queued',attempts=0,due_at=0 WHERE state='retry_later' AND site_root IN ({marks})", roots)
            candidates = conn.execute(
                f"SELECT id,fetch_url FROM frontier WHERE site_root IN ({marks}) AND state='queued' AND kind='html'", roots)
        else:
            conn.execute("UPDATE frontier SET state='queued',lease_until=0 WHERE state='leased'")
            conn.execute("UPDATE frontier SET state='queued',attempts=0,due_at=0 WHERE state='retry_later'")
            candidates = conn.execute("SELECT id,fetch_url FROM frontier WHERE state='queued' AND kind='html'")
        static_ids = [row[0] for row in candidates if non_html_extension(row[1])]
        conn.executemany("UPDATE frontier SET state='skipped_nonhtml' WHERE id=?", ((id_,) for id_ in static_ids))
        if args.page_cap:
            if args.site:
                conn.execute(f"UPDATE sites SET page_cap=? WHERE root IN ({marks})", [args.page_cap, *roots])
            else:
                conn.execute("UPDATE sites SET page_cap=?", (args.page_cap,))
    stopping = threading.Event()
    previous_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    active: set[str] = set()
    futures = {}
    recent: deque[tuple[str, bool]] = deque(maxlen=30)
    outage_mode = False
    probe_after = 0.0
    completed = 0
    html_completed = 0
    cursor = 0
    crawl_summary = {}
    sites: list[str] = []
    next_root = 0
    started_sites: set[str] = set()

    def has_queue(site: str) -> bool:
        return conn.execute("SELECT 1 FROM frontier WHERE site_root=? AND state='queued' LIMIT 1", (site,)).fetchone() is not None

    def fill_window() -> None:
        nonlocal next_root
        while len(sites) < args.site_window and next_root < len(roots):
            site = roots[next_root]
            next_root += 1
            if site not in sites and has_queue(site):
                sites.append(site)
                started_sites.add(site)

    print(f"Running unfinished site groups automatically, window {args.site_window}, "
          f"global concurrency {args.workers}, delay {args.delay}s", flush=True)
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            while True:
                if not stopping.is_set():
                    sites[:] = [site for site in sites if site in active or has_queue(site)]
                    fill_window()
                if not sites and not futures:
                    if outage_mode and not stopping.is_set():
                        marks = ",".join("?" * len(roots))
                        probe_row = conn.execute(
                            f"SELECT id,site_root FROM frontier WHERE state='retry_later' AND site_root IN ({marks}) ORDER BY id LIMIT 1", roots
                        ).fetchone()
                        if probe_row:
                            with conn:
                                conn.execute("UPDATE frontier SET state='queued',attempts=0,due_at=0 WHERE id=?", (probe_row["id"],))
                            sites.append(probe_row["site_root"])
                    if not sites:
                        break
                if not stopping.is_set() and outage_mode and not futures and time.time() >= probe_after:
                    for site in sites:
                        task = claim_task(conn, site, args.delay)
                        if task is None:
                            continue
                        active.add(site)
                        future = pool.submit(fetch, task, site, args.timeout, args.delay)
                        futures[future] = task
                        break
                elif not stopping.is_set() and not outage_mode:
                    for _ in range(len(sites)):
                        if len(futures) >= args.workers:
                            break
                        site = sites[cursor % len(sites)]
                        cursor += 1
                        if site in active:
                            continue
                        task = claim_task(conn, site, args.delay)
                        if task is None:
                            continue
                        active.add(site)
                        future = pool.submit(fetch, task, site, args.timeout, args.delay)
                        futures[future] = task
                if not futures:
                    if stopping.is_set():
                        break
                    marks = ",".join("?" * len(sites))
                    due = conn.execute(f"SELECT min(due_at) FROM frontier WHERE site_root IN ({marks}) AND state='queued'", sites).fetchone()[0]
                    if outage_mode:
                        wake_at = max(probe_after, due or time.time())
                        time.sleep(min(2.0, max(0.1, wake_at - time.time())))
                        continue
                    time.sleep(min(2.0, max(0.1, (due or time.time()) - time.time())))
                    continue
                done, _ = wait(futures, timeout=2, return_when=FIRST_COMPLETED)
                for future in done:
                    task = futures.pop(future)
                    active.remove(task["site_root"])
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = FetchResult(task["fetch_url"], error=f"worker_error: {type(exc).__name__}: {exc}"[:300],
                                             transport_error=True)
                    state = finish_task(conn, task, result)
                    completed += 1
                    html_completed += task["kind"] == "html"
                    if outage_mode:
                        if result.transport_error:
                            probe_after = time.time() + OUTAGE_PROBE_INTERVAL
                            if not futures:
                                print(f"Connection still unavailable; probing again in {OUTAGE_PROBE_INTERVAL}s", flush=True)
                        else:
                            outage_mode = False
                            with conn:
                                conn.execute("UPDATE frontier SET state='queued',attempts=0,due_at=0 WHERE state='retry_later'")
                            next_root = 0
                            recent.clear()
                            print("Connection recovered; resuming normal crawl", flush=True)
                    else:
                        recent.append((task["site_root"], result.transport_error))
                    if not outage_mode and len(recent) == 30 and sum(error for _, error in recent) >= 25 and len({site for site, _ in recent}) >= 10:
                        outage_mode = True
                        probe_after = time.time() + OUTAGE_PROBE_INTERVAL
                        recent.clear()
                        print(f"Broad connection failures detected; pausing dispatch and probing every {OUTAGE_PROBE_INTERVAL}s", flush=True)
                    if completed % 50 == 0:
                        print(f"Completed {completed} requests ({html_completed} HTML); last state {state}", flush=True)
                    if args.max_pages_this_run and html_completed >= args.max_pages_this_run:
                        stopping.set()
                if stopping.is_set() and not futures:
                    break
            states = dict(conn.execute("SELECT state,count(*) FROM frontier GROUP BY state"))
            remaining = sum(states.get(state, 0) for state in ("queued", "leased", "retry_later"))
            crawl_summary = {"crawl_complete": remaining == 0,
                             "remaining_pages": remaining,
                             "retry_later_pages": states.get("retry_later", 0),
                             "permanent_failures": states.get("failed", 0),
                             "pages_skipped_at_cap": states.get("skipped_cap", 0)}
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        conn.close()
    print(json.dumps({"site_groups_started": len(started_sites), "requests_completed_this_run": completed,
                      "html_pages_completed_this_run": html_completed,
                      "stopped": stopping.is_set(), **crawl_summary}, indent=2))


def command_run(args: argparse.Namespace) -> None:
    if args.workers < 1 or args.workers > 500 or args.delay < 0 or args.timeout <= 0:
        raise SystemExit("workers must be 1..500, delay nonnegative, and timeout positive")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with (OUTPUT / ".run.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another Phase 4 run is already active")
        ensure_initialized(args.page_cap or 5000)
        run_locked(args)


def command_status(args: argparse.Namespace) -> None:
    if not DB.exists():
        raise SystemExit("Run init before status")
    conn = open_db()
    sites = select_sites(conn, args.site)
    if not sites:
        raise SystemExit("No sites selected")
    marks = ",".join("?" * len(sites))
    states = dict(conn.execute(f"SELECT state,count(*) FROM frontier WHERE site_root IN ({marks}) GROUP BY state", sites))
    budgets = conn.execute(f"SELECT count(*),sum(pages_attempted),sum(page_cap) FROM sites WHERE root IN ({marks})", sites).fetchone()
    documents = conn.execute(f"SELECT count(*) FROM documents WHERE site_root IN ({marks})", sites).fetchone()[0]
    occurrences = conn.execute(f"SELECT count(*) FROM document_occurrences WHERE site_root IN ({marks})", sites).fetchone()[0]
    pending_sites = conn.execute(f"""SELECT count(DISTINCT site_root) FROM frontier WHERE site_root IN ({marks})
                                   AND state IN ('queued','leased','retry_later')""", sites).fetchone()[0]
    external_redirects = conn.execute(f"SELECT count(*) FROM redirects_outside_scope WHERE site_root IN ({marks})", sites).fetchone()[0]
    errors = [dict(r) for r in conn.execute(f"""SELECT error,count(*) AS count FROM frontier WHERE site_root IN ({marks})
              AND error<>'' GROUP BY error ORDER BY count DESC LIMIT 8""", sites)]
    remaining = sum(states.get(state, 0) for state in ("queued", "leased", "retry_later"))
    initialized = initialization_complete(conn)
    print(json.dumps({"crawl_complete": initialized and remaining == 0,
                      "initialization_complete": initialized, "remaining_pages": remaining,
                      "site_groups": budgets[0], "site_groups_with_pending_pages": pending_sites,
                      "pages_attempted": budgets[1], "page_budget_total": budgets[2],
                      "frontier_states": states, "unique_documents": documents,
                      "document_occurrences": occurrences, "external_redirects": external_redirects,
                      "top_errors": errors}, indent=2))
    conn.close()


def atomic_csv(path: Path, headers: list[str], rows) -> int:
    part = path.with_suffix(path.suffix + ".part")
    count = 0
    with part.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(tuple(row))
            count += 1
    part.replace(path)
    return count


def command_export(args: argparse.Namespace) -> None:
    if not DB.exists():
        raise SystemExit("Run init before export")
    conn = open_db()
    document_rows = conn.execute("""SELECT o.site_root,o.doc_key,d.extension,o.observed_url,o.parent_url,
        o.raw_href,o.anchor_text,o.source_kind,o.discovered_at FROM document_occurrences o
        JOIN documents d ON d.site_root=o.site_root AND d.doc_key=o.doc_key
        ORDER BY o.site_root,o.doc_key,o.parent_url,o.anchor_text""")
    doc_count = atomic_csv(OUTPUT / "documents.csv",
                           ["site_root", "normalized_document_url", "extension", "observed_url", "parent_page",
                            "raw_href", "anchor_text", "source_kind", "discovered_at"], document_rows)
    page_rows = conn.execute("""SELECT site_root,fetch_url,url_key,kind,state,priority,depth,parent_url,source_kind,
        attempts,http_status,final_url,content_type,error,checked_at FROM frontier
        ORDER BY site_root,kind,depth,id""")
    page_count = atomic_csv(OUTPUT / "crawl_pages.csv",
                            ["site_root", "fetch_url", "normalized_url", "kind", "state", "priority", "depth",
                             "first_parent", "source_kind", "attempts", "http_status", "final_url", "content_type",
                             "error", "checked_at"], page_rows)
    print(json.dumps({"document_occurrences": doc_count, "crawl_rows": page_count}, indent=2))
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Import Phase 2 seeds and parse archived Phase 3 homepages")
    init.add_argument("--page-cap", type=int, default=5000)
    run = commands.add_parser("run", help="Run or resume unfinished sites automatically")
    run.add_argument("page_cap_value", nargs="?", type=int, help="HTML page budget per registered domain group")
    run.add_argument("--site", action="append", default=[], metavar="ROOT")
    run.add_argument("--site-window", type=int, default=200)
    run.add_argument("--workers", type=int, default=64)
    run.add_argument("--delay", type=float, default=1.0)
    run.add_argument("--timeout", type=float, default=20.0)
    run.add_argument("--page-cap", type=int, default=0)
    run.add_argument("--max-pages-this-run", type=int, default=0)
    status = commands.add_parser("status", help="Report database progress")
    status.add_argument("--site", action="append", default=[], metavar="ROOT")
    commands.add_parser("export", help="Write fixed document and crawl CSV views")
    argv = sys.argv[1:]
    if not argv:
        argv = ["run"]
    elif argv[0].isdigit():
        argv = ["run", "--page-cap", argv[0], *argv[1:]]
    elif argv[0].startswith("-") and argv[0] != "--help":
        argv = ["run", *argv]
    args = parser.parse_args(argv)
    if args.command == "init":
        if not 1 <= args.page_cap <= 10000:
            raise SystemExit("page-cap must be 1..10000")
        command_init(args)
    elif args.command == "run":
        if args.page_cap_value is not None:
            args.page_cap = args.page_cap_value
        if args.page_cap and not 1 <= args.page_cap <= 10000:
            raise SystemExit("page-cap must be 1..10000")
        if not 1 <= args.site_window <= 500:
            raise SystemExit("site-window must be 1..500")
        command_run(args)
    elif args.command == "status":
        command_status(args)
    else:
        command_export(args)


if __name__ == "__main__":
    main()
