import sqlite3
import tempfile
import unittest
from io import StringIO
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from threading import Lock
from unittest.mock import patch

import phase_four_crawl_documents as crawl


class PhaseFourTests(unittest.TestCase):
    def test_url_and_anchor_rules(self):
        self.assertEqual(crawl.root_domain("account.example.co.in"), "example.co.in")
        self.assertEqual(crawl.root_domain("one.github.io"), "one.github.io")
        self.assertEqual(crawl.root_domain("www.axis.bank.in"), "axis.bank.in")
        self.assertEqual(crawl.root_domain("one.wordpress.com"), "one.wordpress.com")
        url = crawl.public_url("../Annual Report.PDF?download=1&amp;x=2#page", "https://example.com/investors/")
        self.assertEqual(url, "https://example.com/Annual%20Report.PDF?download=1&x=2")
        self.assertEqual(crawl.document_extension(url), "pdf")
        self.assertEqual(crawl.document_key(url), "https://example.com/Annual%20Report.PDF")
        self.assertEqual(crawl.public_url("http://127.0.0.1/private"), "")
        self.assertEqual(crawl.page_key("https://example.com/page?year=2025&utm_source=x#top"),
                         "https://example.com/page?year=2025")
        links, base = crawl.parse_html(
            b'<base href="https://account.example.com/ir/">'
            b'<a href="/reports/2025.xlsx"><img alt="Annual report"></a>'
            b'<a href="/investor-relations">Investors</a>', "https://example.com/"
        )
        self.assertEqual(base, "https://account.example.com/ir/")
        self.assertEqual(links[0].anchor_text, "Annual report")
        self.assertEqual(crawl.link_priority("https://example.com/about", "Investor relations"), 0)
        self.assertEqual(crawl.link_priority("https://example.com/about", "", 0), 1)
        self.assertTrue(crawl.non_html_extension("https://example.com/call.MP3?dl=1"))

    def test_crash_resume_budget_and_document_provenance(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "crawl.sqlite"
            conn = crawl.open_db(db)
            crawl.create_schema(conn)
            with conn:
                conn.execute("INSERT INTO sites(root,page_cap) VALUES('example.com',1)")
                crawl.add_frontier(conn, "example.com", "https://example.com/", "html", 2, 0, "", "seed")
            first = crawl.claim_task(conn, "example.com", 0)
            self.assertIsNotNone(first)
            self.assertEqual(conn.execute("SELECT pages_attempted FROM sites").fetchone()[0], 1)
            body = b'<a href="/investor/report.PDF?download=1">Annual Report</a><a href="/about">About</a>'
            links, base = crawl.parse_html(body, "https://example.com/")
            result = crawl.FetchResult("https://example.com/", final_url="https://example.com/",
                                       status=200, content_type="text/html", body=body, links=links, base_url=base)
            conn.close()  # HTTP completed, but the process died before committing discoveries.

            conn = crawl.open_db(db)
            with conn:
                conn.execute("UPDATE frontier SET state='queued',lease_until=0 WHERE state='leased'")
            retried = crawl.claim_task(conn, "example.com", 0)
            self.assertEqual(retried["url_key"], first["url_key"])
            self.assertEqual(conn.execute("SELECT pages_attempted FROM sites").fetchone()[0], 1)
            self.assertEqual(crawl.finish_task(conn, retried, result), "done")
            with conn:
                crawl.record_link(conn, "example.com", "https://example.com/other",
                                  "https://example.com/other",
                                  crawl.Link("/investor/report.PDF?download=2", "Financials", "anchor"), 1, 2)
            self.assertEqual(conn.execute("SELECT count(*) FROM documents").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM document_occurrences").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT priority FROM frontier WHERE fetch_url='https://example.com/about'").fetchone()[0], 2)
            self.assertIsNone(crawl.claim_task(conn, "example.com", 0))
            self.assertEqual(conn.execute("SELECT state FROM frontier WHERE fetch_url='https://example.com/about'").fetchone()[0], "skipped_cap")
            conn.close()

    def test_retry_after_failure_and_priority_upgrade(self):
        with tempfile.TemporaryDirectory() as folder:
            conn = crawl.open_db(Path(folder) / "crawl.sqlite")
            crawl.create_schema(conn)
            with conn:
                conn.execute("INSERT INTO sites(root,page_cap) VALUES('example.com',5)")
                crawl.add_frontier(conn, "example.com", "https://example.com/page", "html", 2, 1, "", "anchor")
                crawl.add_frontier(conn, "example.com", "https://example.com/page", "html", 0, 1, "", "anchor")
            self.assertEqual(conn.execute("SELECT priority FROM frontier").fetchone()[0], 0)
            task = crawl.claim_task(conn, "example.com", 0)
            failure = crawl.FetchResult(task["fetch_url"], error="connection lost", transport_error=True)
            self.assertEqual(crawl.finish_task(conn, task, failure), "queued")
            with conn:
                conn.execute("UPDATE frontier SET due_at=0 WHERE id=?", (task["id"],))
            retry = crawl.claim_task(conn, "example.com", 0)
            self.assertEqual(retry["attempts"], 2)
            self.assertEqual(conn.execute("SELECT pages_attempted FROM sites").fetchone()[0], 1)
            conn.close()

    def test_non_html_response_does_not_consume_page_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            conn = crawl.open_db(Path(folder) / "crawl.sqlite")
            crawl.create_schema(conn)
            with conn:
                conn.execute("INSERT INTO sites(root,page_cap) VALUES('example.com',1)")
                crawl.add_frontier(conn, "example.com", "https://example.com/media", "html", 2, 0, "", "seed")
                crawl.add_frontier(conn, "example.com", "https://example.com/page", "html", 2, 0, "", "seed")
            task = crawl.claim_task(conn, "example.com", 0)
            result = crawl.FetchResult(task["fetch_url"], final_url=task["fetch_url"],
                                       status=200, content_type="audio/mpeg")
            self.assertEqual(crawl.finish_task(conn, task, result), "skipped_nonhtml")
            self.assertEqual(conn.execute("SELECT pages_attempted FROM sites").fetchone()[0], 0)
            self.assertIsNotNone(crawl.claim_task(conn, "example.com", 0))
            conn.close()

    def test_network_outage_can_resume_without_spending_budget_twice(self):
        with tempfile.TemporaryDirectory() as folder:
            conn = crawl.open_db(Path(folder) / "crawl.sqlite")
            crawl.create_schema(conn)
            with conn:
                conn.execute("INSERT INTO sites(root,page_cap) VALUES('example.com',1)")
                crawl.add_frontier(conn, "example.com", "https://example.com/", "html", 2, 0, "", "seed")
            for attempt in range(3):
                task = crawl.claim_task(conn, "example.com", 0)
                self.assertIsNotNone(task)
                state = crawl.finish_task(conn, task, crawl.FetchResult(
                    task["fetch_url"], error="offline", transport_error=True))
                self.assertEqual(state, "retry_later" if attempt == 2 else "queued")
                with conn:
                    conn.execute("UPDATE frontier SET due_at=0 WHERE id=?", (task["id"],))
            with conn:
                conn.execute("UPDATE frontier SET state='queued',attempts=0 WHERE state='retry_later'")
            task = crawl.claim_task(conn, "example.com", 0)
            self.assertIsNotNone(task)
            self.assertEqual(crawl.finish_task(conn, task, crawl.FetchResult(
                task["fetch_url"], final_url=task["fetch_url"], status=200,
                content_type="text/html", body=b"<html></html>")), "done")
            self.assertEqual(conn.execute("SELECT pages_attempted FROM sites").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM fetch_attempts").fetchone()[0], 4)
            conn.close()

    def test_automatic_site_window_replaces_finished_sites(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "crawl.sqlite"
            conn = crawl.open_db(db)
            crawl.create_schema(conn)
            with conn:
                for site in ("a.com", "b.com", "c.com"):
                    conn.execute("INSERT INTO sites(root) VALUES(?)", (site,))
                    crawl.add_frontier(conn, site, f"https://{site}/", "html", 2, 0, "", "seed")
            conn.close()

            def fake_fetch(task, site, timeout, delay):
                return crawl.FetchResult(task["fetch_url"], final_url=task["fetch_url"],
                                         status=200, content_type="text/html", body=b"<html></html>")

            args = Namespace(site=[], site_window=2, workers=2, delay=0, timeout=1,
                             page_cap=0, max_pages_this_run=0)
            with patch.object(crawl, "DB", db), patch.object(crawl, "fetch", fake_fetch):
                crawl.run_locked(args)
            conn = crawl.open_db(db)
            self.assertEqual(conn.execute("SELECT count(*) FROM frontier WHERE state='done'").fetchone()[0], 3)
            self.assertEqual(conn.execute("SELECT sum(pages_attempted) FROM sites").fetchone()[0], 3)
            conn.close()

    def test_one_command_initializes_then_resumes_without_reimporting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "out"
            source = root / "seeds.csv"
            source.write_text("domain,url\nexample.com,https://example.com/\n", encoding="utf-8")

            def fake_fetch(task, site, timeout, delay):
                return crawl.FetchResult(task["fetch_url"], final_url=task["fetch_url"],
                                         status=200, content_type="text/html", body=b"<html></html>")

            args = Namespace(site=[], site_window=1, workers=1, delay=0, timeout=1,
                             page_cap=2, max_pages_this_run=1)
            with patch.object(crawl, "OUTPUT", output), patch.object(crawl, "DB", output / "crawl.sqlite"), \
                 patch.object(crawl, "SOURCE", source), patch.object(crawl, "PHASE3", root / "missing.csv"), \
                 patch.object(crawl, "fetch", fake_fetch), redirect_stdout(StringIO()):
                crawl.command_run(args)
                conn = crawl.open_db()
                self.assertEqual(conn.execute("SELECT value FROM metadata WHERE key='initialization_complete'").fetchone()[0], "1")
                self.assertGreater(conn.execute("SELECT count(*) FROM frontier WHERE state='queued'").fetchone()[0], 0)
                conn.close()
                args.max_pages_this_run = 0
                crawl.command_run(args)
                conn = crawl.open_db()
                self.assertEqual(conn.execute("SELECT count(*) FROM frontier WHERE state='done'").fetchone()[0], 3)
                self.assertEqual(conn.execute("SELECT pages_attempted FROM sites").fetchone()[0], 1)
                conn.close()

    def test_fetch_streams_html_with_direct_curl_settings(self):
        class Response:
            status_code = 200
            url = "https://example.com/"
            headers = {"content-type": "text/html; charset=utf-8"}

            def iter_content(self, chunk_size):
                yield b"<html><a href='/invest"
                yield b"ors/report.PDF?x=1'>Report</a></html>"

            def close(self):
                pass

        class Session:
            kwargs = None

            def get(self, url, **kwargs):
                self.kwargs = kwargs
                return Response()

        session = Session()
        with patch.object(crawl, "thread_session", return_value=session):
            result = crawl.fetch({"fetch_url": "https://example.com/", "kind": "html"}, "example.com", 1, 0)
        self.assertTrue(result.html_parsed)
        self.assertEqual(result.body, b"")
        self.assertEqual(result.links[0].anchor_text, "Report")
        self.assertEqual(crawl.document_extension(crawl.public_url(result.links[0].raw_href, result.base_url)), "pdf")
        self.assertEqual(session.kwargs["impersonate"], "chrome")
        self.assertIs(session.kwargs["verify"], False)
        self.assertIsNone(session.kwargs["proxy"])

    def test_broad_outage_waits_and_recovers_in_same_run(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "crawl.sqlite"
            conn = crawl.open_db(db)
            crawl.create_schema(conn)
            with conn:
                for index in range(30):
                    site = f"site{index}.com"
                    conn.execute("INSERT INTO sites(root) VALUES(?)", (site,))
                    crawl.add_frontier(conn, site, f"https://{site}/", "html", 2, 0, "", "seed")
            conn.close()
            count = 0
            lock = Lock()

            def fake_fetch(task, site, timeout, delay):
                nonlocal count
                with lock:
                    count += 1
                    attempt = count
                if attempt <= 60:
                    return crawl.FetchResult(task["fetch_url"], error="offline", transport_error=True)
                return crawl.FetchResult(task["fetch_url"], final_url=task["fetch_url"],
                                         status=200, content_type="text/html", body=b"<html></html>")

            args = Namespace(site=[], site_window=30, workers=30, delay=0, timeout=1,
                             page_cap=0, max_pages_this_run=0)
            output = StringIO()
            with patch.object(crawl, "DB", db), patch.object(crawl, "fetch", fake_fetch), \
                 patch.object(crawl, "retry_delay", return_value=0), \
                 patch.object(crawl, "OUTAGE_PROBE_INTERVAL", 0.01), redirect_stdout(output):
                crawl.run_locked(args)
            self.assertIn("Broad connection failures detected", output.getvalue())
            self.assertIn("Connection recovered", output.getvalue())
            conn = crawl.open_db(db)
            self.assertEqual(conn.execute("SELECT count(*) FROM frontier WHERE state='done'").fetchone()[0], 30)
            self.assertEqual(conn.execute("SELECT sum(pages_attempted) FROM sites").fetchone()[0], 30)
            conn.close()


if __name__ == "__main__":
    unittest.main()
