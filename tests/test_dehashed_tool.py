"""
tests/test_dehashed_tool.py — Unit tests for run_dehashed_tool.

Tests are fully offline — all HTTP calls are monkey-patched so no real
Dehashed account is needed.
"""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Make sure the project root is on the path so we can import tools
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tools
from tools import (
    _assert_in_scope,
    init_db,
    is_already_run,
    run_dehashed_tool,
    set_allowed_scope,
    set_output_dir,
    update_db,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_response(payload: dict, status: int = 200):
    """Return a mock object that mimics urllib.request.urlopen context manager."""
    body = json.dumps(payload).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.status = status
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _make_http_error(code: int):
    """Return a urllib.error.HTTPError with the given code."""
    import urllib.error
    return urllib.error.HTTPError(
        url="https://api.dehashed.com/search",
        code=code,
        msg=f"HTTP {code}",
        hdrs=None,
        fp=None,
    )


# ---------------------------------------------------------------------------
# Test case
# ---------------------------------------------------------------------------

class TestRunDehashedTool(unittest.TestCase):

    def setUp(self):
        """Each test gets a fresh temp DB and a clean scope."""
        self.tmpdir = tempfile.mkdtemp()
        set_output_dir(self.tmpdir)
        set_allowed_scope(["example.com"])

    # ------------------------------------------------------------------ #
    #  1. Missing credentials — should gracefully skip                    #
    # ------------------------------------------------------------------ #
    def test_missing_credentials_returns_skip(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("DEHASHED_EMAIL", "DEHASHED_API_KEY")}
        with patch.dict(os.environ, env, clear=True):
            result = run_dehashed_tool.invoke({"domain": "example.com"})
        self.assertIn("[SKIP]", result)
        self.assertIn("DEHASHED_EMAIL", result)

    # ------------------------------------------------------------------ #
    #  2. Out-of-scope domain — should be blocked                         #
    # ------------------------------------------------------------------ #
    def test_out_of_scope_is_blocked(self):
        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            result = run_dehashed_tool.invoke({"domain": "evil.com"})
        self.assertIn("[SCOPE BLOCK]", result)

    # ------------------------------------------------------------------ #
    #  3. Already-run deduplication                                        #
    # ------------------------------------------------------------------ #
    def test_already_run_returns_skip(self):
        tools.mark_as_run("dehashed", "example.com")
        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            result = run_dehashed_tool.invoke({"domain": "example.com"})
        self.assertIn("[SKIP]", result)
        self.assertIn("already queried", result)

    # ------------------------------------------------------------------ #
    #  4. Successful response — credentials stored in DB                  #
    # ------------------------------------------------------------------ #
    def test_successful_response_stores_credentials(self):
        payload = {
            "total": 3,
            "entries": [
                {
                    "email": "alice@example.com",
                    "username": "alice",
                    "password": "hunter2",
                    "hashed_password": "",
                    "database_name": "BreachDB-2022",
                },
                {
                    "email": "bob@example.com",
                    "username": "bob",
                    "password": "",
                    "hashed_password": "$2y$10$abcdefghijklmnopqrstuv",
                    "database_name": "LeakedList-2023",
                },
                {
                    "email": "charlie@example.com",
                    "username": "charlie",
                    "password": "s3cr3t!",
                    "hashed_password": "",
                    "database_name": "BreachDB-2022",
                },
            ],
        }

        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            with patch("urllib.request.urlopen", return_value=_make_fake_response(payload)):
                result = run_dehashed_tool.invoke({"domain": "example.com"})

        # Check return string
        self.assertIn("example.com", result)
        self.assertIn("3 total records", result)
        self.assertIn("2 have plaintext", result)
        self.assertIn("1 have hashed", result)

        # Check DB persistence
        conn = sqlite3.connect(tools.DB_PATH)
        rows = conn.execute(
            "SELECT email, username, password, hashed_password, source "
            "FROM leaked_credentials WHERE domain='example.com'"
        ).fetchall()
        conn.close()

        self.assertEqual(len(rows), 3)
        emails = {r[0] for r in rows}
        self.assertIn("alice@example.com", emails)
        self.assertIn("bob@example.com", emails)
        self.assertIn("charlie@example.com", emails)

        # Passwords stored correctly
        pw_map = {r[0]: r[2] for r in rows}
        self.assertEqual(pw_map["alice@example.com"], "hunter2")
        self.assertEqual(pw_map["bob@example.com"], "")  # only hash

    # ------------------------------------------------------------------ #
    #  5. Empty result set                                                 #
    # ------------------------------------------------------------------ #
    def test_empty_results_returns_informative_message(self):
        payload = {"total": 0, "entries": []}
        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            with patch("urllib.request.urlopen", return_value=_make_fake_response(payload)):
                result = run_dehashed_tool.invoke({"domain": "example.com"})

        self.assertIn("no leaked credentials", result.lower())

        # Nothing written to DB
        conn = sqlite3.connect(tools.DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM leaked_credentials").fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)

    # ------------------------------------------------------------------ #
    #  6. 401 Unauthorized                                                 #
    # ------------------------------------------------------------------ #
    def test_401_returns_error_message(self):
        env = {"DEHASHED_EMAIL": "bad@test.com", "DEHASHED_API_KEY": "wrong"}
        with patch.dict(os.environ, env):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(401)):
                result = run_dehashed_tool.invoke({"domain": "example.com"})
        self.assertIn("[ERROR]", result)
        self.assertIn("401", result)

    # ------------------------------------------------------------------ #
    #  7. 302 subscription redirect                                        #
    # ------------------------------------------------------------------ #
    def test_302_returns_subscription_message(self):
        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(302)):
                result = run_dehashed_tool.invoke({"domain": "example.com"})
        self.assertIn("[ERROR]", result)
        self.assertIn("302", result)

    # ------------------------------------------------------------------ #
    #  8. Malformed JSON response                                          #
    # ------------------------------------------------------------------ #
    def test_malformed_json_returns_error(self):
        bad_resp = MagicMock()
        bad_resp.read.return_value = b"<html>not json</html>"
        bad_resp.__enter__ = lambda s: s
        bad_resp.__exit__ = MagicMock(return_value=False)

        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            with patch("urllib.request.urlopen", return_value=bad_resp):
                result = run_dehashed_tool.invoke({"domain": "example.com"})
        self.assertIn("[ERROR]", result)
        self.assertIn("non-JSON", result)

    # ------------------------------------------------------------------ #
    #  9. Protocol-prefixed domain is stripped correctly                  #
    # ------------------------------------------------------------------ #
    def test_protocol_prefix_stripped_in_query(self):
        set_allowed_scope(["https://example.com"])
        payload = {"total": 0, "entries": []}
        captured_urls = []

        def fake_urlopen(req, timeout=None):
            captured_urls.append(req.full_url)
            return _make_fake_response(payload)

        env = {"DEHASHED_EMAIL": "user@test.com", "DEHASHED_API_KEY": "key123"}
        with patch.dict(os.environ, env):
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                run_dehashed_tool.invoke({"domain": "https://example.com"})

        self.assertTrue(captured_urls, "urlopen was never called")
        # The query should use bare domain, not https://
        self.assertIn("example.com", captured_urls[0])
        self.assertNotIn("https%3A%2F%2F", captured_urls[0])

    # ------------------------------------------------------------------ #
    #  10. update_db deduplication — re-inserting same rows is idempotent #
    # ------------------------------------------------------------------ #
    def test_duplicate_credentials_are_deduplicated_in_db(self):
        cred = {
            "domain": "example.com",
            "email": "dup@example.com",
            "username": "dup",
            "password": "pw",
            "hashed_password": "",
            "source": "TestDB",
        }
        update_db("leaked_credentials", [cred])
        update_db("leaked_credentials", [cred])  # insert again

        conn = sqlite3.connect(tools.DB_PATH)
        count = conn.execute(
            "SELECT COUNT(*) FROM leaked_credentials WHERE email='dup@example.com'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1, "Duplicate credential should be ignored")


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
