"""Unit and integration tests for paper-fetch.

Pure stdlib (unittest + subprocess). No pytest, no network required.
Run from the repo root:

    python -m unittest tests.test_fetch -v
    python tests/test_fetch.py -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Make scripts/ importable when tests are run from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# fetch.py has top-level side effects minimized enough that importing
# it is safe (no network I/O, no argparse on import).
import fetch  # noqa: E402


# ---------------------------------------------------------------------------
# Pure-logic helpers
# ---------------------------------------------------------------------------


class TestSlug(unittest.TestCase):
    def test_normal_input(self):
        self.assertEqual(fetch._slug("Array programming with NumPy"), "Array_programming_with_NumPy")

    def test_truncation(self):
        self.assertEqual(fetch._slug("a" * 100, 10), "a" * 10)

    def test_strips_leading_trailing_underscores(self):
        self.assertEqual(fetch._slug("!!!hello!!!"), "hello")

    def test_empty_and_pure_punctuation(self):
        self.assertEqual(fetch._slug(""), "")
        self.assertEqual(fetch._slug("!!!"), "")

    def test_unicode_dropped(self):
        # Current behavior: non-ASCII alphanumerics get collapsed to underscores.
        # Contract we're locking in: no crash, bounded length.
        result = fetch._slug("深度学习 Deep Learning", 40)
        self.assertIn("Deep_Learning", result)
        self.assertLessEqual(len(result), 40)


class TestFilename(unittest.TestCase):
    def test_complete_meta(self):
        meta = {"author": "Charles R. Harris", "year": 2020, "title": "Array programming with NumPy"}
        self.assertEqual(fetch._filename(meta), "Harris_2020_Array_programming_with_NumPy.pdf")

    def test_missing_author(self):
        meta = {"author": None, "year": 2021, "title": "Highly accurate"}
        self.assertEqual(fetch._filename(meta), "unknown_2021_Highly_accurate.pdf")

    def test_missing_year(self):
        meta = {"author": "Smith", "year": None, "title": "Paper"}
        self.assertEqual(fetch._filename(meta), "Smith_nd_Paper.pdf")

    def test_empty_meta(self):
        self.assertEqual(fetch._filename({}), "unknown_nd_paper.pdf")

    def test_uses_last_name_only(self):
        # "Charles R. Harris" -> last token "Harris"
        meta = {"author": "Charles R. Harris", "year": 2020, "title": "x"}
        self.assertTrue(fetch._filename(meta).startswith("Harris_"))


class TestIsAllowedHost(unittest.TestCase):
    def test_allowed(self):
        self.assertTrue(fetch._is_allowed_host("https://arxiv.org/pdf/1234.5678.pdf"))
        self.assertTrue(fetch._is_allowed_host("https://www.nature.com/articles/s41586-021-03819-2.pdf"))

    def test_case_insensitive(self):
        self.assertTrue(fetch._is_allowed_host("https://ARXIV.org/pdf/x"))

    def test_blocked(self):
        self.assertFalse(fetch._is_allowed_host("https://evil.example.com/x.pdf"))
        self.assertFalse(fetch._is_allowed_host("https://sci-hub.se/10.1038/nature12373"))

    def test_malformed(self):
        self.assertFalse(fetch._is_allowed_host("not-a-url"))
        self.assertFalse(fetch._is_allowed_host(""))

    def test_env_extension(self):
        original = os.environ.get("PAPER_FETCH_ALLOWED_HOSTS", "")
        try:
            os.environ["PAPER_FETCH_ALLOWED_HOSTS"] = "foo.example.com, bar.example.edu"
            self.assertTrue(fetch._is_allowed_host("https://foo.example.com/paper.pdf"))
            self.assertTrue(fetch._is_allowed_host("https://bar.example.edu/paper.pdf"))
            self.assertFalse(fetch._is_allowed_host("https://baz.example.com/paper.pdf"))
        finally:
            if original:
                os.environ["PAPER_FETCH_ALLOWED_HOSTS"] = original
            else:
                os.environ.pop("PAPER_FETCH_ALLOWED_HOSTS", None)


class TestDecideExit(unittest.TestCase):
    def test_all_success(self):
        results = [{"success": True}, {"success": True}]
        self.assertEqual(fetch._decide_exit(results), fetch.EXIT_SUCCESS)

    def test_all_not_found(self):
        results = [{"success": False, "error": {"code": "not_found"}}]
        self.assertEqual(fetch._decide_exit(results), fetch.EXIT_UNRESOLVED)

    def test_transport_failure(self):
        results = [{"success": False, "error": {"code": "download_network_error"}}]
        self.assertEqual(fetch._decide_exit(results), fetch.EXIT_TRANSPORT)

    def test_mixed_not_found_and_transport(self):
        # Transport failures take precedence — the orchestrator should retry
        # the whole batch rather than walking each failure class.
        results = [
            {"success": True},
            {"success": False, "error": {"code": "not_found"}},
            {"success": False, "error": {"code": "download_network_error"}},
        ]
        self.assertEqual(fetch._decide_exit(results), fetch.EXIT_TRANSPORT)

    def test_mixed_success_and_not_found(self):
        results = [
            {"success": True},
            {"success": False, "error": {"code": "not_found"}},
        ]
        self.assertEqual(fetch._decide_exit(results), fetch.EXIT_UNRESOLVED)


class TestNextHints(unittest.TestCase):
    def _args(self, out="pdfs", dry_run=False):
        class A:
            pass
        a = A()
        a.out = out
        a.dry_run = dry_run
        return a

    def test_no_failures_returns_empty(self):
        results = [{"success": True, "doi": "10.1/x"}]
        self.assertEqual(fetch._next_hints(results, self._args()), [])

    def test_single_failure(self):
        results = [{"success": False, "doi": "10.1/x"}]
        hints = fetch._next_hints(results, self._args(out="papers"))
        self.assertEqual(len(hints), 1)
        self.assertIn("10.1/x", hints[0])
        self.assertIn("--out papers", hints[0])
        self.assertNotIn("--dry-run", hints[0])

    def test_single_failure_dry_run(self):
        results = [{"success": False, "doi": "10.1/x"}]
        hints = fetch._next_hints(results, self._args(dry_run=True))
        self.assertIn("--dry-run", hints[0])

    def test_multiple_failures_uses_stdin(self):
        results = [
            {"success": False, "doi": "10.1/a"},
            {"success": False, "doi": "10.2/b"},
        ]
        hints = fetch._next_hints(results, self._args())
        self.assertEqual(len(hints), 1)
        self.assertIn("--batch -", hints[0])
        self.assertIn("10.1/a", hints[0])
        self.assertIn("10.2/b", hints[0])


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------


class TestEnvelopes(unittest.TestCase):
    def setUp(self):
        # _meta() reads module-level state; seed it.
        fetch._request_id = "req_test"
        fetch._started_monotonic = 0.0

    def test_ok_envelope_shape(self):
        e = fetch._envelope_ok({"foo": "bar"})
        self.assertEqual(e["ok"], True)
        self.assertEqual(e["data"], {"foo": "bar"})
        self.assertIn("meta", e)
        self.assertEqual(e["meta"]["schema_version"], fetch.SCHEMA_VERSION)
        self.assertEqual(e["meta"]["cli_version"], fetch.CLI_VERSION)
        self.assertEqual(e["meta"]["request_id"], "req_test")

    def test_ok_envelope_partial(self):
        e = fetch._envelope_ok({}, ok="partial")
        self.assertEqual(e["ok"], "partial")

    def test_err_envelope_shape(self):
        e = fetch._envelope_err("not_found", "No OA PDF found", retryable=True, retry_after_hours=168)
        self.assertEqual(e["ok"], False)
        self.assertEqual(e["error"]["code"], "not_found")
        self.assertEqual(e["error"]["retryable"], True)
        self.assertEqual(e["error"]["retry_after_hours"], 168)
        self.assertIn("meta", e)


# ---------------------------------------------------------------------------
# Schema subcommand shape
# ---------------------------------------------------------------------------


class TestBuildSchema(unittest.TestCase):
    def test_top_level_keys(self):
        s = fetch.build_schema()
        for key in ("command", "cli_version", "schema_version", "description",
                    "subcommands", "params", "exit_codes", "error_codes", "envelope", "env"):
            self.assertIn(key, s, f"missing top-level key {key!r}")

    def test_versions_match_module(self):
        s = fetch.build_schema()
        self.assertEqual(s["cli_version"], fetch.CLI_VERSION)
        self.assertEqual(s["schema_version"], fetch.SCHEMA_VERSION)

    def test_exit_codes_complete(self):
        s = fetch.build_schema()
        for code in ("0", "1", "2", "3", "4"):
            self.assertIn(code, s["exit_codes"], f"exit code {code} missing from schema")

    def test_error_codes_include_core_set(self):
        s = fetch.build_schema()
        for code in ("validation_error", "not_found", "download_network_error", "internal_error"):
            self.assertIn(code, s["error_codes"], f"error code {code!r} missing")

    def test_params_documented(self):
        s = fetch.build_schema()
        for param in ("doi", "batch", "out", "dry_run", "format", "idempotency_key", "timeout"):
            self.assertIn(param, s["params"], f"param {param!r} missing from schema")

    def test_not_found_retryable_in_schema(self):
        s = fetch.build_schema()
        nf = s["error_codes"]["not_found"]
        self.assertTrue(nf["retryable"])
        self.assertIn("retry_after_hours", nf)


# ---------------------------------------------------------------------------
# Integration tests via subprocess (no network)
# ---------------------------------------------------------------------------


FETCH_PY = str(REPO_ROOT / "scripts" / "fetch.py")


def _run(*args, env=None, input_text=None):
    base_env = os.environ.copy()
    base_env["PAPER_FETCH_NO_AUTO_UPDATE"] = "1"  # keep tests hermetic
    if env:
        base_env.update(env)
    return subprocess.run(
        [sys.executable, FETCH_PY, *args],
        capture_output=True,
        text=True,
        env=base_env,
        input=input_text,
        timeout=15,
    )


class TestCliIntegration(unittest.TestCase):
    def test_version(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn(fetch.CLI_VERSION, r.stdout)
        self.assertIn(fetch.SCHEMA_VERSION, r.stdout)

    def test_help_exits_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("paper-fetch", r.stdout)
        self.assertIn("schema", r.stdout)  # subcommand should be mentioned

    def test_schema_subcommand_is_valid_json(self):
        r = _run("schema")
        self.assertEqual(r.returncode, 0, msg=f"stderr: {r.stderr}")
        envelope = json.loads(r.stdout)
        self.assertIs(envelope["ok"], True)
        self.assertIn("data", envelope)
        self.assertIn("meta", envelope)
        self.assertEqual(envelope["data"]["cli_version"], fetch.CLI_VERSION)

    def test_validation_error_no_args(self):
        r = _run("--format", "json")
        self.assertEqual(r.returncode, fetch.EXIT_VALIDATION)
        envelope = json.loads(r.stdout)
        self.assertIs(envelope["ok"], False)
        self.assertEqual(envelope["error"]["code"], "validation_error")
        self.assertIs(envelope["error"]["retryable"], False)

    def test_validation_error_missing_batch_file(self):
        r = _run("--batch", "/nonexistent/path/dois.txt", "--format", "json")
        self.assertEqual(r.returncode, fetch.EXIT_VALIDATION)
        envelope = json.loads(r.stdout)
        self.assertIs(envelope["ok"], False)
        self.assertEqual(envelope["error"]["code"], "validation_error")
        self.assertEqual(envelope["error"].get("field"), "batch")

    def test_empty_stdin_batch(self):
        r = _run("--batch", "-", "--format", "json", input_text="")
        self.assertEqual(r.returncode, fetch.EXIT_VALIDATION)
        envelope = json.loads(r.stdout)
        self.assertEqual(envelope["error"]["code"], "validation_error")

    def test_idempotency_replay_preserves_envelope(self):
        # Seed a fake envelope via the sidecar path, then verify replay.
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            sidecar_dir = out / ".paper-fetch-idem"
            sidecar_dir.mkdir()
            fake_envelope = {
                "ok": True,
                "data": {
                    "results": [{"doi": "10.fake/1", "success": True, "file": "fake.pdf"}],
                    "summary": {"total": 1, "succeeded": 1, "failed": 0},
                    "next": [],
                },
                "meta": {
                    "request_id": "req_seed",
                    "latency_ms": 42,
                    "schema_version": fetch.SCHEMA_VERSION,
                    "cli_version": fetch.CLI_VERSION,
                },
            }
            (sidecar_dir / "replay_test.json").write_text(json.dumps(fake_envelope))

            r = _run(
                "10.fake/1",
                "--out", str(out),
                "--idempotency-key", "replay-test",
                "--format", "json",
            )
            self.assertEqual(r.returncode, 0)
            envelope = json.loads(r.stdout)
            self.assertIs(envelope["ok"], True)
            self.assertEqual(envelope["data"]["results"][0]["doi"], "10.fake/1")
            # Replay marker should be set.
            self.assertIn("replayed_from_idempotency_key", envelope["meta"])
            self.assertEqual(envelope["meta"]["replayed_from_idempotency_key"], "replay-test")
            # request_id should be fresh (not the seeded "req_seed").
            self.assertNotEqual(envelope["meta"]["request_id"], "req_seed")


# ---------------------------------------------------------------------------
# Resolution chain (mock-based — no network)
# ---------------------------------------------------------------------------


from unittest.mock import patch  # noqa: E402 — keep imports grouped by section


class TestFetchLogic(unittest.TestCase):
    """Exercise fetch.fetch() by patching the source resolvers.

    Every test here runs with EMAIL='test@example.com' (so Unpaywall is
    tried) unless explicitly overridden, and with _download mocked to
    always succeed so we can assert on flow rather than filesystem state.
    """

    def setUp(self):
        # Seed output state used by _progress / _meta.
        fetch._format = "json"
        fetch._request_id = "req_mock"
        fetch._started_monotonic = 0.0
        self._email_patch = patch.object(fetch, "EMAIL", "test@example.com")
        self._email_patch.start()
        # Silence stderr progress events during tests.
        self._progress_patch = patch.object(fetch, "_progress", lambda *a, **k: None)
        self._progress_patch.start()

    def tearDown(self):
        self._email_patch.stop()
        self._progress_patch.stop()

    # -- helpers ---------------------------------------------------------

    def _fetch(self, doi, **kwargs):
        out_dir = kwargs.pop("out_dir", Path("/tmp/pf-mock-out"))
        defaults = dict(dry_run=True, overwrite=False, timeout=5)
        defaults.update(kwargs)
        return fetch.fetch(doi, out_dir, **defaults)

    # -- resolution chain -----------------------------------------------

    def test_unpaywall_hit_short_circuits(self):
        with patch.object(fetch, "try_unpaywall", return_value=(
            "https://www.nature.com/articles/x.pdf",
            {"title": "Paper", "year": 2024, "author": "Smith"},
        )) as up, patch.object(fetch, "try_semantic_scholar") as s2:
            r = self._fetch("10.1038/x")
        up.assert_called_once()
        # Full meta from Unpaywall → no enrichment call to S2.
        s2.assert_not_called()
        self.assertTrue(r["success"])
        self.assertEqual(r["source"], "unpaywall")
        self.assertEqual(r["sources_tried"], ["unpaywall"])

    def test_unpaywall_hit_with_missing_author_triggers_enrichment(self):
        with patch.object(fetch, "try_unpaywall", return_value=(
            "https://www.nature.com/articles/x.pdf",
            {"title": "Paper", "year": 2024, "author": None},
        )), patch.object(fetch, "try_semantic_scholar", return_value=(
            None,
            {"title": "Paper", "year": 2024, "author": "Jumper"},
            {},
        )) as s2:
            r = self._fetch("10.1038/x")
        # Enrichment path was taken.
        s2.assert_called_once()
        self.assertEqual(r["meta"]["author"], "Jumper")
        # Filename should use the enriched author.
        self.assertIn("Jumper_", r["file"])
        self.assertIn("semantic_scholar", r["sources_tried"])
        # Source stays as unpaywall — enrichment does not override the PDF URL.
        self.assertEqual(r["source"], "unpaywall")

    def test_unpaywall_miss_falls_to_semantic_scholar(self):
        with patch.object(fetch, "try_unpaywall", return_value=(None, {})), \
             patch.object(fetch, "try_semantic_scholar", return_value=(
                 "https://s2.fake/paper.pdf",
                 {"title": "T", "year": 2020, "author": "Doe"},
                 {},
             )):
            r = self._fetch("10.1/x")
        self.assertTrue(r["success"])
        self.assertEqual(r["source"], "semantic_scholar")
        self.assertEqual(r["sources_tried"], ["unpaywall", "semantic_scholar"])

    def test_s2_externalid_arxiv(self):
        with patch.object(fetch, "try_unpaywall", return_value=(None, {})), \
             patch.object(fetch, "try_semantic_scholar", return_value=(
                 None,
                 {"title": "T", "year": 2020, "author": "Doe"},
                 {"ArXiv": "2103.00001"},
             )):
            r = self._fetch("10.1/x")
        self.assertTrue(r["success"])
        self.assertEqual(r["source"], "arxiv")
        self.assertIn("arxiv", r["sources_tried"])
        self.assertEqual(r["pdf_url"], "https://arxiv.org/pdf/2103.00001.pdf")

    def test_s2_externalid_pmc(self):
        with patch.object(fetch, "try_unpaywall", return_value=(None, {})), \
             patch.object(fetch, "try_semantic_scholar", return_value=(
                 None,
                 {"title": "T", "year": 2020, "author": "Doe"},
                 {"PubMedCentral": "PMC1234567"},
             )):
            r = self._fetch("10.1/x")
        self.assertTrue(r["success"])
        self.assertEqual(r["source"], "pmc")
        self.assertIn("PMC1234567", r["pdf_url"])

    def test_biorxiv_doi_prefix(self):
        with patch.object(fetch, "try_unpaywall", return_value=(None, {})), \
             patch.object(fetch, "try_semantic_scholar", return_value=(None, {}, {})), \
             patch.object(fetch, "try_biorxiv", return_value="https://www.biorxiv.org/x.pdf"):
            r = self._fetch("10.1101/2023.01.01.522400")
        self.assertTrue(r["success"])
        self.assertEqual(r["source"], "biorxiv")
        self.assertIn("biorxiv", r["sources_tried"])

    def test_non_biorxiv_doi_does_not_try_biorxiv(self):
        with patch.object(fetch, "try_unpaywall", return_value=(None, {})), \
             patch.object(fetch, "try_semantic_scholar", return_value=(None, {}, {})), \
             patch.object(fetch, "try_biorxiv") as biorxiv:
            r = self._fetch("10.1038/x")
        biorxiv.assert_not_called()
        self.assertFalse(r["success"])
        self.assertNotIn("biorxiv", r["sources_tried"])

    def test_all_sources_miss_returns_not_found(self):
        with patch.object(fetch, "try_unpaywall", return_value=(None, {})), \
             patch.object(fetch, "try_semantic_scholar", return_value=(None, {}, {})):
            r = self._fetch("10.1/nope")
        self.assertFalse(r["success"])
        self.assertIsNone(r["source"])
        self.assertEqual(r["error"]["code"], "not_found")
        # Contract: not_found is retryable with retry_after_hours.
        self.assertTrue(r["error"]["retryable"])
        self.assertEqual(r["error"]["retry_after_hours"], 168)

    def test_email_unset_skips_unpaywall(self):
        with patch.object(fetch, "EMAIL", ""), \
             patch.object(fetch, "try_unpaywall") as up, \
             patch.object(fetch, "try_semantic_scholar", return_value=(
                 "https://s2.fake/x.pdf",
                 {"title": "T", "year": 2020, "author": "Doe"},
                 {},
             )):
            r = self._fetch("10.1/x")
        up.assert_not_called()
        self.assertTrue(r["success"])
        self.assertNotIn("unpaywall", r["sources_tried"])

    # -- post-resolution flow -------------------------------------------

    def test_dry_run_does_not_download(self):
        with patch.object(fetch, "try_unpaywall", return_value=(
            "https://arxiv.org/pdf/x.pdf",
            {"title": "T", "year": 2024, "author": "Smith"},
        )), patch.object(fetch, "_download") as dl:
            r = self._fetch("10.1/x", dry_run=True)
        dl.assert_not_called()
        self.assertTrue(r["success"])
        self.assertTrue(r.get("dry_run"))

    def test_skip_if_exists(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            # Seed the deterministic destination filename.
            existing = out / "Smith_2024_Paper.pdf"
            existing.write_bytes(b"%PDF-1.4 existing")
            with patch.object(fetch, "try_unpaywall", return_value=(
                "https://arxiv.org/pdf/x.pdf",
                {"title": "Paper", "year": 2024, "author": "Smith"},
            )), patch.object(fetch, "_download") as dl:
                r = self._fetch("10.1/x", out_dir=out, dry_run=False, overwrite=False)
            dl.assert_not_called()
            self.assertTrue(r["success"])
            self.assertTrue(r["skipped"])
            self.assertEqual(r["skip_reason"], "file_exists")

    def test_overwrite_forces_download(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            existing = out / "Smith_2024_Paper.pdf"
            existing.write_bytes(b"%PDF-1.4 existing")
            with patch.object(fetch, "try_unpaywall", return_value=(
                "https://arxiv.org/pdf/x.pdf",
                {"title": "Paper", "year": 2024, "author": "Smith"},
            )), patch.object(fetch, "_download", return_value=None) as dl:
                r = self._fetch("10.1/x", out_dir=out, dry_run=False, overwrite=True)
            dl.assert_called_once()
            self.assertTrue(r["success"])
            self.assertFalse(r.get("skipped", False))

    def test_download_network_error_is_retryable(self):
        with patch.object(fetch, "try_unpaywall", return_value=(
            "https://arxiv.org/pdf/x.pdf",
            {"title": "T", "year": 2024, "author": "Smith"},
        )), patch.object(fetch, "_download", return_value="network_error"):
            r = self._fetch("10.1/x", dry_run=False)
        self.assertFalse(r["success"])
        self.assertEqual(r["error"]["code"], "download_network_error")
        self.assertTrue(r["error"]["retryable"])

    def test_download_not_a_pdf_is_not_retryable(self):
        with patch.object(fetch, "try_unpaywall", return_value=(
            "https://arxiv.org/pdf/x.pdf",
            {"title": "T", "year": 2024, "author": "Smith"},
        )), patch.object(fetch, "_download", return_value="not_a_pdf"):
            r = self._fetch("10.1/x", dry_run=False)
        self.assertFalse(r["success"])
        self.assertEqual(r["error"]["code"], "download_not_a_pdf")
        self.assertFalse(r["error"]["retryable"])

    def test_doi_url_prefix_is_stripped(self):
        with patch.object(fetch, "try_unpaywall") as up:
            up.return_value = (None, {})
            with patch.object(fetch, "try_semantic_scholar", return_value=(None, {}, {})):
                r = self._fetch("https://doi.org/10.1/x")
        # Verify the DOI was normalized before the call.
        self.assertEqual(r["doi"], "10.1/x")
        called_doi = up.call_args[0][0]
        self.assertEqual(called_doi, "10.1/x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
