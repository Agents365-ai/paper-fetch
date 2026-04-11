#!/usr/bin/env python3
"""Fetch legal open-access PDFs by DOI.

Resolution order: Unpaywall -> Semantic Scholar openAccessPdf ->
arXiv -> PMC OA -> bioRxiv/medRxiv.

Exit codes:
  0  success (all DOIs resolved and downloaded / dry-run previewed)
  1  unresolved — one or more DOIs had no OA copy; no transport failure
  2  reserved for auth errors (currently unused; Unpaywall gracefully degrades)
  3  validation error (bad arguments, missing input)
  4  transport error — network / download / IO failure (retryable class)

If UNPAYWALL_EMAIL is not set, the Unpaywall source is skipped
and the remaining 4 sources are still tried.

Machine contract:
  stdout — one JSON object per invocation (or NDJSON with --stream)
  stderr — NDJSON progress events when --format json; prose when --format text

Contract-changing version of this file. The schema_version below is what the
`schema` subcommand reports and what appears in every response's `meta` slot;
agents that cache schema should compare against it to detect drift.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

CLI_VERSION = "0.5.0"
SCHEMA_VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

EMAIL = os.environ.get("UNPAYWALL_EMAIL", "").strip()
UA = f"paper-fetch/{CLI_VERSION} (mailto:{EMAIL or 'anonymous'})"
DEFAULT_TIMEOUT = 30
MAX_PDF_SIZE = 50 * 1024 * 1024  # 50 MB

# Auto-update (background git pull). Default 24h between checks.
# Disable with PAPER_FETCH_NO_AUTO_UPDATE=1. Override interval with
# PAPER_FETCH_UPDATE_INTERVAL=<seconds>.
AUTO_UPDATE_COOLDOWN_SEC = int(os.environ.get("PAPER_FETCH_UPDATE_INTERVAL", "86400"))

EXIT_SUCCESS = 0
EXIT_UNRESOLVED = 1
EXIT_AUTH = 2  # reserved
EXIT_VALIDATION = 3
EXIT_TRANSPORT = 4

_BASE_ALLOWED_HOSTS = {
    "api.unpaywall.org",
    "unpaywall.org",
    "arxiv.org",
    "www.ncbi.nlm.nih.gov",
    "api.semanticscholar.org",
    "api.biorxiv.org",
    "www.biorxiv.org",
    "www.medrxiv.org",
    "europepmc.org",
    "www.nature.com",
    "link.springer.com",
    "journals.plos.org",
    "elifesciences.org",
    "www.cell.com",
    "www.science.org",
    "academic.oup.com",
    "pubs.acs.org",
    "onlinelibrary.wiley.com",
    "www.frontiersin.org",
    "www.mdpi.com",
    "peerj.com",
    "royalsocietypublishing.org",
    "www.pnas.org",
    "proceedings.mlr.press",
    "openreview.net",
    "dl.acm.org",
    "ieeexplore.ieee.org",
}


def _allowed_hosts() -> set[str]:
    extra = os.environ.get("PAPER_FETCH_ALLOWED_HOSTS", "").strip()
    if not extra:
        return _BASE_ALLOWED_HOSTS
    more = {h.strip().lower() for h in extra.split(",") if h.strip()}
    return _BASE_ALLOWED_HOSTS | more


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

# Global output state (set by main()).
_format = "json"
_pretty = False
_stream = False
_request_id = ""
_started_monotonic = 0.0


def _now_ms() -> int:
    return int((time.monotonic() - _started_monotonic) * 1000)


def _log_text(msg: str) -> None:
    """Human-readable diagnostic → stderr only (used in text mode)."""
    print(msg, file=sys.stderr)


def _progress(event: str, **fields) -> None:
    """Progress event on stderr.

    JSON mode emits NDJSON so orchestrators can parse stderr for liveness.
    Text mode emits prose for humans.
    """
    if _format == "json":
        payload = {"event": event, "request_id": _request_id, "elapsed_ms": _now_ms(), **fields}
        print(json.dumps(payload, ensure_ascii=False), file=sys.stderr, flush=True)
        return

    # Text mode — render a short human line.
    if event == "start":
        _log_text(f"==> {fields.get('doi', '?')}")
    elif event == "source_skip":
        _log_text(f"  [{fields.get('source', '?')}] skipped ({fields.get('reason', '?')})")
    elif event == "source_try":
        _log_text(f"  [{fields.get('source', '?')}] trying…")
    elif event == "source_hit":
        _log_text(f"  [{fields.get('source', '?')}] {fields.get('pdf_url', '?')}")
    elif event == "source_miss":
        _log_text(f"  [{fields.get('source', '?')}] no PDF")
    elif event == "download_error":
        _log_text(f"  download failed: {fields.get('reason', '?')}")
    elif event == "download_ok":
        _log_text(f"  saved → {fields.get('file', '?')}")
    elif event == "download_skip":
        _log_text(f"  [skip-existing] {fields.get('file', '?')}")
    elif event == "dry_run":
        _log_text(f"  [dry-run] [{fields.get('source', '?')}] {fields.get('pdf_url', '?')} → {fields.get('file', '?')}")
    elif event == "update_check_spawned":
        _log_text("  [auto-update] background git pull spawned")
    elif event == "not_found":
        _log_text(f"  no OA PDF found for {fields.get('doi', '?')}")
    else:
        # fall back
        _log_text(f"  [{event}] {fields}")


def _dump_json(obj: dict) -> str:
    if _pretty:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    return json.dumps(obj, ensure_ascii=False)


def _emit(obj: dict) -> None:
    """Final result → stdout as JSON or human-readable text."""
    if _format == "json":
        print(_dump_json(obj))
    else:
        _emit_text(obj)


def _emit_ndjson(obj: dict) -> None:
    """Per-item streaming line on stdout (--stream mode)."""
    print(_dump_json(obj), flush=True)


def _emit_text(obj: dict) -> None:
    """Render a result envelope as human-readable text on stdout."""
    ok = obj.get("ok")
    if ok is False:
        err = obj.get("error", {})
        print(f"error: [{err.get('code', '?')}] {err.get('message', '?')}")
        return

    data = obj.get("data", {})
    results = data.get("results", [data] if "doi" in data else [])
    for r in results:
        if r.get("skipped"):
            status = "skipped"
        elif r.get("dry_run"):
            status = "dry-run"
        elif r.get("success"):
            status = "saved"
        else:
            status = "failed"
        src = r.get("source") or "?"
        doi = r.get("doi", "?")
        target = r.get("file") or r.get("pdf_url") or "?"
        print(f"[{src}] {doi} → {target}  ({status})")
    summary = data.get("summary")
    if summary:
        print(f"\n{summary['succeeded']}/{summary['total']} succeeded  ({summary.get('failed', 0)} failed)")
    nxt = data.get("next") or []
    if nxt:
        print("\nnext:")
        for hint in nxt:
            print(f"  {hint}")


def _meta(extra: dict | None = None) -> dict:
    m = {
        "request_id": _request_id,
        "latency_ms": _now_ms(),
        "schema_version": SCHEMA_VERSION,
        "cli_version": CLI_VERSION,
    }
    if extra:
        m.update(extra)
    return m


def _envelope_ok(data: dict, *, ok=True, meta_extra: dict | None = None) -> dict:
    return {"ok": ok, "data": data, "meta": _meta(meta_extra)}


def _envelope_err(code: str, message: str, *, retryable: bool = False, **ctx) -> dict:
    e = {"code": code, "message": message, "retryable": retryable}
    e.update(ctx)
    return {"ok": False, "error": e, "meta": _meta()}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get(url: str, *, accept: str = "application/json", timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _get_json(url: str, *, timeout: int):
    return json.loads(_get(url, timeout=timeout).decode("utf-8"))


def _is_allowed_host(url: str) -> bool:
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host in _allowed_hosts()


def _download(url: str, dest: Path, *, timeout: int) -> str | None:
    """Download a PDF. Returns None on success, or an error slug on failure."""
    if not _is_allowed_host(url):
        _progress("download_error", reason="host_not_allowed", url=url)
        return "host_not_allowed"
    try:
        data = _get(url, accept="application/pdf", timeout=timeout)
    except Exception as e:
        _progress("download_error", reason="network_error", error=str(e))
        return "network_error"
    if len(data) > MAX_PDF_SIZE:
        _progress("download_error", reason="size_exceeded", bytes=len(data), limit=MAX_PDF_SIZE)
        return "size_exceeded"
    if not data[:5].startswith(b"%PDF"):
        _progress("download_error", reason="not_a_pdf")
        return "not_a_pdf"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except OSError as e:
        _progress("download_error", reason="io_error", error=str(e))
        return "io_error"
    return None


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------


def _slug(s: str, n: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")
    return s[:n]


def _filename(meta: dict) -> str:
    author = _slug((meta.get("author") or "unknown").split()[-1], 20)
    year = str(meta.get("year") or "nd")
    title = _slug(meta.get("title") or "paper", 40)
    return f"{author}_{year}_{title}.pdf"


# ---------------------------------------------------------------------------
# Source resolvers
# ---------------------------------------------------------------------------


def try_unpaywall(doi: str, *, timeout: int) -> tuple[str | None, dict]:
    url = f"https://api.unpaywall.org/v2/{urllib.parse.quote(doi)}?email={EMAIL}"
    try:
        d = _get_json(url, timeout=timeout)
    except Exception as e:
        _progress("source_miss", source="unpaywall", reason=str(e))
        return None, {}
    meta = {
        "title": d.get("title"),
        "year": d.get("year"),
        "author": (d.get("z_authors") or [{}])[0].get("family") if d.get("z_authors") else None,
    }
    loc = d.get("best_oa_location") or {}
    return loc.get("url_for_pdf"), meta


def try_semantic_scholar(doi: str, *, timeout: int) -> tuple[str | None, dict, dict]:
    url = (
        f"https://api.semanticscholar.org/graph/v1/paper/DOI:{urllib.parse.quote(doi)}"
        "?fields=title,year,authors,openAccessPdf,externalIds"
    )
    try:
        d = _get_json(url, timeout=timeout)
    except Exception as e:
        _progress("source_miss", source="semantic_scholar", reason=str(e))
        return None, {}, {}
    meta = {
        "title": d.get("title"),
        "year": d.get("year"),
        "author": (d.get("authors") or [{}])[0].get("name"),
    }
    pdf = (d.get("openAccessPdf") or {}).get("url")
    return pdf, meta, d.get("externalIds") or {}


def try_arxiv(arxiv_id: str) -> str:
    return f"https://arxiv.org/pdf/{arxiv_id}.pdf"


def try_pmc(pmcid: str) -> str:
    pmcid = pmcid if pmcid.startswith("PMC") else f"PMC{pmcid}"
    return f"https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid}/pdf/"


def try_biorxiv(doi: str, *, timeout: int) -> str | None:
    if not doi.startswith("10.1101/"):
        return None
    for server in ("biorxiv", "medrxiv"):
        try:
            d = _get_json(f"https://api.biorxiv.org/details/{server}/{doi}", timeout=timeout)
            coll = d.get("collection") or []
            if coll:
                latest = coll[-1]
                return f"https://www.{server}.org/content/10.1101/{latest['doi'].split('/')[-1]}v{latest.get('version', 1)}.full.pdf"
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Core fetch logic
# ---------------------------------------------------------------------------


def fetch(
    doi: str,
    out_dir: Path,
    *,
    dry_run: bool,
    overwrite: bool,
    timeout: int,
) -> dict:
    """Resolve and optionally download a single DOI.

    Returns a structured per-item result (not an envelope). Guaranteed keys:
      doi, success, source, pdf_url, file, meta, sources_tried, error?
    """
    doi = doi.strip()
    # str.removeprefix is Python 3.9+; README advertises 3.8+.
    for _prefix in ("https://doi.org/", "doi.org/"):
        if doi.startswith(_prefix):
            doi = doi[len(_prefix):]
    _progress("start", doi=doi)

    sources_tried: list[str] = []
    pdf_url: str | None = None
    meta: dict = {}
    source = "none"

    if EMAIL:
        _progress("source_try", doi=doi, source="unpaywall")
        sources_tried.append("unpaywall")
        pdf_url, meta = try_unpaywall(doi, timeout=timeout)
        if pdf_url:
            _progress("source_hit", doi=doi, source="unpaywall", pdf_url=pdf_url)
            source = "unpaywall"
        else:
            _progress("source_miss", doi=doi, source="unpaywall")
    else:
        _progress("source_skip", doi=doi, source="unpaywall", reason="UNPAYWALL_EMAIL not set")

    # Metadata enrichment: Unpaywall sometimes returns a PDF URL without
    # full z_authors or title; enrich from Semantic Scholar so the
    # derived filename uses the real first author / title instead of
    # the "unknown_<year>_paper.pdf" fallback. Does not override the
    # Unpaywall PDF URL.
    if pdf_url and (not meta.get("author") or not meta.get("title")):
        _progress("source_try", doi=doi, source="semantic_scholar", reason="metadata_enrichment")
        if "semantic_scholar" not in sources_tried:
            sources_tried.append("semantic_scholar")
        _, s2_meta, _ = try_semantic_scholar(doi, timeout=timeout)
        enriched_fields = []
        for k, v in s2_meta.items():
            if v and not meta.get(k):
                meta[k] = v
                enriched_fields.append(k)
        if enriched_fields:
            _progress("source_enrich", doi=doi, source="semantic_scholar", fields=enriched_fields)
        elif not s2_meta:
            # S2 unreachable during enrichment. The Unpaywall PDF URL is still
            # valid; the filename will just fall back to "unknown_<year>_…".
            _progress("source_enrich_failed", doi=doi, source="semantic_scholar", reason="s2_unavailable")

    if not pdf_url:
        _progress("source_try", doi=doi, source="semantic_scholar")
        sources_tried.append("semantic_scholar")
        s2_pdf, s2_meta, ext = try_semantic_scholar(doi, timeout=timeout)
        for k, v in s2_meta.items():
            if v and not meta.get(k):
                meta[k] = v
        if s2_pdf:
            pdf_url, source = s2_pdf, "semantic_scholar"
            _progress("source_hit", doi=doi, source="semantic_scholar", pdf_url=pdf_url)
        else:
            _progress("source_miss", doi=doi, source="semantic_scholar")
            if ext.get("ArXiv"):
                sources_tried.append("arxiv")
                pdf_url, source = try_arxiv(ext["ArXiv"]), "arxiv"
                _progress("source_hit", doi=doi, source="arxiv", pdf_url=pdf_url)
            elif ext.get("PubMedCentral"):
                sources_tried.append("pmc")
                pdf_url, source = try_pmc(ext["PubMedCentral"]), "pmc"
                _progress("source_hit", doi=doi, source="pmc", pdf_url=pdf_url)

    if not pdf_url and doi.startswith("10.1101/"):
        _progress("source_try", doi=doi, source="biorxiv")
        sources_tried.append("biorxiv")
        pdf_url = try_biorxiv(doi, timeout=timeout)
        if pdf_url:
            source = "biorxiv"
            _progress("source_hit", doi=doi, source="biorxiv", pdf_url=pdf_url)
        else:
            _progress("source_miss", doi=doi, source="biorxiv")

    if not pdf_url:
        _progress("not_found", doi=doi)
        return {
            "doi": doi,
            "success": False,
            "source": None,
            "pdf_url": None,
            "file": None,
            "meta": meta or {},
            "sources_tried": sources_tried,
            "error": {
                "code": "not_found",
                "message": "No open-access PDF found",
                "retryable": True,
                "retry_after_hours": 168,
                "reason": "OA availability changes over time; retry after embargo lifts or preprint appears",
            },
        }

    fname = _filename(meta or {"title": doi})
    dest = out_dir / fname

    if dry_run:
        _progress("dry_run", doi=doi, source=source, pdf_url=pdf_url, file=str(dest))
        return {
            "doi": doi,
            "success": True,
            "source": source,
            "pdf_url": pdf_url,
            "file": str(dest),
            "meta": meta or {},
            "sources_tried": sources_tried,
            "dry_run": True,
        }

    if dest.exists() and not overwrite:
        _progress("download_skip", doi=doi, file=str(dest))
        return {
            "doi": doi,
            "success": True,
            "source": source,
            "pdf_url": pdf_url,
            "file": str(dest),
            "meta": meta or {},
            "sources_tried": sources_tried,
            "skipped": True,
            "skip_reason": "file_exists",
        }

    dl_err = _download(pdf_url, dest, timeout=timeout)
    if dl_err is None:
        _progress("download_ok", doi=doi, file=str(dest))
        return {
            "doi": doi,
            "success": True,
            "source": source,
            "pdf_url": pdf_url,
            "file": str(dest),
            "meta": meta or {},
            "sources_tried": sources_tried,
        }

    retryable = dl_err in ("network_error", "size_exceeded", "io_error")
    return {
        "doi": doi,
        "success": False,
        "source": source,
        "pdf_url": pdf_url,
        "file": None,
        "meta": meta or {},
        "sources_tried": sources_tried,
        "error": {
            "code": f"download_{dl_err}",
            "message": f"Download failed from {source}: {dl_err}",
            "retryable": retryable,
        },
    }


# ---------------------------------------------------------------------------
# Idempotency sidecar
# ---------------------------------------------------------------------------


def _idem_path(out_dir: Path, key: str) -> Path:
    safe = _slug(key, 80) or "default"
    return out_dir / ".paper-fetch-idem" / f"{safe}.json"


def _idem_load(out_dir: Path, key: str) -> dict | None:
    p = _idem_path(out_dir, key)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _idem_store(out_dir: Path, key: str, envelope: dict) -> None:
    p = _idem_path(out_dir, key)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass  # best-effort only


# ---------------------------------------------------------------------------
# Schema subcommand
# ---------------------------------------------------------------------------


def build_schema() -> dict:
    return {
        "command": "paper-fetch",
        "cli_version": CLI_VERSION,
        "schema_version": SCHEMA_VERSION,
        "description": "Fetch legal open-access PDFs by DOI via Unpaywall, Semantic Scholar, arXiv, PMC, and bioRxiv/medRxiv.",
        "subcommands": {
            "schema": "Print this schema as JSON and exit (no network).",
        },
        "params": {
            "doi": {
                "type": "string",
                "required": False,
                "description": "DOI to fetch (positional). Use '-' to read DOIs line-by-line from stdin.",
                "pattern": "^10\\..+/.+$",
                "example": "10.1038/s41586-020-2649-2",
            },
            "batch": {
                "type": "path",
                "required": False,
                "description": "File with one DOI per line for bulk download. Use '-' to read from stdin.",
            },
            "out": {
                "type": "path",
                "required": False,
                "default": "pdfs",
                "description": "Output directory.",
            },
            "dry_run": {
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Resolve sources without downloading; preview the PDF URL and destination path.",
            },
            "format": {
                "type": "enum",
                "values": ["json", "text"],
                "required": False,
                "default": "auto (json when stdout not a TTY, text otherwise)",
                "description": "Output format. json for agents, text for humans.",
            },
            "pretty": {
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Pretty-print JSON output with 2-space indentation.",
            },
            "stream": {
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Emit one NDJSON result per line on stdout as each DOI resolves, then a final summary line.",
            },
            "overwrite": {
                "type": "boolean",
                "required": False,
                "default": False,
                "description": "Re-download PDFs even when the destination file already exists.",
            },
            "idempotency_key": {
                "type": "string",
                "required": False,
                "description": "Stable key for safe retries. Re-running with the same key returns the original envelope from a sidecar in <out>/.paper-fetch-idem/.",
            },
            "timeout": {
                "type": "integer",
                "required": False,
                "default": DEFAULT_TIMEOUT,
                "description": "HTTP timeout in seconds per request.",
            },
        },
        "exit_codes": {
            "0": "success (all DOIs resolved / previewed)",
            "1": "unresolved (some DOIs had no OA copy; no transport failure)",
            "2": "reserved for auth errors (currently unused)",
            "3": "validation error (bad arguments, missing input)",
            "4": "transport error (network / download / IO failure; retryable class)",
        },
        "error_codes": {
            "validation_error": {"retryable": False, "message": "Bad arguments or empty input"},
            "not_found": {"retryable": True, "retry_after_hours": 168, "message": "No OA PDF found anywhere; OA availability changes over time"},
            "download_network_error": {"retryable": True, "message": "Network failure during download"},
            "download_not_a_pdf": {"retryable": False, "message": "Response was not a PDF (HTML landing page)"},
            "download_host_not_allowed": {"retryable": False, "message": "PDF URL host not in allowlist"},
            "download_size_exceeded": {"retryable": True, "message": f"Response exceeded {MAX_PDF_SIZE // (1024*1024)} MB limit"},
            "download_io_error": {"retryable": True, "message": "Local filesystem write failed"},
            "internal_error": {"retryable": False, "message": "Unexpected error"},
        },
        "envelope": {
            "success": {"ok": True, "data": {"results": [], "summary": {}, "next": []}, "meta": {}},
            "partial": {"ok": "partial", "data": {"results": [], "summary": {}, "next": []}, "meta": {}},
            "failure": {"ok": False, "error": {"code": "", "message": "", "retryable": False}, "meta": {}},
        },
        "env": {
            "UNPAYWALL_EMAIL": "Optional. Contact email for Unpaywall API. If unset, Unpaywall is skipped.",
            "PAPER_FETCH_ALLOWED_HOSTS": "Optional. Comma-separated hostnames to extend the download allowlist.",
            "PAPER_FETCH_NO_AUTO_UPDATE": "Optional. Set to any value to disable silent background self-update.",
            "PAPER_FETCH_UPDATE_INTERVAL": "Optional. Cooldown in seconds between update checks. Default 86400.",
        },
    }


# ---------------------------------------------------------------------------
# Auto-update
# ---------------------------------------------------------------------------


def maybe_self_update() -> bool:
    """Spawn a detached background 'git pull --ff-only' to keep the skill up to date.

    Returns True if a background pull was spawned (observable by callers),
    False otherwise. Silent, non-blocking, best-effort.

    No-ops when:
      - PAPER_FETCH_NO_AUTO_UPDATE is set
      - The skill directory is not a git checkout
      - The last update attempt was within AUTO_UPDATE_COOLDOWN_SEC
      - The `git` binary is unavailable
      - Any error occurs (never interferes with the main flow)
    """
    if os.environ.get("PAPER_FETCH_NO_AUTO_UPDATE"):
        return False
    try:
        import subprocess

        skill_dir = Path(__file__).resolve().parent.parent
        git_dir = skill_dir / ".git"
        if not git_dir.exists():
            return False

        stamp = git_dir / ".paper-fetch-last-update"
        now = time.time()
        if stamp.exists():
            try:
                if now - stamp.stat().st_mtime < AUTO_UPDATE_COOLDOWN_SEC:
                    return False
            except OSError:
                pass

        try:
            stamp.touch(exist_ok=True)
            os.utime(stamp, (now, now))
        except OSError:
            return False

        subprocess.Popen(
            ["git", "-C", str(skill_dir), "pull", "--ff-only", "--quiet"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """\
exit codes:
  0  all DOIs resolved successfully
  1  unresolved (some DOIs had no OA copy; no transport failure)
  3  validation error (bad arguments)
  4  transport error (network / download / IO failure; retryable class)

subcommands:
  schema                 print the machine-readable CLI schema and exit (no network)

stdin:
  paper-fetch -          read a single DOI from stdin
  paper-fetch --batch -  read DOIs line-by-line from stdin

output:
  stdout emits one JSON object per invocation (NDJSON with --stream).
  stderr emits NDJSON progress events when --format json, prose when --format text.
  stdout format auto-detects TTY: json when piped/captured, text in a terminal.

examples:
  %(prog)s 10.1038/s41586-020-2649-2
  %(prog)s 10.1038/s41586-020-2649-2 --dry-run
  %(prog)s --batch dois.txt --out ./papers --format text
  echo 10.1038/s41586-020-2649-2 | %(prog)s --batch -
  %(prog)s schema
"""


def _load_dois_from_args(args) -> list[str] | dict:
    """Parse DOI input from args. Returns list of DOIs or an error envelope dict."""
    if args.batch:
        if args.batch == "-":
            text = sys.stdin.read()
            dois = [l.strip() for l in text.splitlines() if l.strip()]
        else:
            batch_path = Path(args.batch)
            if not batch_path.exists():
                return _envelope_err(
                    "validation_error",
                    f"Batch file not found: {args.batch}",
                    field="batch",
                )
            dois = [l.strip() for l in batch_path.read_text().splitlines() if l.strip()]
    elif args.doi == "-":
        text = sys.stdin.read()
        dois = [l.strip() for l in text.splitlines() if l.strip()]
    elif args.doi:
        dois = [args.doi]
    else:
        return _envelope_err("validation_error", "Provide a DOI or --batch file")

    if not dois:
        return _envelope_err("validation_error", "No DOIs found in input")
    return dois


def _default_format() -> str:
    try:
        return "json" if not sys.stdout.isatty() else "text"
    except Exception:
        return "json"


def _decide_exit(results: list[dict]) -> int:
    """Pick the most descriptive exit code from per-item outcomes."""
    any_transport = False
    any_unresolved = False
    any_failure = False
    for r in results:
        if r.get("success"):
            continue
        any_failure = True
        err = r.get("error") or {}
        code = err.get("code", "")
        if code == "not_found":
            any_unresolved = True
        elif code.startswith("download_"):
            any_transport = True
        else:
            any_unresolved = True
    if not any_failure:
        return EXIT_SUCCESS
    if any_transport:
        return EXIT_TRANSPORT
    if any_unresolved:
        return EXIT_UNRESOLVED
    return EXIT_UNRESOLVED


def _next_hints(results: list[dict], args) -> list[str]:
    """Suggest follow-up commands for the failed subset."""
    failed = [r["doi"] for r in results if not r.get("success")]
    if not failed:
        return []
    out = args.out
    if len(failed) == 1:
        cmd = f"paper-fetch {failed[0]} --out {out}"
        if args.dry_run:
            cmd += " --dry-run"
        return [cmd]
    # Multiple failures — suggest piping the failed DOIs back in.
    joined = "\\n".join(failed)
    cmd = f"printf '{joined}\\n' | paper-fetch --batch - --out {out}"
    if args.dry_run:
        cmd += " --dry-run"
    return [cmd]


def main():
    global _format, _pretty, _stream, _request_id, _started_monotonic

    _started_monotonic = time.monotonic()
    _request_id = f"req_{uuid.uuid4().hex[:12]}"

    # Schema subcommand — handle before the main parser so we don't require a DOI.
    if len(sys.argv) >= 2 and sys.argv[1] == "schema":
        # Honor --pretty / --format if they follow.
        rest = sys.argv[2:]
        _pretty = "--pretty" in rest
        if "--format" in rest:
            i = rest.index("--format")
            if i + 1 < len(rest) and rest[i + 1] in ("json", "text"):
                _format = rest[i + 1]
            else:
                _format = _default_format()
        else:
            _format = _default_format()
        schema = build_schema()
        _emit(_envelope_ok(schema))
        sys.exit(EXIT_SUCCESS)

    ap = argparse.ArgumentParser(
        prog="paper-fetch",
        description="Fetch legal open-access PDFs by DOI via Unpaywall, Semantic Scholar, arXiv, PMC, and bioRxiv/medRxiv.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("doi", nargs="?", help="DOI to fetch (e.g. 10.1038/s41586-020-2649-2). Use '-' to read from stdin.")
    ap.add_argument("--batch", metavar="FILE", help="file with one DOI per line for bulk download. Use '-' to read from stdin.")
    ap.add_argument("--out", default="pdfs", metavar="DIR", help="output directory (default: pdfs)")
    ap.add_argument("--dry-run", action="store_true", help="resolve sources without downloading; preview the PDF URL and filename")
    ap.add_argument(
        "--format",
        choices=["json", "text"],
        default=None,
        dest="fmt",
        help="output format. json for agents, text for humans. Default: json when stdout is not a TTY, text otherwise.",
    )
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON output (2-space indent)")
    ap.add_argument("--stream", action="store_true", help="emit one NDJSON result per line on stdout as each DOI resolves (batch mode)")
    ap.add_argument("--overwrite", action="store_true", help="re-download even if the destination file already exists")
    ap.add_argument("--idempotency-key", metavar="KEY", default=None, help="safe-retry key; re-running with the same key replays the original envelope from <out>/.paper-fetch-idem/")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SECONDS", help=f"HTTP timeout in seconds per request (default: {DEFAULT_TIMEOUT})")
    ap.add_argument("--version", action="version", version=f"paper-fetch {CLI_VERSION} (schema {SCHEMA_VERSION})")
    args = ap.parse_args()

    _format = args.fmt or _default_format()
    _pretty = args.pretty
    _stream = args.stream

    # Fire auto-update now that format is known, so the event is routable.
    if maybe_self_update():
        _progress("update_check_spawned")

    if not EMAIL:
        _progress("source_skip", source="unpaywall", reason="UNPAYWALL_EMAIL not set (top-level notice)")

    out_dir = Path(args.out)

    loaded = _load_dois_from_args(args)
    if isinstance(loaded, dict):
        _emit(loaded)
        sys.exit(EXIT_VALIDATION)
    dois: list[str] = loaded

    # Idempotency replay — before any network I/O.
    if args.idempotency_key:
        cached = _idem_load(out_dir, args.idempotency_key)
        if cached is not None:
            # Re-stamp meta so the replayed envelope still reports current latency / request id.
            cached_meta = cached.get("meta", {}) or {}
            cached_meta.update({
                "request_id": _request_id,
                "latency_ms": _now_ms(),
                "replayed_from_idempotency_key": args.idempotency_key,
            })
            cached["meta"] = cached_meta
            _emit(cached)
            # Exit code mirrors the cached envelope's outcome.
            if cached.get("ok") is True:
                sys.exit(EXIT_SUCCESS)
            if cached.get("ok") == "partial":
                sys.exit(_decide_exit(cached.get("data", {}).get("results", [])))
            sys.exit(EXIT_VALIDATION if cached.get("error", {}).get("code") == "validation_error" else EXIT_UNRESOLVED)

    results: list[dict] = []
    for d in dois:
        r = fetch(
            d,
            out_dir,
            dry_run=args.dry_run,
            overwrite=args.overwrite,
            timeout=args.timeout,
        )
        results.append(r)
        if _stream and _format == "json":
            _emit_ndjson({"ok": bool(r.get("success")), "data": r, "meta": _meta()})

    succeeded = sum(1 for r in results if r.get("success"))
    total = len(results)
    failed = total - succeeded

    if succeeded == total:
        ok_flag: bool | str = True
    elif succeeded == 0:
        ok_flag = False
    else:
        ok_flag = "partial"

    data = {
        "results": results,
        "summary": {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
        },
        "next": _next_hints(results, args),
    }

    sources_tried_union = sorted({s for r in results for s in r.get("sources_tried", [])})
    meta_extra = {"sources_tried": sources_tried_union}
    if not EMAIL:
        meta_extra["unpaywall_skipped"] = True

    if ok_flag is False:
        # Total failure of a single-DOI call — downgrade to an error envelope
        # when the single result has an error with a code, so agents see
        # {ok:false, error:{...}} for the simple case.
        if total == 1 and results[0].get("error"):
            err = results[0]["error"]
            envelope = _envelope_err(
                err.get("code", "internal_error"),
                err.get("message", "failed"),
                retryable=err.get("retryable", False),
                **{k: v for k, v in err.items() if k not in ("code", "message", "retryable")},
                doi=results[0]["doi"],
                sources_tried=results[0].get("sources_tried", []),
            )
            envelope["meta"].update(meta_extra)
        else:
            envelope = _envelope_ok(data, ok=False, meta_extra=meta_extra)
    else:
        envelope = _envelope_ok(data, ok=ok_flag, meta_extra=meta_extra)

    # Stream mode already emitted per-item lines; final envelope still goes out as a summary.
    if _stream and _format == "json":
        print(_dump_json({"summary": data["summary"], "meta": envelope["meta"], "next": data["next"], "ok": ok_flag}), flush=True)
    else:
        _emit(envelope)

    # Store idempotency sidecar on completion (even for partial — replay returns same shape).
    if args.idempotency_key:
        _idem_store(out_dir, args.idempotency_key, envelope)

    sys.exit(_decide_exit(results))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        _emit(_envelope_err("internal_error", str(e)))
        sys.exit(EXIT_TRANSPORT)
