#!/usr/bin/env python3
"""Fetch legal open-access PDFs by DOI.

Resolution order: Unpaywall -> Semantic Scholar openAccessPdf ->
arXiv -> PMC OA -> bioRxiv/medRxiv.

Exit codes:
  0  success (all DOIs resolved)
  1  runtime error (some DOIs failed, network issues)
  2  auth error (missing UNPAYWALL_EMAIL)
  3  validation error (bad arguments)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import os

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

EMAIL = os.environ.get("UNPAYWALL_EMAIL", "").strip()
UA = f"paper-fetch/0.1 (mailto:{EMAIL or 'anonymous'})"
TIMEOUT = 30

EXIT_SUCCESS = 0
EXIT_RUNTIME = 1
EXIT_AUTH = 2
EXIT_VALIDATION = 3

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_format = "json"  # set by main()


def _log(msg: str) -> None:
    """Human-readable diagnostic → stderr only."""
    print(msg, file=sys.stderr)


def _emit(obj: dict) -> None:
    """Structured output → stdout as JSON or human-readable text."""
    if _format == "json":
        print(json.dumps(obj, ensure_ascii=False))
    else:
        _emit_text(obj)


def _emit_text(obj: dict) -> None:
    """Render a result envelope as human-readable text on stdout."""
    if obj.get("ok"):
        data = obj.get("data", {})
        results = data.get("results", [data] if "doi" in data else [])
        for r in results:
            status = "dry-run" if r.get("dry_run") else ("saved" if r.get("file") else "failed")
            print(f"[{r.get('source', '?')}] {r.get('doi', '?')} → {r.get('file') or r.get('pdf_url', '?')}  ({status})")
        summary = data.get("summary")
        if summary:
            print(f"\n{summary['succeeded']}/{summary['total']} succeeded")
    else:
        err = obj.get("error", {})
        print(f"error: [{err.get('code', '?')}] {err.get('message', '?')}")


def _ok(data: dict) -> dict:
    return {"ok": True, "data": data}


def _err(code: str, message: str, *, retryable: bool = False, **ctx) -> dict:
    e = {"code": code, "message": message, "retryable": retryable}
    e.update(ctx)
    return {"ok": False, "error": e}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get(url: str, accept: str = "application/json") -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def _get_json(url: str):
    return json.loads(_get(url).decode("utf-8"))


def _download(url: str, dest: Path) -> bool:
    try:
        data = _get(url, accept="application/pdf")
    except Exception as e:
        _log(f"  download failed: {e}")
        return False
    if not data[:5].startswith(b"%PDF"):
        _log("  response was not a PDF")
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return True


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


def try_unpaywall(doi: str) -> tuple[str | None, dict]:
    url = f"https://api.unpaywall.org/v2/{urllib.parse.quote(doi)}?email={EMAIL}"
    try:
        d = _get_json(url)
    except Exception as e:
        _log(f"[unpaywall] error: {e}")
        return None, {}
    meta = {
        "title": d.get("title"),
        "year": d.get("year"),
        "author": (d.get("z_authors") or [{}])[0].get("family") if d.get("z_authors") else None,
    }
    loc = d.get("best_oa_location") or {}
    return loc.get("url_for_pdf"), meta


def try_semantic_scholar(doi: str) -> tuple[str | None, dict, dict]:
    url = (
        f"https://api.semanticscholar.org/graph/v1/paper/DOI:{urllib.parse.quote(doi)}"
        "?fields=title,year,authors,openAccessPdf,externalIds"
    )
    try:
        d = _get_json(url)
    except Exception as e:
        _log(f"[s2] error: {e}")
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


def try_biorxiv(doi: str) -> str | None:
    if not doi.startswith("10.1101/"):
        return None
    for server in ("biorxiv", "medrxiv"):
        try:
            d = _get_json(f"https://api.biorxiv.org/details/{server}/{doi}")
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


def fetch(doi: str, out_dir: Path, *, dry_run: bool = False) -> dict:
    """Resolve and optionally download a single DOI.

    Returns a structured result dict (not an envelope).
    """
    doi = doi.strip().removeprefix("https://doi.org/").removeprefix("doi.org/")
    _log(f"==> {doi}")

    pdf_url, meta = try_unpaywall(doi)
    source = "unpaywall"

    if not pdf_url:
        pdf_url, s2_meta, ext = try_semantic_scholar(doi)
        for k, v in s2_meta.items():
            if v and not meta.get(k):
                meta[k] = v
        source = "semantic_scholar"
        if not pdf_url and ext.get("ArXiv"):
            pdf_url, source = try_arxiv(ext["ArXiv"]), "arxiv"
        if not pdf_url and ext.get("PubMedCentral"):
            pdf_url, source = try_pmc(ext["PubMedCentral"]), "pmc"

    if not pdf_url:
        pdf_url = try_biorxiv(doi)
        if pdf_url:
            source = "biorxiv"

    if not pdf_url:
        _log(f"  no OA PDF found for {doi}")
        return {
            "doi": doi,
            "success": False,
            "source": None,
            "pdf_url": None,
            "file": None,
            "meta": meta or {},
            "error": {"code": "not_found", "message": "No open-access PDF found", "retryable": False},
        }

    fname = _filename(meta or {"title": doi})
    dest = out_dir / fname

    if dry_run:
        _log(f"  [dry-run] [{source}] {pdf_url} → {dest}")
        return {
            "doi": doi,
            "success": True,
            "source": source,
            "pdf_url": pdf_url,
            "file": str(dest),
            "meta": meta or {},
            "dry_run": True,
        }

    _log(f"  [{source}] {pdf_url}")
    if _download(pdf_url, dest):
        _log(f"  saved → {dest}")
        return {
            "doi": doi,
            "success": True,
            "source": source,
            "pdf_url": pdf_url,
            "file": str(dest),
            "meta": meta or {},
        }

    return {
        "doi": doi,
        "success": False,
        "source": source,
        "pdf_url": pdf_url,
        "file": None,
        "meta": meta or {},
        "error": {"code": "download_failed", "message": f"Download failed from {source}", "retryable": True},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """\
exit codes:
  0  all DOIs resolved successfully
  1  runtime error (some DOIs failed, network issues)
  2  auth error (UNPAYWALL_EMAIL not set)
  3  validation error (bad arguments)

output:
  stdout emits one JSON object per invocation (use --format text for humans).
  stderr carries human-readable progress diagnostics.

examples:
  %(prog)s 10.1038/s41586-020-2649-2
  %(prog)s 10.1038/s41586-020-2649-2 --dry-run
  %(prog)s --batch dois.txt --out ./papers --format text
"""


def main():
    global _format

    ap = argparse.ArgumentParser(
        prog="paper-fetch",
        description="Fetch legal open-access PDFs by DOI via Unpaywall, Semantic Scholar, arXiv, PMC, and bioRxiv/medRxiv.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("doi", nargs="?", help="DOI to fetch (e.g. 10.1038/s41586-020-2649-2)")
    ap.add_argument("--batch", metavar="FILE", help="file with one DOI per line for bulk download")
    ap.add_argument("--out", default="pdfs", metavar="DIR", help="output directory (default: pdfs)")
    ap.add_argument("--dry-run", action="store_true", help="resolve sources without downloading; preview the PDF URL and filename")
    ap.add_argument("--format", choices=["json", "text"], default="json", dest="fmt", help="output format (default: json). json for agents, text for humans")
    args = ap.parse_args()

    _format = args.fmt

    if not EMAIL:
        _emit(_err("auth_missing", "Set UNPAYWALL_EMAIL env var to your contact email", retryable=False, retry_after_auth=True))
        sys.exit(EXIT_AUTH)

    out_dir = Path(args.out)
    dois: list[str] = []
    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            _emit(_err("validation_error", f"Batch file not found: {args.batch}", retryable=False, field="batch"))
            sys.exit(EXIT_VALIDATION)
        dois = [l.strip() for l in batch_path.read_text().splitlines() if l.strip()]
    elif args.doi:
        dois = [args.doi]
    else:
        _emit(_err("validation_error", "Provide a DOI or --batch file", retryable=False))
        sys.exit(EXIT_VALIDATION)

    if not dois:
        _emit(_err("validation_error", "No DOIs found in input", retryable=False))
        sys.exit(EXIT_VALIDATION)

    results = [fetch(d, out_dir, dry_run=args.dry_run) for d in dois]
    succeeded = sum(1 for r in results if r["success"])
    total = len(results)

    output = _ok({
        "results": results,
        "summary": {
            "total": total,
            "succeeded": succeeded,
            "failed": total - succeeded,
        },
    })

    _emit(output)
    sys.exit(EXIT_SUCCESS if succeeded == total else EXIT_RUNTIME)


if __name__ == "__main__":
    main()
