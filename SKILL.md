---
name: paper-fetch
description: Use when the user wants to download a paper PDF from a DOI, title, or URL via legal open-access sources. Tries Unpaywall, arXiv, bioRxiv/medRxiv, PubMed Central, and Semantic Scholar in order. Never uses Sci-Hub or paywall bypass.
homepage: https://github.com/Agents365-ai/paper-fetch
metadata: {"openclaw":{"requires":{"bins":["python3"]},"emoji":"📄"},"pimo":{"category":"research","tags":["paper","pdf","doi","open-access","download"]}}
---

# paper-fetch

Fetch the legal open-access PDF for a paper given a DOI (or title). Tries multiple OA sources in priority order and stops at the first hit.

## Resolution order

1. **Unpaywall** — `https://api.unpaywall.org/v2/{doi}?email=$UNPAYWALL_EMAIL`, read `best_oa_location.url_for_pdf` (skipped if `UNPAYWALL_EMAIL` not set)
2. **Semantic Scholar** — `https://api.semanticscholar.org/graph/v1/paper/DOI:{doi}?fields=openAccessPdf,externalIds`
3. **arXiv** — if `externalIds.ArXiv` present, `https://arxiv.org/pdf/{arxiv_id}.pdf`
4. **PubMed Central OA** — if PMCID present, `https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid}/pdf/`
5. **bioRxiv / medRxiv** — if DOI prefix is `10.1101`, use the `claude_ai_bioRxiv` MCP `get_preprint` tool, then fetch the PDF URL
6. Otherwise → report failure with title/authors so the user can request via ILL

If only a title is given, resolve to a DOI first via Semantic Scholar `search_paper_by_title` (asta MCP) or Crossref.

## Usage

```bash
python scripts/fetch.py <DOI> [--out DIR] [--dry-run] [--format json|text]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `doi` | — | DOI to fetch (positional, e.g. `10.1038/s41586-020-2649-2`) |
| `--batch FILE` | — | File with one DOI per line for bulk download |
| `--out DIR` | `pdfs` | Output directory |
| `--dry-run` | off | Resolve sources without downloading; preview the PDF URL and filename |
| `--format` | `json` | Output format: `json` (for agents) or `text` (for humans) |

### Output contract

**stdout** emits a single JSON object (when `--format json`):

Success (all DOIs resolved):
```json
{
  "ok": true,
  "data": {
    "results": [
      {
        "doi": "10.1038/s41586-020-2649-2",
        "success": true,
        "source": "unpaywall",
        "pdf_url": "https://...",
        "file": "pdfs/Author_2020_Title.pdf",
        "meta": {"title": "...", "year": 2020, "author": "Smith"}
      }
    ],
    "summary": {"total": 1, "succeeded": 1, "failed": 0}
  }
}
```

Partial failure (batch mode — some DOIs failed, exit code 1):
```json
{
  "ok": true,
  "data": {
    "results": [
      {
        "doi": "10.1038/s41586-020-2649-2",
        "success": true,
        "source": "semantic_scholar",
        "pdf_url": "https://...",
        "file": "pdfs/Harris_2020_Array_programming_with_NumPy.pdf",
        "meta": {"title": "Array programming with NumPy", "year": 2020, "author": "Charles R. Harris"}
      },
      {
        "doi": "10.1234/nonexistent",
        "success": false,
        "source": null,
        "pdf_url": null,
        "file": null,
        "meta": {},
        "error": {"code": "not_found", "message": "No open-access PDF found", "retryable": false}
      }
    ],
    "summary": {"total": 2, "succeeded": 1, "failed": 1}
  }
}
```

Top-level failure (bad arguments, exit code 3):
```json
{
  "ok": false,
  "error": {
    "code": "validation_error",
    "message": "Provide a DOI or --batch file",
    "retryable": false
  }
}
```

**stderr** carries human-readable progress diagnostics (source attempts, download status).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All DOIs resolved successfully |
| `1` | Runtime error (some DOIs failed, network/download issues) |
| `3` | Validation error (bad arguments, missing input) |

### Error codes in JSON

| Code | Meaning | Retryable |
|------|---------|-----------|
| `validation_error` | Bad arguments or empty input | No |
| `not_found` | No open-access PDF found | No |
| `download_network_error` | Network failure during download | Yes |
| `download_not_a_pdf` | Response was not a PDF (HTML landing page) | No |
| `download_host_not_allowed` | PDF URL host not in allowlist | No |
| `download_size_exceeded` | Response exceeded 50 MB limit | No |
| `download_io_error` | Local filesystem write failed | No |
| `internal_error` | Unexpected error | No |

### Examples

```bash
# Single DOI (JSON output for agents)
python scripts/fetch.py 10.1038/s41586-020-2649-2

# Dry-run preview (resolve without downloading)
python scripts/fetch.py 10.1038/s41586-020-2649-2 --dry-run

# Human-readable output
python scripts/fetch.py 10.1038/s41586-020-2649-2 --format text

# Batch download
python scripts/fetch.py --batch dois.txt --out ./papers

# Works without UNPAYWALL_EMAIL (skips Unpaywall, uses remaining 4 sources)
python scripts/fetch.py 10.1038/s41586-020-2649-2
```

## Notes

- `UNPAYWALL_EMAIL` is optional but recommended. Set it once: `export UNPAYWALL_EMAIL=you@example.com` (e.g. in `~/.zshrc`). Without it, Unpaywall is skipped and the remaining 4 sources are still tried.
- Downloads are restricted to a host allowlist of known OA providers, with a 50 MB size limit per PDF.
- Never attempts to bypass paywalls. If no OA copy exists, the skill reports failure — do not suggest Sci-Hub or similar.
- Default output directory: `./pdfs/`. Filenames: `{first_author}_{year}_{short_title}.pdf`.
