---
name: paper-fetch
description: Use when the user wants to download a paper PDF from a DOI, title, or URL via legal open-access sources. Tries Unpaywall, arXiv, bioRxiv/medRxiv, PubMed Central, and Semantic Scholar in order. Never uses Sci-Hub or paywall bypass.
homepage: https://github.com/Agents365-ai/paper-fetch
metadata: {"openclaw":{"requires":{"bins":["python3"]},"emoji":"📄"},"pimo":{"category":"research","tags":["paper","pdf","doi","open-access","download"]}}
---

# paper-fetch

Fetch the legal open-access PDF for a paper given a DOI (or title). Tries multiple OA sources in priority order and stops at the first hit.

**Agent-native.** Structured JSON envelope on stdout, NDJSON progress on stderr, stable exit codes, machine-readable schema, TTY-aware format default, idempotent retries.

## Resolution order

1. **Unpaywall** — `https://api.unpaywall.org/v2/{doi}?email=$UNPAYWALL_EMAIL`, read `best_oa_location.url_for_pdf` (skipped if `UNPAYWALL_EMAIL` not set)
2. **Semantic Scholar** — `https://api.semanticscholar.org/graph/v1/paper/DOI:{doi}?fields=openAccessPdf,externalIds`
3. **arXiv** — if `externalIds.ArXiv` present, `https://arxiv.org/pdf/{arxiv_id}.pdf`
4. **PubMed Central OA** — if PMCID present, `https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid}/pdf/`
5. **bioRxiv / medRxiv** — if DOI prefix is `10.1101`, query `https://api.biorxiv.org/details/{server}/{doi}` for the latest version PDF URL
6. Otherwise → report failure with title/authors so the user can request via ILL

If only a title is given, resolve to a DOI first via Semantic Scholar `search_paper_by_title` (asta MCP) or Crossref.

## Usage

```bash
python scripts/fetch.py <DOI> [options]
python scripts/fetch.py --batch <FILE|-> [options]
python scripts/fetch.py schema           # machine-readable self-description
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `doi` | — | DOI to fetch (positional). Use `-` to read a single DOI from stdin |
| `--batch FILE` | — | File with one DOI per line for bulk download. Use `-` to read from stdin |
| `--out DIR` | `pdfs` | Output directory |
| `--dry-run` | off | Resolve sources without downloading; preview PDF URL and destination |
| `--format` | auto | `json` for agents, `text` for humans. Auto-detects: `json` when stdout is not a TTY, `text` when it is |
| `--pretty` | off | Pretty-print JSON with 2-space indent |
| `--stream` | off | Emit one NDJSON per line on stdout as each DOI resolves, then a summary line (batch mode) |
| `--overwrite` | off | Re-download even when destination file already exists |
| `--idempotency-key KEY` | — | Safe-retry key. Re-running with the same key replays the original envelope from `<out>/.paper-fetch-idem/` without network I/O |
| `--timeout SECONDS` | `30` | HTTP timeout per request |
| `--version` | — | Print CLI + schema version and exit |

### Agent discovery: `schema` subcommand

```bash
python scripts/fetch.py schema
```

Emits a complete machine-readable description of the CLI on stdout (no network). Includes `cli_version`, `schema_version`, parameter types, exit codes, error codes, envelope shapes, and environment variables. Agents should read this once, cache it against `schema_version`, and re-read when the cached version drifts.

### Output contract

**stdout** emits a single JSON envelope. Every envelope carries a `meta` slot.

**Success** (all DOIs resolved):

```json
{
  "ok": true,
  "data": {
    "results": [
      {
        "doi": "10.1038/s41586-021-03819-2",
        "success": true,
        "source": "unpaywall",
        "pdf_url": "https://www.nature.com/articles/s41586-021-03819-2.pdf",
        "file": "pdfs/Jumper_2021_Highly_accurate_protein_structure_predic.pdf",
        "meta": {"title": "Highly accurate protein structure prediction with AlphaFold", "year": 2021, "author": "Jumper"},
        "sources_tried": ["unpaywall"]
      }
    ],
    "summary": {"total": 1, "succeeded": 1, "failed": 0},
    "next": []
  },
  "meta": {
    "request_id": "req_a908f5156fc1",
    "latency_ms": 2036,
    "schema_version": "1.1.0",
    "cli_version": "0.3.0",
    "sources_tried": ["unpaywall"]
  }
}
```

**Partial** (batch mode — some DOIs failed, exit code reflects the failure class):

```json
{
  "ok": "partial",
  "data": {
    "results": [
      { "doi": "10.1038/s41586-021-03819-2", "success": true, "source": "unpaywall", ... },
      {
        "doi": "10.1234/nonexistent",
        "success": false,
        "source": null,
        "pdf_url": null,
        "file": null,
        "meta": {},
        "sources_tried": ["unpaywall", "semantic_scholar"],
        "error": {
          "code": "not_found",
          "message": "No open-access PDF found",
          "retryable": true,
          "retry_after_hours": 168,
          "reason": "OA availability changes over time; retry after embargo lifts or preprint appears"
        }
      }
    ],
    "summary": {"total": 2, "succeeded": 1, "failed": 1},
    "next": ["paper-fetch 10.1234/nonexistent --out pdfs"]
  },
  "meta": { ... }
}
```

The `next` slot is an array of suggested follow-up commands: re-invoking them retries only the failed subset. Combine with `--idempotency-key` to make the whole batch safely retriable without re-downloading the already-succeeded items.

**Failure** (bad arguments, exit code 3):

```json
{
  "ok": false,
  "error": {
    "code": "validation_error",
    "message": "Provide a DOI or --batch file",
    "retryable": false
  },
  "meta": { ... }
}
```

**Per-item skipped** (destination already exists, no `--overwrite`):

```json
{
  "doi": "10.1038/s41586-021-03819-2",
  "success": true,
  "source": "unpaywall",
  "pdf_url": "https://...",
  "file": "pdfs/Jumper_2021_...pdf",
  "skipped": true,
  "skip_reason": "file_exists",
  "sources_tried": ["unpaywall"]
}
```

**Idempotency replay** (re-run with the same `--idempotency-key`):

The cached envelope is returned verbatim, but `meta.request_id` and `meta.latency_ms` are re-stamped for the current call, and `meta.replayed_from_idempotency_key` is set. No network I/O occurs.

### Stderr progress (NDJSON)

When `--format json`, stderr emits one JSON object per line for liveness:

```
{"event": "start",       "request_id": "req_...", "elapsed_ms": 2,    "doi": "10.1038/..."}
{"event": "source_try",  "request_id": "req_...", "elapsed_ms": 2,    "doi": "...", "source": "unpaywall"}
{"event": "source_hit",  "request_id": "req_...", "elapsed_ms": 2036, "doi": "...", "source": "unpaywall", "pdf_url": "..."}
{"event": "download_ok", "request_id": "req_...", "elapsed_ms": 4120, "doi": "...", "file": "..."}
```

Event types: `start`, `source_try`, `source_hit`, `source_miss`, `source_skip`, `source_enrich`, `source_enrich_failed`, `download_ok`, `download_error`, `download_skip`, `dry_run`, `not_found`, `update_check_spawned`. All events share `request_id` and `elapsed_ms`, letting an orchestrator correlate progress across stderr and the final stdout envelope.

`source_enrich` fires when Semantic Scholar is called purely to backfill missing `author` / `title` after another source already provided the PDF URL; its `fields` array lists exactly which fields were filled in. `source_enrich_failed` fires when that enrichment call fails — the Unpaywall PDF URL is still used and the filename falls back to `unknown_<year>_…`.

When `--format text`, stderr emits human-readable prose.

### Exit codes

| Code | Meaning | Retryable class |
|------|---------|-----------------|
| `0` | All DOIs resolved / previewed | — |
| `1` | Unresolved — one or more DOIs had no OA copy; no transport failure | Not now (retry after `retry_after_hours`) |
| `2` | Reserved for auth errors (currently unused) | — |
| `3` | Validation error (bad arguments, missing input) | No |
| `4` | Transport error (network / download / IO failure) | Yes |

The taxonomy lets an orchestrator route failures deterministically: exit 4 is worth retrying immediately, exit 1 is not, exit 3 is a bug in the caller.

### Error codes in JSON

| Code | Meaning | Retryable |
|------|---------|-----------|
| `validation_error` | Bad arguments or empty input | No |
| `not_found` | No open-access PDF found | Yes (retry after `retry_after_hours: 168`) |
| `download_network_error` | Network failure during download | Yes |
| `download_not_a_pdf` | Response was not a PDF (HTML landing page) | No |
| `download_host_not_allowed` | PDF URL host not in allowlist | No |
| `download_size_exceeded` | Response exceeded 50 MB limit | Yes |
| `download_io_error` | Local filesystem write failed | Yes |
| `internal_error` | Unexpected error | No |

### Examples

```bash
# Single DOI (JSON output when piped; text when in a terminal)
python scripts/fetch.py 10.1038/s41586-020-2649-2

# Dry-run preview (resolve without downloading)
python scripts/fetch.py 10.1038/s41586-020-2649-2 --dry-run

# Force JSON (for agents even inside a terminal)
python scripts/fetch.py 10.1038/s41586-020-2649-2 --format json

# Human-readable with pretty colors in a pipeline
python scripts/fetch.py 10.1038/s41586-020-2649-2 --format text

# Batch download, safely retriable
python scripts/fetch.py --batch dois.txt --out ./papers \
    --idempotency-key monday-review-batch

# Pipe DOIs from another tool
zot -F ids.json query ... | jq -r '.[].doi' | python scripts/fetch.py --batch -

# Agent discovery
python scripts/fetch.py schema --pretty

# Streaming mode — one result per line as each DOI resolves
python scripts/fetch.py --batch dois.txt --stream

# Works without UNPAYWALL_EMAIL (skips Unpaywall, uses remaining 4 sources)
python scripts/fetch.py 10.1038/s41586-020-2649-2
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `UNPAYWALL_EMAIL` | unset | Contact email for Unpaywall API. Optional but recommended. Without it, Unpaywall is skipped (remaining 4 sources still work). |
| `PAPER_FETCH_ALLOWED_HOSTS` | unset | Comma-separated extra hostnames to extend the download allowlist |
| `PAPER_FETCH_NO_AUTO_UPDATE` | unset | Set to any value to disable silent background self-update |
| `PAPER_FETCH_UPDATE_INTERVAL` | `86400` | Cooldown in seconds between update checks |

## Notes

- **Auth is delegated.** The agent never runs a login subcommand. The human or the orchestrator sets `UNPAYWALL_EMAIL` in the environment; the agent inherits it. Missing email degrades gracefully to the remaining 4 sources.
- **Trust is directional.** CLI arguments are validated once at the entry point. The host allowlist and 50 MB size cap are enforced in the environment layer, not at the agent's request. An agent cannot loosen safety by passing a flag — only by the operator setting `PAPER_FETCH_ALLOWED_HOSTS`.
- **Downloads are naturally idempotent.** Re-running against the same `--out` skips files that already exist (deterministic filename: `{first_author}_{year}_{short_title}.pdf`). Pair with `--idempotency-key` to also replay the exact envelope without any network I/O.
- **Never attempts to bypass paywalls.** If no OA copy exists, the skill reports failure honestly — do not suggest Sci-Hub or similar.
- **Default output directory:** `./pdfs/`.

## Auto-update

When installed via `git clone`, the skill keeps itself in sync with upstream automatically. On each invocation, `fetch.py` spawns a **detached background `git pull --ff-only`** in the skill directory:

- **Non-blocking** — the current invocation is not delayed; the pull runs in a new session and is fully detached
- **Silent** — all git output goes to `/dev/null`, the stdout envelope is never polluted
- **Throttled** — at most once every 24 hours (stamped via `.git/.paper-fetch-last-update`)
- **Safe** — `--ff-only` refuses to merge if you have local edits; conflicts never happen
- **Observable** — when a pull is spawned, stderr emits `{"event": "update_check_spawned", ...}` (JSON mode) or a prose notice (text mode)
- **Convergence** — updates apply on the **next** invocation, not the current one (because the pull is backgrounded)

Force an immediate check with `rm <skill_dir>/.git/.paper-fetch-last-update`.
