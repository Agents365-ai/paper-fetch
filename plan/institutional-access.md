# Institutional Access — Design & PR Plan

**Status:** decisions finalized 2026-04-16 · PR 1 implementation in progress
**Skill:** paper-fetch

## Finalized decisions

| # | Answer |
|---|---|
| Q1 | One master switch: `PAPER_FETCH_INSTITUTIONAL=1`. Cookie/EZproxy auto-activate when their env vars are also set. |
| Q2 | Rate limits: 1 req/s · 50/hour · 500/day. Hourly cap is non-disableable. |
| Q3 | **No institutional hostname allowlist.** Instead: SSRF defense (block non-public IPs, non-http(s) schemes, non-80/443 ports, internal metadata hosts) applied in all modes. In institutional mode, hostname policy is open; in public mode, current OA allowlist still applies. |
| Q4 | SKILL.md: *"Never bypasses paywalls. Optionally uses the caller's own institutional subscription (via IP, cookies, or EZproxy) when explicitly enabled via `PAPER_FETCH_INSTITUTIONAL=1`."* |
| Q5 | Ship incrementally: PR 1 → v0.8.0, PR 2 → v0.9.0, PR 3 → v1.0.0. |

---

## 1. Goal

Let paper-fetch fetch papers that are behind a paywall *but to which the caller's institution holds a legitimate subscription*, using only channels the institution and publisher already treat as authorized:

- the caller's IP range (on-campus / institutional VPN)
- the caller's own browser session cookies
- the institution's EZproxy URL rewriter

No CAPTCHA bypass, no credential manufacturing, no Sci-Hub, no stealth automation.

## 2. Scope

### In scope
- Opt-in "institutional mode" (off by default, no surprises for existing users)
- Expanded host allowlist when institutional mode is on
- Cookie-jar injection via a Netscape `cookies.txt` file
- EZproxy URL rewriting
- Per-run rate limiting (global default + institutional default)
- New meta fields (`auth_mode`, `suggest_institutional`) so agents know what happened
- SKILL.md + schema updates

### Explicitly out of scope
- Any form of CAPTCHA solving (manual, OCR, third-party, Playwright stealth)
- Headless-browser rendering (Playwright / Chromium) — breaks zero-deps
- Credential theft from browsers (keyring scraping)
- Shibboleth / SAML login automation
- Bulk / crawling modes that would violate license "systematic downloading" clauses
- Sharing cookies or downloaded PDFs between users

## 3. Design

### 3.1 Trust boundary (Principle 2)

Everything institutional-related is **env-only**. No CLI flags. Rationale: an agent must not be able to point paper-fetch at a cookie jar that wasn't vetted by the human operator.

| Env var | Purpose | Default |
|---|---|---|
| `PAPER_FETCH_INSTITUTIONAL` | Master opt-in. Required for any of the below to take effect. | unset (off) |
| `PAPER_FETCH_COOKIE_JAR` | Path to a Netscape cookies.txt exported from the user's browser | unset |
| `PAPER_FETCH_EZPROXY_HOST` | EZproxy host, e.g. `ezproxy.my.edu` | unset |
| `PAPER_FETCH_RATE_LIMIT_PER_SEC` | Max requests per second across all sources | `1.0` (institutional), `4.0` (public) |
| `PAPER_FETCH_RATE_LIMIT_PER_HOUR` | Max downloads per hour (institutional only) | `50` |
| `PAPER_FETCH_RATE_LIMIT_PER_DAY` | Max downloads per day (institutional only) | `200` |

The last three are env-only hard ceilings — a flag to loosen them would let an agent crawl an institutional subscription and trigger a ToS-level IP ban. The operator can raise the ceiling via env, the agent can't.

### 3.2 Host policy — SSRF defense always on; allowlist only in public mode

Drop the curated institutional allowlist entirely. Hostname allowlisting was solving the wrong problem for institutional mode — the user's own subscription auth (IP / cookies) already limits what they can reach, and maintaining a perpetually-incomplete journal list is friction without security gain.

```python
import ipaddress

# Block-list of internal metadata hostnames common to cloud environments.
_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.aws.internal",
    "metadata",
}


def _is_safe_url(url: str) -> tuple[bool, str]:
    """Universal URL safety check — applied in every mode.

    Returns (ok, reason_if_not_ok). Blocks SSRF vectors regardless of
    whether the hostname passes the allowlist:
      - non-http(s) schemes (no file://, ftp://, gopher://)
      - non-80/443 ports
      - IP literals in private / loopback / link-local / reserved space
      - known cloud metadata hostnames
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "scheme_not_allowed"
    if parsed.port and parsed.port not in (80, 443):
        return False, "port_not_allowed"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "empty_host"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, "private_ip"
    except ValueError:
        pass  # hostname is a name, not a literal — fine
    if host in _METADATA_HOSTS:
        return False, "metadata_host"
    return True, ""


def _is_allowed_host(url: str) -> bool:
    ok, _ = _is_safe_url(url)
    if not ok:
        return False
    # Institutional mode: trust the user's opt-in. Any public HTTPS host OK.
    if os.environ.get("PAPER_FETCH_INSTITUTIONAL"):
        return True
    # Public mode: require hostname in the curated OA allowlist.
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return host in _allowed_hosts()
```

This also closes an existing gap: today's `_is_allowed_host` checks *only* hostname, so a response pointing at `http://192.168.1.1:8080/` via a DNS-rebound hostname in the allowlist would be downloaded. After this change, IP/scheme/port validation runs before the hostname check and applies in all modes.

### 3.3 Cookie jar

Minimal approach: build an opener once, reuse for every request.

```python
import http.cookiejar

def _build_opener() -> urllib.request.OpenerDirector:
    handlers = []
    jar_path = os.environ.get("PAPER_FETCH_COOKIE_JAR")
    if jar_path and os.environ.get("PAPER_FETCH_INSTITUTIONAL"):
        jar = http.cookiejar.MozillaCookieJar(jar_path)
        jar.load(ignore_discard=True, ignore_expires=True)
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)
```

Threaded through `_get()` / `_download()` via a module-level opener.

Failure to load the jar must:
- emit a `cookie_jar_load_failed` stderr event
- continue without cookies (not abort)
- mark `meta.auth_mode = "public"` so the agent knows institutional wasn't actually engaged

### 3.4 EZproxy URL rewriting

```python
def _ezproxy_wrap(url: str) -> str:
    host_suffix = os.environ.get("PAPER_FETCH_EZPROXY_HOST")
    if not host_suffix or not os.environ.get("PAPER_FETCH_INSTITUTIONAL"):
        return url
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return url
    # Skip rewriting for OA-always hosts — no reason to route arXiv via ezproxy
    if parsed.hostname in _OA_ALLOWED_HOSTS:
        return url
    new_host = f"{parsed.hostname.replace('.', '-')}.{host_suffix}"
    return parsed._replace(netloc=new_host).geturl()
```

Applied at download time and when building candidate URLs from S2 `openAccessPdf.url`. Never applied to the OA API calls themselves (Unpaywall / S2 / PMC APIs are public).

### 3.5 Rate limiting

Per-process token bucket. Simple — no shared-state daemon. Institutional mode persists a sidecar counter in `<out>/.paper-fetch-ratelimit.json` for the per-hour/per-day ceilings so that a single orchestrator running many invocations doesn't blow past the cap.

```python
# Pseudocode — full impl in PR
def _rate_limit_gate():
    if not _institutional: return
    _wait_token_bucket()
    _check_hourly_daily_caps_or_abort_with_rate_limited()
```

A rate-limit abort returns a structured error with `retry_after_hours`, fitting the existing contract.

### 3.6 Envelope additions

```json
{
  "meta": {
    "auth_mode": "institutional",   // "public" | "institutional" | "cookie" | "ezproxy"
    "rate_limit": { "per_sec_used": 0.6, "per_hour_used": 12, "per_hour_cap": 50 }
  }
}
```

On not_found when `PAPER_FETCH_INSTITUTIONAL` is unset:
```json
{
  "error": {
    "code": "not_found",
    ...,
    "suggest_institutional": true,
    "hint": "Set PAPER_FETCH_INSTITUTIONAL=1 if your institution has a subscription."
  }
}
```

### 3.7 Schema bumps

- `SCHEMA_VERSION` 1.3.0 → 1.4.0 (additive: new env vars, new error field, new meta fields)
- `CLI_VERSION` 0.7.0 → 0.8.0
- `build_schema()` lists the new env vars, new error code `rate_limited`, new meta fields

## 4. Implementation plan

Split into 3 PRs so each lands independently and can be rolled back on its own.

### PR 1 — IP-only institutional mode (smallest, highest value)
- Add `_is_safe_url` (SSRF defense) — applies in all modes
- Keep current OA allowlist as-is (public mode only)
- `PAPER_FETCH_INSTITUTIONAL=1` env opt-in opens hostname policy
- Global 1 req/s token bucket (active in institutional mode only)
- `meta.auth_mode` field: `"public"` | `"institutional"`
- `suggest_institutional` hint on `not_found` when mode is off
- Doc: SKILL.md section "Institutional access" + ToS warning
- Tests: SSRF blocks (private IP, non-http scheme, non-80/443 port); institutional env opens hostname; rate-limit pacing; meta.auth_mode values

**LoC:** ~100 in fetch.py, ~80 in tests

### PR 2 — Cookie jar
- `PAPER_FETCH_COOKIE_JAR` env
- Module-level opener
- `cookie_jar_load_failed` stderr event
- Tests: valid jar loads and is used on S2/publisher requests; invalid jar degrades to public with event; cookie confined to institutional mode

**LoC:** ~60 in fetch.py, ~60 in tests

### PR 3 — EZproxy + hourly/daily caps
- `PAPER_FETCH_EZPROXY_HOST` env + `_ezproxy_wrap`
- Sidecar rate-limit counter `.paper-fetch-ratelimit.json`
- Structured `rate_limited` error with `retry_after_hours`
- Tests: rewrite skips OA hosts; sidecar survives across invocations; cap hit returns rate_limited envelope

**LoC:** ~100 in fetch.py, ~80 in tests

## 5. Test plan

No live paywalled traffic — all mocked via `urllib.request.urlopen` patches, same pattern as existing `tests/test_fetch.py`.

New test classes:
- `TestInstitutionalAllowlist` — allowlist scope with env on/off
- `TestCookieJar` — valid/invalid jar, verifies Cookie header shape
- `TestEzproxy` — rewrite correctness, OA skip, preservation of path/query
- `TestRateLimit` — token bucket pacing, sidecar persistence, cap exhaustion

Smoke: CI adds a step that runs with `PAPER_FETCH_INSTITUTIONAL=1` but no cookie jar → verifies no regression, `auth_mode == "institutional"`.

## 6. Risks & open questions

### Risks
1. **Institutional ToS violation.** Many site licenses explicitly forbid "systematic downloading, whether manual or automated." The rate limit + per-hour cap mitigates but does not eliminate this. **Mitigation:** prominent warning in SKILL.md; default caps conservative; no way to disable the cap.
2. **Publisher IP ban affecting the whole institution.** A misconfigured orchestrator running paper-fetch in a loop could trigger an IP block on the entire campus. **Mitigation:** per-hour cap is the hard ceiling; cap breach returns a structured error rather than continuing to pound the server.
3. **Cookie leakage.** `cookies.txt` on disk is sensitive. **Mitigation:** docs recommend storing in user's home dir with 0600; paper-fetch never copies or logs cookie contents.
4. **EZproxy correctness.** Some EZproxy setups use path-based rewriting, not subdomain-based. **Mitigation:** start with subdomain form (most common), document the limitation, accept PRs for path form later.

### Open questions

All 5 resolved — see "Finalized decisions" at the top of this doc.
