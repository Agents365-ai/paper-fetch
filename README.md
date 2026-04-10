# paper-fetch — Legal Open-Access PDF Downloader

[中文文档](README_CN.md)

## What it does

- Downloads paper PDFs from a **DOI** (or batch file of DOIs) via legal open-access sources
- **5-source fallback chain**: Unpaywall → Semantic Scholar `openAccessPdf` → arXiv → PubMed Central OA → bioRxiv/medRxiv
- **Zero dependencies** — pure Python standard library, no `pip install` needed
- **Auto-named output** — `{first_author}_{year}_{short_title}.pdf`
- **Batch mode** — pass a file of DOIs with `--batch`
- **Never touches Sci-Hub or any paywall-bypass service** — if no OA copy exists, reports failure with metadata so you can go through ILL

## Multi-Platform Support

Works with all major AI coding agents that support the Agent Skills format:

| Platform | Status | Details |
|----------|--------|---------|
| **Claude Code** | ✅ Full support | Native SKILL.md format |
| **OpenClaw / ClawHub** | ✅ Full support | `metadata.openclaw` namespace |
| **Hermes Agent** | ✅ Full support | Installable under research category |
| **[pi-mono](https://github.com/badlogic/pi-mono)** | ✅ Full support | `metadata.pimo` namespace |
| **OpenAI Codex** | ✅ Full support | `agents/openai.yaml` sidecar |
| **SkillsMP** | ✅ Indexed | GitHub topics configured |

## Comparison

### vs No Skill (native agent)

| Feature | Native agent | This skill |
|---------|-------------|------------|
| Resolve DOI to PDF | Ad-hoc web search | Deterministic 5-source chain |
| Unpaywall integration | No | Yes — highest OA coverage |
| arXiv / PMC / bioRxiv fallback | Manual | Automatic |
| Batch download | No | Yes — `--batch dois.txt` |
| Consistent filenames | No | Yes — `author_year_title.pdf` |
| Legal-only guarantee | None | Hard refuses paywall bypass |
| Dependencies | Varies | Python stdlib only |

## Prerequisites

- **Python 3.8+** (standard library only, no extra packages)
- **Unpaywall contact email** — set once as an environment variable:

```bash
export UNPAYWALL_EMAIL=you@example.com
```

Add it to `~/.zshrc` / `~/.bashrc` to persist. Unpaywall is free, has no account system, and only uses the email to contact you if your requests cause issues.

## Skill Installation

### Claude Code

```bash
# Global install
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.claude/skills/paper-fetch

# Project-level install
git clone https://github.com/Agents365-ai/paper-fetch.git .claude/skills/paper-fetch
```

### OpenClaw / ClawHub

```bash
clawhub install paper-fetch

# Or manual
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.openclaw/skills/paper-fetch
```

### Hermes Agent

```bash
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.hermes/skills/research/paper-fetch
```

Or add to `~/.hermes/config.yaml`:

```yaml
skills:
  external_dirs:
    - ~/myskills/paper-fetch
```

### pi-mono

```bash
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.pimo/skills/paper-fetch
```

### OpenAI Codex

```bash
# User-level
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.agents/skills/paper-fetch

# Project-level
git clone https://github.com/Agents365-ai/paper-fetch.git .agents/skills/paper-fetch
```

### SkillsMP

```bash
skills install paper-fetch
```

### Installation paths summary

| Platform | Global path | Project path |
|----------|-------------|--------------|
| Claude Code | `~/.claude/skills/paper-fetch/` | `.claude/skills/paper-fetch/` |
| OpenClaw | `~/.openclaw/skills/paper-fetch/` | `skills/paper-fetch/` |
| Hermes Agent | `~/.hermes/skills/research/paper-fetch/` | Via `external_dirs` |
| pi-mono | `~/.pimo/skills/paper-fetch/` | — |
| OpenAI Codex | `~/.agents/skills/paper-fetch/` | `.agents/skills/paper-fetch/` |
| SkillsMP | N/A (installed via CLI) | N/A |

## Usage

Single DOI:

```bash
python scripts/fetch.py 10.1038/s41586-021-03819-2
```

Custom output directory:

```bash
python scripts/fetch.py 10.1038/s41586-021-03819-2 --out ~/papers
```

Batch mode:

```bash
cat > dois.txt <<EOF
10.1038/s41586-021-03819-2
10.1126/science.abj8754
10.1101/2023.01.01.522400
EOF

python scripts/fetch.py --batch dois.txt --out ~/papers
```

Or just ask your agent naturally:

> Download the AlphaFold2 paper PDF to my `~/papers` folder

> Fetch the PDF for DOI 10.1038/s41586-020-2649-2

> Download these three papers: 10.1038/s41586-021-03819-2, 10.1126/science.abj8754, 10.1101/2023.01.01.522400

> Check if this paper has an open-access PDF available: 10.1038/s41586-020-2649-2

> Batch download all DOIs from my dois.txt file into ~/papers

## Resolution Order

1. **Unpaywall** — best OA location across all publishers (highest hit rate)
2. **Semantic Scholar** — `openAccessPdf` field + `externalIds` lookup
3. **arXiv** — if the paper has an arXiv ID
4. **PubMed Central OA subset** — if the paper has a PMCID
5. **bioRxiv / medRxiv** — DOI prefix `10.1101/`
6. Otherwise → report failure with metadata (title/authors) for ILL

## Files

- `SKILL.md` — **the only required file**. Loaded by all platforms.
- `scripts/fetch.py` — the downloader (pure stdlib Python)
- `agents/openai.yaml` — OpenAI Codex sidecar configuration
- `README.md` — this file
- `README_CN.md` — Chinese documentation

## Known Limitations

- **Coverage depends on OA availability** — if a paper has no legal OA copy, this skill cannot get it. That is a feature, not a bug.
- **Unpaywall email required** — the script exits with an error if `UNPAYWALL_EMAIL` is not set
- **Some publisher redirects** return an HTML landing page instead of a PDF; the script validates the `%PDF` header and fails cleanly in that case
- **No authentication** — institutional proxies (EZproxy / OpenAthens) are not supported in this version

## License

MIT

## Support

If this skill helps your work, consider supporting the author:

<table>
  <tr>
    <td align="center">
      <img src="https://raw.githubusercontent.com/Agents365-ai/images_payment/main/qrcode/wechat-pay.png" width="180" alt="WeChat Pay">
      <br>
      <b>WeChat Pay</b>
    </td>
    <td align="center">
      <img src="https://raw.githubusercontent.com/Agents365-ai/images_payment/main/qrcode/alipay.png" width="180" alt="Alipay">
      <br>
      <b>Alipay</b>
    </td>
    <td align="center">
      <img src="https://raw.githubusercontent.com/Agents365-ai/images_payment/main/qrcode/buymeacoffee.png" width="180" alt="Buy Me a Coffee">
      <br>
      <b>Buy Me a Coffee</b>
    </td>
  </tr>
</table>

## Author

**Agents365-ai**

- Bilibili: https://space.bilibili.com/441831884
- GitHub: https://github.com/Agents365-ai
