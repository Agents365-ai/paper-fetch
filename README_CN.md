# paper-fetch — 合法开放获取 PDF 下载器

[English](README.md)

## 功能简介

- 根据 **DOI**（或 DOI 批量文件）从合法开放获取源下载论文 PDF
- **5 源回退链**：Unpaywall → Semantic Scholar `openAccessPdf` → arXiv → PubMed Central OA → bioRxiv/medRxiv
- **零依赖** — 纯 Python 标准库，无需 `pip install`
- **自动命名**：`{第一作者}_{年份}_{简短标题}.pdf`
- **批量模式**：`--batch` 传入 DOI 列表文件，或用 `--batch -` 从 stdin 管道读入
- **Agent 原生** — stdout 输出稳定的 JSON 信封，stderr 输出 NDJSON 进度事件，提供机器可读的 `schema` 子命令，`--format` 自动识别 TTY，通过 `--idempotency-key` 支持幂等重试，退出码分类（`0`/`1`/`3`/`4`），批量部分失败时输出带 `next` 重试提示的 `ok: "partial"` 信封
- **安全可重试** — 重复运行会跳过已下载文件；`--idempotency-key` 直接复用原信封，无任何网络 I/O
- **不使用 Sci-Hub 或任何绕过付费墙的服务** — 没有 OA 版本时会报告失败并输出元数据，便于走馆际互借
- **自动更新** — 通过 `git clone` 安装时，每次调用会后台 detach 一个 `git pull --ff-only`（24 小时内至多一次）。无需用户任何操作。禁用：`export PAPER_FETCH_NO_AUTO_UPDATE=1`。

## 学科覆盖

**本 skill 学科无关** —— 不限于生命科学或计算机，任何学科都支持。能否拿到取决于该论文是否有合法 OA 版本，而不是学科本身。

| 来源 | 学科范围 |
|---|---|
| **Unpaywall** | ✅ 全学科（覆盖 Crossref 所有 DOI —— 人文、社科、物理、化学、经济等都支持） |
| **Semantic Scholar** | ✅ 全学科（跨领域学术图谱） |
| **arXiv** | 物理、数学、CS、统计、定量金融、经济学、电气工程 |
| **PubMed Central** | 仅生物医学 |
| **bioRxiv / medRxiv** | 仅生物/医学预印本 |

实际使用中，**仅 Unpaywall + Semantic Scholar 两个源就足以覆盖化学、材料、经济、心理学、人文社科等任何领域的 OA 论文** —— 它们会自动命中机构知识库、SSRN、RePEc 以及出版商自托管的 OA 版本。arXiv/PMC/bioRxiv 只是针对各自领域的额外回退。若论文确实没有任何合法 OA 版本，skill 会如实报告失败 —— 按设计**绝不**绕过付费墙，任何学科都一视同仁。

## 多平台支持

| 平台 | 状态 | 说明 |
|------|------|------|
| **Claude Code** | ✅ 完全支持 | 原生 SKILL.md |
| **OpenClaw / ClawHub** | ✅ 完全支持 | `metadata.openclaw` 命名空间 |
| **Hermes Agent** | ✅ 完全支持 | 安装到 research 分类 |
| **[pi-mono](https://github.com/badlogic/pi-mono)** | ✅ 完全支持 | `metadata.pimo` 命名空间 |
| **OpenAI Codex** | ✅ 完全支持 | `agents/openai.yaml` sidecar |
| **SkillsMP** | ✅ 已索引 | GitHub topics 已配置 |

## 对比

### vs 原生 agent（无 skill）

| 功能 | 原生 agent | 本 skill |
|------|----------|----------|
| DOI → PDF | 临时网络搜索 | 确定性 5 源链 |
| Unpaywall 集成 | 无 | 有，覆盖率最高 |
| arXiv / PMC / bioRxiv 回退 | 手动 | 自动 |
| 批量下载 | 无 | `--batch dois.txt` 或 `--batch -`（stdin） |
| 一致的文件命名 | 无 | `author_year_title.pdf` |
| 机器可读 schema | 无 | `fetch.py schema` |
| 结构化输出 | 无 | 稳定 JSON 信封 + stderr NDJSON 进度 |
| 幂等重试 | 无 | `--idempotency-key` 复用原信封 |
| 退出码分类 | 无 | `0`/`1`/`3`/`4` — orchestrator 可按类路由失败 |
| 合法来源保证 | 无 | 硬性拒绝付费墙绕过 |
| 依赖 | 各异 | 仅 Python 标准库 |

## 环境要求

- **Python 3.8+**（仅标准库）
- **Unpaywall 联系邮箱**（可选但推荐）：

```bash
export UNPAYWALL_EMAIL=you@example.com
```

加入 `~/.zshrc` / `~/.bashrc` 持久化。未设置时 Unpaywall 会被跳过，其余 4 个来源（Semantic Scholar、arXiv、PMC、bioRxiv/medRxiv）仍然可用。

## 安装

### Claude Code

```bash
# 全局安装
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.claude/skills/paper-fetch

# 项目级
git clone https://github.com/Agents365-ai/paper-fetch.git .claude/skills/paper-fetch
```

### OpenClaw / ClawHub

```bash
clawhub install paper-fetch

# 或手动
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.openclaw/skills/paper-fetch
```

### Hermes Agent

```bash
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.hermes/skills/research/paper-fetch
```

或在 `~/.hermes/config.yaml` 中配置：

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
git clone https://github.com/Agents365-ai/paper-fetch.git ~/.agents/skills/paper-fetch
```

### SkillsMP

```bash
skills install paper-fetch
```

### 安装路径一览

| 平台 | 全局路径 | 项目路径 |
|------|---------|---------|
| Claude Code | `~/.claude/skills/paper-fetch/` | `.claude/skills/paper-fetch/` |
| OpenClaw | `~/.openclaw/skills/paper-fetch/` | `skills/paper-fetch/` |
| Hermes Agent | `~/.hermes/skills/research/paper-fetch/` | 通过 `external_dirs` |
| pi-mono | `~/.pimo/skills/paper-fetch/` | — |
| OpenAI Codex | `~/.agents/skills/paper-fetch/` | `.agents/skills/paper-fetch/` |
| SkillsMP | CLI 安装 | 无 |

## 使用

单个 DOI：

```bash
python scripts/fetch.py 10.1038/s41586-021-03819-2
```

指定输出目录：

```bash
python scripts/fetch.py 10.1038/s41586-021-03819-2 --out ~/papers
```

批量模式：

```bash
python scripts/fetch.py --batch dois.txt --out ~/papers
```

预览模式（不下载）：

```bash
python scripts/fetch.py 10.1038/s41586-020-2649-2 --dry-run
```

人类可读文本输出：

```bash
python scripts/fetch.py 10.1038/s41586-020-2649-2 --format text
```

从管道读入 DOI：

```bash
echo 10.1038/s41586-021-03819-2 | python scripts/fetch.py --batch -
```

可安全重试的批量下载（重试时直接复用原信封）：

```bash
python scripts/fetch.py --batch dois.txt --out ~/papers \
    --idempotency-key monday-review-batch
```

机器可读自描述（供 agent 使用）：

```bash
python scripts/fetch.py schema --pretty
```

流式 NDJSON（每个 DOI 解析后立即输出一行结果）：

```bash
python scripts/fetch.py --batch dois.txt --stream
```

或者直接对 agent 说：

> 帮我把 AlphaFold2 那篇论文下到 `~/papers`

> 帮我下载这个 DOI 的 PDF：10.1038/s41586-020-2649-2

> 下载这三篇论文：10.1038/s41586-021-03819-2, 10.1126/science.abj8754, 10.1101/2023.01.01.522400

> 看看这篇论文有没有开放获取的 PDF：10.1038/s41586-020-2649-2

> 把 dois.txt 里的所有 DOI 批量下载到 ~/papers

## 解析顺序

1. **Unpaywall** — 全出版社 OA 最佳位置（命中率最高）
2. **Semantic Scholar** — `openAccessPdf` 字段 + `externalIds`
3. **arXiv** — 论文有 arXiv ID 时
4. **PubMed Central OA 子集** — 论文有 PMCID 时
5. **bioRxiv / medRxiv** — DOI 前缀为 `10.1101/`
6. 都失败 → 输出元数据提示走馆际互借

## 文件说明

- `SKILL.md` — **唯一必需文件**，所有平台都加载它
- `scripts/fetch.py` — 下载器（纯标准库）
- `agents/openai.yaml` — Codex 配置
- `README.md` / `README_CN.md` — 文档

## 已知限制

- **覆盖率取决于 OA 可用性** — 没有合法 OA 版本的论文本 skill 无法获取，这是刻意设计
- **部分出版社重定向**返回 HTML 落地页而非 PDF，脚本会校验 `%PDF` 头并优雅失败
- **不支持机构代理**（EZproxy / OpenAthens）
- **域名白名单** — 下载限制在已知 OA 提供商域名内，未列出的主机会被拦截
- **50 MB 大小限制** — 单个 PDF 下载上限，防止异常大文件

## 许可

MIT

## 支持

如果这个 skill 对你有帮助，欢迎支持作者：

<table>
  <tr>
    <td align="center">
      <img src="https://raw.githubusercontent.com/Agents365-ai/images_payment/main/qrcode/wechat-pay.png" width="180" alt="WeChat Pay">
      <br>
      <b>微信支付</b>
    </td>
    <td align="center">
      <img src="https://raw.githubusercontent.com/Agents365-ai/images_payment/main/qrcode/alipay.png" width="180" alt="Alipay">
      <br>
      <b>支付宝</b>
    </td>
    <td align="center">
      <img src="https://raw.githubusercontent.com/Agents365-ai/images_payment/main/qrcode/buymeacoffee.png" width="180" alt="Buy Me a Coffee">
      <br>
      <b>Buy Me a Coffee</b>
    </td>
  </tr>
</table>

## 作者

**Agents365-ai**

- Bilibili: https://space.bilibili.com/441831884
- GitHub: https://github.com/Agents365-ai
