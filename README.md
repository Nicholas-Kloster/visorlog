[![Claude Code Friendly](https://img.shields.io/badge/Claude_Code-Friendly-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)

# VisorLog

**Centralized findings ledger for the NuClide OSINT ecosystem.**

ECS-normalized, lifecycle-tracked, append-only SQLite store. All NuClide tools (VisorGoose, aimap, ollama-recon) write events here. Every finding moves through a defined lifecycle: `open → disclosed → acknowledged → remediated → verified`.

Inspired by the discipline of [CISA's Logging Made Easy](https://github.com/cisagov/LME) — repurposed for AI infrastructure OSINT tracking.

---

## Use with Claude Code

Claude Code can query VisorLog, triage findings, and generate disclosure artifacts directly from the database.

```
Run `visorlog query --severity critical --status open` and triage the results. For each finding, identify whether it falls under a responsible disclosure safe harbor, draft a one-paragraph impact statement, and suggest the correct disclosure channel.
```

```
I have a visorlog.db with 168 nodes. Run `visorlog stats` and `visorlog alert`. For any stale-critical findings (open > 7 days), draft escalation notes and identify the correct CERT contact for each org_country.
```

---

## Why

The NuClide ecosystem generates findings across multiple tools and sectors. Without a shared store:
- Findings live in fragmented per-sector JSON state files
- Disclosure status tracked manually in SESSION.md
- No unified view across government / university / healthcare findings
- No alert when a CRITICAL finding sits open for a week

VisorLog fixes all of that.

---

## Install

```bash
go install github.com/Nicholas-Kloster/visorlog@latest
```

---

## Commands

### Ingest findings from existing tools
```bash
# From VisorGoose state
visorlog ingest --from visorgoose-state.json --format visorgoose

# From ollama-recon.py state
visorlog ingest --from ollama-gov-state.json --format ollama-recon

# Stream from VisorGoose scan
visorgoose scan | visorlog ingest

# NDJSON (universal)
visorlog ingest --from findings.ndjson
```

### Status overview
```bash
visorlog status
```
```
=== OPEN FINDINGS ===
  critical   ██ 2
  medium     ██ 2

=== BY SECTOR / SEVERITY / STATUS ===
SECTOR           SEVERITY    STATUS        COUNT
government       critical    open          2
government       medium      open          1
```

### Query
```bash
visorlog query --tag TAKEOVER --status open
visorlog query --sector government --severity critical
visorlog query --country ID --json

# Multi-tag OR filter (any-match across tags)
visorlog query --tags SUB2API,SETUP-OPEN

# Date-range filter (YYYY-MM-DD or RFC3339)
visorlog query --since 2026-05-19 --until 2026-05-19T23:59:59Z

# Output formats: table (default), json, csv, md
visorlog query --tags SUB2API --format csv  > findings.csv
visorlog query --tags SUB2API --format md   > findings-table.md
```

Query flags:

| Flag | What it filters |
|---|---|
| `--sector` | sector (government, university, healthcare, commercial) |
| `--severity` | critical / high / medium / low / info |
| `--status` | lifecycle stage (open, disclosed, acknowledged, remediated, verified) |
| `--tag <X>` | single tag substring (legacy, kept for backwards compat) |
| `--tags X,Y,Z` | multi-tag OR (any-match) |
| `--country` | ISO 3166 alpha-2 |
| `--source` | which tool discovered it |
| `--tld` | top-level domain match |
| `--since YYYY-MM-DD` | events with timestamp >= this |
| `--until YYYY-MM-DD` | events with timestamp <= this |
| `--limit N` | max results (default 100) |
| `--format <fmt>` | table \| json \| csv \| md |
| `--json` | shortcut for `--format json` |

### Update lifecycle status
```bash
visorlog update 4 --status disclosed --note "emailed kominfo@jatengprov.go.id"
visorlog update 4 --status acknowledged
visorlog update 4 --status remediated
```

### Alert rules
```bash
visorlog alert
```
```
[new-takeover] TAKEOVER open: 103.107.245.11 (sijoli-11-245-107.jatengprov.go.id) [government]
[stale-critical] STALE critical: 16.64.116.67 open for >7 days — disclose?
```

Built-in rules: `new-takeover`, `new-critical`, `stale-critical` (>7d), `stale-high` (>14d)

### Add a finding manually
```bash
visorlog add --ip 103.107.245.11 \
  --hostname sijoli-11-245-107.jatengprov.go.id \
  --org "Dinas Kominfo Jawa Tengah" \
  --country ID --sector government --tld .go.id \
  --severity critical --tags TAKEOVER,CLOUD,RAG \
  --source manual
```

### Generate report
```bash
visorlog report --out open-findings.md
visorlog report --status "" --out all-findings.md
```

---

## Lifecycle Stages

```
open → disclosed → acknowledged → remediated → verified → archived
```

Every status transition is timestamped and appended as a note. Records are never mutated — the full history is preserved.

---

## Schema (ECS-inspired)

| Field | Description |
|-------|-------------|
| `event.category` | `discovery`, `disclosure`, `remediation`, `regression` |
| `event.severity` | `critical`, `high`, `medium`, `low`, `info` |
| `host.ip` / `host.hostname` | Target identity |
| `org.name` / `org.country` | Organization |
| `nuclide.sector` | `government`, `university`, `healthcare`, `commercial`, `isp` |
| `nuclide.tags` | `TAKEOVER`, `CVE-2025-63389`, `CLOUD`, `RAG`, `DISTILLED` |
| `nuclide.source` | Which tool discovered it |
| `lifecycle.status` | Current stage |
| `vuln.ids` | CVE IDs |

---

## Ecosystem

```
VisorGoose  ──┐
aimap       ──┼──► visorlog ingest ──► visorlog.db ──► query / alert / report
ollama-recon──┘
```

- [VisorGoose](https://github.com/Nicholas-Kloster/visorgoose) — multi-source AI service discovery
- [aimap](https://github.com/Nicholas-Kloster/aimap) — deep AI service fingerprinter
- [AI-LLM-Infrastructure-OSINT](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT) — case study repository

---

_NuClide Research · [nuclide-research.com](https://nuclide-research.com)_

---

## About

Maintained by **[Nicholas Michael Kloster](https://github.com/Nicholas-Kloster)** as part of [**NuClide**](https://nuclide-research.com) — independent AI infrastructure security research.

CISA disclosures: [CVE-2025-4364](https://nvd.nist.gov/vuln/detail/CVE-2025-4364) · [ICSA-25-140-11](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-11)
