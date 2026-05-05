# VisorLog

Centralized findings ledger for the NuClide OSINT ecosystem. ECS-normalized, lifecycle-tracked, append-only SQLite store. All NuClide tools (VisorGoose, aimap, VisorRAG, ollama-recon) write events here. Every finding moves through a defined lifecycle: `open → disclosed → acknowledged → remediated → verified`.

## Language
Go

## Build & Run
```
go build -o visorlog .
visorlog --db nuclide.db status            # severity histogram + sector breakdown
visorlog --db nuclide.db ingest --from findings.ndjson
visorlog --db nuclide.db query --severity critical --status open
visorlog --db nuclide.db update --id <ID> --status disclosed
visorlog --db nuclide.db alert             # run alert rules
visorlog --db nuclide.db serve             # web dashboard at :8765
go test ./...
```

## Claude Code Notes
- Check README for full CLI surface, ingest formats (NDJSON / VisorGoose state / ollama-recon state), and ECS schema reference
- Findings live in `store/event.go` — extend the schema there if adding new fields
- Web dashboard handlers in `web/server.go`; static assets in `web/static/`
- Alert rules in `alert/rules.go` — add new rules by extending the rules slice
- Built with [Claude Code](https://claude.ai/code)
