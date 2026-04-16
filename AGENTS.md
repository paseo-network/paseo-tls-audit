# AGENTS.md

Instructions for coding agents working in the `paseo-tls-audit` repository.

## Purpose

This repo audits TLS certificate health for Paseo Asset Hub peer nodes. It discovers peers via a smoldot light client doing Kademlia DHT crawls, verifies TLS certs on every wss endpoint, and produces a static HTML report.

## Architecture

The audit is a three-step pipeline. Each step reads from the previous step's output.

```
discover.ts  -->  output/peers.json
                        |
check-tls.ts -->  output/report_data.json
                        |
build-report.ts -->  output/report.html
```

- `src/discover.ts` — Starts smoldot, captures peer multiaddrs from debug logs during DHT discovery. Pure smoldot, no other network libraries.
- `src/check-tls.ts` — Merges DHT-discovered peers with chain spec bootnodes, extracts wss endpoints, checks TLS using Node's `tls` module. Classifies as valid/expiring/expired/unreachable.
- `src/build-report.ts` — Simple template injection: reads `template/report.html`, replaces `__REPORT_DATA__` and `__REPORT_DATE__` placeholders, writes final HTML.
- `template/report.html` — Self-contained HTML+CSS+JS. Renders the embedded JSON data client-side. Includes search, filters, and live WebSocket testing from the browser.

## Key decisions

- **Bun runtime** — the project uses Bun for speed and native TypeScript execution. All scripts run directly with `bun src/foo.ts`.
- **No external TLS tools** — we use Node's `tls.connect()` (available in Bun) rather than shelling out to `openssl`. This keeps it cross-platform and avoids subprocess overhead.
- **Chain specs are vendored** in `chain-specs/`. They should be updated when the chain specs change upstream in `paseo-network/paseo-chain-specs`.
- **The HTML report is fully self-contained** — no external JS/CSS dependencies beyond Google Fonts. Data is embedded as a JSON literal so the page works as a static file anywhere.
- **Discovery uses smoldot's debug logs** to capture peer multiaddrs. This is a pragmatic approach; smoldot does not expose discovered peers via its JSON-RPC API.

## Working rules

- Keep the pipeline simple: three scripts, stdin/stdout between them.
- Do not add web frameworks or build tooling. The report is a single HTML file.
- The template should remain human-editable. Do not generate it programmatically beyond the placeholder substitution.
- Test changes by running `bun run audit` and opening `output/report.html` in a browser.
- The `output/` directory is gitignored. Never commit generated artifacts.

## Extending

- To audit a different chain, add its chain spec to `chain-specs/` and update `discover.ts` and `check-tls.ts` to load it.
- To add new TLS checks (e.g., certificate chain depth, cipher suites), extend the `checkTls()` function in `check-tls.ts` and the slim output format.
- To change the report layout, edit `template/report.html` directly. The JavaScript in the template reads from the `DATA` global, which has shape `{ s: Stats, p: Peer[] }`.
