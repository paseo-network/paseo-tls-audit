# Paseo TLS Audit

Discover peers on the Paseo Asset Hub network via Kademlia DHT and verify TLS certificates on their WebSocket Secure (wss) endpoints.

Browser-based light clients (smoldot) require valid TLS certificates on wss endpoints. This tool audits the network to identify nodes with expired, expiring, or missing TLS certs.

## Requirements

- [Bun](https://bun.sh) >= 1.0

## Quick start

```sh
bun install
bun run audit
```

This runs the full pipeline and writes the report to `output/report.html`. Open it in a browser.

## Steps

The audit runs three steps in sequence:

### 1. Discover peers

```sh
bun run discover
```

Starts a [smoldot](https://github.com/smol-dot/smoldot) light client, connects to the Paseo Asset Hub network via the bootnodes in the chain spec, and collects peer multiaddrs from Kademlia DHT discovery for 90 seconds (configurable via `COLLECT_SECONDS` env var).

Outputs `output/peers.json` — a map of peer IDs to their discovered multiaddrs.

### 2. Check TLS

```sh
bun run check-tls
```

Reads `output/peers.json` and the chain specs, merges them, extracts all unique wss endpoints, and verifies each TLS certificate using Node's `tls` module.

Outputs `output/report_data.json` — structured audit data with TLS status per endpoint.

### 3. Generate report

```sh
bun run report
```

Takes `output/report_data.json` and injects it into the HTML template at `template/report.html`.

Outputs `output/report.html` — a self-contained static page with:

- Full list of all discovered peers with their multiaddrs
- TLS certificate status for every wss endpoint (valid, expiring, expired, unreachable)
- Search, filter, and live browser WebSocket testing
- Methodology and reproduction instructions

## Project structure

```
src/
  discover.ts      # Peer discovery via smoldot + Kademlia DHT
  check-tls.ts     # TLS certificate verification
  build-report.ts  # HTML report generation
chain-specs/       # Smoldot chain specs for Paseo relay + Asset Hub
template/          # HTML report template
output/            # Generated artifacts (gitignored)
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `COLLECT_SECONDS` | `90` | How long to crawl the DHT for peers |

## License

MIT
