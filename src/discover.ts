/**
 * Peer discovery for Paseo Asset Hub.
 *
 * Starts a smoldot light client, joins the network via the chain spec
 * bootnodes, and collects peer multiaddrs from Kademlia DHT discovery
 * for a configurable duration.
 *
 * Outputs a JSON map of { peerId: string[] } to stdout.
 */

import * as smoldot from "smoldot";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CHAIN_SPECS_DIR = resolve(__dirname, "..", "chain-specs");

const COLLECT_SECONDS = Number(process.env.COLLECT_SECONDS) || 90;

const relaySpec = readFileSync(
  resolve(CHAIN_SPECS_DIR, "paseo.raw.smol.json"),
  "utf-8",
);
const ahSpec = readFileSync(
  resolve(CHAIN_SPECS_DIR, "paseo-asset-hub.smol.json"),
  "utf-8",
);

const discovered = new Map<string, Set<string>>();

const client = smoldot.start({
  maxLogLevel: 4,
  logCallback: (_level: number, _target: string, message: string) => {
    const multiaddrs = message.match(
      /\/(?:dns4?|dns6|ip4|ip6)\/[^\s,;}\]]+\/p2p\/12D3KooW[A-Za-z0-9]+/g,
    );
    if (!multiaddrs) return;
    for (const ma of multiaddrs) {
      const m = ma.match(/\/p2p\/(12D3KooW[A-Za-z0-9]+)$/);
      if (!m) continue;
      if (!discovered.has(m[1])) discovered.set(m[1], new Set());
      discovered.get(m[1])!.add(ma);
    }
  },
});

const relay = await client.addChain({ chainSpec: relaySpec });
const ah = await client.addChain({
  chainSpec: ahSpec,
  potentialRelayChains: [relay],
});

// Kick off a JSON-RPC call so smoldot starts syncing
ah.sendJsonRpc(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "system_health",
    params: [],
  }),
);

process.stderr.write(
  `Collecting peers for ${COLLECT_SECONDS}s via Kademlia DHT...\n`,
);

for (let i = 0; i < COLLECT_SECONDS; i++) {
  await new Promise((r) => setTimeout(r, 1000));
  // Drain any pending JSON-RPC responses
  try {
    while (true) {
      await Promise.race([
        ah.nextJsonRpcResponse(),
        new Promise((_, rej) => setTimeout(() => rej("timeout"), 100)),
      ]);
    }
  } catch {
    // expected — no more responses
  }
  if (i > 0 && i % 15 === 0) {
    process.stderr.write(`  ${i}s: ${discovered.size} unique peers\n`);
  }
}

process.stderr.write(`\nDone. ${discovered.size} unique peers discovered.\n`);

// Output as JSON
const results: Record<string, string[]> = {};
for (const [peerId, addrs] of discovered) {
  results[peerId] = [...addrs].sort();
}
process.stdout.write(JSON.stringify(results, null, 2));

ah.remove();
relay.remove();
await client.terminate();
