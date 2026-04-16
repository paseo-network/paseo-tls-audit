/**
 * TLS certificate checker.
 *
 * Reads the peer discovery output (peers.json) and the chain spec,
 * merges them, extracts all unique wss endpoints, and verifies TLS
 * certificates using Node's built-in tls module.
 *
 * Outputs a full report data JSON to stdout.
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import * as tls from "tls";
import * as net from "net";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const CHAIN_SPECS_DIR = resolve(ROOT, "chain-specs");
const PEERS_FILE = resolve(ROOT, "output", "peers.json");

// ----- Types -----

interface Addr {
  multiaddr: string;
  host: string;
  port: number;
  proto: "wss" | "ws" | "tcp";
  addrType: string;
  peerId: string;
  source: "chain-spec" | "dht";
  tlsClass?: string;
  tlsIssuer?: string;
  tlsExpires?: string;
  tlsDaysLeft?: number;
}

interface Peer {
  peer_id: string;
  addrs: Addr[];
  is_ah_bootnode: boolean;
  is_relay_bootnode: boolean;
  overall: string;
  transport: string;
  wss_count: number;
  ws_count: number;
  tcp_count: number;
}

// ----- Helpers -----

function isNonRoutable(ip: string): boolean {
  // IPv6 loopback, unspecified, link-local, ULA
  if (ip === "::1" || ip === "::" || ip.startsWith("fe80:") || ip.startsWith("fd") || ip.startsWith("fc")) return true;
  // IPv4 private (RFC 1918), loopback, link-local, CGNAT (RFC 6598)
  if (ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("0.")) return true;
  if (ip.startsWith("169.254.")) return true;
  if (ip.startsWith("100.")) {
    const second = parseInt(ip.split(".")[1], 10);
    if (second >= 64 && second <= 127) return true; // 100.64.0.0/10
  }
  if (ip.startsWith("172.")) {
    const second = parseInt(ip.split(".")[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

function parseMultiaddr(ma: string) {
  const parts = ma.replace(/^\//, "").split("/");
  let host: string | null = null;
  let port: number | null = null;
  let proto: "wss" | "ws" | "tcp" = "tcp";
  let addrType = "";
  let peerId = "";

  for (let i = 0; i < parts.length; i++) {
    if (["dns", "dns4", "dns6"].includes(parts[i]) && i + 1 < parts.length) {
      host = parts[i + 1]; addrType = "dns";
    } else if (["ip4", "ip6"].includes(parts[i]) && i + 1 < parts.length) {
      host = parts[i + 1]; addrType = parts[i];
    } else if (parts[i] === "tcp" && i + 1 < parts.length) {
      port = parseInt(parts[i + 1], 10);
    } else if (parts[i] === "wss") {
      proto = "wss";
    } else if (parts[i] === "ws") {
      proto = "ws";
    } else if (parts[i] === "p2p" && i + 1 < parts.length) {
      peerId = parts[i + 1];
    }
  }
  return { host, port, proto, addrType, peerId };
}

function checkTls(host: string, port: number, timeoutMs = 5000): Promise<{
  status: "ok" | "expired" | "error" | "timeout";
  verify?: number;
  issuer?: string;
  expires?: string;
  daysLeft?: number;
}> {
  return new Promise((res) => {
    const timer = setTimeout(() => {
      socket.destroy();
      res({ status: "timeout" });
    }, timeoutMs);

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        clearTimeout(timer);
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const rawIssuer = cert.issuer?.CN || cert.issuer?.O || "";
        const issuer = Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer;
        const rawExpires = cert.valid_to || "";
        const expires = Array.isArray(rawExpires) ? rawExpires[0] : rawExpires;
        let daysLeft: number | undefined;
        if (expires) {
          const exp = new Date(expires);
          daysLeft = Math.floor((exp.getTime() - Date.now()) / 86400000);
        }
        socket.destroy();

        if (!authorized && daysLeft !== undefined && daysLeft < 0) {
          res({ status: "expired", issuer, expires, daysLeft });
        } else if (!authorized) {
          res({ status: "error", issuer, expires, daysLeft });
        } else {
          res({ status: "ok", issuer, expires, daysLeft });
        }
      },
    );

    socket.on("error", () => {
      clearTimeout(timer);
      res({ status: "error" });
    });
  });
}

// ----- Main -----

// Load data
const dhtPeers: Record<string, string[]> = JSON.parse(
  readFileSync(PEERS_FILE, "utf-8"),
);
const ahSpec = JSON.parse(
  readFileSync(resolve(CHAIN_SPECS_DIR, "paseo-asset-hub.smol.json"), "utf-8"),
);
const relaySpec = JSON.parse(
  readFileSync(resolve(CHAIN_SPECS_DIR, "paseo.raw.smol.json"), "utf-8"),
);

// Extract bootnode peer IDs
const ahBootnodePids = new Set<string>();
for (const bn of ahSpec.bootNodes as string[]) {
  const m = bn.match(/\/p2p\/(12D3KooW[A-Za-z0-9]+)$/);
  if (m) ahBootnodePids.add(m[1]);
}
const relayBootnodePids = new Set<string>();
for (const bn of (relaySpec.bootNodes || []) as string[]) {
  const m = bn.match(/\/p2p\/(12D3KooW[A-Za-z0-9]+)$/);
  if (m) relayBootnodePids.add(m[1]);
}

// Merge chain spec bootnodes into DHT data
for (const bn of ahSpec.bootNodes as string[]) {
  const m = bn.match(/\/p2p\/(12D3KooW[A-Za-z0-9]+)$/);
  if (!m) continue;
  if (!dhtPeers[m[1]]) dhtPeers[m[1]] = [];
  if (!dhtPeers[m[1]].includes(bn)) dhtPeers[m[1]].push(bn);
}

const allChainSpecAddrs = new Set([
  ...ahSpec.bootNodes,
  ...(relaySpec.bootNodes || []),
]);

// Build peer list
const peers: Record<string, Peer> = {};

for (const [pid, addrs] of Object.entries(dhtPeers)) {
  const peer: Peer = {
    peer_id: pid,
    addrs: [],
    is_ah_bootnode: ahBootnodePids.has(pid),
    is_relay_bootnode: relayBootnodePids.has(pid),
    overall: "",
    transport: "",
    wss_count: 0,
    ws_count: 0,
    tcp_count: 0,
  };

  for (const ma of addrs) {
    const parsed = parseMultiaddr(ma);
    if (!parsed.host || !parsed.port) continue;
    if (["ip4", "ip6"].includes(parsed.addrType) && isNonRoutable(parsed.host!)) continue;

    peer.addrs.push({
      multiaddr: ma,
      host: parsed.host!,
      port: parsed.port!,
      proto: parsed.proto,
      addrType: parsed.addrType,
      peerId: parsed.peerId,
      source: allChainSpecAddrs.has(ma) ? "chain-spec" : "dht",
    });
  }

  if (peer.addrs.length > 0) {
    peers[pid] = peer;
  }
}

// Collect unique wss endpoints and check TLS
const wssEndpoints = new Map<string, { host: string; port: number }>();
for (const peer of Object.values(peers)) {
  for (const a of peer.addrs) {
    if (a.proto === "wss") {
      const key = `${a.host}:${a.port}`;
      if (!wssEndpoints.has(key)) {
        wssEndpoints.set(key, { host: a.host, port: a.port });
      }
    }
  }
}

process.stderr.write(`Checking TLS on ${wssEndpoints.size} wss endpoints...\n`);

const tlsResults = new Map<string, Awaited<ReturnType<typeof checkTls>>>();

// Check in batches of 5
const entries = [...wssEndpoints.entries()];
for (let i = 0; i < entries.length; i += 5) {
  const batch = entries.slice(i, i + 5);
  const results = await Promise.all(
    batch.map(async ([key, { host, port }]) => {
      process.stderr.write(`  ${key}...`);
      const r = await checkTls(host, port);
      process.stderr.write(` ${r.status}\n`);
      return [key, r] as const;
    }),
  );
  for (const [key, r] of results) {
    tlsResults.set(key, r);
  }
}

// Enrich addrs with TLS data and classify peers
for (const peer of Object.values(peers)) {
  for (const addr of peer.addrs) {
    if (addr.proto === "wss") {
      const key = `${addr.host}:${addr.port}`;
      const t = tlsResults.get(key);
      if (t) {
        if (t.status === "timeout") {
          addr.tlsClass = "unreachable";
        } else if (t.status === "expired") {
          addr.tlsClass = "expired";
          addr.tlsIssuer = t.issuer;
          addr.tlsExpires = t.expires;
          addr.tlsDaysLeft = t.daysLeft;
        } else if (t.status === "error") {
          addr.tlsClass = "unreachable";
        } else {
          addr.tlsIssuer = t.issuer;
          addr.tlsExpires = t.expires;
          addr.tlsDaysLeft = t.daysLeft;
          addr.tlsClass = t.daysLeft !== undefined && t.daysLeft <= 7 ? "expiring" : "valid";
        }
      }
    }
  }

  const wssAddrs = peer.addrs.filter((a) => a.proto === "wss");
  const wsAddrs = peer.addrs.filter((a) => a.proto === "ws");
  const tcpAddrs = peer.addrs.filter((a) => a.proto === "tcp");

  peer.wss_count = wssAddrs.length;
  peer.ws_count = wsAddrs.length;
  peer.tcp_count = tcpAddrs.length;

  if (wssAddrs.length > 0) {
    const classes = wssAddrs.map((a) => a.tlsClass || "unknown");
    if (classes.includes("valid")) peer.overall = "valid";
    else if (classes.includes("expiring")) peer.overall = "expiring";
    else if (classes.includes("expired")) peer.overall = "expired";
    else peer.overall = "unreachable";
    peer.transport = "wss";
  } else if (wsAddrs.length > 0) {
    peer.overall = "ws-only";
    peer.transport = "ws";
  } else {
    peer.overall = "tcp-only";
    peer.transport = "tcp";
  }
}

// Sort
const order: Record<string, number> = { valid: 0, expiring: 1, expired: 2, unreachable: 3, "ws-only": 4, "tcp-only": 5 };
const sortedPeers = Object.values(peers).sort(
  (a, b) => (order[a.overall] ?? 9) - (order[b.overall] ?? 9) || a.peer_id.localeCompare(b.peer_id),
);

// Stats
const stats = {
  total_peers: sortedPeers.length,
  wss_valid: sortedPeers.filter((p) => p.overall === "valid").length,
  wss_expiring: sortedPeers.filter((p) => p.overall === "expiring").length,
  wss_expired: sortedPeers.filter((p) => p.overall === "expired").length,
  wss_unreachable: sortedPeers.filter((p) => p.overall === "unreachable").length,
  ws_only: sortedPeers.filter((p) => p.overall === "ws-only").length,
  tcp_only: sortedPeers.filter((p) => p.overall === "tcp-only").length,
};

process.stderr.write(`\nResults: ${JSON.stringify(stats)}\n`);

// Slim down for embedding
const slim = sortedPeers.map((p) => ({
  id: p.peer_id,
  o: p.overall,
  t: p.transport,
  ab: p.is_ah_bootnode,
  rb: p.is_relay_bootnode,
  wss: p.wss_count,
  ws: p.ws_count,
  tcp: p.tcp_count,
  a: p.addrs.map((a) => {
    const sa: Record<string, unknown> = {
      m: a.multiaddr,
      p: a.proto,
      s: a.source,
    };
    if (a.proto === "wss") {
      if (a.tlsClass) sa.tc = a.tlsClass;
      if (a.tlsIssuer) sa.ti = a.tlsIssuer;
      if (a.tlsExpires) sa.te = a.tlsExpires;
      if (a.tlsDaysLeft !== undefined) sa.td = a.tlsDaysLeft;
    }
    return sa;
  }),
}));

const output = JSON.stringify({ s: stats, p: slim });
process.stdout.write(output);

process.stderr.write("Done.\n");
