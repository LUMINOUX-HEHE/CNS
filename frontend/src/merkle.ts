// merkle.ts — client-side RFC 9162 verification of the gateway's
// transparency log. Ports research/l0/ctlog.go VerifyInclusion /
// VerifyConsistency so a third party can audit the log WITHOUT trusting
// the gateway: the page fetches only hashes + proofs, and recomputes the
// roots here in the browser.

const enc = new TextEncoder();

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  const d = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(d);
}

// nodeHash = sha256(0x01 || l || r) — ctlog.go:58
async function nodeHash(l: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  return sha256(new Uint8Array([0x01]), l, r);
}

// verifyInclusion recomputes the root from a leaf hash, index, size and
// proof (ctlog.go:241). Returns the computed root hex, or null if the
// proof is malformed. Caller compares it to the expected root.
export async function verifyInclusion(
  leafHashHex: string,
  idx: number,
  size: number,
  proofHex: string[]
): Promise<string | null> {
  if (idx < 0 || idx >= size) return null;
  let r = hexToBytes(leafHashHex);
  let fn = idx;
  let sn = size - 1;
  for (const ph of proofHex) {
    const p = hexToBytes(ph);
    if (sn === 0) return null;
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  if (sn !== 0) return null;
  return bytesToHex(r);
}

// verifyConsistency (ctlog.go:276) reports whether the log at size2 is an
// extension of the log at size1, using only the two roots + proof.
export async function verifyConsistency(
  oldRootHex: string,
  newRootHex: string,
  size1: number,
  size2: number,
  proofHex: string[]
): Promise<boolean> {
  if (size1 === 0) return proofHex.length === 0;
  if (size1 > size2 || !oldRootHex || !newRootHex) return false;
  if (size1 === size2) {
    return proofHex.length === 0 && oldRootHex === newRootHex;
  }
  if (proofHex.length === 0) return false;

  const path = proofHex.slice();
  if ((size1 & (size1 - 1)) === 0) {
    path.unshift(oldRootHex); // size1 is an exact power of two
  }
  let fn = size1 - 1;
  let sn = size2 - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = hexToBytes(path[0]);
  let sr = hexToBytes(path[0]);
  for (let i = 1; i < path.length; i++) {
    const c = hexToBytes(path[i]);
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && bytesToHex(fr) === oldRootHex && bytesToHex(sr) === newRootHex;
}

// verifySTHSignature is a convenience for the STH card: Ed25519 verify of
// the signed tree head is done server-side; here we only expose the root
// so the page can show it. (kept minimal on purpose)
export { bytesToHex, hexToBytes };

// hexToB64 re-encodes a hex string as base64 — the gossip endpoint expects
// root_b64 / signature_b64 (Go decodes []byte from base64 JSON).
export function hexToB64(hex: string): string {
  const bytes = hexToBytes(hex);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}