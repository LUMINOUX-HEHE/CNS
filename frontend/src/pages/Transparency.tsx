import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync, ts, short, Flash, PageHead } from "../lib";
import { MerkleViz } from "../viz";
import { verifyInclusion, verifyConsistency, hexToB64 } from "../merkle";
import type {
  OrgSummary, STH, InclusionProof, ConsistencyProof, TimelineEvent,
} from "../types";

// ---------------------------------------------------------------------------
// Transparency (RFC 9162) — audit the org's log without trusting the gateway.
//
// Every proof request is seeded from the loaded signed tree head, inputs are
// validated client-side, and the recomputed root is bound to the STH the page
// is displaying (so "verified" means "in the head you are looking at", not
// merely "self-consistent"). Leaf index -> event is resolved from the
// timeline so a proof connects to real data. Gossip includes a tamper action
// that mutates the root and proves the check actually rejects a fork.
// ---------------------------------------------------------------------------

export default function Transparency() {
  const [params, setParams] = useSearchParams();
  const org = params.get("org") || "";
  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const timeline = useAsync<{ events: TimelineEvent[] }>(
    () => (org ? api.get(`/v1/orgs/${org}/timeline?limit=500`) : Promise.resolve({ events: [] })),
    [org]
  );
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });

  const [sth, setSth] = useState<STH | null>(null);

  // inclusion inputs
  const [idx, setIdx] = useState("0");
  const [size, setSize] = useState("1");
  const [inc, setInc] = useState<InclusionProof | null>(null);
  const [incVerified, setIncVerified] = useState<boolean | null>(null);
  const [incBound, setIncBound] = useState<boolean | null>(null);

  // consistency inputs
  const [from, setFrom] = useState("1");
  const [to, setTo] = useState("2");
  const [con, setCon] = useState<ConsistencyProof | null>(null);
  const [conVerified, setConVerified] = useState<boolean | null>(null);

  // gossip
  const [gTree, setGTree] = useState("");
  const [gRoot, setGRoot] = useState("");
  const [gSig, setGSig] = useState("");
  const [gTs, setGTs] = useState("");
  const [gFrom, setGFrom] = useState("0");
  const [gProof, setGProof] = useState("");
  const [gossip, setGossip] = useState<any>(null);

  useEffect(() => {
    if (!org && orgs.data?.orgs.length) setParams({ org: orgs.data.orgs[0].id });
  }, [orgs.data, org, setParams]);

  // Timeline arrives newest-first; the CT log is append-only oldest-first, so
  // leaf index i corresponds to the i-th event chronologically.
  const chrono = useMemo(
    () => [...(timeline.data?.events || [])].reverse(),
    [timeline.data]
  );

  async function loadSTH() {
    try {
      const s = await api.get<STH>(`/v1/orgs/${org}/ct/sth`);
      setSth(s);
      // Seed every proof input from the real head: never invalid by default.
      const n = Math.max(1, s.tree_size);
      setSize(String(n));
      setIdx(String(n - 1));
      setFrom(String(Math.max(1, n - 1)));
      setTo(String(n));
      setInc(null);
      setCon(null);
      setIncVerified(null);
      setConVerified(null);
      setIncBound(null);
      setMsg({ m: `tree head loaded · size ${s.tree_size}`, k: "ok" });
    } catch (e: any) {
      setSth(null);
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function inclusion() {
    if (!sth) return setMsg({ m: "load the signed tree head first", k: "err" });
    const i = parseInt(idx, 10);
    const s = parseInt(size, 10);
    if (isNaN(i) || isNaN(s) || i < 0 || s <= 0 || i >= s) {
      return setMsg({ m: "need 0 ≤ index < size", k: "err" });
    }
    if (s > sth.tree_size) {
      return setMsg({ m: `size ${s} exceeds the tree head (${sth.tree_size})`, k: "err" });
    }
    try {
      const p = await api.get<InclusionProof>(`/v1/orgs/${org}/ct/proof?index=${i}&size=${s}`);
      setInc(p);
      const root = await verifyInclusion(p.leaf_hash_hex, p.index, p.size, p.proof);
      setIncVerified(root !== null && root === p.root_hex);
      // Bind to the DISPLAYED head when the proof is at the full tree size.
      setIncBound(s === sth.tree_size ? p.root_hex === sth.root_hex : null);
      setMsg({
        m:
          root === p.root_hex
            ? s === sth.tree_size
              ? "inclusion verified against the displayed signed tree head"
              : `inclusion verified against the root at size ${s} (not the displayed head)`
            : "inclusion proof FAILED",
        k: root === p.root_hex ? "ok" : "err",
      });
    } catch (e: any) {
      setInc(null); setIncVerified(null); setIncBound(null);
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function consistency() {
    if (!sth) return setMsg({ m: "load the signed tree head first", k: "err" });
    const f = parseInt(from, 10);
    const t = parseInt(to, 10);
    if (isNaN(f) || isNaN(t) || f < 0 || t <= f) {
      return setMsg({ m: "need 0 ≤ from < to", k: "err" });
    }
    if (t > sth.tree_size) {
      return setMsg({ m: `to ${t} exceeds the tree head (${sth.tree_size})`, k: "err" });
    }
    try {
      const p = await api.get<ConsistencyProof>(`/v1/orgs/${org}/ct/proof?from=${f}&to=${t}`);
      setCon(p);
      const ok = await verifyConsistency(p.old_root_hex, p.new_root_hex, p.from, p.to, p.proof);
      setConVerified(ok);
      const bound = t === sth.tree_size ? p.new_root_hex === sth.root_hex : null;
      setMsg({
        m: ok ? "consistency verified in-browser — the log only grew" : "consistency proof FAILED",
        k: ok ? "ok" : "err",
      });
      if (ok && bound === false) {
        setMsg({ m: "consistency verified, but the new root ≠ displayed head (size mismatch)", k: "err" });
      }
    } catch (e: any) {
      setCon(null); setConVerified(null);
      setMsg({ m: e.message, k: "err" });
    }
  }

  // The STH signature covers (size, timestamp, root), so the timestamp MUST
  // be echoed exactly as signed — a fresh Date.now() invalidates the sig.
  function seedFromSTH() {
    if (!sth) return setMsg({ m: "load the signed tree head first", k: "err" });
    setGTree(String(sth.tree_size));
    setGRoot(sth.root_hex);
    setGSig(sth.signature_hex);
    setGTs(String(sth.timestamp));
    setGFrom("0");
    setGProof("");
    setMsg({ m: "seeded from signed tree head (this should be ACCEPTED)", k: "ok" });
  }

  // Tamper: flip the last hex nibble of the root, keeping the signature. A
  // verifier that actually checks must reject this (accepted=false/alarm).
  function tamper() {
    if (!sth) return setMsg({ m: "load the signed tree head first", k: "err" });
    const flip = (hex: string) => {
      if (!hex) return hex;
      const last = hex.slice(-1);
      const next = last === "0" ? "1" : "0";
      return hex.slice(0, -1) + next;
    };
    setGTree(String(sth.tree_size));
    setGRoot(flip(sth.root_hex));
    setGSig(sth.signature_hex);
    setGTs(String(sth.timestamp));
    setGFrom("0");
    setGProof("");
    setMsg({ m: "root tampered — submit and watch it be REJECTED", k: "err" });
  }

  async function submitGossip() {
    try {
      const proofHex = gProof.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
      const d = await api.post<any>(`/v1/orgs/${org}/ct/gossip`, {
        tree_size: parseInt(gTree, 10) || 0,
        timestamp: parseInt(gTs, 10) || 0,
        root_b64: hexToB64(gRoot),
        signature_b64: hexToB64(gSig),
        proof_from: parseInt(gFrom, 10) || 0,
        proof_hex: proofHex,
      });
      setGossip(d);
      const good = d.accepted && !d.alarm;
      setMsg({
        m: good
          ? "STH accepted — consistent with the trusted head"
          : d.alarm
          ? `ALARM: ${d.alarm}`
          : "STH rejected — signature invalid (the signed payload changed)",
        k: good ? "ok" : "err",
      });
    } catch (e: any) {
      setGossip(null);
      setMsg({ m: e.message, k: "err" });
    }
  }

  // The event a given leaf index commits to (leaf order = chronological).
  const leafEvent = (i: number) => chrono[i];

  return (
    <>
      <PageHead title="Transparency log (RFC 9162)">
        <select value={org} onChange={(e) => setParams({ org: e.target.value })}>
          <option value="">— select org —</option>
          {(orgs.data?.orgs || []).map((o) => (
            <option key={o.id} value={o.id}>{o.name} ({o.id})</option>
          ))}
        </select>{" "}
        <button className="primary" onClick={loadSTH} disabled={!org}>
          Load signed tree head
        </button>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      <p className="muted">
        Any third party can audit the org's history: the signed tree head commits to every
        event, and inclusion/consistency proofs verify here in the browser — no trust in the
        gateway required. Leaf index <code>i</code> is the <code>i</code>-th event on the
        signed timeline (oldest first).
      </p>

      {sth && (
        <div className="panel">
          <div className="panel-head">
            <h3>Signed tree head</h3>
            <span className="badge healthy">size {sth.tree_size}</span>
          </div>
          <MerkleViz size={sth.tree_size} />
          <div style={{ marginTop: 10 }}>
            <div className="hash">root: {sth.root_hex}</div>
            <div className="hash">key: {sth.log_key_hex}</div>
            <div className="hash">sig: {sth.signature_hex}</div>
            <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>{ts(sth.timestamp)}</div>
          </div>
          <p className="muted" style={{ fontSize: 11, marginTop: 8 }}>
            Leaf map (index → event):{" "}
            {chrono.slice(0, Math.min(8, chrono.length)).map((e, i) => (
              <span key={i} style={{ marginRight: 8 }}>
                <code>{i}</code>={e.type}
              </span>
            ))}
            {chrono.length > 8 && <span>…+{chrono.length - 8}</span>}
          </p>
        </div>
      )}

      <div className="grid cols-2" style={{ marginTop: 6 }}>
        <section className="panel">
          <div className="panel-head"><h3>Inclusion proof</h3></div>
          <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
            Prove leaf <code>index</code> is in the tree at <code>size</code>. Use
            <code> size = {sth?.tree_size ?? "…"}</code> to bind to the displayed head.
          </p>
          <div className="form-row">
            <input placeholder="index" value={idx} onChange={(e) => setIdx(e.target.value)} />
            <input placeholder="size" value={size} onChange={(e) => setSize(e.target.value)} />
            <button className="primary" onClick={inclusion} disabled={!org || !sth}>Prove</button>
          </div>
          {leafEvent(parseInt(idx, 10)) && (
            <p className="muted" style={{ fontSize: 12 }}>
              leaf {idx} = <b>{leafEvent(parseInt(idx, 10)).type}</b>{" "}
              {leafEvent(parseInt(idx, 10)).cert_id ? `(${leafEvent(parseInt(idx, 10)).cert_id})` : ""}
            </p>
          )}
          {inc && (
            <>
              <div className={`flash ${incVerified ? "ok" : "err"}`}>
                {incVerified
                  ? "✓ root recomputed from the proof matches the leaf's root"
                  : "✗ proof does not reconstruct the root"}
              </div>
              {incBound === true && (
                <div className="flash ok">✓ bound to the displayed signed tree head</div>
              )}
              {incBound === false && (
                <div className="flash err">✗ root ≠ displayed head (different size)</div>
              )}
              <div className="hash">leaf: {short(inc.leaf_hash_hex, 32)}</div>
              <div className="hash">root: {short(inc.root_hex, 32)}</div>
              <details>
                <summary className="muted" style={{ cursor: "pointer" }}>proof nodes ({inc.proof.length})</summary>
                <pre>{JSON.stringify(inc.proof, null, 2)}</pre>
              </details>
            </>
          )}
        </section>

        <section className="panel">
          <div className="panel-head"><h3>Consistency proof</h3></div>
          <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
            Prove the log at <code>to</code> is an extension of <code>from</code> — history was
            not rewritten.
          </p>
          <div className="form-row">
            <input placeholder="from" value={from} onChange={(e) => setFrom(e.target.value)} />
            <input placeholder="to" value={to} onChange={(e) => setTo(e.target.value)} />
            <button className="primary" onClick={consistency} disabled={!org || !sth}>Prove</button>
          </div>
          {con && (
            <>
              <div className={`flash ${conVerified ? "ok" : "err"}`}>
                {conVerified
                  ? `✓ log at size ${con.to} is an extension of size ${con.from}`
                  : "✗ consistency proof FAILED — the log forked"}
              </div>
              <div className="hash">old: {short(con.old_root_hex, 32)}</div>
              <div className="hash">new: {short(con.new_root_hex, 32)}</div>
              <details>
                <summary className="muted" style={{ cursor: "pointer" }}>proof nodes ({con.proof.length})</summary>
                <pre>{JSON.stringify(con.proof, null, 2)}</pre>
              </details>
            </>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel-head"><h3>Gossip cross-check</h3></div>
        <p className="muted" style={{ marginTop: 0 }}>
          Submit an STH observed elsewhere. The gateway checks the signature and that its own
          head is a prefix of the reported one. Seed = should be accepted; Tamper = flips the
          root and must be rejected (proving the check is real, not self-fulfilling).
        </p>
        <div className="form-row">
          <button onClick={seedFromSTH} disabled={!org || !sth}>Seed from signed tree head</button>
          <button className="danger" onClick={tamper} disabled={!org || !sth}>Tamper root (must reject)</button>
        </div>
        <div className="form-row">
          <input placeholder="tree_size" value={gTree} onChange={(e) => setGTree(e.target.value)} />
          <input placeholder="timestamp (as signed)" value={gTs} onChange={(e) => setGTs(e.target.value)} />
          <input placeholder="proof_from" value={gFrom} onChange={(e) => setGFrom(e.target.value)} />
        </div>
        <div className="form-row">
          <input placeholder="root_hex" value={gRoot} onChange={(e) => setGRoot(e.target.value)} style={{ flex: 3 }} />
        </div>
        <div className="form-row">
          <input placeholder="signature_hex" value={gSig} onChange={(e) => setGSig(e.target.value)} style={{ flex: 3 }} />
        </div>
        <div className="form-row">
          <input placeholder="proof_hex (space/comma separated)" value={gProof} onChange={(e) => setGProof(e.target.value)} style={{ flex: 3 }} />
        </div>
        <div className="form-row">
          <button className="primary" onClick={submitGossip} disabled={!org}>Submit STH</button>
        </div>
        {gossip && (
          <div className={`flash ${gossip.accepted && !gossip.alarm ? "ok" : "err"}`}>
            accepted={String(gossip.accepted)} alarm={String(gossip.alarm)} trusted_size=
            {gossip.trusted_tree_size}
          </div>
        )}
        {gossip && <pre>{JSON.stringify(gossip, null, 2)}</pre>}
      </section>
    </>
  );
}