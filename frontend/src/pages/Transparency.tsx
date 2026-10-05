import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync, ts, Flash, PageHead } from "../lib";
import type { OrgSummary, STH, InclusionProof, ConsistencyProof } from "../types";

export default function Transparency() {
  const [params, setParams] = useSearchParams();
  const org = params.get("org") || "";
  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });
  const [sth, setSth] = useState<STH | null>(null);
  const [idx, setIdx] = useState("0");
  const [size, setSize] = useState("1");
  const [from, setFrom] = useState("1");
  const [to, setTo] = useState("2");
  const [proof, setProof] = useState<any>(null);

  useEffect(() => {
    if (!org && orgs.data?.orgs.length) setParams({ org: orgs.data.orgs[0].id });
  }, [orgs.data, org, setParams]);

  async function loadSTH() {
    try {
      setSth(await api.get<STH>(`/v1/orgs/${org}/ct/sth`));
      setMsg({ m: "tree head loaded", k: "ok" });
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function inclusion() {
    try {
      const p = await api.get<InclusionProof>(
        `/v1/orgs/${org}/ct/proof?index=${idx}&size=${size}`
      );
      setProof({ kind: "inclusion", p });
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function consistency() {
    try {
      const p = await api.get<ConsistencyProof>(
        `/v1/orgs/${org}/ct/proof?from=${from}&to=${to}`
      );
      setProof({ kind: "consistency", p });
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  return (
    <>
      <PageHead title="Transparency log (RFC 9162)">
        <select value={org} onChange={(e) => setParams({ org: e.target.value })}>
          <option value="">— select org —</option>
          {(orgs.data?.orgs || []).map((o) => (
            <option key={o.id} value={o.id}>
              {o.name} ({o.id})
            </option>
          ))}
        </select>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      <p className="muted">
        Any third party can audit the org's history: the signed tree head commits to
        every event, and inclusion/consistency proofs verify without trusting the gateway.
      </p>

      <button className="primary" onClick={loadSTH} disabled={!org}>
        Get signed tree head
      </button>
      {sth && (
        <div className="card" style={{ marginTop: 12 }}>
          <h3>
            Tree size {sth.tree_size} · {ts(sth.timestamp)}
          </h3>
          <div className="hash">root: {sth.root_hex}</div>
          <div className="hash">key: {sth.log_key_hex}</div>
          <div className="hash">sig: {sth.signature_hex}</div>
        </div>
      )}

      <h3>Inclusion proof</h3>
      <div className="form-row">
        <input placeholder="index" value={idx} onChange={(e) => setIdx(e.target.value)} />
        <input placeholder="size" value={size} onChange={(e) => setSize(e.target.value)} />
        <button onClick={inclusion} disabled={!org}>
          Prove
        </button>
      </div>

      <h3>Consistency proof</h3>
      <div className="form-row">
        <input placeholder="from" value={from} onChange={(e) => setFrom(e.target.value)} />
        <input placeholder="to" value={to} onChange={(e) => setTo(e.target.value)} />
        <button onClick={consistency} disabled={!org}>
          Prove
        </button>
      </div>

      {proof && <pre>{JSON.stringify(proof, null, 2)}</pre>}
    </>
  );
}