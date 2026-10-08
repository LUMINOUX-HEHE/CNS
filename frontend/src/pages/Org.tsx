import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync, short, Flash, PageHead } from "../lib";
import { Gauge, QuorumMeter, TrustGraphSVG, Timeline, StatTile, LivePulse } from "../viz";
import type {
  OrgSummary,
  OrgDetail,
  TimelineEvent,
  TrustState,
  OrgPubKey,
  TrustGraph,
} from "../types";

const WATCHDOGS = [
  { id: "W1", kind: "rate_cusum" },
  { id: "W2", kind: "log_integrity" },
  { id: "W3", kind: "graph_anomaly" },
  { id: "W4", kind: "external_probe" },
  { id: "W5", kind: "behavior_baseline" },
];

export default function OrgPage() {
  const [params, setParams] = useSearchParams();
  const org = params.get("org") || "";
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });

  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const detail = useAsync<OrgDetail>(
    () => (org ? api.get(`/v1/orgs/${org}`) : Promise.resolve(null as any)),
    [org]
  );
  const [tlimit, setTlimit] = useState(200);
  const timeline = useAsync<{ events: TimelineEvent[]; count: number; total: number }>(
    () =>
      org
        ? api.get(`/v1/orgs/${org}/timeline?limit=${tlimit}`)
        : Promise.resolve({ events: [], count: 0, total: 0 }),
    [org, tlimit]
  );
  const state = useAsync<TrustState>(
    () => (org ? api.get(`/v1/orgs/${org}/state`) : Promise.resolve({ certs: {} })),
    [org]
  );
  const pubkey = useAsync<OrgPubKey>(
    () => (org ? api.get(`/v1/orgs/${org}/pubkey`) : Promise.resolve(null as any)),
    [org]
  );
  const graph = useAsync<TrustGraph>(
    () => (org ? api.get(`/v1/orgs/${org}/graph`) : Promise.resolve(null as any)),
    [org]
  );

  // Live mode: poll the org's detail so a DETECTED verdict appears without
  // a manual Refresh (the detection is raised by watchdog scores posted
  // elsewhere / by other operators).
  const [auto, setAuto] = useState(false);
  useEffect(() => {
    if (!auto || !org) return;
    const id = setInterval(() => reload(), 3000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, org]);

  // form fields
  const [cert, setCert] = useState("");
  const [identity, setIdentity] = useState("");
  const [via, setVia] = useState("");
  const [revoke, setRevoke] = useState("");
  const [node, setNode] = useState("watchdog-1");
  const [score, setScore] = useState("0");
  const [badIndex, setBadIndex] = useState("");
  const [shards, setShards] = useState("");

  // Client-side roster of the documented W1..W5 watchdogs. The API has no
  // GET for scores (POST-only), so this console tracks the last score posted
  // per node and shows the derived 3-of-5 quorum verdict.
  const [roster, setRoster] = useState<Record<string, number | null>>(
    Object.fromEntries(WATCHDOGS.map((w) => [w, null]))
  );

  async function postScore(nodeID: string, s: number) {
    try {
      await api.post(`/v1/orgs/${org}/scores`, {
        node_id: nodeID,
        score: s,
        p_value: s < 25 ? 0.01 : 1,
        evidence: null,
      });
      setRoster((r) => ({ ...r, [nodeID]: s }));
      flash(`${nodeID} score=${s} ingested`, "ok");
      setTimeout(reload, 350);
    } catch (e: any) {
      flash(e.message, "err");
    }
  }

  useEffect(() => {
    if (!org && orgs.data?.orgs.length) {
      setParams({ org: orgs.data.orgs[0].id });
    }
  }, [orgs.data, org, setParams]);

  function flash(m: string, k: "ok" | "err") {
    setMsg({ m, k });
  }

  function reload() {
    detail.reload();
    timeline.reload();
    state.reload();
    pubkey.reload();
    graph.reload();
  }

  async function doIssue(e: React.FormEvent) {
    e.preventDefault();
    if (!cert || !identity) return flash("cert_id + identity required", "err");
    try {
      await api.post(`/v1/orgs/${org}/issue`, { cert_id: cert, identity, via });
      setCert("");
      setIdentity("");
      setVia("");
      flash(`issued ${cert}`, "ok");
      reload();
    } catch (e: any) {
      flash(e.message, "err");
    }
  }

  async function doRevoke(e: React.FormEvent) {
    e.preventDefault();
    if (!revoke) return;
    try {
      await api.post(`/v1/orgs/${org}/revoke`, { cert_id: revoke });
      setRevoke("");
      flash(`revoked ${revoke}`, "ok");
      reload();
    } catch (e: any) {
      flash(e.message, "err");
    }
  }

  async function doScore(e: React.FormEvent) {
    e.preventDefault();
    const s = parseFloat(score);
    const evidence = badIndex ? { bad_index: parseInt(badIndex, 10) } : null;
    try {
      await api.post(`/v1/orgs/${org}/scores`, {
        node_id: node,
        score: s,
        p_value: s < 25 ? 0.01 : 1,
        evidence,
      });
      flash(`score ${node}=${s} ingested`, "ok");
      setTimeout(reload, 350);
    } catch (e: any) {
      flash(e.message, "err");
    }
  }

  async function doRecover() {
    let parsed: any;
    try {
      parsed = JSON.parse(shards);
    } catch {
      return flash("fork artifact must be JSON", "err");
    }
    if (!parsed || !parsed.timeline || !parsed.commit) {
      return flash("fork artifact needs {timeline, commit}", "err");
    }
    try {
      const d: any = await api.post(`/v1/orgs/${org}/recover`, parsed);
      flash(
        `recovered: epoch ${d.epoch}, ${d.issued ?? 0} members, head ${short(d.head)}`,
        "ok"
      );
      reload();
    } catch (e: any) {
      flash(e.message, "err");
    }
  }

  async function doDelete() {
    if (!confirm(`Delete org ${org}? Files move to data/trash.`)) return;
    try {
      await api.del(`/v1/orgs/${org}`);
      flash("deleted", "ok");
      setParams({});
      orgs.reload();
    } catch (e: any) {
      flash(e.message, "err");
    }
  }

  const events = timeline.data?.events || [];
  const certs = Object.entries(state.data?.certs || {});
  const revoked = certs.filter(([, c]) => c.revoked).length;
  const alarmedCount = WATCHDOGS.filter((w) => {
    const s = roster[w.id];
    return s !== null && s < 25;
  }).length;
  const affected = new Set(certs.filter(([, c]) => c.revoked).map(([id]) => id));

  return (
    <>
      <PageHead title="Org console">
        <select value={org} onChange={(e) => setParams({ org: e.target.value })}>
          <option value="">— select org —</option>
          {(orgs.data?.orgs || []).map((o) => (
            <option key={o.id} value={o.id}>
              {o.name} ({o.id})
            </option>
          ))}
        </select>{" "}
        <button onClick={reload}>Refresh</button>{" "}
        <button
          className={auto ? "primary" : ""}
          onClick={() => setAuto((a) => !a)}
          title="poll every 3s"
        >
          {auto ? "Live: on" : "Live: off"}
        </button>{" "}
        <button className="danger" onClick={doDelete} disabled={!org}>
          Delete org
        </button>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      {detail.errMsg && <Flash msg={detail.errMsg} kind="err" />}

      {detail.data && (
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12, flexWrap: "wrap" }}>
          <h3 style={{ margin: 0 }}>{detail.data.name}</h3>
          <span className={`badge ${detail.data.detected ? "detected" : "healthy"}`}>
            {detail.data.detected ? "DETECTED" : "healthy"}
          </span>
          <LivePulse on={auto} label={auto ? "polling 3s" : "manual"} tone={detail.data.detected ? "bad" : undefined} />
        </div>
      )}

      <div className="grid cols-4 stagger" style={{ marginBottom: 14 }}>
        <StatTile k="Events" v={timeline.data?.total ?? 0} sub={`${events.length} shown`} />
        <StatTile k="Certs valid" v={certs.length - revoked} tone="ok" sub={`${revoked} revoked`} />
        <StatTile
          k="Alarmed"
          v={`${alarmedCount}/5`}
          tone={alarmedCount >= 3 ? "bad" : alarmedCount > 0 ? "warn" : "ok"}
          sub="quorum ≥3"
        />
        <StatTile k="Issuance edges" v={graph.data?.edges.length ?? 0} tone="info" />
      </div>

      <section className="panel">
        <div className="panel-head"><h3>Watchdog ensemble</h3></div>
        <p className="muted" style={{ marginTop: 0 }}>
          Five independent watchdogs (threshold 25). DETECTED iff ≥3 of 5 score below threshold.
        </p>
        <div className="wd-grid">
          {WATCHDOGS.map((w) => {
            const s = roster[w.id];
            const alarmed = s !== null && s < 25;
            return (
              <div key={w.id} className={`wd ${alarmed ? "alarmed" : "healthy"}`}>
                <div className="wd-top">
                  <span className="wd-id">{w.id}</span>
                  <span className={`chip ${alarmed ? "c-detected" : ""}`}>
                    {s === null ? "no data" : alarmed ? "ALARMED" : "HEALTHY"}
                  </span>
                </div>
                <Gauge score={s} size={82} label={w.kind} />
                <div className="wd-foot">
                  <span>{w.kind}</span>
                  <span>
                    <button className="danger" style={{ padding: "2px 7px", fontSize: 10 }}
                      onClick={() => postScore(w.id, 0)} disabled={!org}>fail</button>{" "}
                    <button style={{ padding: "2px 7px", fontSize: 10 }}
                      onClick={() => postScore(w.id, 100)} disabled={!org}>pass</button>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop: 14 }}>
          <QuorumMeter alarmed={alarmedCount} />
        </div>
        <form className="form-row" onSubmit={doScore}>
          <input placeholder="node_id" value={node} onChange={(e) => setNode(e.target.value)} />
          <input type="number" placeholder="score" value={score} onChange={(e) => setScore(e.target.value)} />
          <input type="number" placeholder="bad_index (optional)" value={badIndex} onChange={(e) => setBadIndex(e.target.value)} />
          <button className="primary" type="submit" disabled={!org}>Post custom score</button>
        </form>
      </section>

      <section className="panel">
        <div className="panel-head"><h3>Issue / revoke</h3></div>
        <form className="form-row" onSubmit={doIssue}>
          <input placeholder="cert_id" value={cert} onChange={(e) => setCert(e.target.value)} />
          <input placeholder="identity" value={identity} onChange={(e) => setIdentity(e.target.value)} />
          <input placeholder="via (optional)" value={via} onChange={(e) => setVia(e.target.value)} />
          <button className="primary" type="submit" disabled={!org}>Issue</button>
        </form>
        <form className="form-row" onSubmit={doRevoke}>
          <input placeholder="cert_id to revoke" value={revoke} onChange={(e) => setRevoke(e.target.value)} />
          <button type="submit" disabled={!org}>Revoke</button>
        </form>
      </section>

      <section className="panel">
        <div className="panel-head"><h3>Recovery</h3></div>
        <p className="muted" style={{ marginTop: 0 }}>
          Council-authorized fork: paste the <code>{`{timeline, commit}`}</code> artifact
          produced by <code>to-council recover</code>. The gateway verifies the FROST
          threshold signature against its council anchor before adopting.
        </p>
        <div className="form-row">
          <textarea
            rows={3}
            placeholder='{"timeline": {...}, "commit": {...}}'
            value={shards}
            onChange={(e) => setShards(e.target.value)}
            style={{ flex: 3, minWidth: 240 }}
          />
          <button onClick={doRecover} disabled={!org}>Recover</button>
        </div>
      </section>

      <div className="grid dash" style={{ marginTop: 6 }}>
        <section className="panel">
          <div className="panel-head">
            <h3>Signed timeline</h3>
            <select value={tlimit} onChange={(e) => setTlimit(parseInt(e.target.value, 10))}>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
            </select>
          </div>
          <Timeline events={events} limit={40} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h3>Trust graph · blast radius</h3>
            <span className="muted" style={{ fontSize: 11 }}>
              {graph.data ? `${graph.data.nodes.length} nodes` : "—"}
            </span>
          </div>
          {graph.data ? (
            <TrustGraphSVG graph={graph.data} affected={affected} width={480} />
          ) : (
            <p className="muted">no issuance edges</p>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel-head"><h3>Verification key</h3></div>
        <p className="muted" style={{ marginTop: 0 }}>
          The org timeline's Ed25519 public key — verify signatures without trusting the gateway.
        </p>
        {pubkey.data ? (
          <div className="hash" style={{ wordBreak: "break-all" }}>{pubkey.data.pubkey_hex}</div>
        ) : (
          <p className="muted">no key</p>
        )}
      </section>

      <section className="panel">
        <div className="panel-head"><h3>Trust state</h3></div>
        <table>
          <thead>
            <tr>
              <th>cert</th>
              <th>identity</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {certs.map(([id, c]) => (
              <tr key={id}>
                <td>{id}</td>
                <td>{c.identity}</td>
                <td className={c.revoked ? "err" : "ok"}>{c.revoked ? "revoked" : "valid"}</td>
              </tr>
            ))}
            {certs.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">no certs</td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </>
  );
}