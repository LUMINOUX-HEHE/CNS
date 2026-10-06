import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync, ts, short, Flash, PageHead } from "../lib";
import type {
  OrgSummary,
  OrgDetail,
  TimelineEvent,
  TrustState,
  OrgPubKey,
  TrustGraph,
} from "../types";

export default function OrgPage() {
  const [params, setParams] = useSearchParams();
  const org = params.get("org") || "";
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });

  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const detail = useAsync<OrgDetail>(
    () => (org ? api.get(`/v1/orgs/${org}`) : Promise.resolve(null as any)),
    [org]
  );
  const timeline = useAsync<{ events: TimelineEvent[] }>(
    () => (org ? api.get(`/v1/orgs/${org}/timeline?limit=100`) : Promise.resolve({ events: [] })),
    [org]
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
    // reload is a stable function declaration (hoisted)
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
  const WATCHDOGS = ["W1", "W2", "W3", "W4", "W5"];
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

  return (
    <>
      <PageHead title="Org">
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
        <h3>
          {detail.data.name}{" "}
          <span className={`badge ${detail.data.detected ? "detected" : "healthy"}`}>
            {detail.data.detected ? "DETECTED" : "healthy"}
          </span>
        </h3>
      )}

      <section>
        <h3>Issue / Revoke</h3>
        <form className="form-row" onSubmit={doIssue}>
          <input placeholder="cert_id" value={cert} onChange={(e) => setCert(e.target.value)} />
          <input
            placeholder="identity"
            value={identity}
            onChange={(e) => setIdentity(e.target.value)}
          />
          <input placeholder="via (optional)" value={via} onChange={(e) => setVia(e.target.value)} />
          <button className="primary" type="submit" disabled={!org}>
            Issue
          </button>
        </form>
        <form className="form-row" onSubmit={doRevoke}>
          <input
            placeholder="cert_id to revoke"
            value={revoke}
            onChange={(e) => setRevoke(e.target.value)}
          />
          <button type="submit" disabled={!org}>
            Revoke
          </button>
        </form>
      </section>

      <section>
        <h3>Watchdog ensemble</h3>
        <p className="muted">
          Five independent watchdogs (threshold 25). DETECTED iff ≥3 of 5 score below
          threshold. Click a node to post a passing (100) or failing (0) score.
        </p>
        <table>
          <thead>
            <tr>
              <th>node</th>
              <th>kind</th>
              <th>last score</th>
              <th>verdict</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {WATCHDOGS.map((w, i) => {
              const s = roster[w];
              const bad = s !== null && s < 25;
              return (
                <tr key={w}>
                  <td>{w}</td>
                  <td className="muted">
                    {["rate_cusum", "log_integrity", "graph_anomaly", "external_probe", "behavior_baseline"][i]}
                  </td>
                  <td>{s === null ? "—" : s}</td>
                  <td className={bad ? "err" : s === null ? "muted" : "ok"}>
                    {s === null ? "no data" : bad ? "alarmed" : "healthy"}
                  </td>
                  <td>
                    <button onClick={() => postScore(w, 0)} disabled={!org} className="danger">
                      fail
                    </button>{" "}
                    <button onClick={() => postScore(w, 100)} disabled={!org}>
                      pass
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="muted">
          quorum: {WATCHDOGS.filter((w) => roster[w] !== null && (roster[w] as number) < 25).length}/3
          {" · "}
          {WATCHDOGS.filter((w) => roster[w] !== null && (roster[w] as number) < 25).length >= 3
            ? "DETECTED"
            : "not detected"}
        </p>

        <form className="form-row" onSubmit={doScore}>
          <input placeholder="node_id" value={node} onChange={(e) => setNode(e.target.value)} />
          <input
            type="number"
            placeholder="score"
            value={score}
            onChange={(e) => setScore(e.target.value)}
          />
          <input
            type="number"
            placeholder="bad_index (optional)"
            value={badIndex}
            onChange={(e) => setBadIndex(e.target.value)}
          />
          <button className="primary" type="submit" disabled={!org}>
            Post custom score
          </button>
        </form>
      </section>

      <section>
        <h3>Recovery</h3>
        <p className="muted">
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
          <button onClick={doRecover} disabled={!org}>
            Recover
          </button>
        </div>
      </section>

      <section>
        <h3>Verification key</h3>
        <p className="muted">
          The org timeline's Ed25519 public key — verify signatures without trusting the gateway.
        </p>
        {pubkey.data ? (
          <div className="hash" style={{ wordBreak: "break-all" }}>
            {pubkey.data.pubkey_hex}
          </div>
        ) : (
          <p className="muted">no key</p>
        )}
      </section>

      <h3>Trust graph</h3>
      <p className="muted">
        Issuance edges: a certificate issued "via" another. Reachability defines the rollback
        blast radius.
      </p>
      <table>
        <thead>
          <tr>
            <th>from</th>
            <th>to</th>
          </tr>
        </thead>
        <tbody>
          {(graph.data?.edges || []).map((e, i) => (
            <tr key={i}>
              <td className="hash">{e[0]}</td>
              <td className="hash">{e[1]}</td>
            </tr>
          ))}
          {(!graph.data || graph.data.edges.length === 0) && (
            <tr>
              <td colSpan={2} className="muted">
                no issuance edges
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <h3>Timeline</h3>
      <table>
        <thead>
          <tr>
            <th>type</th>
            <th>ts</th>
            <th>cert</th>
            <th>identity</th>
            <th>via</th>
            <th>hash</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i}>
              <td>{e.type}</td>
              <td>{ts(e.ts)}</td>
              <td>{e.cert_id || ""}</td>
              <td>{e.identity || ""}</td>
              <td>{e.via || ""}</td>
              <td className="hash">{short(e.hash)}</td>
            </tr>
          ))}
          {events.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                no events
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <h3>Trust state</h3>
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
              <td>{c.Identity}</td>
              <td className={c.Revoked ? "err" : "ok"}>
                {c.Revoked ? "revoked" : "valid"}
              </td>
            </tr>
          ))}
          {certs.length === 0 && (
            <tr>
              <td colSpan={3} className="muted">
                no certs
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}