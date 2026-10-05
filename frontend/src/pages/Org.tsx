import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync, ts, short, Flash, PageHead } from "../lib";
import type { OrgSummary, OrgDetail, TimelineEvent, TrustState } from "../types";

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

  // form fields
  const [cert, setCert] = useState("");
  const [identity, setIdentity] = useState("");
  const [via, setVia] = useState("");
  const [revoke, setRevoke] = useState("");
  const [node, setNode] = useState("watchdog-1");
  const [score, setScore] = useState("0");
  const [badIndex, setBadIndex] = useState("");
  const [shards, setShards] = useState("");

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
    let parsed: unknown;
    try {
      parsed = JSON.parse(shards);
    } catch {
      return flash("shards must be JSON", "err");
    }
    try {
      const d: any = await api.post(`/v1/orgs/${org}/recover`, { shards: parsed });
      flash(
        `recovered: epoch ${d.epoch}, ${d.issued?.length ?? 0} re-issued, verify=${d.verify}`,
        d.verify ? "ok" : "err"
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
        <h3>Watchdog scores</h3>
        <p className="muted">
          Post node scores; ≥3/5 below threshold raises a DETECTED verdict.
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
            Post score
          </button>
        </form>
      </section>

      <section>
        <h3>Recovery</h3>
        <p className="muted">Council-authorized fork: paste shards JSON.</p>
        <div className="form-row">
          <textarea
            rows={3}
            placeholder='[{"x":1,"y":"...","len":32}, ...]'
            value={shards}
            onChange={(e) => setShards(e.target.value)}
            style={{ flex: 3, minWidth: 240 }}
          />
          <button onClick={doRecover} disabled={!org}>
            Recover
          </button>
        </div>
      </section>

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