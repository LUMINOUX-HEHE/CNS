import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAsync, ts, Flash, PageHead, Spinner } from "../lib";
import { StatTile } from "../viz";
import type { OrgSummary } from "../types";

export default function Overview() {
  const nav = useNavigate();
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });
  const res = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const { data, reload } = res;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      await api.post("/v1/orgs", { name: name.trim() });
      setName("");
      setMsg({ m: "org created", k: "ok" });
      reload();
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  const orgs = data?.orgs || [];
  const detected = orgs.filter((o) => o.detected).length;
  const totalEvents = orgs.reduce((s, o) => s + o.events, 0);

  return (
    <>
      <PageHead title="Overview">
        <button onClick={reload}>Refresh</button>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      {res.errMsg && <Flash msg={res.errMsg} kind="err" />}
      <Spinner show={res.loading && !data} label="loading orgs…" />

      <div className="grid cols-3 stagger" style={{ marginBottom: 14 }}>
        <StatTile k="Organizations" v={orgs.length} sub="tenants" />
        <StatTile k="Timeline events" v={totalEvents} sub="across all orgs" />
        <StatTile
          k="Compromised"
          v={detected}
          tone={detected > 0 ? "bad" : "ok"}
          sub={detected > 0 ? "requires recovery" : "all healthy"}
        />
      </div>

      <form className="form-row" onSubmit={create}>
        <input
          placeholder="new org name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button className="primary" type="submit">
          Create org
        </button>
      </form>

      <div className="cards stagger">
        {orgs.map((o) => (
          <div
            key={o.id}
            className="card clickable"
            onClick={() => nav("/org?org=" + encodeURIComponent(o.id))}
          >
            <h3>
              {o.name} <span className="hash">{o.id}</span>
            </h3>
            <div>
              <span className={`badge ${o.detected ? "detected" : "healthy"}`}>
                {o.detected ? "DETECTED" : "healthy"}
              </span>
            </div>
            <div className="stat">
              {o.events} events · created {ts(o.created).slice(0, 10)}
            </div>
          </div>
        ))}
        {data && orgs.length === 0 && (
          <p className="muted">No orgs yet — create one to start.</p>
        )}
      </div>
    </>
  );
}