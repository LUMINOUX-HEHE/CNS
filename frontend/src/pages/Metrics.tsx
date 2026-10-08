import { useMemo } from "react";
import { api } from "../api";
import { useAsync, Flash, PageHead } from "../lib";
import { StatTile, Sparkline } from "../viz";
import type { OrgSummary } from "../types";

// Prometheus text is line-oriented: name{labels} value. We only need the
// totals and the per-org event/detection/recovery counters for the tiles.
function parseProm(text: string): {
  totals: Record<string, number>;
  byOrg: Record<string, Record<string, number>>;
} {
  const totals: Record<string, number> = {};
  const byOrg: Record<string, Record<string, number>> = {};
  for (const line of text.split("\n")) {
    const m = line.match(/^([a-z_]+)(?:\{org="([^"]+)"\})?\s+(\d+)/i);
    if (!m) continue;
    const [, name, org, val] = m;
    const v = parseInt(val, 10);
    if (org) {
      (byOrg[org] ||= {})[name] = v;
    } else {
      totals[name] = v;
    }
  }
  return { totals, byOrg };
}

export default function Metrics() {
  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const raw = useAsync<string>(() => api.get<string>("/v1/metrics"), []);

  const parsed = useMemo(
    () => parseProm(typeof raw.data === "string" ? raw.data : ""),
    [raw.data]
  );
  const t = parsed.totals;
  const orgIDs = Object.keys(parsed.byOrg);

  return (
    <>
      <PageHead title="Metrics">
        <button onClick={() => { orgs.reload(); raw.reload(); }}>Refresh</button>
      </PageHead>
      {orgs.errMsg && <Flash msg={orgs.errMsg} kind="err" />}
      {raw.errMsg && <Flash msg={raw.errMsg} kind="err" />}

      <div className="grid cols-4 stagger" style={{ marginBottom: 14 }}>
        <StatTile k="Uptime" v={`${Math.floor((t.to_uptime_seconds || 0) / 60)}m`} sub={`${t.to_uptime_seconds || 0}s`} />
        <StatTile k="Users" v={t.to_users ?? 0} tone="info" />
        <StatTile k="Orgs" v={t.to_orgs ?? 0} />
        <StatTile k="Audit entries" v={t.to_audit_entries ?? 0} />
      </div>

      <h3>Per-org counters</h3>
      <div className="cards stagger">
        {orgIDs.map((id) => {
          const o = parsed.byOrg[id] || {};
          const events = o.to_events_total || 0;
          const issues = o.to_issues_total || 0;
          const revokes = o.to_revokes_total || 0;
          const detections = o.to_detections_total || 0;
          const recoveries = o.to_recoveries_total || 0;
          const name = (orgs.data?.orgs || []).find((x) => x.id === id)?.name || id;
          return (
            <div key={id} className="card">
              <h3>{name}</h3>
              <div className="stat" style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <span>events <b>{events}</b></span>
                <span>issues <b>{issues}</b></span>
                <span>revokes <b>{revokes}</b></span>
                <span className={detections ? "err" : ""}>detections <b>{detections}</b></span>
                <span>recoveries <b>{recoveries}</b></span>
              </div>
              <Sparkline
                points={[issues, revokes, detections, recoveries, events]}
                ariaLabel={`${name} counter mix`}
              />
            </div>
          );
        })}
        {orgIDs.length === 0 && <p className="muted">No metrics yet.</p>}
      </div>

      <h3>Raw /v1/metrics (Prometheus text)</h3>
      <pre>{typeof raw.data === "string" ? raw.data : ""}</pre>
    </>
  );
}