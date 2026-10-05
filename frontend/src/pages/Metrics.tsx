import { api } from "../api";
import { useAsync, Flash, PageHead } from "../lib";
import type { OrgSummary } from "../types";

export default function Metrics() {
  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const raw = useAsync<string>(() => api.get<string>("/v1/metrics"), []);

  return (
    <>
      <PageHead title="Metrics">
        <button onClick={() => { orgs.reload(); raw.reload(); }}>Refresh</button>
      </PageHead>
      {orgs.errMsg && <Flash msg={orgs.errMsg} kind="err" />}
      {raw.errMsg && <Flash msg={raw.errMsg} kind="err" />}

      <div className="cards">
        {(orgs.data?.orgs || []).map((o) => (
          <div key={o.id} className="card">
            <h3>{o.name}</h3>
            <div className="stat">
              {o.events} events · {o.detected ? "DETECTED" : "healthy"}
            </div>
          </div>
        ))}
      </div>

      <h3>Raw /v1/metrics (Prometheus text)</h3>
      <pre>{typeof raw.data === "string" ? raw.data : ""}</pre>
    </>
  );
}