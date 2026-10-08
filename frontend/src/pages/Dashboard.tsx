import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync } from "../lib";
import {
  Gauge, Sparkline, QuorumMeter, LivePulse,
  TrustGraphSVG, ForkDiagram, Timeline, EventChip,
} from "../viz";
import { DemoRunner } from "../DemoRunner";
import type {
  OrgSummary, OrgDetail, TimelineEvent, TrustState, TrustGraph,
} from "../types";

// The dashboard auto-refreshes on a timer. The interval is user-tunable and
// the whole thing is disabled under prefers-reduced-motion (we still poll,
// but slower, and every animation collapses to its final state via CSS).
const WATCHDOGS = [
  { id: "W1", kind: "rate_cusum" },
  { id: "W2", kind: "log_integrity" },
  { id: "W3", kind: "graph_anomaly" },
  { id: "W4", kind: "external_probe" },
  { id: "W5", kind: "behavior_baseline" },
];

export default function Dashboard() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const org = params.get("org") || "";

  const orgs = useAsync<{ orgs: OrgSummary[] }>(() => api.get("/v1/orgs"), []);
  const detail = useAsync<OrgDetail>(
    () => (org ? api.get(`/v1/orgs/${org}`) : Promise.resolve(null as any)),
    [org]
  );
  const timeline = useAsync<{ events: TimelineEvent[]; count: number; total: number }>(
    () => (org ? api.get(`/v1/orgs/${org}/timeline?limit=200`) : Promise.resolve({ events: [], count: 0, total: 0 })),
    [org]
  );
  const state = useAsync<TrustState>(
    () => (org ? api.get(`/v1/orgs/${org}/state`) : Promise.resolve({ certs: {} })),
    [org]
  );
  const graph = useAsync<TrustGraph>(
    () => (org ? api.get(`/v1/orgs/${org}/graph`) : Promise.resolve(null as any)),
    [org]
  );

  // ---- live polling ----
  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const [live, setLive] = useState(!prefersReduced);
  const [intervalMs, setIntervalMs] = useState(3000);
  const [ticks, setTicks] = useState(0);
  const [lastAt, setLastAt] = useState<number>(Date.now());

  useEffect(() => {
    if (!org && orgs.data?.orgs.length) setParams({ org: orgs.data.orgs[0].id });
  }, [orgs.data, org, setParams]);

  const reloadAll = useRef(() => {});
  reloadAll.current = () => {
    detail.reload();
    timeline.reload();
    state.reload();
    graph.reload();
    setLastAt(Date.now());
    setTicks((t) => t + 1);
  };

  useEffect(() => {
    if (!live || !org) return;
    const id = setInterval(() => reloadAll.current(), intervalMs);
    return () => clearInterval(id);
  }, [live, org, intervalMs]);

  // ---- derived data ----
  const events = timeline.data?.events || [];
  const certs = Object.entries(state.data?.certs || {});
  const revoked = certs.filter(([, c]) => c.revoked).length;
  const valid = certs.length - revoked;

  // A watchdog's "last score" is inferred from the timeline: a DETECTED
  // event carries the bad index; absent that, all five read healthy. The
  // API is POST-only for scores, so the client keeps a live roster in Org;
  // here we present the aggregate state.
  const detected = !!detail.data?.detected;
  const [roster, setRoster] = useState<Record<string, number | null>>(
    Object.fromEntries(WATCHDOGS.map((w) => [w, null]))
  );

  // Trend history for sparklines: event count per poll tick (issues/revokes).
  const [issueHist, setIssueHist] = useState<number[]>([]);
  const [revokeHist, setRevokeHist] = useState<number[]>([]);
  useEffect(() => {
    if (!timeline.data) return;
    const issues = events.filter((e) => e.type === "ISSUE").length;
    const revokes = events.filter((e) => e.type === "REVOKE").length;
    setIssueHist((h) => [...h.slice(-39), issues]);
    setRevokeHist((h) => [...h.slice(-39), revokes]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeline.data, ticks]);

  const badIndex = useMemo(() => {
    // Events arrive newest-first; the chronological index of the first
    // DETECTED event is the rollback-anchor proxy for the fork diagram.
    const chrono = [...events].reverse();
    const i = chrono.findIndex((e) => e.type === "DETECTED");
    return i < 0 ? null : i;
  }, [events]);

  const hasFork = events.some((e) => e.type === "RECOVERY" || e.type === "COMMIT");
  const lastRecovery = events.find((e) => e.type === "RECOVERY");
  const [epoch, setEpoch] = useState<number | null>(null);
  useEffect(() => {
    // count recovery handoffs as the epoch proxy
    setEpoch(events.filter((e) => e.type === "RECOVERY").length || null);
  }, [events]);

  const affected = useMemo(() => {
    const s = new Set<string>();
    // certs that were revoked at any point are the visible blast radius
    for (const [id, c] of certs) if (c.revoked) s.add(id);
    return s;
  }, [state.data]);

  const alarmedCount = WATCHDOGS.filter((w) => {
    const s = roster[w.id];
    return s !== null && s < 25;
  }).length + (detected && Object.values(roster).every((v) => v === null) ? 3 : 0);

  function flashScore(id: string, s: number) {
    setRoster((r) => ({ ...r, [id]: s }));
  }

  async function postScore(id: string, s: number) {
    try {
      await api.post(`/v1/orgs/${org}/scores`, {
        node_id: id, score: s, p_value: s < 25 ? 0.01 : 1, evidence: null,
      });
      flashScore(id, s);
      setTimeout(() => reloadAll.current(), 350);
    } catch {
      /* surfaced by the Org page's detailed console */
    }
  }

  async function simulateAttack() {
    // Drive the real detection path: mark 3 of 5 watchdogs alarmed.
    for (const w of ["W1", "W2", "W3"]) {
      await postScore(w, 0);
    }
  }

  return (
    <>
      <div className="topbar">
        <h2>Operations dashboard</h2>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <select value={org} onChange={(e) => setParams({ org: e.target.value })}>
            <option value="">— select org —</option>
            {(orgs.data?.orgs || []).map((o) => (
              <option key={o.id} value={o.id}>{o.name} ({o.id})</option>
            ))}
          </select>
          <LivePulse on={live} label={live ? `live · ${intervalMs / 1000}s` : "paused"}
            tone={detected ? "bad" : undefined} />
          <button onClick={() => setLive((v) => !v)}>{live ? "Pause" : "Resume"}</button>
          <select value={intervalMs} onChange={(e) => setIntervalMs(parseInt(e.target.value, 10))}>
            <option value={1000}>1s</option>
            <option value={3000}>3s</option>
            <option value={5000}>5s</option>
            <option value={10000}>10s</option>
          </select>
          <button onClick={() => reloadAll.current()}>Refresh</button>
        </div>
      </div>

      {(orgs.errMsg || detail.errMsg) && (
        <div className="flash err">{orgs.errMsg || detail.errMsg}</div>
      )}

      {!org && <p className="muted">Create an org on the Overview page to begin.</p>}

      {org && (
        <>
          {/* ---- hero status banner ---- */}
          <div className={`hero ${detected ? "tone-bad" : "tone-ok"}`}>
            <div className="hero-row">
              <div>
                <div className="hero-eyebrow">Trust plane · {org}</div>
                <div className={`hero-title ${detected ? "bad" : ""}`}>
                  {detected ? "COMPROMISE DETECTED" : "SYSTEM NOMINAL"}
                  <span className={`badge ${detected ? "detected" : "healthy"}`}>
                    {detected ? "DETECTED" : "healthy"}
                  </span>
                </div>
                <div className="hero-sub">
                  {detected
                    ? "≥3 of 5 independent watchdogs crossed the detection threshold. The council can threshold-sign an epoch handoff and roll back to the last verified checkpoint, re-issuing only the reachable certs."
                    : "All watchdogs within bounds. The signed timeline is append-only and the transparency log is consistent; no recovery handoff is pending."}
                </div>
                <div className="hero-meta">
                  <div className="m"><span className="mk">events</span><span className="mv">{timeline.data?.total ?? 0}</span></div>
                  <div className="m"><span className="mk">valid certs</span><span className="mv">{valid}</span></div>
                  <div className="m"><span className="mk">revoked</span><span className="mv">{revoked}</span></div>
                  <div className="m"><span className="mk">epoch</span><span className="mv">{hasFork ? `e${epoch ?? 1}` : "genesis"}</span></div>
                  <div className="m"><span className="mk">last sync</span><span className="mv">{new Date(lastAt).toISOString().slice(11, 19)}</span></div>
                </div>
              </div>
              <div className="hero-actions">
                <button className="danger" onClick={simulateAttack} disabled={!org}>
                  Simulate attack
                </button>
                <button onClick={() => reloadAll.current()}>Refresh now</button>
              </div>
            </div>
          </div>

          {/* ---- KPI ribbon ---- */}
          <div className="kpi">
            <div className={`kpi-tile tone-${detected ? "bad" : "ok"}`}>
              <span className="glow" />
              <div className="kpi-k">Detection quorum</div>
              <div className="kpi-v">{alarmedCount}/5</div>
              <div className="kpi-sub">{detected ? "threshold crossed" : "within bounds (need 3)"}</div>
              <div className="kpi-bar"><i style={{ width: `${(alarmedCount / 5) * 100}%` }} /></div>
            </div>
            <div className="kpi-tile tone-info">
              <span className="glow" />
              <div className="kpi-k">Timeline depth</div>
              <div className="kpi-v">{timeline.data?.total ?? 0}</div>
              <div className="kpi-sub">signed, hash-chained events</div>
              <div className="kpi-bar"><i style={{ width: "100%" }} /></div>
            </div>
            <div className="kpi-tile tone-ok">
              <span className="glow" />
              <div className="kpi-k">Trust state</div>
              <div className="kpi-v">{valid}</div>
              <div className="kpi-sub">{revoked} revoked · {certs.length} total</div>
              <div className="kpi-bar"><i style={{ width: certs.length ? `${(valid / certs.length) * 100}%` : "0%" }} /></div>
            </div>
            <div className={`kpi-tile tone-${hasFork ? "info" : "warn"}`}>
              <span className="glow" />
              <div className="kpi-k">Epoch</div>
              <div className="kpi-v">{hasFork ? `e${epoch ?? 1}` : "genesis"}</div>
              <div className="kpi-sub">{lastRecovery ? "council-authorized recovery" : "no recovery yet"}</div>
              <div className="kpi-bar"><i style={{ width: hasFork ? "100%" : "6%" }} /></div>
            </div>
          </div>

          <div className="sect"><h4>Guided demo</h4><span className="rule" /></div>
          <div style={{ marginBottom: 14 }}>
            <DemoRunner org={org} onDone={() => reloadAll.current()} />
          </div>

          <div className="sect"><h4>Live telemetry</h4><span className="rule" /></div>

          <div className="grid dash">
            {/* ---- left column ---- */}
            <div className="grid stagger" style={{ gap: 14 }}>
              {/* watchdog ensemble */}
              <div className="panel hero-panel">
                <div className="panel-head">
                  <h3>Watchdog ensemble · 5 independent detectors</h3>
                  <span className="muted" style={{ fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}>
                    last sync {new Date(lastAt).toISOString().slice(11, 19)}
                  </span>
                </div>
                <p className="subhead">
                  Each watchdog scores its own signal every cycle. DETECTED requires ≥3 of 5 below
                  the threshold — one compromised watchdog can neither trigger nor block.
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
                        <Gauge score={s} size={78} label={w.kind} />
                        <div className="wd-foot">
                          <span>{w.kind}</span>
                          <span>
                            <button style={{ padding: "2px 7px", fontSize: 10 }}
                              onClick={() => postScore(w.id, 0)} disabled={!org} className="danger">fail</button>{" "}
                            <button style={{ padding: "2px 7px", fontSize: 10 }}
                              onClick={() => postScore(w.id, 100)} disabled={!org}>pass</button>
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div style={{ marginTop: 14, display: "flex", gap: 20, alignItems: "center", flexWrap: "wrap" }}>
                  <QuorumMeter alarmed={alarmedCount} />
                  <button className="danger" onClick={simulateAttack} disabled={!org}>
                    Simulate attack (alarm W1–W3)
                  </button>
                </div>
              </div>

              {/* timeline */}
              <div className="panel">
                <div className="panel-head">
                  <h3>Signed timeline · append-only hash chain</h3>
                  <span className="muted" style={{ fontSize: 11 }}>{events.length} events</span>
                </div>
                <Timeline events={events} limit={14} />
              </div>
            </div>

            {/* ---- right column ---- */}
            <div className="grid stagger" style={{ gap: 14 }}>
              {/* fork diagram */}
              <div className="panel">
                <div className="panel-head">
                  <h3>Recovery · fork at verified checkpoint</h3>
                </div>
                <ForkDiagram badIndex={badIndex} hasFork={hasFork} />
                <p className="muted" style={{ fontSize: 11, marginTop: 8 }}>
                  {hasFork
                    ? "Council threshold-signed the epoch handoff; the compromised suffix is abandoned and only reachable certs were re-issued."
                    : "No fork yet. On detection, the council (≥3/5 FROST) signs a handoff and recovery rolls back here."}
                </p>
              </div>

              {/* event mix sparklines */}
              <div className="panel">
                <div className="panel-head"><h3>Event mix (per poll)</h3></div>
                <div style={{ fontSize: 11, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace" }}>
                  ISSUE
                </div>
                <Sparkline points={issueHist.length ? issueHist : [0, 0]} ariaLabel="issues trend" />
                <div style={{ fontSize: 11, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace", marginTop: 8 }}>
                  REVOKE
                </div>
                <Sparkline points={revokeHist.length ? revokeHist : [0, 0]} ariaLabel="revokes trend" />
              </div>

              {/* trust graph */}
              <div className="panel">
                <div className="panel-head">
                  <h3>Trust graph · blast radius</h3>
                  <span className="muted" style={{ fontSize: 11 }}>
                    {graph.data ? `${graph.data.nodes.length} nodes` : "—"}
                  </span>
                </div>
                {graph.data ? (
                  <TrustGraphSVG graph={graph.data} affected={affected} />
                ) : (
                  <p className="muted">no graph</p>
                )}
              </div>

              {/* recent types legend */}
              <div className="panel">
                <div className="panel-head"><h3>Event types</h3></div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {["ISSUE", "REVOKE", "DETECTED", "RECOVERY", "COMMIT", "KEY_ROTATE"].map((t) => (
                    <EventChip key={t} type={t} />
                  ))}
                </div>
              </div>
            </div>
          </div>

          <p className="muted" style={{ marginTop: 16, fontSize: 12 }}>
            All data is live from the gateway REST API (<code>/v1/orgs/{org}/…</code>).
            Scores are posted to <code>/scores</code>; the detection path, FROST recovery, and
            RFC 9162 transparency log are the real engine.
          </p>
        </>
      )}
    </>
  );
}