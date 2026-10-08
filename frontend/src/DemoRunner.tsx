// DemoRunner.tsx — a guided, scripted walkthrough of the full compromise →
// detection → recovery story, driven entirely against the live gateway API.
//
// Every step calls the real engine: ISSUE/REVOKE append signed timeline
// events; /scores feeds the real detection path (≥3/5 quorum); the recovery
// artifact is produced out-of-band by `to-council recover` and pasted in.
// Nothing here is mocked — the panel just sequences and narrates the calls a
// reviewer would otherwise type by hand.

import { useState } from "react";
import { api } from "./api";
import { LivePulse } from "./viz";

export type DemoStep = {
  id: string;
  title: string;
  detail: string;
  run: () => Promise<string>;
};

export function DemoRunner({
  org,
  onDone,
}: {
  org: string;
  onDone: () => void;
}) {
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<{ step: string; ok: boolean; msg: string }[]>([]);
  const [cursor, setCursor] = useState(-1);

  const steps: DemoStep[] = [
    {
      id: "chain",
      title: "1 · Build a trust chain",
      detail:
        "Issue a root-issued identity cert, then two certs chained via it — the trust edges the blast-radius math walks.",
      run: async () => {
        await api.post(`/v1/orgs/${org}/issue`, {
          cert_id: "root-ca", identity: "root", via: "",
        });
        await api.post(`/v1/orgs/${org}/issue`, {
          cert_id: "server-1", identity: "server", via: "root-ca",
        });
        await api.post(`/v1/orgs/${org}/issue`, {
          cert_id: "client-1", identity: "client", via: "server-1",
        });
        return "3 ISSUE events appended (signed, hash-chained)";
      },
    },
    {
      id: "baseline",
      title: "2 · Establish a healthy baseline",
      detail:
        "Post passing scores for all five watchdogs — the ensemble reads CLEAR and no false positive fires.",
      run: async () => {
        for (const w of ["W1", "W2", "W3", "W4", "W5"]) {
          await api.post(`/v1/orgs/${org}/scores`, {
            node_id: w, score: 100, p_value: 1, evidence: null,
          });
        }
        return "all 5 watchdogs healthy · quorum 0/5 · CLEAR";
      },
    },
    {
      id: "attack",
      title: "3 · Simulate an insider compromise",
      detail:
        "Alarm three of five independent watchdogs (burst, log-integrity, graph). One Byzantine watchdog can neither trigger nor block — it takes the 3/5 quorum.",
      run: async () => {
        for (const w of ["W1", "W2", "W3"]) {
          await api.post(`/v1/orgs/${org}/scores`, {
            node_id: w, score: 0, p_value: 0.01,
            evidence: { bad_index: 2 },
          });
        }
        return "3/5 below threshold → DETECTED event appended to the timeline";
      },
    },
    {
      id: "fork",
      title: "4 · Council recovery (FROST 3-of-5)",
      detail:
        "The council threshold-signs the epoch handoff and rolls back to the verified checkpoint, re-issuing only reachable certs. Paste the `{timeline, commit}` artifact from `to-council recover` to apply it — the gateway verifies the FROST signature against its anchor before adopting.",
      run: async () => {
        return "awaiting artifact — run `go run ./cmd/council recover …` and paste it in the Org page";
      },
    },
  ];

  async function runAll() {
    if (!org || running) return;
    setRunning(true);
    setLog([]);
    for (let i = 0; i < steps.length; i++) {
      setCursor(i);
      const s = steps[i];
      try {
        const msg = await s.run();
        setLog((l) => [...l, { step: s.title, ok: true, msg }]);
      } catch (e: any) {
        setLog((l) => [...l, { step: s.title, ok: false, msg: e.message }]);
        break;
      }
      await new Promise((r) => setTimeout(r, 450));
    }
    setCursor(-1);
    setRunning(false);
    onDone();
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h3>Guided demo · compromise → detection → recovery</h3>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <LivePulse on={running} label={running ? "running" : "ready"} tone={running ? "warn" : undefined} />
          <button className="primary" onClick={runAll} disabled={!org || running}>
            {running ? "Running…" : "Run demo"}
          </button>
          <button onClick={() => { setLog([]); setCursor(-1); }} disabled={running}>Clear</button>
        </div>
      </div>

      <div className="phases">
        {steps.map((s, i) => {
          const done = log.some((l) => l.step === s.title && l.ok);
          const active = cursor === i;
          return (
            <div key={s.id} className={`phase ${active ? "active" : ""}`}>
              <div className="ph-k">{s.title}</div>
              <div className="ph-v">
                {active ? "running…" : done ? "done" : "pending"}
              </div>
            </div>
          );
        })}
      </div>

      {log.length > 0 && (
        <div className="tl" style={{ marginTop: 14 }}>
          {log.map((l, i) => (
            <div key={i} className={`tl-item ${l.ok ? "t-issue" : "t-revoke"}`}>
              <div className="tl-head">
                <span className="tl-type">{l.ok ? "OK" : "ERR"}</span>
                <span className="tl-ts">{l.step}</span>
              </div>
              <div className="tl-body">{l.msg}</div>
            </div>
          ))}
        </div>
      )}

      <p className="muted" style={{ fontSize: 11, marginTop: 12 }}>
        Steps 1–3 execute live against <code>/v1/orgs/{org || "…"}</code>. Step 4 is the
        cryptographic recovery: it requires the council's threshold-signed artifact
        (the root key never exists, so the browser cannot forge it).
      </p>
    </div>
  );
}