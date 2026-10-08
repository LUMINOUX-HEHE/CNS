// viz.tsx — data-visualization primitives for the ops console.
// All hand-rolled SVG (no chart library), theme via CSS variables, and every
// colored element is paired with a label or glyph so meaning never relies on
// color alone. Motion respects prefers-reduced-motion (see styles.css).

import type { TimelineEvent, TrustGraph } from "./types";

/* ---------------------------------------------------------------- helpers */

// hue returns the CSS var for a 0..100 watchdog score.
function hueFor(score: number | null): string {
  if (score === null) return "var(--faint)";
  if (score < 25) return "var(--bad-hue)";
  if (score < 60) return "var(--warn-hue)";
  return "var(--ok-hue)";
}

const EVENT_META: Record<string, { cls: string; chip: string; label: string }> = {
  ISSUE: { cls: "t-issue", chip: "c-issue", label: "ISSUE" },
  REVOKE: { cls: "t-revoke", chip: "c-revoke", label: "REVOKE" },
  DETECTED: { cls: "t-detected", chip: "c-detected", label: "DETECTED" },
  RECOVERY: { cls: "t-recovery", chip: "c-recovery", label: "RECOVERY" },
  COMMIT: { cls: "t-commit", chip: "c-commit", label: "COMMIT" },
  KEY_ROTATE: { cls: "t-keyrotate", chip: "c-keyrotate", label: "KEY_ROTATE" },
  KEY_GEN: { cls: "t-keyrotate", chip: "c-keyrotate", label: "KEY_GEN" },
  POLICY_CHANGE: { cls: "", chip: "", label: "POLICY_CHANGE" },
  SHARD_ACTIVITY: { cls: "", chip: "", label: "SHARD_ACTIVITY" },
};

export function eventMeta(type: string) {
  return EVENT_META[type] || { cls: "", chip: "", label: type };
}

/* ----------------------------------------------------------------- gauge */

export function Gauge({
  score,
  size = 84,
  label,
  cap,
}: {
  score: number | null;
  size?: number;
  label?: string;
  cap?: string;
}) {
  const r = (size - 12) / 2;
  const c = 2 * Math.PI * r;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score)) / 100;
  const off = c * (1 - pct);
  const hue = hueFor(score);
  return (
    <div className="gauge">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
        aria-label={`${label || "watchdog"} score ${score === null ? "unknown" : score}`}>
        <circle className="track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={5} />
        <circle
          className="value"
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={hue} strokeWidth={5} strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text className="num" x="50%" y="50%" textAnchor="middle" dy="0.1em">
          {score === null ? "—" : score}
        </text>
        {label && (
          <text className="lbl" x="50%" y="50%" textAnchor="middle" dy={size > 70 ? "1.9em" : "1.6em"}>
            {label}
          </text>
        )}
      </svg>
      {cap && <span className="cap">{cap}</span>}
    </div>
  );
}

/* ------------------------------------------------------------- sparkline */

export function Sparkline({
  points,
  height = 40,
  ariaLabel = "trend",
}: {
  points: number[];
  height?: number;
  ariaLabel?: string;
}) {
  const w = 240;
  const pad = 4;
  const n = Math.max(2, points.length);
  const max = Math.max(1, ...points);
  const min = Math.min(0, ...points);
  const span = max - min || 1;
  const step = (w - pad * 2) / (n - 1);
  const xy = points.map((v, i) => {
    const x = pad + i * step;
    const y = height - pad - ((v - min) / span) * (height - pad * 2);
    return [x, y] as const;
  });
  const line = xy.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${xy[xy.length - 1][0].toFixed(1)},${height - pad} L${xy[0][0].toFixed(1)},${height - pad} Z`;
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" role="img" aria-label={ariaLabel}>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} className="sp-grid" x1={pad} x2={w - pad} y1={height * f} y2={height * f} />
      ))}
      <path className="sp-area" d={area} />
      <path className="sp-line" d={line} />
    </svg>
  );
}

/* ---------------------------------------------------------- quorum meter */

export function QuorumMeter({ alarmed, total = 5 }: { alarmed: number; total?: number }) {
  const quorum = 3;
  const detected = alarmed >= quorum;
  return (
    <div className="quorum" role="img"
      aria-label={`quorum ${alarmed} of ${total} alarmed, threshold ${quorum}, ${detected ? "detected" : "not detected"}`}>
      <div className="segs" aria-hidden="true">
        {Array.from({ length: total }, (_, i) => (
          <span key={i} className={`seg ${i < alarmed ? "on" : "ok"}`} />
        ))}
      </div>
      <div>
        <div className={`verdict ${detected ? "detected" : "clear"}`}>
          {detected ? "DETECTED" : "CLEAR"}
        </div>
        <div className="muted" style={{ fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}>
          {alarmed}/{total} below threshold · quorum {quorum}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------ stat tile */

export function StatTile({
  k,
  v,
  sub,
  tone,
}: {
  k: string;
  v: React.ReactNode;
  sub?: string;
  tone?: "ok" | "warn" | "bad" | "info";
}) {
  return (
    <div className={`stat-tile ${tone ? "tone-" + tone : ""}`}>
      <span className="k">{k}</span>
      <span className="v">{v}</span>
      {sub && <span className="sub">{sub}</span>}
    </div>
  );
}

/* ------------------------------------------------------------- live pulse */

export function LivePulse({
  on,
  label,
  tone,
}: {
  on: boolean;
  label: string;
  tone?: "warn" | "bad";
}) {
  return (
    <span className={`pulse ${on ? "" : "off"} ${on && tone ? tone : ""}`}>
      <span className="ring" />
      {label}
    </span>
  );
}

/* ----------------------------------------------------------- trust graph */

// A layered left-to-right layout: identities in column 0, certs in column 1,
// via-linked certs in column 2. Edges that touch an affected node render red.
export function TrustGraphSVG({
  graph,
  affected = new Set<string>(),
  width = 640,
}: {
  graph: TrustGraph;
  affected?: Set<string>;
  width?: number;
}) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (nodes.length === 0) {
    return <p className="muted">no issuance edges</p>;
  }
  // assign columns: id:* -> 0, cert:* with no via -> 1, else 2
  const viaTargets = new Set(edges.filter((e) => e[0].startsWith("cert:")).map((e) => e[1]));
  const col = (n: string) => (n.startsWith("id:") ? 0 : viaTargets.has(n) ? 2 : 1);
  const byCol: Record<number, string[]> = { 0: [], 1: [], 2: [] };
  for (const n of nodes) byCol[col(n)].push(n);
  const colX = [70, width / 2, width - 90];
  const pos: Record<string, [number, number]> = {};
  for (const c of [0, 1, 2]) {
    const list = byCol[c];
    const gap = 46;
    const y0 = 30 + (Math.max(3, list.length) - list.length) * gap * 0.5;
    list.forEach((n, i) => {
      pos[n] = [colX[c], y0 + i * gap];
    });
  }
  const maxY = Math.max(140, ...Object.values(pos).map(([, y]) => y + 30));
  const label = (n: string) => n.replace(/^(id:|cert:)/, "").slice(0, 14);
  return (
    <div className="graph-wrap">
      <svg className="graph-svg" viewBox={`0 0 ${width} ${maxY}`} role="img"
        aria-label={`trust graph: ${nodes.length} nodes, ${edges.length} edges`}>
        {edges.map((e, i) => {
          const a = pos[e[0]], b = pos[e[1]];
          if (!a || !b) return null;
          const hit = affected.has(e[1].replace("cert:", "")) || affected.has(e[0].replace("cert:", ""));
          const mid = (a[0] + b[0]) / 2;
          return (
            <path key={i} className={`edge ${hit ? "affected" : ""}`}
              d={`M${a[0]},${a[1]} C${mid},${a[1]} ${mid},${b[1]} ${b[0]},${b[1]}`} />
          );
        })}
        {nodes.map((n) => {
          const [x, y] = pos[n];
          const isCert = n.startsWith("cert:");
          const hit = isCert && affected.has(n.replace("cert:", ""));
          return (
            <g key={n} className={`node ${hit ? "affected" : ""}`}>
              <circle cx={x} cy={y} r={7} className={isCert ? "node-cert" : "node-id"}
                fill={isCert ? "var(--info-hue)" : "#fff"} opacity={hit ? 1 : 0.85}
                stroke={hit ? "var(--bad-hue)" : "var(--line-strong)"} strokeWidth={hit ? 2.5 : 1.5} />
              <text className="nlabel" x={x} y={y + 20} textAnchor="middle">{label(n)}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ----------------------------------------------------------- fork diagram */

// Draws the trust timeline as a chain that forks at a checkpoint: the dead
// (compromised) suffix in red dashes, the recovered branch in green, and the
// council handoff node in violet.
export function ForkDiagram({ badIndex, hasFork }: { badIndex: number | null; hasFork: boolean }) {
  const nodes = 7;
  const w = 640, h = 150, y = 54, step = w / (nodes + 1);
  const forkAt = badIndex !== null ? Math.max(0, Math.min(nodes - 1, badIndex)) : nodes - 2;
  const xs = Array.from({ length: nodes }, (_, i) => step * (i + 1));
  return (
    <svg className="fork-svg" viewBox={`0 0 ${w} ${h}`} role="img"
      aria-label={hasFork ? "timeline forked at a verified checkpoint" : "linear timeline"}>
      {/* main chain */}
      <path className="chain good" d={`M${xs[0]},${y} L${xs[forkAt]},${y}`} />
      {hasFork ? (
        <>
          <path className="chain bad" d={`M${xs[forkAt]},${y} L${xs[nodes - 1]},${y}`} />
          {/* recovery branch */}
          <path className="chain good" style={{ animation: "draw 0.9s ease forwards" }}
            d={`M${xs[forkAt]},${y} C${xs[forkAt] + 30},${y} ${xs[forkAt + 2] - 30},${y + 52} ${xs[forkAt + 3]},${y + 52}`} />
        </>
      ) : (
        <path className="chain good" d={`M${xs[0]},${y} L${xs[nodes - 1]},${y}`} />
      )}
      {xs.slice(0, nodes).map((x, i) => {
        const dead = hasFork && i > forkAt;
        return (
          <circle key={i} className={`node ${dead ? "dead" : "alive"}`}
            cx={x} cy={y} r={7} />
        );
      })}
      {hasFork && (
        <>
          <circle className="node handoff" cx={xs[forkAt + 3]} cy={y + 52} r={9} />
          <text x={xs[forkAt + 3]} y={y + 78} textAnchor="middle">FROST handoff ≥3/5</text>
          <text x={xs[forkAt]} y={y - 18} textAnchor="middle">checkpoint</text>
        </>
      )}
      <text x={xs[nodes - 1]} y={y - 18} textAnchor="middle">{hasFork ? "dead suffix" : "verified chain"}</text>
    </svg>
  );
}

/* --------------------------------------------------------------- timeline */

export function Timeline({
  events,
  limit = 12,
  order = "asc",
}: {
  events: TimelineEvent[];
  limit?: number;
  order?: "asc" | "desc";
}) {
  // The API returns events newest-first; a timeline reads oldest→newest, so
  // reverse by default and take the most recent `limit`.
  const chrono = order === "asc" ? [...events].reverse() : events;
  const shown = chrono.slice(Math.max(0, chrono.length - limit));
  if (shown.length === 0) return <p className="muted">no events</p>;
  return (
    <div className="tl">
      {shown.map((e, i) => {
        const m = eventMeta(e.type);
        const body = [
          e.cert_id && `cert=${e.cert_id}`,
          e.identity && `id=${e.identity}`,
          e.via && `via=${e.via}`,
        ].filter(Boolean).join("  ");
        return (
          <div key={i} className={`tl-item ${m.cls}`}>
            <div className="tl-head">
              <span className="tl-type">{m.label}</span>
              <span className="tl-ts">{e.ts ? new Date(e.ts * 1000).toISOString().slice(11, 19) : ""}</span>
            </div>
            {body && <div className="tl-body">{body}</div>}
            {e.hash && <div className="hash">{e.hash.slice(0, 24)}…</div>}
          </div>
        );
      })}
    </div>
  );
}

/* --------------------------------------------------------------- merkle viz */

// A schematic RFC 9162 Merkle tree: leaf row + parent rows converging on a
// root. Purely illustrative of the log's shape; sizes are not to scale.
export function MerkleViz({ size }: { size: number }) {
  const leaves = Math.max(1, Math.min(8, size));
  const w = 520, h = 150;
  const rowY = [h - 22, h - 58, h - 94, 14];
  const leafW = w / leaves;
  const nodes: { x: number; y: number; r: number }[] = [];
  for (let i = 0; i < leaves; i++) nodes.push({ x: leafW * i + leafW / 2, y: rowY[0], r: 5 });
  let prev = nodes.slice();
  let level = 1;
  while (prev.length > 1 && level < rowY.length) {
    const next: { x: number; y: number; r: number }[] = [];
    for (let i = 0; i < prev.length; i += 2) {
      const a = prev[i], b = prev[i + 1] || prev[i];
      next.push({ x: (a.x + b.x) / 2, y: rowY[level], r: 5 });
    }
    for (const n of next) nodes.push(n);
    prev = next;
    level++;
  }
  const root = prev[0];
  return (
    <svg className="graph-svg" viewBox={`0 0 ${w} ${h}`} role="img"
      aria-label={`Merkle tree schematic, ${size} leaves`}>
      {nodes.map((n, i) => (
        <circle key={i} cx={n.x} cy={n.y} r={n.r}
          fill={i === nodes.length - 1 ? "var(--council-hue)" : "var(--info-hue)"}
          opacity={0.85} />
      ))}
      <text x={root.x} y={root.y - 8} textAnchor="middle">root</text>
      <text x={w / 2} y={h - 4} textAnchor="middle">
        illustrative shape · {size} {size === 1 ? "leaf" : "leaves"} in the real log
      </text>
    </svg>
  );
}

/* ------------------------------------------------------------- event chip */

export function EventChip({ type }: { type: string }) {
  const m = eventMeta(type);
  return <span className={`chip ${m.chip}`}>{m.label}</span>;
}