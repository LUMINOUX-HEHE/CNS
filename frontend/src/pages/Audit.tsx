import { useState } from "react";
import { api } from "../api";
import { ts, short, Flash, PageHead } from "../lib";
import { EventChip } from "../viz";
import type { AuditEvent } from "../types";

interface ActionRow {
  ts: number;
  user: string;
  method: string;
  path: string;
  status: number;
  org?: string;
}

export default function Audit() {
  const [source, setSource] = useState<"events" | "actions">("events");
  const [org, setOrg] = useState("");
  const [type, setType] = useState("");
  const [identity, setIdentity] = useState("");
  const [cert, setCert] = useState("");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [actions, setActions] = useState<ActionRow[]>([]);
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });

  async function search(e?: React.FormEvent) {
    e?.preventDefault();
    const q = new URLSearchParams();
    if (org) q.set("org", org);
    if (type) q.set("type", type);
    if (identity) q.set("identity", identity);
    if (cert) q.set("cert", cert);
    q.set("limit", "200");
    try {
      if (source === "actions") {
        q.set("source", "actions");
        const d = await api.get<{ actions: ActionRow[] }>("/v1/audit?" + q);
        setActions(d.actions || []);
        setEvents([]);
        setMsg({ m: `${d.actions?.length ?? 0} actions`, k: "ok" });
      } else {
        const d = await api.get<{ events: AuditEvent[] }>("/v1/audit?" + q);
        setEvents(d.events || []);
        setActions([]);
        setMsg({ m: `${d.events?.length ?? 0} events`, k: "ok" });
      }
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  return (
    <>
      <PageHead title="Audit search">
        <select
          value={source}
          onChange={(e) => setSource(e.target.value as "events" | "actions")}
        >
          <option value="events">timeline events</option>
          <option value="actions">operator actions</option>
        </select>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      <form className="form-row" onSubmit={search}>
        <input placeholder="org" value={org} onChange={(e) => setOrg(e.target.value)} />
        {source === "events" && (
          <>
            <input placeholder="type" value={type} onChange={(e) => setType(e.target.value)} />
            <input
              placeholder="identity"
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
            />
            <input placeholder="cert_id" value={cert} onChange={(e) => setCert(e.target.value)} />
          </>
        )}
        <button className="primary" type="submit">
          Search
        </button>
      </form>

      {source === "actions" ? (
        <table>
          <thead>
            <tr>
              <th>ts</th>
              <th>user</th>
              <th>method</th>
              <th>path</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((a, i) => (
              <tr key={i}>
                <td>{ts(a.ts)}</td>
                <td>{a.user}</td>
                <td>{a.method}</td>
                <td className="hash">{a.path}</td>
                <td className={a.status >= 400 ? "err" : "ok"}>{a.status}</td>
              </tr>
            ))}
            {actions.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  no actions
                </td>
              </tr>
            )}
          </tbody>
        </table>
      ) : (
        <table>
          <thead>
            <tr>
              <th>org</th>
              <th>type</th>
              <th>ts</th>
              <th>cert</th>
              <th>identity</th>
              <th>hash</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i}>
                <td>{e.org}</td>
                <td><EventChip type={e.type} /></td>
                <td>{ts(e.ts)}</td>
                <td>{e.cert_id || ""}</td>
                <td>{e.identity || ""}</td>
                <td className="hash">{short(e.hash)}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  no results
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </>
  );
}