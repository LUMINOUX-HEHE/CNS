import { useState } from "react";
import { api } from "../api";
import { useAsync, Flash, PageHead } from "../lib";
import type { WebhookRow } from "../types";

export default function Webhooks() {
  const res = useAsync<{ webhooks: WebhookRow[] }>(() => api.get("/v1/webhooks"), []);
  const { data, reload } = res;
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState("");
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return setMsg({ m: "url required", k: "err" });
    const list = events
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    try {
      await api.post("/v1/webhooks", { url: url.trim(), secret, events: list });
      setUrl("");
      setSecret("");
      setEvents("");
      setMsg({ m: "webhook added", k: "ok" });
      reload();
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function remove(id: string) {
    try {
      await api.del("/v1/webhooks/" + id);
      reload();
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  return (
    <>
      <PageHead title="Webhooks">
        <button onClick={reload}>Refresh</button>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      {res.errMsg && <Flash msg={res.errMsg} kind="err" />}
      <form className="form-row" onSubmit={create}>
        <input placeholder="https://..." value={url} onChange={(e) => setUrl(e.target.value)} />
        <input placeholder="secret" value={secret} onChange={(e) => setSecret(e.target.value)} />
        <input
          placeholder="events (comma, empty=all)"
          value={events}
          onChange={(e) => setEvents(e.target.value)}
        />
        <button className="primary" type="submit">
          Add webhook
        </button>
      </form>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>url</th>
            <th>events</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {(data?.webhooks || []).map((w) => (
            <tr key={w.ID}>
              <td className="hash">{w.ID}</td>
              <td>{w.URL}</td>
              <td>{(w.Events || []).join(",") || "all"}</td>
              <td>
                <button className="danger" onClick={() => remove(w.ID)}>
                  delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}