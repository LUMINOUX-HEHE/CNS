import { useRef, useState } from "react";
import { api } from "../api";
import { Flash, PageHead } from "../lib";
import type { BackupInfo } from "../types";

export default function Backup() {
  const [info, setInfo] = useState<BackupInfo | null>(null);
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });
  const file = useRef<HTMLInputElement>(null);
  const [rotateShares, setRotateShares] = useState("");

  async function create() {
    try {
      const d = await api.post<BackupInfo>("/v1/backup");
      setInfo(d);
      setMsg({ m: "backup created", k: "ok" });
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function downloadBackup() {
    if (!info) return;
    try {
      await api.download(info.download, `${info.id}.json`);
      setMsg({ m: "download started", k: "ok" });
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  async function restore() {
    const f = file.current?.files?.[0];
    if (!f) return setMsg({ m: "choose a backup file", k: "err" });
    try {
      const text = await f.text();
      await api.postRaw("/v1/restore", text);
      setMsg({ m: "restored — reload the page", k: "ok" });
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  // Post-compromise KEK rotation: 3-of-5 council shares unwrap the KEK and a
  // new DEK + epoch are minted; old snapshots stop working.
  async function rotate() {
    let parsed: any;
    try {
      parsed = JSON.parse(rotateShares);
    } catch {
      return setMsg({ m: "shares must be JSON", k: "err" });
    }
    if (!Array.isArray(parsed)) {
      return setMsg({ m: "shares must be a JSON array", k: "err" });
    }
    try {
      const d: any = await api.post("/v1/rotate", { shares: parsed });
      setMsg({ m: `rotated — new epoch ${d.epoch}`, k: "ok" });
      setRotateShares("");
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  return (
    <>
      <PageHead title="Backup / Restore" />
      <Flash msg={msg.m} kind={msg.k} />

      <div className="card">
        <h3>Snapshot</h3>
        {info && (
          <div className="stat">
            {info.id} ({info.size} bytes)
          </div>
        )}
        <div className="form-row">
          <button className="primary" onClick={create}>
            Create snapshot
          </button>
          {info && (
            <button onClick={downloadBackup}>Download backup</button>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <h3>Restore from file</h3>
        <div className="form-row">
          <input ref={file} type="file" accept="application/json" />
          <button onClick={restore}>Restore</button>
        </div>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <h3>Rotate vault key (post-compromise)</h3>
        <p className="muted">
          Paste 3-of-5 council KEK shards as a JSON array. A new DEK + epoch are minted;
          old snapshots stop working. Requires the gateway booted with{" "}
          <code>-kek-shares</code>.
        </p>
        <div className="form-row">
          <textarea
            rows={3}
            placeholder='[{"x":1,"y":"123","len":32}, ...]'
            value={rotateShares}
            onChange={(e) => setRotateShares(e.target.value)}
            style={{ flex: 3, minWidth: 240 }}
          />
          <button className="danger" onClick={rotate}>
            Rotate
          </button>
        </div>
      </div>
    </>
  );
}