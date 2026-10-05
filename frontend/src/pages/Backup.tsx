import { useRef, useState } from "react";
import { api } from "../api";
import { Flash, PageHead } from "../lib";
import type { BackupInfo } from "../types";

export default function Backup() {
  const [info, setInfo] = useState<BackupInfo | null>(null);
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });
  const file = useRef<HTMLInputElement>(null);

  async function create() {
    try {
      const d = await api.post<BackupInfo>("/v1/backup");
      setInfo(d);
      setMsg({ m: "backup created", k: "ok" });
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
            <a href={info.download} download="backup.json">
              download
            </a>
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
    </>
  );
}