import { useState } from "react";
import { api } from "../api";
import { useAsync, Flash, PageHead } from "../lib";
import type { UserRow } from "../types";

export default function Users() {
  const res = useAsync<{ users: UserRow[] }>(() => api.get("/v1/users"), []);
  const { data, reload } = res;
  const [id, setId] = useState("");
  const [role, setRole] = useState("operator");
  const [orgs, setOrgs] = useState("");
  const [msg, setMsg] = useState<{ m: string; k: "ok" | "err" | "" }>({ m: "", k: "" });

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!id.trim()) return;
    const list = orgs
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    try {
      const d: any = await api.post("/v1/users", { id: id.trim(), role, orgs: list });
      setMsg({ m: `user ${id} created — token: ${d.token}`, k: "ok" });
      setId("");
      reload();
    } catch (e: any) {
      setMsg({ m: e.message, k: "err" });
    }
  }

  return (
    <>
      <PageHead title="Users">
        <button onClick={reload}>Refresh</button>
      </PageHead>
      <Flash msg={msg.m} kind={msg.k} />
      {res.errMsg && <Flash msg={res.errMsg} kind="err" />}
      <form className="form-row" onSubmit={create}>
        <input placeholder="user id" value={id} onChange={(e) => setId(e.target.value)} />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option>operator</option>
          <option>auditor</option>
          <option>viewer</option>
          <option>admin</option>
        </select>
        <input
          placeholder="orgs (comma, empty=all)"
          value={orgs}
          onChange={(e) => setOrgs(e.target.value)}
        />
        <button className="primary" type="submit">
          Create user
        </button>
      </form>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>role</th>
            <th>orgs</th>
            <th>tokens</th>
          </tr>
        </thead>
        <tbody>
          {(data?.users || []).map((u) => (
            <tr key={u.id}>
              <td>{u.id}</td>
              <td>{u.role}</td>
              <td>{(u.orgs || []).join(", ") || "all"}</td>
              <td>{u.tokens}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}