import { useCallback, useEffect, useState } from "react";

// useAsync runs an async loader on mount and exposes a reload() + errMsg.
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [errMsg, setErrMsg] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const run = useCallback(async () => {
    setLoading(true);
    setErrMsg("");
    try {
      setData(await fn());
    } catch (e: any) {
      setErrMsg(e.message || String(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    run();
  }, [run]);
  return { data, errMsg, loading, reload: run, setData };
}

export function short(hash: string, n = 16) {
  return hash ? hash.slice(0, n) + "…" : "";
}

export function ts(t: number) {
  return new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19);
}

export function Flash({ msg, kind }: { msg: string; kind: "ok" | "err" | "" }) {
  if (!msg) return null;
  return <div className={`flash ${kind}`}>{msg}</div>;
}

export function Spinner({ show, label }: { show: boolean; label?: string }) {
  if (!show) return null;
  return <div className="muted" style={{ padding: "6px 0" }}>{label || "loading…"}</div>;
}

export function PageHead({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="topbar">
      <h2>{title}</h2>
      <div>{children}</div>
    </div>
  );
}