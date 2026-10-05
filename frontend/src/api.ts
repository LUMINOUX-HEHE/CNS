// api.ts — thin client over the gateway REST surface. The token is held in
// localStorage by AuthProvider and passed per request; every call throws a
// readable Error on non-2xx so the UI can surface the gateway's message.

// Default reads localStorage directly so the very first requests (which fire
// from child effects before AuthProvider's effect runs) already carry the
// token. AuthProvider then overrides this with the live state.
let tokenGetter: () => string = () => localStorage.getItem("to_token") || "";

export function setTokenGetter(fn: () => string) {
  tokenGetter = fn;
}

export class Api extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  rawBody?: string
): Promise<T> {
  const headers: Record<string, string> = {};
  const token = tokenGetter();
  if (token) headers["Authorization"] = "Bearer " + token;
  let payload: BodyInit | undefined;
  if (rawBody !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = rawBody;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, { method, headers, body: payload });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON (e.g. prometheus metrics) */
  }
  if (!res.ok) {
    throw new Api(res.status, (json && json.error) || `${res.status} ${text}`);
  }
  return (json === null ? text : json) as T;
}

// download fetches an authenticated file and saves it via a blob URL. A
// plain <a href> cannot carry the Bearer token, so protected downloads
// (e.g. /v1/backup/{id}/download) would otherwise 401.
async function download(path: string, filename: string): Promise<void> {
  const headers: Record<string, string> = {};
  const token = tokenGetter();
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, { headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Api(res.status, `${res.status} ${text}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, body?: unknown) => request<T>("POST", p, body),
  del: <T>(p: string) => request<T>("DELETE", p),
  postRaw: <T>(p: string, raw: string) => request<T>("POST", p, undefined, raw),
  download,
};