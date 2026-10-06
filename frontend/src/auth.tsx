import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { api, setTokenGetter } from "./api";

interface Me {
  id: string;
  role: string;
  orgs: string[] | null;
}

interface AuthCtx {
  token: string;
  connect: (t: string) => void;
  logout: () => void;
  connected: boolean;
  me: Me | null;
}

const Ctx = createContext<AuthCtx>({
  token: "",
  connect: () => {},
  logout: () => {},
  connected: false,
  me: null,
});

const KEY = "to_token";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string>(() => localStorage.getItem(KEY) || "");
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    setTokenGetter(() => token);
  }, [token]);

  // Load the current identity/role so the shell can render role-aware nav.
  useEffect(() => {
    if (!token) {
      setMe(null);
      return;
    }
    let cancelled = false;
    api
      .get<Me>("/v1/me")
      .then((m) => {
        if (!cancelled) setMe(m);
      })
      .catch(() => {
        if (!cancelled) setMe(null);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  const value = useMemo<AuthCtx>(
    () => ({
      token,
      connected: token.length > 0,
      me,
      connect: (t: string) => {
        localStorage.setItem(KEY, t);
        setToken(t);
      },
      logout: () => {
        localStorage.removeItem(KEY);
        setToken("");
        setMe(null);
      },
    }),
    [token, me]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);