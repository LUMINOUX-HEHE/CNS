import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { setTokenGetter } from "./api";

interface AuthCtx {
  token: string;
  connect: (t: string) => void;
  logout: () => void;
  connected: boolean;
}

const Ctx = createContext<AuthCtx>({
  token: "",
  connect: () => {},
  logout: () => {},
  connected: false,
});

const KEY = "to_token";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string>(() => localStorage.getItem(KEY) || "");

  useEffect(() => {
    setTokenGetter(() => token);
  }, [token]);

  const value = useMemo<AuthCtx>(
    () => ({
      token,
      connected: token.length > 0,
      connect: (t: string) => {
        localStorage.setItem(KEY, t);
        setToken(t);
      },
      logout: () => {
        localStorage.removeItem(KEY);
        setToken("");
      },
    }),
    [token]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);