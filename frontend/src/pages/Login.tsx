import { useState } from "react";
import { useAuth } from "../auth";

export default function Login() {
  const { connect } = useAuth();
  const [tok, setTok] = useState("");

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const t = tok.trim();
    if (t) connect(t);
  }

  return (
    <div className="app">
      <header className="appbar">
        <div className="brand">
          <span className="mark">▍</span>
          TRUST&nbsp;ORCHESTRATOR
        </div>
        <div className="spacer" />
        <span className="status">not connected</span>
      </header>

      <form className="login" onSubmit={submit}>
        <h1>Admin console</h1>
        <p>
          Paste the admin token printed on first gateway boot
          (<code>admin token (shown once): …</code>). It is stored only in this
          browser's localStorage.
        </p>
        <div className="form-row">
          <input
            type="password"
            placeholder="API token"
            value={tok}
            onChange={(e) => setTok(e.target.value)}
            autoFocus
          />
          <button className="primary" type="submit">
            Connect
          </button>
        </div>
      </form>

      <footer className="footer">
        <span>Trust Orchestrator</span>
        <span className="sep">/</span>
        <span>RFC 9162 transparency · FROST threshold recovery</span>
        <span className="spacer" />
        <a href="https://github.com/LUMINOUX-HEHE/CNS" target="_blank" rel="noreferrer">
          GitHub
        </a>
      </footer>
    </div>
  );
}