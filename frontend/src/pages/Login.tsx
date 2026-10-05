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
    <form className="login" onSubmit={submit}>
      <h1>Trust Orchestrator</h1>
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
  );
}