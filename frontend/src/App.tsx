import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import OrgPage from "./pages/Org";
import Audit from "./pages/Audit";
import Users from "./pages/Users";
import Webhooks from "./pages/Webhooks";
import Metrics from "./pages/Metrics";
import Backup from "./pages/Backup";
import Transparency from "./pages/Transparency";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/org", label: "Org" },
  { to: "/transparency", label: "Transparency" },
  { to: "/audit", label: "Audit" },
  { to: "/users", label: "Users" },
  { to: "/webhooks", label: "Webhooks" },
  { to: "/metrics", label: "Metrics" },
  { to: "/backup", label: "Backup" },
];

export default function App() {
  const { connected, logout } = useAuth();

  if (!connected) return <Login />;

  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>Trust Orchestrator</h1>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div style={{ marginTop: 20 }}>
          <button onClick={logout} style={{ width: "100%" }}>
            Disconnect
          </button>
        </div>
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/org" element={<OrgPage />} />
          <Route path="/transparency" element={<Transparency />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/users" element={<Users />} />
          <Route path="/webhooks" element={<Webhooks />} />
          <Route path="/metrics" element={<Metrics />} />
          <Route path="/backup" element={<Backup />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}