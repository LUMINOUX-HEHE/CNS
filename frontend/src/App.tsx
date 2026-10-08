import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import {
  IconGrid, IconShield, IconLock, IconSearch, IconUsers,
  IconWebhook, IconChart, IconSave, IconTerminal, IconPulse,
} from "./icons";
import Boundary from "./Boundary";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Overview from "./pages/Overview";
import OrgPage from "./pages/Org";
import Audit from "./pages/Audit";
import Users from "./pages/Users";
import Webhooks from "./pages/Webhooks";
import Metrics from "./pages/Metrics";
import Backup from "./pages/Backup";
import Transparency from "./pages/Transparency";

// Each nav entry lists the roles allowed to see it (mirrors api.go RBAC).
// A missing `roles` means every authenticated role.
const NAV = [
  { to: "/", label: "Dashboard", end: true, icon: <IconPulse /> },
  { to: "/overview", label: "Overview", icon: <IconGrid /> },
  { to: "/org", label: "Org", icon: <IconShield /> },
  { to: "/transparency", label: "Transparency", icon: <IconLock /> },
  { to: "/audit", label: "Audit", icon: <IconSearch />, roles: ["auditor", "operator", "admin"] },
  { to: "/users", label: "Users", icon: <IconUsers />, roles: ["admin"] },
  { to: "/webhooks", label: "Webhooks", icon: <IconWebhook />, roles: ["admin"] },
  { to: "/metrics", label: "Metrics", icon: <IconChart /> },
  { to: "/backup", label: "Backup", icon: <IconSave />, roles: ["admin"] },
];

export default function App() {
  const { connected, logout, me } = useAuth();

  if (!connected) return <Login />;

  const role = me?.role || "";
  // Until /v1/me resolves, show the full nav (the API still enforces RBAC).
  const nav = me ? NAV.filter((n) => !n.roles || n.roles.includes(role)) : NAV;

  return (
    <div className="app">
      <header className="appbar">
        <div className="brand">
          <span className="mark"><IconTerminal size={15} /></span>
          TRUST&nbsp;ORCHESTRATOR
        </div>
        <div className="spacer" />
        <span className="status">
          <span className="dot" /> {role || "session"}
        </span>
        <button onClick={logout}>Disconnect</button>
      </header>

      <div className="body">
        <aside className="sidebar">
          <div className="nav-label">Console</div>
          <nav>
            {nav.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} className="navlink">
                <span className="nav-ico">{n.icon}</span>
                <span>{n.label}</span>
              </NavLink>
            ))}
          </nav>
        </aside>

        <main className="content">
          <Boundary>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/org" element={<OrgPage />} />
              <Route path="/transparency" element={<Transparency />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/users" element={<Users />} />
              <Route path="/webhooks" element={<Webhooks />} />
              <Route path="/metrics" element={<Metrics />} />
              <Route path="/backup" element={<Backup />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Boundary>
        </main>
      </div>

      <footer className="footer">
        <span>Trust Orchestrator</span>
        <span className="sep">/</span>
        <span>RFC 9162 transparency · FROST threshold recovery</span>
        <span className="spacer" />
        <a href="https://github.com/LUMINOUX-HEHE/CNS" target="_blank" rel="noreferrer">
          GitHub
        </a>
        <span className="sep">·</span>
        <span>admin console</span>
      </footer>
    </div>
  );
}