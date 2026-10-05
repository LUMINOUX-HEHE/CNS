import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import {
  IconGrid, IconShield, IconLock, IconSearch, IconUsers,
  IconWebhook, IconChart, IconSave,
} from "./icons";
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
  { to: "/", label: "Overview", end: true, icon: <IconGrid /> },
  { to: "/org", label: "Org", icon: <IconShield /> },
  { to: "/transparency", label: "Transparency", icon: <IconLock /> },
  { to: "/audit", label: "Audit", icon: <IconSearch /> },
  { to: "/users", label: "Users", icon: <IconUsers /> },
  { to: "/webhooks", label: "Webhooks", icon: <IconWebhook /> },
  { to: "/metrics", label: "Metrics", icon: <IconChart /> },
  { to: "/backup", label: "Backup", icon: <IconSave /> },
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
            <NavLink key={n.to} to={n.to} end={n.end} className="navlink">
              <span className="nav-ico">{n.icon}</span>
              <span>{n.label}</span>
            </NavLink>
          ))}
        </nav>
        <div style={{ marginTop: 22 }}>
          <div className="conn">
            <span className="dot" /> connected
          </div>
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