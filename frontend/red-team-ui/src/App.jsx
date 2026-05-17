import { useState } from "react";
import { C } from "./constants.js";
import { DEMO_SESSION } from "./demoData.js";
import Sidebar        from "./components/Sidebar.jsx";
import DashboardView  from "./views/DashboardView.jsx";
import NewSessionView from "./views/NewSessionView.jsx";
import HostsView      from "./views/HostsView.jsx";
import VulnsView      from "./views/VulnsView.jsx";
import ExploitsView   from "./views/ExploitsView.jsx";
import MitreView      from "./views/MitreView.jsx";
import RulesView      from "./views/RulesView.jsx";
import LogsView       from "./views/LogsView.jsx";

const NAV = [
  { id: "dashboard", label: "Dashboard",      icon: "⬡" },
  { id: "new",       label: "New Session",     icon: "▶" },
  { id: "hosts",     label: "Hosts",           icon: "🖥" },
  { id: "vulns",     label: "Vulnerabilities", icon: "⚠" },
  { id: "exploits",  label: "Exploitation",    icon: "⚡" },
  { id: "mitre",     label: "MITRE ATT&CK",    icon: "🛡" },
  { id: "rules",     label: "Rule Trace",      icon: "📋" },
  { id: "logs",      label: "Session Logs",    icon: "⌨" },
];

export default function App() {
  const [view, setView] = useState("dashboard");

  const views = {
    dashboard: <DashboardView />,
    new:       <NewSessionView onStart={() => setView("logs")} />,
    hosts:     <HostsView />,
    vulns:     <VulnsView />,
    exploits:  <ExploitsView />,
    mitre:     <MitreView />,
    rules:     <RulesView />,
    logs:      <LogsView />,
  };

  const current = NAV.find((n) => n.id === view);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800;900&family=JetBrains+Mono:wght@400;700&display=swap');
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: ${C.bg}; color: ${C.text}; font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
        input:focus, select:focus { outline: none; border-color: ${C.blue} !important; }
      `}</style>

      <div style={{ display: "flex", minHeight: "100vh" }}>
        <Sidebar view={view} setView={setView} nav={NAV} />

        <main style={{ flex: 1, marginLeft: 210, padding: "26px 30px", minHeight: "100vh" }}>
          {/* Header */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
            <div>
              <h1 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 900, fontSize: 22, color: C.text, margin: 0 }}>
                {current?.label}
              </h1>
              <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>
                Session {DEMO_SESSION.session_id} · {DEMO_SESSION.target} · Demo Mode
              </div>
            </div>
            <div style={{
              background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              borderRadius: 6, padding: "6px 12px", fontSize: 11, color: C.muted,
            }}>
              Connect backend → localhost:8000
            </div>
          </div>

          {views[view]}
        </main>
      </div>
    </>
  );
}
