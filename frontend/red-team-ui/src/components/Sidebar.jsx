import { C, RISK_THRESHOLD } from "../constants.js";
import { DEMO_SESSION } from "../demoData.js";
import { Mono, Pill, ProgressBar } from "./UI.jsx";

export default function Sidebar({ view, setView, nav }) {
  return (
    <aside style={{
      width: 210, background: "#0a0d17",
      borderRight: `1px solid ${C.border}`,
      display: "flex", flexDirection: "column",
      position: "fixed", top: 0, bottom: 0, left: 0,
    }}>
      {/* Logo */}
      <div style={{ padding: "22px 18px 18px", borderBottom: `1px solid ${C.border}` }}>
        <div style={{
          fontFamily: "'Syne',sans-serif", fontWeight: 900,
          fontSize: 15, color: C.critical, letterSpacing: 1,
        }}>
          ⬡ RED TEAM AI
        </div>
        <div style={{
          fontSize: 9, color: C.muted, marginTop: 3,
          letterSpacing: 2, textTransform: "uppercase",
        }}>
          Rule-Based Orchestrator
        </div>
      </div>

      {/* Active session */}
      <div style={{ padding: "12px 18px", borderBottom: `1px solid ${C.border}` }}>
        <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 6 }}>
          Active Session
        </div>
        <Mono style={{ fontSize: 12, color: C.blue }}>{DEMO_SESSION.session_id}</Mono>
        <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{DEMO_SESSION.target}</div>
        <div style={{ marginTop: 8 }}><Pill status={DEMO_SESSION.status} /></div>
        <div style={{ marginTop: 8 }}><ProgressBar value={DEMO_SESSION.progress} color={C.low} /></div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "14px 10px" }}>
        {nav.map((n) => {
          const active = view === n.id;
          return (
            <button key={n.id} onClick={() => setView(n.id)} style={{
              width: "100%", display: "flex", alignItems: "center", gap: 10,
              padding: "9px 10px", borderRadius: 7, border: "none",
              cursor: "pointer", marginBottom: 2, textAlign: "left",
              background: active ? "rgba(59,130,246,0.12)" : "transparent",
              color: active ? C.blue : C.muted,
              fontFamily: "monospace", fontSize: 12,
              fontWeight: active ? 700 : 400,
              borderLeft: `2px solid ${active ? C.blue : "transparent"}`,
              transition: "all .15s",
            }}>
              <span style={{ fontSize: 14 }}>{n.icon}</span>
              {n.label}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{
        padding: "14px 18px", borderTop: `1px solid ${C.border}`,
        fontSize: 10, color: C.muted, lineHeight: 1.7,
      }}>
        <div style={{ color: C.high }}>⚖ RISK_THRESHOLD = {RISK_THRESHOLD}</div>
        <div>UCAS Cyber Security 2026</div>
        <div style={{ marginTop: 4 }}>⚠ AUTHORIZED USE ONLY</div>
      </div>
    </aside>
  );
}
