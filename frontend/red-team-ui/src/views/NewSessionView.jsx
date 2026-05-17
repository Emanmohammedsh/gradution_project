import { useState } from "react";
import { C, API, RISK_THRESHOLD } from "../constants.js";
import { Card, Label } from "../components/UI.jsx";

export default function NewSessionView({ onStart }) {
  const [target,  setTarget]  = useState("192.168.1.100");
  const [dryRun,  setDryRun]  = useState(true);
  const [loading, setLoading] = useState(false);
  const [msg,     setMsg]     = useState("");

  const handleLaunch = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setMsg("");
    try {
      const ep  = dryRun ? `${API}/dry-run` : `${API}/run`;
      const res = await fetch(ep, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setMsg(`✓ Session started: ${data.session_id}`);
      onStart && onStart(data.session_id);
    } catch {
      setMsg(`Demo mode — backend not connected. Session would target: ${target}`);
    }
    setLoading(false);
  };

  return (
    <div style={{ maxWidth: 560 }}>
      <Card>
        <Label>Launch New Pentest Session</Label>

        <div style={{ marginBottom: 18 }}>
          <div style={{ color: C.muted, fontSize: 12, marginBottom: 8, fontFamily: "monospace" }}>TARGET IP / CIDR</div>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.0/24 or 192.168.1.100"
            style={{
              width: "100%", background: "rgba(255,255,255,0.05)",
              border: `1px solid ${C.border}`, borderRadius: 8,
              padding: "12px 14px", color: C.text, fontSize: 14,
              fontFamily: "monospace", boxSizing: "border-box", outline: "none",
            }}
          />
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20, cursor: "pointer" }}>
          <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)}
            style={{ accentColor: C.blue, width: 16, height: 16 }} />
          <span style={{ color: C.muted, fontSize: 13, fontFamily: "monospace" }}>
            Dry-Run (simulation — no real tools executed)
          </span>
        </label>

        <button onClick={handleLaunch} disabled={loading} style={{
          width: "100%",
          background: loading ? C.safe : dryRun ? C.blue : C.critical,
          color: "#000", border: "none", borderRadius: 8, padding: "13px",
          fontSize: 13, fontWeight: 900, cursor: loading ? "wait" : "pointer",
          fontFamily: "monospace", letterSpacing: 2, textTransform: "uppercase",
        }}>
          {loading ? "Launching..." : dryRun ? "▶  Run Simulation" : "⚡  Launch Pentest"}
        </button>

        {msg && (
          <div style={{
            marginTop: 14, padding: "10px 14px",
            background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)",
            borderRadius: 8, color: C.low, fontSize: 12, fontFamily: "monospace",
          }}>
            {msg}
          </div>
        )}

        <div style={{
          marginTop: 18, padding: "12px 14px",
          background: "rgba(255,255,255,0.03)", border: `1px solid ${C.border}`,
          borderRadius: 8,
        }}>
          <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace", lineHeight: 1.8 }}>
            <div>⚖  RISK THRESHOLD = <span style={{ color: C.high }}>{RISK_THRESHOLD}</span></div>
            <div>📌 Rule R7: risk ≥ {RISK_THRESHOLD} → exploit via Metasploit</div>
            <div>📌 Rule R8: fail + auth → brute force via Hydra</div>
            <div>📌 Rule R10: complete → generate PDF + JSON report</div>
          </div>
        </div>
      </Card>
    </div>
  );
}
