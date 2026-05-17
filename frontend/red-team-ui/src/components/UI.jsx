import { C } from "../constants.js";

export function Card({ children, style = {}, accent }) {
  return (
    <div style={{
      background: C.surface,
      border: `1px solid ${accent ? accent + "44" : C.border}`,
      borderRadius: 10,
      padding: "18px 22px",
      boxShadow: accent ? `0 0 18px ${accent}18` : "0 2px 8px rgba(0,0,0,0.4)",
      ...style,
    }}>
      {children}
    </div>
  );
}

export function Label({ children, style = {} }) {
  return (
    <div style={{
      fontFamily: "'JetBrains Mono','Fira Code',monospace",
      fontSize: 10, textTransform: "uppercase", letterSpacing: 2,
      color: C.muted, marginBottom: 10, ...style,
    }}>
      {children}
    </div>
  );
}

export function Badge({ label, color }) {
  return (
    <span style={{
      background: color + "1a", color,
      border: `1px solid ${color}44`,
      borderRadius: 4, padding: "2px 8px",
      fontFamily: "'JetBrains Mono',monospace",
      fontSize: 10, fontWeight: 700, letterSpacing: 1,
    }}>
      {label}
    </span>
  );
}

export function Mono({ children, color, style = {} }) {
  return (
    <span style={{
      fontFamily: "'JetBrains Mono','Fira Code',monospace",
      color: color || C.text, ...style,
    }}>
      {children}
    </span>
  );
}

export function ProgressBar({ value, color = C.blue, height = 4 }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.05)", borderRadius: 9, height, overflow: "hidden" }}>
      <div style={{
        width: `${value}%`, height: "100%", background: color,
        borderRadius: 9, transition: "width .6s ease",
      }} />
    </div>
  );
}

export function Pill({ status }) {
  const map = { done: C.low, running: C.blue, queued: C.purple, halted: C.high, error: C.critical };
  const c = map[status] || C.safe;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span style={{
        width: 7, height: 7, borderRadius: "50%", background: c,
        boxShadow: status === "running" ? `0 0 8px ${c}` : "none",
        animation: status === "running" ? "blink 1.4s infinite" : "none",
      }} />
      <Mono style={{ fontSize: 11, color: c, textTransform: "uppercase", letterSpacing: 1 }}>
        {status}
      </Mono>
    </span>
  );
}

export function StatCard({ label, value, sub, color = C.blue, icon }) {
  return (
    <Card accent={color} style={{ flex: 1, minWidth: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <Label>{label}</Label>
          <div style={{
            fontSize: 34, fontWeight: 900, color,
            fontFamily: "'Syne','Clash Display',sans-serif", lineHeight: 1,
          }}>{value}</div>
          {sub && <div style={{ color: C.muted, fontSize: 12, marginTop: 6 }}>{sub}</div>}
        </div>
        {icon && <div style={{ fontSize: 26, opacity: 0.35 }}>{icon}</div>}
      </div>
    </Card>
  );
}
