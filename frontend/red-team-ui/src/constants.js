// ── API config ────────────────────────────────────────
export const API = "/api";          // proxied by Vite → http://localhost:8000/api
export const WS  = "/ws";           // proxied by Vite → ws://localhost:8000/ws

// ── Risk threshold (matches exploitation.py) ─────────
export const RISK_THRESHOLD = 0.30;

// ── Design tokens ─────────────────────────────────────
export const C = {
  bg:       "#0b0f1a",
  surface:  "#111827",
  border:   "rgba(255,255,255,0.07)",
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  safe:     "#6b7280",
  blue:     "#3b82f6",
  purple:   "#a855f7",
  cyan:     "#06b6d4",
  text:     "#e2e8f0",
  muted:    "rgba(226,232,240,0.45)",
};

// ── Helpers ───────────────────────────────────────────
export const cvssColour = (cvss) =>
  cvss >= 9 ? C.critical : cvss >= 7 ? C.high : cvss >= 4 ? C.medium : C.low;

export const cvssLabel = (cvss) =>
  cvss >= 9 ? "CRITICAL" : cvss >= 7 ? "HIGH" : cvss >= 4 ? "MEDIUM" : "LOW";

export const riskColour = (r) => (r >= RISK_THRESHOLD ? C.high : C.safe);

// ── Module icons ──────────────────────────────────────
export const MODULE_ICONS = {
  reconnaissance:        "🔍",
  scanning:              "📡",
  vulnerability_mapping: "🧬",
  exploitation:          "⚡",
  post_exploitation:     "🔓",
  reporting:             "📄",
};

// ── MITRE tactic colours ──────────────────────────────
export const TACTIC_COLOUR = {
  "Initial Access":       "#ef4444",
  "Execution":            "#f97316",
  "Persistence":          "#eab308",
  "Privilege Escalation": "#a855f7",
  "Credential Access":    "#3b82f6",
  "Discovery":            "#22c55e",
  "Lateral Movement":     "#ec4899",
  "Exfiltration":         "#f43f5e",
  "Collection":           "#06b6d4",
};
