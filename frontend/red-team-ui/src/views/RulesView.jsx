import { C } from "../constants.js";
import { DEMO_RULES } from "../demoData.js";
import { Card, Label, Badge, Mono } from "../components/UI.jsx";

const RULE_COLORS = {
  R0: C.cyan, R1: C.cyan, R2: C.medium, R3: C.blue, R4: C.blue,
  R5: C.blue,  R6: C.high, R7: C.critical, R8: C.critical,
  R9: C.purple, R10: C.low,
};

export default function RulesView() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <Card>
        <Label>Rule Execution Trace — Explainability Log</Label>
        <div style={{ fontSize: 12, color: C.muted, marginBottom: 16, fontFamily: "monospace" }}>
          Every decision made by the framework is logged here. R0–R10 from the Rule Table.
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {DEMO_RULES.map((r, i) => {
            const c = RULE_COLORS[r.rule] || C.muted;
            return (
              <div key={i} style={{
                display: "grid", gridTemplateColumns: "70px 1fr 1fr",
                gap: 14, alignItems: "flex-start",
                padding: "10px 14px",
                background: "rgba(255,255,255,0.03)",
                border: `1px solid ${c}22`, borderRadius: 8,
              }}>
                <Badge label={r.rule} color={c} />
                <Mono style={{ fontSize: 12, color: C.muted }}>{r.condition}</Mono>
                <Mono style={{ fontSize: 12, color: C.text }}>→ {r.action}</Mono>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
