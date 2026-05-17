import { C, TACTIC_COLOUR } from "../constants.js";
import { DEMO_MITRE } from "../demoData.js";
import { Card, Mono, StatCard } from "../components/UI.jsx";

export default function MitreView() {
  const { by_tactic, total_techniques, tactics_covered } = DEMO_MITRE;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <StatCard label="Techniques Mapped" value={total_techniques} color={C.purple} />
        <StatCard label="Tactics Covered"   value={tactics_covered}  color={C.cyan}   />
      </div>

      {Object.entries(by_tactic).map(([tactic, techs]) => {
        const c = TACTIC_COLOUR[tactic] || C.purple;
        return (
          <Card key={tactic} accent={c}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
              <div style={{ width: 9, height: 9, borderRadius: "50%", background: c, boxShadow: `0 0 8px ${c}` }} />
              <Mono color={c} style={{ fontSize: 12, fontWeight: 700, letterSpacing: 1.5, textTransform: "uppercase" }}>
                {tactic}
              </Mono>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              {techs.map((t, i) => (
                <div key={i} style={{
                  background: c + "10", border: `1px solid ${c}30`,
                  borderRadius: 8, padding: "10px 14px",
                }}>
                  <Mono color={c} style={{ fontSize: 13, fontWeight: 700, display: "block", marginBottom: 3 }}>
                    {t.id}
                  </Mono>
                  <div style={{ color: C.text, fontSize: 12 }}>{t.name}</div>
                  {t.detail && (
                    <Mono style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>via: {t.detail}</Mono>
                  )}
                </div>
              ))}
            </div>
          </Card>
        );
      })}
    </div>
  );
}
