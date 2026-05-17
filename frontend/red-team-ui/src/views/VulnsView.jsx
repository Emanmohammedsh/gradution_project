import { useState } from "react";
import { C, cvssColour, cvssLabel, riskColour, RISK_THRESHOLD } from "../constants.js";
import { DEMO_VULNS } from "../demoData.js";
import { Card, Label, Badge, Mono, ProgressBar } from "../components/UI.jsx";

export default function VulnsView() {
  const [filter, setFilter] = useState("all");

  const vulns =
    filter === "all"        ? DEMO_VULNS :
    filter === "exploitable"? DEMO_VULNS.filter(v => v.risk_score >= RISK_THRESHOLD) :
                              DEMO_VULNS.filter(v => cvssLabel(v.cvss_score).toLowerCase() === filter);

  const filters = [
    { id: "all",         label: "All" },
    { id: "exploitable", label: `Exploitable (risk ≥ ${RISK_THRESHOLD})`, col: C.high },
    { id: "critical",    label: "Critical", col: C.critical },
    { id: "high",        label: "High",     col: C.high     },
    { id: "medium",      label: "Medium",   col: C.medium   },
    { id: "low",         label: "Low",      col: C.low      },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Filter buttons */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {filters.map((f) => (
          <button key={f.id} onClick={() => setFilter(f.id)} style={{
            background: filter === f.id ? (f.col || C.blue) + "22" : "rgba(255,255,255,0.04)",
            border:     `1px solid ${filter === f.id ? (f.col || C.blue) : C.border}`,
            color:      filter === f.id ? (f.col || C.blue) : C.muted,
            borderRadius: 6, padding: "6px 14px", fontSize: 11,
            cursor: "pointer", fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: 1,
          }}>
            {f.label}
          </button>
        ))}
      </div>

      {/* Threshold banner */}
      <div style={{
        padding: "8px 14px",
        background: "rgba(249,115,22,0.08)", border: `1px solid ${C.high}33`,
        borderRadius: 8, fontFamily: "monospace", fontSize: 12, color: C.high,
      }}>
        ⚖  RISK_THRESHOLD = {RISK_THRESHOLD} — Vulnerabilities with risk_score ≥ {RISK_THRESHOLD} trigger Rule R7 (exploit)
      </div>

      {/* Vuln cards */}
      {vulns.map((v, i) => (
        <Card key={i} accent={v.risk_score >= RISK_THRESHOLD ? cvssColour(v.cvss_score) : undefined}>
          <div style={{ display: "grid", gridTemplateColumns: "180px 1fr 100px 100px auto", gap: 14, alignItems: "center" }}>
            <div>
              <Mono color={cvssColour(v.cvss_score)} style={{ fontSize: 13, fontWeight: 700 }}>{v.cve_id}</Mono>
              <div style={{ color: C.muted, fontSize: 11, marginTop: 3 }}>{v.ip_address}:{v.port_number}</div>
            </div>

            <div>
              <div style={{ fontSize: 13, color: C.text }}>{v.description}</div>
              <div style={{ display: "flex", gap: 10, marginTop: 6, flexWrap: "wrap" }}>
                <Mono style={{ fontSize: 11, color: C.muted }}>service: {v.service_name}</Mono>
                <Mono style={{ fontSize: 11, color: C.muted }}>attack: {v.attack_type}</Mono>
                {v.msf_module && (
                  <Mono style={{ fontSize: 10, color: C.blue, background: C.blue + "15", borderRadius: 4, padding: "1px 6px" }}>
                    MSF: {v.msf_module.split("/").slice(-1)[0]}
                  </Mono>
                )}
                {v.requires_auth && <Badge label="AUTH REQUIRED" color={C.medium} />}
              </div>
            </div>

            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 10, color: C.muted, fontFamily: "monospace" }}>CVSS</div>
              <div style={{ fontSize: 22, fontWeight: 900, color: cvssColour(v.cvss_score), fontFamily: "monospace" }}>
                {v.cvss_score}
              </div>
            </div>

            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 10, color: C.muted, fontFamily: "monospace" }}>RISK SCORE</div>
              <div style={{ fontSize: 22, fontWeight: 900, color: riskColour(v.risk_score), fontFamily: "monospace" }}>
                {v.risk_score.toFixed(2)}
              </div>
              <div style={{ marginTop: 4 }}>
                <ProgressBar value={v.risk_score * 100} color={riskColour(v.risk_score)} height={3} />
              </div>
            </div>

            <Badge label={cvssLabel(v.cvss_score)} color={cvssColour(v.cvss_score)} />
          </div>
        </Card>
      ))}
    </div>
  );
}
