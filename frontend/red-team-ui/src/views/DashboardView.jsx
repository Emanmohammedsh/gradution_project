import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer,
  PieChart, Pie, Legend, RadarChart, PolarGrid, PolarAngleAxis, Radar,
} from "recharts";
import { C, cvssColour, RISK_THRESHOLD, MODULE_ICONS } from "../constants.js";
import { DEMO_VULNS, DEMO_EXPLOITS, DEMO_SESSION, DEMO_MITRE } from "../demoData.js";
import { Card, Label, Badge, StatCard } from "../components/UI.jsx";

export default function DashboardView() {
  const summary     = DEMO_SESSION.summary;
  const aboveThresh = DEMO_VULNS.filter((v) => v.risk_score >= RISK_THRESHOLD);
  const successCnt  = DEMO_EXPLOITS.filter((e) => e.result === "SUCCESS").length;

  const pieData = [
    { name: "Critical (≥9)", value: DEMO_VULNS.filter(v => v.cvss_score >= 9).length,                         color: C.critical },
    { name: "High (7–9)",    value: DEMO_VULNS.filter(v => v.cvss_score >= 7 && v.cvss_score < 9).length,     color: C.high     },
    { name: "Medium (4–7)",  value: DEMO_VULNS.filter(v => v.cvss_score >= 4 && v.cvss_score < 7).length,     color: C.medium   },
    { name: "Low (<4)",      value: DEMO_VULNS.filter(v => v.cvss_score < 4).length,                          color: C.low      },
  ].filter((d) => d.value > 0);

  const riskBarData = [...DEMO_VULNS]
    .sort((a, b) => b.risk_score - a.risk_score)
    .map((v) => ({
      name:  v.cve_id.replace("CVE-", ""),
      risk:  +(v.risk_score * 100).toFixed(0),
      color: cvssColour(v.cvss_score),
      above: v.risk_score >= RISK_THRESHOLD,
    }));

  const mitreData = Object.entries(DEMO_MITRE.by_tactic).map(([t, arr]) => ({
    tactic: t.split(" ")[0],
    full:   t,
    count:  arr.length,
  }));

  const tt = { contentStyle: { background: "#1e2433", border: "none", borderRadius: 8, fontSize: 12 } };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        <StatCard label="Hosts Discovered"    value={summary.hosts_found}                             sub="live, scanned"              color={C.cyan}     icon="🖥️" />
        <StatCard label="Vulnerabilities"     value={summary.total_vulnerabilities}                   sub={`${aboveThresh.length} above threshold`} color={C.critical} icon="⚠️" />
        <StatCard label="Successful Exploits" value={`${successCnt}/${summary.exploit_attempts}`}     sub="attempts"                   color={C.high}     icon="⚡" />
        <StatCard label="Rules Fired"         value={summary.rules_fired}                             sub="R0–R10"                     color={C.purple}   icon="📋" />
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr 1fr", gap: 14 }}>
        <Card>
          <Label>Severity Distribution</Label>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={72} paddingAngle={3} dataKey="value">
                {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip {...tt} />
              <Legend iconType="circle" iconSize={8} formatter={v => <span style={{ color: C.muted, fontSize: 11 }}>{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <Label>Risk Score (threshold = {RISK_THRESHOLD})</Label>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={riskBarData} margin={{ left: -28, right: 4 }}>
              <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 9 }} />
              <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 10 }} />
              <Tooltip {...tt} formatter={(v) => [`${v}/100`, "Risk ×100"]} />
              <Bar dataKey="risk" radius={[4, 4, 0, 0]} name="risk">
                {riskBarData.map((e, i) => <Cell key={i} fill={e.above ? C.high : C.safe} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", gap: 14, marginTop: 8 }}>
            <span style={{ fontSize: 11, color: C.high }}>■ Above threshold (≥{RISK_THRESHOLD})</span>
            <span style={{ fontSize: 11, color: C.safe }}>■ Below threshold</span>
          </div>
        </Card>

        <Card>
          <Label>MITRE Tactic Coverage</Label>
          <ResponsiveContainer width="100%" height={180}>
            <RadarChart data={mitreData}>
              <PolarGrid stroke="rgba(255,255,255,0.08)" />
              <PolarAngleAxis dataKey="tactic" tick={{ fill: C.muted, fontSize: 9 }} />
              <Radar dataKey="count" stroke={C.purple} fill={C.purple} fillOpacity={0.3} />
              <Tooltip {...tt} formatter={(v, n, p) => [v, p.payload.full]} />
            </RadarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Pipeline modules */}
      <Card>
        <Label>Pipeline Modules — Session {DEMO_SESSION.session_id}</Label>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 10 }}>
          {Object.entries(MODULE_ICONS).map(([mod, icon]) => (
            <div key={mod} style={{
              background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
              borderRadius: 8, padding: "12px 10px", textAlign: "center",
            }}>
              <div style={{ fontSize: 22, marginBottom: 6 }}>{icon}</div>
              <div style={{ fontFamily: "monospace", fontSize: 9, color: C.muted,
                            textTransform: "uppercase", letterSpacing: 1, lineHeight: 1.4 }}>
                {mod.replace("_", " ")}
              </div>
              <div style={{ marginTop: 8 }}><Badge label="DONE" color={C.low} /></div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
