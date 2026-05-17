import { useRef, useEffect } from "react";
import { C } from "../constants.js";
import { DEMO_LOGS, DEMO_SESSION } from "../demoData.js";
import { Card, Label } from "../components/UI.jsx";

function lineColor(line) {
  if (line.includes("✓"))                        return C.low;
  if (line.includes("[MODULE"))                  return C.cyan;
  if (line.includes("CVE-"))                     return C.high;
  if (line.includes("Risk:") || line.includes("risk=")) return C.purple;
  if (line.includes("ROOT") || line.includes("SUCCESS")) return C.low;
  if (line.includes("R5]") || line.includes("R7") || line.includes("R8")) return C.high;
  if (line.includes("[+]"))                      return "#86efac";
  if (line.includes("[-]"))                      return C.muted;
  if (line.includes("[*]"))                      return C.blue;
  return C.muted;
}

export default function LogsView() {
  const endRef = useRef(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, []);

  return (
    <Card style={{ height: 520, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.low, boxShadow: `0 0 6px ${C.low}` }} />
        <Label style={{ margin: 0 }}>Session Log — {DEMO_SESSION.session_id} (dry-run)</Label>
      </div>
      <div style={{
        flex: 1, overflowY: "auto",
        fontFamily: "'JetBrains Mono',monospace", fontSize: 12, lineHeight: 1.75,
      }}>
        {DEMO_LOGS.map((line, i) => (
          <div key={i} style={{
            color: lineColor(line),
            borderBottom: "1px solid rgba(255,255,255,0.02)",
            padding: "1px 0", whiteSpace: "pre",
          }}>
            {line || "\u00A0"}
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </Card>
  );
}
