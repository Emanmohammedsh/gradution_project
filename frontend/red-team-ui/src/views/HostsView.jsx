import { C } from "../constants.js";
import { DEMO_HOSTS } from "../demoData.js";
import { Card, Label, Badge, Mono } from "../components/UI.jsx";

export default function HostsView() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {DEMO_HOSTS.map((host) => (
        <Card key={host.ip_address} accent={C.cyan}>
          {/* Host header */}
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 18 }}>
            <div style={{ fontSize: 32 }}>🖥️</div>
            <div>
              <Mono color={C.cyan} style={{ fontSize: 16, fontWeight: 700 }}>{host.ip_address}</Mono>
              <div style={{ color: C.muted, fontSize: 12, marginTop: 2 }}>
                {host.hostname} · OS: {host.os_type}
              </div>
            </div>
            <Badge label={host.os_type} color={C.blue} />
          </div>

          {/* Services table */}
          <Label>Open Services</Label>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {host.services.map((svc) => (
              <div key={svc.service_id} style={{
                display: "grid", gridTemplateColumns: "80px 120px 120px 1fr",
                gap: 12, alignItems: "center",
                padding: "10px 14px",
                background: "rgba(255,255,255,0.03)",
                border: `1px solid ${C.border}`,
                borderRadius: 8,
              }}>
                <Mono color={C.high} style={{ fontSize: 13, fontWeight: 700 }}>
                  {svc.port_number}/{svc.protocol}
                </Mono>
                <Mono style={{ fontSize: 12 }}>{svc.service_name}</Mono>
                <Mono style={{ fontSize: 12, color: C.muted }}>{svc.product}</Mono>
                <Mono style={{ fontSize: 11, color: C.purple }}>{svc.version_string}</Mono>
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}
