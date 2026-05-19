/* ══════════════════════════════════════════════
   views/mitre.js — MITRE ATT&CK view renderer
   ══════════════════════════════════════════════ */

function renderMitre() {
  const el            = document.getElementById("view-mitre");
  const totalTechniques = Object.values(MITRE).reduce((acc, arr) => acc + arr.length, 0);
  const tacticsCovered  = Object.keys(MITRE).length;

  const tacticsHtml = Object.entries(MITRE).map(([tactic, techs]) => {
    const c = TACTIC_COLOR[tactic] || "var(--purple)";

    const techsHtml = techs.map(t => `
      <div class="mitre-tech" style="background:${c}10;border:1px solid ${c}30">
        <span class="mitre-id mono" style="color:${c}">${t.id}</span>
        <div class="mitre-name">${t.name}</div>
        ${t.detail ? `<div class="mitre-detail mono">via: ${t.detail}</div>` : ""}
      </div>`).join("");

    return `
      <div class="card mitre-card" style="border-color:${c}44;box-shadow:0 0 18px ${c}18">
        <div class="mitre-tactic-header">
          <div class="mitre-dot" style="background:${c};box-shadow:0 0 8px ${c}"></div>
          ${mono(tactic, c, "font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase")}
        </div>
        <div class="mitre-techniques">${techsHtml}</div>
      </div>`;
  }).join("");

  el.innerHTML = `
    <div class="stat-grid-2">
      <div class="stat-card" style="border-color:rgba(168,85,247,0.27)">
        <div class="card-label">Techniques Mapped</div>
        <div class="stat-value" style="color:var(--purple)">${totalTechniques}</div>
      </div>
      <div class="stat-card" style="border-color:rgba(6,182,212,0.27)">
        <div class="card-label">Tactics Covered</div>
        <div class="stat-value" style="color:var(--cyan)">${tacticsCovered}</div>
      </div>
    </div>
    ${tacticsHtml}`;
}
