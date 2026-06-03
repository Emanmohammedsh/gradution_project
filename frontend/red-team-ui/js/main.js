/* ══════════════════════════════════════════════
   main.js — Boot (v2)
   ══════════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
  buildNav();

  renderDashboard();
  renderSession();
  renderHosts();
  renderVulns();
  renderExploits();
  renderPostExploit();   // NEW
  renderAI();            // NEW
  renderMitre();
  renderChain();         // NEW
  renderRules();
  renderLogs();

  setView("dashboard");
});
