/* ══════════════════════════════════════════════
   main.js — Entry point, boots all views
   ══════════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Build sidebar nav
  buildNav();

  // 2. Render all views once
  renderDashboard();
  renderSession();
  renderHosts();
  renderVulns();
  renderExploits();
  renderMitre();
  renderRules();
  renderLogs();

  // 3. Start on dashboard
  setView("dashboard");
});
