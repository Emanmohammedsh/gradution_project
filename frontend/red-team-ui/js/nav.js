/* ══════════════════════════════════════════════
   nav.js — Sidebar navigation logic
   ══════════════════════════════════════════════ */

const NAV_ITEMS = [
  { id:"dashboard", label:"Dashboard",       icon:"⬡" },
  { id:"new",       label:"New Session",      icon:"▶" },
  { id:"hosts",     label:"Hosts",            icon:"🖥" },
  { id:"vulns",     label:"Vulnerabilities",  icon:"⚠" },
  { id:"exploits",  label:"Exploitation",     icon:"⚡" },
  { id:"mitre",     label:"MITRE ATT&CK",     icon:"🛡" },
  { id:"rules",     label:"Rule Trace",       icon:"📋" },
  { id:"logs",      label:"Session Logs",     icon:"⌨" },
];

let currentView = "dashboard";

function setView(id) {
  currentView = id;

  // Hide all views, show selected
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById("view-" + id).classList.add("active");

  // Update nav button active state
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("nav-btn-" + id).classList.add("active");

  // Update page title
  const item = NAV_ITEMS.find(n => n.id === id);
  if (item) document.getElementById("page-title").textContent = item.label;
}

function buildNav() {
  const navEl = document.getElementById("nav");
  NAV_ITEMS.forEach(n => {
    const btn = document.createElement("button");
    btn.className = "nav-btn" + (n.id === "dashboard" ? " active" : "");
    btn.id = "nav-btn-" + n.id;
    btn.innerHTML = `<span style="font-size:14px">${n.icon}</span>${n.label}`;
    btn.addEventListener("click", () => setView(n.id));
    navEl.appendChild(btn);
  });
}
