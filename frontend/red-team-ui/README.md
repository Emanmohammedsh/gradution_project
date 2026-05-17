# Red Team AI — Frontend

Rule-Based Adaptive Red Teaming Orchestrator  
UCAS Cyber Security Engineering 2026

## Project Structure

```
red-team-ui/
├── index.html
├── vite.config.js
├── package.json
├── public/
│   └── favicon.svg
└── src/
    ├── main.jsx           # React entry point
    ├── App.jsx            # Root layout + navigation
    ├── constants.js       # Colors, API config, helpers
    ├── demoData.js        # Mock data matching backend models
    ├── components/
    │   ├── UI.jsx         # Primitives: Card, Badge, Mono, StatCard …
    │   └── Sidebar.jsx    # Fixed left navigation
    └── views/
        ├── DashboardView.jsx    # Charts + stats overview
        ├── NewSessionView.jsx   # Launch form (dry-run / live)
        ├── HostsView.jsx        # Discovered hosts + services
        ├── VulnsView.jsx        # CVE list with risk scores
        ├── ExploitsView.jsx     # Exploit attempt results
        ├── MitreView.jsx        # MITRE ATT&CK tactic mapping
        ├── RulesView.jsx        # Rule trace / explainability log
        └── LogsView.jsx         # Live terminal session log
```

## Setup & Run

```bash
# Install dependencies
npm install

# Start dev server (with backend proxy to localhost:8000)
npm run dev

# Build for production
npm run build
```

Dev server runs on **http://localhost:5173**  
API calls are proxied: `/api/*` → `http://localhost:8000/api/*`

## Backend Integration

When the FastAPI backend is running on port 8000:

- **POST /api/dry-run** `{ target: "192.168.1.100" }` — start simulation
- **POST /api/run**     `{ target: "192.168.1.100" }` — start live pentest
- **WS  /ws**          — real-time log streaming

Without the backend the app runs fully in **Demo Mode** using `src/demoData.js`.

## ⚠ Authorized Use Only

This tool is for authorized penetration testing within controlled lab environments.
