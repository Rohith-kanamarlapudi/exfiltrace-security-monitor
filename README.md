# ExfilTrace

USB insertion, file activity and network exfiltration monitor. This is the **frontend only** (React + Vite + Tailwind CSS v4), running on mock data.

```bash
npm install
npm run dev      # http://localhost:5173
npm run build
```

## Structure

```
src/
  data/mockData.js     all mock data (the shapes the backend should return)
  services/api.js      the only file pages import data from; swap mocks for fetch() here
  hooks.js             useApi(fetcher) -> { data, loading, error }
  layout/              Sidebar, Navbar, Layout, navItems
  components/          reusable UI (tables, badges, timeline, chart ...)
  pages/               Dashboard, USBForensics, FileMonitoring, NetworkAnalysis, Incidents, Reports
```

## Connecting the Python API later

`src/services/api.js` lists the planned REST endpoints in `ENDPOINTS`. Replace each `delay(mock...)` with a `fetch(API_BASE_URL + ENDPOINTS.x)` call returning the same JSON shape. Set `VITE_API_URL` to change the base URL (default `http://localhost:5000/api`).
