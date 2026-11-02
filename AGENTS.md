Read `PROJECT_CONTEXT.md` first and follow its conventions.
- For the Reports and navigation task, you may edit:
  - `src/layout/navItems.js` to remove the Incidents tab.
  - `src/pages/Reports.jsx` and related report-specific frontend files.
  - `src/services/api.js` and `src/services/normalize.js` for the Reports API connection.
  - `backend/app/` for report generation and API integration.
  - The Reports section of `PROJECT_CONTEXT.md` and its status table.
- Leave unrelated modules and existing user changes untouched.
- Run relevant tests before committing.