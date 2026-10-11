# AGENTS.md

Read **`PROJECT_CONTEXT.md`** at the repo root first — it is the shared source of truth.

- Follow its conventions: ISO 8601 UTC timestamps ending in `Z`, camelCase JSON, one Flask blueprint under `/api` per module.
- Work **only inside your own module folder** under `backend/` (e.g. `backend/usb/`, `backend/files/`, `backend/network/`).
- Never edit `src/`, another module's folder, or another module's shapes.
- Run your module's tests before committing: `python3 -m pytest <your folder>/tests -q`.
- Never commit secrets, `*.db`, `*.pcap`, `__pycache__/`, `dist/`, or `node_modules/`.
- Update only your own section of `PROJECT_CONTEXT.md` and its status table.
