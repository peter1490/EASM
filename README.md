# EASM (External Attack Surface Management)

All‑in‑one EASM security tool with a FastAPI backend and a Next.js + Tailwind frontend.

## Quickstart (local)

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend (in another terminal):

```bash
cd frontend
npm run dev
```

Open `http://localhost:3000`.

## Docker

```bash
docker compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:3000`

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```

## API
- `GET /api/health`
- `POST /api/scans` { target, note? }
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
