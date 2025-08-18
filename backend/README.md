# EASM Backend (FastAPI)

## Setup (macOS / Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

### Database

- The API uses PostgreSQL. Set `DATABASE_URL` (default used if not set): `postgresql://easm:easm@localhost:5432/easm`.

## Run dev server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Run tests

```bash
pytest -q
```

## API
- `GET /api/health`
- `POST /api/scans` body: `{ "target": "example.com", "note": "optional" }`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`

### New (Discovery, Seeds, Assets, Risk)
- `POST /api/seeds` body: `{ "seed_type": "root_domain|acquisition_domain|cidr|asn|keyword", "value": "example.com", "note?": "..." }`
- `GET /api/seeds`
- `DELETE /api/seeds/{seed_id}`
- `POST /api/discovery/run` body: `{ "confidence_threshold": 0.7, "include_scan": true }`
  - Runs best-effort discovery from seeds (crt.sh, BufferOver, HackerTarget, CertSpotter, Subfinder, VirusTotal, Shodan, optional Wayback/URLScan/OTX, DNS NS/MX/SPF/CNAME pivots, cloud bucket heuristics), scores ownership, and schedules scans for assets above the threshold.
- `GET /api/assets?min_confidence=0.7`
- `GET /api/assets/{asset_id}`
- `POST /api/risk/score` body: `{ "cvss_base": number, "asset_criticality_weight": number, "exploitability_multiplier": number }`
  - Returns `{ "risk_score": number, "components": { ... } }`

Notes:
- Data is persisted with SQLAlchemy (async). In dev/test, tables are auto-created at startup.
- Evidence files are stored under `./data/evidence` and served via `/evidence/*`.
 - Optional env keys to enhance discovery: `CERTSPOTTER_API_TOKEN`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `OTX_API_KEY`.
- Company graph enrichment (optional): Clearbit (`CLEARBIT_API_KEY`), Wikidata (no key), OpenCorporates (`OPENCORPORATES_API_TOKEN`).
- Feature toggles (env): `ENABLE_WAYBACK`, `ENABLE_URLSCAN`, `ENABLE_OTX`, `ENABLE_DNS_RECORD_EXPANSION`, `ENABLE_WEB_CRAWL`, `ENABLE_CLOUD_STORAGE_DISCOVERY`, `ENABLE_WIKIDATA`, `ENABLE_OPENCORPORATES`.
