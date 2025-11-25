# EASM Rollout & Migration Checklist

## Prerequisites

- [ ] PostgreSQL 16+ running and accessible.
- [ ] Elasticsearch 8.x running (optional, for advanced search).
- [ ] OIDC Provider (Google or Keycloak) credentials.
- [ ] Rust toolchain (stable).
- [ ] Node.js 18+ (for frontend).

## 1. Configuration

- [ ] Copy `example.env` to `.env`.
- [ ] Generate a strong `AUTH_SECRET`: `openssl rand -base64 32`.
- [ ] Configure Database URL: `DATABASE_URL=postgresql://user:pass@host:5432/easm`.
- [ ] Configure OIDC:
    - [ ] Google: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`.
    - [ ] Keycloak: `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_REALM`.
    - [ ] Redirect URIs must match: `http://<your-domain>/api/auth/callback/google`.

## 2. Database Migration

Run migrations from the `backend` directory:

```bash
cd backend
# Ensure DATABASE_URL is set in env or passed explicitly
sqlx migrate run
```

**Verification:**
- Check tables exist: `users`, `identities`, `assets`, `asset_risk_history`, etc.

## 3. Backend Deployment

- [ ] Build release binary: `cargo build --release`.
- [ ] Run binary: `./target/release/rust-backend`.
- [ ] Verify health check: `curl http://localhost:8000/api/health`.

## 4. Frontend Deployment

- [ ] Set `NEXT_PUBLIC_API_BASE` to your backend URL (e.g., `https://api.easm.example.com`).
- [ ] Build frontend: `npm run build`.
- [ ] Start frontend: `npm start`.

## 5. Post-Deployment Verification

1.  **Login Flow**:
    - Access frontend.
    - Click "Login with Google" or "Keycloak".
    - Verify redirection and successful callback.
    - Verify session cookie is set (`session`).

2.  **RBAC**:
    - New users default to `viewer` role.
    - Access DB to promote your admin user:
      ```sql
      UPDATE user_roles SET role = 'admin' WHERE user_id = (SELECT id FROM users WHERE email = 'your@email.com');
      ```
    - Verify "Settings" or "Seeds" menu access after refresh.

3.  **Risk Calculation**:
    - Run a scan or ensure assets exist.
    - Call risk recalculation (or wait for trigger):
      ```bash
      curl -X POST http://localhost:8000/api/risk/assets/<asset-id>/recalculate -b "session=..."
      ```
    - Verify `risk_score` and `risk_level` in asset details.

4.  **Search (if ES enabled)**:
    - Trigger reindex: `POST /api/search/reindex`.
    - Test search API.

## Operational Notes

- **Logs**: Structured JSON logs are enabled by default (`LOG_FORMAT=json`).
- **Metrics**: Prometheus metrics available at `/api/metrics`.
- **Backups**: Ensure PostgreSQL is backed up regularly.
- **Security**: Ensure `AUTH_SECRET` is rotated if compromised (invalidates all sessions).

