# Mitigations and Concrete Code Fixes (Draft)

This document lists concrete code-level mitigations for each threat in `EASM-threat-model.md`. No changes have been applied yet.

## TM-001 — Auth disabled when `API_KEYS` empty
**Goal:** Prevent accidental unauthenticated access in Internet-exposed deployments.

Proposed code changes:
- Add a startup guard that fails fast in production if `api_keys` is empty.
  - File: `backend/src/main.rs` (or `backend/src/config.rs` validation)
  - Logic: if `settings.environment == "production" && settings.api_keys.is_empty()` then return an error with a clear message.
- Add config validation in `Settings::new_with_options` to enforce minimum auth config in production.
  - File: `backend/src/config.rs`
  - Add a `validate()` method and call it during settings creation.

## TM-002 — API key theft grants full admin access
**Goal:** Scope API keys and reduce blast radius.

Proposed code changes:
- Change `API_KEYS` format to include scope (company_id + role), e.g. `key:company_uuid:role` and parse into structured config.
  - File: `backend/src/config.rs`
  - New struct: `ApiKeyScope { key_hash, company_id, role }`.
- Hash API keys at rest (config) and compare with constant-time check.
  - File: `backend/src/middleware/auth.rs` (hash compare), `backend/src/config.rs` (hash on load or provide hash list).
- In auth middleware, do not allow `X-Company-ID` override for API keys unless scope explicitly allows it.
  - File: `backend/src/middleware/auth.rs`
- Add optional IP allowlist or mTLS requirement for API-key usage (config-driven).
  - File: `backend/src/middleware/auth.rs` or new middleware.

## TM-003 — Permissive CORS with credentials (CSRF/data exfil)
**Goal:** Prevent credentialed cross-origin access and state changes.

Proposed code changes:
- Disallow `*` or empty allowlist when `allow_credentials=true`; fail fast in production.
  - File: `backend/src/middleware/cors.rs`
- Add CSRF protection for state-changing routes (POST/PATCH/DELETE).
  - Files: new `backend/src/middleware/csrf.rs`, apply in `backend/src/main.rs` to protected routes.
  - Frontend: add CSRF token header in `frontend/src/app/api.ts` for mutating calls.
- Set `SameSite=Strict` for session cookies in production.
  - File: `backend/src/handlers/auth_handlers.rs`

## TM-004 — Scan/Discovery misuse for internal probing (SSRF-like)
**Goal:** Enforce strict scan target policy to prevent internal network abuse.

Proposed code changes:
- Add explicit allowlist for scan targets (CIDRs/domains) per deployment.
  - File: `backend/src/config.rs` (new settings), `backend/src/services/scan_service.rs`, `backend/src/services/security_scan_service.rs` (validate targets)
- Hard-block RFC1918 ranges in production regardless of UI settings (unless a new `ALLOW_INTERNAL_SCANS` env var is set).
  - File: `backend/src/services/scan_service.rs`, `backend/src/services/security_scan_service.rs`
- Add audit logging for scan targets and source user.
  - File: `backend/src/services/*` (task metadata) and logging middleware.

## TM-005 — Cross-company data access within tenant
**Goal:** Ensure all data access is scoped to `company_id`.

Proposed code changes:
- Require a resolved `company_id` in `UserContext` for all authenticated requests; reject if missing.
  - File: `backend/src/middleware/auth.rs`
- Enforce company scoping at repository layer (not just handlers).
  - Files: `backend/src/repositories/*` (ensure all query methods take `company_id` and filter by it)
- Add integration tests for cross-company access.
  - File: `backend/tests/integration_test.rs` (or new tests)

## TM-006 — Settings/secret reveal abuse
**Goal:** Reduce exposure of sensitive config even for admins.

Proposed code changes:
- Remove `reveal_secrets` from API or require explicit break-glass header and re-auth.
  - File: `backend/src/handlers/settings_handlers.rs`
- Add auditing whenever secret fields are accessed or changed.
  - File: `backend/src/handlers/settings_handlers.rs` and logging
- Store secrets in a secure store (KMS/Vault); only return redacted values from API.
  - File: `backend/src/config/secure_store.rs` and `backend/src/handlers/settings_handlers.rs`

## TM-007 — Evidence data exposure
**Goal:** Ensure evidence access is permissioned and safe.

Proposed code changes:
- Enforce RBAC permissions on evidence endpoints (view/download).
  - File: `backend/src/handlers/evidence_handlers.rs` (use `require_permission` macro)
- Canonicalize file paths on download (match static handler safety) and verify within evidence directory.
  - File: `backend/src/handlers/evidence_handlers.rs`
- Ensure evidence queries are company-scoped.
  - File: `backend/src/repositories/evidence_repo.rs`

## TM-008 — Task/scan DoS
**Goal:** Rate-limit and constrain costly operations.

Proposed code changes:
- Wire rate limiting middleware into router (global and IP-based), and enable only when config says so.
  - File: `backend/src/main.rs` (apply `rate_limit_middleware` or `ip_rate_limit_middleware`)
- Add per-user/task quotas for scans/discovery (max active tasks per user).
  - File: `backend/src/services/task_manager.rs` and `backend/src/services/*` submission paths
- Add endpoint-specific limits for expensive routes like `/api/search/reindex`.
  - File: `backend/src/handlers/search_handlers.rs`

---

## Next step
Confirm these mitigation targets and priority. Once you approve, I can implement them in code (starting with the top 2–3).
