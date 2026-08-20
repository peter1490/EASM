"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  CardHeader,
  ErrorState,
  Icon,
  Input,
  LoadingBlock,
} from "@/components/kit";
import {
  getSettings,
  updateSettings,
  type SettingsResponse,
  type SettingsUpdatePayload,
  type SettingsView,
} from "@/app/api";
import { cn } from "@/lib/cn";
import { ConfirmDrawer, Field, Note, ToggleRow, errorMessage } from "./shared";

// ---------------------------------------------------------------------------
// Help text — one line per setting, surfaced by the `i` bubble on every label.
// ---------------------------------------------------------------------------

const HELP_TEXT: Record<string, string> = {
  google_client_id: "Google OAuth client ID.",
  google_client_secret: "Google OAuth client secret (kept encrypted).",
  google_discovery_url: "OIDC discovery endpoint for Google.",
  google_redirect_uri: "Redirect URL configured in your Google OAuth app.",
  google_allowed_domains: "Restrict Google sign-ins to these domains (comma separated).",
  keycloak_client_id: "Keycloak client ID for OIDC.",
  keycloak_client_secret: "Keycloak client secret (encrypted).",
  keycloak_discovery_url: "Keycloak OIDC discovery URL.",
  keycloak_redirect_uri: "Redirect URL configured in Keycloak client.",
  keycloak_realm: "Realm name for Keycloak if discovery URL is derived.",
  certspotter_api_token: "API token for CertSpotter certificate search.",
  virustotal_api_key: "API key for VirusTotal enrichment.",
  shodan_api_key: "API key for Shodan discovery.",
  urlscan_api_key: "API key for URLScan (planned).",
  otx_api_key: "API key for AlienVault OTX (planned).",
  clearbit_api_key: "API key for Clearbit enrichment (planned).",
  opencorporates_api_token: "API token for OpenCorporates (planned).",
  cors_allow_origins: "Allowed origins for browser requests (comma separated).",
  log_level: "Logging verbosity for backend/frontend.",
  log_format: "Log output format: json or plain.",
  rate_limit_enabled: "Enable global request rate limiting.",
  rate_limit_requests: "Max requests per window per instance.",
  rate_limit_window_seconds: "Window size in seconds for rate limiting.",
  http_timeout_seconds: "HTTP client request timeout for probes.",
  tls_timeout_seconds: "TLS handshake timeout for probes.",
  dns_concurrency: "Concurrent DNS queries allowed.",
  rdns_concurrency: "Concurrent reverse DNS queries.",
  max_concurrent_scans: "Max background scans running concurrently.",
  max_active_scans_per_user: "Scans one person may have pending or running at once.",
  max_active_discovery_per_user: "Discovery runs one person may have in flight at once.",
  block_internal_ip_scans: "Skip active scans against private or internal IP ranges.",
  max_evidence_bytes: "Maximum allowed upload size for evidence.",
  evidence_allowed_types: "Allowed MIME types for evidence uploads.",
  max_cidr_hosts: "Maximum hosts allowed per CIDR scan.",
  max_discovery_depth: "Maximum recursion depth for discovery pivots.",
  subdomain_enum_timeout: "Timeout (seconds) for subdomain enumeration.",
  enable_wayback: "Toggle Wayback Machine integration (planned).",
  enable_urlscan: "Toggle URLScan integration (planned).",
  enable_otx: "Toggle OTX integration (planned).",
  enable_dns_record_expansion: "Expand related DNS records during discovery.",
  enable_web_crawl: "Enable web crawling for link extraction (planned).",
  enable_cloud_storage_discovery: "Discover cloud storage buckets (planned).",
  enable_wikidata: "Toggle Wikidata enrichment (planned).",
  enable_opencorporates: "Toggle OpenCorporates enrichment (planned).",
  max_assets_per_discovery: "Cap total assets per discovery run.",
  min_pivot_confidence: "Minimum confidence required to pivot relationships.",
  max_orgs_per_domain: "Max organizations pivoted from a domain.",
  max_domains_per_org: "Max domains pivoted from an organization.",
  skip_unresolved_domains: "Don't add or enqueue domains that fail DNS resolution.",
  reindex_min_interval_seconds: "Minimum gap between full search reindexes, per company.",
};

// ---------------------------------------------------------------------------
// Form shape
// ---------------------------------------------------------------------------

type SettingsFormState = {
  google_client_id: string;
  google_client_secret: string;
  google_discovery_url: string;
  google_redirect_uri: string;
  google_allowed_domains: string;
  keycloak_client_id: string;
  keycloak_client_secret: string;
  keycloak_discovery_url: string;
  keycloak_redirect_uri: string;
  keycloak_realm: string;
  certspotter_api_token: string;
  virustotal_api_key: string;
  shodan_api_key: string;
  urlscan_api_key: string;
  otx_api_key: string;
  clearbit_api_key: string;
  opencorporates_api_token: string;
  cors_allow_origins: string;
  log_level: string;
  log_format: string;
  rate_limit_enabled: boolean;
  rate_limit_requests: string;
  rate_limit_window_seconds: string;
  http_timeout_seconds: string;
  tls_timeout_seconds: string;
  dns_concurrency: string;
  rdns_concurrency: string;
  max_concurrent_scans: string;
  max_active_scans_per_user: string;
  max_active_discovery_per_user: string;
  block_internal_ip_scans: boolean;
  max_evidence_bytes: string;
  evidence_allowed_types: string;
  max_cidr_hosts: string;
  max_discovery_depth: string;
  subdomain_enum_timeout: string;
  enable_wayback: boolean;
  enable_urlscan: boolean;
  enable_otx: boolean;
  enable_dns_record_expansion: boolean;
  enable_web_crawl: boolean;
  enable_cloud_storage_discovery: boolean;
  enable_wikidata: boolean;
  enable_opencorporates: boolean;
  max_assets_per_discovery: string;
  min_pivot_confidence: string;
  max_orgs_per_domain: string;
  max_domains_per_org: string;
  skip_unresolved_domains: boolean;
  reindex_min_interval_seconds: string;
};

/**
 * The nine encrypted fields. A secret only ever reaches the PATCH body when the
 * user actually typed in it — see `secretTouched` below.
 */
type SecretKey =
  | "google_client_secret"
  | "keycloak_client_secret"
  | "certspotter_api_token"
  | "virustotal_api_key"
  | "shodan_api_key"
  | "urlscan_api_key"
  | "otx_api_key"
  | "clearbit_api_key"
  | "opencorporates_api_token";

const PROVIDER_SECRETS: Array<{ key: SecretKey; label: string }> = [
  { key: "certspotter_api_token", label: "CertSpotter API token" },
  { key: "virustotal_api_key", label: "VirusTotal API key" },
  { key: "shodan_api_key", label: "Shodan API key" },
  { key: "urlscan_api_key", label: "URLScan API key" },
  { key: "otx_api_key", label: "OTX API key" },
  { key: "clearbit_api_key", label: "Clearbit API key" },
  { key: "opencorporates_api_token", label: "OpenCorporates token" },
];

const listToString = (items: string[]) => items.join(", ");

const settingsToForm = (view: SettingsView): SettingsFormState => ({
  google_client_id: view.google_client_id || "",
  google_client_secret: view.google_client_secret.value || "",
  google_discovery_url: view.google_discovery_url || "",
  google_redirect_uri: view.google_redirect_uri || "",
  google_allowed_domains: listToString(view.google_allowed_domains),
  keycloak_client_id: view.keycloak_client_id || "",
  keycloak_client_secret: view.keycloak_client_secret.value || "",
  keycloak_discovery_url: view.keycloak_discovery_url || "",
  keycloak_redirect_uri: view.keycloak_redirect_uri || "",
  keycloak_realm: view.keycloak_realm || "",
  certspotter_api_token: view.certspotter_api_token.value || "",
  virustotal_api_key: view.virustotal_api_key.value || "",
  shodan_api_key: view.shodan_api_key.value || "",
  urlscan_api_key: view.urlscan_api_key.value || "",
  otx_api_key: view.otx_api_key.value || "",
  clearbit_api_key: view.clearbit_api_key.value || "",
  opencorporates_api_token: view.opencorporates_api_token.value || "",
  cors_allow_origins: listToString(view.cors_allow_origins),
  log_level: view.log_level,
  log_format: view.log_format,
  rate_limit_enabled: view.rate_limit_enabled,
  rate_limit_requests: view.rate_limit_requests.toString(),
  rate_limit_window_seconds: view.rate_limit_window_seconds.toString(),
  http_timeout_seconds: view.http_timeout_seconds.toString(),
  tls_timeout_seconds: view.tls_timeout_seconds.toString(),
  dns_concurrency: view.dns_concurrency.toString(),
  rdns_concurrency: view.rdns_concurrency.toString(),
  max_concurrent_scans: view.max_concurrent_scans.toString(),
  max_active_scans_per_user: view.max_active_scans_per_user.toString(),
  max_active_discovery_per_user: view.max_active_discovery_per_user.toString(),
  block_internal_ip_scans: view.block_internal_ip_scans,
  max_evidence_bytes: view.max_evidence_bytes.toString(),
  evidence_allowed_types: listToString(view.evidence_allowed_types),
  max_cidr_hosts: view.max_cidr_hosts.toString(),
  max_discovery_depth: view.max_discovery_depth.toString(),
  subdomain_enum_timeout: view.subdomain_enum_timeout.toString(),
  enable_wayback: view.enable_wayback,
  enable_urlscan: view.enable_urlscan,
  enable_otx: view.enable_otx,
  enable_dns_record_expansion: view.enable_dns_record_expansion,
  enable_web_crawl: view.enable_web_crawl,
  enable_cloud_storage_discovery: view.enable_cloud_storage_discovery,
  enable_wikidata: view.enable_wikidata,
  enable_opencorporates: view.enable_opencorporates,
  max_assets_per_discovery: view.max_assets_per_discovery.toString(),
  min_pivot_confidence: view.min_pivot_confidence.toString(),
  max_orgs_per_domain: view.max_orgs_per_domain.toString(),
  max_domains_per_org: view.max_domains_per_org.toString(),
  skip_unresolved_domains: view.skip_unresolved_domains,
  reindex_min_interval_seconds: view.reindex_min_interval_seconds.toString(),
});

const splitList = (value: string): string[] =>
  value
    .split(/[,\n]/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);

const toNumber = (value: string): number | undefined => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

// ---------------------------------------------------------------------------
// Controls. Defined at module scope: a component declared inside the pane body
// is a new type on every render, which would remount the input and drop focus
// after each keystroke.
// ---------------------------------------------------------------------------

function TextRow({
  label,
  help,
  value,
  onChange,
  placeholder,
  type,
  step,
}: {
  label: string;
  help?: string;
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  type?: string;
  step?: string;
}) {
  return (
    <Field label={label} help={help}>
      <Input
        type={type}
        step={step}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </Field>
  );
}

function SecretRow({
  label,
  help,
  value,
  isSet,
  revealed,
  visible,
  touched,
  onChange,
  onToggleVisibility,
}: {
  label: string;
  help?: string;
  value: string;
  isSet: boolean;
  revealed: boolean;
  visible: boolean;
  touched: boolean;
  onChange: (next: string) => void;
  onToggleVisibility: () => void;
}) {
  const shown = visible && revealed;
  return (
    <Field
      label={label}
      help={help}
      hint={
        <span className="flex flex-wrap items-center gap-1">
          <span className={isSet ? "text-ok" : "text-ink-3"}>{isSet ? "Stored" : "Not set"}</span>
          {touched ? (
            <span className="text-accent">· replaced on save</span>
          ) : isSet ? (
            <span>· untouched, left as-is on save</span>
          ) : null}
        </span>
      }
    >
      <div className="relative">
        <Input
          type={shown ? "text" : "password"}
          value={value}
          autoComplete="off"
          spellCheck={false}
          placeholder={isSet ? "••••••••" : "Not set"}
          className={cn("pr-9", touched && "border-accent")}
          onChange={(e) => onChange(e.target.value)}
        />
        <button
          type="button"
          onClick={onToggleVisibility}
          disabled={!revealed}
          title={revealed ? (shown ? "Hide value" : "Show value") : "Reveal secrets first"}
          aria-label={shown ? `Hide ${label}` : `Show ${label}`}
          className={cn(
            "absolute right-1 top-1/2 -translate-y-1/2 grid place-items-center w-[24px] h-[24px] rounded",
            revealed
              ? "text-ink-2 hover:text-ink hover:bg-surface-2"
              : "text-ink-3 opacity-45 cursor-not-allowed",
          )}
        >
          <Icon name={shown ? "eyeOff" : "eye"} size={13} />
        </button>
      </div>
    </Field>
  );
}

// ---------------------------------------------------------------------------

export function IntegrationsPane() {
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [form, setForm] = useState<SettingsFormState | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revealError, setRevealError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [confirmReveal, setConfirmReveal] = useState(false);

  /** Whether the last fetch asked the server to decrypt secrets. Carried into the save. */
  const [secretsRevealed, setSecretsRevealed] = useState(false);
  /** Only a touched secret is sent; an untouched one is omitted so the stored key survives. */
  const [secretTouched, setSecretTouched] = useState<Record<string, boolean>>({});
  /** Per-field eye toggle — inert until secrets were actually revealed. */
  const [secretVisibility, setSecretVisibility] = useState<Record<string, boolean>>({});

  const load = useCallback(async (reveal: boolean) => {
    if (reveal) setRevealError(null);
    else setLoading(true);
    try {
      const next = await getSettings(reveal);
      setData(next);
      setForm(settingsToForm(next.settings));
      setSecretsRevealed(reveal);
      setSecretTouched({});
      setSecretVisibility({});
      setError(null);
      return true;
    } catch (e) {
      const message = errorMessage(e);
      // Reveal is allowed to fail on its own (session + break-glass header are
      // required); when it does, keep the masked view we already have.
      if (reveal) setRevealError(message);
      else setError(message);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load(false);
  }, [load]);

  const pristine = useMemo(() => (data ? settingsToForm(data.settings) : null), [data]);
  const touchedAnySecret = Object.values(secretTouched).some(Boolean);
  /**
   * Touching a secret counts even when the field ends up matching what it held
   * before — clearing a stored key back to empty is a real, saveable edit that
   * a value comparison alone would call pristine.
   */
  const dirty = useMemo(
    () =>
      touchedAnySecret || (form && pristine ? JSON.stringify(form) !== JSON.stringify(pristine) : false),
    [form, pristine, touchedAnySecret],
  );

  function set<K extends keyof SettingsFormState>(key: K, value: SettingsFormState[K]) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  function setSecret(key: SecretKey, value: string) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
    setSecretTouched((prev) => ({ ...prev, [key]: true }));
  }

  function buildPayload(current: SettingsFormState): SettingsUpdatePayload {
    const payload: SettingsUpdatePayload = {
      google_client_id: current.google_client_id || null,
      google_discovery_url: current.google_discovery_url || null,
      google_redirect_uri: current.google_redirect_uri || null,
      google_allowed_domains: splitList(current.google_allowed_domains),
      keycloak_client_id: current.keycloak_client_id || null,
      keycloak_discovery_url: current.keycloak_discovery_url || null,
      keycloak_redirect_uri: current.keycloak_redirect_uri || null,
      keycloak_realm: current.keycloak_realm || null,
      cors_allow_origins: splitList(current.cors_allow_origins),
      log_level: current.log_level,
      log_format: current.log_format,
      rate_limit_enabled: current.rate_limit_enabled,
      rate_limit_requests: toNumber(current.rate_limit_requests),
      rate_limit_window_seconds: toNumber(current.rate_limit_window_seconds),
      http_timeout_seconds: toNumber(current.http_timeout_seconds),
      tls_timeout_seconds: toNumber(current.tls_timeout_seconds),
      dns_concurrency: toNumber(current.dns_concurrency),
      rdns_concurrency: toNumber(current.rdns_concurrency),
      max_concurrent_scans: toNumber(current.max_concurrent_scans),
      max_active_scans_per_user: toNumber(current.max_active_scans_per_user),
      max_active_discovery_per_user: toNumber(current.max_active_discovery_per_user),
      block_internal_ip_scans: current.block_internal_ip_scans,
      max_evidence_bytes: toNumber(current.max_evidence_bytes),
      evidence_allowed_types: splitList(current.evidence_allowed_types),
      max_cidr_hosts: toNumber(current.max_cidr_hosts),
      max_discovery_depth: toNumber(current.max_discovery_depth),
      subdomain_enum_timeout: toNumber(current.subdomain_enum_timeout),
      enable_wayback: current.enable_wayback,
      enable_urlscan: current.enable_urlscan,
      enable_otx: current.enable_otx,
      enable_dns_record_expansion: current.enable_dns_record_expansion,
      enable_web_crawl: current.enable_web_crawl,
      enable_cloud_storage_discovery: current.enable_cloud_storage_discovery,
      enable_wikidata: current.enable_wikidata,
      enable_opencorporates: current.enable_opencorporates,
      max_assets_per_discovery: toNumber(current.max_assets_per_discovery),
      min_pivot_confidence: toNumber(current.min_pivot_confidence),
      max_orgs_per_domain: toNumber(current.max_orgs_per_domain),
      max_domains_per_org: toNumber(current.max_domains_per_org),
      skip_unresolved_domains: current.skip_unresolved_domains,
      reindex_min_interval_seconds: toNumber(current.reindex_min_interval_seconds),
    };

    // An untouched secret is omitted entirely. Sending "" would blank the key.
    if (secretTouched.google_client_secret) payload.google_client_secret = current.google_client_secret || null;
    if (secretTouched.keycloak_client_secret) payload.keycloak_client_secret = current.keycloak_client_secret || null;
    if (secretTouched.certspotter_api_token) payload.certspotter_api_token = current.certspotter_api_token || null;
    if (secretTouched.virustotal_api_key) payload.virustotal_api_key = current.virustotal_api_key || null;
    if (secretTouched.shodan_api_key) payload.shodan_api_key = current.shodan_api_key || null;
    if (secretTouched.urlscan_api_key) payload.urlscan_api_key = current.urlscan_api_key || null;
    if (secretTouched.otx_api_key) payload.otx_api_key = current.otx_api_key || null;
    if (secretTouched.clearbit_api_key) payload.clearbit_api_key = current.clearbit_api_key || null;
    if (secretTouched.opencorporates_api_token)
      payload.opencorporates_api_token = current.opencorporates_api_token || null;

    return payload;
  }

  async function save() {
    if (!form) return;
    setSaving(true);
    try {
      // The reveal flag rides along so the response comes back in the same shape
      // the form is currently rendering.
      const next = await updateSettings(buildPayload(form), secretsRevealed);
      setData(next);
      setForm(settingsToForm(next.settings));
      setSecretTouched({});
      setError(null);
      setSavedAt(Date.now());
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  function reset() {
    if (!data) return;
    setForm(settingsToForm(data.settings));
    setSecretTouched({});
  }

  function toggleVisibility(key: SecretKey) {
    if (!secretsRevealed) return;
    setSecretVisibility((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  if (loading && !data) return <LoadingBlock label="Loading configuration" />;

  if (!data || !form) {
    return <ErrorState error={error ?? "Configuration could not be loaded."} onRetry={() => load(false)} />;
  }

  const view = data.settings;
  const current = form;

  const text = (
    field: keyof SettingsFormState,
    label: string,
    opts?: { placeholder?: string; type?: string; step?: string; transform?: (v: string) => string },
  ) => (
    <TextRow
      key={field}
      label={label}
      help={HELP_TEXT[field]}
      value={current[field] as string}
      placeholder={opts?.placeholder}
      type={opts?.type}
      step={opts?.step}
      onChange={(next) => set(field, (opts?.transform ? opts.transform(next) : next) as never)}
    />
  );

  const secret = (field: SecretKey, label: string) => (
    <SecretRow
      key={field}
      label={label}
      help={HELP_TEXT[field]}
      value={current[field]}
      isSet={view[field].is_set}
      revealed={secretsRevealed}
      visible={!!secretVisibility[field]}
      touched={!!secretTouched[field]}
      onChange={(next) => setSecret(field, next)}
      onToggleVisibility={() => toggleVisibility(field)}
    />
  );

  return (
    <div className="space-y-4">
      <Card className="sticky top-0 z-20">
        <CardHeader
          title="Integrations and controls"
          hint={dirty ? "Unsaved changes" : savedAt ? "Saved" : undefined}
          actions={
            <>
              <Button
                size="sm"
                icon="key"
                onClick={() => (dirty ? setConfirmReveal(true) : load(true))}
                disabled={loading || saving}
              >
                {secretsRevealed ? "Refresh secrets" : "Reveal secrets"}
              </Button>
              <Button size="sm" onClick={reset} disabled={!dirty || saving}>
                Reset changes
              </Button>
              <Button size="sm" variant="primary" onClick={save} loading={saving} disabled={!dirty}>
                Save settings
              </Button>
            </>
          }
        />
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 px-4 py-2.5 text-[11.5px] text-ink-2">
          <span>
            Last updated <span className="mono">{new Date(data.updated_at).toLocaleString()}</span>
          </span>
          {data.updated_by && (
            <span>
              by <span className="mono">{data.updated_by.slice(0, 8)}</span>
            </span>
          )}
          <span className={secretsRevealed ? "text-accent" : "text-ink-3"}>
            Secrets {secretsRevealed ? "revealed" : "masked"}
          </span>
        </div>
      </Card>

      {error && <ErrorState error={error} onRetry={() => load(false)} />}

      {revealError && (
        <ErrorState
          error={`Secrets stayed masked. Revealing them needs a signed-in browser session (not an API key) and an X-Break-Glass-Token header — the server answered: ${revealError}`}
          onRetry={() => load(true)}
        />
      )}

      <Card>
        <CardHeader title="Authentication and SSO" hint="Google and Keycloak identity providers" />
        <div className="p-4 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            {text("google_client_id", "Google client ID", {
              placeholder: "client-id.apps.googleusercontent.com",
            })}
            {secret("google_client_secret", "Google client secret")}
            {text("google_discovery_url", "Google discovery URL")}
            {text("google_redirect_uri", "Google redirect URI")}
          </div>
          {text("google_allowed_domains", "Google allowed domains", { placeholder: "example.com, example.org" })}
          <div className="h-px bg-rule" />
          <div className="grid gap-4 sm:grid-cols-2">
            {text("keycloak_client_id", "Keycloak client ID")}
            {secret("keycloak_client_secret", "Keycloak client secret")}
            {text("keycloak_discovery_url", "Keycloak discovery URL", {
              placeholder: "https://idp.example.com/realms/<realm>",
            })}
            {text("keycloak_redirect_uri", "Keycloak redirect URI")}
          </div>
          {text("keycloak_realm", "Keycloak realm")}
        </div>
      </Card>

      <Card>
        <CardHeader title="External API keys" hint="Threat intel and enrichment providers" />
        <div className="p-4 space-y-4">
          {!secretsRevealed && (
            <Note icon="key">
              Values are masked. Typing in a field replaces that key on save; every field you do not touch is left out of
              the request entirely, so stored keys survive.
            </Note>
          )}
          <div className="grid gap-4 sm:grid-cols-2">{PROVIDER_SECRETS.map((s) => secret(s.key, s.label))}</div>
        </div>
      </Card>

      <Card>
        <CardHeader title="Application controls" hint="CORS, logging, rate limits and probe budgets" />
        <div className="p-4 space-y-4">
          {text("cors_allow_origins", "CORS allow origins", {
            placeholder: "http://localhost:3000, http://127.0.0.1:3000",
          })}
          <div className="grid gap-4 sm:grid-cols-2">
            {text("log_level", "Log level", { placeholder: "INFO", transform: (v) => v.toUpperCase() })}
            {text("log_format", "Log format", { placeholder: "json or plain" })}
            {text("rate_limit_requests", "Rate limit requests", { type: "number" })}
            {text("rate_limit_window_seconds", "Rate limit window (s)", { type: "number" })}
            {text("http_timeout_seconds", "HTTP timeout (s)", { type: "number" })}
            {text("tls_timeout_seconds", "TLS timeout (s)", { type: "number" })}
            {text("dns_concurrency", "DNS concurrency", { type: "number" })}
            {text("rdns_concurrency", "rDNS concurrency", { type: "number" })}
            {text("max_concurrent_scans", "Max concurrent scans", { type: "number" })}
            {text("max_active_scans_per_user", "Max active scans per user", { type: "number" })}
            {text("max_active_discovery_per_user", "Max active discovery runs per user", { type: "number" })}
            {text("reindex_min_interval_seconds", "Search reindex cooldown (s)", { type: "number" })}
          </div>
          <div className="h-px bg-rule" />
          <ToggleRow
            label="Enable rate limiting"
            help={HELP_TEXT.rate_limit_enabled}
            checked={form.rate_limit_enabled}
            onChange={(v) => set("rate_limit_enabled", v)}
          />
          <ToggleRow
            label="Never scan internal IPs"
            help={HELP_TEXT.block_internal_ip_scans}
            checked={form.block_internal_ip_scans}
            onChange={(v) => set("block_internal_ip_scans", v)}
          />
        </div>
      </Card>

      <Card>
        <CardHeader title="Evidence, discovery and limits" hint="Storage, recursion and pivot guardrails" />
        <div className="p-4 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            {text("max_evidence_bytes", "Max evidence size (bytes)", { type: "number" })}
            {text("evidence_allowed_types", "Allowed evidence types", {
              placeholder: "image/png, image/jpeg, application/pdf",
            })}
            {text("max_cidr_hosts", "Max CIDR hosts", { type: "number" })}
            {text("max_discovery_depth", "Max discovery depth", { type: "number" })}
            {text("subdomain_enum_timeout", "Subdomain enum timeout (s)", { type: "number" })}
            {text("max_assets_per_discovery", "Max assets per discovery", { type: "number" })}
            {text("min_pivot_confidence", "Min pivot confidence", { type: "number", step: "0.01" })}
            {text("max_orgs_per_domain", "Max orgs per domain", { type: "number" })}
            {text("max_domains_per_org", "Max domains per org", { type: "number" })}
          </div>
          <div className="h-px bg-rule" />
          <ToggleRow
            label="Skip unresolved domains"
            help={HELP_TEXT.skip_unresolved_domains}
            checked={form.skip_unresolved_domains}
            onChange={(v) => set("skip_unresolved_domains", v)}
          />
        </div>
      </Card>

      <Card>
        <CardHeader title="OSINT sources" hint="Enrichment providers used during discovery" />
        <div className="p-4 grid gap-x-8 sm:grid-cols-2">
          {(
            [
              ["enable_wayback", "Wayback Machine"],
              ["enable_urlscan", "URLScan"],
              ["enable_otx", "OTX"],
              ["enable_dns_record_expansion", "DNS record expansion"],
              ["enable_web_crawl", "Web crawl"],
              ["enable_cloud_storage_discovery", "Cloud storage discovery"],
              ["enable_wikidata", "Wikidata"],
              ["enable_opencorporates", "OpenCorporates"],
            ] as Array<[keyof SettingsFormState, string]>
          ).map(([key, label]) => (
            <ToggleRow
              key={key}
              label={label}
              help={HELP_TEXT[key]}
              checked={form[key] as boolean}
              onChange={(v) => set(key, v as never)}
            />
          ))}
        </div>
      </Card>

      <ConfirmDrawer
        open={confirmReveal}
        onClose={() => setConfirmReveal(false)}
        title="Discard unsaved changes?"
        hint="Revealing secrets refetches every setting"
        confirmLabel="Discard and reveal"
        confirmVariant="primary"
        onConfirm={() => {
          setConfirmReveal(false);
          load(true);
        }}
      >
        <p className="text-[12.5px] text-ink-2">
          Revealing asks the server for the decrypted values, which replaces the whole form. Edits you have not saved
          yet will be lost.
        </p>
      </ConfirmDrawer>
    </div>
  );
}
