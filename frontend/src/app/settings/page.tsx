"use client";

import { useCallback, useEffect, useState } from "react";
import { 
  getHealth, 
  getMetrics, 
  listUsers,
  createUser,
  updateUser,
  deleteUser,
  updateUserRole, 
  getSettings,
  updateSettings,
  type SystemMetrics, 
  type UserWithRoles,
  type SettingsResponse,
  type SettingsView,
  type CreateUserRequest,
  type UpdateUserRequest,
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import Select from "@/components/ui/Select";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";
import Modal from "@/components/ui/Modal";
import Input from "@/components/ui/Input";
import Checkbox from "@/components/ui/Checkbox";

type TabType = "status" | "users" | "config";

const ROLE_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  admin: "error",
  operator: "warning",
  analyst: "info",
  viewer: "secondary",
};

const ROLE_DESCRIPTIONS: Record<string, string> = {
  admin: "Full access - can manage users and all settings",
  operator: "Can run scans, discovery, and modify assets",
  analyst: "Can view assets, findings, and update importance",
  viewer: "Read-only access to all data",
};

const ALL_ROLES = ["admin", "operator", "analyst", "viewer"];

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
};

type SecretFieldKey =
  | "certspotter_api_token"
  | "virustotal_api_key"
  | "shodan_api_key"
  | "urlscan_api_key"
  | "otx_api_key"
  | "clearbit_api_key"
  | "opencorporates_api_token";

const SECRET_FIELDS: Array<{ key: SecretFieldKey; label: string }> = [
  { key: "certspotter_api_token", label: "CertSpotter API Token" },
  { key: "virustotal_api_key", label: "VirusTotal API Key" },
  { key: "shodan_api_key", label: "Shodan API Key" },
  { key: "urlscan_api_key", label: "URLScan API Key" },
  { key: "otx_api_key", label: "OTX API Key" },
  { key: "clearbit_api_key", label: "Clearbit API Key" },
  { key: "opencorporates_api_token", label: "OpenCorporates Token" },
];

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
};

const createEmptySettingsForm = (): SettingsFormState => ({
  google_client_id: "",
  google_client_secret: "",
  google_discovery_url: "",
  google_redirect_uri: "",
  google_allowed_domains: "",
  keycloak_client_id: "",
  keycloak_client_secret: "",
  keycloak_discovery_url: "",
  keycloak_redirect_uri: "",
  keycloak_realm: "",
  certspotter_api_token: "",
  virustotal_api_key: "",
  shodan_api_key: "",
  urlscan_api_key: "",
  otx_api_key: "",
  clearbit_api_key: "",
  opencorporates_api_token: "",
  cors_allow_origins: "",
  log_level: "INFO",
  log_format: "json",
  rate_limit_enabled: true,
  rate_limit_requests: "",
  rate_limit_window_seconds: "",
  http_timeout_seconds: "",
  tls_timeout_seconds: "",
  dns_concurrency: "",
  rdns_concurrency: "",
  max_concurrent_scans: "",
  max_evidence_bytes: "",
  evidence_allowed_types: "",
  max_cidr_hosts: "",
  max_discovery_depth: "",
  subdomain_enum_timeout: "",
  enable_wayback: true,
  enable_urlscan: false,
  enable_otx: false,
  enable_dns_record_expansion: true,
  enable_web_crawl: true,
  enable_cloud_storage_discovery: true,
  enable_wikidata: true,
  enable_opencorporates: false,
  max_assets_per_discovery: "",
  min_pivot_confidence: "",
  max_orgs_per_domain: "",
  max_domains_per_org: "",
});

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

const InfoLabel = ({ text, keyName }: { text: string; keyName: string }) => {
  const help = HELP_TEXT[keyName] || "No description available";
  return (
    <div className="flex items-center gap-2">
      <span>{text}</span>
      <span className="relative inline-flex items-center group z-30">
        <span
          className="inline-flex items-center justify-center w-4 h-4 text-xs rounded-full border border-border text-muted-foreground hover:text-foreground cursor-help bg-background/90"
          aria-label={help}
        >
          i
        </span>
        <span className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-2 hidden whitespace-pre-wrap rounded-md border border-border bg-popover/95 backdrop-blur-sm px-3 py-2 text-xs text-foreground shadow-xl ring-1 ring-border group-hover:block group-focus-within:block z-40">
          {help}
        </span>
      </span>
    </div>
  );
};

export default function SettingsPage() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<TabType>("status");
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<{ status: string; version: string } | null>(null);
  const [users, setUsers] = useState<UserWithRoles[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState<string | null>(null);
  const [settingsData, setSettingsData] = useState<SettingsResponse | null>(null);
  const [settingsForm, setSettingsForm] = useState<SettingsFormState>(createEmptySettingsForm());
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [secretsRevealed, setSecretsRevealed] = useState(false);
  const [secretTouched, setSecretTouched] = useState<Record<string, boolean>>({});
  const [secretVisibility, setSecretVisibility] = useState<Record<string, boolean>>({});
  
  // Edit user modal
  const [selectedUser, setSelectedUser] = useState<UserWithRoles | null>(null);
  const [selectedRole, setSelectedRole] = useState("");
  
  // Create/Edit user modal
  const [showUserModal, setShowUserModal] = useState(false);
  const [editingUser, setEditingUser] = useState<UserWithRoles | null>(null);
  const [userFormData, setUserFormData] = useState({
    email: "",
    password: "",
    display_name: "",
    is_active: true,
    roles: [] as string[],
  });
  const [userFormLoading, setUserFormLoading] = useState(false);
  const [userFormError, setUserFormError] = useState<string | null>(null);
  
  // Delete confirmation
  const [deleteConfirmUser, setDeleteConfirmUser] = useState<UserWithRoles | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const isAdmin = user?.roles?.includes("admin");

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [metricsData, healthData] = await Promise.all([
        getMetrics(),
        getHealth(),
      ]);
      
      setMetrics(metricsData);
      setHealth(healthData);
      
      if (isAdmin) {
        const usersData = await listUsers();
        setUsers(usersData);
      } else {
        setUsers([]);
      }
      
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [isAdmin]);

  const loadSettings = useCallback(async (reveal = false) => {
    if (!isAdmin) return;
    try {
      setSettingsLoading(true);
      const data = await getSettings(reveal);
      setSettingsData(data);
      setSettingsForm(settingsToForm(data.settings));
      setSecretsRevealed(reveal);
      setSecretTouched({});
      setSecretVisibility({});
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSettingsLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    loadData();
    if (isAdmin) {
      loadSettings(false);
    }
    const iv = setInterval(loadData, 10000);
    return () => clearInterval(iv);
  }, [isAdmin, loadData, loadSettings]);

  async function handleAddRole(userId: string, role: string) {
    if (!role) return;
    setUpdating(userId);
    try {
      await updateUserRole(userId, role, "add");
      loadData();
      setSelectedRole("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(null);
    }
  }

  function updateFormField<K extends keyof SettingsFormState>(key: K, value: SettingsFormState[K]) {
    setSettingsForm((prev) => ({ ...prev, [key]: value }));
  }

  function buildSettingsPayload() {
    const payload: Parameters<typeof updateSettings>[0] = {
      google_client_id: settingsForm.google_client_id || null,
      google_discovery_url: settingsForm.google_discovery_url || null,
      google_redirect_uri: settingsForm.google_redirect_uri || null,
      google_allowed_domains: splitList(settingsForm.google_allowed_domains),
      keycloak_client_id: settingsForm.keycloak_client_id || null,
      keycloak_discovery_url: settingsForm.keycloak_discovery_url || null,
      keycloak_redirect_uri: settingsForm.keycloak_redirect_uri || null,
      keycloak_realm: settingsForm.keycloak_realm || null,
      cors_allow_origins: splitList(settingsForm.cors_allow_origins),
      log_level: settingsForm.log_level,
      log_format: settingsForm.log_format,
      rate_limit_enabled: settingsForm.rate_limit_enabled,
      rate_limit_requests: toNumber(settingsForm.rate_limit_requests),
      rate_limit_window_seconds: toNumber(settingsForm.rate_limit_window_seconds),
      http_timeout_seconds: toNumber(settingsForm.http_timeout_seconds),
      tls_timeout_seconds: toNumber(settingsForm.tls_timeout_seconds),
      dns_concurrency: toNumber(settingsForm.dns_concurrency),
      rdns_concurrency: toNumber(settingsForm.rdns_concurrency),
      max_concurrent_scans: toNumber(settingsForm.max_concurrent_scans),
      max_evidence_bytes: toNumber(settingsForm.max_evidence_bytes),
      evidence_allowed_types: splitList(settingsForm.evidence_allowed_types),
      max_cidr_hosts: toNumber(settingsForm.max_cidr_hosts),
      max_discovery_depth: toNumber(settingsForm.max_discovery_depth),
      subdomain_enum_timeout: toNumber(settingsForm.subdomain_enum_timeout),
      enable_wayback: settingsForm.enable_wayback,
      enable_urlscan: settingsForm.enable_urlscan,
      enable_otx: settingsForm.enable_otx,
      enable_dns_record_expansion: settingsForm.enable_dns_record_expansion,
      enable_web_crawl: settingsForm.enable_web_crawl,
      enable_cloud_storage_discovery: settingsForm.enable_cloud_storage_discovery,
      enable_wikidata: settingsForm.enable_wikidata,
      enable_opencorporates: settingsForm.enable_opencorporates,
      max_assets_per_discovery: toNumber(settingsForm.max_assets_per_discovery),
      min_pivot_confidence: toNumber(settingsForm.min_pivot_confidence),
      max_orgs_per_domain: toNumber(settingsForm.max_orgs_per_domain),
      max_domains_per_org: toNumber(settingsForm.max_domains_per_org),
    };

    if (secretTouched.google_client_secret) {
      payload.google_client_secret = settingsForm.google_client_secret || null;
    }
    if (secretTouched.keycloak_client_secret) {
      payload.keycloak_client_secret = settingsForm.keycloak_client_secret || null;
    }
    if (secretTouched.certspotter_api_token) {
      payload.certspotter_api_token = settingsForm.certspotter_api_token || null;
    }
    if (secretTouched.virustotal_api_key) {
      payload.virustotal_api_key = settingsForm.virustotal_api_key || null;
    }
    if (secretTouched.shodan_api_key) {
      payload.shodan_api_key = settingsForm.shodan_api_key || null;
    }
    if (secretTouched.urlscan_api_key) {
      payload.urlscan_api_key = settingsForm.urlscan_api_key || null;
    }
    if (secretTouched.otx_api_key) {
      payload.otx_api_key = settingsForm.otx_api_key || null;
    }
    if (secretTouched.clearbit_api_key) {
      payload.clearbit_api_key = settingsForm.clearbit_api_key || null;
    }
    if (secretTouched.opencorporates_api_token) {
      payload.opencorporates_api_token = settingsForm.opencorporates_api_token || null;
    }

    return payload;
  }

  async function handleSaveSettings() {
    try {
      setSettingsSaving(true);
      const payload = buildSettingsPayload();
      const data = await updateSettings(payload, secretsRevealed);
      setSettingsData(data);
      setSettingsForm(settingsToForm(data.settings));
      setSecretTouched({});
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSettingsSaving(false);
    }
  }

  async function handleRevealSecrets() {
    await loadSettings(true);
  }

  function resetSettingsForm() {
    if (settingsData) {
      setSettingsForm(settingsToForm(settingsData.settings));
      setSecretTouched({});
    }
  }

  const toggleSecretVisibility = (field: string) => {
    if (!secretsRevealed) return;
    setSecretVisibility((prev) => ({ ...prev, [field]: !prev[field] }));
  };

  const secretInput = (
    field: keyof SettingsFormState,
    label: string,
    placeholder?: string
  ) => (
    <Input
      label={<InfoLabel text={label} keyName={field} />}
      type={secretVisibility[field] && secretsRevealed ? "text" : "password"}
      value={settingsForm[field] as string}
      placeholder={placeholder}
      onChange={(e) => {
        updateFormField(field, e.target.value as never);
        setSecretTouched((prev) => ({ ...prev, [field]: true }));
      }}
      rightSlot={
        <button
          type="button"
          className={`text-xs px-2 py-1 rounded ${secretsRevealed ? "text-foreground" : "text-muted-foreground cursor-not-allowed"}`}
          onClick={() => toggleSecretVisibility(field)}
          disabled={!secretsRevealed}
          title={secretsRevealed ? "Toggle visibility" : "Click Reveal Secrets first"}
        >
          {secretVisibility[field] && secretsRevealed ? "🙈" : "👁"}
        </button>
      }
    />
  );

  async function handleRemoveRole(userId: string, role: string) {
    setUpdating(userId);
    try {
      await updateUserRole(userId, role, "remove");
      loadData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(null);
    }
  }

  function openCreateUserModal() {
    setEditingUser(null);
    setUserFormData({
      email: "",
      password: "",
      display_name: "",
      is_active: true,
      roles: ["viewer"],
    });
    setUserFormError(null);
    setShowUserModal(true);
  }

  function openEditUserModal(userWithRoles: UserWithRoles) {
    setEditingUser(userWithRoles);
    setUserFormData({
      email: userWithRoles.email,
      password: "",
      display_name: userWithRoles.display_name || "",
      is_active: userWithRoles.is_active,
      roles: userWithRoles.roles || [],
    });
    setUserFormError(null);
    setShowUserModal(true);
  }

  async function handleSaveUser() {
    setUserFormLoading(true);
    setUserFormError(null);

    try {
      if (editingUser) {
        // Update existing user
        const updateData: UpdateUserRequest = {};
        if (userFormData.email !== editingUser.email) {
          updateData.email = userFormData.email;
        }
        if (userFormData.display_name !== (editingUser.display_name || "")) {
          updateData.display_name = userFormData.display_name || undefined;
        }
        if (userFormData.is_active !== editingUser.is_active) {
          updateData.is_active = userFormData.is_active;
        }
        if (userFormData.password) {
          updateData.password = userFormData.password;
        }
        
        await updateUser(editingUser.id, updateData);
        
        // Handle role changes
        const oldRoles = editingUser.roles || [];
        const newRoles = userFormData.roles;
        
        // Remove roles that are no longer selected
        for (const role of oldRoles) {
          if (!newRoles.includes(role)) {
            await updateUserRole(editingUser.id, role, "remove");
          }
        }
        
        // Add new roles
        for (const role of newRoles) {
          if (!oldRoles.includes(role)) {
            await updateUserRole(editingUser.id, role, "add");
          }
        }
      } else {
        // Create new user
        const createData: CreateUserRequest = {
          email: userFormData.email,
          password: userFormData.password || undefined,
          display_name: userFormData.display_name || undefined,
          roles: userFormData.roles.length > 0 ? userFormData.roles : undefined,
        };
        
        await createUser(createData);
      }
      
      setShowUserModal(false);
      loadData();
    } catch (err) {
      setUserFormError((err as Error).message);
    } finally {
      setUserFormLoading(false);
    }
  }

  async function handleDeleteUser(userToDelete: UserWithRoles) {
    setDeleteLoading(true);
    try {
      await deleteUser(userToDelete.id);
      setDeleteConfirmUser(null);
      loadData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDeleteLoading(false);
    }
  }

  function formatBytes(bytes: number) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function formatUptime(seconds: number) {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  }

  const tabs = [
    { id: "status" as TabType, label: "System Status", icon: "⚙️" },
    ...(isAdmin ? [
      { id: "config" as TabType, label: "Configuration", icon: "🛡️" },
      { id: "users" as TabType, label: "User Management", icon: "👥", badge: users.length },
    ] : []),
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Settings" 
        description="System status and administration"
      />

      {/* Tab Navigation */}
      <div className="tab-list">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`tab-item flex items-center gap-2 ${activeTab === tab.id ? "active" : ""}`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-primary/20 text-primary text-xs rounded-full font-medium">
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {error && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-4">
            <div className="text-destructive flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* System Status Tab */}
      {activeTab === "status" && (
        <>
          {loading && !metrics ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : metrics && health ? (
            <div className="space-y-6 stagger-children">
              {/* System Overview */}
              <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>System Status</CardDescription>
                    <CardTitle className="flex items-center gap-3">
                      <div className={`h-4 w-4 rounded-full ${health.status === "healthy" || health.status === "ok" ? "bg-success animate-pulse-glow" : "bg-destructive"}`} />
                      <span className="font-mono">{health.status.toUpperCase()}</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground">
                      Version: <span className="font-mono">{health.version}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>Uptime</CardDescription>
                    <CardTitle className="font-mono">{formatUptime(metrics.uptime_seconds)}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground">Since last restart</div>
                  </CardContent>
                </Card>

                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>Memory Usage</CardDescription>
                    <CardTitle className="font-mono">{formatBytes(metrics.memory_usage.used_bytes)}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground mb-2">
                      of {formatBytes(metrics.memory_usage.total_bytes)} total
                    </div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-primary transition-all duration-500" 
                        style={{ width: `${(metrics.memory_usage.used_bytes / metrics.memory_usage.total_bytes) * 100}%` }}
                      />
                    </div>
                  </CardContent>
                </Card>

                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>CPU Usage</CardDescription>
                    <CardTitle className="font-mono">{metrics.cpu_usage_percent.toFixed(1)}%</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground mb-2">Current load</div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-500 ${metrics.cpu_usage_percent > 80 ? "bg-destructive" : metrics.cpu_usage_percent > 50 ? "bg-warning" : "bg-success"}`}
                        style={{ width: `${Math.min(metrics.cpu_usage_percent, 100)}%` }}
                      />
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Application Stats */}
              <div className="grid gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Application Statistics</CardTitle>
                    <CardDescription>Core metrics for the EASM platform</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {[
                      { icon: "🎯", label: "Total Assets", value: metrics.total_assets, color: "text-foreground" },
                      { icon: "🔍", label: "Total Findings", value: metrics.total_findings, color: "text-info" },
                      { icon: "⚡", label: "Active Scans", value: metrics.active_scans, color: "text-warning" },
                      { icon: "🚀", label: "Requests/sec", value: metrics.requests_per_second.toFixed(2), color: "text-success" },
                    ].map((stat, idx) => (
                      <div key={idx} className="flex items-center justify-between p-4 border border-border rounded-lg hover:bg-muted/30 transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{stat.icon}</span>
                          <div className="font-medium">{stat.label}</div>
                        </div>
                        <span className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Feature Status</CardTitle>
                    <CardDescription>Operational status of system components</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {[
                        { name: "Scanner Engine", status: "operational" },
                        { name: "Drift Detection", status: "operational" },
                        { name: "Search Index", status: "operational" },
                        { name: "Risk Scoring", status: "operational" },
                        { name: "Discovery Engine", status: "operational" },
                      ].map((component) => (
                        <div key={component.name} className="flex items-center justify-between p-3 border border-border rounded-lg">
                          <div className="flex items-center gap-3">
                            <div className="h-2.5 w-2.5 rounded-full bg-success animate-pulse" />
                            <span>{component.name}</span>
                          </div>
                          <Badge variant="success" className="font-mono text-xs">
                            {component.status}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          ) : null}
        </>
      )}

      {/* Configuration Tab */}
      {activeTab === "config" && isAdmin && (
        <div className="space-y-6 stagger-children">
          {settingsLoading && !settingsData ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : null}

          {settingsData && (
            <>
              <Card>
                <CardHeader className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div>
                    <CardTitle>Configuration</CardTitle>
                    <CardDescription>
                      Application, authentication, and discovery controls. Secrets stay hidden unless you choose to reveal them.
                    </CardDescription>
                  </div>
                  <div className="flex gap-3 flex-wrap">
                    <Button variant="outline" onClick={handleRevealSecrets} disabled={settingsLoading}>
                      {secretsRevealed ? "Refresh Secrets" : "Reveal Secrets"}
                    </Button>
                    <Button variant="outline" onClick={resetSettingsForm} disabled={settingsLoading || settingsSaving}>
                      Reset Changes
                    </Button>
                    <Button onClick={handleSaveSettings} disabled={settingsSaving || settingsLoading}>
                      {settingsSaving ? "Saving..." : "Save Settings"}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="flex flex-wrap gap-4 text-sm text-muted-foreground">
                  <span>
                    Last updated: {new Date(settingsData.updated_at).toLocaleString()}
                  </span>
                  <span>Secrets revealed: {secretsRevealed ? "yes" : "no"}</span>
                  {settingsData.updated_by && (
                    <span className="font-mono text-xs bg-muted px-2 py-1 rounded">
                      Updated by {settingsData.updated_by.slice(0, 8)}...
                    </span>
                  )}
                </CardContent>
              </Card>

              <div className="grid gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Authentication & SSO</CardTitle>
                    <CardDescription>Google and Keycloak identity providers</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Google Client ID" keyName="google_client_id" />}
                        value={settingsForm.google_client_id}
                        onChange={(e) => updateFormField("google_client_id", e.target.value)}
                        placeholder="client-id.apps.googleusercontent.com"
                      />
                      {secretInput("google_client_secret", "Google Client Secret", settingsData.settings.google_client_secret.is_set ? "••••••••" : "Enter secret")}
                    </div>
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Google Discovery URL" keyName="google_discovery_url" />}
                        value={settingsForm.google_discovery_url}
                        onChange={(e) => updateFormField("google_discovery_url", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="Google Redirect URI" keyName="google_redirect_uri" />}
                        value={settingsForm.google_redirect_uri}
                        onChange={(e) => updateFormField("google_redirect_uri", e.target.value)}
                      />
                    </div>
                    <Input
                      label={<InfoLabel text="Google Allowed Domains" keyName="google_allowed_domains" />}
                      value={settingsForm.google_allowed_domains}
                      onChange={(e) => updateFormField("google_allowed_domains", e.target.value)}
                      placeholder="comma separated domains"
                    />
                    <div className="grid md:grid-cols-2 gap-4 pt-2">
                      <Input
                        label={<InfoLabel text="Keycloak Client ID" keyName="keycloak_client_id" />}
                        value={settingsForm.keycloak_client_id}
                        onChange={(e) => updateFormField("keycloak_client_id", e.target.value)}
                      />
                      {secretInput("keycloak_client_secret", "Keycloak Client Secret", settingsData.settings.keycloak_client_secret.is_set ? "••••••••" : "Enter secret")}
                    </div>
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Keycloak Discovery URL" keyName="keycloak_discovery_url" />}
                        value={settingsForm.keycloak_discovery_url}
                        onChange={(e) => updateFormField("keycloak_discovery_url", e.target.value)}
                        placeholder="https://idp.example.com/realms/<realm>"
                      />
                      <Input
                        label={<InfoLabel text="Keycloak Redirect URI" keyName="keycloak_redirect_uri" />}
                        value={settingsForm.keycloak_redirect_uri}
                        onChange={(e) => updateFormField("keycloak_redirect_uri", e.target.value)}
                      />
                    </div>
                    <Input
                      label={<InfoLabel text="Keycloak Realm" keyName="keycloak_realm" />}
                      value={settingsForm.keycloak_realm}
                      onChange={(e) => updateFormField("keycloak_realm", e.target.value)}
                    />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>External API Keys</CardTitle>
                    <CardDescription>Threat intel and enrichment providers</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {SECRET_FIELDS.map((field) => {
                      const secretField = settingsData.settings[field.key];
                      return (
                        <div key={field.key}>
                          {secretInput(
                            field.key,
                            field.label,
                            secretField.is_set ? "••••••••" : "Not set"
                          )}
                          <div className="text-xs text-muted-foreground mt-1">
                            {secretField.is_set ? "Stored" : "Not set"}
                          </div>
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              </div>

              <div className="grid gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Application Controls</CardTitle>
                    <CardDescription>CORS, logging, rate limits, and performance</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <Input
                      label={<InfoLabel text="CORS Allow Origins" keyName="cors_allow_origins" />}
                      value={settingsForm.cors_allow_origins}
                      onChange={(e) => updateFormField("cors_allow_origins", e.target.value)}
                      placeholder="http://localhost:3000, http://127.0.0.1:3000"
                    />
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Log Level" keyName="log_level" />}
                        value={settingsForm.log_level}
                        onChange={(e) => updateFormField("log_level", e.target.value.toUpperCase())}
                        placeholder="INFO"
                      />
                      <Input
                        label={<InfoLabel text="Log Format" keyName="log_format" />}
                        value={settingsForm.log_format}
                        onChange={(e) => updateFormField("log_format", e.target.value)}
                        placeholder="json or plain"
                      />
                    </div>
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Rate Limit Requests" keyName="rate_limit_requests" />}
                        type="number"
                        value={settingsForm.rate_limit_requests}
                        onChange={(e) => updateFormField("rate_limit_requests", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="Rate Limit Window (seconds)" keyName="rate_limit_window_seconds" />}
                        type="number"
                        value={settingsForm.rate_limit_window_seconds}
                        onChange={(e) => updateFormField("rate_limit_window_seconds", e.target.value)}
                      />
                    </div>
                    <Checkbox
                      checked={settingsForm.rate_limit_enabled}
                      onChange={(checked) => updateFormField("rate_limit_enabled", checked)}
                      label={<InfoLabel text="Enable rate limiting" keyName="rate_limit_enabled" />}
                    />
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="HTTP Timeout (s)" keyName="http_timeout_seconds" />}
                        type="number"
                        value={settingsForm.http_timeout_seconds}
                        onChange={(e) => updateFormField("http_timeout_seconds", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="TLS Timeout (s)" keyName="tls_timeout_seconds" />}
                        type="number"
                        value={settingsForm.tls_timeout_seconds}
                        onChange={(e) => updateFormField("tls_timeout_seconds", e.target.value)}
                      />
                    </div>
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="DNS Concurrency" keyName="dns_concurrency" />}
                        type="number"
                        value={settingsForm.dns_concurrency}
                        onChange={(e) => updateFormField("dns_concurrency", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="rDNS Concurrency" keyName="rdns_concurrency" />}
                        type="number"
                        value={settingsForm.rdns_concurrency}
                        onChange={(e) => updateFormField("rdns_concurrency", e.target.value)}
                      />
                    </div>
                    <Input
                      label={<InfoLabel text="Max Concurrent Scans" keyName="max_concurrent_scans" />}
                      type="number"
                      value={settingsForm.max_concurrent_scans}
                      onChange={(e) => updateFormField("max_concurrent_scans", e.target.value)}
                    />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Evidence, Discovery & Limits</CardTitle>
                    <CardDescription>Storage, recursion, and performance guardrails</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <Input
                      label={<InfoLabel text="Max Evidence Size (bytes)" keyName="max_evidence_bytes" />}
                      type="number"
                      value={settingsForm.max_evidence_bytes}
                      onChange={(e) => updateFormField("max_evidence_bytes", e.target.value)}
                    />
                    <Input
                      label={<InfoLabel text="Allowed Evidence Types" keyName="evidence_allowed_types" />}
                      value={settingsForm.evidence_allowed_types}
                      onChange={(e) => updateFormField("evidence_allowed_types", e.target.value)}
                      placeholder="image/png, image/jpeg, application/pdf"
                    />
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Max CIDR Hosts" keyName="max_cidr_hosts" />}
                        type="number"
                        value={settingsForm.max_cidr_hosts}
                        onChange={(e) => updateFormField("max_cidr_hosts", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="Max Discovery Depth" keyName="max_discovery_depth" />}
                        type="number"
                        value={settingsForm.max_discovery_depth}
                        onChange={(e) => updateFormField("max_discovery_depth", e.target.value)}
                      />
                    </div>
                    <Input
                      label={<InfoLabel text="Subdomain Enumeration Timeout (s)" keyName="subdomain_enum_timeout" />}
                      type="number"
                      value={settingsForm.subdomain_enum_timeout}
                      onChange={(e) => updateFormField("subdomain_enum_timeout", e.target.value)}
                    />
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Max Assets per Discovery" keyName="max_assets_per_discovery" />}
                        type="number"
                        value={settingsForm.max_assets_per_discovery}
                        onChange={(e) => updateFormField("max_assets_per_discovery", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="Min Pivot Confidence" keyName="min_pivot_confidence" />}
                        type="number"
                        step="0.01"
                        value={settingsForm.min_pivot_confidence}
                        onChange={(e) => updateFormField("min_pivot_confidence", e.target.value)}
                      />
                    </div>
                    <div className="grid md:grid-cols-2 gap-4">
                      <Input
                        label={<InfoLabel text="Max Orgs per Domain" keyName="max_orgs_per_domain" />}
                        type="number"
                        value={settingsForm.max_orgs_per_domain}
                        onChange={(e) => updateFormField("max_orgs_per_domain", e.target.value)}
                      />
                      <Input
                        label={<InfoLabel text="Max Domains per Org" keyName="max_domains_per_org" />}
                        type="number"
                        value={settingsForm.max_domains_per_org}
                        onChange={(e) => updateFormField("max_domains_per_org", e.target.value)}
                      />
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>OSINT Toggles</CardTitle>
                  <CardDescription>Enable or disable enrichment providers</CardDescription>
                </CardHeader>
                <CardContent className="grid md:grid-cols-3 gap-4">
                  <Checkbox
                    checked={settingsForm.enable_wayback}
                    onChange={(checked) => updateFormField("enable_wayback", checked)}
                    label={<InfoLabel text="Wayback Machine" keyName="enable_wayback" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_urlscan}
                    onChange={(checked) => updateFormField("enable_urlscan", checked)}
                    label={<InfoLabel text="URLScan" keyName="enable_urlscan" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_otx}
                    onChange={(checked) => updateFormField("enable_otx", checked)}
                    label={<InfoLabel text="OTX" keyName="enable_otx" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_dns_record_expansion}
                    onChange={(checked) => updateFormField("enable_dns_record_expansion", checked)}
                    label={<InfoLabel text="DNS Record Expansion" keyName="enable_dns_record_expansion" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_web_crawl}
                    onChange={(checked) => updateFormField("enable_web_crawl", checked)}
                    label={<InfoLabel text="Web Crawl" keyName="enable_web_crawl" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_cloud_storage_discovery}
                    onChange={(checked) => updateFormField("enable_cloud_storage_discovery", checked)}
                    label={<InfoLabel text="Cloud Storage Discovery" keyName="enable_cloud_storage_discovery" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_wikidata}
                    onChange={(checked) => updateFormField("enable_wikidata", checked)}
                    label={<InfoLabel text="Wikidata" keyName="enable_wikidata" />}
                  />
                  <Checkbox
                    checked={settingsForm.enable_opencorporates}
                    onChange={(checked) => updateFormField("enable_opencorporates", checked)}
                    label={<InfoLabel text="OpenCorporates" keyName="enable_opencorporates" />}
                  />
                </CardContent>
              </Card>
            </>
          )}
        </div>
      )}

      {/* User Management Tab */}
      {activeTab === "users" && isAdmin && (
        <div className="space-y-6 stagger-children">
          {/* User Stats */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Total Users</CardDescription>
                <CardTitle className="text-3xl font-mono">{users.filter(u => u.id).length}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Admins</CardDescription>
                <CardTitle className="text-3xl font-mono text-destructive">
                  {users.filter(u => u.roles?.includes("admin")).length}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Operators</CardDescription>
                <CardTitle className="text-3xl font-mono text-warning">
                  {users.filter(u => u.roles?.includes("operator")).length}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Active</CardDescription>
                <CardTitle className="text-3xl font-mono text-success">
                  {users.filter(u => u.is_active).length}
                </CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Role Legend */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Role Definitions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 md:grid-cols-2">
                {ALL_ROLES.map((role) => (
                  <div key={role} className="flex items-start gap-3 p-3 border border-border rounded-lg">
                    <Badge variant={ROLE_COLORS[role] || "secondary"} className="mt-0.5">
                      {role}
                    </Badge>
                    <div className="text-sm text-muted-foreground">
                      {ROLE_DESCRIPTIONS[role]}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Users Table */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Users</CardTitle>
                  <CardDescription>Manage user accounts and roles</CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" onClick={loadData}>Refresh</Button>
                  <Button onClick={openCreateUserModal}>Add User</Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="flex justify-center py-12">
                  <LoadingSpinner size="lg" />
                </div>
              ) : users.length === 0 ? (
                <EmptyState
                  icon="👤"
                  title="No users found"
                  description="Users will appear here after they sign in"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>User</TableHead>
                      <TableHead>Email</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Roles</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.filter(u => u.id).map((u) => (
                      <TableRow key={u.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-full bg-gradient-to-br from-primary/20 to-info/20 flex items-center justify-center text-primary font-medium">
                              {u.display_name?.[0] || u.email?.[0]?.toUpperCase() || "?"}
                            </div>
                            <div>
                              <div className="font-medium">{u.display_name || "—"}</div>
                              <div className="text-xs text-muted-foreground font-mono">
                                {u.id?.slice(0, 8)}...
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-sm">{u.email || "—"}</TableCell>
                        <TableCell>
                          <Badge variant={u.is_active ? "success" : "error"}>
                            {u.is_active ? "Active" : "Inactive"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {(u.roles || []).map((role) => (
                              <Badge 
                                key={role} 
                                variant={ROLE_COLORS[role] || "secondary"}
                                className="cursor-pointer hover:opacity-80 transition-opacity"
                                onClick={() => {
                                  if (updating !== u.id) {
                                    handleRemoveRole(u.id, role);
                                  }
                                }}
                                title="Click to remove"
                              >
                                {role} ×
                              </Badge>
                            ))}
                            {(!u.roles || u.roles.length === 0) && (
                              <span className="text-muted-foreground text-sm">No roles</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex gap-2 justify-end">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => openEditUserModal(u)}
                              disabled={updating === u.id}
                            >
                              Edit
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setSelectedUser(u)}
                              disabled={updating === u.id}
                            >
                              Roles
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-destructive hover:text-destructive"
                              onClick={() => setDeleteConfirmUser(u)}
                              disabled={updating === u.id || u.id === user?.user_id}
                              title={u.id === user?.user_id ? "Cannot delete yourself" : "Delete user"}
                            >
                              ×
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* User Role Management Modal */}
      <Modal
        isOpen={!!selectedUser}
        onClose={() => { setSelectedUser(null); setSelectedRole(""); }}
        title="Manage User Roles"
      >
        {selectedUser && (
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="h-14 w-14 rounded-full bg-gradient-to-br from-primary/20 to-info/20 flex items-center justify-center text-primary text-xl font-medium">
                {selectedUser.display_name?.[0] || selectedUser.email[0].toUpperCase()}
              </div>
              <div>
                <div className="font-medium text-lg">
                  {selectedUser.display_name || selectedUser.email}
                </div>
                <div className="text-sm text-muted-foreground">{selectedUser.email}</div>
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-3">Current Roles</h4>
              <div className="flex flex-wrap gap-2">
                {selectedUser.roles.length > 0 ? (
                  selectedUser.roles.map((role) => (
                    <div key={role} className="flex items-center gap-2 p-2 bg-muted rounded-lg">
                      <Badge variant={ROLE_COLORS[role] || "secondary"}>{role}</Badge>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                        onClick={() => handleRemoveRole(selectedUser.id, role)}
                        disabled={updating === selectedUser.id}
                      >
                        ×
                      </Button>
                    </div>
                  ))
                ) : (
                  <span className="text-muted-foreground">No roles assigned</span>
                )}
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-3">Add Role</h4>
              <div className="flex gap-3">
                <Select
                  value={selectedRole}
                  onChange={(e) => setSelectedRole(e.target.value)}
                  className="flex-1"
                >
                  <option value="">Select a role...</option>
                  {ALL_ROLES.filter(r => !selectedUser.roles.includes(r)).map((role) => (
                    <option key={role} value={role}>{role}</option>
                  ))}
                </Select>
                <Button
                  onClick={() => handleAddRole(selectedUser.id, selectedRole)}
                  disabled={!selectedRole || updating === selectedUser.id}
                >
                  Add Role
                </Button>
              </div>
            </div>

            <div className="pt-4 border-t">
              <Button
                variant="outline"
                onClick={() => { setSelectedUser(null); setSelectedRole(""); }}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Create/Edit User Modal */}
      <Modal
        isOpen={showUserModal}
        onClose={() => setShowUserModal(false)}
        title={editingUser ? "Edit User" : "Create User"}
      >
        <div className="space-y-4">
          {userFormError && (
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
              {userFormError}
            </div>
          )}
          
          <Input
            label="Email"
            type="email"
            value={userFormData.email}
            onChange={(e) => setUserFormData(prev => ({ ...prev, email: e.target.value }))}
            placeholder="user@example.com"
            required
          />
          
          <Input
            label="Display Name"
            type="text"
            value={userFormData.display_name}
            onChange={(e) => setUserFormData(prev => ({ ...prev, display_name: e.target.value }))}
            placeholder="John Doe"
          />
          
          <Input
            label={editingUser ? "New Password (leave empty to keep current)" : "Password"}
            type="password"
            value={userFormData.password}
            onChange={(e) => setUserFormData(prev => ({ ...prev, password: e.target.value }))}
            placeholder={editingUser ? "••••••••" : "Min. 8 characters"}
          />
          
          {editingUser && (
            <Checkbox
              checked={userFormData.is_active}
              onChange={(checked) => setUserFormData(prev => ({ ...prev, is_active: checked }))}
              label="Account is active"
            />
          )}
          
          <div>
            <label className="block text-sm font-medium mb-2">Roles</label>
            <div className="flex flex-wrap gap-2">
              {ALL_ROLES.map((role) => (
                <label key={role} className="flex items-center gap-2 p-2 bg-muted rounded-lg cursor-pointer hover:bg-muted/80">
                  <input
                    type="checkbox"
                    checked={userFormData.roles.includes(role)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setUserFormData(prev => ({ ...prev, roles: [...prev.roles, role] }));
                      } else {
                        setUserFormData(prev => ({ ...prev, roles: prev.roles.filter(r => r !== role) }));
                      }
                    }}
                    className="rounded border-border"
                  />
                  <Badge variant={ROLE_COLORS[role] || "secondary"}>{role}</Badge>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t">
            <Button
              variant="outline"
              onClick={() => setShowUserModal(false)}
              disabled={userFormLoading}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSaveUser}
              loading={userFormLoading}
              disabled={!userFormData.email || (!editingUser && !userFormData.password)}
            >
              {editingUser ? "Save Changes" : "Create User"}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteConfirmUser}
        onClose={() => setDeleteConfirmUser(null)}
        title="Delete User"
      >
        {deleteConfirmUser && (
          <div className="space-y-4">
            <p className="text-muted-foreground">
              Are you sure you want to delete the user <strong>{deleteConfirmUser.display_name || deleteConfirmUser.email}</strong>?
              This action cannot be undone.
            </p>
            
            <div className="flex justify-end gap-3 pt-4 border-t">
              <Button
                variant="outline"
                onClick={() => setDeleteConfirmUser(null)}
                disabled={deleteLoading}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={() => handleDeleteUser(deleteConfirmUser)}
                loading={deleteLoading}
              >
                Delete User
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
