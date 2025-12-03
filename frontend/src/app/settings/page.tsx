"use client";

import { useCallback, useEffect, useState, useRef } from "react";
import { useSearchParams } from "next/navigation";
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
  listTags,
  createTag,
  updateTag,
  deleteTag,
  runAutoTagForTag,
  runAutoTagAll,
  listFindingTypeConfigs,
  updateFindingTypeConfig,
  bulkUpdateFindingTypeConfigs,
  recalculateAllRisks,
  type SystemMetrics, 
  type UserWithRoles,
  type SettingsResponse,
  type SettingsView,
  type CreateUserRequest,
  type UpdateUserRequest,
  type TagWithCount,
  type TagCreate,
  type TagUpdate,
  type AutoTagResult,
  type FindingTypeConfig,
  type FindingTypeConfigUpdate,
  type RiskRecalculationResult,
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

type TabType = "status" | "users" | "config" | "tags" | "risk_scoring";

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

const DEFAULT_TAG_COLORS = [
  "#6366f1", // indigo
  "#8b5cf6", // violet
  "#ec4899", // pink
  "#ef4444", // red
  "#f97316", // orange
  "#eab308", // yellow
  "#22c55e", // green
  "#14b8a6", // teal
  "#06b6d4", // cyan
  "#3b82f6", // blue
];

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
  const searchParams = useSearchParams();
  const tabFromUrl = searchParams.get("tab") as TabType | null;
  const [activeTab, setActiveTab] = useState<TabType>(
    tabFromUrl && ["status", "users", "config", "tags", "risk_scoring"].includes(tabFromUrl) ? tabFromUrl : "status"
  );
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<{ status: string; version: string } | null>(null);
  const [users, setUsers] = useState<UserWithRoles[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState<string | null>(null);
  const [settingsData, setSettingsData] = useState<SettingsResponse | null>(null);
  const [settingsForm, setSettingsForm] = useState<SettingsFormState>(createEmptySettingsForm());
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [secretsRevealed, setSecretsRevealed] = useState(false);
  const [secretTouched, setSecretTouched] = useState<Record<string, boolean>>({});
  const [secretVisibility, setSecretVisibility] = useState<Record<string, boolean>>({});
  
  // Track if initial load has happened (ref to avoid re-renders)
  const hasInitialLoadRef = useRef(false);
  
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

  // Tags state
  const [tags, setTags] = useState<TagWithCount[]>([]);
  const [tagsLoading, setTagsLoading] = useState(true);
  const [tagsTotalCount, setTagsTotalCount] = useState(0);
  const [showCreateTagModal, setShowCreateTagModal] = useState(false);
  const [editingTag, setEditingTag] = useState<TagWithCount | null>(null);
  const [deletingTag, setDeletingTag] = useState<TagWithCount | null>(null);
  const [tagFormData, setTagFormData] = useState<TagCreate>({
    name: "",
    description: "",
    importance: 3,
    rule_type: undefined,
    rule_value: "",
    color: DEFAULT_TAG_COLORS[0],
  });
  const [tagFormError, setTagFormError] = useState<string | null>(null);
  const [tagSubmitting, setTagSubmitting] = useState(false);
  const [runningAutoTag, setRunningAutoTag] = useState<string | null>(null);
  const [autoTagResult, setAutoTagResult] = useState<AutoTagResult | null>(null);

  // Finding Type Config state
  const [findingTypeConfigs, setFindingTypeConfigs] = useState<FindingTypeConfig[]>([]);
  const [findingTypeCategories, setFindingTypeCategories] = useState<string[]>([]);
  const [findingTypeConfigsLoading, setFindingTypeConfigsLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [editingFindingType, setEditingFindingType] = useState<FindingTypeConfig | null>(null);
  const [findingTypeFormData, setFindingTypeFormData] = useState<FindingTypeConfigUpdate>({});
  const [findingTypeFormError, setFindingTypeFormError] = useState<string | null>(null);
  const [findingTypeSubmitting, setFindingTypeSubmitting] = useState(false);
  const [recalculatingRisks, setRecalculatingRisks] = useState(false);
  const [riskRecalculationResult, setRiskRecalculationResult] = useState<RiskRecalculationResult | null>(null);
  const [pendingChanges, setPendingChanges] = useState<Map<string, FindingTypeConfigUpdate>>(new Map());

  const isAdmin = user?.roles?.includes("admin");

  const loadData = useCallback(async (isRefresh = false) => {
    try {
      // Only show full loading spinner on initial load, not refreshes
      if (!isRefresh) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }
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
      hasInitialLoadRef.current = true;
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
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

  const loadTags = useCallback(async () => {
    try {
      setTagsLoading(true);
      const response = await listTags(100, 0);
      setTags(response.tags);
      setTagsTotalCount(response.total_count);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setTagsLoading(false);
    }
  }, []);

  const loadFindingTypeConfigs = useCallback(async () => {
    try {
      setFindingTypeConfigsLoading(true);
      const response = await listFindingTypeConfigs();
      setFindingTypeConfigs(response.configs);
      setFindingTypeCategories(response.categories);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setFindingTypeConfigsLoading(false);
    }
  }, []);

  const resetTagForm = () => {
    setTagFormData({
      name: "",
      description: "",
      importance: 3,
      rule_type: undefined,
      rule_value: "",
      color: DEFAULT_TAG_COLORS[Math.floor(Math.random() * DEFAULT_TAG_COLORS.length)],
    });
    setTagFormError(null);
  };

  const openEditTagModal = (tag: TagWithCount) => {
    setTagFormData({
      name: tag.name,
      description: tag.description || "",
      importance: tag.importance,
      rule_type: tag.rule_type || undefined,
      rule_value: tag.rule_value || "",
      color: tag.color || DEFAULT_TAG_COLORS[0],
    });
    setEditingTag(tag);
  };

  const handleCreateTag = async () => {
    if (!tagFormData.name.trim()) {
      setTagFormError("Tag name is required");
      return;
    }

    setTagSubmitting(true);
    setTagFormError(null);

    try {
      const payload: TagCreate = {
        name: tagFormData.name.trim(),
        description: tagFormData.description?.trim() || undefined,
        importance: tagFormData.importance,
        color: tagFormData.color,
      };

      if (tagFormData.rule_type && tagFormData.rule_value?.trim()) {
        payload.rule_type = tagFormData.rule_type;
        payload.rule_value = tagFormData.rule_value.trim();
      }

      await createTag(payload);
      setShowCreateTagModal(false);
      resetTagForm();
      loadTags();
    } catch (e) {
      setTagFormError((e as Error).message);
    } finally {
      setTagSubmitting(false);
    }
  };

  const handleUpdateTag = async () => {
    if (!editingTag) return;
    if (!tagFormData.name.trim()) {
      setTagFormError("Tag name is required");
      return;
    }

    setTagSubmitting(true);
    setTagFormError(null);

    try {
      const payload: TagUpdate = {
        name: tagFormData.name.trim(),
        description: tagFormData.description?.trim() || undefined,
        importance: tagFormData.importance,
        color: tagFormData.color,
      };

      if (!tagFormData.rule_type || !tagFormData.rule_value?.trim()) {
        payload.clear_rule = true;
      } else {
        payload.rule_type = tagFormData.rule_type;
        payload.rule_value = tagFormData.rule_value.trim();
      }

      await updateTag(editingTag.id, payload);
      setEditingTag(null);
      resetTagForm();
      loadTags();
    } catch (e) {
      setTagFormError((e as Error).message);
    } finally {
      setTagSubmitting(false);
    }
  };

  const handleDeleteTag = async () => {
    if (!deletingTag) return;

    setTagSubmitting(true);
    try {
      await deleteTag(deletingTag.id);
      setDeletingTag(null);
      loadTags();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setTagSubmitting(false);
    }
  };

  const handleRunAutoTag = async (tagId: string) => {
    setRunningAutoTag(tagId);
    setAutoTagResult(null);

    try {
      const result = await runAutoTagForTag(tagId);
      setAutoTagResult(result);
      loadTags();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunningAutoTag(null);
    }
  };

  const handleRunAutoTagAll = async () => {
    setRunningAutoTag("all");
    setAutoTagResult(null);

    try {
      const result = await runAutoTagAll();
      setAutoTagResult(result);
      loadTags();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunningAutoTag(null);
    }
  };

  const openEditFindingTypeModal = (config: FindingTypeConfig) => {
    setFindingTypeFormData({
      display_name: config.display_name,
      default_severity: config.default_severity,
      severity_score: config.severity_score,
      type_multiplier: config.type_multiplier,
      description: config.description || undefined,
      is_enabled: config.is_enabled,
    });
    setEditingFindingType(config);
    setFindingTypeFormError(null);
  };

  const handleUpdateFindingTypeConfig = async () => {
    if (!editingFindingType) return;

    setFindingTypeSubmitting(true);
    setFindingTypeFormError(null);

    try {
      await updateFindingTypeConfig(editingFindingType.finding_type, findingTypeFormData);
      setEditingFindingType(null);
      setFindingTypeFormData({});
      loadFindingTypeConfigs();
    } catch (e) {
      setFindingTypeFormError((e as Error).message);
    } finally {
      setFindingTypeSubmitting(false);
    }
  };

  const handleInlineUpdate = (config: FindingTypeConfig, field: keyof FindingTypeConfigUpdate, value: unknown) => {
    const newPending = new Map(pendingChanges);
    const existing = newPending.get(config.finding_type) || {};
    newPending.set(config.finding_type, { ...existing, [field]: value });
    setPendingChanges(newPending);
  };

  const handleSavePendingChanges = async () => {
    if (pendingChanges.size === 0) return;

    setFindingTypeSubmitting(true);
    setFindingTypeFormError(null);

    try {
      const updates = Array.from(pendingChanges.entries()).map(([finding_type, update]) => ({
        finding_type,
        ...update,
      }));

      const result = await bulkUpdateFindingTypeConfigs(updates);
      
      if (result.error_count > 0) {
        setFindingTypeFormError(`${result.error_count} errors: ${result.errors.slice(0, 3).join(", ")}`);
      }
      
      setPendingChanges(new Map());
      loadFindingTypeConfigs();
    } catch (e) {
      setFindingTypeFormError((e as Error).message);
    } finally {
      setFindingTypeSubmitting(false);
    }
  };

  const handleRecalculateAllRisks = async () => {
    setRecalculatingRisks(true);
    setRiskRecalculationResult(null);

    try {
      const result = await recalculateAllRisks();
      setRiskRecalculationResult(result);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRecalculatingRisks(false);
    }
  };

  useEffect(() => {
    loadData(false); // Initial load with full spinner
    if (isAdmin) {
      loadSettings(false);
      loadTags();
      loadFindingTypeConfigs();
    }
    const iv = setInterval(() => loadData(true), 10000); // Silent refreshes
    return () => clearInterval(iv);
  }, [isAdmin, loadData, loadSettings, loadTags, loadFindingTypeConfigs]);

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
      { id: "tags" as TabType, label: "Tags", icon: "🏷️", badge: tagsTotalCount },
      { id: "risk_scoring" as TabType, label: "Risk Scoring", icon: "📊", badge: findingTypeConfigs.length },
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
                  <Button variant="outline" onClick={() => loadData(true)} disabled={refreshing}>
                    {refreshing ? "Refreshing..." : "Refresh"}
                  </Button>
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

      {/* Tags Tab */}
      {activeTab === "tags" && isAdmin && (
        <div className="space-y-6 stagger-children">
          {/* Auto-tag Result Banner */}
          {autoTagResult && (
            <Card className={autoTagResult.errors.length > 0 ? "border-warning bg-warning/5" : "border-success bg-success/5"}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{autoTagResult.errors.length > 0 ? "⚠️" : "✅"}</span>
                    <div>
                      <div className="font-medium">
                        Auto-tagging {autoTagResult.errors.length > 0 ? "completed with warnings" : "completed"}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        Tagged {autoTagResult.assets_tagged} assets with {autoTagResult.tags_applied} tag applications
                      </div>
                    </div>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => setAutoTagResult(null)}>
                    Dismiss
                  </Button>
                </div>
                {autoTagResult.errors.length > 0 && (
                  <div className="mt-3 p-2 bg-warning/10 rounded text-sm">
                    <div className="font-medium text-warning mb-1">Errors:</div>
                    <ul className="list-disc list-inside text-muted-foreground">
                      {autoTagResult.errors.slice(0, 5).map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                      {autoTagResult.errors.length > 5 && (
                        <li>...and {autoTagResult.errors.length - 5} more</li>
                      )}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Stats Cards */}
          <div className="grid gap-6 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Total Tags</CardDescription>
                <CardTitle className="text-3xl">{tagsTotalCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Defined tag categories
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>With Auto-Tag Rules</CardDescription>
                <CardTitle className="text-3xl text-primary">
                  {tags.filter(t => t.rule_type).length}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Tags with regex or IP range rules
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Tagged Assets</CardDescription>
                <CardTitle className="text-3xl text-info">
                  {tags.reduce((sum, t) => sum + t.asset_count, 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Total tag applications
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Actions Bar */}
          <Card>
            <CardContent className="!pt-6 pb-6">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-3">
                  <Button onClick={() => { resetTagForm(); setShowCreateTagModal(true); }}>
                    + Create Tag
                  </Button>
                  <Button
                    variant="outline"
                    onClick={handleRunAutoTagAll}
                    disabled={!!runningAutoTag}
                    loading={runningAutoTag === "all"}
                  >
                    {runningAutoTag === "all" ? "Running..." : "Run All Auto-Tag Rules"}
                  </Button>
                </div>
                <Button variant="outline" onClick={loadTags} disabled={tagsLoading}>
                  {tagsLoading ? "Refreshing..." : "Refresh"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Tags Table */}
          <Card>
            <CardHeader>
              <CardTitle>Tags ({tags.length})</CardTitle>
              <CardDescription>
                Configure tags and auto-tagging rules for your assets
              </CardDescription>
            </CardHeader>
            <CardContent>
              {tagsLoading ? (
                <div className="py-12">
                  <LoadingSpinner size="lg" />
                </div>
              ) : tags.length === 0 ? (
                <EmptyState
                  icon="🏷️"
                  title="No tags defined"
                  description="Create your first tag to start categorizing assets"
                  action={
                    <Button onClick={() => { resetTagForm(); setShowCreateTagModal(true); }}>
                      Create First Tag
                    </Button>
                  }
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tag</TableHead>
                      <TableHead>Importance</TableHead>
                      <TableHead>Auto-Tag Rule</TableHead>
                      <TableHead>Assets</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tags.map((tag) => (
                      <TableRow key={tag.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div
                              className="w-4 h-4 rounded-full"
                              style={{ 
                                backgroundColor: tag.color || "#6366f1", 
                                boxShadow: `0 0 0 2px var(--background), 0 0 0 4px ${tag.color || "#6366f1"}`
                              }}
                            />
                            <div>
                              <div className="font-medium">{tag.name}</div>
                              {tag.description && (
                                <div className="text-sm text-muted-foreground truncate max-w-xs">
                                  {tag.description}
                                </div>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <ImportanceShields count={tag.importance} />
                            <span className="text-xs text-muted-foreground">
                              ({tag.importance}/5)
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          {tag.rule_type ? (
                            <div className="space-y-1">
                              <Badge variant={tag.rule_type === "regex" ? "info" : "secondary"}>
                                {tag.rule_type === "regex" ? "Regex" : "IP Range"}
                              </Badge>
                              <code className="block text-xs bg-muted px-2 py-1 rounded font-mono truncate max-w-xs">
                                {tag.rule_value}
                              </code>
                            </div>
                          ) : (
                            <span className="text-muted-foreground text-sm">Manual only</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="font-mono">
                            {tag.asset_count}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-2">
                            {tag.rule_type && (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleRunAutoTag(tag.id)}
                                disabled={!!runningAutoTag}
                                loading={runningAutoTag === tag.id}
                              >
                                {runningAutoTag === tag.id ? "Running..." : "Auto-Tag"}
                              </Button>
                            )}
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openEditTagModal(tag)}
                            >
                              Edit
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setDeletingTag(tag)}
                              className="text-destructive hover:bg-destructive/10"
                            >
                              Delete
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

      {/* Risk Scoring Tab */}
      {activeTab === "risk_scoring" && isAdmin && (
        <div className="space-y-6 stagger-children">
          {/* Risk Recalculation Result Banner */}
          {riskRecalculationResult && (
            <Card className={riskRecalculationResult.error_count > 0 ? "border-warning bg-warning/5" : "border-success bg-success/5"}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{riskRecalculationResult.error_count > 0 ? "⚠️" : "✅"}</span>
                    <div>
                      <div className="font-medium">
                        Risk recalculation {riskRecalculationResult.error_count > 0 ? "completed with warnings" : "completed"}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        Successfully updated {riskRecalculationResult.success_count} assets
                        {riskRecalculationResult.error_count > 0 && `, ${riskRecalculationResult.error_count} errors`}
                      </div>
                    </div>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => setRiskRecalculationResult(null)}>
                    Dismiss
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Pending Changes Banner */}
          {pendingChanges.size > 0 && (
            <Card className="border-primary bg-primary/5">
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">📝</span>
                    <div>
                      <div className="font-medium">
                        {pendingChanges.size} unsaved change{pendingChanges.size > 1 ? "s" : ""}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        Click &quot;Save All Changes&quot; to apply your modifications
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPendingChanges(new Map())}>
                      Discard
                    </Button>
                    <Button 
                      size="sm" 
                      onClick={handleSavePendingChanges}
                      loading={findingTypeSubmitting}
                    >
                      Save All Changes
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {findingTypeFormError && (
            <Card className="border-destructive/50 bg-destructive/5">
              <CardContent className="py-4">
                <div className="text-destructive flex items-center gap-2">
                  <span>⚠️</span>
                  <span>{findingTypeFormError}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Stats Cards */}
          <div className="grid gap-6 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Total Finding Types</CardDescription>
                <CardTitle className="text-3xl">{findingTypeConfigs.length}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Configurable risk scoring types
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Categories</CardDescription>
                <CardTitle className="text-3xl text-primary">
                  {findingTypeCategories.length}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Organized by finding category
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Enabled</CardDescription>
                <CardTitle className="text-3xl text-success">
                  {findingTypeConfigs.filter(c => c.is_enabled).length}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Active in risk calculations
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Disabled</CardDescription>
                <CardTitle className="text-3xl text-muted-foreground">
                  {findingTypeConfigs.filter(c => !c.is_enabled).length}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Excluded from calculations
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Actions Bar */}
          <Card>
            <CardContent className="!pt-6 pb-6">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-3">
                  <Select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="w-48"
                  >
                    <option value="all">All Categories</option>
                    {findingTypeCategories.map((cat) => (
                      <option key={cat} value={cat}>{cat.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}</option>
                    ))}
                  </Select>
                  <Button
                    variant="outline"
                    onClick={handleRecalculateAllRisks}
                    disabled={recalculatingRisks || pendingChanges.size > 0}
                    loading={recalculatingRisks}
                  >
                    {recalculatingRisks ? "Recalculating..." : "Recalculate All Risks"}
                  </Button>
                </div>
                <Button variant="outline" onClick={loadFindingTypeConfigs} disabled={findingTypeConfigsLoading}>
                  {findingTypeConfigsLoading ? "Refreshing..." : "Refresh"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Finding Type Configs Table */}
          <Card>
            <CardHeader>
              <CardTitle>Finding Type Configuration</CardTitle>
              <CardDescription>
                Customize severity scores and type multipliers used in risk calculations. Changes affect future risk score calculations.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {findingTypeConfigsLoading ? (
                <div className="py-12">
                  <LoadingSpinner size="lg" />
                </div>
              ) : findingTypeConfigs.length === 0 ? (
                <EmptyState
                  icon="📊"
                  title="No finding types configured"
                  description="Run the migration to populate default finding type configurations"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Finding Type</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead className="text-center">Score</TableHead>
                      <TableHead className="text-center">Multiplier</TableHead>
                      <TableHead className="text-center">Enabled</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findingTypeConfigs
                      .filter(config => selectedCategory === "all" || config.category === selectedCategory)
                      .map((config) => {
                        const pending = pendingChanges.get(config.finding_type);
                        const currentScore = pending?.severity_score ?? config.severity_score;
                        const currentMultiplier = pending?.type_multiplier ?? config.type_multiplier;
                        const currentEnabled = pending?.is_enabled ?? config.is_enabled;
                        const hasPending = !!pending;

                        return (
                          <TableRow key={config.id} className={hasPending ? "bg-primary/5" : ""}>
                            <TableCell>
                              <div>
                                <div className="font-medium">{config.display_name}</div>
                                <code className="text-xs text-muted-foreground bg-muted px-1 py-0.5 rounded">
                                  {config.finding_type}
                                </code>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge variant="secondary">
                                {config.category.replace(/_/g, " ")}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge 
                                variant={
                                  config.default_severity === "critical" ? "error" :
                                  config.default_severity === "high" ? "warning" :
                                  config.default_severity === "medium" ? "info" :
                                  config.default_severity === "low" ? "secondary" :
                                  "secondary"
                                }
                              >
                                {config.default_severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-center">
                              <input
                                type="number"
                                min="0"
                                max="100"
                                step="0.5"
                                value={currentScore}
                                onChange={(e) => handleInlineUpdate(config, "severity_score", parseFloat(e.target.value) || 0)}
                                className="w-20 text-center px-2 py-1 text-sm border border-input rounded bg-background"
                              />
                            </TableCell>
                            <TableCell className="text-center">
                              <input
                                type="number"
                                min="0.1"
                                max="10"
                                step="0.1"
                                value={currentMultiplier}
                                onChange={(e) => handleInlineUpdate(config, "type_multiplier", parseFloat(e.target.value) || 1)}
                                className="w-20 text-center px-2 py-1 text-sm border border-input rounded bg-background"
                              />
                            </TableCell>
                            <TableCell className="text-center">
                              <Checkbox
                                checked={currentEnabled}
                                onChange={(checked) => handleInlineUpdate(config, "is_enabled", checked)}
                              />
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => openEditFindingTypeModal(config)}
                              >
                                Edit
                              </Button>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* Severity Score Reference */}
          <Card>
            <CardHeader>
              <CardTitle>Severity Score Reference</CardTitle>
              <CardDescription>Default severity scores used when calculating risk</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 md:grid-cols-5">
                {[
                  { severity: "critical", score: 40.0, color: "bg-destructive" },
                  { severity: "high", score: 20.0, color: "bg-warning" },
                  { severity: "medium", score: 10.0, color: "bg-info" },
                  { severity: "low", score: 3.0, color: "bg-secondary" },
                  { severity: "info", score: 0.5, color: "bg-muted" },
                ].map((item) => (
                  <div key={item.severity} className="flex items-center gap-3 p-3 border border-border rounded-lg">
                    <div className={`w-3 h-3 rounded-full ${item.color}`} />
                    <div>
                      <div className="font-medium capitalize">{item.severity}</div>
                      <div className="text-sm text-muted-foreground">Default: {item.score}</div>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4 p-4 bg-muted/50 rounded-lg text-sm text-muted-foreground">
                <strong>Formula:</strong> <code>risk_score = (exposure_score + Σ((severity_score + cvss_bonus) × type_multiplier)) × importance_multiplier</code>
                <br />
                <span className="mt-2 block">The final score is capped at 100 and mapped to risk levels: Critical (≥80), High (≥60), Medium (≥40), Low (≥20), Info (&lt;20)</span>
              </div>
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

      {/* Create Tag Modal */}
      <Modal
        isOpen={showCreateTagModal}
        onClose={() => { setShowCreateTagModal(false); resetTagForm(); }}
        title="Create New Tag"
        size="lg"
      >
        <TagForm
          formData={tagFormData}
          setFormData={setTagFormData}
          formError={tagFormError}
          submitting={tagSubmitting}
          onSubmit={handleCreateTag}
          onCancel={() => { setShowCreateTagModal(false); resetTagForm(); }}
          submitLabel="Create Tag"
        />
      </Modal>

      {/* Edit Tag Modal */}
      <Modal
        isOpen={!!editingTag}
        onClose={() => { setEditingTag(null); resetTagForm(); }}
        title="Edit Tag"
        size="lg"
      >
        <TagForm
          formData={tagFormData}
          setFormData={setTagFormData}
          formError={tagFormError}
          submitting={tagSubmitting}
          onSubmit={handleUpdateTag}
          onCancel={() => { setEditingTag(null); resetTagForm(); }}
          submitLabel="Save Changes"
        />
      </Modal>

      {/* Delete Tag Confirmation Modal */}
      <Modal
        isOpen={!!deletingTag}
        onClose={() => setDeletingTag(null)}
        title="Delete Tag"
      >
        <div className="space-y-4">
          <p className="text-muted-foreground">
            Are you sure you want to delete the tag <strong>&quot;{deletingTag?.name}&quot;</strong>?
          </p>
          {deletingTag && deletingTag.asset_count > 0 && (
            <div className="p-3 bg-warning/10 rounded-lg text-warning text-sm">
              ⚠️ This tag is applied to {deletingTag.asset_count} asset(s). They will be untagged.
            </div>
          )}
          <div className="flex justify-end gap-3">
            <Button variant="outline" onClick={() => setDeletingTag(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleDeleteTag}
              disabled={tagSubmitting}
              loading={tagSubmitting}
              className="bg-destructive hover:bg-destructive/90"
            >
              Delete Tag
            </Button>
          </div>
        </div>
      </Modal>

      {/* Edit Finding Type Config Modal */}
      <Modal
        isOpen={!!editingFindingType}
        onClose={() => { setEditingFindingType(null); setFindingTypeFormData({}); setFindingTypeFormError(null); }}
        title="Edit Finding Type Configuration"
        size="lg"
      >
        {editingFindingType && (
          <div className="space-y-6">
            {findingTypeFormError && (
              <div className="p-3 bg-destructive/10 rounded-lg text-destructive text-sm">
                {findingTypeFormError}
              </div>
            )}

            <div className="p-4 bg-muted/50 rounded-lg">
              <div className="flex items-center gap-3">
                <code className="px-2 py-1 bg-muted rounded text-sm font-mono">
                  {editingFindingType.finding_type}
                </code>
                <Badge variant="secondary">{editingFindingType.category}</Badge>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <Input
                label="Display Name"
                value={findingTypeFormData.display_name || ""}
                onChange={(e) => setFindingTypeFormData(prev => ({ ...prev, display_name: e.target.value }))}
                placeholder="Human-readable name"
              />
              <Select
                label="Default Severity"
                value={findingTypeFormData.default_severity || ""}
                onChange={(e) => setFindingTypeFormData(prev => ({ ...prev, default_severity: e.target.value }))}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </Select>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium text-foreground mb-1.5">
                  Severity Score: {findingTypeFormData.severity_score?.toFixed(1) || editingFindingType.severity_score.toFixed(1)}
                </label>
                <input
                  type="range"
                  min={0}
                  max={100}
                  step={0.5}
                  value={findingTypeFormData.severity_score ?? editingFindingType.severity_score}
                  onChange={(e) => setFindingTypeFormData(prev => ({ ...prev, severity_score: parseFloat(e.target.value) }))}
                  className="w-full h-2 accent-primary"
                />
                <div className="flex justify-between text-xs text-muted-foreground mt-1">
                  <span>0 (No impact)</span>
                  <span>100 (Maximum)</span>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-foreground mb-1.5">
                  Type Multiplier: {findingTypeFormData.type_multiplier?.toFixed(1) || editingFindingType.type_multiplier.toFixed(1)}×
                </label>
                <input
                  type="range"
                  min={0.1}
                  max={5}
                  step={0.1}
                  value={findingTypeFormData.type_multiplier ?? editingFindingType.type_multiplier}
                  onChange={(e) => setFindingTypeFormData(prev => ({ ...prev, type_multiplier: parseFloat(e.target.value) }))}
                  className="w-full h-2 accent-primary"
                />
                <div className="flex justify-between text-xs text-muted-foreground mt-1">
                  <span>0.1× (Reduced)</span>
                  <span>5.0× (Amplified)</span>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">Description</label>
              <textarea
                className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring min-h-[80px]"
                placeholder="Describe what this finding type means..."
                value={findingTypeFormData.description || ""}
                onChange={(e) => setFindingTypeFormData(prev => ({ ...prev, description: e.target.value }))}
              />
            </div>

            <Checkbox
              checked={findingTypeFormData.is_enabled ?? editingFindingType.is_enabled}
              onChange={(checked) => setFindingTypeFormData(prev => ({ ...prev, is_enabled: checked }))}
              label="Include in risk calculations"
            />

            <div className="flex justify-end gap-3 pt-4 border-t border-border">
              <Button variant="outline" onClick={() => { setEditingFindingType(null); setFindingTypeFormData({}); }}>
                Cancel
              </Button>
              <Button onClick={handleUpdateFindingTypeConfig} disabled={findingTypeSubmitting} loading={findingTypeSubmitting}>
                Save Changes
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

// Helper component for importance visualization
function ImportanceShields({ count, max = 5 }: { count: number; max?: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {Array.from({ length: max }).map((_, i) => (
        <svg
          key={i}
          className={`w-4 h-4 ${i < count ? "text-primary" : "text-muted-foreground/30"}`}
          viewBox="0 0 24 24"
          fill="currentColor"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ))}
    </div>
  );
}

// Tag Form Component
function TagForm({
  formData,
  setFormData,
  formError,
  submitting,
  onSubmit,
  onCancel,
  submitLabel,
}: {
  formData: TagCreate;
  setFormData: (data: TagCreate) => void;
  formError: string | null;
  submitting: boolean;
  onSubmit: () => void;
  onCancel: () => void;
  submitLabel: string;
}) {
  return (
    <div className="space-y-6">
      {formError && (
        <div className="p-3 bg-destructive/10 rounded-lg text-destructive text-sm">
          {formError}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Input
          label="Tag Name *"
          placeholder="e.g., Production, High-Priority, External"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
        <div>
          <label className="block text-sm font-medium text-foreground mb-1.5">Color</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={formData.color}
              onChange={(e) => setFormData({ ...formData, color: e.target.value })}
              className="h-10 w-16 rounded border border-input cursor-pointer"
            />
            <div className="flex gap-1 flex-wrap">
              {DEFAULT_TAG_COLORS.map((color) => (
                <button
                  key={color}
                  type="button"
                  className={`w-6 h-6 rounded-full border-2 transition-transform hover:scale-110 ${
                    formData.color === color ? "border-foreground scale-110" : "border-transparent"
                  }`}
                  style={{ backgroundColor: color }}
                  onClick={() => setFormData({ ...formData, color })}
                />
              ))}
            </div>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-foreground mb-1.5">Description</label>
        <textarea
          className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring min-h-[80px]"
          placeholder="Optional description for this tag..."
          value={formData.description || ""}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-foreground mb-1.5">
          Default Importance: {formData.importance}/5
        </label>
        <div className="flex items-center gap-4">
          <input
            type="range"
            min={1}
            max={5}
            value={formData.importance}
            onChange={(e) => setFormData({ ...formData, importance: Number(e.target.value) })}
            className="flex-1 h-2 accent-primary"
          />
          <div className="flex items-center gap-0.5">
            {Array.from({ length: 5 }).map((_, i) => (
              <svg
                key={i}
                className={`w-5 h-5 ${i < (formData.importance || 0) ? "text-primary" : "text-muted-foreground/30"}`}
                viewBox="0 0 24 24"
                fill="currentColor"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            ))}
          </div>
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          This importance value will be applied to assets when tagged
        </p>
      </div>

      <div className="border-t border-border pt-4">
        <h4 className="font-medium mb-3">Auto-Tagging Rule (Optional)</h4>
        <div className="grid gap-4 md:grid-cols-2">
          <Select
            label="Rule Type"
            value={formData.rule_type || ""}
            onChange={(e) => setFormData({ 
              ...formData, 
              rule_type: e.target.value as "regex" | "ip_range" | undefined || undefined 
            })}
          >
            <option value="">No auto-tagging (manual only)</option>
            <option value="regex">Regex (for domains, ASNs, certificates, orgs)</option>
            <option value="ip_range">IP Range (CIDR notation for IPs)</option>
          </Select>
          <Input
            label={formData.rule_type === "ip_range" ? "CIDR Range(s)" : "Regex Pattern"}
            placeholder={
              formData.rule_type === "ip_range"
                ? "e.g., 10.0.0.0/8, 192.168.1.0/24"
                : "e.g., .*\\.prod\\.example\\.com$"
            }
            value={formData.rule_value || ""}
            onChange={(e) => setFormData({ ...formData, rule_value: e.target.value })}
            disabled={!formData.rule_type}
          />
        </div>
        {formData.rule_type && (
          <div className="mt-2 p-3 bg-muted rounded-lg text-sm">
            {formData.rule_type === "regex" ? (
              <div>
                <strong>Regex:</strong> Will match against domain names, ASN numbers, certificate subjects, and organization names.
                <br />
                <span className="text-muted-foreground">Example: <code>.*\\.staging\\.</code> matches all staging subdomains</span>
              </div>
            ) : (
              <div>
                <strong>IP Range:</strong> Will match IP addresses within the specified CIDR range(s).
                <br />
                <span className="text-muted-foreground">Use comma-separated values for multiple ranges: <code>10.0.0.0/8, 172.16.0.0/12</code></span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-border">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button onClick={onSubmit} disabled={submitting} loading={submitting}>
          {submitLabel}
        </Button>
      </div>
    </div>
  );
}
