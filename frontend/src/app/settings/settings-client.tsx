"use client";

import { Suspense, useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { EmptyState, Icon, LoadingBlock, PageHeader, type IconName } from "@/components/kit";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/cn";
import { CompaniesPane } from "@/components/settings/CompaniesPane";
import { CompanyPane } from "@/components/settings/CompanyPane";
import { IntegrationsPane } from "@/components/settings/IntegrationsPane";
import { MembersPane } from "@/components/settings/MembersPane";
import { RiskScoringPane } from "@/components/settings/RiskScoringPane";
import { StatusPane } from "@/components/settings/StatusPane";
import { TagsPane } from "@/components/settings/TagsPane";
import { UsersPane } from "@/components/settings/UsersPane";

type PaneKey =
  | "company"
  | "members"
  | "tags"
  | "risk"
  | "integrations"
  | "status"
  | "users"
  | "companies";

/**
 * Who may open a pane.
 * - `everyone`: Settings is deliberately reachable by every role, because it
 *   hosts System status and is the only landing spot for a user with no other
 *   access.
 * - `company_admin`: global admin, or admin of the *active* company.
 */
type Gate = "everyone" | "global_admin" | "company_admin";

type PaneDef = {
  key: PaneKey;
  label: string;
  icon: IconName;
  gate: Gate;
  title: string;
  hint: (companyName: string) => string;
};

const GROUPS: Array<{ label: string; panes: PaneDef[] }> = [
  {
    label: "Workspace",
    panes: [
      {
        key: "company",
        label: "Company",
        icon: "building",
        gate: "company_admin",
        title: "Company",
        hint: (name) => `Rename ${name}, or clear what it holds.`,
      },
      {
        key: "members",
        label: "Members",
        icon: "users",
        gate: "company_admin",
        title: "Members",
        hint: (name) => `Who can reach ${name}, and with which role.`,
      },
      {
        key: "tags",
        label: "Tags",
        icon: "tag",
        gate: "global_admin",
        title: "Tags",
        hint: () => "Labels that carry importance onto assets, by hand or by rule.",
      },
    ],
  },
  {
    label: "Detection",
    panes: [
      {
        key: "risk",
        label: "Risk scoring",
        icon: "chart",
        gate: "global_admin",
        title: "Risk scoring",
        hint: () => "What each finding type contributes to an asset's score.",
      },
      {
        key: "integrations",
        label: "Integrations",
        icon: "plug",
        gate: "global_admin",
        title: "Integrations",
        hint: () => "Identity providers, external API keys, and discovery limits.",
      },
    ],
  },
  {
    label: "System",
    panes: [
      {
        key: "status",
        label: "Status and metrics",
        icon: "activity",
        gate: "everyone",
        title: "Status and metrics",
        hint: () => "Live health and load for this deployment.",
      },
      {
        key: "users",
        label: "All users",
        icon: "shield",
        gate: "global_admin",
        title: "All users",
        hint: () => "Every account, its global roles, and its company access.",
      },
      {
        key: "companies",
        label: "Companies",
        icon: "building",
        gate: "global_admin",
        title: "Companies",
        hint: () => "Every company you belong to, and the data inside it.",
      },
    ],
  },
];

const ALL_PANES: PaneDef[] = GROUPS.flatMap((group) => group.panes);

/**
 * The old flat tabs are still linked from elsewhere, so `?tab=` keeps working
 * and resolves to the pane that absorbed it. `system` is the group name other
 * screens point at when they mean "the system health page".
 */
const ALIASES: Record<string, PaneKey> = {
  status: "status",
  users: "users",
  config: "integrations",
  companies: "companies",
  management: "company",
  tags: "tags",
  risk_scoring: "risk",
  system: "status",
  workspace: "company",
  detection: "risk",
};

function resolvePane(raw: string | null): PaneKey {
  if (!raw) return "status";
  if (ALL_PANES.some((p) => p.key === raw)) return raw as PaneKey;
  return ALIASES[raw] ?? "status";
}

function SettingsShell() {
  const router = useRouter();
  const params = useSearchParams();
  const { user, companies, companyId } = useAuth();

  const isGlobalAdmin = !!user?.roles?.includes("global_admin");
  const activeCompany = companies.find((c) => c.id === companyId) ?? null;
  const isActiveCompanyAdmin = activeCompany?.role === "admin";
  const companyName = activeCompany?.name ?? "this company";

  const can = useMemo(
    () => (gate: Gate) => {
      if (gate === "everyone") return true;
      if (isGlobalAdmin) return true;
      if (gate === "company_admin") return isActiveCompanyAdmin;
      return false;
    },
    [isGlobalAdmin, isActiveCompanyAdmin],
  );

  // `?pane=` wins; `?tab=` is mapped for the deep links that still point at the
  // old flat tabs.
  const pane = resolvePane(params.get("pane") ?? params.get("tab"));
  const def = ALL_PANES.find((p) => p.key === pane) ?? ALL_PANES[0];
  const permitted = can(def.gate);

  const select = (key: PaneKey) => {
    router.replace(`/settings?pane=${key}`, { scroll: false });
  };

  return (
    <div className="h-full flex min-h-0">
      <nav
        aria-label="Settings sections"
        className="w-[212px] shrink-0 border-r border-rule bg-surface overflow-y-auto"
      >
        <div className="px-3 py-4 space-y-5">
          {GROUPS.map((group) => {
            const visible = group.panes.filter((p) => can(p.gate));
            if (visible.length === 0) return null;
            return (
              <div key={group.label}>
                <div className="lbl px-2 mb-1.5">{group.label}</div>
                <div className="space-y-0.5">
                  {visible.map((item) => {
                    const active = item.key === pane;
                    return (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() => select(item.key)}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "w-full flex items-center gap-2.5 h-[30px] px-2 rounded-md text-left",
                          "text-[12.5px] transition-colors duration-100",
                          active
                            ? "bg-accent-wash text-accent-ink font-medium"
                            : "text-ink-2 hover:bg-surface-2 hover:text-ink",
                        )}
                      >
                        <Icon
                          name={item.icon}
                          size={14}
                          className={cn("shrink-0", active ? "text-accent" : "text-ink-3")}
                        />
                        <span className="truncate">{item.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </nav>

      <div className="flex-1 min-w-0 overflow-y-auto">
        <div className="px-6 pt-5 pb-10 max-w-[1080px]">
          <PageHeader
            title={def.title}
            hint={permitted ? def.hint(companyName) : "You do not have access to this section."}
          />

          <div className="mt-4">
            {!permitted ? (
              <EmptyState
                icon="ban"
                title="Not available to your role"
                description={
                  def.gate === "global_admin"
                    ? "This section is reserved for global admins."
                    : `This section is for admins of ${companyName}.`
                }
              />
            ) : (
              <Pane pane={def.key} companyId={companyId} companyName={companyName} isGlobalAdmin={isGlobalAdmin} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Pane({
  pane,
  companyId,
  companyName,
  isGlobalAdmin,
}: {
  pane: PaneKey;
  companyId: string | null;
  companyName: string;
  isGlobalAdmin: boolean;
}) {
  switch (pane) {
    case "company":
      return <CompanyPane companyId={companyId} />;
    case "members":
      return <MembersPane companyId={companyId} companyName={companyName} isGlobalAdmin={isGlobalAdmin} />;
    case "tags":
      return <TagsPane />;
    case "risk":
      return <RiskScoringPane />;
    case "integrations":
      return <IntegrationsPane />;
    case "users":
      return <UsersPane />;
    case "companies":
      return <CompaniesPane />;
    case "status":
    default:
      return <StatusPane />;
  }
}

export default function SettingsClient() {
  return (
    <Suspense fallback={<LoadingBlock label="Opening settings" />}>
      <SettingsShell />
    </Suspense>
  );
}
