import type { IconName } from "@/components/kit/Icon";

/**
 * The five destinations. Everything the product does lives under one of these;
 * detail views are children of their list, not siblings in the nav.
 */
export interface Destination {
  href: string;
  label: string;
  icon: IconName;
  /** Roles that may see it. "*" means any authenticated user. */
  roles: string[];
  /** Extra path prefixes that should light this destination up. */
  owns?: string[];
}

export const DESTINATIONS: Destination[] = [
  { href: "/", label: "Overview", icon: "chart", roles: ["admin", "operator", "analyst", "viewer"] },
  {
    href: "/surface",
    label: "Surface",
    icon: "globe",
    roles: ["admin", "operator", "analyst", "viewer"],
  },
  { href: "/findings", label: "Findings", icon: "alert", roles: ["admin", "operator", "analyst", "viewer"] },
  { href: "/ops", label: "Ops", icon: "activity", roles: ["admin", "operator"] },
  // Settings hosts System status, and is the only landing spot for a user with
  // no company role yet — so it stays visible to anyone signed in.
  { href: "/settings", label: "Settings", icon: "settings", roles: ["*"] },
];

export function isActive(pathname: string, destination: Destination): boolean {
  if (destination.href === "/") return pathname === "/";
  if (pathname.startsWith(destination.href)) return true;
  return (destination.owns ?? []).some((prefix) => pathname.startsWith(prefix));
}

/**
 * Global admin is the system super-role and satisfies every gate, mirroring
 * `UserContext::has_role` on the backend. A per-company role counts too — the
 * auth middleware merges it into the request's role set — so a user with no
 * global role still sees their company's screens.
 */
export function canSee(
  destination: Destination,
  globalRoles: string[] | undefined,
  companyRole: string | null,
): boolean {
  if (!globalRoles) return false;
  if (destination.roles.includes("*")) return true;
  if (globalRoles.includes("global_admin")) return true;
  if (destination.roles.some((role) => globalRoles.includes(role))) return true;
  if (companyRole && destination.roles.includes(companyRole)) return true;
  return false;
}
