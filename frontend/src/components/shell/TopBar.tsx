"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/cn";
import { DESTINATIONS, canSee, isActive } from "@/lib/nav";
import { Icon } from "@/components/kit/Icon";
import { useDiscovery, runProgress } from "@/hooks/useDiscovery";

export function TopBar({ onOpenPalette }: { onOpenPalette: () => void }) {
  const pathname = usePathname();
  const { user, companies, companyId } = useAuth();
  const { status } = useDiscovery();

  const companyRole = companies.find((c) => c.id === companyId)?.role ?? null;
  const visible = DESTINATIONS.filter((d) => canSee(d, user?.roles, companyRole));
  const progress = runProgress(status);

  return (
    <header className="shrink-0">
      <div className="flex items-center gap-3 h-[52px] px-5 bg-surface border-b border-rule">
        <Link href="/" className="flex items-center gap-2.5 text-accent shrink-0" aria-label="EASM home">
          <Icon name="shieldCheck" size={19} />
          <span className="text-sm font-semibold tracking-[-0.02em] text-ink">EASM</span>
        </Link>

        <span className="w-px h-5 bg-rule" aria-hidden="true" />
        <CompanySwitcher />

        <nav className="flex gap-0.5 ml-2" aria-label="Main">
          {visible.map((destination) => {
            const on = isActive(pathname, destination);
            return (
              <Link
                key={destination.href}
                href={destination.href}
                aria-current={on ? "page" : undefined}
                className={cn(
                  "inline-flex items-center h-[30px] px-[11px] rounded-md text-[13px] font-medium",
                  "transition-colors duration-100",
                  on ? "bg-ink text-paper" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
                )}
              >
                {destination.label}
              </Link>
            );
          })}
        </nav>

        <div className="flex-1" />

        <button
          type="button"
          onClick={onOpenPalette}
          className="inline-flex items-center gap-2 w-[250px] h-[30px] px-[11px] rounded-md border border-rule-2
                     bg-surface text-ink-3 text-[12.5px] hover:bg-surface-2 hover:border-ink-3 transition-colors"
        >
          <Icon name="search" size={14} />
          <span className="flex-1 text-left truncate">Search assets, findings, actions…</span>
          <kbd className="mono text-[10px] border border-rule rounded px-1 py-px">⌘K</kbd>
        </button>

        <UserMenu />
      </div>

      {/* Ambient run indicator: the banner that used to be repeated on two pages. */}
      <div className="h-0.5 bg-surface-2" aria-hidden={progress == null}>
        {progress != null && (
          <div
            className="h-full bg-accent transition-[width] duration-700"
            style={{ width: `${progress * 100}%` }}
            role="progressbar"
            aria-label="Discovery run progress"
            aria-valuenow={Math.round(progress * 100)}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        )}
      </div>
    </header>
  );
}

function CompanySwitcher() {
  const { companies, companyId, setCompanyId } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (companies.length === 0) return null;
  const active = companies.find((c) => c.id === companyId);

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="inline-flex items-center gap-2 h-7 px-2 rounded-md hover:bg-surface-2 transition-colors"
      >
        <span className="grid place-items-center w-4 h-4 rounded bg-accent text-on-accent text-[9px] font-bold">
          {active?.name?.[0]?.toUpperCase() ?? "?"}
        </span>
        <span className="text-[12.5px] font-semibold max-w-[160px] truncate">{active?.name ?? "Select company"}</span>
        <Icon name="chevronDown" size={12} className="text-ink-3" />
      </button>

      {open && (
        <div
          role="listbox"
          className="absolute left-0 top-full mt-1 z-50 min-w-[240px] p-1 rounded-lg border border-rule-2 bg-surface
                     shadow-[0_12px_32px_-8px_rgba(0,0,0,0.28)]"
        >
          {companies.map((company) => (
            <button
              key={company.id}
              type="button"
              role="option"
              aria-selected={company.id === companyId}
              onClick={() => {
                setOpen(false);
                if (company.id !== companyId) setCompanyId(company.id);
              }}
              className={cn(
                "flex items-center gap-2.5 w-full h-8 px-2 rounded-md text-[12.5px] text-left",
                company.id === companyId ? "bg-accent-wash text-accent-ink" : "hover:bg-surface-2",
              )}
            >
              <span className="grid place-items-center w-4 h-4 rounded bg-surface-2 text-[9px] font-bold text-ink-2 shrink-0">
                {company.name[0]?.toUpperCase()}
              </span>
              <span className="flex-1 truncate font-medium">{company.name}</span>
              <span className="text-[10.5px] text-ink-3">{company.role}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  if (!user) return null;
  const initials = (user.email ?? "?").slice(0, 2).toUpperCase();

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account"
        className="grid place-items-center w-7 h-7 rounded-full bg-ink text-paper text-[10.5px] font-semibold"
      >
        {initials}
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full mt-1 z-50 w-[240px] p-1 rounded-lg border border-rule-2 bg-surface
                     shadow-[0_12px_32px_-8px_rgba(0,0,0,0.28)]"
        >
          <div className="px-2 py-2 border-b border-rule mb-1">
            <div className="text-[12.5px] font-medium truncate">{user.email ?? "Signed in"}</div>
            <div className="flex flex-wrap gap-1 mt-1.5">
              {user.roles.map((role) => (
                <span key={role} className="text-[10px] px-1.5 py-px rounded bg-surface-2 text-ink-2 font-medium">
                  {role}
                </span>
              ))}
            </div>
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={() => void logout()}
            className="flex items-center gap-2.5 w-full h-8 px-2 rounded-md text-[12.5px] hover:bg-surface-2"
          >
            <Icon name="logout" size={14} className="text-ink-3" />
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
