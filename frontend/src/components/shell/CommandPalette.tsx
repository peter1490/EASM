"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/cn";
import { Icon, assetIcon, type IconName } from "@/components/kit/Icon";
import { SeverityChip } from "@/components/kit/Chip";
import { Spinner } from "@/components/kit/States";
import { DESTINATIONS, canSee } from "@/lib/nav";
import { useAuth } from "@/context/AuthContext";
import { searchAssets, searchFindings, searchAssetsAdvanced } from "@/app/api";
import { humanise } from "@/lib/format";

/**
 * Replaces the /search route. Search lives wherever you already are, so finding
 * something is never a navigation away from the thing you were doing.
 */

interface Result {
  id: string;
  group: "Assets" | "Findings" | "Go to";
  title: string;
  subtitle?: string;
  icon: IconName;
  severity?: string;
  href: string;
}

const DEBOUNCE_MS = 180;

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const { user, companies, companyId } = useAuth();
  const [query, setQuery] = useState("");
  const [remote, setRemote] = useState<Result[]>([]);
  const [loading, setLoading] = useState(false);
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const companyRole = companies.find((c) => c.id === companyId)?.role ?? null;

  const navigation = useMemo<Result[]>(
    () =>
      DESTINATIONS.filter((d) => canSee(d, user?.roles, companyRole)).map((d) => ({
        id: `nav:${d.href}`,
        group: "Go to" as const,
        title: d.label,
        icon: d.icon,
        href: d.href,
      })),
    [user?.roles, companyRole],
  );

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setRemote([]);
    setCursor(0);
    const id = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, [open]);

  // Debounced remote search across both indexes at once — the old /search page
  // made you pick "assets" or "findings" from a dropdown first.
  useEffect(() => {
    if (!open) return;
    const term = query.trim();
    if (term.length < 2) {
      setRemote([]);
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    const handle = setTimeout(async () => {
      const results: Result[] = [];
      const [assets, findings] = await Promise.allSettled([
        searchAssets(term, 6),
        searchFindings(term, 6),
      ]);

      if (assets.status === "fulfilled") {
        for (const hit of assets.value.results ?? []) {
          results.push({
            id: `asset:${hit.id}`,
            group: "Assets",
            title: hit.identifier,
            subtitle: [hit.asset_type, hit.sources?.join(", ")].filter(Boolean).join(" · "),
            icon: assetIcon(hit.asset_type),
            href: `/surface/${hit.id}`,
          });
        }
      } else {
        // Search service down: fall back to the database-backed asset query so
        // the palette still finds assets rather than showing nothing.
        try {
          const fallback = await searchAssetsAdvanced({ q: term, limit: 6 });
          for (const asset of fallback.assets ?? []) {
            results.push({
              id: `asset:${asset.id}`,
              group: "Assets",
              title: asset.value,
              subtitle: [asset.asset_type, asset.risk_level ?? undefined].filter(Boolean).join(" · "),
              icon: assetIcon(asset.asset_type),
              href: `/surface/${asset.id}`,
            });
          }
        } catch {
          /* leave assets empty; findings may still have matched */
        }
      }

      if (findings.status === "fulfilled") {
        for (const hit of findings.value.results ?? []) {
          // The finding index stores `data` as an opaque blob, so title and
          // severity are read defensively rather than assumed present.
          const data = (hit.data ?? {}) as Record<string, unknown>;
          const title = typeof data.title === "string" && data.title ? data.title : humanise(hit.finding_type);
          const severity = typeof data.severity === "string" ? data.severity : undefined;
          const assetValue = typeof data.asset_value === "string" ? data.asset_value : undefined;
          results.push({
            id: `finding:${hit.id}`,
            group: "Findings",
            title,
            subtitle: [humanise(hit.finding_type), assetValue].filter(Boolean).join(" · "),
            icon: "alert",
            severity,
            href: `/findings?finding=${hit.id}`,
          });
        }
      }

      if (!cancelled) {
        setRemote(results);
        setLoading(false);
      }
    }, DEBOUNCE_MS);

    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [query, open]);

  const results = useMemo(() => {
    const term = query.trim().toLowerCase();
    const nav = term ? navigation.filter((n) => n.title.toLowerCase().includes(term)) : navigation;
    return [...remote, ...nav];
  }, [remote, navigation, query]);

  useEffect(() => setCursor(0), [results.length]);

  const go = (result: Result) => {
    onClose();
    router.push(result.href);
  };

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      } else if (event.key === "ArrowDown") {
        event.preventDefault();
        setCursor((c) => Math.min(results.length - 1, c + 1));
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        setCursor((c) => Math.max(0, c - 1));
      } else if (event.key === "Enter" && results[cursor]) {
        event.preventDefault();
        go(results[cursor]);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, results, cursor, onClose]);

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>('[data-cursor="true"]')?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  if (!open) return null;

  let index = -1;
  const groups: Array<[string, Result[]]> = [];
  for (const result of results) {
    const last = groups[groups.length - 1];
    if (last && last[0] === result.group) last[1].push(result);
    else groups.push([result.group, [result]]);
  }

  return (
    <>
      <div
        className="fixed inset-0 z-[60] animate-scrim"
        style={{ background: "color-mix(in oklch, var(--ink) 34%, transparent)" }}
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Search"
        className="fixed left-1/2 top-32 z-[61] w-[660px] max-w-[calc(100vw-32px)] max-h-[min(640px,calc(100vh-160px))]
                   flex flex-col rounded-xl border border-rule-2 bg-surface overflow-hidden
                   shadow-[0_32px_80px_-24px_rgba(0,0,0,0.45)]"
        style={{ transform: "translateX(-50%)" }}
      >
        <div className="flex items-center gap-3 h-[54px] px-4 border-b border-rule shrink-0">
          <Icon name="search" size={17} className="text-ink-3" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search assets, findings, actions…"
            aria-label="Search assets, findings and actions"
            className="flex-1 h-[30px] bg-transparent border-0 outline-none text-[15px] tracking-[-0.01em] placeholder:text-ink-3"
          />
          {loading && <Spinner size={14} />}
          <kbd className="mono text-[10px] border border-rule rounded px-1.5 py-0.5 text-ink-3">esc</kbd>
        </div>

        <div ref={listRef} className="flex-1 overflow-y-auto p-2">
          {groups.map(([group, items]) => (
            <div key={group} className="mb-1.5">
              <div className="lbl px-2.5 pt-1.5 pb-1">{group}</div>
              {items.map((result) => {
                index += 1;
                const on = index === cursor;
                return (
                  <button
                    key={result.id}
                    type="button"
                    data-cursor={on}
                    onMouseEnter={() => setCursor(results.indexOf(result))}
                    onClick={() => go(result)}
                    className={cn(
                      "flex items-center gap-3 w-full h-[42px] px-2.5 rounded-[7px] text-left",
                      on ? "bg-accent-wash" : "hover:bg-surface-2",
                    )}
                  >
                    <span
                      className={cn(
                        "grid place-items-center w-6 h-6 rounded-md shrink-0",
                        result.group === "Findings" ? "bg-crit-wash text-crit" : "bg-surface-2 text-ink-2",
                      )}
                    >
                      <Icon name={result.icon} size={13} />
                    </span>
                    <span className="flex-1 min-w-0">
                      <span className="block text-[13px] font-medium truncate">{result.title}</span>
                      {result.subtitle && (
                        <span className="block text-[11.5px] text-ink-3 truncate">{result.subtitle}</span>
                      )}
                    </span>
                    {result.severity && <SeverityChip severity={result.severity} />}
                  </button>
                );
              })}
            </div>
          ))}

          {results.length === 0 && (
            <div className="px-5 py-11 text-center">
              <div className="text-sm font-semibold">
                {query.trim().length < 2 ? "Type to search" : `Nothing matches “${query.trim()}”`}
              </div>
              <p className="text-[12.5px] text-ink-3 mt-1">
                Try a domain, an IP, a CVE id, or the name of a screen.
              </p>
            </div>
          )}
        </div>

        <div className="flex items-center gap-4 h-[38px] px-3.5 border-t border-rule bg-surface-2 text-[11px] text-ink-3 shrink-0">
          <span className="flex items-center gap-1.5">
            <kbd className="mono border border-rule rounded px-1">↑↓</kbd> navigate
          </span>
          <span className="flex items-center gap-1.5">
            <kbd className="mono border border-rule rounded px-1">↵</kbd> open
          </span>
          <span className="ml-auto">Searching assets and findings together</span>
        </div>
      </div>
    </>
  );
}
