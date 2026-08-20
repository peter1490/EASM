"use client";

import { useMemo } from "react";
import { Chip, Icon } from "@/components/kit";
import { num } from "@/lib/format";
import type { AssetScanHistoryEntry, ScanListItem, SecurityFinding } from "@/app/api";
import { Section } from "./shared";

/**
 * What is actually running on this asset: detected technologies and open ports.
 *
 * The obvious place to read these from is `asset.metadata`, and that is checked
 * first. In practice the backend records them on the scan instead — as the
 * `technology_detected` / `open_port` findings and in the scan's
 * `result_summary` — so all three are merged here rather than showing an empty
 * panel next to a scan that plainly found something.
 */

export interface Technology {
  /** Stable identity: the lower-cased product name it was merged under. */
  key: string;
  name: string;
  version?: string | null;
  categories?: string[];
}

export interface OpenPort {
  port: number;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  encrypted?: boolean;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function asNumber(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Merge one technology into the accumulator.
 *
 * Keyed on the product name alone. The version is deliberately NOT part of the
 * key: the same product arrives from several sources — a bare string in a
 * scan's `technology_stack`, an object on a `technology_detected` finding —
 * and only some of them carry a version. Keying on name+version made
 * "nginx" and "nginx 1.24.0" two separate chips, and the string branch keyed
 * on the bare name while the object branch keyed on `name@version`, so the
 * same product could land under two keys and render twice.
 */
function pushTechnology(into: Map<string, Technology>, entry: unknown) {
  let name: string | null = null;
  let version: string | null = null;
  let categories: string[] | undefined;

  if (typeof entry === "string") {
    name = asString(entry);
  } else {
    const record = asRecord(entry);
    if (!record) return;
    name = asString(record.product) ?? asString(record.name);
    version = asString(record.version);
    categories = Array.isArray(record.categories)
      ? record.categories.map(asString).filter((value): value is string => value != null)
      : undefined;
  }
  if (!name) return;

  const key = name.toLowerCase();
  const existing = into.get(key);

  // Scanners report banners lower-cased ("cloudflare") and catalogues report
  // them cased ("Cloudflare"); prefer whichever looks like a product name.
  const preferredName =
    existing && !/[A-Z]/.test(name) && /[A-Z]/.test(existing.name) ? existing.name : name;

  into.set(key, {
    key,
    name: preferredName,
    version: version ?? existing?.version ?? null,
    categories: mergeCategories(existing?.categories, categories),
  });
}

function mergeCategories(a: string[] | undefined, b: string[] | undefined): string[] | undefined {
  if (!a?.length) return b?.length ? b : undefined;
  if (!b?.length) return a;
  return [...new Set([...a, ...b])];
}

function pushPort(into: Map<number, OpenPort>, port: number | null, extra?: Record<string, unknown>) {
  if (port == null || port <= 0) return;
  const existing = into.get(port) ?? { port };
  into.set(port, {
    port,
    service: asString(extra?.service) ?? asString(extra?.service_name) ?? existing.service ?? null,
    product: asString(extra?.product) ?? existing.product ?? null,
    version: asString(extra?.version) ?? existing.version ?? null,
    encrypted: typeof extra?.is_encrypted === "boolean" ? (extra.is_encrypted as boolean) : existing.encrypted,
  });
}

function collectFromSummary(
  summary: Record<string, unknown> | null | undefined,
  technologies: Map<string, Technology>,
  ports: Map<number, OpenPort>,
) {
  if (!summary) return;
  const stack = summary["technology_stack"];
  if (Array.isArray(stack)) stack.forEach((entry) => pushTechnology(technologies, entry));

  const openPorts = summary["open_ports"];
  if (Array.isArray(openPorts)) openPorts.forEach((entry) => pushPort(ports, asNumber(entry)));

  const services = summary["services_detected"];
  if (Array.isArray(services)) {
    services.forEach((entry) => {
      const record = asRecord(entry);
      if (!record) return;
      pushPort(ports, asNumber(record.port), record);
    });
  }
}

export function deriveTechAndPorts(
  metadata: Record<string, unknown> | null | undefined,
  findings: SecurityFinding[],
  scans: ScanListItem[],
  scanHistory: AssetScanHistoryEntry[],
): { technologies: Technology[]; ports: OpenPort[] } {
  const technologies = new Map<string, Technology>();
  const ports = new Map<number, OpenPort>();

  // 1. The asset's own metadata, when the pipeline has put them there.
  if (metadata) {
    const fromMetadata = metadata["technologies"] ?? metadata["technology_stack"];
    if (Array.isArray(fromMetadata)) fromMetadata.forEach((entry) => pushTechnology(technologies, entry));
    const metaPorts = metadata["open_ports"] ?? metadata["ports"];
    if (Array.isArray(metaPorts)) {
      metaPorts.forEach((entry) => {
        const record = asRecord(entry);
        pushPort(ports, record ? asNumber(record.port) : asNumber(entry), record ?? undefined);
      });
    }
  }

  // 2. The findings that reported them.
  findings.forEach((finding) => {
    const data = finding.data ?? {};
    if (Array.isArray(data["technologies"])) {
      (data["technologies"] as unknown[]).forEach((entry) => pushTechnology(technologies, entry));
    }
    if (Array.isArray(data["stack"])) {
      (data["stack"] as unknown[]).forEach((entry) => pushTechnology(technologies, entry));
    }
    if (Array.isArray(data["open_ports"])) {
      (data["open_ports"] as unknown[]).forEach((entry) => pushPort(ports, asNumber(entry)));
    }
    const port = asNumber(data["port"]);
    if (port != null) pushPort(ports, port, data);
  });

  // 3. Whatever the scans summarised.
  scans.forEach((scan) => collectFromSummary(scan.result_summary, technologies, ports));
  scanHistory.forEach((scan) => collectFromSummary(scan.result_summary, technologies, ports));

  return {
    technologies: [...technologies.values()].sort((a, b) => a.name.localeCompare(b.name)),
    ports: [...ports.values()].sort((a, b) => a.port - b.port),
  };
}

export function TechPortsPanel({
  metadata,
  findings,
  scans,
  scanHistory,
}: {
  metadata: Record<string, unknown> | null | undefined;
  findings: SecurityFinding[];
  scans: ScanListItem[];
  scanHistory: AssetScanHistoryEntry[];
}) {
  const { technologies, ports } = useMemo(
    () => deriveTechAndPorts(metadata, findings, scans, scanHistory),
    [metadata, findings, scans, scanHistory],
  );

  if (technologies.length === 0 && ports.length === 0) return null;

  return (
    <Section
      title="Surface"
      hint={[
        technologies.length > 0 ? `${num(technologies.length)} technologies` : null,
        ports.length > 0 ? `${num(ports.length)} open ports` : null,
      ]
        .filter(Boolean)
        .join(" · ")}
    >
      <div className="flex flex-col gap-3.5">
        {ports.length > 0 && (
          <div>
            <div className="lbl mb-1.5">Open ports</div>
            <div className="flex flex-wrap gap-1.5">
              {ports.map((entry) => (
                <span
                  key={entry.port}
                  title={[entry.service, entry.product, entry.version].filter(Boolean).join(" ") || undefined}
                >
                  <Chip>
                    {entry.encrypted && <Icon name="key" size={10} className="text-ink-3" />}
                    <span className="mono">{entry.port}</span>
                    {entry.service && <span className="text-ink-3">{entry.service}</span>}
                  </Chip>
                </span>
              ))}
            </div>
          </div>
        )}

        {technologies.length > 0 && (
          <div>
            <div className="lbl mb-1.5">Technologies</div>
            <div className="flex flex-wrap gap-1.5">
              {technologies.map((tech) => (
                <span key={tech.key} title={tech.categories?.join(", ")}>
                  <Chip>
                    {tech.name}
                    {tech.version && <span className="mono text-ink-3">{tech.version}</span>}
                  </Chip>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}
