"use client";

/**
 * Per-finding-type evidence renderers.
 *
 * This is the logic that used to live in `components/FindingRenderer.tsx` — a
 * fully built component that was imported nowhere, which is why every finding
 * modal in the old build showed a raw `JSON.stringify` blob instead. Ported to
 * the design tokens, emoji icons replaced with `Icon` names, and the generic
 * fallback taught to render nested objects and arrays instead of dumping JSON.
 */

import { ReactNode } from "react";
import { Chip, Icon, type IconName } from "@/components/kit";
import { cn } from "@/lib/cn";
import { dateTime } from "@/lib/format";

type Data = Record<string, unknown>;

/* ------------------------------------------------------------------ *
 * Type vocabulary
 * ------------------------------------------------------------------ */

const TYPE_LABELS: Record<string, string> = {
  port_scan: "Port scan",
  open_port: "Open port",
  open_ports: "Open ports",
  dns_resolution: "DNS resolution",
  dns_resolution_failed: "DNS resolution failed",
  dns_record: "DNS record",
  reverse_dns: "Reverse DNS",
  http_probe: "HTTP probe",
  tls_analysis: "TLS certificate analysis",
  threat_intelligence: "Threat intelligence",
  subdomain_enumeration: "Subdomain enumeration",
  technology_detected: "Technology stack",
  known_cve: "Known CVE",
  exposed_service: "Exposed service",
  sensitive_port: "Sensitive port",
  database_exposed: "Database exposed",
  admin_port_exposed: "Admin port exposed",
  server_version_exposed: "Server version exposed",
  missing_security_header: "Missing security header",
  missing_spf: "Missing SPF",
  missing_dkim: "Missing DKIM",
  missing_dmarc: "Missing DMARC",
  missing_caa: "Missing CAA",
  missing_dnssec: "Missing DNSSEC",
  weak_dmarc_policy: "Weak DMARC policy",
  weak_tls_version: "Weak TLS version",
  weak_cipher_suite: "Weak cipher suite",
  weak_key_strength: "Weak key strength",
  weak_signature_algorithm: "Weak signature algorithm",
  expired_certificate: "Expired certificate",
  certificate_expiring_soon: "Certificate expiring soon",
  certificate_hostname_mismatch: "Certificate hostname mismatch",
  certificate_chain_incomplete: "Incomplete certificate chain",
  certificate_missing_san: "Certificate missing SAN",
  certificate_not_yet_valid: "Certificate not yet valid",
  self_signed_certificate: "Self-signed certificate",
  https_not_enforced: "HTTPS not enforced",
  no_waf_detected: "No WAF detected",
  reputation_issue: "Reputation issue",
  port_drift: "Port drift",
  cidr_expansion: "CIDR expansion",
};

const TYPE_ICONS: Record<string, IconName> = {
  port_scan: "port",
  open_port: "port",
  open_ports: "port",
  port_drift: "port",
  exposed_service: "port",
  sensitive_port: "port",
  database_exposed: "port",
  admin_port_exposed: "port",
  dns_resolution: "globe",
  dns_resolution_failed: "globe",
  dns_record: "globe",
  reverse_dns: "refresh",
  http_probe: "link",
  https_not_enforced: "link",
  tls_analysis: "certificate",
  expired_certificate: "certificate",
  certificate_expiring_soon: "certificate",
  certificate_hostname_mismatch: "certificate",
  certificate_chain_incomplete: "certificate",
  certificate_missing_san: "certificate",
  certificate_not_yet_valid: "certificate",
  self_signed_certificate: "certificate",
  weak_key_strength: "key",
  weak_signature_algorithm: "key",
  weak_tls_version: "certificate",
  weak_cipher_suite: "certificate",
  threat_intelligence: "shield",
  reputation_issue: "shield",
  no_waf_detected: "shield",
  subdomain_enumeration: "search",
  technology_detected: "plug",
  server_version_exposed: "plug",
  known_cve: "alert",
  missing_security_header: "shield",
  missing_spf: "globe",
  missing_dkim: "globe",
  missing_dmarc: "globe",
  missing_caa: "globe",
  missing_dnssec: "globe",
  weak_dmarc_policy: "globe",
  cidr_expansion: "server",
};

export function findingTypeLabel(findingType: string | null | undefined): string {
  if (!findingType) return "Finding";
  return (
    TYPE_LABELS[findingType] ??
    findingType.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase())
  );
}

export function findingTypeIcon(findingType: string | null | undefined): IconName {
  if (!findingType) return "alert";
  return TYPE_ICONS[findingType] ?? "alert";
}

/* ------------------------------------------------------------------ *
 * Small building blocks
 * ------------------------------------------------------------------ */

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 py-1">
      <span className="lbl w-[104px] shrink-0 pt-px">{label}</span>
      <div className="flex-1 min-w-0 text-[12.5px] text-ink">{children}</div>
    </div>
  );
}

function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("mono text-[12px] break-all", className)}>{children}</span>;
}

function Muted({ children }: { children: ReactNode }) {
  return <span className="text-[12.5px] text-ink-3">{children}</span>;
}

function ChipList({
  items,
  tone,
  max = 24,
}: {
  items: ReactNode[];
  tone?: { text: string; wash: string };
  max?: number;
}) {
  if (items.length === 0) return <Muted>—</Muted>;
  const shown = items.slice(0, max);
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((item, i) => (
        <Chip key={i} tone={tone}>
          <span className="mono text-[11px]">{item}</span>
        </Chip>
      ))}
      {items.length > max && <Chip>+{items.length - max} more</Chip>}
    </div>
  );
}

function Disclosure({ summary, children }: { summary: string; children: ReactNode }) {
  return (
    <details className="group">
      <summary className="flex items-center gap-1.5 cursor-pointer text-[12px] text-ink-2 hover:text-ink list-none">
        <Icon name="chevronRight" size={11} className="transition-transform group-open:rotate-90" />
        {summary}
      </summary>
      <div className="mt-2 rounded-md border border-rule bg-surface-2 p-2.5">{children}</div>
    </details>
  );
}

function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 text-accent hover:underline break-all"
    >
      {children}
      <Icon name="external" size={10} className="shrink-0" />
    </a>
  );
}

function StateChip({ ok, on, off }: { ok: boolean; on: string; off: string }) {
  return (
    <Chip tone={ok ? { text: "text-ok", wash: "bg-ok-wash" } : { text: "text-high", wash: "bg-high-wash" }}>
      <Icon name={ok ? "check" : "alert"} size={10} />
      {ok ? on : off}
    </Chip>
  );
}

/* ------------------------------------------------------------------ *
 * Value coercion — result payloads are free-form JSON
 * ------------------------------------------------------------------ */

export const asString = (v: unknown): string | null =>
  typeof v === "string" && v.length > 0 ? v : null;
export const asNumber = (v: unknown): number | null =>
  typeof v === "number" && !Number.isNaN(v) ? v : null;
export const asBool = (v: unknown): boolean => v === true;
export const asObject = (v: unknown): Data | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Data) : null;

/** Distinct strings from a scan-data array.
 *
 *  Deduplicated because every list this feeds is a set — references, SAN domains,
 *  hostnames, detected technologies — and the values are rendered as React keys.
 *  Scanners merge these from several sources without a distinct pass, so an NVD CVE
 *  reporting the same advisory URL twice crashed the evidence panel with a duplicate
 *  key. Nothing downstream counts repeats; showing one twice was never wanted either. */
export function asStrings(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return [...new Set(v.filter((x): x is string => typeof x === "string"))];
}

/** Distinct numbers from a scan-data array. Deduplicated for the reasons in
 *  {@link asStrings} — open-port lists are its main caller and are keyed by value. */
export function asNumbers(v: unknown): number[] {
  if (!Array.isArray(v)) return [];
  return [...new Set(v.filter((x): x is number => typeof x === "number"))];
}

export function asObjects(v: unknown): Data[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is Data => !!x && typeof x === "object" && !Array.isArray(x));
}

const isUrl = (v: string) => /^https?:\/\//i.test(v);
const isIso = (v: string) => /^\d{4}-\d{2}-\d{2}T/.test(v);

const SENSITIVE_PORTS = new Set([21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017]);
const WEB_PORTS = new Set([80, 443, 8080, 8443]);

export function portTone(port: number): { text: string; wash: string } | undefined {
  if (SENSITIVE_PORTS.has(port)) return { text: "text-high", wash: "bg-high-wash" };
  if (WEB_PORTS.has(port)) return { text: "text-ok", wash: "bg-ok-wash" };
  return undefined;
}

/* ------------------------------------------------------------------ *
 * Per-type renderers
 * ------------------------------------------------------------------ */

function PortScan({ data }: { data: Data }) {
  const ports = asNumbers(data.open_ports);
  const count = asNumber(data.count) ?? ports.length;
  return (
    <div className="space-y-1">
      {asString(data.ip) && (
        <Row label="Target">
          <Mono>{asString(data.ip)}</Mono>
        </Row>
      )}
      <Row label={`Open ports (${count})`}>
        {ports.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {ports.map((port) => (
              <Chip key={port} tone={portTone(port)}>
                <span className="mono text-[11px]">{port}</span>
              </Chip>
            ))}
          </div>
        ) : (
          <Muted>None</Muted>
        )}
      </Row>
    </div>
  );
}

function DnsResolution({ data }: { data: Data }) {
  const ips = asStrings(data.ips);
  const count = asNumber(data.count) ?? ips.length;
  return (
    <div className="space-y-1">
      {asString(data.hostname) && (
        <Row label="Hostname">
          <Mono>{asString(data.hostname)}</Mono>
        </Row>
      )}
      <Row label={`Resolves to (${count})`}>
        <ChipList items={ips} />
      </Row>
    </div>
  );
}

function ReverseDns({ data }: { data: Data }) {
  const hostnames = asStrings(data.hostnames);
  const count = asNumber(data.count) ?? hostnames.length;
  return (
    <div className="space-y-1">
      {asString(data.ip) && (
        <Row label="IP address">
          <Mono>{asString(data.ip)}</Mono>
        </Row>
      )}
      <Row label={`Hostnames (${count})`}>
        <ChipList items={hostnames} />
      </Row>
    </div>
  );
}

function HttpProbe({ data }: { data: Data }) {
  const url = asString(data.url);
  const status = asNumber(data.status_code);
  const error = asString(data.error);
  const finalUrl = asString(data.final_url);
  const responseTime = asNumber(data.response_time_ms);
  return (
    <div className="space-y-1">
      {url && (
        <Row label="URL">
          <ExternalLink href={url}>
            <Mono>{url}</Mono>
          </ExternalLink>
        </Row>
      )}
      {error ? (
        <Row label="Error">
          <span className="text-[12.5px] text-crit">{error}</span>
        </Row>
      ) : (
        <>
          <Row label="Status">
            {status != null ? (
              <Chip
                tone={
                  status < 400
                    ? { text: "text-ok", wash: "bg-ok-wash" }
                    : { text: "text-high", wash: "bg-high-wash" }
                }
              >
                <span className="mono text-[11px]">{status}</span>
              </Chip>
            ) : (
              <Muted>—</Muted>
            )}
          </Row>
          {asString(data.title) && <Row label="Page title">{asString(data.title)}</Row>}
          {asString(data.server) && (
            <Row label="Server">
              <Mono>{asString(data.server)}</Mono>
            </Row>
          )}
          {asString(data.content_type) && (
            <Row label="Content type">
              <Mono>{asString(data.content_type)}</Mono>
            </Row>
          )}
          {finalUrl && finalUrl !== url && (
            <Row label="Redirected to">
              <Mono>{finalUrl}</Mono>
            </Row>
          )}
        </>
      )}
      {responseTime != null && (
        <Row label="Response time">
          <Mono>{responseTime} ms</Mono>
        </Row>
      )}
    </div>
  );
}

function TlsAnalysis({ data }: { data: Data }) {
  const cert = asObject(data.certificate);
  if (!cert) {
    return <Muted>No certificate data.</Muted>;
  }
  const san = asStrings(cert.san_domains);
  const notBefore = asString(cert.not_before);
  const notAfter = asString(cert.not_after);
  return (
    <div className="space-y-1">
      {asString(data.address) && (
        <Row label="Address">
          <Mono>{asString(data.address)}</Mono>
        </Row>
      )}
      {asString(cert.common_name) && (
        <Row label="Common name">
          <Mono>{asString(cert.common_name)}</Mono>
        </Row>
      )}
      <Row label="Valid from">{notBefore ? dateTime(notBefore) : <Muted>—</Muted>}</Row>
      <Row label="Valid until">{notAfter ? dateTime(notAfter) : <Muted>—</Muted>}</Row>
      {asString(cert.issuer) && (
        <Row label="Issuer">
          <Mono>{asString(cert.issuer)}</Mono>
        </Row>
      )}
      {san.length > 0 && (
        <Row label={`SAN domains (${san.length})`}>
          <ChipList items={san} max={12} />
        </Row>
      )}
      <div className="pt-2">
        <Disclosure summary="Certificate details">
          <div className="space-y-1">
            <Row label="Serial">
              <Mono>{asString(cert.serial_number) ?? "—"}</Mono>
            </Row>
            <Row label="Subject">
              <Mono>{asString(cert.subject) ?? "—"}</Mono>
            </Row>
            {asString(cert.signature_algorithm) && (
              <Row label="Signature">
                <Mono>{asString(cert.signature_algorithm)}</Mono>
              </Row>
            )}
          </div>
        </Disclosure>
      </div>
    </div>
  );
}

function ThreatIntelligence({ data }: { data: Data }) {
  const malicious = asBool(data.is_malicious);
  const reputation = asNumber(data.reputation_score);
  const sources = asStrings(data.threat_sources);
  const extra = asObject(data.additional_info) ?? {};
  const vtMalicious = asNumber(extra.virustotal_malicious_count);
  const vtSuspicious = asNumber(extra.virustotal_suspicious_count);
  return (
    <div className="space-y-1">
      {asString(data.target) && (
        <Row label="Target">
          <Mono>{asString(data.target)}</Mono>
        </Row>
      )}
      <Row label="Verdict">
        <StateChip ok={!malicious} on="Clean" off="Malicious" />
      </Row>
      {reputation != null && (
        <Row label="Reputation">
          <Mono>{reputation}</Mono>
        </Row>
      )}
      {sources.length > 0 && (
        <Row label="Threat sources">
          <ChipList items={sources} tone={{ text: "text-crit", wash: "bg-crit-wash" }} />
        </Row>
      )}
      {asNumber(extra.asn) != null && (
        <Row label="ASN">
          <Mono>AS{asNumber(extra.asn)}</Mono>
        </Row>
      )}
      {asString(extra.country) && <Row label="Country">{asString(extra.country)}</Row>}
      {vtMalicious != null && (
        <Row label="VirusTotal">
          <Mono>
            {vtMalicious} malicious
            {vtSuspicious != null ? ` · ${vtSuspicious} suspicious` : ""}
          </Mono>
        </Row>
      )}
    </div>
  );
}

function SubdomainEnumeration({ data }: { data: Data }) {
  const subdomains = asStrings(data.subdomains);
  const count = asNumber(data.count) ?? subdomains.length;
  const sources = asObject(data.sources);
  return (
    <div className="space-y-1">
      {asString(data.domain) && (
        <Row label="Domain">
          <Mono>{asString(data.domain)}</Mono>
        </Row>
      )}
      <Row label="Subdomains">
        <Mono>{count}</Mono>
      </Row>
      {sources && Object.keys(sources).length > 0 && (
        <Row label="Sources">
          <div className="flex flex-wrap gap-1">
            {Object.entries(sources).map(([source, found]) => (
              <Chip key={source}>
                {source}
                <span className="mono text-[11px] text-ink-3">
                  {Array.isArray(found) ? found.length : 0}
                </span>
              </Chip>
            ))}
          </div>
        </Row>
      )}
      {subdomains.length > 0 && (
        <div className="pt-2">
          <Disclosure summary={`View all subdomains (${subdomains.length})`}>
            <div className="max-h-56 overflow-y-auto grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5">
              {subdomains.map((sub, i) => (
                <span key={i} className="mono text-[11.5px] text-ink-2 break-all">
                  {sub}
                </span>
              ))}
            </div>
          </Disclosure>
        </div>
      )}
    </div>
  );
}

function KnownCve({ data }: { data: Data }) {
  const cveId = asString(data.cve_id);
  const cvss = asNumber(data.cvss_score);
  const vector = asString(data.cvss_vector);
  const service = asString(data.affected_service);
  const cpe = asString(data.affected_cpe);
  const detectedVersion = asString(data.detected_version);
  const affected = asStrings(data.affected_version);
  const references = asStrings(data.references);
  const detectionMethod = asString(data.detection_method);
  const detectionSource = asString(data.detection_source);
  const evidence = asString(data.fingerprint_value);

  const versionConfirmed = data.version_confirmed !== false;
  const knownExploited = asBool(data.known_exploited);
  const kevAdded = asString(data.kev_date_added);
  const kevDue = asString(data.kev_due_date);
  const ransomware = asBool(data.known_ransomware_campaign_use);
  const epss = asNumber(data.epss_probability);
  const epssPercentile = asNumber(data.epss_percentile);
  const priority = asNumber(data.priority_score);

  return (
    <div className="space-y-2">
      {/* Exploitation evidence first: it is what decides whether this gets
          worked on today, and a CVSS score alone cannot say. */}
      <div className="flex flex-wrap items-center gap-2">
        {cveId && (
          <ExternalLink href={`https://nvd.nist.gov/vuln/detail/${cveId}`}>
            <Mono className="text-[12px]">{cveId}</Mono>
          </ExternalLink>
        )}
        {priority != null && (
          <Chip
            tone={
              priority >= 7.5
                ? { text: "text-crit", wash: "bg-crit-wash" }
                : priority >= 5
                  ? { text: "text-high", wash: "bg-high-wash" }
                  : { text: "text-ink-2", wash: "bg-nil-wash" }
            }
          >
            Priority {priority.toFixed(1)}
          </Chip>
        )}
        {knownExploited && (
          <Chip tone={{ text: "text-crit", wash: "bg-crit-wash" }}>
            <Icon name="alert" size={10} />
            Exploited in the wild
          </Chip>
        )}
        {ransomware && (
          <Chip tone={{ text: "text-crit", wash: "bg-crit-wash" }}>Ransomware campaigns</Chip>
        )}
        {!versionConfirmed && (
          <Chip tone={{ text: "text-med", wash: "bg-med-wash" }}>
            <Icon name="alert" size={10} />
            Unconfirmed
          </Chip>
        )}
      </div>

      {!versionConfirmed && (
        <p className="text-[11.5px] leading-snug text-ink-3">
          {service ?? "This product"} only publishes its major version, so the exact build is
          unknown. This CVE affects some release in the{" "}
          <span className="mono">{detectedVersion ?? "detected"}</span> series — check the running
          build before treating it as exploitable.
        </p>
      )}

      {cvss != null && (
        <Row label="CVSS">
          <span className="flex flex-wrap items-baseline gap-2">
            <Mono>{cvss.toFixed(1)}</Mono>
            {vector && <Mono className="text-[10.5px] text-ink-3 break-all">{vector}</Mono>}
          </span>
        </Row>
      )}

      {epss != null && (
        <Row label="EPSS">
          <span className="flex flex-wrap items-baseline gap-2">
            <Mono>{(epss * 100).toFixed(epss < 0.01 ? 2 : 1)}%</Mono>
            <span className="text-[11.5px] text-ink-3">
              probability of exploitation in the next 30 days
              {epssPercentile != null && ` · ${(epssPercentile * 100).toFixed(1)}th percentile`}
            </span>
          </span>
        </Row>
      )}

      {kevAdded && (
        <Row label="CISA KEV">
          <span className="flex flex-wrap items-baseline gap-2">
            <span>Added {kevAdded}</span>
            {kevDue && <span className="text-[11.5px] text-ink-3">federal due date {kevDue}</span>}
          </span>
        </Row>
      )}

      {service && (
        <Row label="Affected">
          <span className="flex flex-wrap items-baseline gap-2">
            <Mono>
              {service}
              {detectedVersion ? ` ${detectedVersion}` : ""}
              {!versionConfirmed && detectedVersion ? ".x" : ""}
            </Mono>
            {affected.length > 0 && (
              <span className="text-[11.5px] text-ink-3">vulnerable range: {affected.join(", ")}</span>
            )}
          </span>
        </Row>
      )}

      {cpe && (
        <Row label="CPE">
          <Mono className="text-[10.5px] break-all">{cpe}</Mono>
        </Row>
      )}

      {/* How we concluded the product is here at all — the reader needs this to
          judge the claim, especially for a passive, unauthenticated scan. */}
      {(detectionMethod || detectionSource || evidence) && (
        <Row label="Detected via">
          <span className="flex flex-wrap items-baseline gap-2">
            {detectionSource && <Mono className="text-[11px]">{detectionSource}</Mono>}
            {detectionMethod && (
              <span className="text-[11.5px] text-ink-3">{detectionMethod.replace(/_/g, " ")}</span>
            )}
            {evidence && <Mono className="text-[10.5px] text-ink-3 break-all">{evidence}</Mono>}
          </span>
        </Row>
      )}

      {references.length > 0 && (
        <Disclosure summary={`References (${references.length})`}>
          <div className="flex flex-col gap-1">
            {references.slice(0, 25).map((href) => (
              <ExternalLink key={href} href={href}>
                <Mono className="text-[10.5px] break-all">{href}</Mono>
              </ExternalLink>
            ))}
          </div>
        </Disclosure>
      )}
    </div>
  );
}

function TechnologyDetected({ data }: { data: Data }) {
  const technologies = asObjects(data.technologies);
  const stack = asStrings(data.stack);
  const url = asString(data.url);

  if (technologies.length === 0 && stack.length === 0) {
    return <Muted>No technologies detected.</Muted>;
  }

  return (
    <div className="space-y-2">
      {url && (
        <Row label="URL">
          <ExternalLink href={url}>
            <Mono>{url}</Mono>
          </ExternalLink>
        </Row>
      )}
      {technologies.length > 0 ? (
        <div className="flex flex-col gap-1.5">
          {technologies.map((tech, i) => {
            const name = asString(tech.name) ?? asString(tech.product) ?? "Unknown";
            const version = asString(tech.version);
            const categories = asStrings(tech.categories);
            const confidence = asNumber(tech.confidence);
            const source = asString(tech.source);
            const sources = asStrings(tech.sources);
            const inferred = source === "implied";
            const cpe = asString(tech.cpe);
            return (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <Chip tone={{ text: "text-accent-ink", wash: "bg-accent-wash" }}>
                  {name}
                  {version ? <span className="mono text-[11px]">{version}</span> : null}
                </Chip>
                {categories.length > 0 && (
                  <span className="text-[11.5px] text-ink-3">{categories.join(" · ")}</span>
                )}
                {confidence != null && <span className="mono text-[11px] text-ink-3">{confidence}%</span>}
                {sources.length > 0 ? (
                  <span className="mono text-[10.5px] text-ink-3">{sources.join(" + ")}</span>
                ) : (
                  source && <span className="mono text-[10.5px] text-ink-3">{source}</span>
                )}
                {inferred && (
                  <span className="text-[11px] text-ink-3" title="Deduced from another product, not observed directly">
                    inferred
                  </span>
                )}
                {cpe && <span className="mono text-[10.5px] text-ink-3 break-all">{cpe}</span>}
              </div>
            );
          })}
        </div>
      ) : (
        <ChipList items={stack} tone={{ text: "text-accent-ink", wash: "bg-accent-wash" }} />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Generic fallback — readable key/value instead of a JSON dump
 * ------------------------------------------------------------------ */

/** Keys rendered by the finding header, so the evidence block does not repeat them. */
const HANDLED_KEYS = new Set(["source_url", "source_name"]);

function renderScalar(value: unknown): ReactNode {
  if (value === null || value === undefined || value === "") return <Muted>—</Muted>;
  if (typeof value === "boolean") return <StateChip ok={value} on="Yes" off="No" />;
  if (typeof value === "number") return <Mono>{value}</Mono>;
  if (typeof value === "string") {
    if (isUrl(value)) {
      return (
        <ExternalLink href={value}>
          <Mono>{value}</Mono>
        </ExternalLink>
      );
    }
    if (isIso(value)) return <span>{dateTime(value)}</span>;
    if (value.length > 220) {
      return <span className="text-[12.5px] whitespace-pre-wrap break-words">{value}</span>;
    }
    return <span className="break-words">{value}</span>;
  }
  return <Mono>{String(value)}</Mono>;
}

function renderValue(value: unknown, depth = 0): ReactNode {
  if (Array.isArray(value)) {
    if (value.length === 0) return <Muted>None</Muted>;
    const scalars = value.every((v) => v === null || typeof v !== "object");
    if (scalars) {
      return <ChipList items={value.map((v) => String(v))} max={30} />;
    }
    if (depth >= 1) {
      return <Muted>{value.length} entries</Muted>;
    }
    return (
      <div className="flex flex-col gap-2">
        {value.slice(0, 12).map((entry, i) => (
          <div key={i} className="rounded-md border border-rule bg-surface-2 px-2.5 py-1.5">
            {renderValue(entry, depth + 1)}
          </div>
        ))}
        {value.length > 12 && <Muted>+{value.length - 12} more</Muted>}
      </div>
    );
  }

  const object = asObject(value);
  if (object) {
    const entries = Object.entries(object);
    if (entries.length === 0) return <Muted>—</Muted>;
    return (
      <div className="space-y-0.5">
        {entries.map(([key, nested]) => (
          <div key={key} className="flex items-baseline gap-2">
            <span className="lbl shrink-0 min-w-[84px]">{key.replace(/_/g, " ")}</span>
            <div className="flex-1 min-w-0 text-[12.5px]">
              {depth >= 1 ? renderScalar(nested) : renderValue(nested, depth + 1)}
            </div>
          </div>
        ))}
      </div>
    );
  }

  return renderScalar(value);
}

function Generic({ data }: { data: Data }) {
  const entries = Object.entries(data ?? {}).filter(([key]) => !HANDLED_KEYS.has(key));
  if (entries.length === 0) return <Muted>No structured evidence was recorded for this finding.</Muted>;
  return (
    <div className="space-y-1.5">
      {entries.map(([key, value]) => (
        <Row key={key} label={key.replace(/_/g, " ")}>
          {renderValue(value)}
        </Row>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

export function FindingEvidence({
  findingType,
  data,
}: {
  findingType: string;
  data: Data | null | undefined;
}) {
  const payload = data && typeof data === "object" ? data : {};

  switch (findingType) {
    case "port_scan":
      return <PortScan data={payload} />;
    case "dns_resolution":
      return <DnsResolution data={payload} />;
    case "reverse_dns":
      return <ReverseDns data={payload} />;
    case "http_probe":
      return <HttpProbe data={payload} />;
    case "tls_analysis":
      return <TlsAnalysis data={payload} />;
    case "threat_intelligence":
      return <ThreatIntelligence data={payload} />;
    case "subdomain_enumeration":
      return <SubdomainEnumeration data={payload} />;
    case "technology_detected":
      return <TechnologyDetected data={payload} />;
    case "known_cve":
      return <KnownCve data={payload} />;
    default:
      return <Generic data={payload} />;
  }
}

export default FindingEvidence;
