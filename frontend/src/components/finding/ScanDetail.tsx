"use client";

/**
 * The scan result view — what `/security/scans/[id]` was, as sections instead
 * of seven tabs, inside the Findings destination (`/findings?scan=<id>`).
 *
 * `scan.result_summary` is free-form JSON written by whichever scanner ran, so
 * every field is read through a guard and every section renders only when it
 * actually has data. `technology_stack` is included: the backend has always
 * produced it and the old page declared the field but never displayed it.
 */

import { ReactNode, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { getSecurityScan, type SecurityScanDetail } from "@/app/api";
import {
  Bar,
  Button,
  Card,
  CardHeader,
  Chip,
  Dot,
  EmptyState,
  ErrorState,
  Icon,
  LoadingBlock,
  SeverityChip,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/kit";
import { cn } from "@/lib/cn";
import { absolute, dateTime, duration, humanise, num, score } from "@/lib/format";
import { SEVERITY_ORDER, severityFromCvss, severityTone } from "@/lib/severity";
import {
  asBool,
  asNumber,
  asNumbers,
  asObject,
  asObjects,
  asString,
  asStrings,
  portTone,
} from "./FindingEvidence";
import { NVD_BASE } from "./FindingDetail";

const SCAN_STATUS_DOT: Record<string, string> = {
  pending: "var(--ink-3)",
  running: "var(--accent)",
  completed: "var(--ok)",
  failed: "var(--crit)",
  cancelled: "var(--nil)",
};

/* ------------------------------------------------------------------ *
 * Layout helpers
 * ------------------------------------------------------------------ */

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="lbl">{label}</div>
      <div className="text-[12.5px] mt-0.5 break-words">{children}</div>
    </div>
  );
}

function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("mono text-[12px] break-all", className)}>{children}</span>;
}

function Dash() {
  return <span className="text-ink-3">—</span>;
}

function Panel({
  title,
  hint,
  actions,
  children,
}: {
  title: string;
  hint?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader title={title} hint={hint} actions={actions} />
      <div className="p-4">{children}</div>
    </Card>
  );
}

function ScoreText({ value }: { value: number }) {
  const tone = value >= 80 ? "text-ok" : value >= 50 ? "text-med" : "text-crit";
  return (
    <span className="inline-flex items-baseline gap-1">
      <span className={cn("fig text-[26px] leading-none", tone)}>{Math.round(value)}</span>
      <span className="text-[11.5px] text-ink-3">/100</span>
    </span>
  );
}

function Check({ ok, label, warn }: { ok: boolean; label: string; warn?: boolean }) {
  const tone = ok
    ? { text: "text-ok", wash: "bg-ok-wash" }
    : warn
      ? { text: "text-med", wash: "bg-med-wash" }
      : { text: "text-crit", wash: "bg-crit-wash" };
  return (
    <Chip tone={tone}>
      <Icon name={ok ? "check" : "close"} size={10} strokeWidth={2} />
      {label}
    </Chip>
  );
}

/* ------------------------------------------------------------------ *
 * Sections
 * ------------------------------------------------------------------ */

function ProtectionSection({ summary }: { summary: Record<string, unknown> }) {
  const proxy = asObject(summary.proxy_detection);
  const headers = asObject(summary.security_headers);
  if (!proxy && !headers) return null;

  const waf = asBool(proxy?.waf_detected);
  const cdn = asBool(proxy?.cdn_detected);
  const https = asBool(headers?.is_https);
  const hsts = asBool(headers?.hsts_enabled);
  const hstsMaxAge = asNumber(headers?.hsts_max_age);

  const rows: Array<{ icon: "shield" | "globe" | "key"; name: string; detail: ReactNode; chip: ReactNode }> = [
    {
      icon: "shield",
      name: "Web application firewall",
      detail: waf ? (asString(proxy?.waf_type) ?? "Detected") : "Not detected",
      chip: <Check ok={waf} label={waf ? "Protected" : "Unprotected"} warn />,
    },
    {
      icon: "globe",
      name: "Content delivery network",
      detail: cdn ? (asString(proxy?.cdn_provider) ?? "Detected") : "Direct origin",
      chip: <Check ok={cdn} label={cdn ? "Using CDN" : "Direct"} warn />,
    },
    {
      icon: "key",
      name: "HTTPS",
      detail: hsts
        ? `HSTS enabled${hstsMaxAge != null ? ` · max-age ${num(hstsMaxAge)}` : ""}`
        : https
          ? "HSTS not enabled"
          : "Not using HTTPS",
      chip: <Check ok={https} label={https ? "Encrypted" : "Unencrypted"} />,
    },
  ];

  const extra: string[] = [];
  if (asBool(proxy?.load_balancer_detected)) extra.push("Load balancer detected");
  if (asBool(proxy?.direct_ip_access)) extra.push("Direct IP access possible");
  if (asString(proxy?.proxy_type)) extra.push(`Proxy: ${asString(proxy?.proxy_type)}`);

  return (
    <Panel title="Protection status">
      <div className="space-y-1.5">
        {rows.map((row) => (
          <div
            key={row.name}
            className="flex items-center gap-3 px-3 py-2.5 rounded-md border border-rule bg-surface-2"
          >
            <Icon name={row.icon} size={15} className="text-ink-3" />
            <div className="flex-1 min-w-0">
              <div className="text-[12.5px] font-medium">{row.name}</div>
              <div className="text-[11.5px] text-ink-3">{row.detail}</div>
            </div>
            {row.chip}
          </div>
        ))}
      </div>
      {extra.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-2.5">
          {extra.map((item) => (
            <Chip key={item}>{item}</Chip>
          ))}
        </div>
      )}
    </Panel>
  );
}

function PortsSection({ summary }: { summary: Record<string, unknown> }) {
  const ports = asNumbers(summary.open_ports);
  const stack = asStrings(summary.technology_stack);
  if (ports.length === 0 && stack.length === 0) return null;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {ports.length > 0 && (
        <Panel title="Open ports" hint={`${ports.length} open`}>
          <div className="flex flex-wrap gap-1.5">
            {[...ports].sort((a, b) => a - b).map((port) => (
              <Chip key={port} tone={portTone(port)}>
                <span className="mono text-[11px]">{port}</span>
              </Chip>
            ))}
          </div>
          <div className="flex items-center gap-3 mt-3 text-[11px] text-ink-3">
            <span className="inline-flex items-center gap-1">
              <Dot color="var(--high)" /> sensitive
            </span>
            <span className="inline-flex items-center gap-1">
              <Dot color="var(--ok)" /> web
            </span>
          </div>
        </Panel>
      )}
      {stack.length > 0 && (
        <Panel title="Technology stack" hint={`${stack.length} detected`}>
          <div className="flex flex-wrap gap-1.5">
            {stack.map((tech) => (
              <Chip key={tech} tone={{ text: "text-accent-ink", wash: "bg-accent-wash" }}>
                <Icon name="plug" size={10} />
                {tech}
              </Chip>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function ServicesSection({ summary }: { summary: Record<string, unknown> }) {
  const services = asObjects(summary.services_detected);
  if (services.length === 0) return null;

  return (
    <Panel title="Services" hint={`${services.length} detected`}>
      <Table>
        <THead>
          <TR>
            <TH className="w-[70px]">Port</TH>
            <TH>Service</TH>
            <TH>Version</TH>
            <TH className="w-[70px]">Proto</TH>
            <TH className="w-[90px]">Encrypted</TH>
            <TH className="w-[120px]">Confidence</TH>
            <TH>CPE</TH>
            <TH className="w-[90px]">CVEs</TH>
          </TR>
        </THead>
        <TBody>
          {services.map((service, i) => {
            const port = asNumber(service.port);
            const confidence = asNumber(service.confidence) ?? 0;
            const vulns = asStrings(service.vulnerabilities);
            const encrypted = asBool(service.is_encrypted);
            return (
              <TR key={`${port}-${i}`}>
                <TD>
                  <Mono className="font-semibold">{port ?? "—"}</Mono>
                </TD>
                <TD>
                  <div className="text-[12.5px] font-medium">
                    {asString(service.service_name) ?? "unknown"}
                  </div>
                  {asString(service.product) && (
                    <div className="text-[11px] text-ink-3">{asString(service.product)}</div>
                  )}
                </TD>
                <TD>{asString(service.version) ? <Mono>{asString(service.version)}</Mono> : <Dash />}</TD>
                <TD className="uppercase text-[11.5px] text-ink-2">
                  {asString(service.protocol) ?? "—"}
                </TD>
                <TD>
                  <Check ok={encrypted} label={encrypted ? "Yes" : "No"} warn />
                </TD>
                <TD>
                  <div className="flex items-center gap-2">
                    <Bar value={confidence / 100} className="w-12" />
                    <span className="mono text-[11px] text-ink-3">{Math.round(confidence)}%</span>
                  </div>
                </TD>
                <TD>
                  {asString(service.cpe) ? (
                    <Mono className="text-[10.5px] text-ink-2">{asString(service.cpe)}</Mono>
                  ) : (
                    <Dash />
                  )}
                </TD>
                <TD>
                  {vulns.length > 0 ? (
                    <Chip tone={{ text: "text-crit", wash: "bg-crit-wash" }}>
                      <span className="mono text-[11px]">{vulns.length}</span> CVE
                    </Chip>
                  ) : (
                    <Dash />
                  )}
                </TD>
              </TR>
            );
          })}
        </TBody>
      </Table>
    </Panel>
  );
}

function VulnerabilitiesSection({ summary }: { summary: Record<string, unknown> }) {
  const vulns = asObjects(summary.vulnerabilities_found);
  if (vulns.length === 0) return null;

  return (
    <Panel title="Vulnerabilities" hint={`${vulns.length} known CVEs matched to detected versions`}>
      <div className="space-y-2.5">
        {vulns.map((vuln, i) => {
          const cve = asString(vuln.cve_id);
          const cvss = asNumber(vuln.cvss_score);
          const severity = asString(vuln.severity) ?? severityFromCvss(cvss) ?? "info";
          const tone = severityTone(severity);
          const references = asStrings(vuln.references);
          return (
            // Keyed by position as well as CVE: one scan can match the same CVE to
            // two detected services, so the id alone is not unique here.
            <div key={`${cve ?? "cve"}-${i}`} className="rounded-lg border border-rule p-3">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5 mb-1">
                    <SeverityChip severity={severity} />
                    {cve && (
                      <a
                        href={`${NVD_BASE}${encodeURIComponent(cve)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 mono text-[12px] font-semibold text-accent hover:underline"
                      >
                        {cve}
                        <Icon name="external" size={10} />
                      </a>
                    )}
                    {asBool(vuln.has_public_exploit) && (
                      <Chip tone={{ text: "text-crit", wash: "bg-crit-wash" }}>
                        <Icon name="alert" size={10} />
                        Public exploit
                      </Chip>
                    )}
                    {asBool(vuln.exploitable) && (
                      <Chip tone={{ text: "text-high", wash: "bg-high-wash" }}>Exploitable</Chip>
                    )}
                  </div>
                  <div className="text-[12.5px] font-medium">{asString(vuln.title) ?? "Untitled"}</div>
                </div>
                {cvss != null && (
                  <div className="text-right shrink-0">
                    <div className={cn("fig text-[22px] leading-none", tone.text)}>{score(cvss, 1)}</div>
                    <div className="lbl mt-1">CVSS</div>
                  </div>
                )}
              </div>
              {asString(vuln.description) && (
                <p className="text-[12px] text-ink-2 mt-2 leading-relaxed">{asString(vuln.description)}</p>
              )}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-[11.5px] text-ink-3">
                {(asString(vuln.affected_service) || asString(vuln.affected_version)) && (
                  <span>
                    Affected:{" "}
                    <Mono className="text-ink-2">
                      {[asString(vuln.affected_service), asString(vuln.affected_version)]
                        .filter(Boolean)
                        .join(" ")}
                    </Mono>
                  </span>
                )}
                {references.slice(0, 3).map((ref) => (
                  <a
                    key={ref}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-accent hover:underline"
                  >
                    Reference
                    <Icon name="external" size={9} />
                  </a>
                ))}
              </div>
              {asString(vuln.remediation) && (
                <div className="mt-2 rounded-md border border-rule bg-surface-2 p-2.5 text-[12px]">
                  <span className="lbl">Remediation</span>
                  <p className="mt-0.5">{asString(vuln.remediation)}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function HeadersSection({ summary }: { summary: Record<string, unknown> }) {
  // `summary.http` supersedes this: the deep scanner grades each header's value
  // rather than its presence, so showing both would say the same thing twice and
  // disagree about it. Kept for scans recorded before that scanner existed.
  if (asObject(summary.http)) return null;
  const headers = asObject(summary.security_headers);
  if (!headers) return null;

  const present = asStrings(headers.headers_present);
  const missing = asObjects(headers.headers_missing);
  const headerScore = asNumber(headers.score);
  const url = asString(headers.url);

  return (
    <Panel
      title="Security headers"
      hint={url ?? undefined}
      actions={headerScore != null ? <ScoreText value={headerScore} /> : undefined}
    >
      {headerScore != null && <Bar value={headerScore / 100} className="mb-4" height={5} />}
      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="lbl mb-2">Present ({present.length})</div>
          {present.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {present.map((header) => (
                <Chip key={header} tone={{ text: "text-ok", wash: "bg-ok-wash" }}>
                  <Icon name="check" size={10} strokeWidth={2} />
                  <span className="mono text-[11px]">{header}</span>
                </Chip>
              ))}
            </div>
          ) : (
            <p className="text-[12px] text-ink-3">No security headers present.</p>
          )}
          {(asString(headers.server_info) || asString(headers.x_frame_options)) && (
            <div className="mt-3 space-y-1.5">
              {asString(headers.server_info) && (
                <Field label="Server">
                  <Mono>{asString(headers.server_info)}</Mono>
                </Field>
              )}
              {asString(headers.x_frame_options) && (
                <Field label="X-Frame-Options">
                  <Mono>{asString(headers.x_frame_options)}</Mono>
                </Field>
              )}
            </div>
          )}
          {asBool(headers.csp_present) && asString(headers.csp_policy) && (
            <details className="group mt-3">
              <summary className="flex items-center gap-1.5 cursor-pointer text-[12px] text-ink-2 hover:text-ink list-none">
                <Icon name="chevronRight" size={11} className="transition-transform group-open:rotate-90" />
                Content-Security-Policy
              </summary>
              <pre className="mt-2 max-h-40 overflow-auto rounded-md border border-rule bg-surface-2 p-2.5 text-[11px] mono whitespace-pre-wrap break-all">
                {asString(headers.csp_policy)}
              </pre>
            </details>
          )}
        </div>
        <div>
          <div className="lbl mb-2">Missing ({missing.length})</div>
          {missing.length > 0 ? (
            <div className="space-y-2.5">
              {missing.map((header, i) => (
                <div key={`${asString(header.name) ?? "header"}-${i}`} className="border-l-2 border-crit pl-2.5">
                  <div className="flex items-center gap-2">
                    <Mono className="font-medium">{asString(header.name) ?? "—"}</Mono>
                    <SeverityChip severity={asString(header.severity)} short />
                  </div>
                  {asString(header.description) && (
                    <p className="text-[12px] text-ink-2 mt-0.5">{asString(header.description)}</p>
                  )}
                  {asString(header.recommendation) && (
                    <p className="text-[11.5px] text-accent-ink mt-0.5">
                      {asString(header.recommendation)}
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[12px] text-ok">All recommended security headers are present.</p>
          )}
        </div>
      </div>
    </Panel>
  );
}

function DnsSection({ summary }: { summary: Record<string, unknown> }) {
  // Superseded by `summary.dns`. Kept for scans recorded before the deep DNS
  // scanner existed.
  if (asObject(summary.dns)) return null;
  const dns = asObject(summary.dns_security);
  if (!dns) return null;

  const spfIssues = asStrings(dns.spf_issues);
  const dmarcIssues = asStrings(dns.dmarc_issues);
  const caa = asStrings(dns.caa_records);
  const nameservers = asStrings(dns.nameservers);
  const selectors = asStrings(dns.dkim_selectors_found);
  const issues = asObjects(dns.issues);
  const hasSpf = asBool(dns.has_spf);
  const hasDmarc = asBool(dns.has_dmarc);

  return (
    <Panel title="DNS security" hint={asString(dns.domain) ?? undefined}>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <div className="rounded-md border border-rule p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Check ok={hasSpf} label="SPF" />
          </div>
          {hasSpf ? (
            <Mono className="text-ink-2">{asString(dns.spf_record) ?? "Present"}</Mono>
          ) : (
            <p className="text-[12px] text-crit">No SPF record found.</p>
          )}
          {spfIssues.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {spfIssues.map((issue, i) => (
                <li key={i} className="text-[11.5px] text-med">
                  {issue}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Check ok={hasDmarc} label="DMARC" />
            {hasDmarc && asString(dns.dmarc_policy) && (
              <Chip
                tone={
                  asString(dns.dmarc_policy) === "reject"
                    ? { text: "text-ok", wash: "bg-ok-wash" }
                    : asString(dns.dmarc_policy) === "quarantine"
                      ? { text: "text-med", wash: "bg-med-wash" }
                      : { text: "text-high", wash: "bg-high-wash" }
                }
              >
                p={asString(dns.dmarc_policy)}
              </Chip>
            )}
          </div>
          {hasDmarc ? (
            <Mono className="text-ink-2">{asString(dns.dmarc_record) ?? "Present"}</Mono>
          ) : (
            <p className="text-[12px] text-crit">No DMARC record found.</p>
          )}
          {dmarcIssues.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {dmarcIssues.map((issue, i) => (
                <li key={i} className="text-[11.5px] text-med">
                  {issue}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="mb-1.5">
            <Check ok={asBool(dns.has_dkim)} label="DKIM" warn />
          </div>
          {asBool(dns.has_dkim) ? (
            <p className="text-[12px] text-ink-2">
              {selectors.length} selector{selectors.length === 1 ? "" : "s"} found
              {selectors.length > 0 && (
                <span className="text-ink-3"> · {selectors.slice(0, 4).join(", ")}</span>
              )}
            </p>
          ) : (
            <p className="text-[12px] text-ink-3">
              Not detectable without knowing the selector — absence here is not proof.
            </p>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="mb-1.5">
            <Check ok={asBool(dns.has_caa)} label="CAA" warn />
          </div>
          {caa.length > 0 ? (
            <ul className="space-y-0.5">
              {caa.map((record, i) => (
                <li key={i}>
                  <Mono className="text-ink-2">{record}</Mono>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-med">No CAA records — any CA may issue for this domain.</p>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="mb-1.5">
            <Check ok={asBool(dns.has_dnssec)} label="DNSSEC" warn />
          </div>
          {asBool(dns.has_dnssec) ? (
            <Check ok={asBool(dns.dnssec_valid)} label={asBool(dns.dnssec_valid) ? "Valid" : "Invalid"} />
          ) : (
            <p className="text-[12px] text-med">DNSSEC not enabled.</p>
          )}
          {asBool(dns.zone_transfer_possible) && (
            <p className="text-[12px] text-crit mt-1.5">Zone transfer (AXFR) is possible.</p>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="lbl mb-1.5">Nameservers</div>
          {nameservers.length > 0 ? (
            <ul className="space-y-0.5">
              {nameservers.map((ns, i) => (
                <li key={i}>
                  <Mono className="text-ink-2">{ns}</Mono>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-ink-3">No nameservers found.</p>
          )}
        </div>
      </div>

      {issues.length > 0 && (
        <div className="mt-4">
          <div className="lbl mb-2">Issues ({issues.length})</div>
          <div className="space-y-2">
            {issues.map((issue, i) => (
              <div key={i} className="border-l-2 border-med pl-2.5">
                <div className="flex items-center gap-2">
                  <SeverityChip severity={asString(issue.severity)} short />
                  <span className="text-[12.5px] font-medium">
                    {asString(issue.title) ?? humanise(asString(issue.issue_type))}
                  </span>
                </div>
                {asString(issue.description) && (
                  <p className="text-[12px] text-ink-2 mt-0.5">{asString(issue.description)}</p>
                )}
                {asString(issue.remediation) && (
                  <p className="text-[11.5px] text-accent-ink mt-0.5">{asString(issue.remediation)}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

function TlsSection({ summary }: { summary: Record<string, unknown> }) {
  // Superseded by `summary.tls`. Kept for scans recorded before the deep TLS
  // scanner existed — those have a certificate chain but no protocol or cipher
  // enumeration to show.
  if (asObject(summary.tls)) return null;
  const endpoints = asObjects(summary.tls_certificates);
  const tlsVersion = asString(summary.tls_version);
  if (endpoints.length === 0 && !tlsVersion) return null;

  return (
    <Panel
      title="TLS certificates"
      hint={tlsVersion ? `Negotiated ${tlsVersion}` : undefined}
    >
      {endpoints.length === 0 ? (
        <p className="text-[12px] text-ink-3">No certificate chain was captured for this scan.</p>
      ) : (
        <div className="space-y-4">
          {endpoints.map((endpoint, endpointIdx) => {
            const chain = asObjects(endpoint.certificate_chain);
            const host = asString(endpoint.host);
            const port = asNumber(endpoint.port);
            const err = asString(endpoint.error);
            return (
              <div key={`${host}-${port}-${endpointIdx}`} className="space-y-2">
                <div className="flex items-center gap-2">
                  <Icon name="certificate" size={13} className="text-ink-3" />
                  <Mono className="font-medium">
                    {host ?? "—"}
                    {port != null ? `:${port}` : ""}
                  </Mono>
                </div>
                {err && <p className="text-[12px] text-crit">{err}</p>}
                {chain.length === 0 && !err && (
                  <p className="text-[12px] text-ink-3">No certificate details collected.</p>
                )}
                {chain.map((cert, certIdx) => {
                  const san = asStrings(cert.san_domains);
                  const keyType = asString(cert.public_key_type);
                  const keyBits = asNumber(cert.public_key_bits);
                  return (
                    <div
                      // Serial numbers repeat across a chain more often than they should
                      // (self-signed and misissued certificates both do it).
                      key={`${asString(cert.serial_number) ?? "cert"}-${certIdx}`}
                      className="rounded-md border border-rule bg-surface-2 p-3"
                    >
                      <div className="flex items-center justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2">
                          <Chip
                            tone={
                              certIdx === 0 ? { text: "text-ok", wash: "bg-ok-wash" } : undefined
                            }
                          >
                            {certIdx === 0 ? "Leaf" : `Chain ${certIdx + 1}`}
                          </Chip>
                          {asString(cert.serial_number) && (
                            <Mono className="text-ink-3">{asString(cert.serial_number)}</Mono>
                          )}
                        </div>
                        {asString(cert.signature_algorithm) && (
                          <Chip>{asString(cert.signature_algorithm)}</Chip>
                        )}
                      </div>
                      <div className="grid gap-2.5 md:grid-cols-2">
                        <Field label="Subject">
                          <Mono>{asString(cert.subject) ?? "—"}</Mono>
                        </Field>
                        <Field label="Issuer">
                          <Mono>{asString(cert.issuer) ?? "Self-signed"}</Mono>
                        </Field>
                        <Field label="Valid from">
                          {asString(cert.not_before) ? dateTime(asString(cert.not_before)) : <Dash />}
                        </Field>
                        <Field label="Valid until">
                          {asString(cert.not_after) ? dateTime(asString(cert.not_after)) : <Dash />}
                        </Field>
                        <Field label="Common name">{asString(cert.common_name) ?? <Dash />}</Field>
                        <Field label="Organization">{asString(cert.organization) ?? <Dash />}</Field>
                        <Field label="Public key">
                          {keyType ? (
                            <span>
                              {keyType.toUpperCase()}
                              {keyBits != null ? ` · ${keyBits} bits` : ""}
                            </span>
                          ) : (
                            <Dash />
                          )}
                        </Field>
                        <Field label={`SAN domains (${san.length})`}>
                          {san.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {san.slice(0, 6).map((domain) => (
                                <Chip key={domain}>
                                  <span className="mono text-[11px]">{domain}</span>
                                </Chip>
                              ))}
                              {san.length > 6 && <Chip>+{san.length - 6} more</Chip>}
                            </div>
                          ) : (
                            <Dash />
                          )}
                        </Field>
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * Deep scanner sections
 *
 * `summary.tls`, `summary.dns` and `summary.http` are written by the deep
 * scanners in `services/scanners/`. Each renders only when its scanner ran, and
 * every field is read through a guard — `result_summary` is free-form JSON, and
 * a scan from before these scanners existed simply has none of it.
 * ------------------------------------------------------------------ */

/**
 * A letter grade, coloured the way its scale intends.
 *
 * Three different scales land here — SSL Labs (A+…F, plus T for a trust failure
 * and M for a name mismatch), Mozilla Observatory (A+…F), and the DNS hygiene
 * score — and they agree on what the letters mean, so one component serves all
 * three. `T` and `M` sit outside the A–F scale entirely and are shown as
 * failures, which is what they are.
 */
function Grade({ grade, size = "lg" }: { grade: string; size?: "sm" | "lg" }) {
  const letter = grade.charAt(0).toUpperCase();
  const tone =
    grade === "T" || grade === "M"
      ? { text: "text-crit", wash: "bg-crit-wash" }
      : letter === "A"
        ? { text: "text-ok", wash: "bg-ok-wash" }
        : letter === "B"
          ? { text: "text-ok", wash: "bg-ok-wash" }
          : letter === "C"
            ? { text: "text-med", wash: "bg-med-wash" }
            : letter === "D" || letter === "E"
              ? { text: "text-high", wash: "bg-high-wash" }
              : { text: "text-crit", wash: "bg-crit-wash" };
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-md font-semibold tabular-nums",
        tone.text,
        tone.wash,
        size === "lg" ? "text-[22px] leading-none px-3 py-2 min-w-[52px]" : "text-[13px] px-2 py-1",
      )}
      title={
        grade === "T"
          ? "Certificate is not trusted"
          : grade === "M"
            ? "Certificate does not match the hostname"
            : undefined
      }
    >
      {grade}
    </span>
  );
}

/** A labelled 0–100 bar, for the three component scores of an SSL Labs grade. */
function ScoreRow({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="lbl w-[104px] shrink-0">{label}</span>
      <Bar value={value / 100} className="flex-1" height={5} />
      <span className="mono text-[11px] text-ink-3 w-8 text-right">{value}</span>
    </div>
  );
}

function TlsDeepSection({ summary }: { summary: Record<string, unknown> }) {
  const tls = asObject(summary.tls);
  if (!tls) return null;

  const grade = asObject(tls.grade);
  const protocols = asObjects(tls.protocols);
  const ciphers = asObjects(tls.ciphers);
  const vulnerabilities = asObjects(tls.vulnerabilities);
  const features = asObject(tls.features) ?? {};
  const chain = asObject(tls.chain);
  const cert = asObject(tls.certificate);
  const errors = asStrings(tls.errors);
  const host = asString(tls.host);
  const port = asNumber(tls.port);
  const caps = asStrings(grade?.caps);
  const warnings = asStrings(grade?.warnings);
  const sslLabs = asString(tls.ssl_labs_url);
  const crtSh = asString(tls.crt_sh_url);

  return (
    <Panel
      title="TLS configuration"
      hint={host ? `${host}${port != null ? `:${port}` : ""}` : undefined}
      actions={grade ? <Grade grade={asString(grade.grade) ?? "?"} /> : undefined}
    >
      {asString(grade?.grade) === "?" && (
        <p className="text-[12px] text-ink-3 mb-4">
          Only the certificate could be assessed: the endpoint did not answer this scanner&rsquo;s
          handshake, so protocol versions, cipher suites and the grade were not measured.
        </p>
      )}
      {grade && asString(grade.grade) !== "?" && (
        <div className="grid gap-4 lg:grid-cols-2 mb-4">
          <div className="space-y-2">
            <ScoreRow label="Protocol" value={asNumber(grade.protocol_score) ?? 0} />
            <ScoreRow label="Key exchange" value={asNumber(grade.key_exchange_score) ?? 0} />
            <ScoreRow label="Cipher strength" value={asNumber(grade.cipher_score) ?? 0} />
            <div className="flex items-center gap-2.5 pt-1 border-t border-rule mt-2">
              <span className="lbl w-[104px] shrink-0">Overall</span>
              <Bar value={(asNumber(grade.score) ?? 0) / 100} className="flex-1" height={5} />
              <span className="mono text-[11px] text-ink-2 w-8 text-right">
                {asNumber(grade.score) ?? 0}
              </span>
            </div>
            <p className="text-[11px] text-ink-3 pt-1">
              Scored 30/30/40 across protocol, key exchange and cipher strength, per the SSL Labs
              Server Rating Guide.
            </p>
          </div>
          <div className="space-y-2">
            {caps.length > 0 && (
              <div>
                <div className="lbl mb-1">Grade capped by</div>
                <ul className="space-y-0.5">
                  {caps.map((cap, i) => (
                    <li key={i} className="text-[12px] text-crit flex items-start gap-1.5">
                      <Icon name="alert" size={11} className="mt-0.5 shrink-0" />
                      <span>{cap}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {warnings.length > 0 && (
              <div>
                <div className="lbl mb-1">Warnings</div>
                <ul className="space-y-0.5">
                  {warnings.map((warning, i) => (
                    <li key={i} className="text-[12px] text-med">
                      {warning}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {caps.length === 0 && warnings.length === 0 && (
              <p className="text-[12px] text-ok">
                No grade caps or warnings — the configuration is clean.
              </p>
            )}
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="lbl mb-2">Protocols</div>
          <div className="flex flex-wrap gap-1.5">
            {protocols.map((protocol, i) => {
              const supported = asBool(protocol.supported);
              const deprecated = asBool(protocol.deprecated);
              const count = asNumber(protocol.cipher_count);
              return (
                <Chip
                  key={i}
                  tone={
                    !supported
                      ? undefined
                      : deprecated
                        ? { text: "text-crit", wash: "bg-crit-wash" }
                        : { text: "text-ok", wash: "bg-ok-wash" }
                  }
                >
                  <Icon
                    name={supported ? (deprecated ? "alert" : "check") : "close"}
                    size={10}
                    strokeWidth={2}
                  />
                  <span className="mono text-[11px]">{asString(protocol.version)}</span>
                  {supported && count != null && count > 0 && (
                    <span className="text-ink-3 text-[10.5px]">· {count}</span>
                  )}
                </Chip>
              );
            })}
          </div>
        </div>

        <div>
          <div className="lbl mb-2">Protocol features</div>
          <div className="flex flex-wrap gap-1.5">
            <Check ok={asBool(features.forward_secrecy_only)} label="Forward secrecy" warn />
            <Check ok={asBool(features.aead_only)} label="AEAD only" warn />
            <Check ok={asBool(features.http2)} label="HTTP/2" warn />
            <Check ok={asBool(features.secure_renegotiation)} label="Secure renegotiation" />
            <Check ok={asBool(features.session_tickets)} label="Session tickets" warn />
            <Check ok={asBool(features.extended_master_secret)} label="Ext. master secret" warn />
            {features.ocsp_stapling === null || features.ocsp_stapling === undefined ? (
              <Chip>
                <Icon name="minus" size={10} />
                OCSP stapling not determined
              </Chip>
            ) : (
              <Check ok={asBool(features.ocsp_stapling)} label="OCSP stapling" warn />
            )}
            {asBool(features.compression) && (
              <Chip tone={{ text: "text-crit", wash: "bg-crit-wash" }}>
                <Icon name="alert" size={10} />
                TLS compression on
              </Chip>
            )}
            {asBool(features.server_cipher_preference) && (
              <Chip tone={{ text: "text-ok", wash: "bg-ok-wash" }}>
                <Icon name="check" size={10} strokeWidth={2} />
                Server cipher order
              </Chip>
            )}
          </div>
          {asStrings(features.named_curves).length > 0 && (
            <div className="mt-2">
              <Field label="Key exchange groups">
                <Mono>{asStrings(features.named_curves).join(", ")}</Mono>
              </Field>
            </div>
          )}
        </div>
      </div>

      {vulnerabilities.length > 0 && (
        <div className="mt-4">
          <div className="lbl mb-2">Vulnerabilities ({vulnerabilities.length})</div>
          <div className="space-y-2">
            {vulnerabilities.map((vulnerability, i) => {
              const confirmed = asString(vulnerability.confidence) === "confirmed";
              return (
                <div
                  key={i}
                  className={cn(
                    "border-l-2 pl-2.5 py-0.5",
                    confirmed ? "border-crit" : "border-med",
                  )}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityChip severity={asString(vulnerability.severity)} short />
                    <span className="text-[12.5px] font-medium">
                      {asString(vulnerability.name)}
                    </span>
                    {asString(vulnerability.cve) && (
                      <a
                        href={`${NVD_BASE}${asString(vulnerability.cve)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="mono text-[11px] text-accent-ink hover:underline"
                      >
                        {asString(vulnerability.cve)}
                      </a>
                    )}
                    <Chip
                      tone={
                        confirmed
                          ? { text: "text-crit", wash: "bg-crit-wash" }
                          : { text: "text-med", wash: "bg-med-wash" }
                      }
                    >
                      {confirmed ? "confirmed" : "potential"}
                    </Chip>
                  </div>
                  <p className="text-[12px] text-ink-2 mt-0.5">
                    {asString(vulnerability.description)}
                  </p>
                  {asString(vulnerability.evidence) && (
                    <p className="text-[11.5px] text-ink-3 mt-0.5">
                      Evidence: <Mono>{asString(vulnerability.evidence)}</Mono>
                    </p>
                  )}
                </div>
              );
            })}
          </div>
          <p className="text-[11px] text-ink-3 mt-2">
            “Potential” means the configuration is a precondition for the attack; confirming it
            needs an active oracle or timing test this scan deliberately does not run.
          </p>
        </div>
      )}

      {ciphers.length > 0 && (
        <details className="group mt-4">
          <summary className="flex items-center gap-1.5 cursor-pointer text-[12px] text-ink-2 hover:text-ink list-none">
            <Icon name="chevronRight" size={11} className="transition-transform group-open:rotate-90" />
            Cipher suites ({ciphers.length})
          </summary>
          <div className="mt-2 -mx-4 overflow-x-auto">
            <Table>
              <THead>
                <TR>
                  <TH>Suite</TH>
                  <TH className="w-[86px]">Protocol</TH>
                  <TH className="w-[110px]">Key exchange</TH>
                  <TH className="w-[70px]">Bits</TH>
                  <TH className="w-[92px]">Strength</TH>
                </TR>
              </THead>
              <TBody>
                {ciphers.map((cipher, i) => {
                  const strength = asString(cipher.strength) ?? "unknown";
                  const tone =
                    strength === "insecure"
                      ? { text: "text-crit", wash: "bg-crit-wash" }
                      : strength === "weak"
                        ? { text: "text-high", wash: "bg-high-wash" }
                        : strength === "strong"
                          ? { text: "text-ok", wash: "bg-ok-wash" }
                          : undefined;
                  return (
                    <TR key={i}>
                      <TD>
                        <Mono>{asString(cipher.name)}</Mono>
                        {!asBool(cipher.forward_secrecy) && (
                          <span className="text-[10.5px] text-med ml-1.5">no PFS</span>
                        )}
                      </TD>
                      <TD className="text-[12px]">{asString(cipher.protocol)}</TD>
                      <TD className="text-[12px]">
                        {asString(cipher.key_exchange)}
                        {asNumber(cipher.dh_bits) != null && (
                          <span className="text-ink-3"> · {asNumber(cipher.dh_bits)}b</span>
                        )}
                      </TD>
                      <TD className="mono text-[12px]">{asNumber(cipher.bits) ?? "—"}</TD>
                      <TD>
                        <Chip tone={tone}>{strength}</Chip>
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          </div>
        </details>
      )}

      {(chain || cert) && (
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md border border-rule p-3">
            <div className="lbl mb-1.5">Chain trust</div>
            <Check
              ok={asString(chain?.trust) === "trusted"}
              label={humanise(asString(chain?.trust) ?? "unknown")}
            />
            {asString(chain?.trust_detail) && (
              <p className="text-[11.5px] text-ink-3 mt-1">{asString(chain?.trust_detail)}</p>
            )}
          </div>
          <div className="rounded-md border border-rule p-3">
            <div className="lbl mb-1.5">Hostname</div>
            <Check ok={asBool(chain?.hostname_matches)} label="Matches certificate" />
          </div>
          <div className="rounded-md border border-rule p-3">
            <div className="lbl mb-1.5">Chain</div>
            <Check
              ok={!asBool(chain?.chain_incomplete)}
              label={asBool(chain?.chain_incomplete) ? "Incomplete" : "Complete"}
            />
          </div>
          <div className="rounded-md border border-rule p-3">
            <div className="lbl mb-1.5">Transparency</div>
            <Check
              ok={(asNumber(cert?.sct_count) ?? 0) > 0}
              label={`${asNumber(cert?.sct_count) ?? 0} SCT${(asNumber(cert?.sct_count) ?? 0) === 1 ? "" : "s"}`}
              warn
            />
            {asBool(cert?.must_staple) && (
              <p className="text-[11.5px] text-ink-3 mt-1">OCSP Must-Staple set</p>
            )}
          </div>
        </div>
      )}

      {(sslLabs || crtSh) && (
        <div className="flex items-center gap-3 mt-3 text-[11.5px]">
          {sslLabs && (
            <a href={sslLabs} target="_blank" rel="noreferrer" className="text-accent-ink hover:underline inline-flex items-center gap-1">
              <Icon name="external" size={11} />
              Second opinion on SSL Labs
            </a>
          )}
          {crtSh && (
            <a href={crtSh} target="_blank" rel="noreferrer" className="text-accent-ink hover:underline inline-flex items-center gap-1">
              <Icon name="external" size={11} />
              Certificates on crt.sh
            </a>
          )}
        </div>
      )}

      {errors.length > 0 && (
        <ul className="mt-3 space-y-1">
          {errors.map((message, i) => (
            <li key={i} className="text-[11.5px] text-ink-3 flex items-start gap-1.5">
              <Icon name="alert" size={11} className="mt-0.5 shrink-0" />
              <span>{message}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function DnsDeepSection({ summary }: { summary: Record<string, unknown> }) {
  const dns = asObject(summary.dns);
  if (!dns) return null;

  const email = asObject(dns.email) ?? {};
  const spf = asObject(email.spf) ?? {};
  const dmarc = asObject(email.dmarc) ?? {};
  const mtaSts = asObject(email.mta_sts) ?? {};
  const tlsRpt = asObject(email.tls_rpt) ?? {};
  const bimi = asObject(email.bimi) ?? {};
  const dnssec = asObject(dns.dnssec) ?? {};
  const nameservers = asObject(dns.nameservers) ?? {};
  const nsList = asObjects(nameservers.nameservers);
  const records = asObject(dns.records) ?? {};
  const caa = asObjects(records.caa);
  const takeover = asObject(dns.takeover) ?? {};
  const wildcard = asObject(dns.wildcard) ?? {};
  const soa = asObject(records.soa);
  const internal = asStrings(dns.internal_addresses);
  const hasMx = asBool(email.has_mx);

  // A name that serves no SOA of its own is not a zone: its delegation, DNSSEC,
  // CAA and email policy all live on the parent. The cards below still show what
  // this exact name publishes, which is nothing — so without this the panel reads
  // as a wall of failures next to a clean grade and no findings.
  const isZoneApex = asBool(dns.is_zone_apex);

  return (
    <Panel
      title="DNS & email authentication"
      hint={asString(dns.domain) ?? undefined}
      actions={<Grade grade={asString(dns.grade) ?? "?"} />}
    >
      {!isZoneApex && (
        <p className="text-[12px] text-ink-2 mb-4 rounded-md border border-rule bg-surface-2 p-2.5">
          This name is not a zone apex — it publishes no SOA of its own. Email
          authentication, DNSSEC, CAA and the delegation are properties of the parent zone and
          are shown here for reference only; they are assessed on the apex domain, not here.
        </p>
      )}
      {asBool(dns.zone_transfer_possible) && (
        <div className="mb-4 rounded-md border border-crit bg-crit-wash p-3">
          <div className="flex items-center gap-2">
            <Icon name="alert" size={13} className="text-crit" />
            <span className="text-[12.5px] font-medium text-crit">
              Zone transfer (AXFR) succeeded
            </span>
          </div>
          <p className="text-[12px] text-ink-2 mt-1">
            A nameserver handed the complete zone to an unauthenticated client. Every hostname in
            it — internal services, staging, the address layout — is public.
          </p>
        </div>
      )}

      {asBool(takeover.dangling) && (
        <div className="mb-4 rounded-md border border-high bg-high-wash p-3">
          <div className="flex items-center gap-2">
            <Icon name="alert" size={13} className="text-high" />
            <span className="text-[12.5px] font-medium text-high">
              Dangling record — {asString(takeover.service) ?? "third-party service"}
            </span>
          </div>
          <p className="text-[12px] text-ink-2 mt-1">{asString(takeover.evidence)}</p>
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <div className="rounded-md border border-rule p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Check
              ok={asBool(spf.present) && asBool(spf.valid)}
              label="SPF"
              warn={!hasMx || !isZoneApex}
            />
            {asString(spf.all_qualifier) && (
              <Chip
                tone={
                  asString(spf.all_qualifier) === "fail"
                    ? { text: "text-ok", wash: "bg-ok-wash" }
                    : asString(spf.all_qualifier) === "pass"
                      ? { text: "text-crit", wash: "bg-crit-wash" }
                      : { text: "text-med", wash: "bg-med-wash" }
                }
              >
                {humanise(asString(spf.all_qualifier))}
              </Chip>
            )}
          </div>
          {asString(spf.record) ? (
            <Mono className="text-ink-2">{asString(spf.record)}</Mono>
          ) : (
            <p className="text-[12px] text-crit">No SPF record.</p>
          )}
          {asBool(spf.present) && asNumber(spf.dns_lookups) != null && (
            <p
              className={cn(
                "text-[11.5px] mt-1",
                asBool(spf.exceeds_lookup_limit) ? "text-crit" : "text-ink-3",
              )}
            >
              {asNumber(spf.dns_lookups)} of 10 DNS lookups used
              {asBool(spf.exceeds_lookup_limit) && " — over the RFC 7208 limit, so receivers discard the policy"}
            </p>
          )}
          {asStrings(spf.issues).map((issue, i) => (
            <p key={i} className="text-[11.5px] text-med mt-1">
              {issue}
            </p>
          ))}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Check
              ok={asBool(dmarc.enforced)}
              label="DMARC"
              warn={asBool(dmarc.present) || !isZoneApex}
            />
            {asString(dmarc.policy) && (
              <Chip
                tone={
                  asString(dmarc.policy) === "reject"
                    ? { text: "text-ok", wash: "bg-ok-wash" }
                    : asString(dmarc.policy) === "quarantine"
                      ? { text: "text-med", wash: "bg-med-wash" }
                      : { text: "text-high", wash: "bg-high-wash" }
                }
              >
                p={asString(dmarc.policy)}
                {asNumber(dmarc.percentage) != null && asNumber(dmarc.percentage) !== 100
                  ? ` · ${asNumber(dmarc.percentage)}%`
                  : ""}
              </Chip>
            )}
          </div>
          {asString(dmarc.record) ? (
            <Mono className="text-ink-2">{asString(dmarc.record)}</Mono>
          ) : (
            <p className="text-[12px] text-crit">No DMARC record.</p>
          )}
          {asStrings(dmarc.issues).map((issue, i) => (
            <p key={i} className="text-[11.5px] text-med mt-1">
              {issue}
            </p>
          ))}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="mb-1.5">
            <Check
              ok={asStrings(email.dkim_selectors_found).length > 0}
              label="DKIM"
              warn
            />
          </div>
          {asStrings(email.dkim_selectors_found).length > 0 ? (
            <p className="text-[12px] text-ink-2">
              Selectors found:{" "}
              <Mono>{asStrings(email.dkim_selectors_found).join(", ")}</Mono>
            </p>
          ) : (
            <p className="text-[12px] text-ink-3">
              None of the {asNumber(email.dkim_probed) ?? 0} common selectors answered. Selectors
              cannot be enumerated from DNS, so this is not proof DKIM is absent.
            </p>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="mb-1.5">
            <Check ok={asBool(dnssec.zone_signed) && asBool(dnssec.delegation_signed)} label="DNSSEC" warn />
          </div>
          {!asBool(dnssec.checked) ? (
            <p className="text-[12px] text-ink-3">Not determined — the DNSKEY query did not answer.</p>
          ) : asBool(dnssec.island_of_security) ? (
            <p className="text-[12px] text-crit">
              Zone is signed ({asNumber(dnssec.dnskey_count) ?? 0} DNSKEY) but the parent has no DS
              record, so nothing validates it.
            </p>
          ) : asBool(dnssec.zone_signed) ? (
            <p className="text-[12px] text-ok">
              Signed and anchored · {asNumber(dnssec.dnskey_count) ?? 0} DNSKEY,{" "}
              {asNumber(dnssec.ds_count) ?? 0} DS
            </p>
          ) : (
            <p className="text-[12px] text-med">Zone is not signed.</p>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="mb-1.5">
            <Check ok={caa.length > 0} label="CAA" warn />
          </div>
          {caa.length > 0 ? (
            <ul className="space-y-0.5">
              {caa.map((record, i) => (
                <li key={i}>
                  <Mono className="text-ink-2">
                    {asString(record.tag)} {asString(record.value)}
                  </Mono>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-med">Any CA may issue for this domain.</p>
          )}
        </div>

        <div className="rounded-md border border-rule p-3">
          <div className="lbl mb-1.5">Mail transport security</div>
          <div className="flex flex-wrap gap-1.5">
            <Check
              ok={asString(mtaSts.mode) === "enforce"}
              label={`MTA-STS${asString(mtaSts.mode) ? ` (${asString(mtaSts.mode)})` : ""}`}
              warn
            />
            <Check ok={asBool(tlsRpt.present)} label="TLS-RPT" warn />
            <Check ok={asStrings(email.dane_hosts).length > 0} label="DANE" warn />
            <Check ok={asBool(bimi.present)} label="BIMI" warn />
          </div>
          {!hasMx && (
            <p className="text-[11.5px] text-ink-3 mt-1.5">
              No MX records — this domain does not receive mail.
            </p>
          )}
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <div className="lbl mb-2">
            Nameservers ({asNumber(nameservers.count) ?? nsList.length})
          </div>
          {nsList.length > 0 ? (
            <div className="space-y-1.5">
              {nsList.map((ns, i) => (
                <div key={i} className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <Mono className="text-ink-2">{asString(ns.hostname)}</Mono>
                    <div className="text-[11px] text-ink-3">
                      {asStrings(ns.addresses).join(", ") || "does not resolve"}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {!asBool(ns.answers_for_zone) && (
                      <Chip tone={{ text: "text-med", wash: "bg-med-wash" }}>lame</Chip>
                    )}
                    <Chip
                      tone={
                        asString(ns.zone_transfer) === "transferred"
                          ? { text: "text-crit", wash: "bg-crit-wash" }
                          : asString(ns.zone_transfer) === "refused"
                            ? { text: "text-ok", wash: "bg-ok-wash" }
                            : undefined
                      }
                    >
                      AXFR {asString(ns.zone_transfer)}
                    </Chip>
                  </div>
                </div>
              ))}
              <p className="text-[11px] text-ink-3 pt-1">
                {asNumber(nameservers.distinct_networks) ?? 0} distinct network
                {(asNumber(nameservers.distinct_networks) ?? 0) === 1 ? "" : "s"} ·{" "}
                {asNumber(nameservers.distinct_providers) ?? 0} provider
                {(asNumber(nameservers.distinct_providers) ?? 0) === 1 ? "" : "s"}
              </p>
            </div>
          ) : (
            <p className="text-[12px] text-ink-3">No nameservers found.</p>
          )}
        </div>

        <div className="space-y-2">
          {soa && (
            <div>
              <div className="lbl mb-1">SOA</div>
              <Mono className="text-ink-2">
                {asString(soa.primary_ns)} · serial {asNumber(soa.serial)}
              </Mono>
              <div className="text-[11px] text-ink-3">
                refresh {asNumber(soa.refresh)}s · retry {asNumber(soa.retry)}s · expire{" "}
                {asNumber(soa.expire)}s · min {asNumber(soa.minimum)}s
              </div>
              {asStrings(soa.issues).map((issue, i) => (
                <p key={i} className="text-[11.5px] text-med mt-0.5">
                  {issue}
                </p>
              ))}
            </div>
          )}
          {asBool(wildcard.enabled) && (
            <p className="text-[12px] text-med">
              Wildcard DNS is on — every name under this domain resolves, to{" "}
              <Mono>{asStrings(wildcard.resolved_to).join(", ")}</Mono>.
            </p>
          )}
          {internal.length > 0 && (
            <p className="text-[12px] text-med">
              Private addresses in public DNS: <Mono>{internal.join(", ")}</Mono>
            </p>
          )}
          {asObjects(nameservers.issues).map((issue, i) => (
            <p
              key={i}
              className={cn(
                "text-[11.5px]",
                asString(issue.severity) === "high"
                  ? "text-crit"
                  : asString(issue.severity) === "medium"
                    ? "text-high"
                    : asString(issue.severity) === "info"
                      ? "text-ink-3"
                      : "text-med",
              )}
            >
              {asString(issue.message)}
            </p>
          ))}
        </div>
      </div>
    </Panel>
  );
}

function HttpDeepSection({ summary }: { summary: Record<string, unknown> }) {
  const http = asObject(summary.http);
  if (!http) return null;

  const observatory = asObject(http.observatory);
  const checks = asObjects(observatory?.checks);
  const csp = asObject(http.csp) ?? {};
  const hsts = asObject(http.hsts) ?? {};
  const cookies = asObjects(http.cookies);
  const cors = asObject(http.cors) ?? {};
  const methods = asObject(http.methods) ?? {};
  const exposed = asObjects(http.exposed_paths);
  const redirects = asObjects(http.redirect_chain);
  const mixed = asStrings(http.mixed_content);
  const errors = asStrings(http.errors);

  return (
    <Panel
      title="HTTP configuration"
      hint={asString(http.final_url) ?? undefined}
      actions={
        observatory ? <Grade grade={asString(observatory.grade) ?? "?"} /> : undefined
      }
    >
      {observatory && (
        <div className="mb-4">
          <div className="flex items-center gap-2.5">
            <Bar
              value={Math.min(asNumber(observatory.score) ?? 0, 100) / 100}
              className="flex-1"
              height={5}
            />
            <span className="mono text-[11px] text-ink-2 w-10 text-right">
              {asNumber(observatory.score) ?? 0}
            </span>
          </div>
          <p className="text-[11px] text-ink-3 mt-1">
            Scored with the Mozilla HTTP Observatory modifiers: 100 baseline, deductions and
            bonuses per check.
          </p>
        </div>
      )}

      {exposed.length > 0 && (
        <div className="mb-4 rounded-md border border-crit bg-crit-wash p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Icon name="alert" size={13} className="text-crit" />
            <span className="text-[12.5px] font-medium text-crit">
              Exposed files and endpoints ({exposed.length})
            </span>
          </div>
          <ul className="space-y-1">
            {exposed.map((item, i) => (
              <li key={i} className="text-[12px]">
                <Mono className="text-ink">{asString(item.path)}</Mono>
                <span className="text-ink-2"> — {asString(item.label)}</span>
                <span className="text-ink-3">
                  {" "}
                  (matched <Mono>{asString(item.matched_signature)}</Mono>)
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="lbl mb-2">Checks</div>
          <div className="space-y-1">
            {checks.map((check, i) => {
              const modifier = asNumber(check.score_modifier) ?? 0;
              return (
                <div key={i} className="flex items-start gap-2">
                  <Icon
                    name={asBool(check.passed) ? "check" : "close"}
                    size={11}
                    strokeWidth={2}
                    className={cn("mt-0.5 shrink-0", asBool(check.passed) ? "text-ok" : "text-crit")}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="text-[12px] text-ink-2">{asString(check.description)}</div>
                    <div className="mono text-[10.5px] text-ink-3">{asString(check.name)}</div>
                  </div>
                  <span
                    className={cn(
                      "mono text-[11px] shrink-0 tabular-nums",
                      modifier > 0 ? "text-ok" : modifier < 0 ? "text-crit" : "text-ink-3",
                    )}
                  >
                    {modifier > 0 ? `+${modifier}` : modifier}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="space-y-3">
          <div className="rounded-md border border-rule p-3">
            <div className="lbl mb-1.5">Content-Security-Policy</div>
            {asBool(csp.present) ? (
              <>
                <Check
                  ok={asStrings(csp.issues).length === 0}
                  label={asBool(csp.report_only) ? "Report-only" : "Enforced"}
                  warn={asBool(csp.report_only)}
                />
                {asStrings(csp.issues).map((issue, i) => (
                  <p key={i} className="text-[11.5px] text-med mt-1">
                    {issue}
                  </p>
                ))}
              </>
            ) : (
              <p className="text-[12px] text-crit">No CSP header.</p>
            )}
          </div>

          <div className="rounded-md border border-rule p-3">
            <div className="flex items-center gap-2 mb-1.5">
              <Check ok={asBool(hsts.present) && asBool(hsts.valid)} label="HSTS" />
              {asBool(hsts.include_subdomains) && <Chip>includeSubDomains</Chip>}
              {asBool(hsts.preload) && (
                <Chip tone={{ text: "text-ok", wash: "bg-ok-wash" }}>preload</Chip>
              )}
            </div>
            {asNumber(hsts.max_age) != null && (
              <p className="text-[12px] text-ink-2">
                max-age {num(asNumber(hsts.max_age) ?? 0)}s (
                {Math.round((asNumber(hsts.max_age) ?? 0) / 86400)} days)
              </p>
            )}
            {asStrings(hsts.issues).map((issue, i) => (
              <p key={i} className="text-[11.5px] text-med mt-1">
                {issue}
              </p>
            ))}
          </div>

          {asStrings(cors.issues).length > 0 && (
            <div className="rounded-md border border-high p-3">
              <div className="lbl mb-1.5">CORS</div>
              {asStrings(cors.issues).map((issue, i) => (
                <p key={i} className="text-[12px] text-high">
                  {issue}
                </p>
              ))}
            </div>
          )}

          <div className="rounded-md border border-rule p-3">
            <div className="lbl mb-1.5">Transport</div>
            <div className="flex flex-wrap gap-1.5">
              <Check ok={asBool(http.is_https)} label="HTTPS" />
              <Check ok={asBool(http.supports_http2)} label="HTTP/2" warn />
              <Check ok={asBool(http.supports_http3)} label="HTTP/3" warn />
              {http.security_txt === null || http.security_txt === undefined ? (
                <Chip>
                  <Icon name="minus" size={10} />
                  security.txt not probed
                </Chip>
              ) : (
                <Check ok={asBool(http.security_txt)} label="security.txt" warn />
              )}
              {asBool(methods.trace_enabled) && (
                <Chip tone={{ text: "text-crit", wash: "bg-crit-wash" }}>
                  <Icon name="alert" size={10} />
                  TRACE enabled
                </Chip>
              )}
            </div>
            {asStrings(methods.advertised).length > 0 && (
              <p className="text-[11.5px] text-ink-3 mt-1.5">
                Methods advertised: <Mono>{asStrings(methods.advertised).join(", ")}</Mono>
              </p>
            )}
          </div>
        </div>
      </div>

      {cookies.length > 0 && (
        <div className="mt-4">
          <div className="lbl mb-2">Cookies ({cookies.length})</div>
          <div className="space-y-1.5">
            {cookies.map((cookie, i) => (
              <div key={i} className="flex items-start gap-2 flex-wrap">
                <Mono className="font-medium">{asString(cookie.name)}</Mono>
                <Check ok={asBool(cookie.secure)} label="Secure" />
                <Check ok={asBool(cookie.http_only)} label="HttpOnly" warn={!asBool(cookie.session_like)} />
                <Chip
                  tone={
                    asString(cookie.same_site)
                      ? { text: "text-ok", wash: "bg-ok-wash" }
                      : { text: "text-med", wash: "bg-med-wash" }
                  }
                >
                  SameSite={asString(cookie.same_site) ?? "unset"}
                </Chip>
                {asStrings(cookie.issues).length > 0 && (
                  <span className="text-[11.5px] text-med basis-full">
                    {asStrings(cookie.issues).join(" ")}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {(redirects.length > 0 || mixed.length > 0) && (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {redirects.length > 0 && (
            <div>
              <div className="lbl mb-2">HTTP redirect chain</div>
              <ol className="space-y-1">
                {redirects.map((hop, i) => (
                  <li key={i} className="text-[12px] flex items-start gap-2">
                    <Chip>{asNumber(hop.status)}</Chip>
                    <div className="min-w-0">
                      <Mono className="text-ink-2">{asString(hop.url)}</Mono>
                      {asString(hop.location) && (
                        <div className="text-[11px] text-ink-3">→ {asString(hop.location)}</div>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {mixed.length > 0 && (
            <div>
              <div className="lbl mb-2">
                Mixed content ({asNumber(http.mixed_content_total) ?? mixed.length})
              </div>
              <ul className="space-y-0.5">
                {mixed.map((resource, i) => (
                  <li key={i}>
                    <Mono className="text-med">{resource}</Mono>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {errors.length > 0 && (
        <ul className="mt-3 space-y-1">
          {errors.map((message, i) => (
            <li key={i} className="text-[11.5px] text-ink-3 flex items-start gap-1.5">
              <Icon name="alert" size={11} className="mt-0.5 shrink-0" />
              <span>{message}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function RiskFactorsSection({ summary }: { summary: Record<string, unknown> }) {
  const factors = asObjects(summary.risk_factors);
  if (factors.length === 0) return null;

  return (
    <Panel title="Risk factors" hint={`${factors.length} contributing`}>
      <div className="space-y-1.5">
        {factors.map((factor, i) => {
          const impact = asNumber(factor.impact_score) ?? 0;
          return (
            <div
              key={i}
              className="flex items-start gap-3 px-3 py-2 rounded-md border border-rule bg-surface-2"
            >
              <SeverityChip severity={asString(factor.severity)} short className="mt-px" />
              <div className="flex-1 min-w-0">
                <div className="text-[12.5px] font-medium">
                  {asString(factor.name) ?? humanise(asString(factor.factor_type))}
                </div>
                {asString(factor.description) && (
                  <div className="text-[11.5px] text-ink-3">{asString(factor.description)}</div>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Bar value={impact} className="w-14" />
                <span className="mono text-[11px] text-ink-3 w-9 text-right">
                  {Math.round(impact * 100)}%
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function ErrorsSection({ summary }: { summary: Record<string, unknown> }) {
  const errors = asStrings(summary.errors);
  if (errors.length === 0) return null;
  return (
    <Panel title="Scan errors" hint={`${errors.length}`}>
      <ul className="space-y-1">
        {errors.map((message, i) => (
          <li key={i} className="flex items-start gap-2 text-[12px] text-ink-2">
            <Icon name="alert" size={12} className="text-crit mt-0.5 shrink-0" />
            <span className="break-words">{message}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ------------------------------------------------------------------ *
 * The view
 * ------------------------------------------------------------------ */

export function ScanDetail({
  scanId,
  onClear,
}: {
  scanId: string;
  /** Clears `?scan=` and returns the screen to the full findings list. */
  onClear?: () => void;
}) {
  const [detail, setDetail] = useState<SecurityScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const hasLoadedRef = useRef(false);
  const statusRef = useRef<string | null>(null);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const data = await getSecurityScan(scanId);
        setDetail(data);
        statusRef.current = data.scan.status;
        setError(null);
        hasLoadedRef.current = true;
      } catch (err) {
        if (!hasLoadedRef.current) setError((err as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [scanId],
  );

  useEffect(() => {
    hasLoadedRef.current = false;
    load(false);
  }, [load]);

  // Live only while the scan is still moving; a finished scan never changes.
  useEffect(() => {
    const timer = setInterval(() => {
      if (statusRef.current === "running" || statusRef.current === "pending") load(true);
    }, 5000);
    return () => clearInterval(timer);
  }, [load]);

  if (loading && !detail) return <LoadingBlock label="Loading scan" />;

  if (error && !detail) {
    return <ErrorState error={error} onRetry={() => load(false)} />;
  }

  if (!detail) return null;

  const { scan, asset, findings } = detail;
  const summary = (scan.result_summary ?? {}) as Record<string, unknown>;
  const durationMs = asNumber(summary.scan_duration_ms);
  const counts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: findings.filter((f) => (f.severity || "info") === severity).length,
  })).filter((entry) => entry.count > 0);
  const summaryEmpty = Object.keys(summary).length === 0;
  const running = scan.status === "running" || scan.status === "pending";

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4 px-4 py-3.5 border-b border-rule">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-flex items-center gap-1.5 text-[12px] font-medium">
                <Dot color={SCAN_STATUS_DOT[scan.status] ?? "var(--ink-3)"} />
                {humanise(scan.status)}
              </span>
              <span className="w-px h-3 bg-rule-2" aria-hidden="true" />
              <span className="text-[12px] text-ink-2">{humanise(scan.scan_type)}</span>
              <span className="mono text-[11px] text-ink-3">{scan.id.slice(0, 8)}</span>
            </div>
            <h2 className="text-[17px] font-semibold tracking-[-0.02em] leading-tight break-all">
              <Link href={`/surface/${asset.id}`} className="hover:text-accent">
                {asset.value}
              </Link>
            </h2>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {onClear && (
              <Button size="sm" icon="close" onClick={onClear}>
                Clear scan filter
              </Button>
            )}
          </div>
        </div>

        <div className="flex flex-wrap divide-x divide-rule">
          <div className="px-[18px] py-3">
            <div className="lbl">Findings</div>
            <div className="fig text-[24px] mt-0.5 leading-none">{num(detail.findings_count)}</div>
            {counts.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1.5">
                {counts.map(({ severity, count }) => (
                  <SeverityChip key={severity} severity={severity} short count={count} />
                ))}
              </div>
            )}
          </div>
          <div className="px-[18px] py-3">
            <div className="lbl">Open ports</div>
            <div className="fig text-[24px] mt-0.5 leading-none">
              {num(asNumbers(summary.open_ports).length)}
            </div>
          </div>
          <div className="px-[18px] py-3">
            <div className="lbl">Duration</div>
            <div className="fig text-[24px] mt-0.5 leading-none">
              {durationMs != null
                ? durationMs < 1000
                  ? `${durationMs}ms`
                  : `${(durationMs / 1000).toFixed(1)}s`
                : duration(scan.started_at, scan.completed_at)}
            </div>
          </div>
          <div className="px-[18px] py-3 min-w-[160px]">
            <div className="lbl">Started</div>
            <div className="text-[12.5px] mt-1">
              {scan.started_at ? dateTime(scan.started_at) : <Dash />}
            </div>
            <div className="text-[11.5px] text-ink-3">
              {scan.completed_at ? `Completed ${dateTime(scan.completed_at)}` : running ? "In progress" : ""}
            </div>
          </div>
          <div className="px-[18px] py-3 min-w-[150px]">
            <div className="lbl">Trigger</div>
            <div className="text-[12.5px] mt-1">{humanise(scan.trigger_type)}</div>
            <div className="text-[11.5px] text-ink-3">
              Priority {scan.priority} · {asset.asset_type}
            </div>
          </div>
        </div>

        {scan.note && (
          <div className="px-4 py-2.5 border-t border-rule text-[12px] text-ink-2">
            <span className="lbl mr-2">Note</span>
            {scan.note}
          </div>
        )}
      </Card>

      {summaryEmpty ? (
        <Card>
          <EmptyState
            icon={running ? "clock" : "activity"}
            title={running ? "Scan still running" : "No result summary"}
            description={
              running
                ? `This scan started ${absolute(scan.started_at)} and has not written a result summary yet. It refreshes on its own.`
                : "This scan finished without recording a result summary, so there is nothing to break down. The findings below are all it produced."
            }
          />
        </Card>
      ) : (
        <>
          <TlsDeepSection summary={summary} />
          <DnsDeepSection summary={summary} />
          <HttpDeepSection summary={summary} />
          <ProtectionSection summary={summary} />
          <PortsSection summary={summary} />
          <ServicesSection summary={summary} />
          <VulnerabilitiesSection summary={summary} />
          <HeadersSection summary={summary} />
          <DnsSection summary={summary} />
          <TlsSection summary={summary} />
          <RiskFactorsSection summary={summary} />
          <ErrorsSection summary={summary} />
        </>
      )}
    </div>
  );
}

export default ScanDetail;
