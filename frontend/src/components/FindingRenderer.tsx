import Badge from "@/components/ui/Badge";

interface FindingData {
  [key: string]: unknown;
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function PortScanRenderer({ data }: { data: FindingData }) {
  const ip = data.ip as string;
  const openPorts = data.open_ports as number[];
  const count = data.count as number;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Target:</span>
        <span className="font-mono font-medium">{ip}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Open Ports ({count}):</span>
        <div className="flex flex-wrap gap-1">
          {openPorts?.map((port) => (
            <Badge key={port} variant="info">{port}</Badge>
          ))}
        </div>
      </div>
    </div>
  );
}

function DnsResolutionRenderer({ data }: { data: FindingData }) {
  const hostname = data.hostname as string;
  const ips = data.ips as string[];
  const count = data.count as number;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Hostname:</span>
        <span className="font-mono font-medium">{hostname}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Resolves to ({count}):</span>
        <div className="flex flex-wrap gap-1">
          {ips?.map((ip, idx) => (
            <Badge key={idx} variant="secondary">{ip}</Badge>
          ))}
        </div>
      </div>
    </div>
  );
}

function ReverseDnsRenderer({ data }: { data: FindingData }) {
  const ip = data.ip as string;
  const hostnames = data.hostnames as string[];
  const count = data.count as number;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">IP Address:</span>
        <span className="font-mono font-medium">{ip}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Hostnames ({count}):</span>
        <div className="flex flex-wrap gap-1">
          {hostnames?.map((hostname, idx) => (
            <Badge key={idx} variant="info">{hostname}</Badge>
          ))}
        </div>
      </div>
    </div>
  );
}

function HttpProbeRenderer({ data }: { data: FindingData }) {
  const url = data.url as string;
  const statusCode = data.status_code as number | null;
  const title = data.title as string | null;
  const server = data.server as string | null;
  const contentType = data.content_type as string | null;
  const responseTime = data.response_time_ms as number;
  const error = data.error as string | null;
  const finalUrl = data.final_url as string | null;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">URL:</span>
        <span className="font-mono text-sm">{url}</span>
      </div>
      {error ? (
        <div className="p-2 rounded bg-destructive/10 border border-destructive/20">
          <div className="text-sm font-medium text-destructive mb-1">Error</div>
          <div className="text-xs text-muted-foreground">{error}</div>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Status:</span>
            <Badge variant={statusCode && statusCode < 400 ? "success" : "warning"}>
              {statusCode || "N/A"}
            </Badge>
          </div>
          {title && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Title:</span>
              <span className="text-sm">{title}</span>
            </div>
          )}
          {server && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Server:</span>
              <Badge variant="secondary">{server}</Badge>
            </div>
          )}
          {contentType && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Content-Type:</span>
              <span className="text-xs font-mono">{contentType}</span>
            </div>
          )}
          {finalUrl && finalUrl !== url && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Redirected to:</span>
              <span className="font-mono text-xs">{finalUrl}</span>
            </div>
          )}
        </>
      )}
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Response Time:</span>
        <span className="text-sm font-medium">{responseTime}ms</span>
      </div>
    </div>
  );
}

function TlsAnalysisRenderer({ data }: { data: FindingData }) {
  const address = data.address as string;
  const certificate = data.certificate as Record<string, unknown>;

  if (!certificate) {
    return <div className="text-sm text-muted-foreground">No certificate data</div>;
  }

  const commonName = certificate.common_name as string | null;
  const issuer = certificate.issuer as string;
  const subject = certificate.subject as string;
  const notBefore = certificate.not_before as string;
  const notAfter = certificate.not_after as string;
  const serialNumber = certificate.serial_number as string;
  const sanDomains = certificate.san_domains as string[];

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Address:</span>
        <span className="font-mono font-medium">{address}</span>
      </div>
      {commonName && (
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Common Name:</span>
          <Badge variant="info">{commonName}</Badge>
        </div>
      )}
      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>
          <span className="text-muted-foreground">Valid From:</span>
          <div className="font-mono text-xs">{new Date(notBefore).toLocaleString()}</div>
        </div>
        <div>
          <span className="text-muted-foreground">Valid Until:</span>
          <div className="font-mono text-xs">{new Date(notAfter).toLocaleString()}</div>
        </div>
      </div>
      {issuer && (
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Issuer:</span>
          <span className="text-xs">{issuer || "Self-signed"}</span>
        </div>
      )}
      {sanDomains && sanDomains.length > 0 && (
        <div className="space-y-1">
          <span className="text-sm text-muted-foreground">SAN Domains:</span>
          <div className="flex flex-wrap gap-1">
            {sanDomains.map((domain, idx) => (
              <Badge key={idx} variant="secondary">{domain}</Badge>
            ))}
          </div>
        </div>
      )}
      <details className="text-xs">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
          Certificate Details
        </summary>
        <div className="mt-2 p-2 bg-muted rounded space-y-1">
          <div><strong>Serial:</strong> {serialNumber}</div>
          <div><strong>Subject:</strong> {subject || "—"}</div>
        </div>
      </details>
    </div>
  );
}

function ThreatIntelligenceRenderer({ data }: { data: FindingData }) {
  const target = data.target as string;
  const isMalicious = data.is_malicious as boolean;
  const reputationScore = data.reputation_score as number;
  const threatSources = data.threat_sources as string[];
  const additionalInfo = data.additional_info as Record<string, unknown>;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Target:</span>
        <span className="font-mono font-medium">{target}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Status:</span>
        <Badge variant={isMalicious ? "error" : "success"}>
          {isMalicious ? "Malicious" : "Clean"}
        </Badge>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Reputation Score:</span>
        <span className="font-medium">{reputationScore}</span>
      </div>
      {threatSources && threatSources.length > 0 && (
        <div className="p-2 rounded bg-destructive/10 border border-destructive/20">
          <div className="text-sm font-medium text-destructive mb-1">Threat Sources</div>
          <div className="flex flex-wrap gap-1">
            {threatSources.map((source, idx) => (
              <Badge key={idx} variant="error">{source}</Badge>
            ))}
          </div>
        </div>
      )}
      {additionalInfo && Object.keys(additionalInfo).length > 0 && (
        <div className="text-xs space-y-1">
          {(() => {
            const asn = additionalInfo.asn;
            const country = additionalInfo.country;
            const vtMalicious = additionalInfo.virustotal_malicious_count;
            const vtSuspicious = additionalInfo.virustotal_suspicious_count;
            
            return (
              <>
                {asn && (
                  <div>
                    <span className="text-muted-foreground">ASN:</span>{" "}
                    <Badge variant="secondary">AS{String(asn)}</Badge>
                  </div>
                )}
                {country && (
                  <div>
                    <span className="text-muted-foreground">Country:</span>{" "}
                    <Badge variant="secondary">{String(country)}</Badge>
                  </div>
                )}
                {vtMalicious !== undefined && vtMalicious !== null ? (
                  <div>
                    <span className="text-muted-foreground">VirusTotal Detections:</span>{" "}
                    <span className="font-medium">{String(vtMalicious)}</span>
                    {vtSuspicious !== undefined && vtSuspicious !== null ? (
                      <span className="text-muted-foreground">
                        /{String(vtSuspicious)} suspicious
                      </span>
                    ) : null}
                  </div>
                ) : null}
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}

function SubdomainEnumerationRenderer({ data }: { data: FindingData }) {
  const domain = data.domain as string;
  const count = data.count as number;
  const subdomains = data.subdomains as string[];
  const sources = data.sources as Record<string, string[]>;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Domain:</span>
        <span className="font-mono font-medium">{domain}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Subdomains Found:</span>
        <Badge variant="info">{count}</Badge>
      </div>
      {sources && (
        <div className="space-y-1">
          <span className="text-sm text-muted-foreground">Sources:</span>
          <div className="flex flex-wrap gap-1">
            {Object.entries(sources).map(([source, domains]) => (
              <Badge key={source} variant="secondary">
                {source} ({domains.length})
              </Badge>
            ))}
          </div>
        </div>
      )}
      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
          View all subdomains ({subdomains?.length || 0})
        </summary>
        <div className="mt-2 p-3 bg-muted rounded max-h-48 overflow-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
            {subdomains?.map((subdomain, idx) => (
              <div key={idx} className="font-mono text-xs">{subdomain}</div>
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}

function GenericRenderer({ data }: { data: FindingData }) {
  // Handle null, undefined, or empty data
  if (!data || typeof data !== 'object') {
    return (
      <div className="text-sm text-muted-foreground">
        No data available
      </div>
    );
  }

  const entries = Object.entries(data);
  
  if (entries.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">
        No data available
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {entries.map(([key, value]) => (
        <div key={key} className="flex items-start gap-2">
          <span className="text-sm text-muted-foreground min-w-32">{key}:</span>
          <span className="text-sm font-mono flex-1 break-all">{formatValue(value)}</span>
        </div>
      ))}
    </div>
  );
}

export default function FindingRenderer({ 
  findingType, 
  data 
}: { 
  findingType: string; 
  data: FindingData;
}) {
  switch (findingType) {
    case "port_scan":
      return <PortScanRenderer data={data} />;
    case "dns_resolution":
      return <DnsResolutionRenderer data={data} />;
    case "reverse_dns":
      return <ReverseDnsRenderer data={data} />;
    case "http_probe":
      return <HttpProbeRenderer data={data} />;
    case "tls_analysis":
      return <TlsAnalysisRenderer data={data} />;
    case "threat_intelligence":
      return <ThreatIntelligenceRenderer data={data} />;
    case "subdomain_enumeration":
      return <SubdomainEnumerationRenderer data={data} />;
    default:
      return <GenericRenderer data={data} />;
  }
}

export function getFindingTypeLabel(findingType: string): string {
  const labels: Record<string, string> = {
    port_scan: "Port Scan",
    dns_resolution: "DNS Resolution",
    reverse_dns: "Reverse DNS",
    http_probe: "HTTP Probe",
    tls_analysis: "TLS Certificate Analysis",
    threat_intelligence: "Threat Intelligence",
    subdomain_enumeration: "Subdomain Enumeration",
  };
  return labels[findingType] || findingType.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());
}

export function getFindingTypeIcon(findingType: string): string {
  const icons: Record<string, string> = {
    port_scan: "🔌",
    dns_resolution: "🌐",
    reverse_dns: "🔄",
    http_probe: "🌍",
    tls_analysis: "🔒",
    threat_intelligence: "🛡️",
    subdomain_enumeration: "🔍",
  };
  return icons[findingType] || "📋";
}

