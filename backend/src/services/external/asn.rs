//! ASN, netblock and registry attribution.
//!
//! Subdomain enumeration answers "what names does this organisation publish".
//! It does not answer "what address space does this organisation *own*" — and
//! an owned netblock is where the assets nobody publishes a name for live:
//! jump hosts, management interfaces, appliances, forgotten lab racks.
//!
//! Two independent, key-free sources are used, because each is authoritative
//! about a different thing:
//!
//! - **Team Cymru's IP-to-ASN service**, over DNS. Mapping an address to its
//!   origin AS and BGP prefix is a routing-table fact, and Cymru serves it
//!   from a feed of 50+ BGP peers over plain DNS TXT lookups — no HTTP, no
//!   key, and it reuses the resolver already in the process.
//! - **RIPEstat**, over HTTP. The RIR view: which prefixes an AS actually
//!   announces, and the registry record behind an address. Key-free.
//!
//! Registrant attribution uses **RDAP** (RFC 9082/9083) through the IANA
//! bootstrap at `rdap.org`, which is the structured, machine-readable successor
//! to scraping port-43 WHOIS text.

use crate::error::ApiError;
use crate::services::external::DnsResolver;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// What Team Cymru and RIPEstat say about one address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpAttribution {
    /// Origin AS number, without the `AS` prefix.
    pub asn: Option<u32>,
    /// The announced BGP prefix covering the address.
    pub prefix: Option<String>,
    /// Registered AS name, e.g. `EXAMPLE-AS, US`.
    pub as_name: Option<String>,
    pub country: Option<String>,
    pub registry: Option<String>,
    /// Holder as recorded by the RIR, when it differs from the AS name.
    pub holder: Option<String>,
}

impl IpAttribution {
    /// The best available organisation label for this address.
    pub fn organization(&self) -> Option<&str> {
        self.holder
            .as_deref()
            .or(self.as_name.as_deref())
            .filter(|name| !name.trim().is_empty())
    }
}

/// The prefixes an autonomous system announces.
#[derive(Debug, Clone, Default)]
pub struct AsnPrefixes {
    pub asn: u32,
    pub holder: Option<String>,
    pub prefixes: Vec<String>,
}

/// The registry record behind a domain or address.
#[derive(Debug, Clone, Default)]
pub struct RdapRecord {
    /// Registrant / holder organisation names found in the record's entities.
    pub organizations: Vec<String>,
    /// Contact and abuse email addresses, whose domains are themselves a pivot.
    pub emails: Vec<String>,
    /// Nameservers listed for the object.
    pub nameservers: Vec<String>,
}

pub struct AsnClient {
    http: reqwest::Client,
    resolver: Arc<DnsResolver>,
    timeout: Duration,
}

impl AsnClient {
    pub fn new(resolver: Arc<DnsResolver>, timeout: Duration) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("EASM-Rust-Backend/1.0")
            .build()?;
        Ok(Self {
            http,
            resolver,
            timeout,
        })
    }

    // ------------------------------------------------------------------
    // Team Cymru — IP to ASN over DNS
    // ------------------------------------------------------------------

    /// Map an address to its origin AS and prefix using Team Cymru's DNS service.
    ///
    /// The query name is the address reversed under `origin.asn.cymru.com`
    /// (`origin6` for IPv6, nibble-reversed). The TXT answer is a pipe-separated
    /// record: `AS | BGP Prefix | CC | Registry | Allocated`.
    pub async fn lookup_ip_asn(&self, ip: &IpAddr) -> Result<IpAttribution, ApiError> {
        let query = cymru_origin_query(ip);
        let records = self.resolver.lookup_txt(&query).await?;

        let Some(record) = records.first() else {
            return Err(ApiError::NotFound(format!(
                "Team Cymru has no origin record for {}",
                ip
            )));
        };

        let mut attribution = parse_cymru_origin(record);

        // A second lookup turns the AS number into a name. It is a separate zone
        // (`asn.cymru.com`), so a failure here must not lose the mapping above.
        if let Some(asn) = attribution.asn {
            match self.lookup_asn_name(asn).await {
                Ok(Some(name)) => attribution.as_name = Some(name),
                Ok(None) => {}
                Err(e) => tracing::debug!("Team Cymru AS name lookup failed for AS{}: {}", asn, e),
            }
        }

        Ok(attribution)
    }

    /// Resolve an AS number to its registered name via Team Cymru.
    pub async fn lookup_asn_name(&self, asn: u32) -> Result<Option<String>, ApiError> {
        let records = self
            .resolver
            .lookup_txt(&format!("AS{}.asn.cymru.com", asn))
            .await?;

        Ok(records.first().and_then(|record| {
            // `AS | CC | Registry | Allocated | AS Name`
            record
                .split('|')
                .nth(4)
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
        }))
    }

    // ------------------------------------------------------------------
    // RIPEstat — announced prefixes and network info
    // ------------------------------------------------------------------

    /// Every prefix an AS currently announces, per RIPE's route collectors.
    ///
    /// This is the step that turns "our web server is in AS64500" into a
    /// concrete list of netblocks to sweep.
    pub async fn announced_prefixes(&self, asn: u32) -> Result<AsnPrefixes, ApiError> {
        let url = format!(
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}",
            asn
        );
        let response: RipeStatResponse<AnnouncedPrefixesData> = self.get_json(&url).await?;

        let mut prefixes: Vec<String> = response
            .data
            .prefixes
            .into_iter()
            .filter_map(|entry| entry.prefix)
            .collect();
        prefixes.sort();
        prefixes.dedup();

        let holder = match self.as_overview(asn).await {
            Ok(holder) => holder,
            Err(e) => {
                tracing::debug!("RIPEstat AS overview failed for AS{}: {}", asn, e);
                None
            }
        };

        Ok(AsnPrefixes {
            asn,
            holder,
            prefixes,
        })
    }

    /// The registered holder of an AS.
    pub async fn as_overview(&self, asn: u32) -> Result<Option<String>, ApiError> {
        let url = format!(
            "https://stat.ripe.net/data/as-overview/data.json?resource=AS{}",
            asn
        );
        let response: RipeStatResponse<AsOverviewData> = self.get_json(&url).await?;
        Ok(response
            .data
            .holder
            .filter(|holder| !holder.trim().is_empty()))
    }

    /// The RIR's view of an address: covering prefix and ASNs.
    ///
    /// Used as a cross-check on Team Cymru — the two disagreeing usually means
    /// a recent re-announcement, which is itself worth knowing.
    pub async fn network_info(&self, ip: &IpAddr) -> Result<IpAttribution, ApiError> {
        let url = format!(
            "https://stat.ripe.net/data/network-info/data.json?resource={}",
            ip
        );
        let response: RipeStatResponse<NetworkInfoData> = self.get_json(&url).await?;

        let asn = response
            .data
            .asns
            .first()
            .and_then(|asn| asn.trim().parse::<u32>().ok());

        Ok(IpAttribution {
            asn,
            prefix: response.data.prefix,
            ..Default::default()
        })
    }

    // ------------------------------------------------------------------
    // RDAP
    // ------------------------------------------------------------------

    /// Fetch the RDAP record for a domain.
    ///
    /// RDAP replaced port-43 WHOIS with structured JSON, so registrant
    /// organisation and abuse contacts can be read reliably rather than parsed
    /// out of free text that differs per registry. Many registries redact
    /// registrant data under GDPR; an empty record is a normal outcome, not an
    /// error.
    pub async fn rdap_domain(&self, domain: &str) -> Result<RdapRecord, ApiError> {
        let url = format!("https://rdap.org/domain/{}", urlencoding::encode(domain));
        let response: RdapResponse = self.get_json(&url).await?;
        Ok(parse_rdap(&response))
    }

    /// Fetch the RDAP record for an address, whose `name`/`entities` identify
    /// the netblock holder.
    pub async fn rdap_ip(&self, ip: &IpAddr) -> Result<RdapRecord, ApiError> {
        let url = format!("https://rdap.org/ip/{}", ip);
        let response: RdapResponse = self.get_json(&url).await?;
        Ok(parse_rdap(&response))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, ApiError> {
        let response = tokio::time::timeout(self.timeout, self.http.get(url).send())
            .await
            .map_err(|_| ApiError::Timeout(format!("{} timed out", url)))??;

        let status = response.status();
        if !status.is_success() {
            return Err(ApiError::ExternalService(format!(
                "{} returned HTTP {}",
                url, status
            )));
        }

        let body = response.text().await?;
        serde_json::from_str(&body).map_err(|e| {
            ApiError::ExternalService(format!("{} returned unparseable JSON: {}", url, e))
        })
    }
}

// ============================================================================
// Wire formats
// ============================================================================

#[derive(Debug, Deserialize)]
struct RipeStatResponse<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct AnnouncedPrefixesData {
    #[serde(default)]
    prefixes: Vec<AnnouncedPrefix>,
}

#[derive(Debug, Deserialize)]
struct AnnouncedPrefix {
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AsOverviewData {
    #[serde(default)]
    holder: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NetworkInfoData {
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    asns: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RdapResponse {
    #[serde(default)]
    entities: Vec<RdapEntity>,
    #[serde(default)]
    nameservers: Vec<RdapNameserver>,
    /// Present on IP network objects; the netblock's own label.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RdapEntity {
    #[serde(default)]
    roles: Vec<String>,
    /// jCard (RFC 7095): `["vcard", [[ "fn", {}, "text", "Example Inc" ], …]]`.
    #[serde(rename = "vcardArray", default)]
    vcard_array: Option<serde_json::Value>,
    #[serde(default)]
    entities: Vec<RdapEntity>,
}

#[derive(Debug, Default, Deserialize)]
struct RdapNameserver {
    #[serde(rename = "ldhName", default)]
    ldh_name: Option<String>,
}

/// Flatten an RDAP object into the few fields that are useful as pivots.
fn parse_rdap(response: &RdapResponse) -> RdapRecord {
    let mut organizations: BTreeSet<String> = BTreeSet::new();
    let mut emails: BTreeSet<String> = BTreeSet::new();

    if let Some(name) = response.name.as_deref() {
        let name = name.trim();
        if !name.is_empty() {
            organizations.insert(name.to_string());
        }
    }

    // Entities nest — a registrar entity carries the registrant inside it — so
    // the walk has to recurse rather than read only the top level.
    fn walk(
        entity: &RdapEntity,
        organizations: &mut BTreeSet<String>,
        emails: &mut BTreeSet<String>,
    ) {
        // Only identity-bearing roles; a `technical` contact at the registrar
        // is the registrar, not the asset owner.
        let identity_role = entity.roles.iter().any(|role| {
            matches!(
                role.as_str(),
                "registrant" | "administrative" | "abuse" | "noc" | "owner"
            )
        }) || entity.roles.is_empty();

        if let Some(vcard) = entity.vcard_array.as_ref() {
            for (property, value) in vcard_properties(vcard) {
                match property.as_str() {
                    "fn" | "org" if identity_role => {
                        let value = value.trim();
                        if !value.is_empty() {
                            organizations.insert(value.to_string());
                        }
                    }
                    "email" => {
                        let value = value.trim().to_lowercase();
                        if value.contains('@') {
                            emails.insert(value);
                        }
                    }
                    _ => {}
                }
            }
        }

        for nested in &entity.entities {
            walk(nested, organizations, emails);
        }
    }

    for entity in &response.entities {
        walk(entity, &mut organizations, &mut emails);
    }

    let nameservers: Vec<String> = response
        .nameservers
        .iter()
        .filter_map(|ns| ns.ldh_name.as_deref())
        .map(|name| name.trim_end_matches('.').to_lowercase())
        .filter(|name| !name.is_empty())
        .collect();

    RdapRecord {
        organizations: organizations.into_iter().collect(),
        emails: emails.into_iter().collect(),
        nameservers,
    }
}

/// Extract `(property, value)` pairs from a jCard array.
///
/// The shape is `["vcard", [[name, params, type, value], …]]`, where `value`
/// is a string for the properties we care about and an array for structured
/// ones like `adr`. Anything non-string is skipped.
fn vcard_properties(vcard: &serde_json::Value) -> Vec<(String, String)> {
    let Some(entries) = vcard.as_array().and_then(|outer| outer.get(1)) else {
        return Vec::new();
    };
    let Some(entries) = entries.as_array() else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|entry| {
            let entry = entry.as_array()?;
            let name = entry.first()?.as_str()?.to_lowercase();
            let value = entry.get(3)?.as_str()?.to_string();
            Some((name, value))
        })
        .collect()
}

/// Build the Team Cymru origin query name for an address.
///
/// IPv4 reverses the octets under `origin.asn.cymru.com`; IPv6 reverses the
/// nibbles under `origin6.asn.cymru.com`, exactly as `ip6.arpa` does.
fn cymru_origin_query(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.origin.asn.cymru.com",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            // Least significant nibble first: walk the octets backwards, and
            // within each octet emit the low nibble before the high one.
            let mut nibbles: Vec<String> = Vec::with_capacity(32);
            for octet in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", octet & 0x0f));
                nibbles.push(format!("{:x}", octet >> 4));
            }
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

/// Parse a Team Cymru origin TXT record.
///
/// `"64500 | 192.0.2.0/24 | US | arin | 2011-01-01"`. The AS field can carry
/// several numbers when a prefix has multiple origins; the first is taken.
fn parse_cymru_origin(record: &str) -> IpAttribution {
    let fields: Vec<&str> = record.trim().trim_matches('"').split('|').collect();

    let asn = fields
        .first()
        // `split_whitespace` already skips leading whitespace.
        .and_then(|field| field.split_whitespace().next())
        .and_then(|asn| asn.parse::<u32>().ok());

    let field = |index: usize| -> Option<String> {
        fields
            .get(index)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };

    IpAttribution {
        asn,
        prefix: field(1),
        as_name: None,
        country: field(2),
        registry: field(3),
        holder: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cymru_query_reverses_ipv4_octets() {
        let ip: IpAddr = "192.0.2.44".parse().unwrap();
        assert_eq!(
            cymru_origin_query(&ip),
            "44.2.0.192.origin.asn.cymru.com".to_string()
        );
    }

    #[test]
    fn cymru_query_nibble_reverses_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let query = cymru_origin_query(&ip);
        assert!(query.ends_with(".origin6.asn.cymru.com"));
        let nibbles: Vec<&str> = query
            .trim_end_matches(".origin6.asn.cymru.com")
            .split('.')
            .collect();
        assert_eq!(nibbles.len(), 32, "an IPv6 query has 32 nibble labels");
        // Least significant nibble first, exactly like ip6.arpa.
        assert_eq!(nibbles[0], "1");
        assert_eq!(nibbles[31], "2");
    }

    #[test]
    fn cymru_origin_record_is_parsed_field_by_field() {
        let parsed = parse_cymru_origin("64500 | 192.0.2.0/24 | US | arin | 2011-01-01");
        assert_eq!(parsed.asn, Some(64500));
        assert_eq!(parsed.prefix.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(parsed.country.as_deref(), Some("US"));
        assert_eq!(parsed.registry.as_deref(), Some("arin"));
    }

    #[test]
    fn a_multi_origin_prefix_takes_the_first_asn() {
        let parsed = parse_cymru_origin("\"64500 64501 | 192.0.2.0/24 | US | arin | 2011-01-01\"");
        assert_eq!(parsed.asn, Some(64500));
    }

    #[test]
    fn a_malformed_cymru_record_yields_no_asn_rather_than_panicking() {
        let parsed = parse_cymru_origin("no data available");
        assert_eq!(parsed.asn, None);
        assert_eq!(parsed.prefix, None);
    }

    #[test]
    fn rdap_entities_are_walked_recursively_for_org_and_email() {
        let json = serde_json::json!({
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Registrar LLC"],
                    ["email", {}, "text", "Abuse@registrar.example"]
                ]],
                "entities": [{
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Example Holdings Inc"],
                        ["email", {}, "text", "hostmaster@example.com"]
                    ]]
                }]
            }],
            "nameservers": [
                {"ldhName": "NS1.EXAMPLE.COM."},
                {"ldhName": "ns2.example.com"}
            ]
        });
        let response: RdapResponse = serde_json::from_value(json).unwrap();
        let record = parse_rdap(&response);

        // The registrar's own name carries a `registrar` role, which is not an
        // identity role, so it must not be reported as the asset owner.
        assert_eq!(
            record.organizations,
            vec!["Example Holdings Inc".to_string()]
        );
        // Emails are collected from every entity — the abuse address is a pivot
        // regardless of whose it is — and normalised to lower case.
        assert_eq!(
            record.emails,
            vec![
                "abuse@registrar.example".to_string(),
                "hostmaster@example.com".to_string()
            ]
        );
        assert_eq!(
            record.nameservers,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
        );
    }

    #[test]
    fn an_empty_rdap_record_is_not_an_error() {
        let record = parse_rdap(&RdapResponse::default());
        assert!(record.organizations.is_empty());
        assert!(record.emails.is_empty());
        assert!(record.nameservers.is_empty());
    }

    #[test]
    fn ip_attribution_prefers_the_registry_holder_over_the_as_name() {
        let attribution = IpAttribution {
            as_name: Some("EXAMPLE-AS, US".to_string()),
            holder: Some("Example Holdings Inc".to_string()),
            ..Default::default()
        };
        assert_eq!(attribution.organization(), Some("Example Holdings Inc"));

        let attribution = IpAttribution {
            as_name: Some("EXAMPLE-AS, US".to_string()),
            ..Default::default()
        };
        assert_eq!(attribution.organization(), Some("EXAMPLE-AS, US"));
    }
}
