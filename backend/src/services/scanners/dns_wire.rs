//! The DNS wire protocol, spoken directly.
//!
//! Two things a security scan needs are out of reach of the `trust-dns` stub
//! resolver the rest of the codebase uses, and both are solved here by encoding
//! the DNS message format ourselves.
//!
//! **Zone transfers.** A stub resolver asks a recursive server for answers; it
//! has no way to send AXFR to a named authoritative nameserver, which is the
//! whole check. A successful transfer hands an attacker the entire zone — every
//! internal hostname, every staging record, the full address layout — so `dig
//! axfr`, `dnsrecon` and `fierce` all treat it as table stakes.
//!
//! **Record types `trust-dns` will not decode.** Built without its `dnssec`
//! feature, `trust-dns-proto` cannot parse DNSKEY, DS, RRSIG or NSEC, and its
//! `Record::read` carries a `debug_assert!` that *panics* on the mismatch
//! (`record types do not match, DNSKEY <> Some(Unknown(48))`). In release builds
//! the assertion compiles out and the record silently becomes `Unknown`, so
//! DNSSEC would read as "absent" on every signed zone in existence. Asking for
//! those types over the wire and parsing the answer here avoids both failures
//! without pulling a crypto stack into the dependency tree for what is a
//! presence check.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_DS: u16 = 43;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_TLSA: u16 = 52;
pub const TYPE_CAA: u16 = 257;
pub const TYPE_AXFR: u16 = 252;

/// A UDP DNS response is capped at 512 bytes without EDNS0; we advertise a 4096
/// byte buffer, which is what every resolver does and what DNSKEY answers need.
const UDP_BUFFER_SIZE: u16 = 4096;

/// An unpredictable transaction id for one query.
fn query_id() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Cap on how much of a transferred zone we read. A hostile or very large zone
/// must not be able to exhaust memory, and the first megabyte is far more than
/// enough to prove the transfer succeeded and to sample its contents.
const MAX_TRANSFER_BYTES: usize = 1_048_576;
/// Records kept from a successful transfer. The finding needs proof and a sample,
/// not a copy of the zone.
const MAX_SAMPLED_RECORDS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum ZoneTransferOutcome {
    /// The nameserver handed over the zone. `records` is a bounded sample.
    Transferred {
        record_count: usize,
        truncated: bool,
        records: Vec<ZoneRecord>,
    },
    /// The nameserver answered and refused — the correct behaviour.
    Refused(String),
    /// No usable answer: connection refused, timeout, or a malformed reply.
    Unavailable(String),
}

impl ZoneTransferOutcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, ZoneTransferOutcome::Transferred { .. })
    }
}

fn type_name(code: u16) -> String {
    match code {
        TYPE_A => "A",
        TYPE_NS => "NS",
        TYPE_CNAME => "CNAME",
        TYPE_SOA => "SOA",
        12 => "PTR",
        TYPE_MX => "MX",
        TYPE_TXT => "TXT",
        TYPE_AAAA => "AAAA",
        TYPE_SRV => "SRV",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        52 => "TLSA",
        257 => "CAA",
        other => return format!("TYPE{}", other),
    }
    .to_string()
}

/// Encode a domain name as a sequence of length-prefixed labels.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        // A label is capped at 63 octets by RFC 1035; anything longer is invalid
        // input and is truncated rather than producing a malformed packet.
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

/// Build a DNS query message.
///
/// `id` is echoed by the server. Callers pass an unpredictable value from
/// [`query_id`] so a reply to a different question — or a forged one — does not
/// match; on its own it is a weak filter, which is why the UDP path also connects
/// the socket to the server.
pub fn build_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&id.to_be_bytes());
    // A zone transfer is asked of an authoritative server directly, so recursion
    // is not requested.
    msg.extend_from_slice(&0x0000u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(name, &mut msg);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    msg
}

/// Read a name at `pos`, following RFC 1035 compression pointers.
/// Returns the name and the offset just past it in the *current* record.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_pos = pos;
    // A compression loop would otherwise hang the parser; 128 hops is far beyond
    // any legitimate message.
    let mut hops = 0;

    loop {
        if hops > 128 {
            return None;
        }
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            if !jumped {
                next_pos = pos;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let lo = *msg.get(pos + 1)? as usize;
            let target = ((len & 0x3F) << 8) | lo;
            if !jumped {
                next_pos = pos + 2;
            }
            if target >= msg.len() {
                return None;
            }
            pos = target;
            jumped = true;
            hops += 1;
            continue;
        }
        pos += 1;
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        pos += len;
        if !jumped {
            next_pos = pos;
        }
    }

    Some((
        if labels.is_empty() {
            ".".to_string()
        } else {
            labels.join(".")
        },
        next_pos,
    ))
}

fn render_rdata(msg: &[u8], rtype: u16, rdata_start: usize, rdlength: usize) -> String {
    let Some(rdata) = msg.get(rdata_start..rdata_start + rdlength) else {
        return String::new();
    };
    match rtype {
        TYPE_A if rdlength == 4 => {
            std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()
        }
        TYPE_AAAA if rdlength == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        TYPE_NS | TYPE_CNAME | 12 => read_name(msg, rdata_start)
            .map(|(name, _)| name)
            .unwrap_or_default(),
        TYPE_MX if rdlength >= 3 => {
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let exchange = read_name(msg, rdata_start + 2)
                .map(|(name, _)| name)
                .unwrap_or_default();
            format!("{} {}", preference, exchange)
        }
        TYPE_TXT => {
            let mut out = String::new();
            let mut offset = 0;
            while offset < rdata.len() {
                let len = rdata[offset] as usize;
                offset += 1;
                if offset + len > rdata.len() {
                    break;
                }
                out.push_str(&String::from_utf8_lossy(&rdata[offset..offset + len]));
                offset += len;
            }
            out
        }
        TYPE_SOA => {
            let Some((mname, next)) = read_name(msg, rdata_start) else {
                return String::new();
            };
            let Some((rname, _)) = read_name(msg, next) else {
                return mname;
            };
            format!("{} {}", mname, rname)
        }
        TYPE_SRV if rdlength >= 7 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let target = read_name(msg, rdata_start + 6)
                .map(|(name, _)| name)
                .unwrap_or_default();
            format!("{} {} {} {}", priority, weight, port, target)
        }
        TYPE_DNSKEY if rdlength >= 4 => {
            let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
            // Bit 0 of the flags field is the Secure Entry Point: set on the
            // key-signing key the parent's DS record points at.
            let role = if flags & 0x0001 != 0 { "KSK" } else { "ZSK" };
            format!(
                "flags={} protocol={} algorithm={} {}",
                flags, rdata[2], rdata[3], role
            )
        }
        TYPE_DS if rdlength >= 4 => {
            let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
            format!(
                "keytag={} algorithm={} digest_type={}",
                key_tag, rdata[2], rdata[3]
            )
        }
        _ => format!("{} bytes", rdlength),
    }
}

/// Append an EDNS0 OPT pseudo-record advertising a larger UDP buffer, and
/// optionally setting the DNSSEC OK bit so signed answers come back intact.
fn push_edns0(msg: &mut Vec<u8>, dnssec_ok: bool) {
    msg.push(0); // root name
    msg.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    msg.extend_from_slice(&UDP_BUFFER_SIZE.to_be_bytes()); // CLASS = UDP payload size
    msg.push(0); // extended rcode
    msg.push(0); // EDNS version 0
    msg.extend_from_slice(&if dnssec_ok { 0x8000u16 } else { 0 }.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // no options
    // ARCOUNT becomes 1.
    msg[11] = 1;
}

/// Parse the answer section of a DNS response, ignoring authority and additional.
fn parse_answers(msg: &[u8]) -> Option<(u8, Vec<ZoneRecord>)> {
    if msg.len() < 12 {
        return None;
    }
    let rcode = msg[3] & 0x0F;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(msg, pos)?;
        pos = next + 4; // QTYPE + QCLASS
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        if pos >= msg.len() {
            break;
        }
        let Some((name, next)) = read_name(msg, pos) else {
            break;
        };
        pos = next;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > msg.len() {
            break;
        }
        records.push(ZoneRecord {
            name,
            record_type: type_name(rtype),
            ttl,
            value: render_rdata(msg, rtype, pos, rdlength),
        });
        pos += rdlength;
    }
    Some((rcode, records))
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        9 => "NOTAUTH",
        _ => "unknown",
    }
}

/// The nameservers the host is configured to use, for queries that must bypass
/// the typed stub resolver.
pub fn system_resolvers() -> Vec<IpAddr> {
    match trust_dns_resolver::system_conf::read_system_conf() {
        Ok((config, _)) => {
            let mut seen = Vec::new();
            for ns in config.name_servers() {
                let ip = ns.socket_addr.ip();
                if !seen.contains(&ip) {
                    seen.push(ip);
                }
            }
            seen
        }
        Err(e) => {
            tracing::debug!("could not read the system resolver configuration: {}", e);
            Vec::new()
        }
    }
}

/// Send one query over UDP and return `(rcode, answers)`.
///
/// Used for the record types the stub resolver cannot decode. A truncated answer
/// (the TC bit) is retried over TCP by the caller if it cares; for the presence
/// checks this serves, the header alone is conclusive.
pub async fn query_over_udp(
    name: &str,
    qtype: u16,
    nameserver: SocketAddr,
    timeout: Duration,
) -> Result<(u8, Vec<ZoneRecord>), String> {
    let id = query_id();
    let mut query = build_query(name, qtype, id);
    query[2] |= 0x01; // recursion desired
    // DNSKEY and DS answers are large and DNSSEC-relevant; ask for them properly.
    push_edns0(&mut query, true);

    let bind: SocketAddr = if nameserver.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid bind address")
    } else {
        "[::]:0".parse().expect("valid bind address")
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    // Connect before sending so the kernel drops datagrams from anyone else. An
    // unconnected socket accepts whatever arrives at the ephemeral port, and the
    // transaction id alone is a weak filter — these answers decide the DNSSEC and
    // DANE verdicts, so an off-path forgery would flip them.
    socket
        .connect(nameserver)
        .await
        .map_err(|e| e.to_string())?;
    socket.send(&query).await.map_err(|e| e.to_string())?;

    let mut buffer = vec![0u8; UDP_BUFFER_SIZE as usize];
    let len = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| "query timed out".to_string())?
        .map_err(|e| e.to_string())?;
    buffer.truncate(len);

    // Only accept a reply to the question we asked.
    if buffer.len() < 12 || buffer[0..2] != query[0..2] {
        return Err("DNS response did not match the query id".to_string());
    }

    // TC: the answer did not fit. Large TXT sets and DNSKEY answers routinely
    // overflow, and taking the truncated body at face value reports a populated
    // record set as empty — which for DNSKEY means "unsigned".
    if buffer[2] & 0x02 != 0 {
        return query_over_tcp(name, qtype, nameserver, timeout, true).await;
    }

    parse_answers(&buffer).ok_or_else(|| "malformed DNS response".to_string())
}

/// Ask the system resolvers for one record type, trying each in turn.
///
/// `Ok(records)` means an authoritative answer was received — an empty vector is
/// a definite "no such record". `Err` means no resolver answered, which must not
/// be reported as absence.
pub async fn query_system(
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<ZoneRecord>, String> {
    let resolvers = system_resolvers();
    if resolvers.is_empty() {
        return Err("no system resolver is configured".to_string());
    }
    let mut last_error = String::from("no resolver answered");
    for resolver in resolvers {
        match query_over_udp(name, qtype, SocketAddr::new(resolver, 53), timeout).await {
            // NOERROR and NXDOMAIN are both definite answers about existence.
            Ok((0, records)) => return Ok(records),
            Ok((3, _)) => return Ok(Vec::new()),
            Ok((rcode, _)) => last_error = format!("{} from {}", rcode_name(rcode), resolver),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

/// Send one query to a specific nameserver over TCP and return `(rcode, answers)`.
///
/// The stub resolver cannot be pointed at an arbitrary server per query, and some
/// record types a security scan needs — DNSKEY and DS in particular — are exactly
/// the ones a caching resolver is most likely to strip or refuse. Asking the
/// authoritative server directly removes that layer.
pub async fn query_over_tcp(
    name: &str,
    qtype: u16,
    nameserver: SocketAddr,
    timeout: Duration,
    recursion_desired: bool,
) -> Result<(u8, Vec<ZoneRecord>), String> {
    let mut query = build_query(name, qtype, query_id());
    if recursion_desired {
        query[2] |= 0x01; // RD
    }
    push_edns0(&mut query, true);
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(nameserver))
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| e.to_string())?;
    stream.write_all(&framed).await.map_err(|e| e.to_string())?;

    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline || buffer.len() > MAX_TRANSFER_BYTES {
            break;
        }
        match tokio::time::timeout(deadline - now, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e.to_string()),
        }
        if buffer.len() >= 2 {
            let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
            if buffer.len() >= 2 + len {
                return parse_answers(&buffer[2..2 + len])
                    .ok_or_else(|| "malformed DNS response".to_string());
            }
        }
    }
    Err("no complete DNS response".to_string())
}

/// Attempt a zone transfer of `zone` from one nameserver.
pub async fn attempt_transfer(
    zone: &str,
    nameserver: SocketAddr,
    timeout: Duration,
) -> ZoneTransferOutcome {
    let query = build_query(zone, TYPE_AXFR, 0x4321);
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(nameserver)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return ZoneTransferOutcome::Unavailable(e.to_string()),
        Err(_) => return ZoneTransferOutcome::Unavailable("connection timed out".to_string()),
    };
    if let Err(e) = stream.write_all(&framed).await {
        return ZoneTransferOutcome::Unavailable(e.to_string());
    }

    let mut buffer = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + timeout;
    let mut records: Vec<ZoneRecord> = Vec::new();
    let mut total_records = 0usize;
    let mut truncated = false;
    let mut rcode = None;

    // A zone transfer ends with a repeat of the opening SOA (RFC 5936 §2.2).
    // Without seeing it we have a prefix of the zone, not the zone — and
    // reporting a prefix as complete would put a wrong record count in a finding.
    let mut saw_closing_soa = false;
    let mut soa_seen = 0usize;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline || buffer.len() > MAX_TRANSFER_BYTES {
            truncated = true;
            break;
        }
        match tokio::time::timeout(deadline - now, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Err(_) => {
                truncated = true;
                break;
            }
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => {
                truncated = true;
                break;
            }
        }

        // A transfer arrives as a stream of length-prefixed messages.
        let mut consumed = 0usize;
        while buffer.len() >= consumed + 2 {
            let len = u16::from_be_bytes([buffer[consumed], buffer[consumed + 1]]) as usize;
            if buffer.len() < consumed + 2 + len {
                break;
            }
            let message = &buffer[consumed + 2..consumed + 2 + len];
            if let Some((code, mut parsed)) = parse_answers(message) {
                rcode.get_or_insert(code);
                total_records += parsed.len();
                soa_seen += parsed.iter().filter(|r| r.record_type == "SOA").count();
                if soa_seen >= 2 {
                    saw_closing_soa = true;
                }
                if records.len() < MAX_SAMPLED_RECORDS {
                    let room = MAX_SAMPLED_RECORDS - records.len();
                    parsed.truncate(room);
                    records.append(&mut parsed);
                }
            }
            consumed += 2 + len;
        }
        buffer.drain(..consumed);
        if saw_closing_soa {
            truncated = false;
            break;
        }
    }

    match rcode {
        Some(0) if total_records > 0 => ZoneTransferOutcome::Transferred {
            record_count: total_records,
            // Either the read stopped early, or more records arrived than the
            // sample keeps. Both mean the count below is a floor, not a total.
            truncated: truncated || total_records > records.len() || !saw_closing_soa,
            records,
        },
        Some(0) => ZoneTransferOutcome::Refused(
            "the nameserver answered NOERROR but transferred no records".to_string(),
        ),
        Some(code) => ZoneTransferOutcome::Refused(rcode_name(code).to_string()),
        None => ZoneTransferOutcome::Unavailable(
            "no parsable DNS response on the TCP connection".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_well_formed() {
        let query = build_query("example.com", TYPE_AXFR, 0x1234);
        assert_eq!(&query[0..2], &[0x12, 0x34], "id is echoed back by the server");
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1, "one question");
        // 7"example" 3"com" 0
        assert_eq!(&query[12..13], &[7]);
        assert_eq!(&query[13..20], b"example");
        assert_eq!(&query[20..21], &[3]);
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0);
        assert_eq!(u16::from_be_bytes([query[25], query[26]]), TYPE_AXFR);
        assert_eq!(u16::from_be_bytes([query[27], query[28]]), 1, "class IN");
    }

    #[test]
    fn trailing_dots_and_empty_labels_are_tolerated() {
        assert_eq!(
            build_query("example.com.", TYPE_A, 1),
            build_query("example.com", TYPE_A, 1)
        );
    }

    /// Build a response carrying one A record for `www.example.com`.
    fn response_with_a_record(rcode: u8) -> Vec<u8> {
        let mut msg = vec![0x43, 0x21, 0x84, rcode];
        msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        // Question
        encode_name("example.com", &mut msg);
        msg.extend_from_slice(&TYPE_AXFR.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        // Answer
        encode_name("www.example.com", &mut msg);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[192, 0, 2, 1]);
        msg
    }

    #[test]
    fn answers_are_parsed_with_names_types_and_values() {
        let (rcode, records) = parse_answers(&response_with_a_record(0)).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "www.example.com");
        assert_eq!(records[0].record_type, "A");
        assert_eq!(records[0].ttl, 300);
        assert_eq!(records[0].value, "192.0.2.1");
    }

    #[test]
    fn a_refusal_rcode_is_surfaced() {
        let (rcode, _) = parse_answers(&response_with_a_record(5)).unwrap();
        assert_eq!(rcode, 5);
        assert_eq!(rcode_name(rcode), "REFUSED");
    }

    #[test]
    fn compression_pointers_are_followed() {
        // "example.com" at offset 12, then a pointer back to it.
        let mut msg = vec![0u8; 12];
        encode_name("example.com", &mut msg);
        let pointer_at = msg.len();
        msg.push(0xC0);
        msg.push(12);
        let (name, next) = read_name(&msg, pointer_at).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(next, pointer_at + 2, "a pointer is two bytes wide");
    }

    #[test]
    fn a_compression_loop_terminates() {
        // A pointer to itself must not hang the parser.
        let mut msg = vec![0u8; 12];
        msg.push(0xC0);
        msg.push(12);
        assert!(read_name(&msg, 12).is_none());
    }

    #[test]
    fn truncated_messages_never_panic() {
        let full = response_with_a_record(0);
        for cut in 0..full.len() {
            let _ = parse_answers(&full[..cut]);
        }
    }

    #[test]
    fn a_lying_record_count_does_not_overrun() {
        let mut msg = response_with_a_record(0);
        // Claim 500 answers when only one is present.
        msg[6..8].copy_from_slice(&500u16.to_be_bytes());
        let (_, records) = parse_answers(&msg).unwrap();
        assert_eq!(records.len(), 1, "parsing stops at the end of the buffer");
    }

    #[test]
    fn the_truncation_bit_is_read_from_the_right_place() {
        // Byte 2 bit 1 is TC. A response with it set must be retried over TCP
        // rather than parsed, or a large DNSKEY set reads as an empty one.
        let mut header = [0u8; 12];
        header[2] = 0x84; // QR + AA
        assert_eq!(header[2] & 0x02, 0);
        header[2] |= 0x02;
        assert_ne!(header[2] & 0x02, 0);
        // RD lives in bit 0 of the same byte and must not be confused with it.
        let mut query = build_query("example.com", TYPE_TXT, 1);
        query[2] |= 0x01;
        assert_eq!(query[2] & 0x02, 0, "setting RD must not set TC");
    }

    #[test]
    fn edns0_opt_record_is_appended_with_the_do_bit() {
        let mut query = build_query("example.com", TYPE_DNSKEY, 1);
        let before = query.len();
        push_edns0(&mut query, true);
        assert_eq!(u16::from_be_bytes([query[10], query[11]]), 1, "ARCOUNT becomes 1");
        let opt = &query[before..];
        assert_eq!(opt[0], 0, "OPT owner name is the root");
        assert_eq!(u16::from_be_bytes([opt[1], opt[2]]), 41, "TYPE = OPT");
        assert_eq!(u16::from_be_bytes([opt[3], opt[4]]), UDP_BUFFER_SIZE);
        assert_eq!(u16::from_be_bytes([opt[7], opt[8]]) & 0x8000, 0x8000, "DO bit set");

        let mut plain = build_query("example.com", TYPE_A, 1);
        let before = plain.len();
        push_edns0(&mut plain, false);
        assert_eq!(u16::from_be_bytes([plain[before + 7], plain[before + 8]]) & 0x8000, 0);
    }

    #[test]
    fn dnskey_and_ds_rdata_render_readably() {
        let mut msg = vec![0x00, 0x01, 0x84, 0x00];
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&2u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());

        // DNSKEY with the Secure Entry Point bit set: a key-signing key.
        encode_name("example.com", &mut msg);
        msg.extend_from_slice(&TYPE_DNSKEY.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&3600u32.to_be_bytes());
        let dnskey = [0x01u8, 0x01, 3, 13, 0xAA, 0xBB];
        msg.extend_from_slice(&(dnskey.len() as u16).to_be_bytes());
        msg.extend_from_slice(&dnskey);

        encode_name("example.com", &mut msg);
        msg.extend_from_slice(&TYPE_DS.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&3600u32.to_be_bytes());
        let ds = [0x12u8, 0x34, 13, 2, 0xDE, 0xAD];
        msg.extend_from_slice(&(ds.len() as u16).to_be_bytes());
        msg.extend_from_slice(&ds);

        let (_, records) = parse_answers(&msg).unwrap();
        assert_eq!(records[0].record_type, "DNSKEY");
        assert!(records[0].value.contains("KSK"), "{}", records[0].value);
        assert!(records[0].value.contains("algorithm=13"));
        assert_eq!(records[1].record_type, "DS");
        assert!(records[1].value.contains("keytag=4660"), "{}", records[1].value);
    }

    #[test]
    fn mx_and_txt_rdata_render_readably() {
        let mut msg = vec![0x00, 0x01, 0x84, 0x00];
        msg.extend_from_slice(&0u16.to_be_bytes()); // no question
        msg.extend_from_slice(&2u16.to_be_bytes()); // two answers
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());

        encode_name("example.com", &mut msg);
        msg.extend_from_slice(&TYPE_MX.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        let mut mx_rdata = Vec::new();
        mx_rdata.extend_from_slice(&10u16.to_be_bytes());
        encode_name("mail.example.com", &mut mx_rdata);
        msg.extend_from_slice(&(mx_rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&mx_rdata);

        encode_name("example.com", &mut msg);
        msg.extend_from_slice(&TYPE_TXT.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        let text = b"v=spf1 -all";
        msg.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
        msg.push(text.len() as u8);
        msg.extend_from_slice(text);

        let (_, records) = parse_answers(&msg).unwrap();
        assert_eq!(records[0].value, "10 mail.example.com");
        assert_eq!(records[1].value, "v=spf1 -all");
    }
}
