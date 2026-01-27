use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ============================================================================
// PORT SCAN RESULT WITH SERVICE DETECTION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<ServiceInfo>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub confidence: u8, // 0-100
    pub cpe: Option<String>, // Common Platform Enumeration
}

// ============================================================================
// EXTENDED PORT LISTS
// ============================================================================

/// Common ports for quick scanning
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9090,
];

/// Extended ports for thorough scanning
pub const EXTENDED_PORTS: &[u16] = &[
    // Standard services
    7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 84, 85,
    88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443,
    444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723,
    1755, 1900, 2000, 2001, 2049, 2121, 2181, 2717, 3000, 3128, 3306, 3389,
    3986, 4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101, 5190, 5357,
    5432, 5631, 5666, 5800, 5900, 5901, 6000, 6001, 6379, 6646, 7000, 7001,
    7002, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9001, 9042,
    9090, 9100, 9200, 9300, 9418, 9999, 10000, 10443, 27017, 27018, 32768,
    49152, 49153, 49154,
];

/// Top 1000 ports (subset for performance)
pub const TOP_PORTS: &[u16] = &[
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
    42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
    109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199,
    211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
    406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
    512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
    616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
    711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
    880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
    999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
    1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037,
    1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
    1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061,
    1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
    1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085,
    1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097,
    1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112,
    1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132,
    1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164,
    1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199,
    1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259,
    1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
    1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503,
    1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687,
    1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783,
    1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935,
    1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
    2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033,
    2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049,
    2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126,
    2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251,
    2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401,
    2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638,
    2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909,
    2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011,
    3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260,
    3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333,
    3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517,
    3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800,
    3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889,
    3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002,
    4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
    4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899,
    4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051,
    5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214,
    5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432,
    5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678,
    5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850,
    5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911,
    5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988,
    5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009,
    6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6379, 6389,
    6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668,
    6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969,
    7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200,
    7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778,
    7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008,
    8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181,
    8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383,
    8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873,
    8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050,
    9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111,
    9200, 9207, 9220, 9290, 9300, 9418, 9485, 9500, 9502, 9503, 9535, 9575,
    9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929,
    9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009,
    10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10443, 10566,
    10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967,
    12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
    14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001,
    16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040,
    18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000,
    20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800,
    25734, 25735, 26214, 27000, 27017, 27352, 27353, 27355, 27356, 27715,
    28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771,
    32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781,
    32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500,
    38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
    49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001,
    50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
    52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
    56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078,
    63331, 64623, 64680, 65000, 65129, 65389,
];

// ============================================================================
// SERVICE DETECTION PROBES
// ============================================================================

lazy_static::lazy_static! {
    /// Service signatures for banner-based detection
    static ref SERVICE_SIGNATURES: HashMap<&'static str, Vec<ServiceSignature>> = {
        let mut m = HashMap::new();
        
        // SSH signatures - specific products first, then generic
        m.insert("ssh", vec![
            ServiceSignature {
                pattern: "OpenSSH",
                name: "ssh",
                product: Some("OpenSSH"),
                version_regex: Some(r"OpenSSH[_\s]*([\d.]+\w*)"),
            },
            ServiceSignature {
                pattern: "Dropbear",
                name: "ssh",
                product: Some("Dropbear SSH"),
                version_regex: Some(r"dropbear[_\s]*([\d.]+)"),
            },
            ServiceSignature {
                pattern: "SSH-",
                name: "ssh",
                product: None, // Generic SSH, no specific product
                version_regex: Some(r"SSH-[\d.]+-([\w\d._-]+)"),
            },
        ]);
        
        // HTTP signatures - specific products FIRST, generic HTTP last
        m.insert("http", vec![
            ServiceSignature {
                pattern: "Apache",
                name: "http",
                product: Some("Apache HTTP Server"),
                version_regex: Some(r"Apache(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "nginx",
                name: "http",
                product: Some("nginx"),
                version_regex: Some(r"nginx(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Microsoft-IIS",
                name: "http",
                product: Some("Microsoft IIS"),
                version_regex: Some(r"Microsoft-IIS/([\d.]+)"),
            },
            ServiceSignature {
                pattern: "LiteSpeed",
                name: "http",
                product: Some("LiteSpeed"),
                version_regex: Some(r"LiteSpeed(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Caddy",
                name: "http",
                product: Some("Caddy"),
                version_regex: Some(r"Caddy(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "lighttpd",
                name: "http",
                product: Some("lighttpd"),
                version_regex: Some(r"lighttpd(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Tomcat",
                name: "http",
                product: Some("Apache Tomcat"),
                version_regex: Some(r"Tomcat(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Jetty",
                name: "http",
                product: Some("Eclipse Jetty"),
                version_regex: Some(r"Jetty(?:\(| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "gunicorn",
                name: "http",
                product: Some("Gunicorn"),
                version_regex: Some(r"gunicorn(?:/| )([\d.]+)"),
            },
            ServiceSignature {
                pattern: "uvicorn",
                name: "http",
                product: Some("Uvicorn"),
                version_regex: Some(r"uvicorn(?:/| )([\d.]+)"),
            },
            // Generic HTTP - last resort, no CVE lookup
            ServiceSignature {
                pattern: "HTTP/",
                name: "http",
                product: None, // No specific product identified
                version_regex: Some(r"HTTP/([\d.]+)"),
            },
        ]);
        
        // FTP signatures - specific products first
        m.insert("ftp", vec![
            ServiceSignature {
                pattern: "vsftpd",
                name: "ftp",
                product: Some("vsftpd"),
                version_regex: Some(r"vsftpd ([\d.]+)"),
            },
            ServiceSignature {
                pattern: "ProFTPD",
                name: "ftp",
                product: Some("ProFTPD"),
                version_regex: Some(r"ProFTPD ([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Pure-FTPd",
                name: "ftp",
                product: Some("Pure-FTPd"),
                version_regex: Some(r"Pure-FTPd[^\d]*([\d.]+)?"),
            },
            ServiceSignature {
                pattern: "FileZilla",
                name: "ftp",
                product: Some("FileZilla Server"),
                version_regex: Some(r"FileZilla Server ([\d.]+)"),
            },
            ServiceSignature {
                pattern: "220",
                name: "ftp",
                product: None, // Generic FTP
                version_regex: None,
            },
        ]);
        
        // SMTP signatures - specific products first
        m.insert("smtp", vec![
            ServiceSignature {
                pattern: "Postfix",
                name: "smtp",
                product: Some("Postfix"),
                version_regex: None,
            },
            ServiceSignature {
                pattern: "Exim",
                name: "smtp",
                product: Some("Exim"),
                version_regex: Some(r"Exim ([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Sendmail",
                name: "smtp",
                product: Some("Sendmail"),
                version_regex: Some(r"Sendmail[/ ]([\d.]+)"),
            },
            ServiceSignature {
                pattern: "Microsoft ESMTP",
                name: "smtp",
                product: Some("Microsoft Exchange"),
                version_regex: None,
            },
            ServiceSignature {
                pattern: "Haraka",
                name: "smtp",
                product: Some("Haraka"),
                version_regex: Some(r"Haraka[/ ]([\d.]+)"),
            },
            ServiceSignature {
                pattern: "220",
                name: "smtp",
                product: None, // Generic SMTP
                version_regex: None,
            },
        ]);
        
        // MySQL signatures - specific products first
        m.insert("mysql", vec![
            ServiceSignature {
                pattern: "MariaDB",
                name: "mysql",
                product: Some("MariaDB"),
                version_regex: Some(r"([\d.]+)-MariaDB"),
            },
            ServiceSignature {
                pattern: "mysql",
                name: "mysql",
                product: Some("MySQL"),
                version_regex: Some(r"([\d.]+)"),
            },
        ]);
        
        // PostgreSQL signatures
        m.insert("postgresql", vec![
            ServiceSignature {
                pattern: "PostgreSQL",
                name: "postgresql",
                product: Some("PostgreSQL"),
                version_regex: Some(r"PostgreSQL ([\d.]+)"),
            },
        ]);
        
        // Redis signatures
        m.insert("redis", vec![
            ServiceSignature {
                pattern: "redis_version:",
                name: "redis",
                product: Some("Redis"),
                version_regex: Some(r"redis_version:([\d.]+)"),
            },
            ServiceSignature {
                pattern: "-ERR",
                name: "redis",
                product: Some("Redis"),
                version_regex: None,
            },
            ServiceSignature {
                pattern: "PONG",
                name: "redis",
                product: Some("Redis"),
                version_regex: None,
            },
        ]);
        
        // MongoDB signatures
        m.insert("mongodb", vec![
            ServiceSignature {
                pattern: "MongoDB",
                name: "mongodb",
                product: Some("MongoDB"),
                version_regex: Some(r"([\d.]+)"),
            },
        ]);
        
        // RDP signatures
        m.insert("rdp", vec![
            ServiceSignature {
                pattern: "RDP",
                name: "rdp",
                product: Some("Microsoft Remote Desktop"),
                version_regex: None,
            },
            ServiceSignature {
                pattern: "Remote Desktop",
                name: "rdp",
                product: Some("Microsoft Remote Desktop"),
                version_regex: None,
            },
        ]);
        
        // Telnet signatures
        m.insert("telnet", vec![
            ServiceSignature {
                pattern: "login:",
                name: "telnet",
                product: None, // Generic telnet
                version_regex: None,
            },
            ServiceSignature {
                pattern: "Telnet",
                name: "telnet",
                product: None,
                version_regex: None,
            },
            ServiceSignature {
                pattern: "Welcome to",
                name: "telnet",
                product: None,
                version_regex: None,
            },
        ]);
        
        // DNS signatures
        m.insert("dns", vec![
            ServiceSignature {
                pattern: "BIND",
                name: "dns",
                product: Some("ISC BIND"),
                version_regex: Some(r"BIND ([\d.]+)"),
            },
            ServiceSignature {
                pattern: "dnsmasq",
                name: "dns",
                product: Some("dnsmasq"),
                version_regex: Some(r"dnsmasq-([\d.]+)"),
            },
        ]);
        
        // LDAP signatures
        m.insert("ldap", vec![
            ServiceSignature {
                pattern: "OpenLDAP",
                name: "ldap",
                product: Some("OpenLDAP"),
                version_regex: Some(r"OpenLDAP[/ ]([\d.]+)"),
            },
            ServiceSignature {
                pattern: "LDAP",
                name: "ldap",
                product: None, // Generic LDAP
                version_regex: None,
            },
        ]);
        
        m
    };
    
    /// Default port-to-service mapping
    static ref PORT_SERVICE_MAP: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(21, "ftp");
        m.insert(22, "ssh");
        m.insert(23, "telnet");
        m.insert(25, "smtp");
        m.insert(53, "dns");
        m.insert(80, "http");
        m.insert(110, "pop3");
        m.insert(111, "rpcbind");
        m.insert(135, "msrpc");
        m.insert(139, "netbios-ssn");
        m.insert(143, "imap");
        m.insert(389, "ldap");
        m.insert(443, "https");
        m.insert(445, "microsoft-ds");
        m.insert(465, "smtps");
        m.insert(513, "rlogin");
        m.insert(514, "rsh");
        m.insert(515, "printer");
        m.insert(587, "submission");
        m.insert(636, "ldaps");
        m.insert(993, "imaps");
        m.insert(995, "pop3s");
        m.insert(1433, "mssql");
        m.insert(1521, "oracle");
        m.insert(1723, "pptp");
        m.insert(2049, "nfs");
        m.insert(3306, "mysql");
        m.insert(3389, "rdp");
        m.insert(5432, "postgresql");
        m.insert(5900, "vnc");
        m.insert(5901, "vnc");
        m.insert(6379, "redis");
        m.insert(8080, "http-proxy");
        m.insert(8443, "https-alt");
        m.insert(9000, "cslistener");
        m.insert(9090, "zeus-admin");
        m.insert(9200, "elasticsearch");
        m.insert(9300, "elasticsearch");
        m.insert(27017, "mongodb");
        m.insert(27018, "mongodb");
        m
    };
}

#[derive(Debug, Clone)]
struct ServiceSignature {
    pattern: &'static str,
    name: &'static str,
    product: Option<&'static str>, // Actual software product name for CVE lookups
    version_regex: Option<&'static str>,
}

// ============================================================================
// CORE SCANNING FUNCTIONS
// ============================================================================

pub async fn scan_port(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<bool, ApiError> {
    let socket_addr = SocketAddr::new(ip, port);

    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false), // Timeout
    }
}

/// Scan a port and grab the service banner
pub async fn scan_port_with_banner(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> PortScanResult {
    let socket_addr = SocketAddr::new(ip, port);
    let start = std::time::Instant::now();

    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(mut stream)) => {
            let response_time = start.elapsed().as_millis() as u64;
            
            // Try to grab banner
            let banner = grab_banner(&mut stream, port, timeout_duration).await;
            let service = identify_service(port, banner.as_deref());
            
            PortScanResult {
                port,
                open: true,
                service: Some(service),
                response_time_ms: Some(response_time),
            }
        }
        Ok(Err(_)) | Err(_) => PortScanResult {
            port,
            open: false,
            service: None,
            response_time_ms: None,
        },
    }
}

/// Grab banner from an open port
async fn grab_banner(
    stream: &mut TcpStream,
    port: u16,
    timeout_duration: Duration,
) -> Option<String> {
    // Set socket options
    let _ = stream.set_nodelay(true);
    
    // Some services need a probe to respond
    let probe = get_service_probe(port);
    
    if let Some(probe_data) = probe {
        if timeout(timeout_duration / 2, stream.write_all(probe_data.as_bytes()))
            .await
            .is_err()
        {
            return None;
        }
    }
    
    // Read response
    let mut buffer = vec![0u8; 4096];
    
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            // Try to convert to UTF-8, fall back to lossy conversion
            let response = String::from_utf8_lossy(&buffer[..n]).to_string();
            // Clean up the response (remove non-printable characters except newlines)
            let cleaned: String = response
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .take(1024) // Limit banner length
                .collect();
            if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            }
        }
        _ => None,
    }
}

/// Get the appropriate probe for a service
fn get_service_probe(port: u16) -> Option<&'static str> {
    match port {
        80 | 8080 | 8000 | 8008 | 8888 | 9000 => {
            Some("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        }
        443 | 8443 | 9443 => None, // TLS - handled separately
        21 => None,                // FTP sends banner automatically
        22 => None,                // SSH sends banner automatically
        23 => None,                // Telnet sends negotiation
        25 | 587 | 465 => None,    // SMTP sends banner
        110 | 995 => None,         // POP3 sends banner
        143 | 993 => None,         // IMAP sends banner
        6379 => Some("PING\r\n"),  // Redis
        3306 => None,              // MySQL sends handshake
        5432 => None,              // PostgreSQL needs special handling
        27017 => None,             // MongoDB
        _ => None,
    }
}

/// Identify service from port and banner
fn identify_service(port: u16, banner: Option<&str>) -> ServiceInfo {
    let default_service = PORT_SERVICE_MAP.get(&port).copied().unwrap_or("unknown");
    
    let mut service_info = ServiceInfo {
        name: default_service.to_string(),
        version: None,
        banner: banner.map(|s| s.chars().take(512).collect()),
        product: None,
        extra_info: None,
        confidence: 30, // Low confidence for port-based detection
        cpe: None,
    };
    
    if let Some(banner) = banner {
        // Try to match against known signatures
        for (category, signatures) in SERVICE_SIGNATURES.iter() {
            for sig in signatures {
                if banner.to_lowercase().contains(&sig.pattern.to_lowercase()) {
                    service_info.name = sig.name.to_string();
                    service_info.product = sig.product.map(|p| p.to_string()); // Set the product!
                    service_info.confidence = if sig.product.is_some() { 85 } else { 60 };
                    
                    // Extract version if regex provided
                    if let Some(regex_pattern) = sig.version_regex {
                        if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex_pattern)) {
                            if let Some(captures) = re.captures(banner) {
                                if let Some(version) = captures.get(1) {
                                    service_info.version = Some(version.as_str().to_string());
                                    service_info.confidence = if sig.product.is_some() { 95 } else { 70 };
                                }
                            }
                        }
                    }
                    
                    // Generate CPE if we have enough info (use product name if available)
                    let product_for_cpe = sig.product.unwrap_or(sig.name);
                    service_info.cpe = generate_cpe(product_for_cpe, service_info.version.as_deref());
                    
                    // Add category as extra info
                    service_info.extra_info = Some(category.to_string());
                    
                    return service_info;
                }
            }
        }
    }
    
    service_info
}

/// Generate CPE (Common Platform Enumeration) string
fn generate_cpe(product: &str, version: Option<&str>) -> Option<String> {
    let product_lower = product.to_lowercase();
    let (vendor, cpe_product) = match product_lower.as_str() {
        "openssh" | "ssh" => ("openbsd", "openssh"),
        "dropbear ssh" | "dropbear" => ("matt_johnston", "dropbear_ssh_server"),
        "apache http server" | "apache" => ("apache", "http_server"),
        "nginx" => ("nginx", "nginx"),
        "microsoft iis" | "iis" => ("microsoft", "iis"),
        "litespeed" => ("litespeedtech", "litespeed_web_server"),
        "caddy" => ("caddyserver", "caddy"),
        "lighttpd" => ("lighttpd", "lighttpd"),
        "apache tomcat" | "tomcat" => ("apache", "tomcat"),
        "eclipse jetty" | "jetty" => ("eclipse", "jetty"),
        "gunicorn" => ("gunicorn", "gunicorn"),
        "uvicorn" => ("encode", "uvicorn"),
        "mysql" => ("oracle", "mysql"),
        "mariadb" => ("mariadb", "mariadb"),
        "postgresql" => ("postgresql", "postgresql"),
        "redis" => ("redis", "redis"),
        "mongodb" => ("mongodb", "mongodb"),
        "postfix" => ("postfix", "postfix"),
        "exim" => ("exim", "exim"),
        "sendmail" => ("sendmail", "sendmail"),
        "microsoft exchange" => ("microsoft", "exchange_server"),
        "vsftpd" => ("beasts", "vsftpd"),
        "proftpd" => ("proftpd_project", "proftpd"),
        "pure-ftpd" => ("pureftpd", "pure-ftpd"),
        "filezilla server" => ("filezilla-project", "filezilla_server"),
        "isc bind" | "bind" => ("isc", "bind"),
        "dnsmasq" => ("thekelleys", "dnsmasq"),
        "openldap" => ("openldap", "openldap"),
        "microsoft remote desktop" | "rdp" => ("microsoft", "remote_desktop_services"),
        _ => return None,
    };
    
    let version_str = version.unwrap_or("*");
    Some(format!("cpe:/a:{}:{}:{}", vendor, cpe_product, version_str))
}

/// Scan multiple ports with service detection (concurrent)
pub async fn scan_ports_with_services(
    ip: IpAddr,
    ports: &[u16],
    timeout_duration: Duration,
    max_concurrent: usize,
) -> Vec<PortScanResult> {
    use futures::stream::{self, StreamExt};
    
    let results: Vec<PortScanResult> = stream::iter(ports.iter().cloned())
        .map(|port| {
            let ip = ip;
            async move {
                scan_port_with_banner(ip, port, timeout_duration).await
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;
    
    // Filter to only open ports
    results.into_iter().filter(|r| r.open).collect()
}

pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>, ApiError> {
    let network: ipnet::IpNet = cidr
        .parse()
        .map_err(|e| ApiError::Validation(format!("Invalid CIDR: {}", e)))?;

    let hosts: Vec<IpAddr> = network.hosts().collect();
    Ok(hosts)
}

pub async fn scan_ports(ip: IpAddr, ports: &[u16], timeout_duration: Duration) -> Vec<u16> {
    let mut open_ports = Vec::new();

    for &port in ports {
        if let Ok(true) = scan_port(ip, port, timeout_duration).await {
            open_ports.push(port);
        }
    }

    open_ports
}

// ============================================================================
// HTTP SECURITY ANALYSIS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpSecurityAnalysis {
    pub url: String,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub missing_security_headers: Vec<MissingHeader>,
    pub server_info: Option<String>,
    pub technology_stack: Vec<String>,
    pub cookies: Vec<CookieAnalysis>,
    pub redirect_chain: Vec<String>,
    pub is_https: bool,
    pub hsts_enabled: bool,
    pub hsts_max_age: Option<u64>,
    pub cors_policy: Option<CorsPolicy>,
    pub content_security_policy: Option<String>,
    pub x_frame_options: Option<String>,
    pub behind_proxy: bool,
    pub proxy_type: Option<String>,
    pub waf_detected: bool,
    pub waf_type: Option<String>,
    pub cdn_detected: bool,
    pub cdn_provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingHeader {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAnalysis {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicy {
    pub allow_origin: Option<String>,
    pub allow_credentials: bool,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: Option<u64>,
    pub is_permissive: bool,
}

/// Security headers that should be present
pub const SECURITY_HEADERS: &[(&str, &str, &str, &str)] = &[
    (
        "Strict-Transport-Security",
        "critical",
        "HSTS header enforces HTTPS connections",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
    ),
    (
        "Content-Security-Policy",
        "high",
        "CSP prevents XSS and data injection attacks",
        "Implement a Content Security Policy header",
    ),
    (
        "X-Frame-Options",
        "medium",
        "Prevents clickjacking attacks",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        "Prevents MIME type sniffing",
        "Add 'X-Content-Type-Options: nosniff' header",
    ),
    (
        "X-XSS-Protection",
        "low",
        "Enables browser XSS filter (legacy)",
        "Add 'X-XSS-Protection: 1; mode=block' header (or use CSP instead)",
    ),
    (
        "Referrer-Policy",
        "low",
        "Controls referrer information",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
    ),
    (
        "Permissions-Policy",
        "low",
        "Controls browser features",
        "Add Permissions-Policy header to limit browser features",
    ),
];

/// CDN detection signatures
pub const CDN_SIGNATURES: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare"),
    ("cloudfront", "Amazon CloudFront"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("stackpath", "StackPath"),
    ("sucuri", "Sucuri"),
    ("incapsula", "Imperva Incapsula"),
    ("edgecast", "Verizon EdgeCast"),
    ("azure", "Azure CDN"),
    ("google", "Google Cloud CDN"),
    ("keycdn", "KeyCDN"),
    ("bunny", "BunnyCDN"),
];

/// WAF detection signatures
pub const WAF_SIGNATURES: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare WAF"),
    ("mod_security", "ModSecurity"),
    ("aws-waf", "AWS WAF"),
    ("imperva", "Imperva WAF"),
    ("sucuri", "Sucuri WAF"),
    ("f5", "F5 BIG-IP ASM"),
    ("barracuda", "Barracuda WAF"),
    ("fortinet", "Fortinet FortiWeb"),
    ("akamai", "Akamai Kona"),
    ("citrix", "Citrix NetScaler"),
];

/// Proxy detection headers
pub const PROXY_HEADERS: &[&str] = &[
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Via",
    "X-Real-IP",
    "X-Proxy-ID",
    "Forwarded",
    "X-ProxyUser-Ip",
    "CF-Connecting-IP", // Cloudflare
    "True-Client-IP",   // Akamai
    "X-Azure-ClientIP", // Azure
];

// ============================================================================
// DNS SECURITY ANALYSIS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsSecurityAnalysis {
    pub domain: String,
    pub has_spf: bool,
    pub spf_record: Option<String>,
    pub spf_issues: Vec<String>,
    pub has_dkim: bool,
    pub dkim_selectors: Vec<String>,
    pub has_dmarc: bool,
    pub dmarc_record: Option<String>,
    pub dmarc_policy: Option<String>,
    pub dmarc_issues: Vec<String>,
    pub has_dnssec: bool,
    pub dnssec_valid: Option<bool>,
    pub has_caa: bool,
    pub caa_records: Vec<String>,
    pub nameservers: Vec<String>,
    pub mx_records: Vec<MxRecord>,
    pub zone_transfer_enabled: bool,
    pub dangling_dns: bool,
    pub issues: Vec<DnsSecurityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub priority: u16,
    pub exchange: String,
    pub has_spf: bool,
    pub has_starttls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSecurityIssue {
    pub issue_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

// ============================================================================
// VULNERABILITY DATA
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub affected_versions: Vec<String>,
    pub references: Vec<String>,
    pub exploitable: bool,
    pub has_public_exploit: bool,
}

/// Known vulnerable versions (simplified - in production, use a proper CVE database)
pub fn get_known_vulnerabilities(product: &str, version: &str) -> Vec<VulnerabilityInfo> {
    let mut vulns = Vec::new();
    
    // These are examples - in production, integrate with NVD/CVE database
    match (product.to_lowercase().as_str(), version) {
        ("openssh", v) if version_compare(v, "8.3") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2020-15778".to_string(),
                title: "OpenSSH Command Injection".to_string(),
                description: "scp allows command injection via the username".to_string(),
                severity: "high".to_string(),
                cvss_score: Some(7.8),
                cvss_vector: Some("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()),
                affected_versions: vec!["< 8.3".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-15778".to_string()],
                exploitable: true,
                has_public_exploit: true,
            });
        }
        ("openssh", v) if version_compare(v, "7.7") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2018-15473".to_string(),
                title: "OpenSSH User Enumeration".to_string(),
                description: "User enumeration via malformed authentication request".to_string(),
                severity: "medium".to_string(),
                cvss_score: Some(5.3),
                cvss_vector: Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string()),
                affected_versions: vec!["< 7.7".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-15473".to_string()],
                exploitable: true,
                has_public_exploit: true,
            });
        }
        ("apache", v) if version_compare(v, "2.4.50") < 0 && version_compare(v, "2.4.49") >= 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2021-41773".to_string(),
                title: "Apache Path Traversal".to_string(),
                description: "Path traversal and file disclosure vulnerability".to_string(),
                severity: "critical".to_string(),
                cvss_score: Some(9.8),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                affected_versions: vec!["2.4.49".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-41773".to_string()],
                exploitable: true,
                has_public_exploit: true,
            });
        }
        ("nginx", v) if version_compare(v, "1.20.1") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2021-23017".to_string(),
                title: "nginx DNS Resolver Off-by-One".to_string(),
                description: "1-byte memory overwrite in resolver".to_string(),
                severity: "high".to_string(),
                cvss_score: Some(7.7),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L".to_string()),
                affected_versions: vec!["< 1.20.1".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23017".to_string()],
                exploitable: true,
                has_public_exploit: false,
            });
        }
        ("redis", v) if version_compare(v, "6.2.6") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2021-32761".to_string(),
                title: "Redis Integer Overflow".to_string(),
                description: "Integer overflow in BITFIELD command".to_string(),
                severity: "high".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string()),
                affected_versions: vec!["< 6.2.6".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-32761".to_string()],
                exploitable: true,
                has_public_exploit: false,
            });
        }
        ("mysql", v) | ("mariadb", v) if version_compare(v, "8.0.23") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2021-2154".to_string(),
                title: "MySQL Server Vulnerability".to_string(),
                description: "Vulnerability in MySQL Server product".to_string(),
                severity: "medium".to_string(),
                cvss_score: Some(4.9),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H".to_string()),
                affected_versions: vec!["< 8.0.23".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-2154".to_string()],
                exploitable: false,
                has_public_exploit: false,
            });
        }
        ("postgresql", v) if version_compare(v, "13.3") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2021-32027".to_string(),
                title: "PostgreSQL Buffer Overrun".to_string(),
                description: "Buffer overrun from integer overflow in array subscripting".to_string(),
                severity: "high".to_string(),
                cvss_score: Some(8.8),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()),
                affected_versions: vec!["< 13.3".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-32027".to_string()],
                exploitable: true,
                has_public_exploit: false,
            });
        }
        ("vsftpd", "2.3.4") => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2011-2523".to_string(),
                title: "vsftpd Backdoor".to_string(),
                description: "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200".to_string(),
                severity: "critical".to_string(),
                cvss_score: Some(10.0),
                cvss_vector: Some("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C".to_string()),
                affected_versions: vec!["2.3.4".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2011-2523".to_string()],
                exploitable: true,
                has_public_exploit: true,
            });
        }
        ("proftpd", v) if version_compare(v, "1.3.7a") < 0 => {
            vulns.push(VulnerabilityInfo {
                cve_id: "CVE-2020-9273".to_string(),
                title: "ProFTPD Use-After-Free".to_string(),
                description: "Use-after-free vulnerability in ProFTPD".to_string(),
                severity: "high".to_string(),
                cvss_score: Some(8.8),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()),
                affected_versions: vec!["< 1.3.7a".to_string()],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-9273".to_string()],
                exploitable: true,
                has_public_exploit: true,
            });
        }
        _ => {}
    }
    
    vulns
}

/// Simple version comparison (returns -1, 0, or 1)
fn version_compare(v1: &str, v2: &str) -> i32 {
    let parse_version = |v: &str| -> Vec<u32> {
        v.split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    
    let v1_parts = parse_version(v1);
    let v2_parts = parse_version(v2);
    
    for i in 0..std::cmp::max(v1_parts.len(), v2_parts.len()) {
        let p1 = v1_parts.get(i).copied().unwrap_or(0);
        let p2 = v2_parts.get(i).copied().unwrap_or(0);
        
        if p1 < p2 {
            return -1;
        }
        if p1 > p2 {
            return 1;
        }
    }
    
    0
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compare() {
        assert_eq!(version_compare("1.0.0", "1.0.0"), 0);
        assert_eq!(version_compare("1.0.0", "1.0.1"), -1);
        assert_eq!(version_compare("1.0.1", "1.0.0"), 1);
        assert_eq!(version_compare("2.0.0", "1.9.9"), 1);
        assert_eq!(version_compare("7.6p1", "7.7"), -1);
        assert_eq!(version_compare("8.3p1", "8.3"), 0);
    }

    #[test]
    fn test_identify_service_ssh() {
        let banner = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1";
        let service = identify_service(22, Some(banner));
        assert_eq!(service.name, "openssh");
        assert!(service.version.is_some());
        assert!(service.confidence >= 80);
    }

    #[test]
    fn test_identify_service_http() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\n";
        let service = identify_service(80, Some(banner));
        assert_eq!(service.name, "nginx");
        assert_eq!(service.version, Some("1.20.1".to_string()));
    }

    #[test]
    fn test_get_vulnerabilities() {
        let vulns = get_known_vulnerabilities("openssh", "7.6");
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2018-15473"));
    }

    #[test]
    fn test_generate_cpe() {
        let cpe = generate_cpe("openssh", Some("8.4"));
        assert_eq!(cpe, Some("cpe:/a:openbsd:openssh:8.4".to_string()));
    }
}
