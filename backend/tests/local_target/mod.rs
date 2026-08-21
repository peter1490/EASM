//! A deliberately misconfigured HTTP server, used as a scan target.
//!
//! Everything it does wrong is something the HTTP scanner is meant to find, and
//! one thing it does — answering 200 with unrelated content at `/.DS_Store` — is
//! there to prove the scanner does *not* report a path on status code alone.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct LocalTarget {
    addr: SocketAddr,
}

impl LocalTarget {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

const PAGE: &str = concat!(
    "<html><head><title>Test</title></head><body>",
    "<script src=\"https://cdn.example.com/with-sri.js\" integrity=\"sha384-abc\"></script>",
    "<script src=\"https://cdn.example.com/no-sri.js\"></script>",
    "<p>Traceback (most recent call last): File \"/srv/app/main.py\", line 42</p>",
    "</body></html>"
);

fn body_for(path: &str) -> &'static str {
    match path {
        "/.env" => "APP_KEY=base64:abcdef\nDB_PASSWORD=hunter2\n",
        "/.git/config" => "[core]\n\trepositoryformatversion = 0\n",
        "/server-status" => {
            "<h1>Apache Server Status for localhost</h1><p>Server uptime: 3 days</p>"
        }
        "/phpinfo.php" => "<h1>phpinfo()</h1><tr><td>PHP Version</td><td>8.1.2</td></tr>",
        // Right status, wrong content: must not be reported.
        "/.DS_Store" => "<html>nothing here</html>",
        _ => PAGE,
    }
}

async fn handle(mut stream: TcpStream) {
    let mut buffer = vec![0u8; 8192];
    let Ok(read) = stream.read(&mut buffer).await else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
    let start_line = request.lines().next().unwrap_or_default().to_string();
    let mut parts = start_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    let origin = request
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("origin:"))
        .and_then(|line| line.splitn(2, ':').nth(1))
        .map(str::trim)
        .map(str::to_string);

    let body = if method == "TRACE" {
        // Echo the request: this is what makes TRACE a finding.
        request.clone()
    } else {
        body_for(&path).to_string()
    };

    let mut response = String::new();
    response.push_str("HTTP/1.1 200 OK\r\n");
    response.push_str("Content-Type: text/html\r\n");
    response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    response.push_str("Server: TestServer/1.2.3\r\n");
    // A CSP that looks present but permits scripts from anywhere.
    response.push_str("Content-Security-Policy: default-src 'self'; script-src https:\r\n");
    response.push_str("Strict-Transport-Security: max-age=300\r\n");
    response.push_str("Set-Cookie: PHPSESSID=abc123; Path=/\r\n");
    response.push_str("Set-Cookie: theme=dark; Secure; SameSite=Lax\r\n");
    if method == "OPTIONS" {
        response.push_str("Allow: GET, POST, OPTIONS, TRACE, PUT, DELETE\r\n");
    }
    // Reflect any Origin, with credentials.
    if let Some(origin) = origin {
        response.push_str(&format!("Access-Control-Allow-Origin: {}\r\n", origin));
        response.push_str("Access-Control-Allow-Credentials: true\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");
    response.push_str(&body);

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Ports the scanner recognises as web ports. Binding to one of these is what
/// lets an IP asset find the target: `select_http_target_for_ip` probes this set
/// when no port scan has run.
const WEB_PORTS: [u16; 5] = [8080, 8000, 8888, 9000, 8443];

/// Bind to a web port and serve until the test process exits.
pub async fn start() -> LocalTarget {
    let mut bound = None;
    for port in WEB_PORTS {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            bound = Some(listener);
            break;
        }
    }
    let listener = bound.expect("no web port was free for the test target");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle(stream));
        }
    });
    LocalTarget { addr }
}
