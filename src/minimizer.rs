use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map, Value};
/// Hook for protocol-specific reducers; implementors should mutate `meta` and `tech` as needed.
pub trait ProtocolReducer {
    fn reduce(
        &self,
        meta: &mut Map<String, Value>,
        tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)>;
}


/// Result of minimizing a Shodan record
#[derive(Debug, Clone)]
pub struct Minimized {
    pub meta_json: String,
    pub tech_json: String,
    pub html: Option<(i64, String)>,
    pub scheme: String,
    pub sanitization_fixes: usize,
    // New: hex-encoded BLAKE3 hash of cleaned HTML body, if present
    pub html_hash_b3: Option<String>,
}

// Precompiled regexes to strip base64-embedded data URIs and large inline base64 chunks
static RE_DATA_URI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"data:[^;,]+;?[^,]*,([A-Za-z0-9+/=]+)").expect("valid regex")
});
static RE_CSS_BG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"background-image:\s*url\(["']?data:[^;,]+;?[^,]*,([A-Za-z0-9+/=]+)["']?\)"#).expect("valid regex")
});
static RE_SRC_LONG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"src=\"data:[^;,]+;?[^,]*,([A-Za-z0-9+/=]{100,})\""#).expect("valid regex")
});

// Additional regex patterns for HTML cleaning
static RE_DATA_IMAGE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"data:image/[^;]+;base64,[^"']+"#).expect("valid regex")
});
static RE_SVG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)<svg[^>]*>.*?</svg>").expect("valid regex")
});
static RE_SESSION_ID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"session[_-]?id[=:]\w+").expect("valid regex")
});
static RE_WHITESPACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\s+").expect("valid regex")
});
static RE_EMPTY_LINES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\n\s*\n").expect("valid regex")
});

pub fn strip_base64_data(input: &str) -> String {
    let mut out = input.to_string();

    // Apply additional HTML cleaning patterns first (before generic data URI removal)
    out = RE_DATA_IMAGE
        .replace_all(&out, "data:image/removed;base64,removed")
        .into_owned();
    out = RE_SVG
        .replace_all(&out, "<!-- SVG content removed -->")
        .into_owned();
    out = RE_SESSION_ID
        .replace_all(&out, "session_id=removed")
        .into_owned();

    // Apply existing base64 data removal patterns
    out = RE_DATA_URI
        .replace_all(&out, "data:removed-base64-content")
        .into_owned();
    out = RE_CSS_BG
        .replace_all(&out, "background-image: url(data:removed-base64-content)")
        .into_owned();
    out = RE_SRC_LONG
        .replace_all(&out, "src=\"data:removed-base64-content\"")
        .into_owned();

    // Apply whitespace cleaning last
    out = RE_WHITESPACE
        .replace_all(&out, " ")
        .into_owned();
    out = RE_EMPTY_LINES
        .replace_all(&out, "\n")
        .into_owned();

    out
}

fn sanitize_text(s: &str, fixes: &mut usize) -> String {
    if s.contains('\u{0}') {
        *fixes += 1;
    }
    s.replace('\u{0}', "")
}

fn sanitize_value(v: &mut Value, fixes: &mut usize) {
    match v {
        Value::String(s) => {
            if s.contains('\u{0}') {
                let cleaned = sanitize_text(s, fixes);
                *s = cleaned;
            }
        }
        Value::Array(arr) => {
            for elem in arr.iter_mut() {
                sanitize_value(elem, fixes)
            }
        }
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if let Some(val) = map.get_mut(&k) {
                    sanitize_value(val, fixes)
                }
            }
        }
        _ => {}
    }
}

struct HttpReducer;
impl ProtocolReducer for HttpReducer {
    fn reduce(
        &self,
        obj: &mut Map<String, Value>,
        tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)> {
        let mut html_out: Option<(i64, String)> = None;
        if let Some(Value::Object(http)) = obj.get_mut("http") {
        // Extract html body if both html and html_hash exist
        let mut body_hash: Option<i64> = None;
        if let Some(Value::Number(h)) = http.get("html_hash") {
            body_hash = h.as_i64();
        }
        if let (Some(h), Some(Value::String(body))) = (body_hash, http.get("html")) {
            if !body.is_empty() {
                let mut fixes = 0usize;
                let cleaned = sanitize_text(&strip_base64_data(body), &mut fixes);
                html_out = Some((h, cleaned));
                // keep original html_hash field name
            }
        }

        // Drop heavy or unstable fields per minimization.md
        http.remove("html");
        http.remove("robots");
        http.remove("robots_hash");
        http.remove("securitytxt");
        http.remove("securitytxt_hash");
        http.remove("sitemap");
        http.remove("sitemap_hash");

        // favicon -> hash scalar if present
        if let Some(fav) = http.get_mut("favicon") {
            if let Value::Object(f) = fav {
                if let Some(Value::Number(h)) = f.get("hash") {
                    *fav = Value::Number(h.clone());
                }
            }
        }

        // Keep other http fields for now; revisit after review

        // If http.data is Incapsula noise, drop it
        if let Some(Value::String(data)) = http.get("data") {
            if data.contains("Incapsula incident ID: 0-") {
                http.remove("data");
            }
        }

        // Minimal HTTP: capture headers and favicon hash into tech
        if let Some(Value::Object(hdrs)) = http.get("headers") {
            // Copy a minimal subset or full headers as a map, depending on presence
            if !hdrs.is_empty() {
                tech.insert("http_headers".to_string(), Value::Object(hdrs.clone()));
            }
        }
        if let Some(fav) = http.get_mut("favicon") {
            if let Value::Object(f) = fav {
                if let Some(Value::Number(h)) = f.get("hash") {
                    tech.insert("favicon_hash".to_string(), Value::Number(h.clone()));
                }
            }
        }
        }
        html_out
    }
}

struct SslReducer;
impl ProtocolReducer for SslReducer {
    fn reduce(
        &self,
        obj: &mut Map<String, Value>,
        tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)> {
        if let Some(Value::Object(mut ssl)) = obj.remove("ssl") {
            let mut slim = Map::new();
            if let Some(v) = ssl.remove("ja3s") { slim.insert("ja3s".to_string(), v); }
            if let Some(v) = ssl.remove("jarm") { slim.insert("jarm".to_string(), v); }
            if let Some(v) = ssl.remove("versions") { slim.insert("versions".to_string(), v); }
            if let Some(Value::Object(mut cipher)) = ssl.remove("cipher") {
                let mut keep = Map::new();
                if let Some(v) = cipher.remove("name") { keep.insert("name".to_string(), v); }
                if let Some(v) = cipher.remove("version") { keep.insert("version".to_string(), v); }
                if !keep.is_empty() { slim.insert("cipher".to_string(), Value::Object(keep)); }
            }
            if let Some(Value::Object(mut cert)) = ssl.remove("cert") {
                let mut keep = Map::new();
                for k in ["sha256", "expires", "expired", "subject_cn", "issuer_cn"] {
                    if let Some(v) = cert.remove(k) { keep.insert(k.to_string(), v); }
                }
                if !keep.is_empty() { slim.insert("cert".to_string(), Value::Object(keep)); }
            }
            if !slim.is_empty() {
                tech.insert("ssl".to_string(), Value::Object(slim));
            }
        }
        None
    }
}

struct SshReducer;
impl ProtocolReducer for SshReducer {
    fn reduce(
        &self,
        obj: &mut Map<String, Value>,
        _tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)> {
        if let Some(Value::Object(mut ssh)) = obj.remove("ssh") {
            let mut slim = Map::new();
            if let Some(v) = ssh.remove("hassh") { slim.insert("hassh".to_string(), v); }
            if !slim.is_empty() { obj.insert("ssh".to_string(), Value::Object(slim)); }
        }
        obj.remove("data");
        None
    }
}

struct IsakmpReducer;
impl ProtocolReducer for IsakmpReducer {
    fn reduce(
        &self,
        obj: &mut Map<String, Value>,
        _tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)> {
        if let Some(Value::Object(mut isakmp)) = obj.remove("isakmp") {
            isakmp.remove("data");
            if !isakmp.is_empty() { obj.insert("isakmp".to_string(), Value::Object(isakmp)); }
        }
        None
    }
}

struct SmbReducer;
impl ProtocolReducer for SmbReducer {
    fn reduce(
        &self,
        obj: &mut Map<String, Value>,
        _tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)> {
        if let Some(Value::Object(mut smb)) = obj.remove("smb") {
            smb.remove("raw");
            if !smb.is_empty() { obj.insert("smb".to_string(), Value::Object(smb)); }
        }
        None
    }
}

struct GenericReducer {
    section: &'static str,
    drop_keys: &'static [&'static str],
}

impl ProtocolReducer for GenericReducer {
    fn reduce(
        &self,
        obj: &mut Map<String, Value>,
        _tech: &mut Map<String, Value>,
    ) -> Option<(i64, String)> {
        if let Some(Value::Object(mut sec)) = obj.remove(self.section) {
            // Always drop common heavy keys
            for k in ["data", "raw", "payload", "result", "packet", "full"] {
                sec.remove(k);
            }
            // Drop configured keys
            for &k in self.drop_keys {
                sec.remove(k);
            }
            if !sec.is_empty() {
                obj.insert(self.section.to_string(), Value::Object(sec));
            }
        }
        // Also drop top-level data if present when a protocol section exists
        obj.remove("data");
        None
    }
}

fn normalize_cpe(obj: &Map<String, Value>) -> Vec<String> {
    // Restrict to CPE 2.3 only (keys: "cpe.2.3" or "cpe23"); emit only entries with a version.
    let mut out: Vec<String> = Vec::new();
    for key in ["cpe.2.3", "cpe23"] {
        if let Some(val) = obj.get(key) {
            match val {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            if !s.starts_with("cpe:2.3:") { continue; }
                            let parts: Vec<&str> = s.split(':').collect();
                            if parts.len() >= 6 {
                                let vendor = parts[3];
                                let product = parts[4];
                                let version = parts[5];
                                if !vendor.is_empty() && !product.is_empty() {
                                    if !version.is_empty() && version != "*" {
                                        out.push(format!("{}:{}:{}", vendor, product, version));
                                    } else {
                                        out.push(format!("{}:{}", vendor, product));
                                    }
                                }
                            }
                        }
                    }
                }
                Value::String(s) => {
                    if s.starts_with("cpe:2.3:") {
                        let parts: Vec<&str> = s.split(':').collect();
                        if parts.len() >= 6 {
                            let vendor = parts[3];
                            let product = parts[4];
                            let version = parts[5];
                            if !vendor.is_empty() && !product.is_empty() {
                                if !version.is_empty() && version != "*" {
                                    out.push(format!("{}:{}:{}", vendor, product, version));
                                } else {
                                    out.push(format!("{}:{}", vendor, product));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn derive_scheme(port: Option<i64>, has_http: bool, has_ssl: bool) -> String {
    match port {
        Some(443) => "https".to_string(),
        Some(80) => "http".to_string(),
        _ => {
            if has_http && has_ssl { "https".to_string() }
            else if has_http { "http".to_string() }
            else { "tcp".to_string() }
        }
    }
}

pub fn minimize_record(raw_json: &str) -> Option<Minimized> {
    let mut v: Value = serde_json::from_str(raw_json).ok()?;
    let obj = v.as_object_mut()?;

    // Honeypot short-circuit
    let tags_list: Vec<String> = obj
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if tags_list.iter().any(|t| t == "honeypot") {
        let tech = Value::Object(Map::from_iter(vec![("tags".to_string(), Value::Array(vec![Value::String("honeypot".into())]))]));
        return Some(Minimized { meta_json: "{}".to_string(), tech_json: tech.to_string(), html: None, scheme: "tcp".to_string(), sanitization_fixes: 0, html_hash_b3: None });
    }

    // Start with a shallow clone to manipulate and then split into meta/tech
    let mut meta_map: Map<String, Value> = obj.clone();
    let mut tech_map: Map<String, Value> = Map::new();

    // Extract and clean domains/hostnames before removing them
    let mut domains = Vec::new();
    let mut hostnames = Vec::new();

    if let Some(domains_val) = obj.get("domains") {
        if let Some(arr) = domains_val.as_array() {
            for domain in arr {
                if let Some(s) = domain.as_str() {
                    if !s.is_empty() && s != "null" {
                        domains.push(s.to_string());
                    }
                }
            }
        }
    }

    if let Some(hostnames_val) = obj.get("hostnames") {
        if let Some(arr) = hostnames_val.as_array() {
            for hostname in arr {
                if let Some(s) = hostname.as_str() {
                    if !s.is_empty() && s != "null" {
                        hostnames.push(s.to_string());
                    }
                }
            }
        }
    }

    // Remove noisy top-level keys from meta
    for k in [
        "vulns","vulnerability","cvss","cve","screenshot","location","id","crawler",
        "region","os","_shodan","asn","org","isp","hash","ip","opts","tags","cloud",
        "ip_str","port","transport","timestamp","cpe","cpe23","cpe.2.3","domains","hostnames"
    ] {
        meta_map.remove(k);
    }

    // Minimal path: handle HTTP (html, headers, favicon) and SSL essentials into tech
    let reducers: Vec<Box<dyn ProtocolReducer>> = vec![
        Box::new(HttpReducer),
        Box::new(SslReducer),
    ];
    let mut html_tuple: Option<(i64, String)> = None;
    for r in reducers {
        if html_tuple.is_none() {
            html_tuple = r.reduce(&mut meta_map, &mut tech_map);
        } else {
            let _ = r.reduce(&mut meta_map, &mut tech_map);
        }
    }

    // Protocol-aware drops: not needed in simple mode since meta will be empty

    // CPE aggregation only (no special cases)
    let cpes = normalize_cpe(obj);
    if !cpes.is_empty() {
        tech_map.insert("cpe".to_string(), Value::Array(cpes.into_iter().map(Value::String).collect()));
    }

    // Tags + cloud collapsing
    if !tags_list.is_empty() {
        tech_map.insert("tags".to_string(), Value::Array(tags_list.into_iter().map(Value::String).collect()));
    }
    if let Some(provider) = v
        .get("cloud")
        .and_then(|c| c.get("provider"))
        .and_then(|p| p.as_str())
    {
        let entry = tech_map.entry("tags".to_string()).or_insert(Value::Array(Vec::new()));
        if let Value::Array(arr) = entry {
            arr.push(Value::String(format!("cloud:{}", provider)));
        }
    }

    // Derive scheme
    let port_num = v.get("port").and_then(|p| p.as_i64());
    let has_http = v.get("http").is_some();
    let has_ssl = v.get("ssl").is_some();
    let scheme = derive_scheme(port_num, has_http, has_ssl);

    // BGP specific: drop meta.data on port 179
    if matches!(port_num, Some(179)) {
        meta_map.remove("data");
    }

    // Simple mode: do not include domains/hostnames in meta

    // Sanitize NULs and serialize
    // Simple mode: empty meta
    let mut meta_val = Value::Object(Map::new());
    let mut tech_val = Value::Object(tech_map);
    let mut sanitization_fixes = 0usize;
    sanitize_value(&mut meta_val, &mut sanitization_fixes);
    sanitize_value(&mut tech_val, &mut sanitization_fixes);
    let meta_json = meta_val.to_string();
    let tech_json = tech_val.to_string();

    // Compute BLAKE3 of cleaned HTML body if present
    let html_hash_b3 = html_tuple.as_ref().map(|(_, body)| blake3::hash(body.as_bytes()).to_hex().to_string());

    Some(Minimized { meta_json, tech_json, html: html_tuple, scheme, sanitization_fixes, html_hash_b3 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_base64() {
        let html = "<img src=\"data:image/png;base64,AAAA\">\u{0}";
        let out = strip_base64_data(html);
        assert!(out.contains("data:removed-base64-content"));
    }

    #[test]
    fn test_additional_html_cleaning() {
        // Test data:image removal
        let html_with_data_image = r#"<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="/>"#;
        let out = strip_base64_data(html_with_data_image);
        assert!(out.contains("data:image/removed;base64,removed"));

        // Test SVG removal
        let html_with_svg = r#"<div><svg width="100" height="100"><circle cx="50" cy="50" r="40"/></svg></div>"#;
        let out = strip_base64_data(html_with_svg);
        assert!(out.contains("<!-- SVG content removed -->"));

        // Test session ID removal
        let html_with_session = r#"<a href="/login?session-id=abc123">Login</a>"#;
        let out = strip_base64_data(html_with_session);
        assert!(out.contains("session_id=removed"));

        // Test whitespace normalization
        let html_with_whitespace = "<div>\n  \t  <p>Hello</p>\n</div>";
        let out = strip_base64_data(html_with_whitespace);
        assert!(!out.contains("\n  \t  "));

        // Test empty line removal
        let html_with_empty_lines = "<div>\n\n<p>Hello</p>\n\n</div>";
        let out = strip_base64_data(html_with_empty_lines);
        assert!(!out.contains("\n\n"));
    }

    #[test]
    fn test_minimize_basic() {
        let raw = r#"{
            "ip_str":"1.2.3.4","port":443,
            "http": {"html_hash": 123, "html": "<html>hi</html>", "headers": {"server":"nginx"}},
            "ssl": {"versions":["tls1.2"]}
        }"#;
        let m = minimize_record(raw).unwrap();
        assert_eq!(m.scheme, "https");
        assert!(m.meta_json.contains("html_hash"));
        assert!(m.tech_json.contains("http_server"));
        assert!(m.html.is_some());
        assert_eq!(m.sanitization_fixes, 0);
    }

    #[test]
    fn test_honeypot_short_circuit() {
        let raw = r#"{"tags":["honeypot"], "port": 22}"#;
        let m = minimize_record(raw).unwrap();
        assert_eq!(m.scheme, "tcp");
        assert_eq!(m.meta_json, "{}");
        assert!(m.tech_json.contains("honeypot"));
        assert!(m.html.is_none());
        assert_eq!(m.sanitization_fixes, 0);
    }

    #[test]
    fn test_bgpd_drops_data() {
        let raw = r#"{"port":179, "data":"SHOULD_BE_DROPPED", "ip_str":"1.1.1.1"}"#;
        let m = minimize_record(raw).unwrap();
        assert_eq!(m.scheme, "tcp");
        assert!(!m.meta_json.contains("SHOULD_BE_DROPPED"));
        assert_eq!(m.sanitization_fixes, 0);
    }

    #[test]
    fn test_squid_collapse() {
        let raw = r#"{
          "ip_str":"2.2.2.2",
          "port":3128,
          "http": {"headers": {"server":"squid/5.9"}},
          "cpe": ["other:values"]
        }"#;
        let m = minimize_record(raw).unwrap();
        assert!(m.meta_json == "{}" || m.meta_json == "{ }".replace(' ',""));
        assert!(m.tech_json.contains("squid-cache:squid"));
    }

    #[test]
    fn test_ssl_minimalization() {
        let raw = r#"{
          "port":443,
          "ssl": {"jarm": "0000000000000000000000000000000000000000000000000000000000000000", "ja3s":"abc", "versions":["tls1.2"],
                   "cipher": {"name":"TLS_AES_128", "version":"TLSv1.3", "bits":128},
                   "cert": {"sha256":"deadbeef", "expires": 123, "expired": false, "subject_cn":"cn", "issuer_cn":"icn", "extra":"x"}}
        }"#;
        let m = minimize_record(raw).unwrap();
        assert!(m.meta_json.contains("\"ssl\""));
        assert!(m.meta_json.contains("ja3s"));
        assert!(m.meta_json.contains("versions"));
        assert!(m.meta_json.contains("cipher"));
        assert!(m.meta_json.contains("cert"));
        assert!(!m.meta_json.contains("bits\""));
        assert!(!m.meta_json.contains("extra\""));
        assert!(!m.meta_json.contains("jarm\""));
    }

    #[test]
    fn test_cpe_normalization() {
        let raw = r#"{
           "port":80,
           "cpe.2.3":["cpe:2.3:a:nginx:nginx:1.20:*:*:*:*:*:*:*"],
           "cpe23": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
           "cpe": ["vendor:product:version"]
        }"#;
        let m = minimize_record(raw).unwrap();
        assert!(m.tech_json.contains("nginx:nginx:1.20"));
        assert!(m.tech_json.contains("apache:http_server"));
    }

    #[test]
    fn test_http_components_prune() {
        let raw = r#"{
           "port":80,
           "http": {"components": {"react": {"categories": ["js"], "version": "18"}}}
        }"#;
        let m = minimize_record(raw).unwrap();
        assert!(m.meta_json.contains("components"));
        assert!(!m.meta_json.contains("categories"));
    }
}


