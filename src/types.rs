use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Debug, Deserialize)]
pub struct HttpBlock<'a> {
    #[serde(borrow)]
    pub html: Option<&'a str>,
    pub html_hash: Option<i64>,
    #[serde(borrow)]
    pub headers: Option<&'a RawValue>,
}

#[derive(Debug, Deserialize)]
pub struct ShodanRecord<'a> {
    #[serde(borrow)]
    pub ip_str: Option<&'a str>,
    pub ip: Option<u64>,
    pub port: Option<i32>,
    #[serde(borrow)]
    pub transport: Option<&'a str>,
    #[serde(borrow)]
    pub http: Option<HttpBlock<'a>>,
}

#[derive(Debug)]
pub struct UpsertRecord {
    pub target: String,
    pub port: i32,
    pub scheme: String,
    pub meta_json: String,
    pub tech_json: String,
    pub html_fk: Option<i64>,
    pub html_body: Option<String>,
    pub sanitization_fixes: usize,
}
