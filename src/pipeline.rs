use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use zstd::stream::Decoder;
use std::time::Instant;
use chrono::{DateTime, Utc};
use serde_json::json;

// Trait for JSON output writers
trait JsonWriter: Write + Send + Sync {}
impl JsonWriter for File {}
impl JsonWriter for std::io::Stdout {}

use crate::db::Db;
use crate::types::{ShodanRecord, UpsertRecord};
use crate::minimizer::minimize_record;

pub struct Config {
    pub path: String,
    pub batch_size: usize,
    pub workers: usize,
    pub db_url: Option<String>,
    pub dry_run: bool,
    pub stats_every: u64,
    pub max_records: Option<usize>,
    pub json_output: bool,
    pub json_output_file: Option<String>,
}

pub async fn run(cfg: Config) -> Result<()> {
    let started_at = Instant::now();
    let wall_start: DateTime<Utc> = Utc::now();
    let db = if cfg.dry_run || cfg.json_output {
        None
    } else {
        Some(Db::connect(cfg.db_url.as_ref().ok_or_else(|| anyhow!("Database URL required when not using JSON output or dry run"))?).await?)
    };

    // JSON output writer for streaming
    let json_writer: Option<Arc<Mutex<Box<dyn JsonWriter>>>> = if cfg.json_output {
        Some(if let Some(output_path) = &cfg.json_output_file {
            Arc::new(Mutex::new(Box::new(File::create(output_path)?) as Box<dyn JsonWriter>))
        } else {
            Arc::new(Mutex::new(Box::new(std::io::stdout()) as Box<dyn JsonWriter>))
        })
    } else {
        None
    };

    // Channels
    let (tx_lines, rx_lines) = mpsc::channel::<String>(cfg.batch_size * 2);
    let (tx_recs, mut rx_recs) = mpsc::channel::<UpsertRecord>(cfg.batch_size * 2);

    // Reader task (blocking)
    let path = cfg.path.clone();
    let reader_jh = tokio::task::spawn_blocking(move || -> Result<()> {
        let file = File::open(&path).with_context(|| format!("open {}", path))?;
        let decoder = Decoder::new(file)?;
        let reader = BufReader::new(decoder);
        for line in reader.lines() {
            let line = line?;
            if !line.is_empty() {
                // blocking_send is valid from a blocking thread
                let _ = tx_lines.blocking_send(line);
            }
        }
        Ok(())
    });

    // Share a single receiver among workers
    let rx_shared = Arc::new(Mutex::new(rx_lines));

    // Worker pool
    for _ in 0..cfg.workers {
        let rx_shared_cloned = Arc::clone(&rx_shared);
        let tx_out = tx_recs.clone();
        tokio::spawn(async move {
            loop {
                // Pull one line; only recv is behind the mutex
                let line = {
                    let mut guard = rx_shared_cloned.lock().await;
                    match guard.recv().await {
                        Some(l) => l,
                        None => break,
                    }
                };

                // Parse directly into ShodanRecord to avoid lifetime issues
                #[cfg(feature = "simd")]
                let mut line_bytes = line.into_bytes();

                #[cfg(feature = "simd")]
                let rec: ShodanRecord = match simd_json::from_slice(&mut line_bytes) {
                    Ok(v) => v,
                    Err(_) => match serde_json::from_slice(&line_bytes) { Ok(v) => v, Err(_) => continue },
                };

                #[cfg(not(feature = "simd"))]
                let rec: ShodanRecord = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let target = rec
                    .ip_str
                    .map(|s| s.to_string())
                    .or_else(|| rec.ip.map(|x| std::net::Ipv4Addr::from(x as u32).to_string()))
                    .unwrap_or_else(|| "unknown".to_string());
                let port = rec.port.unwrap_or(0);
                if port == 0 || target == "unknown" {
                    continue;
                }

                // Minimize full record JSON for meta/tech/scheme/html
                let minimized = {
                    #[cfg(feature = "simd")]
                    { minimize_record(std::str::from_utf8(&line_bytes).unwrap_or("")) }
                    #[cfg(not(feature = "simd"))]
                    { minimize_record(&line) }
                };
                let Some(minimized) = minimized else { continue };

                let _ = tx_out
                    .send(UpsertRecord {
                        target,
                        port,
                        scheme: minimized.scheme,
                        meta_json: minimized.meta_json,
                        tech_json: minimized.tech_json,
                        html_fk: minimized.html.as_ref().map(|(h, _)| *h),
                        html_body: minimized.html.as_ref().map(|(_, b)| b.clone()),
                        sanitization_fixes: minimized.sanitization_fixes,
                    })
                    .await;
            }
        });
    }
    drop(tx_recs);

    // Batcher / flusher
    let mut batcher = Batcher::new(cfg.batch_size);
    let mut stats = Stats::default();
    let mut tick = interval(Duration::from_secs(cfg.stats_every));
    let mut processed_total: usize = 0;

    loop {
        tokio::select! {
            maybe = rx_recs.recv() => {
                // Exit cleanly when all senders are dropped and channel is drained
                let Some(u) = maybe else { break };
                stats.parsed += 1;
                processed_total += 1;

                // For JSON output, stream records immediately
                if let Some(writer) = &json_writer {
                    if let Err(e) = batcher.stream_json_record(writer, &u).await {
                        tracing::error!("JSON stream error: {e}");
                    }
                } else {
                    // For database mode, use batching, but DO NOT store HTML in Postgres anymore
                    // Only enqueue asset_port rows; skip html/link rows entirely
                    batcher.ap_rows.push((u.target, u.port, u.scheme, u.meta_json, u.tech_json));

                    if batcher.should_flush() {
                        if let Some(db) = &db {
                            if let Err(e) = batcher.flush(db).await {
                                tracing::error!("flush error: {e}");
                            }
                        } else {
                            batcher.dry_flush();
                        }
                        batcher.reset_caps();
                    }
                }

                stats.sanitization_fixes += u.sanitization_fixes;
                if let Some(max) = cfg.max_records {
                    if processed_total >= max { break; }
                }
            }
            _ = tick.tick() => {
                if cfg.dry_run {
                    // Always visible progress even without RUST_LOG configured
                    println!(
                        "[dry-run] parsed={}, processed_total={}, html_distinct={}, sanitization_fixes={}, pending_ap={}, pending_html={}, pending_links={}",
                        stats.parsed, processed_total, stats.sanitization_fixes,
                        stats.html_distinct,
                        batcher.ap_rows.len(),
                        batcher.html_rows.len(),
                        batcher.link_rows.len(),
                    );
                } else if cfg.json_output {
                    // JSON output progress
                    println!(
                        "[json-output] parsed={}, processed_total={}, sanitization_fixes={}, pending_ap={}",
                        stats.parsed, processed_total, stats.sanitization_fixes,
                        batcher.ap_rows.len(),
                    );
                } else {
                    tracing::info!(
                        parsed = stats.parsed,
                        processed_total = processed_total,
                        html_distinct = stats.html_distinct,
                        sanitization_fixes = stats.sanitization_fixes,
                        pending_ap = batcher.ap_rows.len(),
                        pending_html = batcher.html_rows.len(),
                        pending_links = batcher.link_rows.len(),
                        "ingest stats"
                    );
                }
            }
        }
        if let Some(max) = cfg.max_records { if processed_total >= max { break; } }
    }

    if let Some(db) = &db {
        batcher.flush(db).await?;
        let elapsed = started_at.elapsed();
        tracing::info!(
            parsed = stats.parsed,
            html_distinct = stats.html_distinct,
            elapsed_secs = elapsed.as_secs_f64(),
            started_at = %wall_start.to_rfc3339(),
            completed_at = %Utc::now().to_rfc3339(),
            "ingestion complete"
        );
    } else if let Some(writer) = &json_writer {
        // Final JSON flush
        batcher.flush_json(writer).await?;
        let elapsed = started_at.elapsed();
        println!(
            "[json-output] complete: parsed={}, unique_html={}, elapsed_secs={:.3}, started_at={}, completed_at={}",
            stats.parsed,
            stats.html_distinct,
            elapsed.as_secs_f64(),
            wall_start.to_rfc3339(),
            Utc::now().to_rfc3339()
        );
    } else {
        // Final dry-run flush
        batcher.dry_flush();
        let elapsed = started_at.elapsed();
        println!(
            "[dry-run] complete: parsed={}, unique_html={}, elapsed_secs={:.3}, started_at={}, completed_at={}",
            stats.parsed,
            stats.html_distinct,
            elapsed.as_secs_f64(),
            wall_start.to_rfc3339(),
            Utc::now().to_rfc3339()
        );
    }
    reader_jh.await??;
    Ok(())
}

use std::collections::HashMap;

#[derive(Default)]
struct Stats {
    parsed: usize,
    html_distinct: usize,
    sanitization_fixes: usize,
}

struct Batcher {
    pub ap_rows: Vec<(String, i32, String, String, String)>, // (target, port, scheme, meta_json, tech_json)
    pub html_rows: HashMap<i64, String>, // shodan_hash -> content
    pub link_rows: Vec<(String, i32, String, i64)>, // (target, port, scheme, fk)
    cap: usize,
}

impl Batcher {
    fn new(cap: usize) -> Self {
        Self {
            ap_rows: Vec::with_capacity(cap),
            html_rows: HashMap::with_capacity(cap / 2),
            link_rows: Vec::with_capacity(cap / 2),
            cap,
        }
    }
    fn reset_caps(&mut self) {
        if self.ap_rows.capacity() > self.cap * 2 {
            self.ap_rows.shrink_to(self.cap);
        }
        if self.html_rows.capacity() > self.cap {
            self.html_rows.shrink_to(self.cap);
        }
        if self.link_rows.capacity() > self.cap {
            self.link_rows.shrink_to(self.cap);
        }
    }
    fn should_flush(&self) -> bool {
        self.ap_rows.len() >= self.cap
            || self.html_rows.len() >= self.cap / 2
            || self.link_rows.len() >= self.cap / 2
    }
    async fn flush(&mut self, db: &Db) -> Result<()> {
        // Pre-flush health check (non-fatal)
        let _ = db.health_check().await;

        // Grouped flush: HTML -> assets -> merge -> links
        if !self.html_rows.is_empty() {
            let mut rows: Vec<(i64, String)> = Vec::with_capacity(self.html_rows.len());
            for (k, v) in self.html_rows.drain() { rows.push((k, v)); }
            db.copy_raw_html(&rows).await?;
        }
        if !self.ap_rows.is_empty() {
            let rows = std::mem::take(&mut self.ap_rows);
            db.copy_staging_asset_ports(&rows).await?;
        }
        // Ensure main table has rows before inserting FK-dependent links
        db.merge_staging().await?;
        if !self.link_rows.is_empty() {
            let rows = std::mem::take(&mut self.link_rows);
            db.copy_asset_port_html(&rows).await?;
        }
        Ok(())
    }

    fn csv_escape(s: &str) -> String {
        // strip NULs and escape quotes for CSV preview
        s.replace('\u{0}', "").replace('"', "\"\"")
    }

    fn dry_flush(&mut self) {
        if self.ap_rows.is_empty() && self.html_rows.is_empty() && self.link_rows.is_empty() {
            return;
        }

        // Summaries
        let ap_n = self.ap_rows.len();
        let html_n = self.html_rows.len();
        let link_n = self.link_rows.len();

        println!("\n==== DRY-RUN FLUSH ====");
        println!("Would COPY:");
        println!("  raw_html            : {html_n} rows");
        println!("  staging_asset_ports : {ap_n} rows");
        println!("  asset_port_html     : {link_n} rows");

        // Samples (up to 2 rows each)
        if html_n > 0 {
            println!("-- raw_html (csv preview)");
            for (i, (h, body)) in self.html_rows.iter().take(2).enumerate() {
                let body_preview = Self::csv_escape(body);
                let preview = if body_preview.len() > 120 { &body_preview[..120] } else { &body_preview };
                println!("  {i}: {h},\"{preview}...\"");
            }
        }
        if ap_n > 0 {
            println!("-- staging_asset_ports (csv preview)");
            for (i, (t, p, s, m, te)) in self.ap_rows.iter().take(2).enumerate() {
                let t = Self::csv_escape(t);
                let s = Self::csv_escape(s);
                let m = Self::csv_escape(m);
                let te = Self::csv_escape(te);
                println!("  {i}: \"{t}\",{p},\"{s}\",\"{m}\",\"{te}\"");
            }
        }
        if link_n > 0 {
            println!("-- asset_port_html (csv preview)");
            for (i, (t, p, s, fk)) in self.link_rows.iter().take(2).enumerate() {
                let t = Self::csv_escape(t);
                let s = Self::csv_escape(s);
                println!("  {i}: \"{t}\",{p},\"{s}\",{fk}");
            }
        }

        println!("======================\n");

        // Discard current buffers as if they were flushed
        self.html_rows.clear();
        self.ap_rows.clear();
        self.link_rows.clear();
    }

    async fn stream_json_record(&mut self, writer: &Arc<Mutex<Box<dyn JsonWriter>>>, record: &UpsertRecord) -> Result<()> {
        let mut guard = writer.lock().await;

        // Create a clean JSON record with only essential fields
        let mut record_json = json!({
            "target": record.target,
            "port": record.port,
            "scheme": record.scheme
        });

        // Parse and filter meta JSON
        if let Ok(meta_val) = serde_json::from_str::<serde_json::Value>(&record.meta_json) {
            if let Some(meta_obj) = meta_val.as_object() {
                let filtered_meta = filter_meta_fields(meta_obj);
                if !filtered_meta.is_empty() {
                    record_json["meta"] = serde_json::Value::Object(filtered_meta);
                }
            }
        }

        // Parse and filter tech JSON
        if let Ok(tech_val) = serde_json::from_str::<serde_json::Value>(&record.tech_json) {
            if let Some(tech_obj) = tech_val.as_object() {
                let filtered_tech = filter_tech_fields(tech_obj);
                if !filtered_tech.is_empty() {
                    record_json["tech"] = serde_json::Value::Object(filtered_tech);
                }
            }
        }

        // Output HTML content if present
        if let (Some(html_hash), Some(html_content)) = (record.html_fk, &record.html_body) {
            let html_record = json!({
                "type": "html",
                "hash": html_hash,
                "content": html_content,
                "target": record.target,
                "port": record.port
            });
            writeln!(guard, "{}", html_record)?;
        }

        // Output the main record
        writeln!(guard, "{}", record_json)?;
        guard.flush()?;

        Ok(())
    }

    async fn flush_json(&mut self, writer: &Arc<Mutex<Box<dyn JsonWriter>>>) -> Result<()> {
        if self.ap_rows.is_empty() && self.html_rows.is_empty() {
            return Ok(());
        }

        let mut guard = writer.lock().await;

        // Output asset_ports records as JSON
        for (target, port, scheme, meta_json, tech_json) in std::mem::take(&mut self.ap_rows) {
            let record = json!({
                "target": target,
                "port": port,
                "scheme": scheme,
                "meta": serde_json::from_str::<serde_json::Value>(&meta_json).unwrap_or(serde_json::Value::Null),
                "tech": serde_json::from_str::<serde_json::Value>(&tech_json).unwrap_or(serde_json::Value::Null)
            });

            writeln!(guard, "{}", record)?;
        }

        // Output HTML records as separate JSON objects
        for (hash, content) in std::mem::take(&mut self.html_rows) {
            let html_record = json!({
                "type": "html",
                "hash": hash,
                "content": content
            });

            writeln!(guard, "{}", html_record)?;
        }

        // Clear link rows as they're not needed for JSON output
        self.link_rows.clear();

        guard.flush()?;
        Ok(())
    }
}

// Field filtering functions for clean JSON output
fn filter_meta_fields(meta: &serde_json::Map<String, serde_json::Value>) -> serde_json::Map<String, serde_json::Value> {
    let mut filtered = serde_json::Map::new();

    // Only include HTTP if it has meaningful content
    if let Some(http_val) = meta.get("http") {
        if let Some(http_obj) = http_val.as_object() {
            let mut filtered_http = serde_json::Map::new();

            // Keep only essential HTTP fields
            let essential_fields = ["status", "server", "title", "host", "location"];
            for &field in &essential_fields {
                if let Some(val) = http_obj.get(field) {
                    // Skip null/empty values
                    if !val.is_null() && !(val.is_string() && val.as_str().unwrap_or("").is_empty()) {
                        filtered_http.insert(field.to_string(), val.clone());
                    }
                }
            }

            // Keep components if present and not empty
            if let Some(components) = http_obj.get("components") {
                if let Some(comp_obj) = components.as_object() {
                    if !comp_obj.is_empty() {
                        filtered_http.insert("components".to_string(), components.clone());
                    }
                }
            }

            if !filtered_http.is_empty() {
                filtered.insert("http".to_string(), serde_json::Value::Object(filtered_http));
            }
        }
    }

    // Keep SSL if present
    if let Some(ssl_val) = meta.get("ssl") {
        filtered.insert("ssl".to_string(), ssl_val.clone());
    }

    filtered
}

fn filter_tech_fields(tech: &serde_json::Map<String, serde_json::Value>) -> serde_json::Map<String, serde_json::Value> {
    let mut filtered = serde_json::Map::new();

    // Keep all tech fields but filter out empty arrays/objects
    for (key, value) in tech {
        match value {
            serde_json::Value::Array(arr) if arr.is_empty() => continue,
            serde_json::Value::Object(obj) if obj.is_empty() => continue,
            serde_json::Value::String(s) if s.is_empty() => continue,
            _ => {
                filtered.insert(key.clone(), value.clone());
            }
        }
    }

    filtered
}

// minimization helpers live in crate::minimizer
