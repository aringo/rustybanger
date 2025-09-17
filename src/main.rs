mod pipeline;
mod db;
mod types;
mod minimizer;

use clap::Parser;
use anyhow::{Result, Context};
use tracing_subscriber::EnvFilter;
use std::fs;

#[derive(Parser, Debug, Clone)]
struct Args {
    /// Path to .zst NDJSON file (one JSON record per line)
    #[arg(long)]
    input: String,
    /// Batch size (rows per flush)
    #[arg(long, default_value_t = 10000)]
    batch: usize,
    /// Worker count
    #[arg(long, default_value_t = 12)]
    workers: usize,
    /// Postgres connection string (postgres://...) - not required for JSON output
    #[arg(long, env = "DATABASE_URL")]
    db_url: Option<String>,
    /// Dry run: parse/normalize only (no DB writes)
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    /// Stats interval seconds
    #[arg(long, default_value_t = 5)]
    stats_every: u64,
    /// Max records to process (None = all)
    #[arg(long)]
    max_records: Option<usize>,
    /// Output JSON instead of inserting to database
    #[arg(long, default_value_t = false)]
    json_output: bool,
    /// JSON output file path (default: stdout)
    #[arg(long)]
    json_output_file: Option<String>,
    /// Dot-notation allowlist of fields to keep from raw Shodan JSON (repeatable)
    #[arg(long = "keep")]
    keep: Vec<String>,
    /// File with dot-notation fields to keep (newline-separated or JSON array)
    #[arg(long = "keep-file")]
    keep_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Load keep-file if provided
    let mut keep_fields = args.keep.clone();
    if let Some(path) = &args.keep_file {
        let content = fs::read_to_string(path).with_context(|| format!("read keep-file {}", path))?;
        // Try JSON array first
        let parsed_json: Result<Vec<String>, _> = serde_json::from_str(&content);
        let mut from_file: Vec<String> = match parsed_json {
            Ok(v) => v,
            Err(_) => {
                // Fallback: newline-separated, trim and skip empties/comments
                content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|s| s.to_string())
                    .collect()
            }
        };
        keep_fields.append(&mut from_file);
    }

    pipeline::run(pipeline::Config {
        path: args.input,
        batch_size: args.batch,
        workers: args.workers,
        db_url: args.db_url,
        dry_run: args.dry_run,
        stats_every: args.stats_every,
        max_records: args.max_records,
        json_output: args.json_output,
        json_output_file: args.json_output_file,
        keep_fields,
    }).await
}
