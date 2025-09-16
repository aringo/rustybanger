use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use zstd::stream::Decoder;

#[derive(Parser, Debug, Clone)]
struct Args {
    /// Path to input NDJSON (.json or .json.zst). If omitted, read from stdin
    #[arg(long)]
    input: Option<String>,
    /// Limit number of lines to process
    #[arg(long)]
    limit: Option<usize>,
}

fn open_reader(path: &str) -> Result<Box<dyn BufRead>> {
    let f = File::open(path).with_context(|| format!("open {}", path))?;
    if path.ends_with(".zst") {
        let dec = Decoder::new(f)?;
        Ok(Box::new(BufReader::new(dec)))
    } else {
        Ok(Box::new(BufReader::new(f)))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let reader: Box<dyn BufRead> = match args.input.as_deref() {
        Some(p) => open_reader(p)?,
        None => Box::new(BufReader::new(io::stdin())),
    };

    let mut count = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let minimized = shodan_ingest::minimizer::minimize_record(&line);
        if let Some(m) = minimized {
            let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            let target = v.get("ip_str").and_then(|x| x.as_str()).unwrap_or("");
            let port = v.get("port").and_then(|x| x.as_i64()).unwrap_or(0);
            let html_len = m.html.as_ref().map(|(_, b)| b.len()).unwrap_or(0);
            let out = serde_json::json!({
                "target": target,
                "port": port,
                "scheme": m.scheme,
                "meta": serde_json::from_str::<Value>(&m.meta_json).ok(),
                "tech": serde_json::from_str::<Value>(&m.tech_json).ok(),
                "html_hash": m.html.as_ref().map(|(h, _)| h),
                "html_len": html_len,
                "sanitization_fixes": m.sanitization_fixes,
            });
            println!("{}", serde_json::to_string(&out)?);
        }
        count += 1;
        if let Some(max) = args.limit { if count >= max { break; } }
    }
    Ok(())
}





