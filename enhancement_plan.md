Current plan is to make a `minimizer` module in Rust that mirrors your Python rules, call it from `pipeline.rs` per record, and sanitize JSON strings before COPY. No schema changes.

What to implement in rusty_banger
- New module `src/minimizer.rs` with:
  - Public API:
    - `fn minimize_record(raw_json: &str) -> Option<Minimized>` returning:
      - `meta_json: String` (minimized banner)
      - `tech_json: String` (fingerprints, tags)
      - `html: Option<(i64 /*html_hash*/, String /*cleaned html*/)>`
      - `scheme: String` (http/https/tcp)
    - `fn strip_base64_data(html: &str) -> String` (already present; move here)
  - Logic (mirror Python rules):
    - Drop top-level noisy keys: `vulns, vulnerability, cvss, cve, screenshot, location, id, crawler, region, os`
    - Drop/move meta keys: `_shodan, asn, org, isp, hash, ip, opts, tags, cloud, ip_str, port, transport, timestamp, cpe, cpe23, cpe.2.3`
    - HTTP:
      - Keep `http.data` unless it contains “Incapsula incident ID: 0-”
      - Drop `html, robots*, securitytxt*, sitemap*, dom_hash, headers_hash, title_hash, server_hash`
      - Reduce `http.favicon` to scalar hash
      - Drop `http.location == "/"` and empty `http.redirects`
      - In `http.components.*` drop `categories`, prune empties
    - HTML: if `http.html` and `http.html_hash` exist, strip base64 and emit `(hash, body)`
    - SSL:
      - Keep `ja3s`
      - Keep `jarm` when not all-zero
      - Keep `versions`, minimal `cipher {name,version}`, `cert {sha256,expires,expired,subject_cn,issuer_cn}`
    - CPE:
      - Normalize from `cpe.2.3` then `cpe23` then `cpe` into `tech.cpe` of form `vendor:product(:version)`
    - Tags:
      - Build `tech.tags`: copy tags; collapse cloud to `cloud:<Provider>` and drop plain `cloud` if provider present
      - Honeypot: if `tags` contains `honeypot`, force `meta = {}`, `tech = {"tags":["honeypot"]}` only
    - Protocol-aware drops:
      - If `http`/`ssh`/`isakmp`/`smb` exists: drop top-level `data`
      - `ssh`: reduce to `{"hassh": "..."}`
      - `isakmp`: drop `isakmp.data` and prune if empty
      - `smb`: drop `smb.raw` and prune if empty
      - BGP (port 179): drop `meta.data`
    - Squid collapse:
      - Detect by cpe or `server` header `squid/x.y`
      - Set `meta = {}` and set `tech.cpe = ["squid-cache:squid:<ver>"| "squid-cache:squid"]`
      - Drop `tech.product`, `tech.version`, `tech.http_server` for squid
    - Derive scheme:
      - 443 -> `https`, 80 -> `http`, else `https` if `meta.http` and `meta.ssl` else `http` if `meta.http` else `tcp`
    - Sanitize:
      - Recursively strip NULs from all strings in `meta` and `tech` before stringify
- Update `src/pipeline.rs`
  - Parse each line into a `serde_json::Value` (use existing simd-json fast path; keep typed minimal struct only if needed for fast drop)
  - Call `minimizer::minimize_record(&line)`; if `None`, continue
  - Use returned `meta_json`, `tech_json`, `scheme`, and optional `(hash, html)` to populate:
    - `ap_rows.push((target, port, scheme, meta_json, tech_json))`
    - If html present: `html_rows.insert(hash, html_body)` and `link_rows.push((target, port, scheme, hash))`
- Update `src/db.rs`
  - Ensure CSV field sanitizer also strips NULs from `meta`, `tech` JSON strings (the sanitizer exists; use it on all fields you copy)
  - Keep COPY order HTML -> asset_ports -> merge -> links (already implemented)
- Crates
  - Already present: `regex`, `once_cell`, `serde_json`, optionally keep `simd-json`
  - No schema changes required

Build and run
```bash
cd /Volumes/bulk/Repos/shodanclient/rusty_banger
cargo build --release
RUST_LOG=info cargo run --release --features simd -- --input /Volumes/bulk/Repos/shodanclient/2025-08-04T08:00:00.json.zst --batch 10000 --workers 12 --db-url $DATABASE_URL
```

Validate
```bash
cd /Volumes/bulk/Repos/shodanclient/python_tools
python -m shodan_explorer.cli summary
python -m shodan_explorer.cli large-html --limit 5 --show-sample
python -m shodan_explorer.cli analyze --column meta --top-k 10
```


### Status update

- Accomplished
  - Implemented `src/minimizer.rs` with:
    - `minimize_record(&str) -> Option<Minimized>` returning `meta_json`, `tech_json`, `html: Option<(i64, String)>`, and `scheme`.
    - `strip_base64_data(&str) -> String` with precompiled regexes.
  - Ported core rules from Python/plan:
    - HTTP reductions (remove heavy fields, favicon hash scalar, redirects/location pruning, Incapsula noise drop, components pruning) with HTML body extraction when `html` and `html_hash` exist and `meta.http.body_hash` back-reference.
    - SSL minimal view (keep `ja3s`, non-zero `jarm`, `versions`, minimal `cipher`, minimal `cert`).
    - CPE normalization into `tech.cpe` with deduplication.
    - Tags/cloud: propagate tags and append `cloud:<Provider>` when present.
    - Honeypot short-circuit: `meta = {}` and `tech = {"tags":["honeypot"]}`.
    - Protocol-aware drops: remove top-level `data` when protocol blocks exist; prune `ssh`, `isakmp`, `smb` fields.
    - Squid collapse: detect via `server` header or cpe, clear `meta`, and set `tech.cpe` appropriately.
    - Scheme derivation consistent with Python.
    - Recursive sanitization of NULs in all strings before stringify.
  - Integrated minimizer in `src/pipeline.rs` worker path; removed duplicated base64/meta helpers.
  - Preserved COPY order: HTML -> `staging_asset_ports` -> merge -> links; continued to escape and strip NULs for CSV COPY.
  - Exposed a `lib` target (`src/lib.rs`) to allow benches and reuse.
  - Added Criterion benchmark `benches/minimizer_bench.rs`; enabled via Cargo `[bench]` entry. Build and bench are green.

- Next up
  - Extend rule coverage to full parity with Python plan (BGP port 179 meta.data drop already noted; add tests to verify all branches).
  - Introduce a modular reducer pattern:
    - `trait ProtocolReducer { fn reduce(meta: &mut Value, tech: &mut Map<String, Value>) }` and register per-protocol reducers (`http`, `ssl`, `ssh`, `isakmp`, `smb`).
  - Tests
    - Unit tests per rule (honeypot, squid, ssl fields, Incapsula case, favicon hash, redirects pruning, components pruning, CPE normalization, scheme derivation, NUL stripping).
    - Golden tests: compare a sampled set against Python output for equivalence of key fields (`scheme`, presence of `meta.http.body_hash`, shape of `tech`, `tech.cpe`).
  - CLI ergonomics
    - Add `--max-records` to mirror Python and allow controlled sampling/benching.
    - Progress/metrics counters (records seen, distinct HTML, sanitization fixes) surfaced periodically.
  - Benchmarks
    - Keep Criterion micro-bench of `minimize_record` (existing).
    - Add a streaming benchmark that samples N lines from `/Volumes/bulk/Repos/shodanclient/2025-08-04T08:00:00.json.zst` and runs the minimizer to measure end-to-end throughput without DB I/O.

### Benchmarks

- Run existing minimizer benchmark
```bash
cd /Volumes/bulk/Repos/shodanclient/rusty_banger
cargo bench --bench minimizer_bench
```

- Dry-run ingest for throughput using the large example file (no DB writes)
```bash
cd /Volumes/bulk/Repos/shodanclient/rusty_banger
RUST_LOG=info cargo run --release --features simd -- --input /Volumes/bulk/Repos/shodanclient/2025-08-04T08:00:00.json.zst --batch 10000 --workers 12 --db-url $DATABASE_URL --dry-run
```

- Planned streaming benchmark (to be implemented)
```bash
# Streams M lines from /Volumes/bulk/Repos/shodanclient/2025-08-04T08:00:00.json.zst
# and measures minimizer throughput with Criterion. Will land as benches/stream_minimize_bench.rs.
```

