# JSON Output Mode

The application now supports outputting processed data as JSON instead of inserting into a database. This is useful for:

- Testing and validation before database insertion
- Data analysis and processing pipelines
- Integration with other tools that consume JSON data
- Debugging and inspection of processed records

## Usage

### Basic JSON Output (to stdout)
```bash
cargo run --release --features simd -- \
  --input /path/to/data.json.zst \
  --json-output \
  --batch 1000 \
  --workers 4
```

### JSON Output to File
```bash
cargo run --release --features simd -- \
  --input /path/to/data.json.zst \
  --json-output \
  --json-output-file /path/to/output.json \
  --batch 1000 \
  --workers 4
```

### Limited Records (for testing)
```bash
cargo run --release --features simd -- \
  --input /path/to/data.json.zst \
  --json-output \
  --max-records 100 \
  --batch 50
```

## Output Format

The JSON output contains two types of records:

### 1. Asset Port Records
Each processed Shodan record becomes an asset port record (includes `html_hash_b3` when an HTML body exists):
```json
{
  "target": "192.168.1.1",
  "port": 80,
  "scheme": "http",
  "html_hash_b3": "aa1f...c9",
  "meta": {},
  "tech": {
    "tags": ["web"]
  }
}
```

### 2. HTML Records (when present)
HTML content is output as separate records. The hash uses hex-encoded BLAKE3 of the cleaned body and is the only hash emitted:
```json
{
  "type": "html",
  "hash_b3": "aa1f...c9",
  "content": "<html><body>...</body></html>"
}
```

## Command Line Options

- `--json-output`: Enable JSON output mode (disables database operations)
- `--json-output-file <path>`: Write JSON to specified file (default: stdout)
- `--max-records <n>`: Limit processing to N records (useful for testing)
- `--batch <n>`: Batch size for processing (default: 10000)
- `--workers <n>`: Number of worker threads (default: 12)

## Notes

- When `--json-output` is used, database operations are completely bypassed
- Progress is reported to stderr, JSON data goes to stdout or specified file
- The output format matches the minimized data structure used internally
- HTML records are deduplicated by hash (same as database mode)
- All the same minimization rules apply as in database mode

