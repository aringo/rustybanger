# shodan_ingest (Rust, fast)

High-throughput Shodan .zst NDJSON ingester:
- Streams `.zst`
- SIMD-JSON fast-path (enable with `--features simd`)
- Multi-worker parsing
- COPY-only bulk loads
- Sparse HTML side table

## Prereqs

- Rust 1.75+
- Postgres 14+
- Load the schema (matches `init.sql`)

```sql
-- Schema
CREATE SCHEMA IF NOT EXISTS asm;

-- Raw HTML blobs keyed by Shodan's html_hash
CREATE TABLE IF NOT EXISTS asm.raw_html (
  shodan_hash BIGINT PRIMARY KEY,
  content     TEXT NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Unlogged staging for raw_html
CREATE UNLOGGED TABLE IF NOT EXISTS asm.staging_raw_html (
  shodan_hash BIGINT NOT NULL,
  content     TEXT NOT NULL
);

-- Staging for asset ports (ingest goes here first)
CREATE TABLE IF NOT EXISTS asm.staging_asset_ports (
  target     TEXT NOT NULL,
  port       INT  NOT NULL,
  scheme     TEXT NOT NULL,
  meta       JSONB NOT NULL DEFAULT '{}',
  tech       JSONB NOT NULL DEFAULT '{}'
);

-- Main normalized table
CREATE TABLE IF NOT EXISTS asm.asset_ports (
  target     TEXT NOT NULL,
  port       INT  NOT NULL,
  scheme     TEXT NOT NULL,
  meta       JSONB NOT NULL DEFAULT '{}',
  tech       JSONB NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (target, port, scheme)
);

-- Sparse relation: exists only when HTML exists
-- Note: intentionally no FK to raw_html to keep link insert fast/loose
CREATE TABLE IF NOT EXISTS asm.asset_port_html (
  target     TEXT NOT NULL,
  port       INT  NOT NULL,
  scheme     TEXT NOT NULL,
  shodan_fk  BIGINT NOT NULL,
  PRIMARY KEY (target, port, scheme)
);

-- Unlogged staging for asset_port_html
CREATE UNLOGGED TABLE IF NOT EXISTS asm.staging_asset_port_html (
  target    TEXT NOT NULL,
  port      INT  NOT NULL,
  scheme    TEXT NOT NULL,
  shodan_fk BIGINT NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_asset_ports_target ON asm.asset_ports(target);
CREATE INDEX IF NOT EXISTS idx_asset_ports_port   ON asm.asset_ports(port);
CREATE INDEX IF NOT EXISTS idx_asset_ports_meta   ON asm.asset_ports USING GIN(meta);
CREATE INDEX IF NOT EXISTS idx_asset_ports_tech   ON asm.asset_ports USING GIN(tech);
CREATE INDEX IF NOT EXISTS idx_asset_port_html_fk ON asm.asset_port_html (shodan_fk);

-- Merge functions (truncated here; see init.sql for full bodies)
-- SELECT asm.merge_staging_raw_html();
-- SELECT asm.merge_staging_asset_ports();
-- SELECT asm.merge_staging_asset_port_html();
```

## Start the database

```bash
docker-compose up -d

docker-compose ps

# Verify
docker exec -it shodan-postgres psql -U postgres -d shodan_db -c "\\dt asm.*"
```

## Run

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/shodan_db

# Full ingest
export RUST_LOG=INFO
cargo run --release --features simd -- \
  --input /Volumes/bulk/Repos/shodanclient/2025-08-04T08:00:00.json.zst \
  --batch 10000 \
  --workers 12 \
  --db-url $DATABASE_URL
```

## JSON Output Mode

For testing and validation, you can output processed data as JSON instead of inserting into the database:

```bash
# Output to stdout
cargo run --release --features simd -- \
  --input /path/to/data.json.zst \
  --json-output \
  --batch 1000

# Output to file
cargo run --release --features simd -- \
  --input /path/to/data.json.zst \
  --json-output \
  --json-output-file output.json \
  --max-records 100
```

See [JSON_OUTPUT.md](JSON_OUTPUT.md) for detailed documentation.

## Resetting data (truncate tables)

If you need to clear the data without psql CLI, you can use the Python helper (see `python_tools`):

```bash
cd python_tools
# Truncate ASM tables (asset_ports, asset_port_html, raw_html + staging)
python -m shodan_explorer.cli truncate-asm
```

Or SQL:

```sql
TRUNCATE asm.staging_asset_port_html,
         asm.staging_raw_html,
         asm.asset_port_html,
         asm.asset_ports,
         asm.raw_html
RESTART IDENTITY;
```
