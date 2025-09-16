use anyhow::{anyhow, Result};
use tokio_postgres::{Client, NoTls};
use futures_util::SinkExt; // for CopyInSink::send
use bytes::Bytes;
use std::pin::pin;
use tokio::time::{sleep, Duration};

pub struct Db {
    pub client: Client,
}

impl Db {
    pub async fn connect(url: &str) -> Result<Self> {
        let (client, conn) = tokio_postgres::connect(url, NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("postgres connection error: {e}");
            }
        });
        client
            .batch_execute(
                "SET application_name='shodan_ingest'; \
                 SET statement_timeout='0'; \
                 SET idle_in_transaction_session_timeout='0'; \
                 SET synchronous_commit='off';",
            )
            .await?;
        Ok(Self { client })
    }

    pub async fn health_check(&self) -> Result<()> {
        self.client.batch_execute("SELECT 1").await?;
        Ok(())
    }

    fn sanitize_field(s: &str) -> String {
        // Strip NUL and escape quotes for CSV; we do not add surrounding quotes here
        let no_nul = s.replace('\u{0}', "");
        no_nul.replace('"', "\"\"")
    }

    async fn with_retry<F, Fut>(&self, mut op: F, label: &str) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let mut delay = Duration::from_millis(250);
        let mut attempts = 0usize;
        let max_attempts = 5usize;
        loop {
            attempts += 1;
            match op().await {
                Ok(()) => return Ok(()),
                Err(e) if attempts < max_attempts => {
                    eprintln!("{label} failed (attempt {attempts}): {e}; retrying in {:?}", delay);
                    sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_secs(5));
                }
                Err(e) => return Err(anyhow!("{label} failed after {attempts} attempts: {e}")),
            }
        }
    }

    pub async fn copy_raw_html(&self, rows: &[(i64, String)]) -> Result<()> {
        if rows.is_empty() { return Ok(()); }
        let chunk = 25_000usize; // keep moderate to avoid huge transactions
        for part in rows.chunks(chunk) {
            self.health_check().await.ok();
            let op = || async {
                // Copy into persistent UNLOGGED staging to avoid temp-table lifecycle issues
                let sink = self.client
                    .copy_in("COPY asm.staging_raw_html (shodan_hash, content) FROM STDIN WITH (FORMAT csv)")
                    .await?;
                let mut sink = pin!(sink);
                for (h, body) in part {
                    let mut line = String::new();
                    line.push_str(&h.to_string());
                    line.push(',');
                    line.push('"');
                    // sanitize: strip NULs and escape quotes
                    let sanitized = Self::sanitize_field(body);
                    line.push_str(&sanitized);
                    line.push('"');
                    line.push('\n');
                    sink.as_mut().send(Bytes::from(line)).await?;
                }
                sink.as_mut().close().await?;
                // Merge from staging into main
                self.client.batch_execute("SELECT asm.merge_staging_raw_html();").await?;
                Ok(())
            };
            self.with_retry(op, "COPY raw_html").await?;
        }
        Ok(())
    }

    pub async fn copy_staging_asset_ports(&self, rows: &[ (String, i32, String, String, String) ]) -> Result<()> {
        if rows.is_empty() { return Ok(()); }
        let chunk = 50_000usize;
        for part in rows.chunks(chunk) {
            self.health_check().await.ok();
            let op = || async {
                // Copy directly into persistent staging; merge function will dedup/aggregate
                let sink = self.client
                    .copy_in("COPY asm.staging_asset_ports (target, port, scheme, meta, tech) FROM STDIN WITH (FORMAT csv)")
                    .await?;
                let mut sink = pin!(sink);
                for (t, p, s, m, te) in part {
                    let line = format!(
                        "\"{}\",{},\"{}\",\"{}\",\"{}\"\n",
                        Self::sanitize_field(t),
                        p,
                        Self::sanitize_field(s),
                        Self::sanitize_field(m),
                        Self::sanitize_field(te),
                    );
                    sink.as_mut().send(Bytes::from(line)).await?;
                }
                sink.as_mut().close().await?;
                // nothing else; merge will handle dedup/aggregation
                Ok(())
            };
            self.with_retry(op, "COPY staging_asset_ports").await?;
        }
        Ok(())
    }

    pub async fn copy_asset_port_html(&self, rows: &[ (String, i32, String, i64) ]) -> Result<()> {
        if rows.is_empty() { return Ok(()); }
        let chunk = 50_000usize;
        for part in rows.chunks(chunk) {
            self.health_check().await.ok();
            let op = || async {
                // Copy into persistent staging table, then merge function will upsert
                let sink = self.client
                    .copy_in("COPY asm.staging_asset_port_html (target, port, scheme, shodan_fk) FROM STDIN WITH (FORMAT csv)")
                    .await?;
                let mut sink = pin!(sink);
                for (t, p, s, fk) in part {
                    let line = format!(
                        "\"{}\",{},\"{}\",{}\n",
                        Self::sanitize_field(t),
                        p,
                        Self::sanitize_field(s),
                        fk
                    );
                    sink.as_mut().send(Bytes::from(line)).await?;
                }
                sink.as_mut().close().await?;
                self.client.batch_execute("SELECT asm.merge_staging_asset_port_html();").await?;
                Ok(())
            };
            self.with_retry(op, "COPY asset_port_html").await?;
        }
        Ok(())
    }

    pub async fn merge_staging(&self) -> Result<()> {
        // Retry merge, it's cheap but crucial
        self.with_retry(|| async {
            self.client.batch_execute("SELECT asm.merge_staging_asset_ports()").await?;
            Ok(())
        }, "merge_staging").await
    }
}