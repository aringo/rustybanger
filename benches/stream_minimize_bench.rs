use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use shodan_ingest::minimizer::minimize_record;
use std::fs::File;
use std::io::{BufRead, BufReader};
use zstd::stream::Decoder;

fn sample_lines(n: usize) -> Vec<String> {
    let path = "/Volumes/bulk/Repos/shodanclient/2025-08-04T08:00:00.json.zst";
    let file = File::open(path).expect("open zst");
    let decoder = Decoder::new(file).expect("zstd decoder");
    let reader = BufReader::new(decoder);
    let mut out = Vec::with_capacity(n);
    for (i, line) in reader.lines().enumerate() {
        if i >= n { break; }
        if let Ok(l) = line { if !l.is_empty() { out.push(l); } }
    }
    out
}

fn bench_stream_minimize(c: &mut Criterion) {
    let lines = sample_lines(50_000);
    let mut group = c.benchmark_group("stream_minimize");
    group.throughput(Throughput::Elements(lines.len() as u64));
    group.bench_function("minimize_50k", |b| {
        b.iter(|| {
            let mut cnt = 0usize;
            for l in &lines {
                if minimize_record(l).is_some() { cnt += 1; }
            }
            cnt
        })
    });
    group.finish();
}

criterion_group!(benches, bench_stream_minimize);
criterion_main!(benches);





