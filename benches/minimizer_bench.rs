use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shodan_ingest::minimizer::minimize_record;

fn bench_minimizer(c: &mut Criterion) {
    let sample = r#"{
        "ip_str":"1.2.3.4","port":443,
        "http": {"html_hash": 123, "html": "<html>hi</html>", "headers": {"server":"nginx"}},
        "ssl": {"versions":["tls1.2"],"jarm":"0000000000000000000000000000000000000000000000000000000000000000"}
    }"#;
    c.bench_function("minimize_record", |b| {
        b.iter(|| {
            let out = minimize_record(black_box(sample));
            black_box(out)
        })
    });
}

criterion_group!(benches, bench_minimizer);
criterion_main!(benches);


