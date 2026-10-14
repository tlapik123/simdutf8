use std::time::Instant;


mod old;
use old::{check_utf8_avx_old, parallel_automata_old};


fn time(f: &dyn Fn(&[u8]) -> bool, data: &[u8], iters: usize) -> f64 {
    let mut ok = false;
    let t = Instant::now();
    for _ in 0..iters {
        ok = std::hint::black_box(f(std::hint::black_box(data)));
    }
    let _ = ok;
    t.elapsed().as_secs_f64() / iters as f64
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn bench_pair(name_a: &str, name_b: &str, a: &dyn Fn(&[u8]) -> bool, b: &dyn Fn(&[u8]) -> bool, data: &[u8]) {
    let per = data.len() as f64;
    // ~25 ms of work per timed round, assuming ~0.4 ns/byte
    let iters = ((25_000_000.0 / (per * 0.4)) as usize).clamp(200, 20_000_000);
    // warmup
    for _ in 0..3 {
        let _ = a(data);
        let _ = b(data);
    }
    let rounds = 61;
    let mut ta = Vec::with_capacity(rounds);
    let mut tb = Vec::with_capacity(rounds);
    let mut alternate = true;
    for _ in 0..rounds {
        // alternate which goes first to cancel ordering effects
        if alternate {
            ta.push(time(a, data, iters));
            tb.push(time(b, data, iters));
        } else {
            tb.push(time(b, data, iters));
            ta.push(time(a, data, iters));
        }
        alternate = !alternate;
    }
    let ma = median(&mut ta);
    let mb = median(&mut tb);
    let na = ta.iter().cloned().fold(f64::INFINITY, f64::min);
    let nb = tb.iter().cloned().fold(f64::INFINITY, f64::min);
    println!(
        "{:24} {:9} B  med {:8.1} ns {:7.2} GB/s | {:8.1} ns {:7.2} GB/s | med {:.3} | min {:.3}",
        format!("{name_a} / {name_b}"),
        data.len(),
        ma * 1e9,
        per / ma / 1e9,
        mb * 1e9,
        per / mb / 1e9,
        ma / mb,
        na / nb
    );
}

fn main() {
    let files = ["Latin-Lipsum.txt", "Russian-Lipsum.txt", "Chinese-Lipsum.txt", "Emoji-Lipsum.txt"];
    for file in files {
        let data0 = std::fs::read(format!("bench/data/{file}")).unwrap();
        let full = data0.repeat(1024 * 1024 / data0.len() + 1);
        println!("--- {file}");
        for len in [8usize, 64, 255, 256, 512, 4096, 65536] {
            let mut end = len;
            loop {
                if std::str::from_utf8(&full[..end]).is_ok() {
                    break;
                }
                end += 1;
            }
            let data = &full[..end];
            bench_pair(
                "old",
                "new",
                &check_utf8_avx_old,
                &simdutf8::avx512_dfa::check_utf8_avx,
                data,
            );
            bench_pair(
                "par_old",
                "par_new",
                &|d| parallel_automata_old(d),
                &simdutf8::avx512_dfa::parallel_automata,
                data,
            );
            bench_pair(
                "basic",
                "par_new",
                &|d| simdutf8::basic::from_utf8(d).is_ok(),
                &simdutf8::avx512_dfa::parallel_automata,
                data,
            );
        }
    }
}
