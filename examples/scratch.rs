use std::time::Instant;

fn bench(name: &str, f: impl Fn(&[u8]) -> bool, data: &[u8], iters: usize) {
    // warmup
    for _ in 0..iters / 10 + 1 {
        std::hint::black_box(f(std::hint::black_box(data)));
    }
    let t = Instant::now();
    let mut ok = false;
    for _ in 0..iters {
        ok = std::hint::black_box(f(std::hint::black_box(data)));
    }
    let dt = t.elapsed().as_nanos() as f64 / iters as f64;
    println!(
        "{:32} {:9} bytes {:9.1} ns {:8.2} GB/s {}",
        name,
        data.len(),
        dt,
        data.len() as f64 / dt,
        ok
    );
}

#[target_feature(enable = "avx512f")]
#[inline(never)]
unsafe fn calibrate_freq() -> f64 {
    let mut x = core::arch::x86_64::_mm512_set1_epi64(1);
    let count: u64 = 1 << 26;
    let mut n: u64 = count;
    let t = Instant::now();
    core::arch::asm!(
        "3:",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "vpaddq {x}, {x}, {x}",
        "dec {n}",
        "jnz 3b",
        x = inout(zmm_reg) x,
        n = inout(reg) n,
        options(nostack)
    );
    let ns = t.elapsed().as_nanos() as f64;
    let _ = x;
    let _ = n;
    (count * 10) as f64 / ns
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let which: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(usize::MAX);
    let f0 = unsafe { calibrate_freq() };
    println!("freq before: {f0:.3} GHz");
    let f = std::fs::read_to_string("/proc/cpuinfo").unwrap();
    let mhz: f64 = f
        .lines()
        .find(|l| l.starts_with("cpu MHz"))
        .and_then(|l| l.split(':').nth(1).and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0.0);
    println!("cpu MHz: {mhz}");

    let files = [
        "Latin-Lipsum.txt",
        "Russian-Lipsum.txt",
        "Chinese-Lipsum.txt",
        "Emoji-Lipsum.txt",
    ];
    for (i, file) in files.iter().enumerate() {
        if which != usize::MAX && which != i {
            continue;
        }
        let data0 = std::fs::read(format!("bench/data/{file}")).unwrap();
        let full = data0.repeat(1024 * 1024 / data0.len() + 1);
        println!("--- {file}");
        for len in [64, 4096, 65536, 131072, 262144, 1048576] {
            // find a valid prefix of len or a bit more
            let mut end = len;
            loop {
                if std::str::from_utf8(&full[..end]).is_ok() {
                    break;
                }
                end += 1;
            }
            let data = &full[..end];
            let iters = (400_000_000 / data.len()).clamp(100, 3_000_000);
            let f1 = unsafe { calibrate_freq() };
            println!("freq during: {f1:.3} GHz");
            #[cfg(target_arch = "x86_64")]
            {
                if std::arch::is_x86_feature_detected!("avx512vbmi2") {
                    bench("parallel_automata", simdutf8::avx512_dfa::parallel_automata, data, iters);
                    bench("check_utf8_avx", simdutf8::avx512_dfa::check_utf8_avx, data, iters);
                }
                if std::arch::is_x86_feature_detected!("avx2") {
                    bench("basic(avx2)", |d| simdutf8::basic::from_utf8(d).is_ok(), data, iters);
                }
            }
            bench("std", |d| std::str::from_utf8(d).is_ok(), data, iters);
            let f2 = unsafe { calibrate_freq() };
            println!("freq after: {f2:.3} GHz");
        }
    }
}
