use std::time::Instant;

unsafe fn time(name: &str, iters: usize, freq_ghz: &mut f64, ops_per_iter: f64, f: impl Fn()) {
    for _ in 0..(iters / 10).max(1) {
        std::hint::black_box(f());
    }
    let reps = 11;
    let mut best = f64::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(f());
        }
        best = best.min(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    if *freq_ghz < 0.0 {
        *freq_ghz = ops_per_iter / best;
        println!("calibrated freq: {freq_ghz:.3} GHz (vpaddq lat 1, 100/iter)");
        return;
    }
    println!("{:34} {:10.1} ns/iter {:7.3} cyc/op", name, best, best * *freq_ghz / ops_per_iter);
}

macro_rules! rep16 {
    ($op:literal) => {
        concat!($op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n",
                $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n", $op, "\n")
    };
}

#[target_feature(enable = "avx512f,avx512bw,avx512vbmi,avx512vbmi2")]
unsafe fn run() {
    let buf = [7u8; 64];
    let p = buf.as_ptr() as usize;
    let mut freq = -1.0;
    const LOOPS: u64 = (1 << 12) - 1;

    time("calib", 256, &mut freq, 100.0 * LOOPS as f64, || {
        let mut x = std::arch::x86_64::_mm512_set1_epi64(1);
        let mut n = LOOPS;
        std::arch::asm!(
            "2:",
            rep16!("vpaddq {x}, {x}, {x}"),
            rep16!("vpaddq {x}, {x}, {x}"),
            rep16!("vpaddq {x}, {x}, {x}"),
            rep16!("vpaddq {x}, {x}, {x}"),
            rep16!("vpaddq {x}, {x}, {x}"),
            rep16!("vpaddq {x}, {x}, {x}"),
            "vpaddq {x}, {x}, {x}\nvpaddq {x}, {x}, {x}\nvpaddq {x}, {x}, {x}\nvpaddq {x}, {x}, {x}",
            "dec {n}",
            "jnz 2b",
            x = inout(zmm_reg) x,
            n = inout(reg) n,
            options(nostack)
        );
    });

    macro_rules! cal {
        ($name:literal, $ops:expr, $n_ops:expr) => {{
            let iters = 512;
            unsafe {
                time($name, iters.max(1), &mut freq, $n_ops, || {
                    let mut x = std::arch::x86_64::_mm512_set1_epi64(0x0706_0504_0302_0100);
                    let y = std::arch::x86_64::_mm512_set1_epi64(0x5a5a_3c3c_0f0f_1010);
                    let t = std::arch::x86_64::_mm512_set1_epi64(0x3333_4444_5555_6666);
                    let mut n = LOOPS;
                    std::arch::asm!(
                        "vpcmpb {kz}, {y}, {t}, 1",
                        "vmovdqu8 {tmp}, [{p}]",
                        "2:",
                        $ops,
                        "dec {n}",
                        "jnz 2b",
                        x = inout(zmm_reg) x,
                        y = in(zmm_reg) y,
                        t = in(zmm_reg) t,
                        n = inout(reg) n,
                        p = in(reg) p,
                        kz = out(kreg) _,
                        tmp = out(zmm_reg) _,
                        options(nostack)
                    );
                });
            }
        }};
    }

    cal!("vpaddq tp x16", rep16!("vpaddq {x}, {y}, {t}"), 16.0);
    cal!("vpternlogd tp x16", rep16!("vpternlogd {x}, {y}, {t}, 0x96"), 16.0);
    cal!("vpermi2b tp x16", rep16!("vpermi2b {x}, {y}, {t}"), 16.0);
    cal!("vpermb tp x16", rep16!("vpermb {x}, {y}, {t}"), 16.0);
    cal!("vpmaddwd tp x16", rep16!("vpmaddwd {x}, {y}, {t}"), 16.0);
    cal!("vpshldq tp x16", rep16!("vpshldq {x}, {y}, {t}, 8"), 16.0);
    cal!("vpshrdq tp x16", rep16!("vpshrdq {x}, {y}, {t}, 8"), 16.0);
    cal!("valignq tp x16", rep16!("valignq {x}, {y}, {t}, 1"), 16.0);
    cal!("vpmaxub tp x16", rep16!("vpmaxub {x}, {y}, {t}"), 16.0);
    cal!("vmovdqu8 load tp x16", rep16!("vmovdqu8 {x}, [{p}]"), 16.0);
    cal!("vpermw tp x16", rep16!("vpermw {x}, {y}, {t}"), 16.0);
    cal!("vprolq tp x16", rep16!("vprolq {x}, {y}, 7"), 16.0);
    cal!("vpsubb tp x16", rep16!("vpsubb {x}, {y}, {t}"), 16.0);
    cal!("vpermi2b lat x8", rep16!("vpermi2b {x}, {x}, {y}"), 8.0);
    cal!("vpermb lat x8", rep16!("vpermb {x}, {x}, {y}"), 8.0);
    cal!("vpmaddwd lat x8", rep16!("vpmaddwd {x}, {x}, {y}"), 8.0);
    cal!("vpshldq lat x8", rep16!("vpshldq {x}, {x}, {y}, 8"), 8.0);
}

fn main() {
    unsafe { run() };
}
