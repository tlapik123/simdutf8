/// Differential test: check_utf8_avx / parallel_automata vs std::str::from_utf8
/// on adversarial inputs. Run: cargo run --release --example difftest [iters]
use std::time::Instant;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn check(buf: &[u8], n: u64) -> u64 {
    let expected = std::str::from_utf8(buf).is_ok();
    let mut bad = 0;
    let a = unsafe { simdutf8::avx512_dfa::check_utf8_avx(buf) };
    let b = unsafe { simdutf8::avx512_dfa::parallel_automata(buf) };
    if a != expected || b != expected {
        println!(
            "MISMATCH case {n} len {} expected {expected} avx={a} par={b}: {}",
            buf.len(),
            buf.iter().map(|x| format!("{x:02x}")).collect::<String>()
        );
        bad += 1;
    }
    bad
}

fn main() {
    let t0 = Instant::now();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
    let mut total_bad = 0u64;
    let mut n = 0u64;

    // byte pool skewed to structural boundary values
    const POOL: [u8; 32] = [
        0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1,
        0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf4, 0xf5, 0xff, b'a', b'a', b'a', 0x41, 0x41, 0x80,
        0xbf, 0xc2, 0xf0, 0xed,
    ];

    // 1. random lengths 0..=256, pool bytes
    for _ in 0..60_000 {
        buf.clear();
        let len = (rng.next() % 257) as usize;
        for _ in 0..len {
            buf.push(POOL[(rng.next() % POOL.len() as u64) as usize]);
        }
        total_bad += check(&buf, n);
        n += 1;
    }

    // 2. lengths clustered on kernel boundaries
    for _ in 0..60_000 {
        buf.clear();
        let base = match rng.next() % 8 {
            0 => 63,
            1 => 255,
            2 => 511,
            3 => 4095,
            4 => 8192,
            5 => 16384,
            6 => 65535,
            _ => 131072,
        };
        let len = base + (rng.next() % 8) as usize;
        for _ in 0..len {
            let r = rng.next();
            buf.push(if r % 3 == 0 { POOL[(r >> 8) as usize % POOL.len()] } else { (r >> 16) as u8 });
        }
        total_bad += check(&buf, n);
        n += 1;
    }

    // 3. mostly-valid text with 1-3 byte corruptions
    let words: Vec<String> = (0..200)
        .map(|i| {
            let r = rng.next();
            match r % 4 {
                0 => "lorem ipsum dolor ".repeat(1 + (r >> 8) as usize % 4),
                1 => "Лорем ипсум долор ".repeat(1 + (r >> 8) as usize % 4),
                2 => "世界你好文本 ".repeat(1 + (r >> 8) as usize % 4),
                _ => "🚀💡🎉🦀 ".repeat(1 + (i % 3)),
            }
        })
        .collect();
    for _ in 0..40_000 {
        buf.clear();
        let nwords = 1 + rng.next() % 600;
        for _ in 0..nwords {
            buf.extend_from_slice(words[(rng.next() % words.len() as u64) as usize].as_bytes());
        }
        // corrupt
        if !buf.is_empty() {
            for _ in 0..1 + rng.next() % 3 {
                let pos = (rng.next() as usize) % buf.len();
                buf[pos] = POOL[(rng.next() % POOL.len() as u64) as usize];
            }
        }
        total_bad += check(&buf, n);
        n += 1;
    }

    // 4. single-byte and truncation sweeps over a valid multi-charset base
    let mut base: Vec<u8> = Vec::new();
    for i in 0..2048 {
        let s = match i % 4 {
            0 => "abc",
            1 => "циф",
            2 => "汉字",
            _ => "🎵🎶",
        };
        base.extend_from_slice(s.as_bytes());
    }
    for cut in [base.len() - 1, 511, 512, 513, 1023, 1024, 4095, 4096] {
        let b = &base[..cut.min(base.len())];
        total_bad += check(b, n);
        n += 1;
    }
    for pos in (0..base.len()).step_by(7) {
        for v in [0x00u8, 0x7f, 0x80, 0xbf, 0xc0, 0xc2, 0xe0, 0xed, 0xf0, 0xf4, 0xf5, 0xff] {
            let mut b = base.clone();
            b[pos] = v;
            total_bad += check(&b, n);
            n += 1;
        }
    }

    println!(
        "{n} cases, {total_bad} mismatches, {:.1}s",
        t0.elapsed().as_secs_f64()
    );
}
