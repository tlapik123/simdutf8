#[cfg(target_arch = "x86_64")]
use simdutf8_bench::define_throughput_benchmark;

#[cfg(target_arch = "x86_64")]
define_throughput_benchmark!(BenchFn::ParallelShifter);

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
