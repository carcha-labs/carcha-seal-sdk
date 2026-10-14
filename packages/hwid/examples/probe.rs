//! Prints what the library reads on this machine and how long it takes.
//! Only kinds, hashes and error codes are printed, never raw serials.
//!
//!   cargo run --release --example probe [product-key]

use std::time::Instant;

fn main() {
    let key = std::env::args().nth(1).unwrap_or_else(|| "licensekit-probe".into());
    let start = Instant::now();
    let (c, notes) = licensekit_hwid::collect_with_notes(key.as_bytes());
    let elapsed = start.elapsed();
    println!("licensekit_hwid {} on {}/{}", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH);
    println!("vm: {}", c.vm);
    for x in &c.components {
        println!("{:<6} {}", x.kind.as_str(), x.hash);
    }
    println!("{} components in {:.1} ms", c.components.len(), elapsed.as_secs_f64() * 1000.0);
    for n in &notes {
        println!("not read: {n}");
    }
}
