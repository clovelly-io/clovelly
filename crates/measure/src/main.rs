//! `measure --uki UKI --disk DISK`: prints the predicted RTMR1 and RTMR2 as
//! `rtmr1=<hex>` and `rtmr2=<hex>`, then each extension as `# <register> <digest> <what>`.

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (uki, disk) = match args.as_slice() {
        [a, uki, b, disk] if a == "--uki" && b == "--disk" => (uki, disk),
        _ => anyhow::bail!("usage: measure --uki UKI --disk DISK"),
    };
    let uki = std::fs::read(uki).with_context(|| format!("reading {uki}"))?;
    let mut disk = std::fs::File::open(disk).with_context(|| format!("opening {disk}"))?;
    let p = measure::predict(&uki, &mut disk)?;
    println!("rtmr1={}\nrtmr2={}", p.rtmr1, p.rtmr2);
    for (reg, events) in [("rtmr1", &p.rtmr1_events), ("rtmr2", &p.rtmr2_events)] {
        for e in events {
            println!("# {reg} {} {}", e.digest, e.what);
        }
    }
    Ok(())
}
