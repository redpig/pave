//! Rough timings for the operations a wallet does per payment.
//! `cargo run --release -p pave-scheme-briolette --example timing`
use pave_kernel::Scheme;
use pave_scheme_briolette::Issuer;
use std::time::Instant;

fn main() {
    let issuer = Issuer::new();
    let s = issuer.scheme();
    let key = issuer.join_locally();
    let n = 50;
    let t = Instant::now();
    let creds: Vec<_> = (0..n).map(|_| s.credential(&key)).collect();
    let randomize = t.elapsed() / n;
    let msg = vec![7u8; 200];
    let t = Instant::now();
    let sigs: Vec<_> = creds
        .iter()
        .map(|c| s.sign(&key, c, &msg, Some(b"state")))
        .collect();
    let sign = t.elapsed() / n;
    let t = Instant::now();
    for (c, sig) in creds.iter().zip(&sigs) {
        assert!(s.verify(c, &msg, Some(b"state"), sig));
    }
    let verify = t.elapsed() / n;
    println!("randomize credential {randomize:?}, sign with basename {sign:?}, verify {verify:?} (this machine, one core)");

    // Standing against a list of known cheats: per cheat on the list.
    let cheats: Vec<_> = (0..10u8)
        .map(|i| {
            let k = issuer.join_locally();
            let c = s.credential(&k);
            let bsn = vec![i; 32];
            (
                bsn.clone(),
                s.nym(&s.sign(&k, &c, b"x", Some(&bsn))).unwrap(),
            )
        })
        .collect();
    let t = Instant::now();
    let proofs: Vec<_> = creds
        .iter()
        .take(10)
        .map(|c| s.prove_not_cheat(&key, c, &cheats, b"ctx").unwrap())
        .collect();
    let prove = t.elapsed() / 100;
    let t = Instant::now();
    for (c, p) in creds.iter().zip(&proofs) {
        assert!(s.verify_not_cheat(c, &cheats, b"ctx", p));
    }
    let check = t.elapsed() / 100;
    println!(
        "standing, per known cheat: prove {prove:?}, verify {check:?}, {} bytes",
        proofs[0].len() / cheats.len()
    );
}
