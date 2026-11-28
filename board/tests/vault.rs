//! Sealed state and the signing log: what a restored backup can and can't do.

use pave_board::node::{Node, PendingJoin};
use pave_board::vault::{Keystore, MemoryKeystore};

fn join(town: &mut Node, name: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", credits).unwrap();
    let mut p = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    let t = town
        .answer_refill(&p.refill_request(&town.refill_terms().unwrap(), 8).unwrap())
        .unwrap();
    p.take_tickets(t);
    p
}

fn meet(a: &mut Node, b: &mut Node) {
    let (ba, bb) = (a.bundle(), b.bundle());
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
}

#[test]
fn sealed_state_and_restores() {
    let dir = std::env::temp_dir().join(format!("pave-vault-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut alice = join(&mut town, "alice", &dir, &[10, 10]);
    let mut bob = join(&mut town, "bob", &dir, &[]);
    let mut carol = join(&mut town, "carol", &dir, &[]);

    // At rest, the state is sealed: the secret key isn't in the file.
    let file = std::fs::read(&alice.path).unwrap();
    let secret = pave_kernel::hash::encode(&alice.key);
    assert!(!file.windows(secret.len()).any(|w| w == secret.as_slice()));
    let mut tampered = file.clone();
    *tampered.last_mut().unwrap() ^= 1;
    std::fs::write(dir.join("tampered"), &tampered).unwrap();
    std::fs::copy(
        alice.path.with_extension("vault"),
        dir.join("tampered.vault"),
    )
    .unwrap();
    assert!(Node::load(&dir.join("tampered")).is_err());

    // The software keystore can't stop a restore of both files: the old
    // copy signs the coin again, and evidence names alice. Detection, not
    // prevention, is all software alone can offer.
    let coin = alice.my_coins()[0].state;
    let (backup, backup_vault) = (
        std::fs::read(&alice.path).unwrap(),
        std::fs::read(alice.path.with_extension("vault")).unwrap(),
    );
    let to_bob = bob.receive().unwrap();
    let paid = alice.spend(coin, to_bob.clone()).unwrap();
    // The signing log is saved before a signature leaves. A wallet that
    // dies right after signing comes back still holding the coin in its
    // view, but its log won't sign that state for anyone else; the same
    // payment again just returns the record it released.
    let mut crashed = Node::load(&alice.path).unwrap();
    assert!(crashed.my_coins().iter().any(|c| c.state == coin));
    let err = crashed.spend(coin, carol.receive().unwrap()).unwrap_err();
    assert!(err.contains("second time"), "{err}");
    assert_eq!(crashed.spend(coin, to_bob).unwrap(), paid);
    drop(crashed);
    meet(&mut alice, &mut bob);
    std::fs::write(&alice.path, &backup).unwrap();
    std::fs::write(alice.path.with_extension("vault"), &backup_vault).unwrap();
    let mut restored = Node::load(&alice.path).unwrap();
    assert!(
        restored.my_coins().iter().any(|c| c.state == coin),
        "the old copy thinks it still holds the coin"
    );
    restored.spend(coin, carol.receive().unwrap()).unwrap();
    meet(&mut restored, &mut carol);
    meet(&mut carol, &mut bob);
    assert_eq!(bob.view.flagged().len(), 1, "the restore framed alice");

    // On a rollback-resistant keystore, every save retires the key the
    // last state was sealed under, so the old copy won't open at all.
    let mut dave = join(&mut town, "dave", &dir, &[10]);
    let device = MemoryKeystore::default();
    assert!(device.rollback_resistant());
    dave.use_keystore(Box::new(device.clone())).unwrap();
    let backup = std::fs::read(&dave.path).unwrap();
    let coin = dave.my_coins()[0].state;
    dave.spend(coin, bob.receive().unwrap()).unwrap();
    std::fs::write(&dave.path, &backup).unwrap();
    let err = Node::load_with(&dave.path, Box::new(device.clone()))
        .err()
        .unwrap();
    assert!(err.contains("retired key"), "{err}");
    // The live state still opens.
    dave.save().unwrap();
    let again = Node::load_with(&dave.path, Box::new(device)).unwrap();
    assert!(again.my_coins().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
