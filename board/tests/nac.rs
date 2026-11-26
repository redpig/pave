//! The network access gate: every exposed service asks for a NAC.

use pave_board::net::{self, read_msg, write_msg, Wire};
use pave_board::node::{Node, PendingJoin};
use std::collections::BTreeSet;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn join(town: &mut Node, name: &str, dir: &std::path::Path) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", &[]).unwrap();
    Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap()
}

#[test]
fn gate() {
    let dir = std::env::temp_dir().join(format!("pave-nac-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let alice = join(&mut town, "alice", &dir);
    let mut other_town = Node::init_town(&dir.join("other"), "other").unwrap();
    let mallory = join(&mut other_town, "mallory", &dir);

    // Admitted: the server learns the class and a pseudonym, nothing else.
    let c = town.nac_challenge();
    let p = alice.nac_prove("board.pine", &c).unwrap();
    let a = town.nac_admit("board.pine", &c, &p).unwrap();
    assert_eq!(a.class, "hardware");
    // The same pseudonym on this service this epoch, so it can be counted...
    let c2 = town.nac_challenge();
    assert_eq!(
        town.nac_admit(
            "board.pine",
            &c2,
            &alice.nac_prove("board.pine", &c2).unwrap()
        )
        .unwrap()
        .nym,
        a.nym
    );
    // ...and an unrelated one at another service.
    let c3 = town.nac_challenge();
    assert_ne!(
        town.nac_admit(
            "clerk.pine",
            &c3,
            &alice.nac_prove("clerk.pine", &c3).unwrap()
        )
        .unwrap()
        .nym,
        a.nym
    );

    // A proof signed for another service, or for another challenge, fails.
    assert!(town.nac_admit("clerk.pine", &c, &p).is_err());
    let c4 = town.nac_challenge();
    assert!(town.nac_admit("board.pine", &c4, &p).is_err(), "no replay");
    // So does another town's credential.
    let c5 = town.nac_challenge();
    assert!(town
        .nac_admit(
            "board.pine",
            &c5,
            &mallory.nac_prove("board.pine", &c5).unwrap()
        )
        .is_err());

    // A limit per pseudonym per epoch, and barring for the rest of the epoch.
    town.nac_limit = 2;
    let c6 = town.nac_challenge();
    assert!(town
        .nac_admit(
            "board.pine",
            &c6,
            &alice.nac_prove("board.pine", &c6).unwrap()
        )
        .unwrap_err()
        .contains("too many"));
    town.nac_limit = 100;
    town.nac_bar(c6.epoch, a.nym.clone());
    let c7 = town.nac_challenge();
    assert!(town
        .nac_admit(
            "board.pine",
            &c7,
            &alice.nac_prove("board.pine", &c7).unwrap()
        )
        .unwrap_err()
        .contains("barred"));
    // A new epoch: a new pseudonym, and the bar is over.
    town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    let c8 = town.nac_challenge();
    let a8 = town
        .nac_admit(
            "board.pine",
            &c8,
            &alice.nac_prove("board.pine", &c8).unwrap(),
        )
        .unwrap();
    assert_ne!(a8.nym, a.nym);

    // A client refuses a challenge epochs behind its own: a server that held
    // its epoch back would keep the client's pseudonym from changing. One
    // epoch ahead of the client is fine (it has been away).
    let mut fresh = town.nac_challenge();
    town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    town.roll_epoch(BTreeSet::new(), BTreeSet::new()).unwrap();
    assert!(town.nac_prove("board.pine", &fresh).is_err(), "two behind");
    fresh.epoch += 1;
    assert!(town.nac_prove("board.pine", &fresh).is_ok(), "one behind");
    fresh.epoch += 10;
    assert!(town.nac_prove("board.pine", &fresh).is_ok(), "ahead");

    // Over a socket: a client without a NAC is refused; one with is served.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = Arc::new(Mutex::new(town));
    let (srv, service) = (server.clone(), addr.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let (n, service) = (srv.clone(), service.clone());
            std::thread::spawn(move || net::serve_peer(n, conn, &service));
        }
    });
    let mut raw = TcpStream::connect(&addr).unwrap();
    raw.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    assert!(matches!(read_msg(&mut raw).unwrap().0, Wire::Challenge(_)));
    write_msg(&mut raw, &Wire::RefillAsk).unwrap();
    assert!(
        matches!(read_msg(&mut raw).unwrap().0, Wire::Refused(e) if e.contains("network access"))
    );
    let alice = Arc::new(Mutex::new(alice));
    let met = net::gossip_with(&alice, &addr);
    assert!(met.is_ok(), "{met:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
