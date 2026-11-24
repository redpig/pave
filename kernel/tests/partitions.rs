//! Random offline histories, the code analog of the TLA+ safe configs.
//!
//! Two sites start from the same view. People spend at either site while the
//! sites are apart; sometimes one site merges the other's records. One holder
//! (m) is dishonest and will sign the same state twice; honest wallets never
//! do. After a final merge both ways, every kernel check must hold, evidence
//! must name only m, and both sites must hold the same evidence.

use ed25519_dalek::SigningKey;
use pave_kernel::invariants::{check_all, no_false_flag};
use pave_kernel::scheme::DevScheme;
use pave_kernel::*;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
enum Action {
    Spend { site: usize, actor: usize, pick: usize, to: usize, split: bool },
    Merge { into: usize },
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        8 => (0..2usize, 0..4usize, 0..8usize, 0..4usize, any::<bool>())
            .prop_map(|(site, actor, pick, to, split)| Action::Spend { site, actor, pick, to, split }),
        1 => (0..2usize).prop_map(|into| Action::Merge { into }),
    ]
}

const DISHONEST: usize = 0;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(120))]
    #[test]
    fn offline_histories_keep_every_invariant(actions in proptest::collection::vec(action(), 1..40)) {
        let keys: Vec<SigningKey> = (0..4).map(|_| DevScheme::keygen()).collect();
        let creds: Vec<Credential> = keys.iter().map(|k| DevScheme.credential(k)).collect();
        let root_key = DevScheme::keygen();
        let root = DevScheme.credential(&root_key);
        let genesis = Genesis { label: "t".into(), root_rules: ScopeRules::default(), rooting: root.clone() };
        let mut base = View::new(DevScheme, genesis);
        let schema = Schema { label: "credit".into(), divisible: true, soft_expiry: None, hard_expiry: None, offline_transfers: None, max_per_holder: None, sequence: None };
        let issue = sign(&DevScheme, &root_key, &root, Op::IssueBudget { authority: base.genesis().rooting_capability(), schema, amount: 100, to: root.clone() });
        base.apply(&issue).unwrap();
        let m1 = sign(&DevScheme, &root_key, &root, Op::Mint { budget: issue.output(0), amount: 4, to: creds[0].clone(), change_to: root.clone() });
        base.apply(&m1).unwrap();
        let m2 = sign(&DevScheme, &root_key, &root, Op::Mint { budget: m1.output(1), amount: 2, to: creds[1].clone(), change_to: root.clone() });
        base.apply(&m2).unwrap();

        let mut sites = [base.clone(), base];
        let mut signed: Vec<BTreeSet<Hash>> = vec![BTreeSet::new(); 4];
        // Every (state, signer) -> record ids actually signed, to know which uses were double.
        let mut uses: BTreeMap<Hash, BTreeSet<Hash>> = BTreeMap::new();

        for a in actions {
            match a {
                Action::Spend { site, actor, pick, to, split } => {
                    if actor == to { continue; }
                    let mut held: Vec<Coin> = sites[site].coins_held_by(&creds[actor]).cloned().collect();
                    held.sort_by_key(|c| c.state);
                    if held.is_empty() { continue; }
                    let coin = &held[pick % held.len()];
                    if actor != DISHONEST && signed[actor].contains(&coin.state) { continue; }
                    let op = if split && coin.amount >= 2 {
                        Op::Split { state: coin.state, parts: vec![(1, creds[to].clone()), (coin.amount - 1, creds[actor].clone())], receipt: Hash([0; 32]) }
                    } else {
                        Op::Transfer { state: coin.state, to: creds[to].clone(), receipt: Hash([0; 32]) }
                    };
                    let rec = sign(&DevScheme, &keys[actor], &creds[actor], op);
                    let r = sites[site].apply(&rec);
                    prop_assert!(r.is_ok(), "holder's own spend refused: {:?}", r);
                    signed[actor].insert(coin.state);
                    uses.entry(coin.state).or_default().insert(rec.id());
                }
                Action::Merge { into } => {
                    let other = sites[1 - into].clone();
                    sites[into].merge_from(&other);
                }
            }
        }
        let b = sites[1].clone();
        sites[0].merge_from(&b);
        let a = sites[0].clone();
        sites[1].merge_from(&a);

        let honest: BTreeSet<Credential> = creds[1..].iter().cloned().chain([root]).collect();
        let double_used: BTreeSet<Hash> = uses.iter().filter(|(_, r)| r.len() > 1).map(|(s, _)| *s).collect();
        for v in &sites {
            prop_assert_eq!(check_all(v), Ok(()));
            prop_assert_eq!(no_false_flag(v, &honest), Ok(()));
            let evidenced: BTreeSet<Hash> = v.evidence().map(|e| e.basename).collect();
            prop_assert_eq!(&evidenced, &double_used, "every double use, and only those, has evidence");
            for e in v.evidence() {
                prop_assert_eq!(&e.signer, &creds[DISHONEST]);
            }
        }
    }
}
