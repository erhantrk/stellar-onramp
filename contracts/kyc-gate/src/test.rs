#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    Address, Env, IntoVal,
};

/// Every test starts here rather than at sequence 0, so drift in the expiry boundary
/// arithmetic shows up as a failure instead of an accidental pass against zero.
const START_SEQ: u32 = 1_000;

fn setup(env: &Env) -> KycGateClient<'_> {
    env.mock_all_auths();
    env.ledger().set_sequence_number(START_SEQ);
    let admin = Address::generate(env);
    let registry = Address::generate(env);
    let id = env.register(KycGate, ());
    let client = KycGateClient::new(env, &id);
    client.init(&admin, &registry);
    client
}


#[test]
fn unattested_subject_fails_every_check() {
    let env = Env::default();
    let client = setup(&env);
    let subject = Address::generate(&env);

    assert!(!client.check(&subject, &CLAIM_OVER_18));
    assert!(!client.check(&subject, &CLAIM_NOT_SANCTIONED));
}

#[test]
fn double_init_is_rejected() {
    let env = Env::default();
    let client = setup(&env);
    let admin = Address::generate(&env);
    let registry = Address::generate(&env);
    assert_eq!(
        client.try_init(&admin, &registry),
        Err(Ok(Error::AlreadyInitialized))
    );
}

#[test]
fn claim_bits_are_independent() {
    // Guards the frozen bit positions: a record proving over-18 must not accidentally
    // satisfy a not-sanctioned check.
    assert_eq!(CLAIM_OVER_18 & CLAIM_NOT_SANCTIONED, 0);
    assert_eq!(CLAIM_OVER_18 & CLAIM_OVER_21, 0);
    assert_eq!(CLAIM_JURISDICTION_OK & CLAIM_OVER_18, 0);
}

// ---------------------------------------------------------------------------------
// Gateway key registration
// ---------------------------------------------------------------------------------

/// `init` records whoever the caller names as admin, so its `require_auth` is the only
/// thing stopping a third party from initialising a freshly-deployed gate with an admin
/// address they do not control (griefing: the real operator's `init` then hits
/// `admin.require_auth()` from `init` turned no other test red.
#[test]
fn init_requires_auth_from_the_declared_admin() {
    let env = Env::default();
    env.ledger().set_sequence_number(START_SEQ);
    let admin = Address::generate(&env);
    let stranger = Address::generate(&env);
    let registry = Address::generate(&env);
    let id = env.register(KycGate, ());
    let client = KycGateClient::new(&env, &id);

    // A stranger's signature does not authorise naming `admin` as admin.
    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "init",
            args: (admin.clone(), registry.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert!(matches!(client.try_init(&admin, &registry), Err(Err(_))));

    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "init",
            args: (admin.clone(), registry.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.init(&admin, &registry);
}

/// Re-revoking is idempotent and moves the subject forward. Harmless for the admin; the
/// gateway path is nonce-protected against it (`replayed_revocation_nonce_is_rejected`).
//
// `re_revoking_pushes_the_floor_forward`: what moves forward is the EPOCH, not a floor. The
// floor is gone, so the tombstone's `expires_at` is simply the ledger each revocation
// happened at, and only the epoch is monotonic.

#[test]
fn attestation_horizon_and_storage_lifetime_end_together() {
    // An attestation may be dated up to MAX_EXPIRY_HORIZON ahead and its entry is bumped to
    // CLAIM_TTL_EXTEND_TO; if these ever differ a record is either archived while still live
    // or pays rent doing nothing.
    assert_eq!(MAX_EXPIRY_HORIZON, CLAIM_TTL_EXTEND_TO);
    assert_eq!(MAX_EXPIRY_HORIZON, 2_073_600, "constant moved - re-derive the bound above");
}
