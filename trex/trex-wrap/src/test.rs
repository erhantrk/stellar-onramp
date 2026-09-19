#![cfg(test)]

// The crate is `no_std`; the tests need a heap for the wasm parser and the
// generated `Address` values.
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    Address, Env, IntoVal,
};

/// Every test starts here rather than at sequence 0, so drift in the expiry
/// boundary arithmetic shows up as a failure instead of an accidental pass
/// against zero. Mirrors contracts/kyc-gate/src/test.rs.
const START_SEQ: u32 = 1_000;

/// Claim bits mirror kyc-gate's frozen positions (contracts/kyc-gate/src/lib.rs:
/// CLAIM_OVER_18 = 1<<0, CLAIM_NOT_SANCTIONED = 1<<2). The exact positions do
/// not matter to the mock (it is plain mask arithmetic), but naming them
/// against the real gate keeps the seam honest.
const CLAIM_OVER_18: u32 = 1 << 0;
const CLAIM_NOT_SANCTIONED: u32 = 1 << 2;
const MASK_OVER_18_AND_NOT_SANCTIONED: u32 = CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED;

// ---------------------------------------------------------------------------
// A mock kyc-gate. A SEPARATE #[contractimpl] struct registered into the same
// test env, with its own storage and the SAME `check` ABI, but faithful mask
// semantics: claim_bit == 0 -> false, unknown subject -> false, expiry, and
// `claims & claim_bit == claim_bit`. We do NOT load the real v27 kyc-gate wasm
// into a v26 test env.
// ---------------------------------------------------------------------------

#[contracttype]
pub enum MockDataKey {
    Claims(Address),
}

#[contracttype]
#[derive(Clone)]
pub struct MockRecord {
    pub claims: u32,
    pub expires_at: u32,
}

#[contract]
pub struct MockKycGate;

#[contractimpl]
impl MockKycGate {
    pub fn set_claims(env: Env, subject: Address, claims: u32, expires_at: u32) {
        env.storage().persistent().set(
            &MockDataKey::Claims(subject),
            &MockRecord { claims, expires_at },
        );
    }

    pub fn check(env: Env, subject: Address, claim_bit: u32) -> bool {
        // Faithful to kyc-gate.check() (contracts/kyc-gate/src/lib.rs:1028):
        // empty mask fails closed, unknown subject fails, expiry, subset.
        if claim_bit == 0 {
            return false;
        }
        let Some(rec) = env
            .storage()
            .persistent()
            .get::<_, MockRecord>(&MockDataKey::Claims(subject))
        else {
            return false;
        };
        if env.ledger().sequence() > rec.expires_at {
            return false;
        }
        rec.claims & claim_bit == claim_bit
    }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

struct Ctx<'a> {
    client: TrexWrapClient<'a>,
    owner: Address,
    mock: MockKycGateClient<'a>,
}

/// Happy-path setup: `mock_all_auths` makes every `require_auth` succeed, so
/// the owner gate is invisible to the non-auth tests — exactly like kyc-gate's
/// `setup`. Auth-rejection tests build their own env with scoped `mock_auths`.
fn setup(env: &Env) -> Ctx<'_> {
    env.mock_all_auths();
    env.ledger().set_sequence_number(START_SEQ);
    let owner = Address::generate(env);
    let mock_addr = env.register(MockKycGate, ());
    let id = env.register(TrexWrap, (owner.clone(), mock_addr.clone(), CLAIM_OVER_18));
    Ctx {
        client: TrexWrapClient::new(env, &id),
        owner,
        mock: MockKycGateClient::new(env, &mock_addr),
    }
}

/// A fresh env with both contracts registered, but NO auth mocked — for the
/// owner-gated tests, which drive auth explicitly via `mock_auths`.
fn setup_unauthed(env: &Env) -> (TrexWrapClient<'_>, Address) {
    env.ledger().set_sequence_number(START_SEQ);
    let owner = Address::generate(env);
    let mock_addr = env.register(MockKycGate, ());
    let id = env.register(TrexWrap, (owner.clone(), mock_addr.clone(), CLAIM_OVER_18));
    (TrexWrapClient::new(env, &id), owner)
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// A panicking call through the client is `Err(Ok(soroban_sdk::Error))` where
/// the inner error is a contract error with the given numeric code. For a fn
/// whose return type is NOT `Result<_, ContractError>` the client's `E` type is
/// the catch-all `soroban_sdk::Error`, so a contract panic lands in the inner
/// `Ok`. We pin the numeric code — `WrapError` cannot be reconstructed from the
/// ABI of a unit- or Address-returning function.
fn assert_contract_error<T: PartialEq + core::fmt::Debug>(
    r: Result<
        Result<T, soroban_sdk::ConversionError>,
        Result<soroban_sdk::Error, soroban_sdk::InvokeError>,
    >,
    code: u32,
) {
    assert_eq!(
        r,
        Err(Ok(soroban_sdk::Error::from_contract_error(code))),
        "expected contract error code {code}"
    );
}

/// A rejected owner-only call (unit-returning setter) is `Err(Ok(_))` where the
/// inner error is a HOST error (a failed `require_auth`), NOT a contract error.
/// (Contrast kyc-gate, whose `Result<(), E>` setters yield `Err(Err(InvokeError::Abort))`
/// here.) The load-bearing property is "rejected with a host error, not success,
/// and not a contract-error panic" — a deleted `#[only_owner]` would turn this
/// into `Ok(Ok(()))` and fail the match.
fn assert_auth_rejection(
    r: Result<
        Result<(), soroban_sdk::ConversionError>,
        Result<soroban_sdk::Error, soroban_sdk::InvokeError>,
    >,
) {
    match r {
        Err(Ok(e)) => assert!(
            !e.is_type(soroban_sdk::xdr::ScErrorType::Contract),
            "expected a host-level (auth) rejection, got a contract error: {e:?}"
        ),
        other => panic!("expected an auth rejection (Err(Ok(_))), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

#[test]
fn constructor_records_gate_and_required_mask() {
    let env = Env::default();
    let ctx = setup(&env);
    assert_eq!(ctx.client.required(), CLAIM_OVER_18);
    // The mock's address is whatever `register` returned; the getter must agree.
    assert_eq!(ctx.client.kyc_gate(), ctx.mock.address.clone());
}

// ---------------------------------------------------------------------------
// Owner gating
// ---------------------------------------------------------------------------

#[test]
fn set_required_is_owner_gated() {
    let env = Env::default();
    let (client, owner) = setup_unauthed(&env);
    let id = client.address.clone();
    let stranger = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_required",
            args: (MASK_OVER_18_AND_NOT_SANCTIONED,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert_auth_rejection(client.try_set_required(&MASK_OVER_18_AND_NOT_SANCTIONED));

    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_required",
            args: (MASK_OVER_18_AND_NOT_SANCTIONED,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.set_required(&MASK_OVER_18_AND_NOT_SANCTIONED);
    assert_eq!(client.required(), MASK_OVER_18_AND_NOT_SANCTIONED);
}

#[test]
fn set_kyc_gate_is_owner_gated() {
    let env = Env::default();
    let (client, owner) = setup_unauthed(&env);
    let id = client.address.clone();
    let stranger = Address::generate(&env);
    let new_gate = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_kyc_gate",
            args: (new_gate.clone(),).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert_auth_rejection(client.try_set_kyc_gate(&new_gate));

    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_kyc_gate",
            args: (new_gate.clone(),).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.set_kyc_gate(&new_gate);
    assert_eq!(client.kyc_gate(), new_gate);
}

#[test]
fn set_recovery_is_owner_gated() {
    let env = Env::default();
    let (client, owner) = setup_unauthed(&env);
    let id = client.address.clone();
    let stranger = Address::generate(&env);
    let old = Address::generate(&env);
    let new = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_recovery",
            args: (old.clone(), new.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert_auth_rejection(client.try_set_recovery(&old, &new));

    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_recovery",
            args: (old.clone(), new.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.set_recovery(&old, &new);
    assert_eq!(client.recovery_target(&old), Some(new));
}

// ---------------------------------------------------------------------------
// verify_identity
// ---------------------------------------------------------------------------

#[test]
fn verify_identity_passes_when_the_gate_reports_a_sufficient_mask() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);
    ctx.mock.set_claims(&subject, &CLAIM_OVER_18, &(START_SEQ + 100));
    // The required mask is CLAIM_OVER_18, the record proves it — must not panic.
    ctx.client.verify_identity(&subject);
}

#[test]
fn verify_identity_rejects_a_subject_with_no_record() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);
    assert_contract_error(
        ctx.client.try_verify_identity(&subject),
        WrapError::IdentityVerificationFailed as u32,
    );
}

#[test]
fn verify_identity_rejects_an_insufficient_mask() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);
    // Record proves over-18 only; the required mask demands not-sanctioned too.
    ctx.client.set_required(&MASK_OVER_18_AND_NOT_SANCTIONED);
    ctx.mock.set_claims(&subject, &CLAIM_OVER_18, &(START_SEQ + 100));
    assert_contract_error(
        ctx.client.try_verify_identity(&subject),
        WrapError::IdentityVerificationFailed as u32,
    );
}

#[test]
fn verify_identity_rejects_an_expired_record() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);
    ctx.mock.set_claims(&subject, &CLAIM_OVER_18, &(START_SEQ + 100));
    // Push the ledger past the record's expiry.
    env.ledger().set_sequence_number(START_SEQ + 101);
    assert_contract_error(
        ctx.client.try_verify_identity(&subject),
        WrapError::IdentityVerificationFailed as u32,
    );
}

#[test]
fn verify_identity_fails_closed_on_an_empty_required_mask() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);
    // A subject with a real record, but the required mask is cleared to 0.
    // The adapter passes the empty mask straight through; the gate's check
    // returns false on claim_bit == 0, so this must reject — there is no
    // second path that would let an unset mask silently gate on nothing.
    ctx.client.set_required(&0u32);
    ctx.mock.set_claims(&subject, &CLAIM_OVER_18, &(START_SEQ + 100));
    assert_contract_error(
        ctx.client.try_verify_identity(&subject),
        WrapError::IdentityVerificationFailed as u32,
    );
}

/// The verdict must come from the gate, not from the adapter's own storage:
/// flipping ONLY the mock gate's state flips the verdict.
#[test]
fn verify_identity_reads_the_gate_not_local_state() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);

    // No record in the gate yet -> the adapter must fail closed.
    assert_contract_error(
        ctx.client.try_verify_identity(&subject),
        WrapError::IdentityVerificationFailed as u32,
    );

    // Writing to the MOCK's storage (not the adapter's) flips the verdict. If
    // the adapter consulted its own state, this call would change nothing.
    ctx.mock.set_claims(&subject, &CLAIM_OVER_18, &(START_SEQ + 100));
    ctx.client.verify_identity(&subject);
}

// ---------------------------------------------------------------------------
// recovery_target
// ---------------------------------------------------------------------------

#[test]
fn recovery_target_is_none_until_set_then_some() {
    let env = Env::default();
    let ctx = setup(&env);
    let old = Address::generate(&env);
    let new = Address::generate(&env);

    assert_eq!(ctx.client.recovery_target(&old), None);

    ctx.client.set_recovery(&old, &new);
    assert_eq!(ctx.client.recovery_target(&old), Some(new));
    // A different, unmapped account stays None.
    assert_eq!(ctx.client.recovery_target(&Address::generate(&env)), None);
}

// ---------------------------------------------------------------------------
// claim_topics_and_issuers
// ---------------------------------------------------------------------------

#[test]
fn claim_topics_and_issuers_is_not_initialized_until_set() {
    let env = Env::default();
    let ctx = setup(&env);
    assert_contract_error(
        ctx.client.try_claim_topics_and_issuers(),
        WrapError::NotInitialized as u32,
    );
}

#[test]
fn set_claim_topics_and_issuers_round_trips_and_is_owner_gated() {
    let env = Env::default();
    let (client, owner) = setup_unauthed(&env);
    let id = client.address.clone();
    let stranger = Address::generate(&env);
    let cti = Address::generate(&env);
    let operator = Address::generate(&env);

    // A stranger must not set it.
    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_claim_topics_and_issuers",
            args: (cti.clone(), operator.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert_auth_rejection(client.try_set_claim_topics_and_issuers(&cti, &operator));

    // The owner's auth sets it, and the getter reads it back.
    env.mock_auths(&[MockAuth {
        address: &owner,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "set_claim_topics_and_issuers",
            args: (cti.clone(), operator.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.set_claim_topics_and_issuers(&cti, &operator);
    assert_eq!(client.claim_topics_and_issuers(), cti);
}

// ---------------------------------------------------------------------------
// Error-code pin
// ---------------------------------------------------------------------------

/// Error codes are a wire format: deployed clients decode by number. Pin both
/// codes, pin the fact that neither lands in 300-399 (OpenZeppelin's range),
/// and pin that they do not collide with each other.
#[test]
fn error_codes_are_frozen_and_outside_the_reserved_range() {
    let all = [
        (WrapError::IdentityVerificationFailed, 2101u32),
        (WrapError::NotInitialized, 2102u32),
    ];
    for (e, code) in all {
        assert_eq!(e as u32, code, "error code renumbered — clients decode by number");
        assert!(!(300..=399).contains(&code), "code {code} is in the reserved 300-399 range");
    }
    assert_ne!(all[0].1, all[1].1, "duplicate error code");
}

// ---------------------------------------------------------------------------
// Export-list assertion (the load-bearing bit)
// ---------------------------------------------------------------------------

/// The ten function names this contract must export, exactly. This is the CI
/// `#[contractimpl(contracttrait)]` to plain `#[contractimpl]`, which silently
/// drops OZ's defaulted `claim_topics_and_issuers` export.
const EXPECTED_EXPORTS: [&str; 10] = [
    "__constructor",
    "claim_topics_and_issuers",
    "kyc_gate",
    "recovery_target",
    "required",
    "set_claim_topics_and_issuers",
    "set_kyc_gate",
    "set_recovery",
    "set_required",
    "verify_identity",
];

/// Minimal wasm binary reader: walks the section stream and returns the names
/// in the export section (section id 7). No external crates — the export
/// section format is frozen by the core wasm spec.
fn wasm_export_names(wasm: &[u8]) -> std::vec::Vec<std::string::String> {
    assert_eq!(&wasm[0..4], b"\x00asm", "not a wasm binary");
    let mut names = std::vec::Vec::new();
    let mut p = 8usize; // skip magic + version
    while p < wasm.len() {
        let section_id = wasm[p];
        p += 1;
        let (size, content_start) = read_uleb(wasm, p);
        let section_end = content_start + size;
        if section_id == 7 {
            let (count, mut r) = read_uleb(wasm, content_start);
            for _ in 0..count {
                let (len, s) = read_uleb(wasm, r);
                r = s;
                names.push(std::string::String::from(
                    std::str::from_utf8(&wasm[r..r + len]).unwrap(),
                ));
                r += len;
                r += 1; // kind byte (0 = function)
                let (_, s) = read_uleb(wasm, r); // function index
                r = s;
            }
        }
        p = section_end;
    }
    names
}

fn read_uleb(wasm: &[u8], mut p: usize) -> (usize, usize) {
    let mut result = 0usize;
    let mut shift = 0usize;
    loop {
        let byte = wasm[p];
        p += 1;
        result |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return (result, p);
        }
        shift += 7;
    }
}

/// Internal wasm exports that are NOT contract functions. Everything else in
/// the export section must be exactly the ten contract functions.
const INTERNAL_EXPORTS: [&str; 4] = ["memory", "_", "__data_end", "__heap_base"];

/// Reads the BUILT artifact off disk (must run after `stellar contract build`)
/// and asserts the exported-function list is exactly the ten names. This is the
/// defence: when `claim_topics_and_issuers` is dropped (the two-part footgun,
/// flag + override removed), `cargo test` fails to COMPILE first — three tests
/// call `ctx.client.claim_topics_and_issuers()`, which no longer exists on the
/// generated client (E0599) — so this test never gets to run. Its unique value
/// is drift no call site would catch: an extra/renamed export, a dropped export
/// whose call sites were also removed, and `__constructor` (which no client can
/// call). Defense-in-depth, not the catcher of that particular footgun.
#[test]
fn built_wasm_exports_the_full_surface() {
    let wasm = std::fs::read(std::concat!(
        std::env!("CARGO_MANIFEST_DIR"),
        "/../target/wasm32v1-none/release/trex_wrap.wasm"
    ))
    .expect("run `stellar contract build` first: this test needs the built wasm");

    let exports = wasm_export_names(&wasm);
    let mut contract_fns: std::vec::Vec<&str> = exports
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !INTERNAL_EXPORTS.contains(s))
        .collect();

    let mut expected: std::vec::Vec<&str> = EXPECTED_EXPORTS.to_vec();
    expected.sort_unstable();
    contract_fns.sort_unstable();
    assert_eq!(contract_fns, expected, "exported function list drifted from the frozen ten");
}

/// Belt-and-braces: call every client-callable export through the generated
/// client so a dropped export traps at call time too, independent of the wasm
/// parser. (`__constructor` is exercised by `env.register` in every setup; it
/// is not client-callable.)
#[test]
fn every_export_is_callable_through_the_client() {
    let env = Env::default();
    let ctx = setup(&env);
    let subject = Address::generate(&env);

    // set_required / required
    ctx.client.set_required(&MASK_OVER_18_AND_NOT_SANCTIONED);
    assert_eq!(ctx.client.required(), MASK_OVER_18_AND_NOT_SANCTIONED);

    // set_kyc_gate / kyc_gate
    let gate2 = Address::generate(&env);
    ctx.client.set_kyc_gate(&gate2);
    assert_eq!(ctx.client.kyc_gate(), gate2);

    // set_recovery / recovery_target
    let old = Address::generate(&env);
    let new = Address::generate(&env);
    ctx.client.set_recovery(&old, &new);
    assert_eq!(ctx.client.recovery_target(&old), Some(new));

    // set_claim_topics_and_issuers / claim_topics_and_issuers
    let cti = Address::generate(&env);
    ctx.client.set_claim_topics_and_issuers(&cti, &ctx.owner);
    assert_eq!(ctx.client.claim_topics_and_issuers(), cti);

    // verify_identity: point the gate back at the mock and give a sufficient record.
    ctx.client.set_kyc_gate(&ctx.mock.address);
    ctx.client.set_required(&CLAIM_OVER_18);
    ctx.mock.set_claims(&subject, &CLAIM_OVER_18, &(START_SEQ + 100));
    ctx.client.verify_identity(&subject);
}

// ---------------------------------------------------------------------------
// Source-level flag pin (the `contracttrait` literal)
// ---------------------------------------------------------------------------

/// Pins the literal `#[contractimpl(contracttrait)]` flag token in `lib.rs`.
///
/// This is the one assertion the export-list gate CANNOT provide. A *pure*
/// downgrade to plain `#[contractimpl]` (override kept) is behaviourally
/// neutral — same 10 exports, same 16 tests — because this adapter overrides
/// all four `IdentityVerifier` methods, including the only one with an OZ
/// default (`claim_topics_and_issuers`). No behavioural test can distinguish
/// the flag's presence from its absence. This source-level lint asserts the
/// flag appears on its own attribute line (trimmed), so that pure downgrade —
/// behavioural suite leaves open by design.
#[test]
fn contracttrait_flag_is_present_in_source() {
    let src = include_str!("lib.rs");
    assert!(
        src.lines().any(|l| l.trim() == "#[contractimpl(contracttrait)]"),
        "the IdentityVerifier trait impl must keep `#[contractimpl(contracttrait)]`: \
         plain `#[contractimpl]` would silently drop OZ's defaulted claim_topics_and_issuers"
    );
}
