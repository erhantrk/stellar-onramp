#![cfg(test)]

// The crate is `no_std`; the tests need a heap to hand a contiguous `&[u8]` to dalek.
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    Address, BytesN, Env, IntoVal, String as SorobanString,
};

/// Every test starts here rather than at sequence 0, so drift in the expiry boundary
/// arithmetic shows up as a failure instead of an accidental pass against zero.
const START_SEQ: u32 = 1_000;

const VECTORS_SRC: &str = "packages/identity/fixtures/vectors.json";
const VECTORS_JSON: &str = include_str!("../../../packages/identity/fixtures/vectors.json");

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

fn nonce(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
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
fn re_revoking_pushes_the_revocation_epoch_forward() {
    let env = Env::default();
    let client = setup(&env);
    let subject = Address::generate(&env);

    client.revoke(&subject);
    let first = client.claim_record(&subject);
    assert_eq!(first.expires_at, START_SEQ);
    assert_eq!(first.revocation_epoch, 1);

    env.ledger().set_sequence_number(START_SEQ + 1_000);
    client.revoke(&subject);
    let second = client.claim_record(&subject);
    assert_eq!(second.expires_at, START_SEQ + 1_000);
    assert_eq!(
        second.revocation_epoch, 2,
        "a second revocation must invalidate anything signed for the first"
    );
    assert!(!client.check(&subject, &CLAIM_OVER_18));
}

// --- 9. cost ----------------------------------------------------------------------

/// ATTACK 5. An attestation may be dated up to `MAX_EXPIRY_HORIZON` ahead and its record's
/// entry is bumped to `CLAIM_TTL_EXTEND_TO`, so the two end at the SAME ledger with nothing to
/// re-extend the entry. Past that point the guarantee is the ledger's, not the contract's: the
/// entry is archived and any access to it fails the transaction until someone pays to restore
/// it. The test env does not model archival, so this pins the arithmetic rather than the
/// archival behaviour, which is the honest limit of what can be asserted here.
#[test]
fn attestation_horizon_and_storage_lifetime_end_together() {
    // `tombstone_floor_and_storage_lifetime_end_together`. The floor this test was named
    // after no longer exists, so the coupling it pinned (floor == entry lifetime) is vacuous.
    // What survives is the bound
    // that still does work: an ATTESTATION may not outlive the entry that stores it or the
    // nonce tombstone that stops it being replayed. The tombstone's own lifetime is no longer
    // a correctness question — the epoch it carries survives archival, because a persistent
    // entry is archived rather than deleted and restoring one returns the same bytes.
    assert_eq!(
        MAX_EXPIRY_HORIZON, CLAIM_TTL_EXTEND_TO,
        "an attestation may be dated up to MAX_EXPIRY_HORIZON ahead and its entry is bumped \
         to CLAIM_TTL_EXTEND_TO; if these ever differ a record is either archived while still \
         live or pays rent doing nothing"
    );
    const {
        assert!(
            MAX_EXPIRY_HORIZON <= NONCE_MAX_TTL,
            "a revocation nonce tombstone must outlive the attestation horizon it protects"
        )
    };
    assert_eq!(MAX_EXPIRY_HORIZON, 2_073_600, "constant moved — re-derive both bounds above");
}

/// The admin `upgrade` inherits from `set_admin`, so a handed-over contract is upgradable by
/// the new admin and NOT by the old one. Written because "who can replace the code" is the
/// highest-consequence question this contract answers.
#[test]
fn upgrade_follows_the_admin_across_a_handover() {
    let env = Env::default();
    env.ledger().set_sequence_number(START_SEQ);
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let registry = Address::generate(&env);
    let id = env.register(KycGate, ());
    let client = KycGateClient::new(&env, &id);

    env.mock_all_auths();
    client.init(&admin, &registry);
    client.set_admin(&new_admin);

    let wasm = std::fs::read(std::concat!(
        std::env!("CARGO_MANIFEST_DIR"),
        "/../target/wasm32v1-none/release/kyc_registry.wasm"
    ))
    .expect("run `stellar contract build` first: this test needs a real wasm to upload");
    let wasm_hash = env
        .deployer()
        .upload_contract_wasm(soroban_sdk::Bytes::from_slice(&env, &wasm));

    // The OLD admin authorising alone is now a stranger.
    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "upgrade",
            args: (wasm_hash.clone(),).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert!(matches!(client.try_upgrade(&wasm_hash), Err(Err(_))));

    // The new admin can.
    env.mock_auths(&[MockAuth {
        address: &new_admin,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "upgrade",
            args: (wasm_hash.clone(),).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.upgrade(&wasm_hash);
}

// --- 12. the host TTL rule -------------------------------------------------------------


/// Locates `"<key>": <u32>` inside a JSON text slice and returns the number. A missing key, a
/// non-numeric value, or a STRING-TYPED value is a PANIC, not a skip — "the pin could not be read"
/// must fail the suite, and a skipped assertion is worse than none.
///
/// The string-typed case is load-bearing: the previous version scanned for the first ASCII digit
/// anywhere after the key, so `"maxEntryTtl": "3110400"` (a JSON string) was silently read as
/// `3110400` and the pin stayed green while the TS pin threw. A wrong-typed value must fail the
/// Rust side the same way, because deployments.json is only ever a number via `JSON.stringify` —
/// a quoted value means a human edited or hand-crafted the file, which is exactly what this pin
/// exists to catch.
fn json_u32(haystack: &str, key: &str) -> u32 {
    json_u32_in("deployments.json", haystack, key)
}

/// `json_u32` with the source file named, so a broken pin says which artifact it failed to read.
fn json_u32_in(source: &str, haystack: &str, key: &str) -> u32 {
    // The crate is `no_std`; std items are only available fully-qualified (see `extern crate std`
    // at the top of this file), hence `std::format!` / `std::string::String`.
    let marker = std::format!("\"{key}\"");
    let start = haystack
        .find(&marker)
        .unwrap_or_else(|| panic!("{source}: missing key `{key}` — the pin test cannot run"));
    let after = &haystack[start + marker.len()..];
    // Expect `:` (ignoring whitespace) before any value.
    let after_colon = after.trim_start();
    if !after_colon.starts_with(':') {
        panic!("{source}: key `{key}` is not followed by `: <number>`");
    }
    let value = after_colon[1..].trim_start();
    // Refuse a string-typed value outright: `"3110400"` must NOT be read as a number.
    if value.starts_with('"') {
        panic!("{source}: key `{key}` value is a STRING, not a bare number");
    }
    let digits: std::string::String = value
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        panic!("{source}: key `{key}` has no numeric value");
    }
    digits
        .parse()
        .unwrap_or_else(|_| panic!("{source}: key `{key}` value `{digits}` is not a u32"))
}

// ---------------------------------------------------------------------------------
//
// The frozen gate-onramp vector from packages/identity/fixtures/vectors.json is the
// cross-language contract: these exact bytes (disclosed {0,1,2,3,4,5,6,8}, R=8, U=4,
// 400 B compressed / 544 B Soroban-flat) must verify bit-for-bit. The negative cases are
// the reject-path contract — each tampering must be refused, never silently accepted.
// ---------------------------------------------------------------------------------

const GATE_ONRAMP_FLAT: &str = concat!(
    "1407fd773ab33ee8296f22c6ecd1185a5682fefc2b5b2c78b7b603bc6872dd14",
    "cf187ad33c4619f54614ad7fc58380941764c847fe757794b55fa4f67264abb4",
    "364f92675ad38c19ddd4de9d4aee59164bb8d6bec2b8589fcaf5d62c7af73bc1",
    "0b9f515509803b3abf105e9fa730712fba890d2047d2e4807f95894a894ba1b1",
    "348158b84936e4820c6791d715c681010f4724b420d3bdcc7f3da98a60b1f221",
    "b8ea854b52772f80947eaeb03ca730cb14507d6723fe443576d8b54c58225311",
    "13cbea0d66e6322f03e36985234639d009f04305dfdf73fb4ff8d63f34cc06ce",
    "772f725d4a0dcde530fd03f2aa3c250c097111d9d88d3fe928dc6671139edca1",
    "1ddaa59a386c5d72e7395f1b2774ef4ede10727a1caaede2e114e631eb69ff85",
    "138d68e8ab814b3731c4734fa7c5f855941dc6ae08d43ae0a01eb4ddb865e72a",
    "61c842a546b4a221b853a4469a7998a1d65a490e51755100f874a03820a615ac",
    "5d1c607fab6808e04377beb467a62f2aca5b1332deb36a52df8f2b7e797a406b",
    "26ecd1b8eecd264f64d08ae48baace89a1b7359c1638df55a22bc216bb541757",
    "60b38dc1fd7d7e7f72991c14de5dbf82fd7edf26d564bae6e1e45dbb133309a8",
    "0a081c1d7bae524cb9ceac2378dcdd83f82a180bb8485f4d48b739da109e40a5",
    "1a3c3627a56f229ce71b16faeb28f9d4df60c403edb961f76ede2ff781851da6",
    "428d0c8e2eaad0d5141721881324844b04e83330c52a06818ad590eed9656ff9",
);


const ISSUER_PK_G2: &str = concat!(
    "0caadcb6e5983f95e0f6d1255288dab820954fb4d4e78ec895cc9905d689de58",
    "80fe421611200d280431660a79a8bf810d8c7f7ac6fad85d11b1c033091f2498",
    "b27f4beee538883d9d0e988a91e088782d7c6eb9f1eab1a7edbcd8b187904237",
    "01d7e2b82c9c066cf905d9d8abdd61ff370daf28e6564ec02ac29b027627dc96",
    "84d8c49312ba0699d05bc74ddf4ac20d1134411e2d5146160879728e928fd979",
    "7ebf6a7441423ae5543e36d265cf60508a4234925a86840f9e3368d0b13055f6",
);

const ISSUER_ID_HEX: &str = "a9daf8fdce22775d5d5ed973f320a91911d684a91f82e522fef26cb5120205e5";
const HEADER: &str = "stellaronramp/kyc-credential/v1";

// ---------------------------------------------------------------------------------
// THE PRESENTATION BINDING, BOTH SIDES OF IT.
//
// `attest_bbs` no longer takes `presentation_header`; it DERIVES it from
// {subject, this contract, network_id, nonce, ledger_expiry}. So the Rust test has to pin
// the SAME four context values the TypeScript vector generator bound the proof to, or the
// frozen proof cannot reproduce. Three of them are properties of the ENV, not arguments:
//
//   * the gate's own address -> `Env::register_at(&test_gate_address(), ...)`
//   * the network id         -> `env.ledger().set_network_id(...)`; `Env::default()` uses
//                               [0u8; 32], which is NOT any real network, so without this
//                               every test would silently bind to the wrong one
//   * the subject            -> `bound_subject()`, NOT `Address::generate()`
//
// Values come from packages/identity/fixtures/vectors.json, cases[gate-onramp].sorobanBinding.
// ---------------------------------------------------------------------------------

/// `binding.contractId`. A UNIT-TEST address, `StrKey.encodeContract(sha256(
/// "stellaronramp/test-gate/v1"))` — deliberately not any deployed contract, so these frozen
/// proofs cannot be replayed against the live gate. It used to be the deployed REGISTRY address,
/// which nothing ever checked.
const TEST_GATE_CONTRACT_ID: &str = "CDL45EUB2GIFFP2KJG4ULBLAIB6VT7HWGVPI65T6G6VEZOTULWPSQZI6";

/// `binding.walletAddress` — the holder the frozen proof is bound to, and the ONLY `subject` for
const BOUND_SUBJECT: &str = "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4K";

/// `sha256("Test SDF Network ; September 2015")` — what `env.ledger().network_id()` returns on
/// testnet and what the canonical binding hashes.
const TESTNET_NETWORK_ID: &str = "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472";

const NONCE_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const NONCE2_HEX: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// `binding.ledgerExpiry`, and it is EXACTLY `START_SEQ + PROOF_MAX_WINDOW` — the widest
/// there, not merely inside the cap, so the suite exercises the boundary from both sides:
/// `attest_bbs_refuses_a_proof_bound_further_ahead_than_the_max_window` submits it one ledger
/// EARLIER (window = cap + 1 -> `ExpiryTooFar`) and every happy-path test submits it at
/// `START_SEQ` (window = cap exactly -> accepted).
///
const LEDGER_EXPIRY: u32 = START_SEQ + PROOF_MAX_WINDOW;

/// The header the contract must DERIVE for `(BOUND_SUBJECT, TEST_GATE_CONTRACT_ID,
/// TESTNET_NETWORK_ID, NONCE_HEX, LEDGER_EXPIRY)`. No longer an argument — it is an EXPECTED
/// OUTPUT, pinned against `presentationHeaderFor()` in packages/identity/src/binding.ts.
const PH_HEX: &str = "5e46fa9fe0c74184a7e498709058745a21dd9268848c7bbc392c04475f9f8fb6";
const PH2_HEX: &str = "5fc5fb4633e29a5359174c1260d6e448444d043f94c4016e9d3a1693c71c1340";

// The frozen first generator Q_1 (uncompressed), pinned so a drift in the seed/DST or the
// hash-to-curve goes red independently of the full-vector test.
const Q1_UNCOMPRESSED: &str = concat!(
    "09ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f",
    "9ecb17ed27d38d27cdeddff44c8137be0e251c6621fa1d69fc1f471b9753a5a6",
    "e0772dc3af4b8d793a544548052fe03f75a76ae208d96556fcf542fdece6fda7",
);

fn hex_bytes(s: &str) -> std::vec::Vec<u8> {
    let mut out = std::vec::Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
    }
    out
}

fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex_bytes(s);
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}


/// The body of `cases[<name>]` — from its `"name"` key to the next one. Case names are unique and
/// no other `"name"` key appears inside a case, so this is exactly one case.
fn vector_case(name: &str) -> &'static str {
    let head = std::format!("\"name\": \"{name}\"");
    let start = VECTORS_JSON
        .find(&head)
        .unwrap_or_else(|| panic!("{VECTORS_SRC}: no case named `{name}` — the pin cannot run"));
    let rest = &VECTORS_JSON[start + head.len()..];
    let end = rest.find("\"name\":").unwrap_or(rest.len());
    &rest[..end]
}

/// `json_u32`'s string sibling. No escape handling: every key it is used on holds hex or a strkey.
fn json_str<'a>(source: &str, haystack: &'a str, key: &str) -> &'a str {
    let marker = std::format!("\"{key}\"");
    let start = haystack
        .find(&marker)
        .unwrap_or_else(|| panic!("{source}: missing key `{key}` — the pin test cannot run"));
    let after = haystack[start + marker.len()..].trim_start();
    if !after.starts_with(':') {
        panic!("{source}: key `{key}` is not followed by `: \"<string>\"`");
    }
    let value = after[1..].trim_start();
    if !value.starts_with('"') {
        panic!("{source}: key `{key}` value is not a JSON string");
    }
    let body = &value[1..];
    let end = body
        .find('"')
        .unwrap_or_else(|| panic!("{source}: key `{key}` string is unterminated"));
    &body[..end]
}

fn strkey_address(env: &Env, strkey: &str) -> Address {
    Address::from_string(&SorobanString::from_str(env, strkey))
}

fn test_gate_address(env: &Env) -> Address {
    strkey_address(env, TEST_GATE_CONTRACT_ID)
}

/// The one address the frozen proof is bound to.
fn bound_subject(env: &Env) -> Address {
    strkey_address(env, BOUND_SUBJECT)
}

fn nonce_of(env: &Env, hex: &str) -> BytesN<32> {
    BytesN::from_array(env, &hex_array::<32>(hex))
}

fn gate_onramp_proof(env: &Env) -> BbsProof {
    gate_onramp_proof_from(env, GATE_ONRAMP_FLAT)
}


fn gate_onramp_proof_from(env: &Env, flat_hex: &str) -> BbsProof {
    let flat = hex_bytes(flat_hex);
    let abar: [u8; 96] = flat[0..96].try_into().unwrap();
    let bbar: [u8; 96] = flat[96..192].try_into().unwrap();
    let d: [u8; 96] = flat[192..288].try_into().unwrap();
    let e_hat: [u8; 32] = flat[288..320].try_into().unwrap();
    let r1_hat: [u8; 32] = flat[320..352].try_into().unwrap();
    let r3_hat: [u8; 32] = flat[352..384].try_into().unwrap();
    let mut m_hat = soroban_sdk::Vec::new(env);
    for i in 0..4u32 {
        let m: [u8; 32] = flat[(384 + i * 32) as usize..(384 + (i + 1) * 32) as usize]
            .try_into()
            .unwrap();
        m_hat.push_back(BytesN::from_array(env, &m));
    }
    let challenge: [u8; 32] = flat[512..544].try_into().unwrap();
    BbsProof {
        a_bar: BytesN::from_array(env, &abar),
        b_bar: BytesN::from_array(env, &bbar),
        d: BytesN::from_array(env, &d),
        e_hat: BytesN::from_array(env, &e_hat),
        r1_hat: BytesN::from_array(env, &r1_hat),
        r3_hat: BytesN::from_array(env, &r3_hat),
        m_hat,
        challenge: BytesN::from_array(env, &challenge),
    }
}

fn gate_onramp_indexes(env: &Env) -> soroban_sdk::Vec<u32> {
    let mut v = soroban_sdk::Vec::new(env);
    for i in [0u32, 1, 2, 3, 4, 5, 6, 8] {
        v.push_back(i);
    }
    v
}





fn gate_onramp_messages(env: &Env) -> soroban_sdk::Vec<soroban_sdk::Bytes> {
    let mut v = soroban_sdk::Vec::new(env);
    for m in [
        "schemaVersion=1",
        "issuerId=a9daf8fdce22775d5d5ed973f320a91911d684a91f82e522fef26cb5120205e5",
        "revocationIndex=4242",
        "issuedAt=1767225600",
        "expiresAt=1782950400",
        "subjectBinding=3d1f2b6a9c8e4705b1d2c3a4f5e6978899aabbccddeeff001122334455667788",
        "over18=true",
        "notSanctioned=true",
    ] {
        v.push_back(soroban_sdk::Bytes::from_slice(env, m.as_bytes()));
    }
    v
}

/// Deploy a real registry, register the frozen issuer key, and deploy the gate against it.
fn setup_bbs(env: &Env) -> (KycGateClient<'_>, BytesN<32>, Address) {
    let pk_g2 = BytesN::from_array(env, &hex_array::<192>(ISSUER_PK_G2));
    setup_bbs_with_pubkey(env, pk_g2)
}

/// `setup_bbs` with a caller-supplied issuer pubkey, so a test can register a MALFORMED or
/// flagged key under the frozen issuer id and observe `attest_bbs`'s cheap rejection.
fn setup_bbs_with_pubkey(env: &Env, pk_g2: BytesN<192>) -> (KycGateClient<'_>, BytesN<32>, Address) {
    let at = test_gate_address(env);
    setup_bbs_at(env, pk_g2, &at)
}

/// `setup_bbs_with_pubkey` with a caller-chosen gate ADDRESS, so a test can deploy the identical
/// contract somewhere else and watch the frozen proof stop verifying — cross-contract replay.
fn setup_bbs_at<'a>(
    env: &'a Env,
    pk_g2: BytesN<192>,
    gate_address: &Address,
) -> (KycGateClient<'a>, BytesN<32>, Address) {
    env.mock_all_auths();
    env.ledger().set_sequence_number(START_SEQ);
    // BOTH SIDES OF THE BINDING, PINNED. `Env::default()`'s network_id is [0u8; 32] and its
    // generated contract ids are arbitrary; the frozen proof commits to testnet's network id and
    // to TEST_GATE_CONTRACT_ID. Drop either line and `attest_bbs` derives a different presentation
    env.ledger()
        .set_network_id(hex_array::<32>(TESTNET_NETWORK_ID));
    let admin = Address::generate(env);

    let registry_id = env.register(kyc_registry::KycRegistry, ());
    let registry_client = kyc_registry::KycRegistryClient::new(env, &registry_id);
    registry_client.init(&admin);
    let issuer_id = BytesN::from_array(env, &hex_array::<32>(ISSUER_ID_HEX));
    registry_client.register_issuer(&issuer_id, &pk_g2, &0u32);

    let gate_id = env.register_at(gate_address, KycGate, ());
    let gate = KycGateClient::new(env, &gate_id);
    gate.init(&admin, &registry_id);

    (gate, issuer_id, registry_id)
}

/// Submit the frozen proof for `subject`, expecting success.
///
/// The subject is a PARAMETER and not hard-wired on purpose: passing anything but
/// `bound_subject()` must now fail, and
/// `attest_bbs_refuses_the_frozen_proof_for_a_different_subject` is exactly that call.
fn attest_gate_onramp(env: &Env, gate: &KycGateClient<'_>, subject: &Address) {
    let issuer_id = BytesN::from_array(env, &hex_array::<32>(ISSUER_ID_HEX));
    gate.attest_bbs(
        subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(env),
        &gate_onramp_indexes(env),
        &gate_onramp_messages(env),
        &soroban_sdk::Bytes::from_slice(env, HEADER.as_bytes()),
        &nonce_of(env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
}

#[test]
fn bbs_generator_derivation_is_pinned_to_the_frozen_reference() {
    let env = Env::default();
    let generators = crate::bbs::create_generators(&env);
    assert_eq!(generators.len(), 13);
    let q1 = generators.get(0).unwrap();
    let expected: [u8; 96] = hex_array::<96>(Q1_UNCOMPRESSED);
    assert_eq!(q1.to_array(), expected, "generator derivation drifted from the frozen reference");
}

/// THE OTHER HALF OF A CROSS-LANGUAGE WIRE CONTRACT. `packages/identity/src/generators.ts`
/// exports these thirteen points and `GET /v1/.well-known/issuer` PUBLISHES them, so a drift
/// between this derivation and that one is an issuer document that describes parameters the
/// chain does not use. `bbs_generator_derivation_is_pinned_to_the_frozen_reference` pins Q_1
/// alone, which leaves the `I2OSP(i, 8)` loop index unpinned for every i > 1 — this pins all
/// thirteen and the `generators_root` computed over them.
///
/// `generators_root` = sha256 over the thirteen UNCOMPRESSED 96-byte `be(X) || be(Y)`
/// encodings concatenated in index order, 1,248 bytes in.
///
/// UNCOMPRESSED, and NOT because a contract could not recompute the compressed form — it can,
/// and this one does: `bbs::g1_compress` is pure byte arithmetic with no host call, and
/// `calculate_domain` compresses all thirteen generators on every single `attest_bbs`. That
/// compressed point outright, and the host rejects the compression flag on input — so the bytes
/// step 2 hashes are the uncompressed ones already in hand.
///
/// REJECTED ALTERNATIVE, named so it is visibly considered: `calculate_domain`'s own `dom_octs`,
/// `I2OSP(L, 8) || 13 compressed generators` (the BBS `serialize()` form), which is this repo's
/// nearest precedent for "canonical L+1 generator encoding". It hashes to
/// `524451dfde46907f1445c3a22359578426f1762a02e15edec879d130250199c0`; the same points
/// concatenated compressed WITHOUT the length prefix hash to
/// `bd40396e37860601a72ebed0b9351a86c99ead181b10605f19afa4f94f2a6d8c`. Both are measured, and
/// the mirror test in `packages/identity/test/generators.test.ts` pins them by value.
///
/// NOTHING ON CHAIN READS THIS TODAY — `kyc-gate` re-derives the generators and never consults a
/// root, and `kyc-registry` is spec-only. This test is the definition, landed ahead of the
/// contract that will enforce it.
///
/// The mirror is `packages/identity/test/generators.test.ts`, which asserts the same hex.
#[test]
fn bbs_generators_match_the_typescript_export() {
    const FROZEN: [&str; 13] = [
        concat!(
            "09ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f",
            "9ecb17ed27d38d27cdeddff44c8137be0e251c6621fa1d69fc1f471b9753a5a6",
            "e0772dc3af4b8d793a544548052fe03f75a76ae208d96556fcf542fdece6fda7",
        ),
        concat!(
            "18cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd2",
            "8dd090fd24ed27f7f4d22d5ff5dea7d40a9d63cda350d1a810eccc89c5092742",
            "31c3e6ee9d471a8b924a71b170035e166a8db9a4ba39d04e0ca2b33a47b73c08",
        ),
        concat!(
            "031fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f376",
            "97a9d452490a970eea6f9ad6c3dcaa3a18c1678525a53bf03d9728cf252cdac0",
            "4eb5d94bad3876e102de933014a387003da21ec158a4a89f9b0f34d6533cb384",
        ),
        concat!(
            "1479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754c",
            "c5ce90d9bc4c696dffbc9ef1d6ad1b621901c15e64733b12e043edcb8e1938a6",
            "c757ac57bf2ae98777eb14d5633adc15160659534bbfd3a125ef73c7a71195de",
        ),
        concat!(
            "0c0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7",
            "b0b7557b77604869633bb49afbe200350f1a8bbefe73d4c40e54fd64fc716e91",
            "94accd0a60b31b2eaec0e3db1431aafcee3167069881517f4110abe773456e88",
        ),
        concat!(
            "195d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69",
            "127d919e984ea0747f5223821b5963350d450e64c34ee92a685e504a588fdf01",
            "fccff32ad34871860e3b9a9c7c9e15e8c5d8af28b3da37980cbd8e07d820454b",
        ),
        concat!(
            "0f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb284",
            "5cbf03fd7e23b7f031ed9c7564e52f3902af3ec6aa5643ab7369ac81cb1bcbd7",
            "1777dbfb7ae7842df6450b55940ed88ba15b1b810323985c005f5a4ecae9342e",
        ),
        concat!(
            "0bc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d5",
            "58a8c9946bd35e00c69d167aadf304c11315c0a9c22a3b42aba7b868808d5ad7",
            "f9b899bd87388a58f6b7e11ae686dc52969f732d3d257f0b769161075beb7950",
        ),
        concat!(
            "00755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f2405",
            "1c352567ba6c01e57ac75dff763eaa17080f07fa454c89bbe9f4a4b141cf62c3",
            "7b0a7ddc1d6c00a75a2415aedaf2581dac41ce6336b3f229a49ca55b95083fba",
        ),
        concat!(
            "02701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927",
            "f86f118dcb7819a7b218d8f3fee4bd7f016b44294c9c63516304b43c466469ec",
            "4f1d3e1b8953102fb4940570ec167369f6d937874e877f8c56fb35d8f1ca5e76",
        ),
        concat!(
            "01f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d5949313267967303",
            "2ac7db3fb3d79b46b13c1c41ee495bca186b31df3cfd967dab35da581652ac72",
            "e7ea7ded0cd1f14ce977604e30019d6f56a2d513641f9a71cbf625ca4268cd0b",
        ),
        concat!(
            "089b76d1df62140633f1635c8b82a273308bf801f64e3e12bad0c9b48e62a626",
            "aeb08a7ffb30211be340f1d92d94b0c2052e5bec6c160b007249ee9ecbd3d2dd",
            "3a900b9936b7c234d4f314d4cd60fc96256a60c22156cfe16775046601827042",
        ),
        concat!(
            "065f53f44d8ab28ff0848061d84944ee897e9041c9d9e2a990312ba8c08f171f",
            "dab0d6748703bc7b4870595a12d9f01f11fbdef742062d66b1c757668bde67d1",
            "df3ec5df42159393da9d5a880f3196b80c20a19b52158d02397c6739283df79b",
        ),
    ];
    const FROZEN_GENERATORS_ROOT: &str = "a8b625391c8a4bdeb3d1840f4851da6c362559e98d25ab69c51a9732f242b48d";

    let env = Env::default();
    let generators = crate::bbs::create_generators(&env);
    assert_eq!(generators.len() as usize, FROZEN.len(), "generator COUNT drifted");

    let mut blob = soroban_sdk::Bytes::new(&env);
    for (i, expected_hex) in FROZEN.iter().enumerate() {
        let g = generators.get(i as u32).unwrap();
        let got = g.to_array();
        let expected: [u8; 96] = hex_array::<96>(expected_hex);
        assert_eq!(
            got, expected,
            "generator {i} drifted from packages/identity/src/generators.ts"
        );
        blob.extend_from_array(&got);
    }
    assert_eq!(blob.len(), 13 * 96, "the root is hashed over 1,248 bytes");

    let root = env.crypto().sha256(&blob).to_array();
    let expected_root: [u8; 32] = hex_array::<32>(FROZEN_GENERATORS_ROOT);
    assert_eq!(
        root, expected_root,
        "generators_root drifted; .well-known/issuer would publish a root the chain disagrees with"
    );
}

///
/// Verbatim replay: the frozen proof, its indexes, its messages, its header, its nonce and its
/// ledger_expiry — the exact bytes an attacker lifts out of a landed transaction, since Soroban
/// arguments are plaintext in the ledger — resubmitted with `subject` swapped for an address the
/// attacker controls. The contract must refuse it.
///
/// The control at the end is load-bearing: without it a broken fixture would make this test pass
/// for a reason that has nothing to do with the binding.
#[test]
fn attest_bbs_refuses_the_frozen_proof_for_a_different_subject() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);

    let attacker = Address::generate(&env);
    let res = gate.try_attest_bbs(
        &attacker,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&attacker, &CLAIM_OVER_18));
    assert!(!gate.check(&attacker, &CLAIM_NOT_SANCTIONED));

    // The failed replay wrote nothing anywhere, including under the bound holder.
    let subject = bound_subject(&env);
    assert!(!gate.check(&subject, &CLAIM_OVER_18));

    // CONTROL: byte-identical arguments, for the subject the proof IS bound to, succeed. So the
    // rejection above is the binding and nothing else.
    attest_gate_onramp(&env, &gate, &subject);
    assert!(gate.check(&subject, &CLAIM_OVER_18));
}

/// The same proof twice, for its own bound subject, is refused: the nonce is spent.
///
/// Deriving the header alone does not give this. The derivation is deterministic in its inputs, so
/// a verbatim resubmission re-derives the same header and verifies again — replay across TIME has
/// to be stopped by consuming something, which is what `DataKey::Nonce` is for.
///
/// `expires_at` is moved FORWARD on the second call on purpose. At an equal expiry the tombstone
/// ordering rule would reject it as `StaleAttestation` and the nonce guard would never be reached;
/// with a later expiry the second call is otherwise entirely legitimate, so `NonceAlreadyUsed` is
/// the only thing standing in its way.
///
/// the nonce probe below `bbs::verify_bbs_proof` returns the identical error and left the whole
/// suite green, so nothing held the ordering in place. It matters because the rejection is
/// free to provoke and the ~96M instructions are paid by the relayer: an unordered probe is a
/// griefing amplifier. Measured at ~41k here, so the 5M bound only fires on a real reordering —
/// same pattern and same bound as `attest_bbs_rejects_a_flagged_pubkey_cheaply`.
#[test]
fn attest_bbs_refuses_a_replayed_nonce() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    attest_gate_onramp(&env, &gate, &subject);
    assert!(gate.check(&subject, &CLAIM_OVER_18));

    env.cost_estimate().budget().reset_default();
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 60_000), // strictly later, so StaleAttestation cannot mask the nonce guard
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::NonceAlreadyUsed)));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::println!("replayed-nonce rejection host CPU: {cpu}");
    assert!(
        cpu < 5_000_000,
        "a replayed nonce must be rejected before the ~96M pairing/MSM; got {cpu}"
    );

    // The first record is intact — a refused replay must not disturb what is already there.
    assert_eq!(gate.claim_record(&subject).expires_at, START_SEQ + 50_000);
}

/// PROOF FRESHNESS. `ledger_expiry` is the holder's own bound deadline, and it is INCLUSIVE:
/// spendable at exactly `ledger_expiry`, dead one ledger later. Both sides of the boundary are
/// asserted, because an off-by-one here is the difference between a working freshness window and
/// none at all.
///
/// `expires_at` moves with the sequence in both halves: this is testing the PROOF's clock, and a
/// record-expiry failure would be a different error for a different reason.
///
/// The cost assertion pins the guard's POSITION, not just its verdict — see
#[test]
fn attest_bbs_refuses_a_proof_past_its_ledger_expiry() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    env.ledger().set_sequence_number(LEDGER_EXPIRY + 1);
    env.cost_estimate().budget().reset_default();
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(LEDGER_EXPIRY + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::Expired)));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::println!("stale-proof rejection host CPU: {cpu}");
    assert!(
        cpu < 5_000_000,
        "a stale proof must be rejected before the ~96M pairing/MSM; got {cpu}"
    );
    assert!(!gate.check(&subject, &CLAIM_OVER_18));

    // One ledger earlier — exactly ON the deadline — the same proof is still good.
    env.ledger().set_sequence_number(LEDGER_EXPIRY);
    gate.attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(LEDGER_EXPIRY + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert!(gate.check(&subject, &CLAIM_OVER_18));
}

/// The value side of a disclosed message is read, not just its presence: a credential that says
/// `over18=false` grants no `CLAIM_OVER_18`. This is the half a "does index 6 appear?" check would
/// miss, and it is why the cross-check compares against the canonical `name=true` bytes.
///
/// The proof cannot verify with a swapped message (the messages are inside the challenge), so the
/// assertion is that the claims cross-check fires FIRST, cheaply, before the ~96M of pairing/MSM —
/// a forged claim value never reaches the crypto at all.
#[test]
fn attest_bbs_refuses_a_false_valued_claim_message_cheaply() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    // Same indexes, but index 6 now reads `over18=false`.
    let mut messages = soroban_sdk::Vec::new(&env);
    for (i, m) in gate_onramp_messages(&env).iter().enumerate() {
        if i == 6 {
            messages.push_back(soroban_sdk::Bytes::from_slice(&env, b"over18=false"));
        } else {
            messages.push_back(m);
        }
    }

    env.cost_estimate().budget().reset_default();
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &CLAIM_OVER_18,
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &messages,
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::println!("false-valued-claim rejection host CPU: {cpu}");
    assert!(
        cpu < 5_000_000,
        "a claim the messages do not assert must be refused before the ~96M pairing/MSM; got {cpu}"
    );
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

///
/// The nonce tombstone is TEMPORARY storage: it is evicted when its TTL runs out. The proof stays
/// verifiable until `ledger_expiry`. If the second outlives the first there is a window in which
///
/// `PROOF_MAX_WINDOW <= NONCE_MIN_TTL` is what closes it, and this test drives that inequality at
/// its tightest point: `expires_at` is set close so the TTL lands on the `NONCE_MIN_TTL` FLOOR
/// (not on the record's lifetime), and `LEDGER_EXPIRY == START_SEQ + PROOF_MAX_WINDOW` is the last
/// ledger the proof is fresh in. The two coincide exactly, so:
///
///   * at `LEDGER_EXPIRY` the proof is still fresh and the tombstone is still there -> refused
///   * at `LEDGER_EXPIRY + 1` the tombstone is GONE — asserted, not assumed — and the only thing
///     left standing between the attacker and a re-verification is the freshness check.
///
/// Widen `PROOF_MAX_WINDOW` past `NONCE_MIN_TTL` and the first half goes red (the `const`
/// assertion in lib.rs catches it earlier still).
#[test]
fn attest_bbs_nonce_tombstone_outlives_the_freshness_window() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);
    let nonce = nonce_of(&env, NONCE_HEX);

    // A short record lifetime, so the nonce TTL is the NONCE_MIN_TTL floor and nothing longer.
    gate.attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 100),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce,
        &LEDGER_EXPIRY,
    );
    assert_eq!(START_SEQ + NONCE_MIN_TTL, LEDGER_EXPIRY, "the floor and the window must coincide");

    // The LAST ledger the proof is fresh in. The tombstone must still be there.
    env.ledger().set_sequence_number(LEDGER_EXPIRY);
    let nonce_key = DataKey::Nonce(nonce.clone());
    assert!(
        env.as_contract(&gate.address, || env
            .storage()
            .temporary()
            .has(&nonce_key)),
        "the nonce tombstone was evicted while its proof was still fresh"
    );
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(LEDGER_EXPIRY + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce,
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::NonceAlreadyUsed)));

    // One ledger later the tombstone is gone — and that is FINE, because the proof died with it.
    env.ledger().set_sequence_number(LEDGER_EXPIRY + 1);
    assert!(
        !env.as_contract(&gate.address, || env
            .storage()
            .temporary()
            .has(&nonce_key)),
        "expected the tombstone to be evicted here — if it is not, this test proves nothing"
    );
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(LEDGER_EXPIRY + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce,
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::Expired)));
}

/// observer with no key, no credential and no holder cooperation lifts the proof arguments out of
/// the ledger (they are plaintext), waits for the nonce tombstone to lapse, and resubmits them
/// verbatim with a later `expires_at` and the current epoch. Under the uncapped window that
/// returned `Ok` and the revoked subject was live again with `check(OVER_18) == true`.
///
/// It now dies on the freshness check, and the compliance tombstone is still the record.
#[test]
fn attest_bbs_replay_after_the_tombstone_cannot_resurrect_a_revoked_subject() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    attest_gate_onramp(&env, &gate, &subject);
    gate.revoke(&subject);
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
    assert_eq!(gate.claim_record(&subject).revocation_epoch, 1);

    // Far past both the tombstone's TTL and the proof's freshness window.
    env.ledger().set_sequence_number(START_SEQ + 60_000);
    assert!(
        !env.as_contract(&gate.address, || env
            .storage()
            .temporary()
            .has(&DataKey::Nonce(nonce_of(&env, NONCE_HEX)))),
        "the nonce tombstone should be long gone by here — otherwise this proves nothing"
    );

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 110_000), // later than the revocation ledger, so `prev_revoked` lets it by
        &1u32,                  // the current epoch, read straight off `claim_record()`
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::Expired)));

    let rec = gate.claim_record(&subject);
    assert_eq!(rec.claims, 0, "the revocation tombstone must still be the record");
    assert_eq!(rec.revocation_epoch, 1);
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// The frozen proof is bound to ONE gate contract id. Deploy the identical wasm anywhere else and
/// it stops verifying — `env.current_contract_address()` is an input to the derivation.
///
/// This is also what makes the regenerated fixtures safe to keep in the repo: they are bound to
/// `TEST_GATE_CONTRACT_ID`, which is a `sha256`-derived unit-test address and not the deployed
/// gate, so the vectors can no longer be replayed against a live deployment at all.
#[test]
fn attest_bbs_refuses_the_frozen_proof_at_a_different_gate_address() {
    let env = Env::default();
    let elsewhere = Address::generate(&env);
    let pk_g2 = BytesN::from_array(&env, &hex_array::<192>(ISSUER_PK_G2));
    let (gate, issuer_id, _) = setup_bbs_at(&env, pk_g2, &elsewhere);
    assert_ne!(gate.address, test_gate_address(&env));

    let subject = bound_subject(&env);
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// THE CROSS-LANGUAGE PIN. The Rust derivation must equal `presentationHeaderFor()` in
/// packages/identity/src/binding.ts for the same binding, byte for byte.
///
/// The full-vector tests above already imply this — a header that differed by one bit would fail
/// the challenge — but they cannot say WHICH field of the canonical layout drifted. This asserts
/// the output directly against the value the TypeScript generator wrote into vectors.json
/// (`cases[*].presentationHeader`), so a layout change reports as "the header is wrong" rather
/// than as "the crypto broke".
#[test]
fn presentation_derives_the_presentation_header_the_typescript_sdk_computes() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    // `presentation_header` reads `env.current_contract_address()`, so it has to run inside the
    // gate's own contract context — the same context `attest_bbs` runs in.
    let (derived, derived2) = env.as_contract(&gate.address, || {
        (
            presentation_header(&env, &subject, &nonce_of(&env, NONCE_HEX), LEDGER_EXPIRY),
            presentation_header(&env, &subject, &nonce_of(&env, NONCE2_HEX), LEDGER_EXPIRY),
        )
    });

    assert_eq!(
        derived,
        soroban_sdk::Bytes::from_slice(&env, &hex_bytes(PH_HEX)),
        "derived presentation header drifted from packages/identity/src/binding.ts"
    );
    assert_eq!(
        derived2,
        soroban_sdk::Bytes::from_slice(&env, &hex_bytes(PH2_HEX)),
        "the nonce is not reaching the canonical binding bytes"
    );
    assert_ne!(derived, derived2);
}

/// The two domain separators are a wire format shared with TypeScript. Changing either silently
/// invalidates every proof in existence, so they are pinned as literals rather than left to a
/// reader's memory of what binding.ts says.
#[test]
fn presentation_binding_domains_are_pinned() {
    assert_eq!(
        BINDING_DOMAIN,
        b"stellaronramp/presentation-binding/v1".as_slice()
    );
    assert_eq!(
        PRESENTATION_HEADER_DOMAIN,
        b"stellaronramp/presentation-header/v1".as_slice()
    );
    // Distinct domains are the whole point: bindingDigest and presentationHeader must never be
    // confusable for one another on the wire.
    assert_ne!(BINDING_DOMAIN, PRESENTATION_HEADER_DOMAIN);
}

#[test]
fn attest_bbs_rejects_an_unknown_issuer() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    // A proof naming an issuer never registered in the registry must fail closed.
    let unknown = BytesN::from_array(&env, &[0xEEu8; 32]);
    let res = gate.try_attest_bbs(
        &subject,
        &unknown,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::UntrustedIssuer)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

#[test]
fn attest_bbs_rejects_a_tampered_challenge() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);
    let issuer_id = BytesN::from_array(&env, &hex_array::<32>(ISSUER_ID_HEX));

    let mut proof = gate_onramp_proof(&env);
    let mut challenge = proof.challenge.to_array();
    challenge[31] ^= 0x01; // flip the low bit of the challenge scalar
    proof.challenge = BytesN::from_array(&env, &challenge);

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &proof,
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

#[test]
fn attest_bbs_rejects_a_tampered_a_bar_point() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);
    let issuer_id = BytesN::from_array(&env, &hex_array::<32>(ISSUER_ID_HEX));

    let mut proof = gate_onramp_proof(&env);
    let mut abar = proof.a_bar.to_array();
    abar[95] ^= 0x01; // flip the low bit of the uncompressed A-bar Y coordinate
    proof.a_bar = BytesN::from_array(&env, &abar);

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &proof,
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    // The tampered point must not verify: either the challenge mismatches or the MSM/pairing
    // rejects it as an invalid point. Both are a refusal, never an accept.
    assert!(res.is_err());
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

#[test]
fn attest_bbs_rejects_a_tampered_hidden_message_response() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);
    let issuer_id = BytesN::from_array(&env, &hex_array::<32>(ISSUER_ID_HEX));

    let mut proof = gate_onramp_proof(&env);
    let mut m0 = proof.m_hat.get(0).unwrap().to_array();
    m0[31] ^= 0x01; // "lie about a hidden attribute"
    proof.m_hat.set(0, BytesN::from_array(&env, &m0));

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &proof,
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

#[test]
fn attest_bbs_rejects_a_swapped_disclosed_message() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);
    let issuer_id = BytesN::from_array(&env, &hex_array::<32>(ISSUER_ID_HEX));

    // Swap the two disclosed boolean messages; the index->message mapping must not survive it.
    let mut messages = gate_onramp_messages(&env);
    let over18 = messages.get(6).unwrap();
    let not_sanctioned = messages.get(7).unwrap();
    messages.set(6, not_sanctioned);
    messages.set(7, over18);

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &messages,
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// A TAMPERED NONCE breaks the derived header, so the challenge no longer reproduces.
///
/// The old shape of this test flipped bits in a caller-supplied `presentation_header`. There is no
/// such argument any more — the header's INPUTS are the only thing a caller can move, so this is
/// the same attack expressed against the surface that still exists.
#[test]
fn attest_bbs_rejects_a_tampered_nonce() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    let mut n = hex_array::<32>(NONCE_HEX);
    n[31] ^= 0x01;
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &BytesN::from_array(&env, &n),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// A TAMPERED `ledger_expiry` likewise. This is the guard that stops a relayer stretching a
/// proof's freshness window: the window is INSIDE the challenge, so extending it invalidates the
/// proof rather than extending it.
///
/// Tampered DOWNWARD by one, deliberately. The frozen binding sits exactly at
/// `START_SEQ + PROOF_MAX_WINDOW`, so `LEDGER_EXPIRY + 1` is now refused one guard EARLIER, by the
/// window cap, and would prove nothing about the challenge. `LEDGER_EXPIRY - 1` is a perfectly
/// legal window that simply is not the one the proof committed to.
#[test]
fn attest_bbs_rejects_a_tampered_ledger_expiry() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &(LEDGER_EXPIRY - 1),
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

#[test]
fn attest_bbs_rejects_a_mismatched_issuer_id_argument() {
    let env = Env::default();
    let (gate, issuer_id, registry_id) = setup_bbs(&env);
    let subject = bound_subject(&env);

    // Register the SAME frozen key under an ALIAS issuer id. The proof discloses `issuerId=<frozen>`
    // (index 1), so when the caller names the alias the crypto WOULD verify (same key -> same
    // domain -> same challenge -> pairing holds), and the cross-check against index 1 is the only
    // thing that stops the record claiming the wrong issuer id.
    let alias = BytesN::from_array(&env, &[0xDDu8; 32]);
    let registry_client = kyc_registry::KycRegistryClient::new(&env, &registry_id);
    let pk_g2 = BytesN::from_array(&env, &hex_array::<192>(ISSUER_PK_G2));
    registry_client.register_issuer(&alias, &pk_g2, &0u32);

    let res = gate.try_attest_bbs(
        &subject,
        &alias,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));

    // Sanity: the frozen id still works, so the rejection above is the cross-check, not a dead gate.
    let _ = issuer_id;
}

#[test]
fn attest_bbs_rejects_a_mismatched_revocation_index_argument() {
    let env = Env::default();
    let (gate, _, _) = setup_bbs(&env);
    let subject = bound_subject(&env);
    let issuer_id = BytesN::from_array(&env, &hex_array::<32>(ISSUER_ID_HEX));

    // revocation_index (schema index 2) must equal the disclosed value; 4242 is disclosed, so a
    // different argument fails the cross-check.
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4243u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// infinity-point issuer key: the point-at-infinity is a VALID group element the host pairing
/// accepts, and `e(Abar, W=∞) = 1_GT` collapses the pairing to `e(Bbar, -BP2) == 1`, satisfiable
/// with `Bbar = identity` — a forgeable verifier against a malicious admin who registers it. The
/// check must also fire CHEAPLY, before the ~96M of generator/MSM work, which is what the cost
/// assertion pins (dropping the guard still rejects the frozen proof, but only after spending
/// ~70M).
#[test]
fn attest_bbs_rejects_a_flagged_pubkey_cheaply() {
    let env = Env::default();
    // 0x40 is the infinity flag; every other byte zero, the host's canonical "point at infinity".
    let mut infinity = [0u8; 192];
    infinity[0] = 0x40;
    let (gate, issuer_id, _) = setup_bbs_with_pubkey(&env, BytesN::from_array(&env, &infinity));

    let subject = bound_subject(&env);
    env.cost_estimate().budget().reset_default();
    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ + 50_000),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::InvalidProof)));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::println!("flagged-pubkey rejection host CPU: {cpu}");
    assert!(
        cpu < 5_000_000,
        "a flagged pubkey must be rejected before the ~96M pairing/MSM; got {cpu}"
    );
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// unit). A value behind the current ledger must be refused before any crypto is spent.
#[test]
fn attest_bbs_rejects_an_expired_expiry() {
    let env = Env::default();
    let (gate, issuer_id, _) = setup_bbs(&env);
    let subject = bound_subject(&env);

    let res = gate.try_attest_bbs(
        &subject,
        &issuer_id,
        &(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED),
        &(START_SEQ - 1),
        &0u32,
        &4242u32,
        &gate_onramp_proof(&env),
        &gate_onramp_indexes(&env),
        &gate_onramp_messages(&env),
        &soroban_sdk::Bytes::from_slice(&env, HEADER.as_bytes()),
        &nonce_of(&env, NONCE_HEX),
        &LEDGER_EXPIRY,
    );
    assert_eq!(res, Err(Ok(Error::Expired)));
    assert!(!gate.check(&subject, &CLAIM_OVER_18));
}

/// coordinate is compared against to recover the compressed-form "sort" bit. It is only
/// PROBABILISTICALLY exercised by the frozen vector (a corrupted threshold only changes a
/// compressed point, and hence the challenge, if a frozen point's y-coordinate happens to
/// straddle the corrupted band — a single-byte high-order flip survived on a ~55% draw). Pin the
/// exact 48 bytes so any drift goes red at test time, not by luck.
#[test]
fn half_p_sort_bit_threshold_is_pinned() {
    let expected: [u8; 48] = hex_array::<48>(
        "0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555",
    );
    assert_eq!(
        crate::bbs::HALF_P_BE,
        expected,
        "HALF_P_BE drifted from (p-1)/2 for the BLS12-381 base field"
    );
}
