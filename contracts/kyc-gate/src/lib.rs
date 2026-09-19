#![no_std]
#![allow(clippy::too_many_arguments)]
//! BBS+ selective-disclosure verifier with a cached claim record per subject.
//!
//! Verifying a BBS+ proof on chain costs on the order of 10^8 instructions, and the network
//! caps a ledger at 580M, so it cannot be done on every transfer. The contract therefore
//! verifies a proof ONCE, at onboarding (`attest_bbs`), and stores a compact `ClaimRecord`
//! that any relying contract can read for a few thousand instructions (`check`).
//!
//! The verifier itself (`bbs.rs`) is written directly against the BLS12-381 host functions;
//! no pure-wasm pairing library is involved.

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    Bytes, BytesN, Env, Vec,
};

mod bbs;

/// Claims are a bitmap so a relying contract's check is one storage load and one AND.
/// Bit positions are frozen: never renumber, only append.
pub const CLAIM_OVER_18: u32 = 1 << 0;
pub const CLAIM_OVER_21: u32 = 1 << 1;
pub const CLAIM_NOT_SANCTIONED: u32 = 1 << 2;
pub const CLAIM_JURISDICTION_OK: u32 = 1 << 3;

/// Persistent-entry TTL policy, tuned to mainnet minimums (testnet's are far shorter).
/// A record is bumped back to ~120 days whenever it drops below ~60.
const CLAIM_TTL_THRESHOLD: u32 = 1_036_800;
const CLAIM_TTL_EXTEND_TO: u32 = 2_073_600;

/// A consumed nonce is a temporary entry. It must outlive the attestation it protects, and
/// its ceiling is `max_entry_ttl - 1` (the host requires `extend_to < max_entry_ttl`).
const NONCE_MIN_TTL: u32 = 17_280;
const NONCE_MAX_TTL: u32 = 3_110_399;

/// How far ahead a record may expire. It is the smaller of the two storage lifetimes
/// involved: a record must never outlive the nonce tombstone that stops its proof from
/// being replayed, nor the TTL its own entry is bumped to.
const MAX_EXPIRY_HORIZON: u32 = if CLAIM_TTL_EXTEND_TO < NONCE_MAX_TTL {
    CLAIM_TTL_EXTEND_TO
} else {
    NONCE_MAX_TTL
};

/// How far ahead of the current ledger a presentation's `ledger_expiry` may sit (~1 day).
/// A presentation is derived and submitted immediately; the short window is what makes the
/// consumed nonce meaningful: with `PROOF_MAX_WINDOW <= NONCE_MIN_TTL`, every ledger in which
/// a proof is still fresh is a ledger in which its nonce tombstone still exists.
const PROOF_MAX_WINDOW: u32 = 17_280;
const _: () = assert!(
    PROOF_MAX_WINDOW <= NONCE_MIN_TTL,
    "a proof must never stay fresh past the eviction of the nonce that was spent on it",
);

/// Domain separators for the presentation binding. They are the exact strings the off-chain
/// library uses; changing either invalidates every proof in existence.
const BINDING_DOMAIN: &[u8] = b"stellaronramp/presentation-binding/v1";
const PRESENTATION_HEADER_DOMAIN: &[u8] = b"stellaronramp/presentation-header/v1";

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Registry,
    /// subject -> ClaimRecord
    Claims(Address),
    /// Consumed proof nonces, temporary storage.
    Nonce(BytesN<32>),
}

/// A `ClaimRecord` with `claims == 0` is a revocation tombstone, not an attestation.
///
/// The struct is stored as a map keyed by field name, so adding or renaming a field makes
/// every existing record fail to decode. Migrate before changing it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRecord {
    pub claims: u32,
    /// Ledger sequence at which this record stops being honoured.
    pub expires_at: u32,
    pub issuer_id: BytesN<32>,
    /// Ledger sequence the record was written at. Audit trail only.
    pub issued_at: u32,
    /// Revocations this subject has ever had. Monotone, never reset; a proof is accepted only
    /// at the epoch it was derived for, so a proof made before a revocation can never come
    /// back after it.
    pub revocation_epoch: u32,
    /// Index of the credential behind this record in the issuer's status list. An audit link
    /// between the on-chain record and the off-chain revocation list; the contract never
    /// reads it back to decide anything.
    pub revocation_index: u32,
}

/// The proof in Soroban's uncompressed wire form:
///
///   a_bar(96) || b_bar(96) || d(96) || e_hat(32) || r1_hat(32) || r3_hat(32)
///     || m_hat(U × 32) || challenge(32)
///
/// `m_hat` holds one response per undisclosed message, in ascending hidden-index order. The
/// points are uncompressed because the host offers no decompression; the SDK decompresses
/// before submitting.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BbsProof {
    pub a_bar: BytesN<96>,
    pub b_bar: BytesN<96>,
    pub d: BytesN<96>,
    pub e_hat: BytesN<32>,
    pub r1_hat: BytesN<32>,
    pub r3_hat: BytesN<32>,
    pub m_hat: Vec<BytesN<32>>,
    pub challenge: BytesN<32>,
}

/// The `kyc-registry` error codes this contract can observe on a cross-contract call.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    IssuerNotFound = 3,
    IssuerAlreadyRegistered = 4,
}

/// The one `kyc-registry` entry point the verifier needs: the issuer's uncompressed G2 public
/// key, returned only while the issuer is registered, unrevoked and unexpired.
#[contractclient(name = "RegistryClient")]
pub trait RegistryTrait {
    fn active_key(env: &Env, issuer_id: BytesN<32>) -> Result<BytesN<192>, RegistryError>;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NoClaimRecord = 3,
    Expired = 4,
    NonceAlreadyUsed = 5,
    InvalidProof = 6,
    UntrustedIssuer = 7,
    /// An older attestation was replayed over a fresher live record.
    StaleAttestation = 10,
    /// An empty bitmap attests nothing and would only ever serve to wipe a live record.
    EmptyClaims = 12,
    /// `expires_at` or `ledger_expiry` is further ahead than the storage lifetimes allow.
    ExpiryTooFar = 13,
    /// The subject carries a revocation tombstone and the attestation does not clear it.
    SubjectRevoked = 14,
    /// The proof was derived for a `revocation_epoch` that is not the subject's current one.
    RevocationEpochMismatch = 15,
}

/// Emitted on every successful attestation.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attested {
    #[topic]
    pub subject: Address,
    pub claims: u32,
    pub expires_at: u32,
    pub issuer_id: BytesN<32>,
}

/// Emitted on every revocation. `revocation_epoch` is the epoch a later proof must be
/// derived for to be accepted for this subject.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revoked {
    #[topic]
    pub subject: Address,
    pub revoked_at: u32,
    pub revocation_epoch: u32,
}

/// Emitted on admin handover.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChanged {
    #[topic]
    pub old_admin: Address,
    #[topic]
    pub new_admin: Address,
}

fn append_len_prefixed(msg: &mut Bytes, field: Bytes) {
    msg.extend_from_array(&field.len().to_be_bytes());
    msg.append(&field);
}

fn strkey_bytes(addr: &Address) -> Bytes {
    addr.to_string().into()
}

/// The presentation header the holder MUST have bound the proof to. Derived on chain from
/// the submitted `subject`, `nonce` and `ledger_expiry` plus this contract's own address and
/// the network id, so a proof can only ever attest the subject it was made for, on this
/// contract, on this network, before its deadline. The caller cannot supply it.
fn presentation_header(
    env: &Env,
    subject: &Address,
    nonce: &BytesN<32>,
    ledger_expiry: u32,
) -> Bytes {
    let mut canonical = Bytes::new(env);
    append_len_prefixed(&mut canonical, Bytes::from_slice(env, BINDING_DOMAIN));
    append_len_prefixed(&mut canonical, Bytes::from_array(env, &nonce.to_array()));
    append_len_prefixed(&mut canonical, strkey_bytes(subject));
    append_len_prefixed(
        &mut canonical,
        strkey_bytes(&env.current_contract_address()),
    );
    append_len_prefixed(
        &mut canonical,
        Bytes::from_array(env, &env.ledger().network_id().to_array()),
    );
    append_len_prefixed(
        &mut canonical,
        Bytes::from_array(env, &ledger_expiry.to_be_bytes()),
    );

    let binding_digest = env.crypto().sha256(&canonical).to_array();
    let mut ph_input = Bytes::from_slice(env, PRESENTATION_HEADER_DOMAIN);
    ph_input.extend_from_array(&binding_digest);
    Bytes::from_array(env, &env.crypto().sha256(&ph_input).to_array())
}

fn hex32(env: &Env, bytes: &[u8; 32]) -> Bytes {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Bytes::new(env);
    for b in bytes {
        out.push_back(HEX[(b >> 4) as usize]);
        out.push_back(HEX[(b & 0x0f) as usize]);
    }
    out
}

fn decimal(env: &Env, mut v: u32) -> Bytes {
    if v == 0 {
        return Bytes::from_slice(env, b"0");
    }
    let mut buf = [0u8; 10];
    let mut i = 10;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    Bytes::from_slice(env, &buf[i..])
}

fn bytes_eq(a: &Bytes, b: &Bytes) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a.get(i) != b.get(i) {
            return false;
        }
    }
    true
}

/// True iff schema index `idx` is disclosed and its message equals `expected`.
fn disclosed_is(
    indexes: &Vec<u32>,
    messages: &Vec<Bytes>,
    idx: u32,
    expected: &Bytes,
) -> bool {
    for i in 0..indexes.len() {
        if indexes.get(i).unwrap() == idx {
            return bytes_eq(&messages.get(i).unwrap(), expected);
        }
    }
    false
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(CLAIM_TTL_THRESHOLD, CLAIM_TTL_EXTEND_TO);
}

fn read_claim(env: &Env, subject: &Address) -> Option<ClaimRecord> {
    env.storage()
        .persistent()
        .get(&DataKey::Claims(subject.clone()))
}

/// Write a tombstone: claims cleared, epoch advanced. The issuer id and audit index of the
/// previous record are preserved so the revocation stays traceable.
fn write_tombstone(env: &Env, subject: &Address, prev: Option<ClaimRecord>) {
    let seq = env.ledger().sequence();

    let epoch = match &prev {
        Some(p) => p.revocation_epoch.saturating_add(1),
        None => 1,
    };
    let (issuer_id, revocation_index) = match prev {
        Some(p) => (p.issuer_id, p.revocation_index),
        None => (BytesN::from_array(env, &[0u8; 32]), 0),
    };

    let claims_key = DataKey::Claims(subject.clone());
    env.storage().persistent().set(
        &claims_key,
        &ClaimRecord {
            claims: 0,
            expires_at: seq,
            issuer_id,
            issued_at: seq,
            revocation_epoch: epoch,
            revocation_index,
        },
    );
    env.storage()
        .persistent()
        .extend_ttl(&claims_key, CLAIM_TTL_THRESHOLD, CLAIM_TTL_EXTEND_TO);
    bump_instance(env);

    Revoked {
        subject: subject.clone(),
        revoked_at: seq,
        revocation_epoch: epoch,
    }
    .publish(env);
}

fn require_admin(env: &Env) -> Result<Address, Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(admin)
}

#[contract]
pub struct KycGate;

#[contractimpl]
impl KycGate {
    pub fn init(env: Env, admin: Address, registry: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Registry, &registry);
        bump_instance(&env);
        Ok(())
    }

    /// Verify a BBS+ selective-disclosure proof on chain and cache the granted claims.
    ///
    /// The issuer's public key is fetched from `kyc-registry`, so only a registered, live
    /// issuer is trusted. The proof must disclose the issuer id and revocation index it was
    /// issued with, and every claim bit requested must be backed by a disclosed `=true`
    /// attribute. The presentation header is derived here from the subject, nonce, deadline,
    /// this contract and the network, so the proof cannot be replayed for anyone or anywhere
    /// else; the nonce is then consumed so it cannot be replayed for the same subject either.
    ///
    /// Returns the claims written.
    pub fn attest_bbs(
        env: Env,
        subject: Address,
        issuer_id: BytesN<32>,
        claims: u32,
        expires_at: u32,
        revocation_epoch: u32,
        revocation_index: u32,
        proof: BbsProof,
        disclosed_indexes: Vec<u32>,
        disclosed_messages: Vec<Bytes>,
        header: Bytes,
        nonce: BytesN<32>,
        ledger_expiry: u32,
    ) -> Result<u32, Error> {
        if claims == 0 {
            return Err(Error::EmptyClaims);
        }

        let seq = env.ledger().sequence();
        if expires_at < seq {
            return Err(Error::Expired);
        }
        if expires_at - seq > MAX_EXPIRY_HORIZON {
            return Err(Error::ExpiryTooFar);
        }
        if seq > ledger_expiry {
            return Err(Error::Expired);
        }
        if ledger_expiry - seq > PROOF_MAX_WINDOW {
            return Err(Error::ExpiryTooFar);
        }

        let nonce_key = DataKey::Nonce(nonce.clone());
        if env.storage().temporary().has(&nonce_key) {
            return Err(Error::NonceAlreadyUsed);
        }

        if disclosed_indexes.len() != disclosed_messages.len() {
            return Err(Error::InvalidProof);
        }

        // Cheap checks first; the pairing is the expensive part and runs last.
        let registry: Address = env
            .storage()
            .instance()
            .get(&DataKey::Registry)
            .ok_or(Error::NotInitialized)?;
        let pubkey_g2: BytesN<192> = match RegistryClient::new(&env, &registry)
            .try_active_key(&issuer_id)
        {
            Ok(Ok(pk)) => pk,
            _ => return Err(Error::UntrustedIssuer),
        };
        // Uncompressed encoding only: the top three flag bits must be clear.
        if pubkey_g2.to_array()[0] & 0xE0 != 0 {
            return Err(Error::InvalidProof);
        }

        let expected_issuer = {
            let mut m = Bytes::from_slice(&env, b"issuerId=");
            m.append(&hex32(&env, &issuer_id.to_array()));
            m
        };
        let expected_rev_index = {
            let mut m = Bytes::from_slice(&env, b"revocationIndex=");
            m.append(&decimal(&env, revocation_index));
            m
        };
        if !disclosed_is(&disclosed_indexes, &disclosed_messages, 1, &expected_issuer)
            || !disclosed_is(&disclosed_indexes, &disclosed_messages, 2, &expected_rev_index)
        {
            return Err(Error::InvalidProof);
        }

        // Claim bits are granted only from disclosed `=true` attributes at their schema index.
        let mut derived = 0u32;
        if disclosed_is(
            &disclosed_indexes,
            &disclosed_messages,
            6,
            &Bytes::from_slice(&env, b"over18=true"),
        ) {
            derived |= CLAIM_OVER_18;
        }
        if disclosed_is(
            &disclosed_indexes,
            &disclosed_messages,
            7,
            &Bytes::from_slice(&env, b"over21=true"),
        ) {
            derived |= CLAIM_OVER_21;
        }
        if disclosed_is(
            &disclosed_indexes,
            &disclosed_messages,
            8,
            &Bytes::from_slice(&env, b"notSanctioned=true"),
        ) {
            derived |= CLAIM_NOT_SANCTIONED;
        }
        if disclosed_is(
            &disclosed_indexes,
            &disclosed_messages,
            10,
            &Bytes::from_slice(&env, b"jurisdictionOk=true"),
        ) {
            derived |= CLAIM_JURISDICTION_OK;
        }
        if claims & !derived != 0 {
            return Err(Error::InvalidProof);
        }

        let presentation_header = presentation_header(&env, &subject, &nonce, ledger_expiry);

        let pk = soroban_sdk::crypto::bls12_381::Bls12381G2Affine::from_bytes(pubkey_g2.clone());
        if !bbs::verify_bbs_proof(
            &env,
            &pk,
            &header,
            &presentation_header,
            &disclosed_indexes,
            &disclosed_messages,
            &proof,
        ) {
            return Err(Error::InvalidProof);
        }

        let claims_key = DataKey::Claims(subject.clone());
        let prev: Option<ClaimRecord> = env.storage().persistent().get(&claims_key);

        let current_epoch = match &prev {
            Some(p) => p.revocation_epoch,
            None => 0,
        };
        if revocation_epoch != current_epoch {
            return Err(Error::RevocationEpochMismatch);
        }

        // A live record (or a tombstone) is only ever replaced by a fresher one.
        if let Some(prev) = prev {
            let prev_revoked = prev.claims == 0;
            let prev_live = seq <= prev.expires_at || prev_revoked;
            if prev_live && expires_at <= prev.expires_at {
                return Err(if prev_revoked {
                    Error::SubjectRevoked
                } else {
                    Error::StaleAttestation
                });
            }
        }

        env.storage().temporary().set(&nonce_key, &());
        let nonce_ttl = expires_at
            .saturating_sub(seq)
            .max(NONCE_MIN_TTL)
            .min(NONCE_MAX_TTL);
        env.storage()
            .temporary()
            .extend_ttl(&nonce_key, nonce_ttl, nonce_ttl);

        let record = ClaimRecord {
            claims,
            expires_at,
            issuer_id,
            issued_at: seq,
            revocation_epoch: current_epoch,
            revocation_index,
        };
        env.storage().persistent().set(&claims_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&claims_key, CLAIM_TTL_THRESHOLD, CLAIM_TTL_EXTEND_TO);
        bump_instance(&env);

        Attested {
            subject,
            claims,
            expires_at,
            issuer_id: record.issuer_id,
        }
        .publish(&env);

        Ok(claims)
    }

    /// Admin revocation: writes a tombstone and advances the subject's epoch, so every proof
    /// derived before this call is dead. There is no un-revoke; a subject is re-onboarded.
    pub fn revoke(env: Env, subject: Address) -> Result<(), Error> {
        require_admin(&env)?;
        let prev = read_claim(&env, &subject);
        write_tombstone(&env, &subject, prev);
        Ok(())
    }

    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let old_admin = require_admin(&env)?;
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        bump_instance(&env);
        AdminChanged {
            old_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        require_admin(&env)?;
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        bump_instance(&env);
        Ok(())
    }

    /// The read every relying contract makes: is `claim_bit` granted for `subject` right now?
    /// A missing record, an expired record and a tombstone all answer `false`.
    pub fn check(env: Env, subject: Address, claim_bit: u32) -> bool {
        if claim_bit == 0 {
            return false;
        }
        let rec: ClaimRecord = match env.storage().persistent().get(&DataKey::Claims(subject)) {
            Some(r) => r,
            None => return false,
        };
        if env.ledger().sequence() > rec.expires_at {
            return false;
        }
        rec.claims & claim_bit == claim_bit
    }

    pub fn claim_record(env: Env, subject: Address) -> Result<ClaimRecord, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Claims(subject))
            .ok_or(Error::NoClaimRecord)
    }
}

mod test;
