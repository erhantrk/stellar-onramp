#![no_std]

//! SEP-57 `IdentityVerifier` adapter (`TrexWrap`) that fronts the existing
//! `contracts/kyc-gate.check()` seam, making StellarOnramp drop-in compatible
//! with any SEP-57 T-REX token via a single
//! `set_identity_verifier(trex_wrap_addr, operator)` call by the issuer.
//!
//! The hot path (`verify_identity`) forwards the stored required-claims mask to
//! `kyc-gate.check(subject, mask)` and panics on a `false` verdict — panic ==
//! reject is the SEP-57 contract, not a style choice. The mask is passed through
//! verbatim; there is deliberately no second path that could turn an empty mask
//! into a pass. `kyc-gate.check` already fails closed on `claim_bit == 0`
//! (contracts/kyc-gate/src/lib.rs:1028), so an unset mask stays fail-closed.
//!

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Env,
};
use stellar_access::ownable;
use stellar_macros::only_owner;
use stellar_tokens::rwa::identity_verification::IdentityVerifier;

/// Error codes are a wire format: deployed clients decode by number. Pin every
/// one of them, and keep them OUT of 300-399, which OpenZeppelin occupies
/// (RWAError 300-313, ClaimTopicsAndIssuersError, ComplianceModuleError).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WrapError {
    /// SEP-57 `verify_identity` panic == reject. NOT 304 — OZ owns 300-399.
    IdentityVerificationFailed = 2101,
    /// A getter read storage that was never set (e.g. `claim_topics_and_issuers`
    /// before `set_claim_topics_and_issuers`).
    NotInitialized = 2102,
}

/// The cross-contract ABI of the existing `kyc-gate` contract. `check` has
/// subset semantics: a record proves a claim mask, and it passes exactly when
/// `claims & claim_bit == claim_bit`. It also fails closed on `claim_bit == 0`.
#[contractclient(name = "KycGateClient")]
pub trait KycGate {
    fn check(env: Env, subject: Address, claim_bit: u32) -> bool;
}

/// Instance/persistent storage keys. `Recovery(old)` is a persistent map from a
/// lost account to its recovery target.
///
/// Storage-key collision to be aware of: `ClaimTopicsAndIssuers` below is a
/// unit variant that serialises to `ScVal::Symbol("ClaimTopicsAndIssuers")` —
/// the SAME instance slot as OpenZeppelin's
/// `IdentityVerifierStorageKey::ClaimTopicsAndIssuers`
/// (stellar-tokens 0.7.2, `identity_verification/storage.rs:18`). Benign in the
/// shipped code because this adapter overrides BOTH the setter and the getter
/// and never calls OZ's `storage::` helpers, so every read/write goes through
/// `DataKey` consistently. Latent: a future call to OZ's
/// `storage::set_claim_topics_and_issuers` would clobber this same slot.
#[contracttype]
pub enum DataKey {
    Required,
    KycGate,
    ClaimTopicsAndIssuers,
    Recovery(Address),
}

#[contract]
pub struct TrexWrap;

// The admin surface. Plain #[contractimpl]: these are ordinary contract
// functions, not a trait impl, so `contracttrait` is irrelevant here.
#[contractimpl]
impl TrexWrap {
    pub fn __constructor(e: Env, owner: Address, kyc_gate: Address, required_bitmap: u32) {
        // set_owner is auth-free and panics OwnableError::OwnerAlreadySet if the
        // owner is already set — it is only ever called here, once.
        ownable::set_owner(&e, &owner);
        e.storage().instance().set(&DataKey::KycGate, &kyc_gate);
        e.storage().instance().set(&DataKey::Required, &required_bitmap);
    }

    #[only_owner]
    pub fn set_required(e: Env, required_bitmap: u32) {
        e.storage().instance().set(&DataKey::Required, &required_bitmap);
    }

    #[only_owner]
    pub fn set_kyc_gate(e: Env, kyc_gate: Address) {
        e.storage().instance().set(&DataKey::KycGate, &kyc_gate);
    }

    #[only_owner]
    pub fn set_recovery(e: Env, old_account: Address, new_account: Address) {
        e.storage()
            .persistent()
            .set(&DataKey::Recovery(old_account), &new_account);
    }

    pub fn required(e: Env) -> u32 {
        e.storage()
            .instance()
            .get(&DataKey::Required)
            .unwrap_or_else(|| panic_with_error!(&e, WrapError::NotInitialized))
    }

    pub fn kyc_gate(e: Env) -> Address {
        e.storage()
            .instance()
            .get(&DataKey::KycGate)
            .unwrap_or_else(|| panic_with_error!(&e, WrapError::NotInitialized))
    }
}

// The SEP-57 seam. `#[contractimpl(contracttrait)]` is MANDATORY: plain
// `#[contractimpl]` silently drops OZ's defaulted `claim_topics_and_issuers`
// with no error or warning, and the contract builds and deploys missing an
// export. In THIS codebase the first thing that catches the real two-part
// footgun (flag dropped AND the override removed) is a test compile error —
// three tests call `ctx.client.claim_topics_and_issuers()`, which no longer
// exists on the generated client — before the wasm export-list assertion can
// even run. The export-list assertion (test.rs) is the backstop for drift no
// call site would catch: an extra/renamed export, or a dropped export whose
// call sites were also removed. Separately, the source-level test
// so even the *pure* downgrade (flag dropped, override KEPT — behaviourally
// neutral) goes red.
#[contractimpl(contracttrait)]
impl IdentityVerifier for TrexWrap {
    /// Panics with `WrapError::IdentityVerificationFailed` on failure — that is
    /// the SEP-57 contract, not a style choice.
    fn verify_identity(e: &Env, account: &Address) {
        let gate = Self::kyc_gate(e.clone());
        let need = Self::required(e.clone());
        if !KycGateClient::new(e, &gate).check(account, &need) {
            panic_with_error!(e, WrapError::IdentityVerificationFailed);
        }
    }

    /// `None` when there is no recovery mapping for `old_account` — the SEP-57
    /// contract a token consults during `recover_balance`.
    fn recovery_target(e: &Env, old_account: &Address) -> Option<Address> {
        e.storage().persistent().get(&DataKey::Recovery(old_account.clone()))
    }

    /// The SEP leaves RBAC to the implementation ("RBAC checks are expected to
    /// be enforced on the `operator`"); this adapter's single privileged role
    /// is its owner, so the owner's auth is the gate. The `operator` argument
    /// exists only to match the trait.
    fn set_claim_topics_and_issuers(e: &Env, claim_topics_and_issuers: Address, _operator: Address) {
        ownable::enforce_owner_auth(e);
        e.storage()
            .instance()
            .set(&DataKey::ClaimTopicsAndIssuers, &claim_topics_and_issuers);
    }

    /// MUST be overridden. OZ's default getter (`storage::get_claim_topics_and_issuers`,
    /// stellar-tokens 0.7.2) reads `IdentityVerifierStorageKey::ClaimTopicsAndIssuers`
    /// and panics `RWAError::ClaimTopicsAndIssuersNotSet` (310) when unset. That key
    /// serialises to the SAME instance slot as `DataKey::ClaimTopicsAndIssuers` (see
    /// the `DataKey` comment), so after a set the OZ default would actually return the
    /// stored address — the only observable difference of the default is the WRONG
    /// panic code (310 vs our 2102) before the first set. The override pins our
    /// `WrapError::NotInitialized` (2102); that is what
    /// `claim_topics_and_issuers_is_not_initialized_until_set` asserts, and the test
    /// that goes red if this override is ever dropped with the flag kept (mutation d3).
    fn claim_topics_and_issuers(e: &Env) -> Address {
        e.storage()
            .instance()
            .get(&DataKey::ClaimTopicsAndIssuers)
            .unwrap_or_else(|| panic_with_error!(e, WrapError::NotInitialized))
    }
}

#[cfg(test)]
mod test;
