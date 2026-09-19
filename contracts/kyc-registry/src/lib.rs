#![no_std]
//! Registry of trusted credential issuers.
//!
//! but the registry is still a separate contract so issuer keys can be rotated and revoked
//! without touching the verifier in `kyc-gate`.
//!
//! verification, so it lives in `instance` storage — which has the useful side effect that
//! `Instance::extend_ttl` also extends the contract *code* entry.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, Vec};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    /// issuer_id -> Issuer
    Issuer(BytesN<32>),
    /// Enumerable list of registered issuer ids.
    IssuerIds,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Issuer {
    /// BBS+ public key, BLS12-381 G2. Stored UNCOMPRESSED (192 bytes, big-endian) because the
    /// Soroban host rejects the compression flag and offers no decompression function — the
    pub pubkey_g2: BytesN<192>,
    /// Ledger sequence after which this issuer's credentials are no longer accepted.
    /// 0 means "no expiry".
    pub valid_until: u32,
    pub revoked: bool,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    // Codes 300-399 are reserved by OpenZeppelin's stack — stay clear of them.
    AlreadyInitialized = 1,
    NotInitialized = 2,
    IssuerNotFound = 3,
    IssuerAlreadyRegistered = 4,
}

#[contract]
pub struct KycRegistry;

#[contractimpl]
impl KycRegistry {
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::IssuerIds, &Vec::<BytesN<32>>::new(&env));
        Ok(())
    }

    pub fn register_issuer(
        env: Env,
        issuer_id: BytesN<32>,
        pubkey_g2: BytesN<192>,
        valid_until: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env)?;

        let key = DataKey::Issuer(issuer_id.clone());
        if env.storage().instance().has(&key) {
            return Err(Error::IssuerAlreadyRegistered);
        }

        env.storage().instance().set(
            &key,
            &Issuer {
                pubkey_g2,
                valid_until,
                revoked: false,
            },
        );

        let mut ids: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&DataKey::IssuerIds)
            .unwrap_or_else(|| Vec::new(&env));
        ids.push_back(issuer_id);
        env.storage().instance().set(&DataKey::IssuerIds, &ids);
        Ok(())
    }

    pub fn revoke_issuer(env: Env, issuer_id: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env)?;
        let key = DataKey::Issuer(issuer_id);
        let mut issuer: Issuer = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::IssuerNotFound)?;
        issuer.revoked = true;
        env.storage().instance().set(&key, &issuer);
        Ok(())
    }

    /// Returns the issuer's key only if it is currently usable. `kyc-gate` calls this
    /// before spending ~60M instructions on a pairing check, so the cheap rejections
    /// (unknown issuer, revoked, expired) all happen here first.
    pub fn active_key(env: Env, issuer_id: BytesN<32>) -> Result<BytesN<192>, Error> {
        let issuer: Issuer = env
            .storage()
            .instance()
            .get(&DataKey::Issuer(issuer_id))
            .ok_or(Error::IssuerNotFound)?;

        if issuer.revoked {
            return Err(Error::IssuerNotFound);
        }
        if issuer.valid_until != 0 && env.ledger().sequence() > issuer.valid_until {
            return Err(Error::IssuerNotFound);
        }
        Ok(issuer.pubkey_g2)
    }

    pub fn is_trusted(env: Env, issuer_id: BytesN<32>) -> bool {
        Self::active_key(env, issuer_id).is_ok()
    }

    pub fn issuer_ids(env: Env) -> Vec<BytesN<32>> {
        env.storage()
            .instance()
            .get(&DataKey::IssuerIds)
            .unwrap_or_else(|| Vec::new(&env))
    }

    fn require_admin(env: &Env) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();
        Ok(())
    }
}

mod test;
