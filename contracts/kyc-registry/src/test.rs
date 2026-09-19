#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Env};

fn setup(env: &Env) -> (KycRegistryClient<'_>, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let id = env.register(KycRegistry, ());
    let client = KycRegistryClient::new(env, &id);
    client.init(&admin);
    (client, admin)
}

fn issuer_id(env: &Env, b: u8) -> BytesN<32> {
    BytesN::from_array(env, &[b; 32])
}

fn pubkey(env: &Env, b: u8) -> BytesN<192> {
    BytesN::from_array(env, &[b; 192])
}

#[test]
fn registers_and_resolves_an_issuer() {
    let env = Env::default();
    let (client, _admin) = setup(&env);

    let id = issuer_id(&env, 1);
    let key = pubkey(&env, 7);
    client.register_issuer(&id, &key, &0);

    assert_eq!(client.active_key(&id), key);
    assert!(client.is_trusted(&id));
    assert_eq!(client.issuer_ids().len(), 1);
}

#[test]
fn double_init_is_rejected() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    assert_eq!(client.try_init(&admin), Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn duplicate_registration_is_rejected() {
    let env = Env::default();
    let (client, _) = setup(&env);
    let id = issuer_id(&env, 1);
    client.register_issuer(&id, &pubkey(&env, 7), &0);
    assert_eq!(
        client.try_register_issuer(&id, &pubkey(&env, 8), &0),
        Err(Ok(Error::IssuerAlreadyRegistered))
    );
}

#[test]
fn revoked_issuer_stops_being_trusted() {
    let env = Env::default();
    let (client, _) = setup(&env);
    let id = issuer_id(&env, 1);
    client.register_issuer(&id, &pubkey(&env, 7), &0);
    assert!(client.is_trusted(&id));

    client.revoke_issuer(&id);
    assert!(!client.is_trusted(&id));
    assert_eq!(client.try_active_key(&id), Err(Ok(Error::IssuerNotFound)));
}

#[test]
fn expired_issuer_stops_being_trusted() {
    let env = Env::default();
    let (client, _) = setup(&env);
    let id = issuer_id(&env, 1);
    // Valid only through ledger 100.
    client.register_issuer(&id, &pubkey(&env, 7), &100);

    env.ledger().set_sequence_number(100);
    assert!(client.is_trusted(&id), "still valid AT the boundary");

    env.ledger().set_sequence_number(101);
    assert!(!client.is_trusted(&id), "expired one ledger past the boundary");
}

#[test]
fn unknown_issuer_is_not_trusted() {
    let env = Env::default();
    let (client, _) = setup(&env);
    assert!(!client.is_trusted(&issuer_id(&env, 99)));
}
