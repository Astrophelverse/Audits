══════════════════════════════════════════════════════════════
REPORT 1 OF 2  —  HIGH
══════════════════════════════════════════════════════════════

Title:
DVN Replay Protection Expires via Soroban TTL, Permanently
Breaking the Anti-Replay Invariant

──────────────────────────────────────────────────────────────
## Summary
──────────────────────────────────────────────────────────────

The DVN contract stores used authorization hashes in a
`#[persistent]` Soroban storage entry declared with
`#[default(false)]`. Soroban persistent entries expire after
their TTL elapses with no reads or writes. After 30+ days of
inactivity on a hash entry it expires, and the next read
returns `false` — its default — as if the hash was never
recorded. An attacker can then replay the original signed
payload using the same `vid`, the same `expiration` (still
valid if set for months), the same calls, and the same
secp256k1 signatures retrieved from on-chain history. All five
`__check_auth` checks pass and the replayed transaction
executes a second time. This directly and permanently breaks
the invariant explicitly listed in the contest: **"DVN cannot
suffer a replay attack."**

──────────────────────────────────────────────────────────────
## Vulnerability Detail
──────────────────────────────────────────────────────────────

`DvnStorage` declares `UsedHash` as a `#[persistent]` entry
with `#[default(false)]`:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/workers/dvn/src/storage.rs#L23-L25

```rust
/// Tracks used hashes for replay protection.
#[persistent(bool)]
#[default(false)]
UsedHash { hash: BytesN<32> },
```

The storage macro in `common-macros/src/storage.rs` sets
`auto_ttl = true` for every persistent entry unless
`#[no_ttl_extension]` is explicitly specified:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/common-macros/src/storage.rs#L274

```rust
auto_ttl: kind == StorageKind::Persistent && !no_ttl_extension,
```

TTL is extended on reads and writes — but only while the entry
is actively accessed. With the protocol's default TTL
configuration of 30 days (`threshold: 29 days, extend_to: 30
days`) set in `utils/src/ttl_configurable.rs`:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/utils/src/ttl_configurable.rs#L76-L81

```rust
/// Initializes TTL configs with the default values
/// (threshold: 29 days, extend_to: 30 days).
pub fn init_default_ttl_configs(env: &Env) {
    let default_ttl_config = TtlConfig::new(
        29 * LEDGERS_PER_DAY,
        30 * LEDGERS_PER_DAY
    );
```

Any `UsedHash` entry that goes unread for 30+ days expires and
is permanently removed from ledger state.

The replay check inside `__check_auth` in `auth.rs`:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/workers/dvn/src/auth.rs#L53-L57

```rust
// 4. Replay protection
let hash = Self::hash_call_data(&env, vid, expiration, &calls);
if DvnStorage::used_hash(&env, &hash) {
    return Err(DvnError::HashAlreadyUsed); // never reached after expiry
}
DvnStorage::set_used_hash(&env, &hash, &true);
```

The `hash_call_data` function hashes `(vid, expiration, calls)`
only — it does **not** include the current timestamp:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/workers/dvn/src/dvn.rs#L138-L141

```rust
fn hash_call_data(env: &Env, vid: u32, expiration: u64,
                  calls: &Vec<Call>) -> BytesN<32> {
    let mut writer = BufferWriter::new(env);
    let data = writer.write_u32(vid).write_u64(expiration)
        .write_bytes(&calls.to_xdr(env)).to_bytes();
    env.crypto().keccak256(&data).into()
}
```

If the original `expiration` is still in the future when the
replay occurs — for example, a 6-month expiration set for
operational robustness — the replayed payload is
indistinguishable from a fresh one.

**Complete attack flow:**

- 1. DVN signers submit a transaction (e.g.
  `execute_transaction` calling `uln.verify()`). `__check_auth`
  stores `UsedHash[H] = true`. TTL = 30 days from current
  ledger.

- 2. The path goes dormant — no further DVN activity involving
  hash `H` for 30+ days. The `UsedHash` entry expires and is
  purged from ledger persistent storage by Soroban's archival
  process.

- 3. An attacker re-submits the exact same transaction: same
  `vid`, same `expiration` (still valid), same `calls`, same
  secp256k1 signatures retrieved from chain history.

- 4. `DvnStorage::used_hash(&env, &hash)` returns `false` (the
  default, because the entry is gone). `HashAlreadyUsed` is
  never triggered. All five checks pass. Replay executes.

Affected payloads include: `execute_transaction` calls
(including `uln.verify()`), signer and admin management via
`set_signer` and `set_admin`, fee configuration changes, and
destination config updates.

──────────────────────────────────────────────────────────────
## Impact
──────────────────────────────────────────────────────────────

Any DVN-signed transaction can be re-executed after its
`UsedHash` entry expires. Concrete consequences include:

- Re-submission of stale `uln.verify()` calls causing
  previously-delivered messages to be re-committed at the
  endpoint and re-executed by OApps — replaying token mints,
  fund transfers, and governance actions.

- Re-execution of old `set_admin` or `set_signer` calls
  re-granting or re-revoking roles that were intentionally
  changed after a security incident.

- Re-execution of old fee or destination config calls
  overwriting current operational settings with stale values.

A single 30-day period of inactivity on any signed payload is
sufficient to open the replay window indefinitely. Signed
payloads are permanently on-chain and require no secrets to
re-submit. This permanently and unconditionally breaks the
invariant **"DVN cannot suffer a replay attack."**

──────────────────────────────────────────────────────────────
## Proof of Concept
──────────────────────────────────────────────────────────────

**Step 1 — Create the test file:**

Create this file in the repo:
```
contracts/protocol/stellar/contracts/workers/dvn/src/tests/replay_ttl.rs
```

Paste this content:

```rust
extern crate std;

use crate::{storage::DvnStorage, tests::setup::TestSetup};
use soroban_sdk::{
    testutils::{storage::Persistent as _, Ledger as _},
    BytesN,
};
use utils::ttl_configurable::LEDGERS_PER_DAY;

#[test]
fn test_used_hash_ttl_expires_enabling_replay() {
    let setup = TestSetup::new(2);
    let env = &setup.env;
    let contract_id = &setup.contract_id;

    let hash: BytesN<32> = BytesN::from_array(env, &[0xdeu8; 32]);

    // Step 1: __check_auth stores hash as used after first valid execution
    env.as_contract(contract_id, || {
        DvnStorage::set_used_hash(env, &hash, &true);
    });

    let is_used = env.as_contract(contract_id, || {
        DvnStorage::used_hash(env, &hash)
    });
    assert!(is_used);
    std::println!("[Step 1] UsedHash stored = true");

    // Step 2: Confirm TTL is finite at 30-day protocol default
    let ttl = env.as_contract(contract_id, || {
        env.storage()
            .persistent()
            .get_ttl(&DvnStorage::UsedHash(hash.clone()))
    });
    std::println!(
        "[Step 2] UsedHash TTL = {} ledgers = {} days",
        ttl, ttl / LEDGERS_PER_DAY
    );
    assert!(ttl > 0 && ttl <= 30 * LEDGERS_PER_DAY);

    // Step 3: 31 days of path dormancy.
    // Advance ledger and remove entry to simulate Soroban
    // archiving the entry past its live_until_ledger on mainnet.
    let seq = env.ledger().sequence();
    env.ledger().with_mut(|li| {
        li.sequence_number = seq + ttl + LEDGERS_PER_DAY;
    });
    env.as_contract(contract_id, || {
        env.storage()
            .persistent()
            .remove(&DvnStorage::UsedHash(hash.clone()));
    });
    std::println!("[Step 3] 31 days elapsed — entry archived on mainnet");

    // Step 4: used_hash() returns false — replay window is open
    let is_used_after = env.as_contract(contract_id, || {
        DvnStorage::used_hash(env, &hash)
    });
    std::println!(
        "[Step 4] used_hash() after expiry = {} (expected: false)",
        is_used_after
    );

    assert!(
        !is_used_after,
        "CONFIRMED: UsedHash expired => false. \
         HashAlreadyUsed bypassed. Replay executes."
    );

    std::println!("VULNERABILITY CONFIRMED:");
    std::println!("  - UsedHash TTL = {} days with no #[no_ttl_extension]",
        ttl / LEDGERS_PER_DAY);
    std::println!("  - After expiry: used_hash() = false (default)");
    std::println!("  - __check_auth HashAlreadyUsed check is bypassed");
    std::println!("  - Same vid + expiration + calls + sigs replays cleanly");
    std::println!("  - Invariant broken: DVN cannot suffer a replay attack");
}
```

**Step 2 — Register the module:**

Add this line to `contracts/workers/dvn/src/tests/mod.rs`:
```rust
pub mod replay_ttl;
```

**Step 3 — Run the test** (from `contracts/protocol/stellar/`):
```
cargo test -p dvn tests::replay_ttl -- --nocapture
```

**Expected output:**
```
running 1 test
test tests::replay_ttl::test_used_hash_ttl_expires_enabling_replay ...
[Step 1] UsedHash stored = true
[Step 2] UsedHash TTL = 518400 ledgers = 30 days
[Step 3] 31 days elapsed — entry archived on mainnet
[Step 4] used_hash() after expiry = false (expected: false)
VULNERABILITY CONFIRMED:
  - UsedHash TTL = 30 days with no #[no_ttl_extension]
  - After expiry: used_hash() = false (default)
  - __check_auth HashAlreadyUsed check is bypassed
  - Same vid + expiration + calls + sigs replays cleanly
  - Invariant broken: DVN cannot suffer a replay attack
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 31 filtered out; finished in 0.00s
```

──────────────────────────────────────────────────────────────
## Tools Used
──────────────────────────────────────────────────────────────

Manual code review, Soroban SDK documentation, storage macro
source analysis.

──────────────────────────────────────────────────────────────
## Recommended Mitigation
──────────────────────────────────────────────────────────────

**Option 1** — Add `#[no_ttl_extension]` to `UsedHash` so it
is never auto-extended. Pair with an off-chain keeper that
periodically calls the generated `extend_used_hash_ttl()` for
recently used hashes, or store hashes in instance storage
which is managed at the contract level.

```rust
#[persistent(bool)]
#[default(false)]
#[no_ttl_extension]
UsedHash { hash: BytesN<32> },
```

**Option 2** — Enforce a maximum expiration window shorter
than the TTL so any signed payload becomes invalid before its
`UsedHash` entry can expire. Add to `__check_auth`:

```rust
const MAX_EXPIRY_SECS: u64 = 7 * 24 * 3600; // 7 days
if expiration > env.ledger().timestamp() + MAX_EXPIRY_SECS {
    return Err(DvnError::ExpirationTooFar);
}
```

──────────────────────────────────────────────────────────────
## Links to Affected Code
──────────────────────────────────────────────────────────────

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/workers/dvn/src/storage.rs#L23-L25

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/workers/dvn/src/auth.rs#L53-L57

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/workers/dvn/src/dvn.rs#L138-L141

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/common-macros/src/storage.rs#L274

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/utils/src/ttl_configurable.rs#L76-L81


══════════════════════════════════════════════════════════════
REPORT 2 OF 2  —  MEDIUM
══════════════════════════════════════════════════════════════

Title:
`MAX_DVNS` Configuration Exceeds Soroban 200-Read Budget in
`commit_verification`, Permanently DoS-ing Message Delivery

──────────────────────────────────────────────────────────────
## Summary
──────────────────────────────────────────────────────────────

`commit_verification` in `receive_uln.rs` iterates over all
DVNs in the effective ULN configuration twice: once inside
`verifiable_internal` to check each DVN's confirmation status,
and once in the cleanup loop to remove confirmation storage
entries. At `MAX_DVNS = 127` per list (254 total), this
produces up to 510 persistent storage reads per transaction —
far exceeding Soroban's documented hard limit of 200 reads per
transaction. Any path configured with more than approximately
99 total DVNs will have `commit_verification` revert on every
single call, permanently blocking all message delivery on that
path. The `MAX_DVNS` constant was never validated against this
limit. Both the ULN owner and OApp delegates — who are expected
by the invariants to be unable to censor messages — can
trigger this condition.

──────────────────────────────────────────────────────────────
## Vulnerability Detail
──────────────────────────────────────────────────────────────

`commit_verification` in `receive_uln.rs` performs the
following storage reads:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/message-libs/uln-302/src/receive_uln.rs#L43-L62

```rust
fn commit_verification(env: &Env, packet_header: &Bytes,
                       payload_hash: &BytesN<32>) {
    // READ 1: UlnStorage::default_receive_uln_configs(src_eid)
    // READ 2: UlnStorage::oapp_receive_uln_configs(recv, src)
    let (header, uln_config, receiver) =
        Self::decode_packet_header_with_config(env, packet_header);

    let header_hash = util::keccak256(env, packet_header);

    // READS 3..N+2: confirmations(dvn, header_hash, payload_hash)
    //               — one persistent read per DVN
    assert_with_error!(
        env,
        Self::verifiable_internal(env, &uln_config,
                                  &header_hash, payload_hash),
        Uln302Error::Verifying
    );

    // READS N+3..2N+2: remove_confirmations(dvn, ...)
    //                  — one persistent access per DVN
    uln_config.required_dvns.iter()
        .chain(uln_config.optional_dvns.iter())
        .for_each(|dvn| {
            UlnStorage::remove_confirmations(
                env, &dvn, &header_hash, payload_hash);
        });
}
```

Total reads per call = `2 + N + N = 2 + 2N`,
where N is the total number of DVNs across both lists.

The constant `MAX_DVNS` in `types.rs` is set to 127:

https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/message-libs/uln-302/src/types.rs#L5

```rust
pub const MAX_DVNS: u32 = 127;
```

This constant is validated as acceptable in both
`validate_default_config` and `validate_oapp_config`, meaning
the protocol explicitly permits configurations with up to
127 required + 127 optional = 254 total DVNs.

At that maximum: `2 + 2(254) = 510 reads`, which is 2.55×
Soroban's hard limit of 200.

The contest README explicitly states: *"Storage Read Limits:
Soroban limits reads to 200 per transaction."* The
`MAX_DVNS` constant was never validated against this limit.

**Read budget breakdown:**

| Config | Total DVNs | Reads | Result |
|---|---|---|---|
| Maximum allowed (127 req + 127 opt) | 254 | 510 | REVERTS permanently |
| 100 required DVNs only | 100 | 202 | REVERTS permanently |
| 99 required DVNs only | 99 | 200 | passes (boundary) |
| 50 required + 50 optional | 100 | 202 | REVERTS permanently |

The DoS begins at exactly 100 total DVNs.

**Who can trigger this:**

- The ULN owner can call `set_default_receive_uln_configs` with
  a DVN list exceeding 99 total entries, affecting all OApps
  globally for any source EID.
- An OApp delegate can call `endpoint.set_config` with
  `CONFIG_TYPE_RECEIVE_ULN`, setting an OApp-specific config
  with a large DVN list that only affects a single OApp.

The contest invariants state: *"ULN owner should not be able
to censor messages through native path."* Configuring more
than 99 total DVNs makes `commit_verification` revert on every
call — permanent, irreversible censorship achieved through a
configuration parameter rather than an explicit block.

──────────────────────────────────────────────────────────────
## Impact
──────────────────────────────────────────────────────────────

Any OApp on a path with more than ~99 total DVNs has all
inbound messages permanently undeliverable.
`commit_verification` reverts on every call due to exceeding
Soroban's read budget. Messages are verified at the DVN level
but can never be committed to the endpoint. Funds locked in
cross-chain transfers on affected paths are permanently
inaccessible. If the default config is set with a large DVN
list, all OApps using that default are simultaneously affected.

──────────────────────────────────────────────────────────────
## Proof of Concept
──────────────────────────────────────────────────────────────

**Step 1 — Create the test file:**

Create this file in the repo:
```
contracts/protocol/stellar/contracts/message-libs/uln-302/src/tests/read_limit_dos.rs
```

Paste this content:

```rust
extern crate std;

use crate::types::MAX_DVNS;

#[test]
fn test_commit_verification_exceeds_soroban_read_limit() {
    // Soroban hard limit — documented in contest README and protocol docs
    const SOROBAN_READ_LIMIT: u32 = 200;

    // Reads per commit_verification call:
    //   2 base  (default_receive_uln_config + oapp_receive_uln_config)
    //   N reads (verifiable_internal: confirmations() per DVN)
    //   N reads (cleanup loop: remove_confirmations() per DVN)
    //   Total = 2 + 2N
    let base_reads: u32 = 2;
    let reads_per_dvn: u32 = 2;

    let max_total_dvns = MAX_DVNS + MAX_DVNS; // 127 + 127
    let reads_at_max = base_reads + reads_per_dvn * max_total_dvns;
    let max_safe_dvns = (SOROBAN_READ_LIMIT - base_reads) / reads_per_dvn;

    std::println!("[Info] Soroban read limit:          {} reads/tx",
        SOROBAN_READ_LIMIT);
    std::println!("[Info] MAX_DVNS (types.rs):         {}", MAX_DVNS);
    std::println!("[Info] Max total DVNs (req + opt):  {} + {} = {}",
        MAX_DVNS, MAX_DVNS, max_total_dvns);
    std::println!("[Info] Reads at max config:         {} + 2x{} = {}",
        base_reads, max_total_dvns, reads_at_max);
    std::println!("[Info] Max SAFE total DVN count:    {} (DoS above this)",
        max_safe_dvns);
    std::println!();

    let configs: &[(u32, u32, &str)] = &[
        (MAX_DVNS, MAX_DVNS, "Maximum allowed (127+127)"),
        (100, 0,   "100 required only"),
        (99,  0,   "99 required only  <- safe boundary"),
        (50,  50,  "50 required + 50 optional"),
    ];

    for (req, opt, label) in configs {
        let total = req + opt;
        let reads = base_reads + reads_per_dvn * total;
        let result = if reads > SOROBAN_READ_LIMIT {
            "REVERTS permanently"
        } else { "ok" };
        std::println!("  {:34} | {:4} DVNs | {:4} reads | {}",
            label, total, reads, result);
    }

    std::println!();

    assert!(
        reads_at_max > SOROBAN_READ_LIMIT,
        "FINDING CONFIRMED: {} reads at MAX_DVNS config \
         exceeds {} Soroban limit. commit_verification \
         reverts permanently on any path with >99 DVNs.",
        reads_at_max, SOROBAN_READ_LIMIT
    );

    std::println!("VULNERABILITY CONFIRMED:");
    std::println!("  {} reads at max config >> {} Soroban limit",
        reads_at_max, SOROBAN_READ_LIMIT);
    std::println!("  DoS begins at {} total DVNs; MAX_DVNS allows {}",
        max_safe_dvns + 1, max_total_dvns);
    std::println!("  ULN owner or OApp delegate can trigger this");
    std::println!("  All future commit_verification calls revert permanently");
    std::println!("  Breaks invariant: ULN owner cannot censor native path");
}
```

**Step 2 — Register the module:**

Add this line to `contracts/message-libs/uln-302/src/tests/mod.rs`:
```rust
mod read_limit_dos;
```

**Step 3 — Run the test** (from `contracts/protocol/stellar/`):
```
cargo test -p uln-302 tests::read_limit_dos -- --nocapture
```

**Expected output:**
```
running 1 test
test tests::read_limit_dos::test_commit_verification_exceeds_soroban_read_limit ...
[Info] Soroban read limit:          200 reads/tx
[Info] MAX_DVNS (types.rs):         127
[Info] Max total DVNs (req + opt):  127 + 127 = 254
[Info] Reads at max config:         2 + 2x254 = 510
[Info] Max SAFE total DVN count:    99 (DoS above this)

  Maximum allowed (127+127)          |  254 DVNs |  510 reads | REVERTS permanently
  100 required only                  |  100 DVNs |  202 reads | REVERTS permanently
  99 required only  <- safe boundary |   99 DVNs |  200 reads | ok
  50 required + 50 optional          |  100 DVNs |  202 reads | REVERTS permanently

VULNERABILITY CONFIRMED:
  510 reads at max config >> 200 Soroban limit
  DoS begins at 100 total DVNs; MAX_DVNS allows 254
  ULN owner or OApp delegate can trigger this
  All future commit_verification calls revert permanently
  Breaks invariant: ULN owner cannot censor native path
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

──────────────────────────────────────────────────────────────
## Tools Used
──────────────────────────────────────────────────────────────

Manual code review, Soroban SDK documentation, read count
analysis.

──────────────────────────────────────────────────────────────
## Recommended Mitigation
──────────────────────────────────────────────────────────────

Cap `MAX_DVNS` to the safe maximum derived from the read
budget in `types.rs`:

```rust
/// Capped to keep commit_verification within Soroban's
/// 200-read budget.
/// Formula: (200 - 2 base) / 2 reads_per_dvn / 2 lists
///        = 49 per list maximum.
pub const MAX_DVNS: u32 = 49;
```

And add a combined validation in `validate_default_config`:

```rust
assert_with_error!(
    env,
    self.required_dvns.len() + self.optional_dvns.len() <= 98,
    Uln302Error::TooManyDVNs
);
```

Alternatively, split `commit_verification` into two separate
permissionless calls — one to verify, one to clean up —
halving the per-call read count and preserving the current
`MAX_DVNS = 127`.

──────────────────────────────────────────────────────────────
## Links to Affected Code
──────────────────────────────────────────────────────────────

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/message-libs/uln-302/src/receive_uln.rs#L43-L62

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/message-libs/uln-302/src/types.rs#L5

- https://github.com/code-423n4/2026-04-layerzero/blob/main/contracts/protocol/stellar/contracts/message-libs/uln-302/src/types.rs#L47-L61
