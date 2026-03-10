<div align="center">

```
██╗     ██╗███╗   ███╗██████╗  ██████╗ ██╗    ██╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
██║     ██║████╗ ████║██╔══██╗██╔═══██╗██║    ██║██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
██║     ██║██╔████╔██║██████╔╝██║   ██║██║ █╗ ██║███████║██║     █████╔╝ █████╗  ██████╔╝
██║     ██║██║╚██╔╝██║██╔══██╗██║   ██║██║███╗██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
███████╗██║██║ ╚═╝ ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗██║  ██╗███████╗██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

**Independent Smart Contract Security Researcher**

*Finding bugs others miss — in unaudited code, post-audit regressions, and complex cross-chain logic.*

---

![Findings](https://img.shields.io/badge/Total%20Findings-7%2B-00E5FF?style=for-the-badge)
![High](https://img.shields.io/badge/High%20Severity-6-F97316?style=for-the-badge)
![Critical](https://img.shields.io/badge/Critical-1-EF4444?style=for-the-badge)
![Platforms](https://img.shields.io/badge/Platforms-Immunefi%20%7C%20C4%20%7C%20Cantina-7B2FBE?style=for-the-badge)

</div>

---

## Findings

| # | Protocol | Severity | Platform | Language | Status |
|:-:|---|:-:|---|:-:|---|
| 01 | [Rujira Ghost Credit](#01--rujira-ghost-credit) | 🟠 High | Code4rena | Rust / CosmWasm | ✅ Valid · Fixed |
| 02 | [Daimo Pay](#02--daimo-pay) | 🟠 High | Immunefi | Solidity | ✅ Valid · Duplicated |
| 03 | [Jupiter Lend H-01](#03--jupiter-lend) | 🟠 High | Code4rena | Solidity | ⏳ Pending |
| 04 | [Jupiter Lend H-02](#03--jupiter-lend) | 🟠 High | Code4rena | Solidity | ⏳ Pending |
| 05 | [Jupiter Lend H-03](#03--jupiter-lend) | 🟠 High | Code4rena | Solidity | ⏳ Pending |
| 06 | [Morpho Blue](#06--morpho-blue) | 🔴 Critical | Cantina | Solidity | ✅ Valid • Duplicated |
| 07 | [CircuitDAO](#07--circuitdao) | 🟡 Medium | Cantina | Chialisp | ✅ Acknowledged |

> **On duplicates:** Duplicate = two researchers independently confirmed the same real bug.
> It reflects competition, not quality. Every finding here is original independent research.

---

## 01 · Rujira Ghost Credit

**Liquidation DoS via Poison Repayment Preference**

Users can configure liquidation preferences — ordered messages executed when their position is liquidated. The `execute_liquidate` handler for `LiquidateMsg::Repay` performs a strict balance check and **hard-reverts** if the token balance is zero, instead of skipping gracefully. A malicious user sets a `Repay` preference for a token they hold zero of — permanently blocking all liquidation attempts.

```rust
// contract.rs L272-L276 — hard revert instead of graceful skip
if balance.amount.is_zero() {
    return Err(ContractError::ZeroDebtTokens { denom: balance.denom });
}
```

| | |
|---|---|
| **Impact** | Protocol insolvency · Liquidation DoS · Bad debt accumulation |
| **Submission** | S-752 · duplicate of F-1 · 141 total duplicates |
| **Fix** | MR #97 — return `Ok(Response::default())` on zero balance |

📁 [`rujira/`](./rujira/) → [`RujiraPoC.rs`](./rujira/RujiraPoC.rs) · [`report.pdf`](./rujira/report.pdf)

---

## 02 · Daimo Pay

**`refundFulfillment()` Ignores FastFinish Claim Rights — Permanent Relayer Fund Loss**

`DepositAddressManager` tracks fastFinish relayers via `fulfillmentToRecipient`. `claim()` honours this correctly. But `refundFulfillment()` has **zero check** on the mapping — it unconditionally sweeps bridged tokens to `params.refundAddress`, permanently stealing the relayer's repayment after expiry. `DepositAddressManager.sol` was **not included** in the Nethermind audit (NM-0500, April 2025).

```solidity
// refundFulfillment() — no check on fulfillmentToRecipient
TokenUtils.transfer({
    token: tokens[i],
    recipient: payable(params.refundAddress), // relayer ignored
    amount: amounts[i]
});
```

| | |
|---|---|
| **Impact** | 100% permanent loss of relayer's fronted capital · no recovery path |
| **PoC** | `forge test` passes · 99 USDC net loss proven on-chain |
| **Per Daimo's own criteria** | *"A well-implemented relayer does everything right but still loses funds. These are High."* |

📁 [`daimo-pay/`](./daimo-pay/) → [`DaimoPayPoC.t.sol`](./daimo-pay/DaimoPayPoC.t.sol) · [`report.pdf`](./daimo-pay/report.pdf)

---

## 03 · Jupiter Lend

**3x High Severity Findings**

Three independent High severity findings submitted to the Jupiter Lend Code4rena contest. Full details to be published after judging completes.

📁 [`jupiter-lend/`](./jupiter-lend/) → details pending

---

## 06 · Morpho Blue

**Bad Debt Socialization Bypass via Dust Collateral**

`liquidate()` triggers bad debt socialization only when `collateral == 0` (exact zero). Leaving **1 wei** of collateral bypasses this entirely. The zombie position continues counting bad debt as valid supply, inflating the exchange rate. Early withdrawers drain the pool; last lenders cannot exit.

```solidity
// Morpho.sol L391 — exact zero check only
if (position[id][borrower].collateral == 0) {  // bypassed by 1 wei
    badDebtShares = position[id][borrower].borrowShares;
}
```

| | |
|---|---|
| **Impact** | Inflated exchange rate · bank run vector · lender principal loss |
| **PoC** | `[PASS] test_BadDebt_DustCollateral_Bypass()` |
| **Note** | Independent rediscovery of OZ 2023 finding against current codebase |

📁 [`morpho-blue/`](./morpho-blue/) → [`MorphoBluePoC.t.sol`](./morpho-blue/MorphoBluePoC.t.sol) · [`report.pdf`](./morpho-blue/report.pdf)

---

## 07 · CircuitDAO

**`recharge_auction.clsp` Passes Unsanitized `input_conditions` to Operation Programs**

In Chialisp's puzzle layer model, `inner_conditions` (protocol-validated) and `input_conditions` (raw user input) must never be conflated. `recharge_auction.clsp` passes raw `input_conditions` directly to operation programs, breaking the fundamental security boundary and enabling arbitrary condition injection into the auction flow.

📁 [`circuitdao/`](./circuitdao/) → [`CircuitDAOPoC.clsp`](./circuitdao/CircuitDAOPoC.clsp) · [`report.pdf`](./circuitdao/report.pdf)

---

## Stack

```
Languages    Solidity · Rust/CosmWasm · Chialisp · (Move, Go — expanding)
Tooling      Foundry · cargo-test · Chia Dev Tools
Focus        Cross-chain bridges · Lending protocols · Unaudited codebases
Specialty    Post-audit regressions · State machine violations · Economic logic bugs
```

---

## Platforms

| Platform | Handle | KYC |
|---|---|:-:|
| Code4rena | astrophel12 | ✅ Verified |
| Immunefi | Limbowalker | ✅ Verified |
| Cantina | Limbowalker | ✅ Verified |

---

<div align="center">

*This repo is a living document — updated after every hunt.*
*The code doesn't lie.*

</div>
