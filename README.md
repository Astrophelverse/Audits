# Astrophelverse — Smart Contract Security Portfolio

> Independent smart contract security researcher specializing in cross-chain DeFi protocols, Solidity, and Chialisp.
> Finding bugs others miss in unaudited and post-audit codebases.

---

## Stats

| Total Findings | High Severity | Protocols Audited | Platforms |
|:-:|:-:|:-:|:-:|
| 6+ | 5 | 3 | Immunefi · Code4rena · Cantina |

---

## Findings

### 1. Daimo Pay — `refundFulfillment` Ignores FastFinish Claim Rights
| Field | Detail |
|---|---|
| **Protocol** | [Daimo Pay](https://github.com/daimo-eth/pay) |
| **Platform** | Immunefi |
| **Severity** | High |
| **Status** | Duplicated (Valid bug, raced) |
| **Language** | Solidity |
| **Contract** | `DepositAddressManager.sol` |
| **Payout** | — |

**Summary:**
`refundFulfillment()` sweeps bridged tokens to `params.refundAddress` without checking `fulfillmentToRecipient`. When a relayer calls `fastFinish()` and fronts their own capital to deliver funds early to a user, a subsequent `refundFulfillment()` call after expiry permanently redirects the bridged tokens away from the relayer. The relayer loses 100% of their fronted capital with no recovery path.

**Root Cause:**
```solidity
// fastFinish() correctly records relayer:
fulfillmentToRecipient[fulfillmentAddress] = msg.sender;

// claim() correctly honours it:
address recipient = fulfillmentToRecipient[fulfillmentAddress];

// refundFulfillment() NEVER checks fulfillmentToRecipient:
TokenUtils.transfer({
    token: tokens[i],
    recipient: payable(params.refundAddress), // ignores relayer
    amount: amounts[i]
});
```

**Fix:**
```solidity
require(
    fulfillmentToRecipient[fulfillmentAddress] == address(0),
    "DAM: fulfillment was fast-finished, call claim() to repay relayer"
);
```

**Note:** Duplicate status confirms validity. Two independent researchers found the same bug. `DepositAddressManager.sol` was NOT included in the Nethermind audit (NM-0500, April 2025).

📄 [Full PoC](./daimo-pay/AuditPoC_RefundFulfillmentStealsRelayerFunds.t.sol)

---

### 2. Jupiter Lend — H-01 (Code4rena)
| Field | Detail |
|---|---|
| **Protocol** | Jupiter Lend |
| **Platform** | Code4rena |
| **Severity** | High |
| **Status** | Submitted — Pending Judging |
| **Language** | Solidity |

*Details to be added after contest judging completes.*

📄 [Finding](./jupiter-lend/H-01.md)

---

### 3. Jupiter Lend — H-02 (Code4rena)
| Field | Detail |
|---|---|
| **Protocol** | Jupiter Lend |
| **Platform** | Code4rena |
| **Severity** | High |
| **Status** | Submitted — Pending Judging |
| **Language** | Solidity |

*Details to be added after contest judging completes.*

📄 [Finding](./jupiter-lend/H-02.md)

---

### 4. Jupiter Lend — H-03 (Code4rena)
| Field | Detail |
|---|---|
| **Protocol** | Jupiter Lend |
| **Platform** | Code4rena |
| **Severity** | High |
| **Status** | Submitted — Pending Judging |
| **Language** | Solidity |

*Details to be added after contest judging completes.*

📄 [Finding](./jupiter-lend/H-03.md)

---

### 5. CircuitDAO — `recharge_auction.clsp` Input Conditions Injection
| Field | Detail |
|---|---|
| **Protocol** | [CircuitDAO](https://www.circuitdao.com) |
| **Platform** | Cantina |
| **Severity** | Medium (disputed — researcher assesses High) |
| **Status** | Acknowledged — Pending Resolution |
| **Language** | Chialisp |
| **Contract** | `recharge_auction.clsp` |

**Summary:**
`recharge_auction.clsp` passes raw `input_conditions` directly to operation programs instead of sanitized `inner_conditions`. This allows an attacker to inject arbitrary conditions into the recharge auction flow, potentially manipulating coin lifecycle and protocol state in unintended ways.

**Root Cause:**
The distinction between `input_conditions` (user-supplied, unsanitized) and `inner_conditions` (protocol-validated) is not enforced when delegating to operation programs, breaking the security boundary that Chialisp's puzzle layer model depends on.

📄 [Finding](./circuitdao/recharge-auction-input-conditions.md)

---

## Platforms

| Platform | Profile | Status |
|---|---|---|
| Immunefi | KYC Verified ✅ | Active |
| Code4rena | Active | Active |
| Cantina | Active | Active |

---

## Skills

**Languages:** Solidity · Chialisp · Rust (learning)

**Expertise:**
- Cross-chain bridge logic & fulfillment lifecycle bugs
- State machine violations & missing invariant checks
- Post-audit regression hunting (finding bugs auditors missed)
- Foundry PoC development

**Focus Areas:** DeFi protocols · Cross-chain systems · Unaudited codebases

---

## Philosophy

> Most researchers hunt the same audited contracts. I go where the auditors didn't.
> Every duplicate is a confirmed real bug. Every rejection is a lesson.
> The code doesn't lie.

---

## Contact

- GitHub: [@astrophelverse](https://github.com/astrophelverse)
- Discord: [Astrophel](https://discord.gg/nCxcQzv6)

---

*This repo is updated after each hunt. All findings are my own independent research.*
*Duplicate findings are included — they confirm validity, not failure.*

