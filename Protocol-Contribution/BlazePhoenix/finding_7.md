# Router's uniform hop input rescaling silently undoes the Solver's input side capacity clamp

## Severity: High
**Contracts:** `BlazePhoenixRouter.sol`, `BlazePhoenixSolver.sol`

---

## Summary

`Solver._singleLeg` (and any `_buildHop` call that filters to one survivor) protects against phantom quotes a raw quote that exceeds a thin V3/Algebra pool's entire real `tokenOut` balance by cutting the **leg's** committed input down to a size the pool can actually pay:

```solidity
// BlazePhoenixSolver.sol - _singleLeg, phantom tier
uint256 legIn = amountIn;
if (allowCut && out_ > balOut) {
    legIn = BPC.mulDiv(amountIn, cap, out_);   // CUT
    out_  = cap;                                // capped promise
}
...
legs[0] = Leg({ ..., amountIn: legIn, expectedOut: out_, ... });
hop = Hop({ ..., amountIn: amountIn, expectedOut: out_, legs: legs });
//                        ^^^^^^^^^ stays the ORIGINAL, uncut amount
```

`hop.amountIn` is never reduced along with the leg.

The Router treats `hop.amountIn`/the real balance it holds as ground truth and rescales every leg's input to match it for hop 0, against `sum(hop.legs[].amountIn)`:

```solidity
// BlazePhoenixRouter.sol - _hopScaleImpactAndQuote
uint256 realIn = h == 0 ? amountIn : BPC.balanceOf(hop.tokenIn, address(this));
uint256 quotedIn;
for (uint256 l; l < legs; ) { quotedIn += hop.legs[l].amountIn; unchecked { ++l; } }   // = legIn for a single-leg hop
scaleNum = realIn;      // the REAL amount the Router holds (the full order)
scaleDen = quotedIn == 0 ? 1 : quotedIn;   // the CUT amount the Solver committed

// BlazePhoenixRouter.sol - _execute
uint256 scaledAmt = BPC.mulDiv(leg.amountIn, scaleNum, scaleDen);
// = mulDiv(legIn, amountIn, legIn) = amountIn  <-- the cut is exactly undone
```

**Exploit path:** any swap whose route collapses to a single V3/Algebra candidate against a pool thin enough that the raw quote exceeds the pool's whole balance (the documented field case: an order into a pool with real holdings well below what the quote implies).

1. Solver plans the route, cuts `leg.amountIn` to a small, fillable size, caps `leg.expectedOut` at the pool's holdings `hop.amountIn` stays at the full order.

2. Caller submits this Solver-produced route as-is to `swapExactIn`.

3. The Router's rescale reconstructs the full, uncut order and dispatches `IUniswapV3PoolMin.swap(..., amountSpecified: <full order>, ...)`.

4. Outcome depends on whether the per-leg floor guard is active:

   - **Guarded** (`leg.expectedOut != 0`, the normal case): `_execScaled`'s `minLeg` check is rebuilt from the rescaled `amt` against the *original* phantom promise (`≈ 75% × out_original`), a number the pool can never pay `RouterE(5)`.

     On a real pool (tick-crossing self-caps the payout) this is exactly where it reverts.

     On the simplified mock used in testing (flat, uncapped payout) it reverts one layer deeper, inside the pool's own transfer, before the Router's check is even reached same root cause, sharper symptom.

   - **Unguarded** (`leg.expectedOut == 0`, e.g. a relayed/crafted route): no per-leg check at all the full amount walks the pool's tick ladder at a collapsing marginal price, bounded only by `userMinOut`.

Either way, the Solver's own "best route" designed to be a safe, protection-respecting partial fill never executes as planned.

---

## Impact

| Scenario | Solver's intent | What the Router actually does | Result |
|---|---|---|---|
| Single-venue phantom tier, per-leg guard active (default) | Small honest fill (`legIn` in, `cap` out), residual swept back | Rescales to the full uncut order; `minLeg` floor rebuilt from the original phantom quote | **Guaranteed revert** the Solver's marked "best route" is unexecutable |
| Same, guard bypassed (`expectedOut == 0`, e.g. relayed route) | Same small honest fill | Full uncut order sent into the pool, no per-leg check | Thin pool force-fed the full order; walks tick ladder at collapsing price, real measured loss pattern **20–27% one-way** (per Solver's own inline docs) bounded only by `userMinOut` |
| Same route, Solver's own numbers executed directly (control, proven in test suite) | — | `legIn` spent, pool pays `≈cap` | Fills cleanly, well within the pool's real balance confirms the cut itself is sound |

**Confirmed end-to-end** (real `BlazePhoenixSolver` output fed to real `BlazePhoenixRouter`, Foundry trace):

- Solver plan for a 50,000-token order against a pool holding 1,000 tokenB:

  `hop.amountIn = 5e22` (uncut),

  `legs[0].amountIn = 3.001e20` (cut),

  `legs[0].expectedOut = 3e20` (≈30% of the pool's real 1,000e18 balance - `MAX_CONC_DRAIN_BPS`).

- Router dispatches `pool.swap(..., 5e22, ...)`  **166× the Solver's own committed input** and the pool's payout attempt of `≈4.997e22` reverts against its real `1,000e18` balance.

- Executing the Solver's own cut amount directly (bypassing the Router) fills cleanly near the capped promise, isolating the defect to the Router's rescale step.

Consequence: **every phantom-tier route the Solver produces is either unexecutable or, if the per-leg guard is bypassed, a severe-loss fill** the exact failure mode `MAX_CONC_DRAIN_BPS` was built to prevent, reintroduced by the Router's own rescale logic.

The bridge stage-B path already avoids this (`allowCut = false`, with an inline comment describing this identical failure mode), but hop 0 / stage A does not, despite the code comment's claim that "the input-side cut protects hop 0 / single-hop, where amounts execute as built" which this report shows to be false.

---

## Mitigation

The Solver's `hop.amountIn` (and, for the split path, the sum of its legs' `amountIn`) must reflect what was actually committed after any capacity cut, so the Router's rescale has a truthful denominator to rescale against instead of silently reconstructing the pre-cut order.

```solidity
// BlazePhoenixSolver.sol - _singleLeg
Leg[] memory legs = new Leg[](1);
legs[0] = Leg({
    pool: cand.pool, hooks: cand.hooks, kind: cand.kind,
    fee: cand.fee, tickSpacing: cand.tickSpacing,
    zeroForOne: cand.token0 == tIn, stable: cand.stable,
    amountIn: legIn, expectedOut: out_,
    auxId: ...
});
hop = Hop({
    tokenIn: tIn, tokenOut: tOut,
-   amountIn: amountIn, expectedOut: out_, legs: legs
+   amountIn: legIn,     expectedOut: out_, legs: legs
});
```

With `hop.amountIn == legIn`, the Router's `scaleNum` (`realIn`, the full amount actually received) will legitimately exceed `scaleDen` (`sum(leg.amountIn) == legIn`) this is the intended, safe direction of mismatch: it means the Router correctly identifies that it holds more than this hop plans to spend, and the existing residual-sweep logic in `_execute` (already present, lines 425–429) returns the uncommitted remainder to the caller instead of force-feeding it into the pool.

This also requires an equivalent check on the multi-leg path (`_buildHop`'s split loop): where a phantom cut fires and its freed capital cannot be fully reabsorbed by later legs (the "whatever no surviving venue can absorb stays unrouted" case the code comment already acknowledges), `hop.amountIn` must be set to `sum(legs[i].amountIn)` actually assembled, not the caller's original `amountIn`, for the same reason.


## POC

Add this test file in `Blaze-Phoenix-Dex-V2/test`

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.28;


import {Test} from "forge-std/Test.sol";
import {BlazePhoenixHub} from "../src/BlazePhoenixHub.sol";
import {BlazePhoenixSolver} from "../src/BlazePhoenixSolver.sol";
import {BlazePhoenixRouter} from "../src/BlazePhoenixRouter.sol";
import {
    BlazePhoenixCore as BPC,
    Route, Hop, Leg, RoutePlan
} from "../src/BlazePhoenixCore.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockV3Pool} from "./mocks/MockV3Pool.sol";

/// @notice Minimal direct V3 taker used only by the control test, to execute
///         MockV3Pool.swap() exactly as the Router's _execV3Amt would pull
///         the committed input via the callback, nothing more WITHOUT
///         going through the Router's rescale, so the control isolates the
///         Solver's cut amount as fillable on its own terms.
contract DirectV3Taker {
    function takeSwap(MockV3Pool pool, address tokenIn, bool zeroForOne, uint256 amountIn)
        external returns (uint256 received)
    {
        (int256 a0, int256 a1) = pool.swap(address(this), zeroForOne, int256(amountIn), 0, abi.encode(tokenIn));
        received = uint256(zeroForOne ? -a1 : -a0);
    }

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        address tokenIn = abi.decode(data, (address));
        uint256 owed = amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
        MockERC20(tokenIn).transfer(msg.sender, owed);
    }
}

contract RouterUndoesSolverCapacityClampTest is Test {
    BlazePhoenixHub hub;
    BlazePhoenixSolver solver;
    BlazePhoenixRouter router;
    MockERC20 tokenA; // tokenIn
    MockERC20 tokenB; // tokenOut

    address treasury1 = address(0xFEE1);
    address treasury2 = address(0xFEE2);
    address user      = address(0xBEEF);

    uint128 constant DEEP_L = 1e26; // deep concentrated liquidity: quote ~1:1 at this price

    // Field-shaped setup: the pool's REAL tokenB holdings are far thinner than
    // what a large order would naively quote at DEEP_L, e.g. the documented
    // Base USDC->USDS case (89% of a $10k order into a $6.2k-holding pool).
    uint256 constant ORDER          = 50_000e18;
    uint256 constant POOL_HOLDING_B = 1_000e18; // pool's whole real tokenB balance

    function setUp() public {
        hub = new BlazePhoenixHub();
        hub.initialize(address(this), address(0));

        tokenA = new MockERC20("A", "A");
        tokenB = new MockERC20("B", "B");

        solver = new BlazePhoenixSolver(address(hub));
        router = new BlazePhoenixRouter(
            address(hub), address(solver), address(this), treasury1, treasury2
        );

        tokenA.mint(user, ORDER);
        vm.prank(user);
        tokenA.approve(address(router), type(uint256).max);
    }

    function _seedSingleThinV3() internal returns (MockV3Pool p) {
        p = new MockV3Pool(address(tokenA), address(tokenB), 100);
        p.setState(uint160(BPC.Q96), DEEP_L);
        tokenB.mint(address(p), POOL_HOLDING_B);
        hub.seedPool(address(p), BPC.KIND_V3, 100, address(0), address(tokenA), address(tokenB));
    }


    /// @notice Verifies the Solver actually enters the phantom-tier clamp.
    ///         The returned route must keep hop.amountIn unchanged while
    ///         reducing leg.amountIn and capping expectedOut. This establishes
    ///         the exact precondition required for the bug.
    function test_Precondition_SolverAppliesPhantomTierInputCut() public {
        _seedSingleThinV3();

        RoutePlan memory plan = solver.findBestRoutePlan(address(tokenA), address(tokenB), ORDER);
        assertEq(plan.best.hops.length, 1, "expected a single hop");
        Hop memory hop = plan.best.hops[0];
        assertEq(hop.legs.length, 1, "expected a single leg (only one registered venue)");

        Leg memory leg = hop.legs[0];

        assertLt(leg.amountIn, ORDER,
            "precondition failed: the phantom-tier clamp did not cut leg.amountIn");
        assertApproxEqRel(
            leg.expectedOut, BPC.mulDiv(POOL_HOLDING_B, 3_000, BPC.BPS), 0.01e18,
            "leg.expectedOut should be capped at ~30% of the pool's real holdings"
        );

        // THE BUG SEED: hop.amountIn was never reduced along with the leg
        // this is the field the Router's rescale trusts.
        assertEq(hop.amountIn, ORDER,
            "hop.amountIn must still report the ORIGINAL uncut order");
    }

    /// @notice Executes the Solver-generated route through the real Router.
    ///         The Router rescales the cut leg back to the original order,
    ///         making the planned partial-fill route fail instead of executing.
    function test_Router_RevertsOnSolverPlan_InsteadOfExecutingCutRoute() public {
        _seedSingleThinV3();

        RoutePlan memory plan = solver.findBestRoutePlan(address(tokenA), address(tokenB), ORDER);
        Route memory route = plan.best;

        // Precondition restated inline so this test fails loudly (not
        // silently passes for the wrong reason) if the Solver's behavior
        // ever changes.
        require(route.hops[0].legs[0].amountIn < ORDER, "precondition: clamp must have fired");

        vm.prank(user);
        vm.expectRevert(); // any revert — the cut route is unexecutable, full stop
        router.swapExactIn(route, ORDER, 0, user, block.timestamp + 1);
    }

    /// @notice Proves algebraically that once the Router reconstructs the
    ///         original input, the rebuilt per-leg minimum output exceeds the
    ///         pool's real capacity. This explains why the Solver's cut route
    ///         cannot complete successfully.
    function test_RevertReason_MinLegFloorExceedsPoolCapacity() public {
        MockV3Pool pool = _seedSingleThinV3();

        RoutePlan memory plan = solver.findBestRoutePlan(address(tokenA), address(tokenB), ORDER);
        Leg memory leg = plan.best.hops[0].legs[0];

        uint256 legIn = leg.amountIn;      // the Solver's CUT input
        uint256 cap   = leg.expectedOut;   // the Solver's CAPPED promise (~30% of holdings)
        require(legIn < ORDER, "precondition: clamp must have fired");

        // What the Router will rescale `amt` back up to for a single-leg hop 0.
        uint256 scaledAmt = BPC.mulDiv(legIn, ORDER, legIn);
        assertEq(scaledAmt, ORDER, "rescale must reconstruct the full original amount");

        // What the Router's per-leg floor WOULD require, if the pool's
        // swap() ever returned control to it (LEG_FLOOR_BPS = 75%).
        uint256 minLeg = BPC.mulDiv(BPC.mulDiv(cap, scaledAmt, legIn), 7_500, BPC.BPS);

        uint256 poolRealBalance = tokenB.balanceOf(address(pool));
        assertGt(minLeg, poolRealBalance,
            "the reconstructed floor must exceed the pool's ENTIRE real holdings: "
            "no fill bounded by real liquidity can ever satisfy it once the cut is undone");

        // And independently: the amount the rescale forces the pool to
        // ATTEMPT to pay out (outV3 at the full, uncut amount) is itself
        // already far beyond the pool's real balance -- confirming the
        // observable failure in the previous test happens even earlier than
        // the minLeg check, for the reason explained in the block comment
        // above (this mock's uncapped, non-tick-crossing payout).
        bool zfo = address(tokenA) < address(tokenB);
        uint256 poolWouldAttemptToPay =
            BPC.outV3(scaledAmt, uint160(BPC.Q96), DEEP_L, 100, zfo);
        assertGt(poolWouldAttemptToPay, poolRealBalance,
            "the pool is asked to pay out more than it holds the moment the rescale "
            "hands it the uncut amount");
    }

    /// @notice Removes the per-leg quote guard and shows that the Router still
    ///         executes the original order instead of the Solver's cut amount.
    ///         The bug is therefore the rescale itself, not the guard.
    function test_Router_UnguardedRoute_ForceFeedsFullAmountIntoThinPool() public {
        _seedSingleThinV3();

        RoutePlan memory plan = solver.findBestRoutePlan(address(tokenA), address(tokenB), ORDER);
        Route memory route = plan.best;
        uint256 cutLegIn = route.hops[0].legs[0].amountIn;
        require(cutLegIn < ORDER, "precondition: clamp must have fired");

        // Strip the attested quote to bypass the per-leg guard, and relax the
        // aggregate floor so nothing short-circuits BEFORE the pool call.
        route.hops[0].legs[0].expectedOut = 0;
        route.hops[0].expectedOut = 0;
        route.singleOutFloor = 0;

        bool zfo = address(tokenA) < address(tokenB);
        uint256 phantomFullQuote = BPC.outV3(ORDER, uint160(BPC.Q96), DEEP_L, 100, zfo);
        assertGt(phantomFullQuote, POOL_HOLDING_B,
            "setup sanity: full-order quote must exceed the pool's real holdings, "
            "or this test proves nothing about the bug");

        // Reverts — but not with the protocol's own graceful RouterE(5). It
        // reverts one level deeper, on MockV3Pool's own payout transfer,
        // because the Router asked it to fill the FULL (uncut) order.
        vm.prank(user);
        vm.expectRevert(); // bubbles up from MockV3Pool -> MockERC20 insufficient-balance
        router.swapExactIn(route, ORDER, 0, user, block.timestamp + 1);
    }

    /// @notice Control test.
    ///         Executes the Solver's cut amount directly, bypassing the Router.
    ///         The swap succeeds, showing the Solver's cut is valid and the
    ///         failure comes from the Router's rescale.
    function test_Control_SolverCutAmountFillsCleanlyWhenExecutedAsPlanned() public {
        MockV3Pool pool = _seedSingleThinV3();

        RoutePlan memory plan = solver.findBestRoutePlan(address(tokenA), address(tokenB), ORDER);
        Leg memory leg = plan.best.hops[0].legs[0];
        require(leg.amountIn < ORDER, "precondition: clamp must have fired");

        bool zfo = address(tokenA) < address(tokenB);
        uint256 quoted = BPC.outV3(leg.amountIn, uint160(BPC.Q96), DEEP_L, 100, zfo);
        assertLe(quoted, POOL_HOLDING_B,
            "the Solver's own cut input, executed as planned, must be fillable "
            "from the pool's real holdings -- proving the cut itself is sound");

        // Actually execute pool.swap() spending exactly legIn (the Solver's
        // cut) the way the Router *should* have, bypassing its rescale
        // via a minimal direct taker, and confirm it fills cleanly against
        // the pool's real, thin balance with no revert.
        DirectV3Taker taker = new DirectV3Taker();
        tokenA.mint(address(taker), leg.amountIn);

        uint256 poolBalBefore = tokenB.balanceOf(address(pool));
        uint256 received = taker.takeSwap(pool, address(tokenA), zfo, leg.amountIn);
        uint256 poolBalAfter = tokenB.balanceOf(address(pool));

        assertApproxEqRel(received, leg.expectedOut, 0.01e18,
            "direct fill of the Solver's cut amount should land near its capped promise");
        assertLe(poolBalBefore - poolBalAfter, POOL_HOLDING_B,
            "the fill must never draw more tokenB than the pool actually held");
    }
}
```