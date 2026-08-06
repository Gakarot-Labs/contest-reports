# V4 Pool-Key mismatch duplicates solver candidates and falsifies registry freshness

## Severity: Low

---

## Summary

`addV4()` and `recordSwap()` derive the registry key for the same V4 pool two different ways, so every V4 pool ends up registered twice under two different keys the first time it is swapped through.

`addV4` (operator-only, one-time registration) keys the pool off the raw `bytes32` poolId:

```solidity
// BlazePhoenixHub.sol
bytes32 pid = BPC.computeV4PoolId(s0, s1, fee, tickSpacing, hooks);
key = _poolKeyV4(pid, s0, s1);
_register(key, address(uint160(uint256(pid))), BPC.KIND_V4, fee, hooks, s0, s1, true);

// BlazePhoenixHub.sol
function _poolKeyV4(bytes32 pid, address t0, address t1) private pure returns (bytes32) {
    return keccak256(abi.encodePacked(pid, t0, t1));   // pid: bytes32 (32 bytes)
}
```

`recordSwap` (called by the Router after every successful swap) always keys off the generic `keyOf`, using the pool as an `address`:

```solidity
// BlazePhoenixHub.sol
function keyOf(address pool, address tA, address tB) public pure returns (bytes32) {
    (address s0, address s1) = BPC.sortTokens(tA, tB);
    return keccak256(abi.encodePacked(pool, s0, s1));   // pool: address (20 bytes)
}

// BlazePhoenixHub.sol
function recordSwap(address pool, ...) external onlyRouter whenLive {
    ...
    bytes32 key = keyOf(pool, t0, t1);
    uint256 s = $.slot[key];
    if (s != 0) { /* tick existing */ return; }
    // else: falls through to _register creates a NEW row
```

Because `abi.encodePacked` is encoding-width-sensitive, `keccak256(abi.encodePacked(pid, t0, t1))` (32-byte word) and `keccak256(abi.encodePacked(address(uint160(uint256(pid))), t0, t1))` (20-byte word) never collide, even though both describe the identical pool. `recordSwap` therefore always finds slot `0` on the first swap and registers a second row.

This is compounded by the Router itself: for a V4 leg, `leg.pool` is not a real contract the Router's own comment says so yet it is fed into `BPC.getLiquidity(leg.pool)` as the depth argument passed to `recordSwap`:

```solidity
// BlazePhoenixRouter.sol
// V4 has no pool address leg.pool holds the truncated poolId, not a
// token. The counterpart currency travels in auxId (low 160 bits).
address tokenOther = address(uint160(uint256(leg.auxId)));

// BlazePhoenixRouter.sol::_recordHits
uint256 depth = (leg.kind == BPC.KIND_V2 || leg.kind == BPC.KIND_SOLIDLY)
    ? _v2Depth(leg.pool)
    : curveLike
        ? leg.expectedOut
        : uint256(BPC.getLiquidity(leg.pool));   // staticcall to a non-pool address
try hub.recordSwap(leg.pool, leg.kind, leg.fee, leg.hooks, t0, t1, leg.amountIn, leg.expectedOut, depth) {} catch {}
```

`getLiquidity` static calls `pool.liquidity()`; since `leg.pool` is a hash fragment truncated to 20 bytes, it is essentially never a deployed contract, so the call returns no data and `depth` is `0`. V4 depth feedback is therefore meaningless on top of being duplicated.

### Exploit path (no attacker required triggered by normal use)

1. Operator lists a V4 pool: `hub.addV4(WETH, USDC, 500, 10, address(0))` → registers under `key1`.
2. Any user swaps `WETH→USDC` through that pool via the Router.
3. Router calls `hub.recordSwap(pseudoPool, KIND_V4, ...)` → computes `key2 = keyOf(pseudoPool, t0, t1) ≠ key1` → slot is empty → `_register()` runs again, creating a second row for the same pool.
4. `getActivePools(WETH, USDC)` now returns **both** rows (no pool-address dedup `BlazePhoenixHub.sol` returns every active key in `pairKeys` unconditionally).
5. `BlazePhoenixSolver`'s discovered-vs-registered dedup (`BlazePhoenixSolver.sol:742-747`) only compares `dis[i].pool == reg[j].pool`; it never compares `reg` against itself, so both rows pass through into candidate scoring and can both be selected into route legs.
6. `key1`'s slot is never written to again it silently goes stale forever, while all future swap activity accrues only to `key2`.

---

## Impact

| # | Effect | Where | Consequence |
|---|---|---|---|
| 1 | Duplicate registry row created on first swap | `recordSwap` → `_register` | 1 logical V4 pool occupies 2 of `MAX_SLOTS = 16` registry slots per pair |
| 2 | Original `addV4` row never ticks again | `recordSwap` (line 521 always resolves to `key2`) | Its fitness/`lastUpdateTs` is permanently stale; visible via `getSlot` unchanged across N swaps |
| 3 | No dedup on read | `getActivePools` (425-441) | Callers (Solver) see 2 entries describing 1 venue |
| 4 | No dedup on registered-vs-registered | `Solver` merge loop (742-747) | Same V4 liquidity can be counted twice in split/weighting and appear as 2 legs in one route |
| 5 | Freshness gate distorted | `_registryFresh` (`BlazePhoenixSolver.sol:782-795`) recomputes each row's key via `keyOf(reg[i].pool, ...)` | Both duplicate rows resolve to the *same* underlying slot (`key2`) for freshness purposes, so `rn` (row count) is inflated toward `MIN_FRESH_VENUES = 3` by 1 without a 2nd real venue existing verified: two independent `keyOf` calls on the two rows return the identical key |
| 6 | V4 depth feedback is void | `Router._recordHits`, line 785 | `getLiquidity(leg.pool)` staticcalls a non-contract address; depth ≈ 0 for essentially all V4 recordings |

Confirmed empirically (`HubV4KeyMismatchTest`, unmodified source, forge traces):
- `addV4` key `0x5bbc...` vs. `recordSwap` key `0x5aad...` for identical pool params different, as predicted.
- After 1 swap: `getActivePools` row count goes from 1 → 2; `getSlot(0x5bbc...)` unchanged across 5 subsequent swaps while `0x5aad...` absorbs all activity.
- At `MAX_SLOTS` capacity: 16 registry rows represent only 15 distinct pool addresses.

This is a registry-integrity / routing-quality bug, **not** a fund-safety bug the iron floor still re-derives from realised output regardless of how many rows describe a venue, so no exploit path leads to fund loss.

---

## Mitigation

Make `recordSwap` resolve V4 pools the same way `addV4` registered them, instead of via the generic address-based `keyOf`. The cleanest fix is to key every registry row on the pool's `bytes32` identity consistently, and derive that identity for V4 the same way on both write paths.

**Recommended fix** give `recordSwap` a way to recompute the V4-specific key when `kind == KIND_V4`, using the same inputs `addV4` used to derive `pid`:

```solidity
// BlazePhoenixHub.sol

function recordSwap(
    address pool, uint8 kind, uint24 fee, address hooks,
    address tA, address tB, uint256 amtIn, uint256 amtOut, uint256 depthWad
) external onlyRouter whenLive {
    if (pool == address(0) || amtIn == 0) return;
    (address t0, address t1) = BPC.sortTokens(tA, tB);

    // V4 pools have no real address; addV4 keys them off the poolId, so
    // recordSwap must reconstruct the SAME key rather than keyOf(pool,..),
    // which hashes a different (address-width) encoding of the same pool.
    bytes32 key = (kind == BPC.KIND_V4)
        ? _poolKeyV4(BPC.computeV4PoolId(t0, t1, fee, tickSpacing, hooks), t0, t1)
        : keyOf(pool, t0, t1);

    HubStore storage $ = _store();
    uint256 s = $.slot[key];
    if (s != 0) {
        uint256 newSlot = BPC.tickSlot(s, uint32(block.number), depthWad);
        $.slot[key] = _stampTs(newSlot);
        emit Volume(key, amtIn, amtOut);
        return;
    }
    // ... existing _register fallback for genuinely new pools
}
```

This requires `recordSwap` to also receive `tickSpacing` (currently absent from its signature) so `computeV4PoolId` can be reconstructed exactly as `addV4` computed it add it as a parameter and have the Router pass `leg.tickSpacing` through on V4 legs.

**Companion fix for the depth bug** skip the meaningless `getLiquidity` staticcall for V4 legs rather than feeding it a non-pool address:

```solidity
// BlazePhoenixRouter.sol:781-785
uint256 depth = (leg.kind == BPC.KIND_V2 || leg.kind == BPC.KIND_SOLIDLY)
    ? _v2Depth(leg.pool)
    : curveLike
        ? leg.expectedOut
        : leg.kind == BPC.KIND_V4
            ? leg.expectedOut          // no real pool address to query; use realised output as the depth proxy
            : uint256(BPC.getLiquidity(leg.pool));
```

**Defense in depth** add a pool-address dedup pass to `getActivePools` (or to the Solver's merge step, comparing `reg` against itself, not only against `dis`) so that even if a future registration path introduces another duplicate-key class, callers never see the same underlying pool counted twice.

After the fix, `HubV4KeyMismatchTest`'s five duplicate-detecting assertions should flip from pass (bug present) to fail (bug absent) and can be inverted into permanent regression tests.

## POC

Add this test in `Blaze-Phoenix-Dex/test`

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.28;

// =============================================================================
//  HUB V4 KEY-DERIVATION MISMATCH (addV4 vs recordSwap)
//
//  addV4() keys a V4 pool as keccak256(abi.encodePacked(pid, t0, t1)) where
//  pid is bytes32. recordSwap() always looks pools up via keyOf(pool, t0, t1)
//  = keccak256(abi.encodePacked(pool, t0, t1)) where pool is an address —
//  here, the poolId truncated to its low 160 bits. Packed encoding is
//  width-sensitive, so the two keys never match for the same pool.
//
//  Result: the first swap after addV4() always creates a second registry
//  row instead of ticking the existing one. Not a fund-safety bug the
//  iron floor still re-derives from realised output regardless.
// =============================================================================

import { Test } from "forge-std/Test.sol";
import { BlazePhoenixHub } from "../src/BlazePhoenixHub.sol";
import { PoolInfo } from "../src/BlazePhoenixCore.sol";

contract HubV4KeyMismatchTest is Test {
    BlazePhoenixHub hub;

    address constant T0 = address(0x1111);
    address constant T1 = address(0x2222);
    uint8   constant KIND_V4 = 4;
    uint256 constant MAX_SLOTS = 16;

    function setUp() public {
        hub = new BlazePhoenixHub();
        hub.initialize(address(this), address(0xBEEF));
        hub.setRoles(address(this), address(0x5), address(0x6));
    }

    /// @dev Mirrors Core.computeV4PoolId (internal, not callable from here).
    function _computeV4PoolId(
        address c0, address c1, uint24 fee, int24 tickSpacing, address hooks
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(c0, c1, fee, tickSpacing, hooks));
    }

    /// @dev Mirrors Hub._poolKeyV4 (private).
    function _poolKeyV4(bytes32 pid, address t0, address t1) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pid, t0, t1));
    }

    // ─── 1. addV4 and recordSwap disagree on the key for the same pool ───
    function test_addV4_and_recordSwap_produceDifferentKeys() public {
        uint24 fee = 500;
        int24 tickSpacing = 10;
        address hooks = address(0);

        bytes32 keyFromAddV4 = hub.addV4(T0, T1, fee, tickSpacing, hooks);

        bytes32 pid = _computeV4PoolId(T0, T1, fee, tickSpacing, hooks);
        address pseudoPool = address(uint160(uint256(pid)));
        bytes32 keyFromRecordSwap = hub.keyOf(pseudoPool, T0, T1);

        assertEq(keyFromAddV4, _poolKeyV4(pid, T0, T1), "addV4 key derivation mismatch (test setup)");
        assertTrue(
            keyFromAddV4 != keyFromRecordSwap,
            "BUG NOT REPRODUCED: addV4 key and recordSwap key coincide"
        );
        assertEq(hub.getSlot(keyFromRecordSwap), 0, "recordSwap key should be empty pre-swap");
        assertTrue(hub.getSlot(keyFromAddV4) != 0, "addV4 key should be populated");
    }

    // ─── 2. First swap creates a duplicate row instead of ticking ───
    function test_firstSwap_afterAddV4_createsDuplicateRow_notATick() public {
        uint24 fee = 500;
        int24 tickSpacing = 10;
        address hooks = address(0);

        bytes32 keyFromAddV4 = hub.addV4(T0, T1, fee, tickSpacing, hooks);
        uint256 slotBeforeSwap = hub.getSlot(keyFromAddV4);
        assertEq(hub.getActivePools(T0, T1).length, 1, "should start with exactly one V4 row");

        bytes32 pid = _computeV4PoolId(T0, T1, fee, tickSpacing, hooks);
        address pseudoPool = address(uint160(uint256(pid)));
        hub.recordSwap(pseudoPool, KIND_V4, fee, hooks, T0, T1, 1e18, 1e18, 1e21);

        PoolInfo[] memory ps = hub.getActivePools(T0, T1);
        assertEq(ps.length, 2, "BUG: recordSwap should have ticked the existing V4 row, not added a new one");
        assertEq(hub.getSlot(keyFromAddV4), slotBeforeSwap, "original V4 row must NOT have been touched by the swap");

        bytes32 keyFromRecordSwap = hub.keyOf(pseudoPool, T0, T1);
        assertTrue(hub.getSlot(keyFromRecordSwap) != 0, "duplicate row should exist and be populated");
        assertTrue(keyFromRecordSwap != keyFromAddV4, "duplicate row must be a distinct slot");
    }

    // ─── 3. getActivePools has no pool-address dedup ───
    function test_getActivePools_returnsBothRowsForSamePool_noDedup() public {
        uint24 fee = 3000;
        int24 tickSpacing = 60;
        address hooks = address(0);

        hub.addV4(T0, T1, fee, tickSpacing, hooks);
        bytes32 pid = _computeV4PoolId(T0, T1, fee, tickSpacing, hooks);
        address pseudoPool = address(uint160(uint256(pid)));
        hub.recordSwap(pseudoPool, KIND_V4, fee, hooks, T0, T1, 1e18, 1e18, 1e21);

        PoolInfo[] memory ps = hub.getActivePools(T0, T1);
        assertEq(ps.length, 2, "expected the duplicate row to surface via getActivePools");
        assertEq(ps[0].pool, pseudoPool, "row 0 should resolve to the same pseudo-pool address");
        assertEq(ps[1].pool, pseudoPool, "row 1 should resolve to the same pseudo-pool address");
        assertEq(ps[0].pool, ps[1].pool, "both rows describe the identical V4 pool");
    }

    // ─── 4. Original addV4 row is permanently orphaned ───
    function test_repeatedSwaps_onlyTickDuplicate_originalStaysOrphaned() public {
        uint24 fee = 500;
        int24 tickSpacing = 10;
        address hooks = address(0);

        bytes32 keyFromAddV4 = hub.addV4(T0, T1, fee, tickSpacing, hooks);
        uint256 origSlotAfterAdd = hub.getSlot(keyFromAddV4);

        bytes32 pid = _computeV4PoolId(T0, T1, fee, tickSpacing, hooks);
        address pseudoPool = address(uint160(uint256(pid)));

        for (uint256 i; i < 5; ++i) {
            vm.warp(block.timestamp + 1 hours);
            hub.recordSwap(pseudoPool, KIND_V4, fee, hooks, T0, T1, 1e18, 1e18, 1e21);
        }

        assertEq(hub.getActivePools(T0, T1).length, 2, "should have exactly one duplicate, repeatedly ticked");
        assertEq(hub.getSlot(keyFromAddV4), origSlotAfterAdd, "original V4 slot must remain orphaned across repeated swaps");
    }

    // ─── 5. Duplicate wastes one of MAX_SLOTS ───
    function test_duplicateWastesOneOfMaxSlots() public {
        uint24 fee = 500;
        int24 tickSpacing = 10;
        address hooks = address(0);

        hub.addV4(T0, T1, fee, tickSpacing, hooks);
        bytes32 pid = _computeV4PoolId(T0, T1, fee, tickSpacing, hooks);
        address pseudoPool = address(uint160(uint256(pid)));
        hub.recordSwap(pseudoPool, KIND_V4, fee, hooks, T0, T1, 1e18, 1e18, 1e21);
        assertEq(hub.getActivePools(T0, T1).length, 2, "sanity: 2 slots used for 1 logical V4 pool");

        for (uint256 i; i < 14; ++i) {
            address p = address(uint160(uint256(keccak256(abi.encode("v3pool", i))) | 1));
            hub.recordSwap(p, 1 /*KIND_V3*/, 3000, address(0), T0, T1, 1e18, 1e18, 1e21);
        }

        PoolInfo[] memory ps = hub.getActivePools(T0, T1);
        assertEq(ps.length, MAX_SLOTS, "registry should be at capacity");

        uint256 distinct;
        for (uint256 i; i < ps.length; ++i) {
            bool seen;
            for (uint256 j; j < i; ++j) if (ps[j].pool == ps[i].pool) { seen = true; break; }
            if (!seen) distinct++;
        }
        assertEq(distinct, MAX_SLOTS - 1, "BUG: MAX_SLOTS reached with only 15 distinct venues -- 1 slot wasted on the V4 duplicate");
    }

    // ─── 6. Duplicate rows collapse onto one freshness slot ───
    function test_duplicateV4Rows_countSameK2ActivityTwiceTowardFreshness() public {
        uint24 fee = 500;
        int24 tickSpacing = 10;
        address hooks = address(0);

        bytes32 k1 = hub.addV4(T0, T1, fee, tickSpacing, hooks);

        bytes32 pid = _computeV4PoolId(T0, T1, fee, tickSpacing, hooks);
        address pseudoPool = address(uint160(uint256(pid)));
        bytes32 k2 = hub.keyOf(pseudoPool, T0, T1);

        vm.warp(10_000);
        hub.recordSwap(pseudoPool, KIND_V4, fee, hooks, T0, T1, 1e18, 1e18, 1e21);

        PoolInfo[] memory ps = hub.getActivePools(T0, T1);
        assertEq(ps.length, 2);
        assertEq(ps[0].pool, pseudoPool);
        assertEq(ps[1].pool, pseudoPool);
        assertTrue(k1 != k2);

        // _registryFresh() recomputes keyOf(PoolInfo.pool,...) rather than
        // using the original registry key — both rows resolve to k2.
        bytes32 solverKey0 = hub.keyOf(ps[0].pool, ps[0].token0, ps[0].token1);
        bytes32 solverKey1 = hub.keyOf(ps[1].pool, ps[1].token0, ps[1].token1);
        assertEq(solverKey0, k2);
        assertEq(solverKey1, k2);
        assertEq(solverKey0, solverKey1);

        uint256 slot0 = hub.getSlot(solverKey0);
        uint256 slot1 = hub.getSlot(solverKey1);
        assertEq(slot0, slot1);
        assertTrue(slot0 != 0);

        // k1 remains a distinct, orphaned slot.
        assertTrue(hub.getSlot(k1) != slot0);
    }
}
```