# Title

Block-Number-Based Vitality Aging Produces Chain-Dependent Fitness Scoring

## Severity: Protocol Improvement (Low)

## Summary

Pool vitality is derived from `block.number`, not elapsed wall-clock time. BlazePhoenix is designed to deploy unchanged across Ethereum, Arbitrum, Base and Optimism, which have very different block cadences so the same block-count decay window means very different real-world durations per chain.

```solidity
function vitality(uint256 slot, uint32 currentBlock) internal pure returns (uint256 v) {
    uint32 lastBlk = decodeLastBlk(slot);
    if (lastBlk == 0) return 0;

    uint32 age = currentBlock > lastBlk ? currentBlock - lastBlk : 0;
    uint32 swapCount = decodeSwapCount(slot);

    if (age >= 16) {
        uint256 shift = age >> 4;
        if (shift > 31) return 0;
        v = uint256(swapCount) >> shift;
    } else {
        v = swapCount;
    }
    if (v == 0) v = 1;
}
```

The implementation documents the decay horizon using an Ethereum-specific reference:

```solidity
/// base: swap count, decayed by age window of 65,536 blocks
/// (~9 days @ 12s).
```

But because vitality decays by one bit every 16 blocks, the effective vitality reaches its minimum long before this documented reference horizon. `swapCount` loses one bit per 16 blocks of inactivity, so it reaches the floor (`v == 1`) after only `16 * bit_length(swapCount)` blocks i.e. 208 blocks for `swapCount = 10,000`, 256 blocks for `swapCount = 100,000`. The 65,536-block figure only marks the *hard* `shift > 31` cutoff, at which point vitality has long since floored and reads a literal **0**.

Furthermore, since BlazePhoenix is deployed across chains with different block cadences, the same block window corresponds to very different real-world durations depending on deployment:

| Network         | Block time | Wall-clock to reach floor (swapCount=100,000, 256 blocks) |
| --------------- | ---------- | --------------------------------------------------------- |
| Ethereum        | ~12s       | ~51 min                                                   |
| Base / Optimism | ~2s        | ~8.5 min                                                  |

Even on Ethereum, a pool merely idle for under an hour already receives the minimum vitality contribution. On Base/Optimism this collapses to under 9 minutes.

Notably, the protocol's own discovery-freshness gate (`_registryFresh` / `DISCOVERY_TTL_SECONDS`) deliberately uses `block.timestamp` to achieve identical real-time behavior across deployments. Vitality aging does not follow the same pattern, despite serving an analogous purpose (recency-weighting a pool's activity) this is an internal inconsistency within the protocol's own design: one recency mechanism is chain-uniform by construction, the other is not.

## Impact

`vitality` feeds `psi` (`Core.psi`), which drives both Hub pool admission (`_canInsert`) and eviction ranking (`_register`, via `_psiOfSlot`). Because of the above:

- A genuinely healthy, actively traded pool that goes quiet for minutes (L2) or under an hour (mainnet) reaches the minimum non-zero vitality contribution. This substantially reduces the influence of historical trading activity in the overall fitness score, despite the pool potentially remaining fundamentally healthy.
- This may disproportionately bias fitness-based admission and replacement decisions toward recent routing activity, particularly on fast-block chains.
- Route selection quality may degrade as good pools are prematurely deprioritized or evicted, more severely on fast-block L2s than on Ethereum, despite BlazePhoenix advertising identical behavior across all four chains.

No funds are directly at risk; this is a routing-quality and cross-chain-consistency defect.

## Mitigation

Normalize aging to elapsed wall-clock time, matching the pattern already used for discovery freshness:

- Update the packed slot layout to encode the last activity **timestamp** instead of the last observed **block number**.
- Every location currently performing `lastBlk = uint32(block.number);` should instead persist `lastActivityTimestamp = uint32(block.timestamp);`.
- Compute `age` from `block.timestamp` instead of `block.number`.
- Define the decay window in seconds (e.g. `DECAY_WINDOW_SECONDS`) rather than a fixed block count, and derive `periods = age / DECAY_WINDOW_SECONDS` for the shift.
- Update the associated encoding/decoding helpers (`encodeSlot`, `decodeLastBlk`, etc.) accordingly to preserve consistent semantics throughout the protocol.

This makes vitality decay identically, in real time, regardless of deployment chain, and aligns it with the existing timestamp-based freshness gate.

Using `block.number` is a valid deterministic heuristic, but it couples vitality decay to network-specific block cadence rather than elapsed time. If consistent cross-chain behavior is the design objective, timestamp-based aging provides more uniform semantics.

## POC

Add this `helper` in `Blaze-Phoenix-Dex/test/harness/CoreHarness.sol`

```solidity
    function vitality(uint256 s, uint32 currentBlock) external pure returns (uint256) {
        return BPC.vitality(s, currentBlock);
    }
```

Add these tests in `Blaze-Phoenix-Dex/test/CoreMath.t.sol`

```solidity
// Shows that at the documented 65,536-block reference horizon, vitality is
// already hard-zeroed (not gracefully decayed) and that the actual floor
// (v==1) is reached at just 208 blocks.

function test_vitality_collapsesFarBeforeClaimedNineDayWindow() public view {
    uint32 lastBlk = 1_000_000;
    uint32 swapCount = 10_000;
    uint256 s = h.encodeSlot(true, 0, 1, 0, 0, 0, 0, 0, swapCount, 0, lastBlk);

    _req(h.vitality(s, lastBlk + 65_536) == 0, "hard cutoff should already have zeroed this");
    _req(h.vitality(s, lastBlk + 208) == 1, "floor should be reached by 208 blocks");
    uint256 vEarlier = h.vitality(s, lastBlk + 192);
    _req(vEarlier == (uint256(swapCount) >> 12), "expected one bit removed per 16 blocks");
    _req(vEarlier > 1, "192 blocks should not yet be at the floor");
}

// Converts the same block-count collapse (256 blocks, for a highly active
// pool) into wall-clock time per chain: ~51 minutes on Ethereum vs. ~8.5
// minutes on Base/Optimism the L2 case is ~6x faster purely from block
// cadence, despite identical real-world trading activity.

function test_vitality_wallClockCollapse_perChain() public view {
    uint32 lastBlk = 500_000;
    uint32 swapCount = 100_000;
    uint256 s = h.encodeSlot(true, 0, 1, 0, 0, 0, 0, 0, swapCount, 0, lastBlk);

    _req(h.vitality(s, lastBlk + 256) == 1, "expected floor at 256 blocks");
    _req(h.vitality(s, lastBlk + 240) > 1, "240 blocks should still be above the floor");

    uint256 ethSeconds  = uint256(256) * 12;
    uint256 baseSeconds = uint256(256) * 2;
    _req(ethSeconds < 1 hours, "Ethereum floor reached in under an hour, not ~9 days");
    _req(baseSeconds < 9 minutes, "Base/Optimism floor reached in well under 9 minutes");
}

// Shows a pool idle for only ~8.5 minutes (256 blocks on an L2) reaches the
// same minimum vitality (v=1) that a long-dead pool reads past the hard
// cutoff (v=0, 10,000 blocks) i.e. the two are nearly indistinguishable
// in fitness evaluation despite one being healthy and merely quiet.

function test_vitality_brieflyIdleIndistinguishableFromDead() public view {
    uint32 lastBlk = 1_000_000;
    uint32 swapCount = 50_000;
    uint256 s = h.encodeSlot(true, 0, 1, 0, 0, 0, 0, 0, swapCount, 0, lastBlk);

    _req(h.vitality(s, lastBlk + 256) == 1, "briefly-idle pool should already be at the floor");
    _req(h.vitality(s, lastBlk + 10_000) == 0, "long-dead pool hits the hard cutoff, not the floor");
}
```