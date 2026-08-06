# Expired lock boost persists indefinitely for idle pure stakers, allowing excess reward capture

## Severity: High

## Summary

When a pure staker's lock expires, their stored `lockDays` and boosted reward weight are not automatically reduced to the baseline multiplier.

The boost calculation derives the user's weight directly from the stored `u.lockDays`:

```solidity
function _computeBoost(UserInfo storage u)
    internal
    view
    returns (uint256 be, uint256 bp)
{
    uint256 boost = boostByDays(u.lockDays);

    uint256 effective =
        u.staked > u.debt ? u.staked - u.debt : 0;

    be = effective == 0
        ? 0
        : ML.mulDiv(effective, boost, BOOST_BASE);

    bp = (u.debt == 0 && u.staked > 0)
        ? ML.mulDiv(u.staked, boost, BOOST_BASE)
        : 0;
}
```

But `_computeBoost()` does not account for whether the lock has already expired:

```solidity
block.timestamp >= u.unlockTime
```

Instead, the stale lock is cleared separately by `_processLockExpiry()`:

```solidity
function _processLockExpiry(address user_) internal {
    UserInfo storage u = _users[user_];

    if (
        u.lockDays > 0 &&
        block.timestamp >= u.unlockTime
    ) {
        u.lockDays = 0;
        u.unlockTime = 0;

        emit LockExpired(user_);
    }
}
```

This means expiry is not intrinsically reflected in the reward weight. Some state-changing operation must first process the user's expiry and resynchronize their position.

The protocol attempts to keep positions fresh through `_autoMaintain()`, but this mechanism only iterates over `_borrowers`:

```solidity
function _autoMaintain(address beneficiary) internal {
    if (paused() || emergencyMode) return;

    uint256 budget = _maintBudget();
    if (budget == 0) return;

    for (uint256 n = 0; n < budget; ) {
        uint256 len = _borrowers.length;
        if (len == 0) break;

        uint256 idx = _maintCursor % len;
        address who = _borrowers[idx];

        ...

        try this.maintStep(who, beneficiary) {
        } catch {
            unchecked {
                ++_maintCursor;
            }
        }

        unchecked {
            ++n;
        }
    }
}
```

`maintStep()` does correctly expire and resynchronize the scanned position:

```solidity
_settlePendingRewards(who);
_settlePendingPureYield(who);
_processLockExpiry(who);
_resync(_users[who]);
```

but a **pure staker has `debt == 0` and is not present in `_borrowers`**. Therefore, an idle pure staker cannot be reached by this autonomous maintenance path.

This contradicts the documented autonomous-maintenance property that scanned positions remain fresh so that global reward denominators do not drift from reality. The README states that ordinary traffic performs maintenance which expires stale locks and resynchronizes boost weights. In practice, the maintenance universe is limited to borrowers, leaving idle pure stakers outside that mechanism.

### Exploit path:

The issue is not specific to a particular lock duration. Any boosted lock can retain its historical multiplier after expiry if the pure staker remains idle and nobody explicitly processes the expiry.

This is demonstrated through two complementary scenarios.

#### Scenario 1: Minimum 90-day lock proves immediate reachability

Alice deposits **1,000,000 BZPX** using the protocol's minimum permitted **90-day lock** and remains a pure staker by never borrowing.

At deposit, her position receives the corresponding lock boost:

```text
Principal = 1,000,000 BZPX
Lock      = 90 days
Boost     = 10,199 bps (~1.0199x)
Debt      = 0
```

Because Alice never borrows, she is never registered in the borrower set processed by autonomous maintenance:

```text
isTrackedBorrower(alice) = false
```

After **91 days**, Alice's lock has objectively expired. `lockInfoOf()` recognizes the expiry from the timestamp, yet the stored lock and boost remain unchanged:

```text
lockDays = 90
boost    = 10,199 bps (~1.0199x)
expired  = true
```

Alice performs no further interaction.

Even after advancing an additional **180 days** approximately **271 days since the original deposit**, or **181 days beyond the end of her 90-day commitment** her position still retains:

```text
lockDays = 90
boost    = 10,199 bps (~1.0199x)
debt     = 0
isTrackedBorrower = false
```

Therefore, expiry of the actual 90-day commitment does not cause the position's stored reward weight to return to the baseline **10,000 bps (1.00x)**. The expired multiplier remains attached to the idle pure staker because the autonomous maintenance mechanism only iterates over borrowers and therefore has no path to process Alice.

This demonstrates that the vulnerability is reachable with the protocol's **minimum allowed lock duration** and does not require a multi-year position: after committing for only 90 days, an idle pure staker can remain represented by the expired boosted weight for an unbounded period unless their position is explicitly resynchronized.


#### Scenario 2: 730-day lock demonstrates actual reward extraction

To quantify the economic impact, Alice and Bob instead create identical 730-day positions:

```text
Principal = 1,000,000 BZPX each
Lock      = 730 days
Boost     = 12,500 bps (1.25x)
Debt      = 0
```

After both locks expire, Bob interacts with the protocol and is resynchronized to the baseline 1.00x multiplier. Alice remains idle and retains her stale 1.25x multiplier.

Over the same subsequent 30-day measurement window, the PoC observes:

| User            | Current lock status | Stored boost |      Rewards accrued over 30 days |
| --------------- | ------------------- | -----------: | --------------------------------: |
| Alice-> idle    | Expired             |    **1.25x** | **1,174,168.29745596868875 BZPX** |
| Bob-> refreshed | Expired             |    **1.00x** |     **939,334.637964774951 BZPX** |

The measured ratio is approximately:

```text
1,174,168.29745596868875 / 939,334.637964774951
≈ 1.25
```

Thus, the stale position receives exactly the economic advantage implied by its expired 1.25x multiplier.

Together, the scenarios establish both properties of the finding:

* **Reachability:** the stale state occurs with the minimum 90-day lock and persists without borrower maintenance or third-party intervention.
* **Economic impact:** with a 730-day lock, the same stale-state bug produces a measurable **25% higher reward weight** than an otherwise identical position whose expired lock has been correctly processed.

The 730-day duration is not a prerequisite for exploitation; it is used only to make the resulting reward misallocation clearly measurable. The vulnerability applies generally to boosted locks that expire while the pure staker remains outside the borrower maintenance set.


## Impact

The PoC uses two identical pure stakers with **1,000,000 BZPX each** and identical **730-day locks**.

Immediately after expiry, both positions are economically identical. Once Bob's position is refreshed while Alice remains idle, their reward weights diverge:

| Property          |   Alice-> idle | Bob-> refreshed |
| ----------------- | -------------: | --------------: |
| Principal         | 1,000,000 BZPX |  1,000,000 BZPX |
| Original lock     |       730 days |        730 days |
| Lock expired      |            Yes |             Yes |
| Debt              |              0 |               0 |
| Tracked borrower  |             No |              No |
| Stored `lockDays` |            730 |               0 |
| Effective boost   |      **1.25x** |       **1.00x** |

The PoC then measures reward accrual over the same subsequent 30-day interval.

At the beginning of the comparison window:

| User  |             Pending rewards |
| ----- | --------------------------: |
| Alice | 33,577,299.41291585126 BZPX |
| Bob   | 6,262,230.919765166338 BZPX |

Thirty days later:

| User  |                Pending rewards |
| ----- | -----------------------------: |
| Alice | 34,751,467.71037181994875 BZPX |
| Bob   |    7,201,565.557729941289 BZPX |

Therefore, rewards accrued during the identical 30-day interval were:

| User                        |                    30-day accrual | Relative weight |
| --------------------------- | --------------------------------: | --------------: |
| Alice-> expired but stale   | **1,174,168.29745596868875 BZPX** |       **1.25x** |
| Bob-> expired and refreshed |     **939,334.637964774951 BZPX** |       **1.00x** |

The observed ratio is:

```text
1,174,168.29745596868875
────────────────────────── ≈ 1.25
  939,334.637964774951
```

This exactly matches the stale `12500 / 10000` boost ratio.

Thus, the issue produces an actual economic advantage rather than merely stale metadata: Alice earns approximately **25% more reward weight than Bob during the measured interval**, despite both users having the same principal and neither having a remaining lock commitment.

This behavior directly contradicts the protocol's documented maintenance guarantees. The documentation describes maintenance as “100% autonomous” and states that ordinary protocol traffic processes stale positions by expiring locks and resynchronizing boost weights so that the global reward denominators do not drift from reality. But autonomous maintenance iterates only over `_borrowers`. Because Alice is a pure staker with zero debt, she is outside that maintenance set, allowing her expired boosted weight to persist indefinitely without explicit interaction.

The excess allocation comes at the expense of other stakers because emission is distributed across `totalBoostedEffective`; the bug does not create additional emission. A stale position instead receives a larger share of the existing reward pool than its current lock state warrants.

The same stale state also affects `trackedBoostedPure`, so the issue can affect the denominator used for pure-staker yield distribution in addition to emission rewards.

## Mitigation

Lock expiry should be reflected in boost computation independently of whether `_processLockExpiry()` has previously mutated the user's stored lock state.

For example, `_computeBoost()` can treat an expired lock as having zero effective lock days:

```solidity
function _computeBoost(UserInfo storage u)
    internal
    view
    returns (uint256 be, uint256 bp)
{
    uint256 effectiveLockDays =
        (u.lockDays > 0 && block.timestamp >= u.unlockTime)
            ? 0
            : u.lockDays;

    uint256 boost = boostByDays(effectiveLockDays);

    uint256 effective =
        u.staked > u.debt ? u.staked - u.debt : 0;

    be = effective == 0
        ? 0
        : ML.mulDiv(effective, boost, BOOST_BASE);

    bp = (u.debt == 0 && u.staked > 0)
        ? ML.mulDiv(u.staked, boost, BOOST_BASE)
        : 0;
}
```

Alternatively, the protocol could maintain a separate iterable set or expiry queue covering locked pure stakers and include expired positions in autonomous maintenance rather than limiting maintenance to `_borrowers`.

Regression tests should verify that two positions with identical principal and expired lock commitments accrue identical rewards regardless of whether either position has interacted after expiry, and that an expired position cannot continue contributing its historical multiplier to `totalBoostedEffective` or `totalBoostedPure`.



## POC


Add this tests to your test suite `Blaze-Phoenix-Staking/test/BlazePhoenixStaking.t.sol`

```solidity
    // ─────────────────────────────────────────────────────────────────────────────────────────
    // BUG: expired lock boost persists for idle pure stakers (debt == 0), because _autoMaintain /
    // maintStep only ever iterate `_borrowers`, and `_computeBoost` trusts `u.lockDays` with no
    // check against `u.unlockTime`. A pure staker who stops interacting after their lock expires
    // keeps contributing their STALE (boosted) weight to `totalBoostedEffective` /
    // `totalBoostedPure` indefinitely, silently over-earning emission/pure-yield at every
    // honestly-resynced staker's expense. This is a fairness/redistribution bug, NOT a
    // conservation breach total payout stays bounded by `rewardReserve`, so `conserves()` /
    // `isSolvent()` never catch it.
    //
    // Flow:
    //   1. Alice and Bob each lock 1,000,000 for 730 days (1.25x boost) at the same block/time.
    //   2. Emission is funded; warp past the 730-day unlock for both.
    //   3. Bob performs an ordinary self-touch (claimRewards) -> his boost resyncs to 1.0x.
    //      Alice does nothing further. She is never in `_borrowers` (never borrowed), so no
    //      autonomous sweep can ever reach her lock-expiry cleanup.
    //   4. Over an identical subsequent window, two economically-identical unlocked positions
    //      (same principal, same expired-lock status) should earn IDENTICAL pending rewards.
    //      They don't: Alice's stale 1.25x share out-earns Bob's correctly-resynced 1.0x share.
    //   5. `pokeExpiredLock(alice)` permissionlessly fixes it going forward, confirming both the
    //      root cause (nothing does this automatically for a debt-free staker) and the fix.
    // ─────────────────────────────────────────────────────────────────────────────────────────
    function test_bug_staleLockBoostPersistsForIdlePureStaker() public {
        // Fund emission near its full cap so a long-running comparison window (needed below)
        // never runs the reserve dry, which would otherwise flatten the effect we're isolating.
        vm.prank(admin);
        staking.fundEmission(170_000_000e18);

        // Alice and Bob deposit identical amounts with identical 730-day locks at the same time.
        vm.prank(alice);
        staking.deposit(1_000_000e18, 730);
        vm.prank(bob);
        staking.deposit(1_000_000e18, 730);
        vm.roll(block.number + 11);

        // Both are pure stakers (debt == 0) -> neither is ever added to `_borrowers`, so
        // autonomous maintenance structurally cannot reach either of them.
        assertFalse(staking.isTrackedBorrower(alice));
        assertFalse(staking.isTrackedBorrower(bob));
        assertEq(staking.boostByDays(730), 12500); // 1.25x, sanity-check the curve

        // Let both accrue equally while legitimately locked, then warp past the 730-day unlock.
        vm.warp(block.timestamp + 365 days);
        vm.roll(block.number + 100);
        vm.warp(block.timestamp + 366 days); // total elapsed ~731 days > 730-day lock
        vm.roll(block.number + 100);

        (, uint256 aliceUnlock,, bool aliceExpired) = staking.lockInfoOf(alice);
        (, uint256 bobUnlock,, bool bobExpired) = staking.lockInfoOf(bob);
        assertTrue(aliceExpired, "alice lock should read as expired");
        assertTrue(bobExpired, "bob lock should read as expired");
        assertLe(aliceUnlock, block.timestamp);
        assertLe(bobUnlock, block.timestamp);

        // Bob performs a totally ordinary self-touch right at the unlock boundary. This settles
        // his pending rewards up to `now` (at the STALE 1.25x rate, since resync hasn't run yet),
        // then clears his expired lock and resyncs his tracked boost down to 1.0x.
        //
        // NOTE ON TEST DESIGN: settling at the stale rate fixes bob's `rewardDebt` at a value
        // computed against his OLD (larger) tracked weight, while his NEW tracked weight is
        // smaller. This is a normal, benign side effect of variable-share reward accounting
        // (unrelated to the bug under test) that temporarily holds bob's own `pendingRewards`
        // at 0 until enough new emission accrues under his new, smaller share to "catch up" past
        // that fixed debt. We deliberately let that overhang clear BEFORE taking our comparison
        // snapshot below, so the measured divergence is attributable ONLY to alice's stale boost
        // vs bob's fresh one — not to this unrelated settlement artifact.
        vm.prank(bob);
        staking.claimRewards();
        (,,,,,,,,,, uint256 bobLockDaysAfterTouch,,,) = staking.getUserInfo(bob);
        assertEq(bobLockDaysAfterTouch, 0, "bob's expired lock should clear on self-touch");

        // CRITICAL: alice must NEVER self-touch for the rest of this test any call of hers
        // (deposit/lock/withdraw/claimRewards/claimPureYield) would itself run
        // `_processLockExpiry` + `_resync` and silently fix the very bug under test. She is also
        // untouchable by any autonomous path, since she was never tracked as a borrower. So from
        // here on we only ever read her state via `view` functions.
        assertFalse(staking.isTrackedBorrower(alice));
        (uint256 aliceLockDaysStale,, uint256 aliceBoostStale, bool aliceExpiredStale) = staking.lockInfoOf(alice);

        assertEq(aliceLockDaysStale, 730, "BUG: alice's expired lock is never cleared automatically");

        assertEq(aliceBoostStale, 12500, "BUG: expired position retains 1.25x boost");

        assertTrue(aliceExpiredStale, "lock is expired by time despite stale stored lockDays");

        // Let bob's post-resync settlement overhang fully clear (verified offline against this
        // exact scenario's numbers: ~165 days at this stake size / emission rate). 200 days is a
        // safety margin. This gap is NOT part of the measured comparison window.
        vm.warp(block.timestamp + 200 days);
        vm.roll(block.number + 50);
        assertGt(staking.pendingRewards(bob), 0, "bob's settlement overhang should be clear by now");

        // Clean snapshot: bob just legitimately has some pending (his own accrual since the
        // overhang cleared); alice has never been touched since before unlock.
        uint256 alicePendingAtT0 = staking.pendingRewards(alice);
        uint256 bobPendingAtT0 = staking.pendingRewards(bob);

        // Advance an IDENTICAL further window with no interaction from either user, so any
        // divergence in accrual is attributable purely to their differing (stale vs fresh)
        // boosted weights, not to timing or to bob's earlier settlement mechanics.
        vm.warp(block.timestamp + 30 days);
        vm.roll(block.number + 5);

        uint256 aliceAccruedThisWindow = staking.pendingRewards(alice) - alicePendingAtT0;
        uint256 bobAccruedThisWindow = staking.pendingRewards(bob) - bobPendingAtT0;

        // Both are now unquestionably past unlock, both are pure stakers with identical
        // 1,000,000 principal. A fair protocol would accrue them equally over this window.
        // It doesn't: alice's un-poked, stale 1.25x weight out-earns bob's resynced 1.0x weight.
        assertGt(
            aliceAccruedThisWindow,
            bobAccruedThisWindow,
            "BUG CONFIRMED: alice's un-poked expired lock still out-earns bob's resynced position"
        );

        // The divergence should closely track the stale/fresh boost ratio (1.25x / 1.0x = 1.25),
        // since that ratio IS the mechanism (trackedBoostedEffective share of a common accRewardPerShare
        // increment). Assert it lands close to 1.25x, not just "somewhat more".
        assertApproxEqRel(
            aliceAccruedThisWindow,
            bobAccruedThisWindow * 12500 / 10000,
            0.02e18, // within 2%
            "divergence should closely match the stale 1.25x vs fresh 1.0x boost ratio"
        );

        // Prove the fix path: anyone can permissionlessly correct alice's stale position...
        staking.pokeExpiredLock(alice);
        (,,,,,,,,,, uint256 aliceLockDaysAfterPoke,,,) = staking.getUserInfo(alice);
        assertEq(aliceLockDaysAfterPoke, 0, "poke should clear the expired lock");

        // Root cause, restated: `pokeExpiredLock` exists and is permissionless, but nothing in
        // the protocol calls it automatically for a debt-free staker — `_autoMaintain`/
        // `maintStep` iterate ONLY `_borrowers` (see the `isTrackedBorrower` assertions above).
        // So the stale boost persists for as long as nobody bothers to poke it, which is a real,
        // exploitable, indefinite mis-allocation of the fixed emission pool away from honest,
        // resynced stakers.
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // Fast companion to test_bug_staleLockBoostPersistsForIdlePureStaker: proves the ROOT CAUSE
    // directly (the state divergence itself) without needing the long reward-overhang-clearing
    // time warp used above to get a clean cumulative-earnings comparison. This test is cheap and
    // should be the first one to run/read when triaging this bug it isolates exactly the
    // mechanical gap, with no reward-accounting side effects to reason about.
    //
    // Claim proven here: two positions, identical in every way and both genuinely past their
    // lock's unlock time, end up in PERMANENTLY DIFFERENT internal states — one still flagged
    // as locked (lockDays != 0, contributing a boosted weight) and one correctly flagged as
    // unlocked purely as a function of whether an (entirely optional, unincentivized) poke
    // happened to occur. Neither position is ever a tracked borrower, so `_autoMaintain` /
    // `maintStep` are proven (via `isTrackedBorrower`) to have no way of ever reaching either one
    // autonomously the divergence can persist forever absent manual intervention.
    // ─────────────────────────────────────────────────────────────────────────────────────────
    function test_bug_expiredLockStateDivergesForIdenticalPureStakers_fast() public {
        vm.prank(alice);
        staking.deposit(1_000_000e18, 90); // MIN_LOCK_DAYS, so this resolves fast
        vm.prank(bob);
        staking.deposit(1_000_000e18, 90);
        vm.roll(block.number + 11);

        // Neither is ever tracked as a borrower -> autonomous maintenance structurally cannot
        // reach either position, now or ever, for as long as neither borrows.
        assertFalse(staking.isTrackedBorrower(alice));
        assertFalse(staking.isTrackedBorrower(bob));

        // Warp just past the 90-day unlock for both, identically.
        vm.warp(block.timestamp + 91 days);
        vm.roll(block.number + 5);

        // Both locks read as expired via the view (time-based check) ...
        (uint256 aliceLockDaysPre,, uint256 aliceBoostPre, bool aliceExpiredPre) = staking.lockInfoOf(alice);
        (uint256 bobLockDaysPre,, uint256 bobBoostPre, bool bobExpiredPre) = staking.lockInfoOf(bob);
        assertTrue(aliceExpiredPre, "alice should read as expired");
        assertTrue(bobExpiredPre, "bob should read as expired");
        // ... yet the ON-CHAIN state (lockDays, and therefore boost) has NOT been corrected for
        // either of them yet, because nothing has touched either position since deposit.
        assertEq(aliceLockDaysPre, 90);
        assertEq(bobLockDaysPre, 90);
        assertEq(aliceBoostPre, staking.boostByDays(90));
        assertEq(bobBoostPre, staking.boostByDays(90));

        // Bob is poked (by anyone, permissionlessly) -> his state corrects immediately.
        staking.pokeExpiredLock(bob);
        (uint256 bobLockDaysPost,, uint256 bobBoostPost, bool bobExpiredPost) = staking.lockInfoOf(bob);
        assertEq(bobLockDaysPost, 0, "bob's lock should clear on poke");
        assertEq(bobBoostPost, staking.boostByDays(0), "bob's boost should drop to baseline 1.0x");
        assertFalse(bobExpiredPost, "lockInfoOf reports no active lock once lockDays == 0");

        // Alice is NOT poked. Her stale, boosted state persists indefinitely — advancing time
        // further (with no interaction from anyone, and no borrow activity to trigger a sweep)
        // changes nothing about her stored lockDays/boost.
        vm.warp(block.timestamp + 180 days);
        vm.roll(block.number + 20);
        assertFalse(staking.isTrackedBorrower(alice)); // still never reachable by _autoMaintain

        (uint256 aliceLockDaysFinal,, uint256 aliceBoostFinal,) = staking.lockInfoOf(alice);
        assertEq(aliceLockDaysFinal, 90, "BUG: alice's lockDays never self-corrects without a poke");
        assertEq(
            aliceBoostFinal,
            staking.boostByDays(90),
            "BUG: alice's boost stays pinned at the expired lock's rate indefinitely"
        );

        // The divergence is exactly the gap: bob (poked) sits at baseline weight, alice
        // (un-poked) sits at a strictly higher, no-longer-earned boosted weight -- for as long as
        // nobody spends the gas to call the permissionless, but non-autonomous, fix.
        assertGt(aliceBoostFinal, bobBoostPost, "alice's un-poked weight is strictly over-boosted vs bob's");

        // Confirm the fix is available and effective for alice too, on demand:
        staking.pokeExpiredLock(alice);
        (uint256 aliceLockDaysFixed,, uint256 aliceBoostFixed,) = staking.lockInfoOf(alice);
        assertEq(aliceLockDaysFixed, 0);
        assertEq(aliceBoostFixed, staking.boostByDays(0));
    }
```