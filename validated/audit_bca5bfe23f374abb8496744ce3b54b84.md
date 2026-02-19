# Audit Report

## Title
Voluntary Key Rotation Bypasses Performance Penalties in Miner Reward Distribution

## Summary
The Treasury contract's `UpdateBasicMinerRewardWeights` function incorrectly applies penalty-bypass logic (`IsReplacedEvilMiner` flag) to voluntary key rotations instead of evil miner replacements. This allows underperforming miners to double their Basic Miner Reward shares by rotating their public key before term end, circumventing the quadratic performance penalty system designed to enforce reliable block production.

## Finding Description

The vulnerability stems from a logic inversion in how miner replacements are tracked for reward distribution. The system has two distinct replacement mechanisms:

**1. Voluntary Key Rotation Flow:**
When a miner admin calls `ReplaceCandidatePubkey`, the Election contract triggers `RecordCandidateReplacement` [1](#0-0) , which updates the consensus round by transferring the complete `MinerInRound` information (including `ProducedBlocks`) to the new pubkey [2](#0-1) . This then calls `RecordMinerReplacement` on the Treasury contract [3](#0-2) , which sets `IsReplacedEvilMiner[newPubkey] = true` [4](#0-3) .

**2. Evil Miner Replacement Flow:**
When `GenerateNextRoundInformation` detects evil miners, it creates a fresh `MinerInRound` object for replacement candidates with only basic consensus fields (pubkey, expected time, order) and **default ProducedBlocks = 0** [5](#0-4) . Critically, this flow **never calls** `RecordMinerReplacement` on the Treasury contract.

At term end, `UpdateBasicMinerRewardWeights` distributes the Basic Miner Reward. For miners where `IsReplacedEvilMiner` is true, shares are set directly to `ProducedBlocks` [6](#0-5) , bypassing the `CalculateShares` penalty function. Normal miners undergo quadratic penalty calculation where miners producing 50-80% of average blocks receive `blocks² / average` shares [7](#0-6) .

**The Bug:**
The code comment suggests the bypass is intended for "new miners" who "took over from evil miners" [8](#0-7) , but the implementation only sets `IsReplacedEvilMiner` for voluntary key rotations where the original miner's performance data (including poor `ProducedBlocks`) is preserved. Evil miner replacements, which would legitimately deserve fair treatment, receive default values and no flag exemption.

## Impact Explanation

**Direct Fund Misallocation:**

For a miner producing 200 blocks when average is 400:
- **Normal path:** `CalculateShares(200, 400) = 200² / 400 = 100 shares`
- **After key rotation:** `200 shares` directly
- **Result:** 100% reward increase (100 excess shares)

For miners at 40% performance (160 blocks when average is 400):
- **Normal path:** `160² / 400 = 64 shares`
- **After rotation:** `160 shares`  
- **Result:** 150% reward increase (96 excess shares)

The Basic Miner Reward represents 10% of treasury distribution. Over multiple terms with strategic rotations, underperforming miners can maintain reward levels equivalent to 80%+ performing miners, directly diluting rewards from honest high-performers. This undermines the consensus economic model's core invariant: block production reliability must correlate with reward allocation to ensure network stability.

## Likelihood Explanation

**Attack Requirements:**
- Attacker controls a candidate admin account (normal operational requirement for miners)
- Single transaction calling `ReplaceCandidatePubkey` with new pubkey [9](#0-8) 
- No timing restrictions beyond term boundaries
- No cost beyond transaction fees

**Execution Scenario:**
1. Miner monitors their `ProducedBlocks` during term
2. If performance falls below 80% of expected average, execute key rotation
3. New pubkey inherits all consensus data including poor block production count
4. `IsReplacedEvilMiner` flag ensures penalty bypass at term end
5. Flag cleared after one-time use, ready for next term exploitation

**Detection Difficulty:**
Key rotations are legitimate operational needs (security key updates, hardware migration). Distinguishing malicious penalty avoidance from genuine operations is nearly impossible without correlating performance metrics with rotation timing across multiple terms.

**Feasibility:** High - publicly callable method, deterministic outcome, zero operational risk.

## Recommendation

Modify the Treasury contract's `RecordMinerReplacement` to properly distinguish between voluntary key rotations and genuine evil miner replacements. The fix should:

1. **For voluntary key rotations:** Do NOT set `IsReplacedEvilMiner`, as the original miner's performance data is preserved and should be subject to normal penalty calculations.

2. **For evil miner replacements:** Implement proper tracking (the AEDPoS contract should call `RecordMinerReplacement` with `IsOldPubkeyEvil = true` during `GenerateNextRoundInformation`) to ensure replacement miners who take over mid-term are fairly compensated.

The corrected logic in `RecordMinerReplacement` should be:
```
// Only set IsReplacedEvilMiner for actual evil miner replacements
// where a new candidate takes over with fresh start
if (input.IsOldPubkeyEvil) {
    State.IsReplacedEvilMiner[input.NewPubkey] = true;
}
```

Additionally, update `GenerateNextRoundInformation` to call `RecordMinerReplacement` when evil miners are replaced with alternative candidates.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize election with miners producing blocks during a term
2. Have one miner produce only 50% of average blocks (triggering quadratic penalty range)
3. Execute `ReplaceCandidatePubkey` for that underperforming miner
4. Advance to term end and distribute rewards via treasury release
5. Verify the rotated miner receives full `ProducedBlocks` count as shares, while a comparable non-rotated underperformer receives quadratically penalized shares
6. Demonstrate the reward delta constitutes direct fund misallocation from honest miners

The test would prove that voluntary key rotation serves as a penalty bypass mechanism for underperforming miners.

---

## Notes

This vulnerability represents a critical misalignment between intended economic incentives and implementation. The flag name `IsReplacedEvilMiner` and code comments suggest it should protect **replacement candidates** taking over from detected evil miners, ensuring they aren't penalized for the evil miner's poor performance. However, the implementation inverts this logic, protecting **the original underperforming miner** during voluntary key rotation while leaving genuine replacement candidates without protection (since evil miner replacements don't trigger the flag at all).

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L140-143)
```csharp
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L149-154)
```csharp
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L596-596)
```csharp
        State.IsReplacedEvilMiner[input.NewPubkey] = true;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L802-807)
```csharp
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L835-846)
```csharp
    private long CalculateShares(long producedBlocksCount, long averageProducedBlocksCount)
    {
        if (producedBlocksCount < averageProducedBlocksCount.Div(2))
            // If count < (1/2) * average_count, then this node won't share Basic Miner Reward.
            return 0;

        if (producedBlocksCount < averageProducedBlocksCount.Div(5).Mul(4))
            // If count < (4/5) * average_count, then ratio will be (count / average_count)
            return producedBlocksCount.Mul(producedBlocksCount).Div(averageProducedBlocksCount);

        return producedBlocksCount;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L328-335)
```csharp
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };
```
