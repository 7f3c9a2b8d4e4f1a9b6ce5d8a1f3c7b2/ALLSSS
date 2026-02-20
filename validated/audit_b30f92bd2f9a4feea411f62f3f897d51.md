# Audit Report

## Title
Voluntary Key Rotation Bypasses Performance Penalties in Miner Reward Distribution

## Summary
The Treasury contract's `UpdateBasicMinerRewardWeights` function incorrectly applies penalty-bypass logic (`IsReplacedEvilMiner` flag) to voluntary key rotations instead of evil miner replacements. This allows underperforming miners to double their Basic Miner Reward shares by rotating their public key before term end, circumventing the quadratic performance penalty system designed to enforce reliable block production.

## Finding Description

The vulnerability stems from a logic inversion in how miner replacements are tracked for reward distribution. The system has two distinct replacement mechanisms:

**1. Voluntary Key Rotation Flow:**

When a miner admin calls `ReplaceCandidatePubkey`, the Election contract triggers the consensus contract's `RecordCandidateReplacement` method. [1](#0-0) 

The `RecordCandidateReplacement` method copies the **complete** `MinerInRound` information (including `ProducedBlocks`) from the old pubkey to the new pubkey: [2](#0-1) 

This then calls `RecordMinerReplacement` on the Treasury contract: [3](#0-2) 

Critically, the Treasury's `RecordMinerReplacement` method **ALWAYS** sets `IsReplacedEvilMiner[newPubkey] = true` regardless of whether the replacement was due to evil behavior: [4](#0-3) 

**2. Evil Miner Replacement Flow:**

When `GenerateNextRoundInformation` detects evil miners through the Election contract's `GetMinerReplacementInformation`, it creates a fresh `MinerInRound` object for replacement candidates with only basic consensus fields (pubkey, expected time, order) and **NO ProducedBlocks** set (defaults to 0): [5](#0-4) 

**Critically, this flow never calls `RecordMinerReplacement` on the Treasury contract**, so the `IsReplacedEvilMiner` flag is never set for actual evil miner replacements.

**Reward Distribution Logic:**

At term end, `UpdateBasicMinerRewardWeights` distributes the Basic Miner Reward. For miners where `IsReplacedEvilMiner` is true, shares are set directly to `ProducedBlocks`, bypassing the penalty function: [6](#0-5) 

Normal miners undergo quadratic penalty calculation where miners producing less than 80% of average blocks receive reduced shares: [7](#0-6) 

**The Bug:**

The code comment on line 804 suggests the bypass is intended for "new miners" who "took over from evil miners," but the implementation does the opposite: it sets `IsReplacedEvilMiner` for voluntary key rotations where the original miner's poor performance data is preserved, while actual evil miner replacements receive no flag and start with ProducedBlocks = 0.

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

The Basic Miner Reward represents a significant portion of treasury distribution. Over multiple terms with strategic rotations, underperforming miners can maintain reward levels equivalent to 80%+ performing miners, directly diluting rewards from honest high-performers. This undermines the consensus economic model's core invariant: block production reliability must correlate with reward allocation to ensure network stability.

## Likelihood Explanation

**Attack Requirements:**
- Attacker controls a candidate admin account (normal operational requirement for miners)
- Single transaction calling `ReplaceCandidatePubkey` with new pubkey
- No timing restrictions beyond term boundaries  
- No cost beyond transaction fees

The method is publicly accessible with only candidate admin permission check: [8](#0-7) 

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

The fix should invert the logic to match the intended behavior:

1. In `RecordCandidateReplacement`, pass an `IsOldPubkeyEvil` parameter when calling `RecordMinerReplacement` (currently not passed, defaults to false): [3](#0-2) 

2. Only set `IsReplacedEvilMiner` flag in `RecordMinerReplacement` when `IsOldPubkeyEvil` is true:

```csharp
// In TreasuryContract.RecordMinerReplacement
if (input.IsOldPubkeyEvil)
{
    var replaceCandidates = State.ReplaceCandidateMap[input.CurrentTermNumber] ?? new StringList();
    replaceCandidates.Value.Add(input.NewPubkey);
    State.ReplaceCandidateMap[input.CurrentTermNumber] = replaceCandidates;
    State.IsReplacedEvilMiner[input.NewPubkey] = true; // Only set here
}
else
{
    var latestMinedTerm = State.LatestMinedTerm[input.OldPubkey];
    State.LatestMinedTerm[input.NewPubkey] = latestMinedTerm;
    State.LatestMinedTerm.Remove(input.OldPubkey);
    // Do NOT set IsReplacedEvilMiner for voluntary rotations
}
```

3. In `GenerateNextRoundInformation`, call `RecordMinerReplacement` with `IsOldPubkeyEvil = true` when replacing evil miners.

## Proof of Concept

A test would demonstrate:
1. Setup a miner with poor performance (e.g., 200 blocks when average is 400)
2. Call `ReplaceCandidatePubkey` to rotate the key
3. Verify `IsReplacedEvilMiner` flag is set for new pubkey
4. Trigger term end and `UpdateBasicMinerRewardWeights`
5. Verify the miner receives 200 shares instead of the penalized 100 shares
6. Compare with a control miner with same performance who didn't rotate keys and receives only 100 shares

The vulnerability is confirmed by the code flow where voluntary replacements set the bypass flag while preserving poor performance data, whereas actual evil miner replacements receive fresh state without the flag.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
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
