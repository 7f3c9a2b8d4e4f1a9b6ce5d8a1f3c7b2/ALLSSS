# Audit Report

## Title
Voluntary Key Rotation Bypasses Performance Penalties in Miner Reward Distribution

## Summary
The Treasury contract's `UpdateBasicMinerRewardWeights` function incorrectly applies penalty-bypass logic (`IsReplacedEvilMiner` flag) to voluntary key rotations instead of evil miner replacements. This allows underperforming miners to double their Basic Miner Reward shares by rotating their public key before term end, circumventing the quadratic performance penalty system designed to enforce reliable block production.

## Finding Description

The vulnerability stems from a logic inversion in how miner replacements are tracked for reward distribution. The system has two distinct replacement mechanisms:

**1. Voluntary Key Rotation Flow:**

When a miner admin calls `ReplaceCandidatePubkey`, the Election contract triggers `RecordCandidateReplacement` [1](#0-0) , which updates the consensus round by transferring the complete `MinerInRound` information (including `ProducedBlocks`) to the new pubkey [2](#0-1) . This then calls `RecordMinerReplacement` on the Treasury contract [3](#0-2) , which unconditionally sets `IsReplacedEvilMiner[newPubkey] = true` [4](#0-3) .

**2. Evil Miner Replacement Flow:**

When `GenerateNextRoundInformation` detects evil miners, it creates a fresh `MinerInRound` object for replacement candidates with only basic consensus fields (pubkey, expected time, order) and **default ProducedBlocks = 0** [5](#0-4) . Critically, this flow **never calls** `RecordMinerReplacement` on the Treasury contract [6](#0-5) .

At term end, `UpdateBasicMinerRewardWeights` distributes the Basic Miner Reward. For miners where `IsReplacedEvilMiner` is true, shares are set directly to `ProducedBlocks` [7](#0-6) , bypassing the `CalculateShares` penalty function. Normal miners undergo quadratic penalty calculation where miners producing 50-80% of average blocks receive `blocks² / average` shares [8](#0-7) .

**The Bug:**

The code comment suggests the bypass is intended for "new miners" who "took over from evil miners" [9](#0-8) , but the implementation only sets `IsReplacedEvilMiner` for voluntary key rotations where the original miner's performance data (including poor `ProducedBlocks`) is preserved. Evil miner replacements, which would legitimately deserve fair treatment, receive default values and no flag exemption.

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
- Attacker controls a candidate admin account (normal operational requirement for miners) [10](#0-9) 
- Single transaction calling `ReplaceCandidatePubkey` with new pubkey [11](#0-10) 
- No timing restrictions beyond term boundaries
- No cost beyond transaction fees

**Execution Scenario:**
1. Miner monitors their `ProducedBlocks` during term
2. If performance falls below 80% of expected average, execute key rotation
3. New pubkey inherits all consensus data including poor block production count
4. `IsReplacedEvilMiner` flag ensures penalty bypass at term end
5. Flag cleared after one-time use, ready for next term exploitation [12](#0-11) 

**Detection Difficulty:**
Key rotations are legitimate operational needs (security key updates, hardware migration). Distinguishing malicious penalty avoidance from genuine operations is nearly impossible without correlating performance metrics with rotation timing across multiple terms.

**Feasibility:** High - publicly callable method, deterministic outcome, zero operational risk.

## Recommendation

Modify `RecordCandidateReplacement` in the AEDPoS contract to pass the `IsOldPubkeyEvil` parameter to Treasury's `RecordMinerReplacement`: [3](#0-2) 

Change the call to include:
```csharp
State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
{
    OldPubkey = input.OldPubkey,
    NewPubkey = input.NewPubkey,
    CurrentTermNumber = State.CurrentTermNumber.Value,
    IsOldPubkeyEvil = false  // Explicitly set for voluntary rotations
});
```

For evil miner replacements in `GenerateNextRoundInformation`, add a call to `RecordMinerReplacement` with `IsOldPubkeyEvil = true` after creating the replacement miner entry [13](#0-12) .

Finally, update the Treasury's `RecordMinerReplacement` to only set the flag when `IsOldPubkeyEvil` is true:
```csharp
if (input.IsOldPubkeyEvil)
{
    State.IsReplacedEvilMiner[input.NewPubkey] = true;
}
```

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task VoluntaryKeyRotation_BypassesPenalties_Test()
{
    // Setup: Miner with poor performance (50% of average)
    var poorPerformerOldKey = "oldkey";
    var poorPerformerNewKey = "newkey";
    var averageBlocks = 400L;
    var producedBlocks = 200L; // 50% performance
    
    // Execute voluntary key rotation
    await ElectionContractStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = poorPerformerOldKey,
        NewPubkey = poorPerformerNewKey
    });
    
    // Advance to term end and trigger reward distribution
    await AdvanceToNextTerm();
    
    // Verify: New key gets full ProducedBlocks as shares (200) instead of penalized shares (100)
    var shares = await GetMinerShares(poorPerformerNewKey);
    
    // Without bypass: shares = 200^2 / 400 = 100
    // With bypass: shares = 200 (direct assignment)
    Assert.Equal(200, shares); // Proves bypass is active
    
    // Calculate excess reward
    var normalShares = (producedBlocks * producedBlocks) / averageBlocks; // 100
    var excessShares = shares - normalShares; // 100
    var rewardIncrease = (excessShares * 100) / normalShares; // 100% increase
    Assert.Equal(100, rewardIncrease);
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-173)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L328-339)
```csharp
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```
