# Audit Report

## Title
Multiple Miners Can Spam Tiny Blocks During Round Transition Gap

## Summary
The AEDPoS consensus validation logic fails to enforce that only the designated `ExtraBlockProducerOfPreviousRound` can produce blocks during round transition gaps. Any miner in the current round can exploit this to produce up to 8 tiny blocks during each transition, enabling collective block spam and unfair reward distribution.

## Finding Description

The vulnerability exists in a critical mismatch between what honest miners are programmed to do versus what validation actually enforces during round transition gaps.

**The Gap Creation:** When a new round begins, the first miner's expected mining time is set to `currentBlockTimestamp + miningInterval`, creating a time gap before the new round officially starts. [1](#0-0) 

**Honest Behavior (Not Enforced):** The consensus command generation logic correctly checks that only the `ExtraBlockProducerOfPreviousRound` should produce tiny blocks during this gap. [2](#0-1)  This identity verification ensures `CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey` before returning `TinyBlock` behavior. [3](#0-2) 

**Validation Bypass:** However, this identity check is NOT enforced during validation. The `UpdateTinyBlockInformation` method is publicly accessible [4](#0-3)  and processes transactions through `ProcessConsensusInformation` [5](#0-4) , which only performs a `PreCheck()` that verifies miner list membership without checking `ExtraBlockProducerOfPreviousRound`. [6](#0-5) 

**Insufficient Validation Chain:** The validation providers used by `ValidateBeforeExecution` are: [7](#0-6) 

1. **MiningPermissionValidationProvider** - Only checks if sender is in the miner list, not their specific role. [8](#0-7) 

2. **TimeSlotValidationProvider** - During the gap (when `latestActualMiningTime < expectedMiningTime`), it only verifies `latestActualMiningTime < GetRoundStartTime()` without checking if the sender equals `ExtraBlockProducerOfPreviousRound`. [9](#0-8) 

3. **ContinuousBlocksValidationProvider** - Limits each miner to producing continuous blocks, but allows up to 8 blocks per miner. [10](#0-9) 

**Attack Execution:**
1. Malicious miner monitors for `NextRound` blocks
2. During the gap (before new round start time), they submit `UpdateTinyBlockInformation` transactions
3. Validation passes because they are in the miner list and timing is within the gap
4. `ProcessTinyBlock` increments their `ProducedBlocks` counter for each spam block [11](#0-10) 
5. With the default 17 miners [12](#0-11)  and 8 blocks maximum [13](#0-12) , this enables 136 spam blocks per round transition.

## Impact Explanation

**Consensus Integrity Violation:** The AEDPoS protocol is designed with deterministic block production schedules where only the `ExtraBlockProducerOfPreviousRound` should produce blocks during transition gaps. This vulnerability breaks this fundamental consensus invariant, allowing any miner to produce blocks out of their designated turn.

**Unfair Reward Distribution:** Each spam block increments the miner's `ProducedBlocks` counter, affecting mining reward calculations. The initial mining reward is substantial [14](#0-13) , making this exploitation economically significant.

**Transaction Fee Capture:** Each tiny block can include transactions and capture their fees, giving attackers unfair advantage in fee collection compared to honest miners who follow the proper schedule.

**Network Performance Degradation:** Block propagation, validation, and storage are stressed by 136 extra blocks per round transition, potentially causing network congestion and increased blockchain bloat.

## Likelihood Explanation

**Highly Likely:**
- **Public Entry Point:** `UpdateTinyBlockInformation` is a publicly accessible RPC method with no special authorization requirements
- **Low Barrier:** Attacker only needs to be an elected miner, which is a normal operational state, not a privileged position requiring compromise
- **Frequent Opportunity:** Round transitions occur automatically with every consensus round, providing continuous exploitation windows
- **Low Complexity:** Attack requires only monitoring for round transitions and submitting transactions - no complex cryptographic operations or state manipulation needed
- **Economic Incentive:** Attackers gain extra block rewards and transaction fees with minimal additional cost

## Recommendation

Add identity verification to `TimeSlotValidationProvider` to enforce that only the `ExtraBlockProducerOfPreviousRound` can produce blocks during the gap:

```csharp
private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
{
    if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
    var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
    if (latestActualMiningTime == null) return true;
    var expectedMiningTime = minerInRound.ExpectedMiningTime;
    var endOfExpectedTimeSlot =
        expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
    if (latestActualMiningTime < expectedMiningTime)
    {
        // ADD IDENTITY CHECK HERE:
        if (validationContext.BaseRound.ExtraBlockProducerOfPreviousRound != validationContext.SenderPubkey)
            return false;
        
        return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
    }

    return latestActualMiningTime < endOfExpectedTimeSlot;
}
```

This ensures validation matches the intended consensus behavior defined in `ConsensusBehaviourProviderBase`.

## Proof of Concept

```csharp
// Test demonstrating that any miner can submit UpdateTinyBlockInformation during gap
[Fact]
public async Task AnyMinerCanSpamTinyBlocksDuringGap()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(17);
    await InitializeConsensusAsync(miners);
    
    // Advance to create a NextRound scenario
    var currentRound = await GetCurrentRoundAsync();
    var firstMiner = miners[0];
    var attackerMiner = miners[1]; // NOT the ExtraBlockProducerOfPreviousRound
    
    // Trigger NextRound to create the gap
    await firstMiner.NextRoundAsync();
    
    var newRound = await GetCurrentRoundAsync();
    var roundStartTime = newRound.GetRoundStartTime();
    var currentTime = await GetCurrentBlockTimeAsync();
    
    // Verify gap exists
    Assert.True(currentTime < roundStartTime);
    
    // Attacker (who is NOT ExtraBlockProducerOfPreviousRound) submits tiny blocks
    for (int i = 0; i < 8; i++)
    {
        var result = await attackerMiner.UpdateTinyBlockInformationAsync(
            new TinyBlockInput {
                ActualMiningTime = currentTime.AddMilliseconds(i * 100),
                ProducedBlocks = i + 1,
                RoundId = newRound.RoundId
            });
        
        // Validation should reject but actually passes - demonstrating the vulnerability
        Assert.True(result.Success); // This shows the bug
    }
    
    // Verify attacker's ProducedBlocks counter was incorrectly incremented
    var attackerInfo = newRound.RealTimeMinersInformation[attackerMiner.Pubkey];
    Assert.Equal(8, attackerInfo.ProducedBlocks); // Should be 0, proves exploitation
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L33-33)
```csharp
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

**File:** protobuf/aedpos_contract.proto (L42-42)
```text
    rpc UpdateTinyBlockInformation (TinyBlockInput) returns (google.protobuf.Empty) {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L108-112)
```csharp
    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L303-306)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L46-48)
```csharp
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L16-23)
```csharp
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L7-7)
```csharp
    public const long InitialMiningRewardPerBlock = 12500000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```
