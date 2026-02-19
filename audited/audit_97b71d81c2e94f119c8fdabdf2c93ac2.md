# Audit Report

## Title
Multiple Miners Can Spam Tiny Blocks During Round Transition Gap

## Summary
The AEDPoS consensus validation logic fails to enforce that only the designated `ExtraBlockProducerOfPreviousRound` can produce blocks during round transition gaps. Any miner in the current round can exploit this to produce up to 8 tiny blocks during each transition, enabling collective block spam and unfair reward distribution.

## Finding Description

The vulnerability exists in the consensus block validation chain where the `TimeSlotValidationProvider` performs insufficient identity verification during round transition gaps.

When a new round begins via `NextRound`, the system creates a time gap from the current block timestamp to the new round's start time (defined as `currentBlockTimestamp + miningInterval`). [1](#0-0)  The round start time is calculated as the first miner's expected mining time. [2](#0-1) 

During this gap, the `TimeSlotValidationProvider` checks if a miner can produce blocks but fails to verify their identity. [3](#0-2)  The validation only checks timing (`latestActualMiningTime < GetRoundStartTime()`) without verifying that the sender is the `ExtraBlockProducerOfPreviousRound`.

The system correctly implements identity verification in `IsCurrentMiner()` for consensus command generation. [4](#0-3)  This logic checks both the time condition AND that the pubkey equals `ExtraBlockProducerOfPreviousRound`. Similarly, the behavior provider uses this check when generating commands for honest miners. [5](#0-4) 

However, `IsCurrentMiner()` is NOT enforced during validation. The validation chain consists of: [6](#0-5) 

1. **MiningPermissionValidationProvider** - Only checks miner list membership [7](#0-6) 
2. **TimeSlotValidationProvider** - Checks timing but not identity during the gap
3. **ContinuousBlocksValidationProvider** - Limits consecutive blocks per miner [8](#0-7) 

The maximum blocks count is set to 8 in normal conditions. [9](#0-8) 

**Attack Execution:**
1. Malicious miner monitors for `NextRound` blocks
2. During the gap (before new round start time), they submit tiny blocks via `UpdateTinyBlockInformation` [10](#0-9) 
3. Blocks pass validation because `PreCheck()` only verifies miner list membership [11](#0-10) 
4. With 17 miners (typical configuration [12](#0-11) ), this enables 136 spam blocks per round transition

## Impact Explanation

**Consensus Integrity Violation**: The AEDPoS consensus mechanism is designed to have deterministic block production schedules where only the `ExtraBlockProducerOfPreviousRound` should produce blocks during the transition gap. This vulnerability breaks this fundamental consensus rule, allowing any miner to produce blocks out of turn.

**Unfair Reward Distribution**: Malicious miners earn extra block rewards for spam blocks. The initial mining reward is defined in the contract constants. [13](#0-12)  Each spam block increments the miner's produced block count, [14](#0-13)  affecting reward distributions.

**Transaction Fee Capture**: Each tiny block can include transactions and claim their fees, giving attackers unfair advantage in fee collection versus honest miners.

**Network Performance Degradation**: Block propagation, validation, and storage are stressed by excessive block production during gaps, potentially causing legitimate blocks to be delayed or rejected.

## Likelihood Explanation

**Highly Likely**: 
- Entry points are publicly accessible consensus methods
- Precondition (being an elected miner) is a normal operational state, not a high barrier
- Round transitions occur automatically and frequently (potentially thousands of times daily)
- Attack complexity is low - simply monitor for round transitions and submit blocks
- Economic incentive is high - attackers earn extra rewards with minimal cost

The gap exists for the duration of one mining interval during every round transition, providing regular exploitation opportunities.

## Recommendation

Add identity verification to `TimeSlotValidationProvider.CheckMinerTimeSlot()` when validating blocks during the round transition gap:

```csharp
if (latestActualMiningTime < expectedMiningTime)
{
    // Verify sender is the ExtraBlockProducerOfPreviousRound during gap
    if (latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime() &&
        validationContext.BaseRound.ExtraBlockProducerOfPreviousRound != validationContext.SenderPubkey)
    {
        return false; // Only ExtraBlockProducerOfPreviousRound can produce during gap
    }
    return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
}
```

This aligns the validation logic with the intended behavior already implemented in `IsCurrentMiner()` and the consensus command generation logic.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task Test_MultipleMinersCanSpamTinyBlocksDuringGap()
{
    // Setup: Initialize AEDPoS contract with 3 miners for simplicity
    var miners = new[] { "miner1", "miner2", "miner3" };
    await InitializeConsensusAsync(miners);
    
    // Step 1: Advance to a point where NextRound will be called
    var currentRound = await GetCurrentRoundAsync();
    await ProduceBlocksUntilRoundEnd(currentRound);
    
    // Step 2: Miner1 produces NextRound block, creating the gap
    var nextRoundTime = TimestampHelper.GetUtcNow();
    await ProduceNextRoundBlock("miner1", nextRoundTime);
    
    // Step 3: Get the new round information
    var newRound = await GetCurrentRoundAsync();
    var roundStartTime = newRound.GetRoundStartTime();
    var extraBlockProducer = newRound.ExtraBlockProducerOfPreviousRound;
    
    // Step 4: Miner2 and Miner3 (NOT the ExtraBlockProducerOfPreviousRound) 
    // attempt to produce tiny blocks during the gap
    var gapTime = nextRoundTime.AddMilliseconds(1000); // Within gap
    Assert.True(gapTime < roundStartTime); // Verify we're in the gap
    
    // Miner2 produces tiny block (should fail but doesn't due to bug)
    var tinyBlockInput2 = new TinyBlockInput
    {
        ActualMiningTime = gapTime,
        RoundId = newRound.RoundId,
        ProducedBlocks = 1
    };
    
    var result2 = await ExecuteConsensusTransactionAsync("miner2", 
        nameof(AEDPoSContract.UpdateTinyBlockInformation), tinyBlockInput2);
    
    // BUG: This should fail if miner2 != ExtraBlockProducerOfPreviousRound
    // but it succeeds because TimeSlotValidationProvider doesn't check identity
    Assert.True(result2.Status == TransactionResultStatus.Mined); // VULNERABILITY: Passes when it shouldn't
    
    // Miner3 also produces tiny block
    var tinyBlockInput3 = new TinyBlockInput
    {
        ActualMiningTime = gapTime.AddMilliseconds(500),
        RoundId = newRound.RoundId,
        ProducedBlocks = 1
    };
    
    var result3 = await ExecuteConsensusTransactionAsync("miner3",
        nameof(AEDPoSContract.UpdateTinyBlockInformation), tinyBlockInput3);
    
    // VULNERABILITY: Multiple non-designated miners can produce during gap
    Assert.True(result3.Status == TransactionResultStatus.Mined);
    
    // Verify both miners got rewards they shouldn't have
    var roundAfter = await GetCurrentRoundAsync();
    Assert.True(roundAfter.RealTimeMinersInformation["miner2"].ProducedBlocks > 0);
    Assert.True(roundAfter.RealTimeMinersInformation["miner3"].ProducedBlocks > 0);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L33-33)
```csharp
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L105-108)
```csharp
    public Timestamp GetRoundStartTime()
    {
        return FirstMiner().ExpectedMiningTime;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L46-48)
```csharp
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L108-112)
```csharp
    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L304-306)
```csharp
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```
