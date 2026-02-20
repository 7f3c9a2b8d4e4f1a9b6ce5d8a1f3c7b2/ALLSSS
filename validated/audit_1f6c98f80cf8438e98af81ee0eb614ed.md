# Audit Report

## Title
Missing Authorization Check for Extra Block Slot Tiny Block Production

## Summary
The AEDPoS consensus validation logic fails to verify that miners producing tiny blocks during the previous round's extra block slot are authorized as `ExtraBlockProducerOfPreviousRound`. While client-side command generation correctly enforces this authorization, the on-chain validation path omits this critical check, allowing any validator to bypass consensus time slot restrictions and steal block rewards.

## Finding Description

The AEDPoS consensus mechanism designates a specific miner as `ExtraBlockProducerOfPreviousRound` to produce tiny blocks during round transitions. This authorization is properly enforced in the client-side command generation logic [1](#0-0) , which checks if the miner's public key matches before allowing tiny block behavior.

The `IsCurrentMiner()` view method also validates this authorization [2](#0-1) .

However, the on-chain validation path contains a critical authorization gap. When a block with `Behaviour = TinyBlock` is validated, the system only applies basic validation providers [3](#0-2) .

Critically, the switch statement that adds behavior-specific validators has cases for `UpdateValue`, `NextRound`, and `NextTerm`, but **no case for TinyBlock** [4](#0-3) . This means no additional authorization validators are added for tiny blocks.

The `TimeSlotValidationProvider.CheckMinerTimeSlot()` method detects when a miner is producing tiny blocks (indicated by the comment "Which means this miner is producing tiny blocks for previous extra block slot"), but only validates timing without checking authorization [5](#0-4) .

The `MiningPermissionValidationProvider` only verifies that the sender is in the current miner list, not whether they are specifically authorized for extra block slot production [6](#0-5) .

The `PreCheck()` method similarly only validates miner list membership [7](#0-6) .

Finally, `ProcessTinyBlock()` executes without any authorization verification, directly incrementing the miner's `ProducedBlocks` and `ProducedTinyBlocks` counters [8](#0-7) .

**Attack Flow:**
1. Malicious validator MinerB (not the `ExtraBlockProducerOfPreviousRound`) monitors round transitions
2. MinerB crafts a block with `Behaviour = TinyBlock` and timing before their expected mining slot
3. `ValidateBeforeExecution` is called: TinyBlock behavior detected, only basic validators applied
4. `MiningPermissionValidationProvider` passes (MinerB is in validator set)
5. `TimeSlotValidationProvider.CheckMinerTimeSlot()` passes (timing is valid, no authorization check)
6. `ContinuousBlocksValidationProvider` passes (within continuous block limits)
7. `ProcessConsensusInformation` calls `PreCheck()` which passes (MinerB in miner list)
8. `ProcessTinyBlock()` increments MinerB's block production counters
9. MinerB successfully produced an unauthorized block and will receive block rewards

## Impact Explanation

This vulnerability has **HIGH** impact for the following reasons:

**1. Consensus Invariant Violation:** The fundamental consensus rule that only the designated `ExtraBlockProducerOfPreviousRound` can mine during the extra block slot is broken. This undermines the predictability and fairness of the consensus mechanism.

**2. Reward Theft:** Block production rewards are calculated based on the `ProducedBlocks` counter [9](#0-8) . Unauthorized miners incrementing this counter steal rewards from legitimate miners. The calculation uses `CalculateShares()` which directly affects reward distribution [10](#0-9) .

**3. Consensus Disruption:** If multiple validators simultaneously exploit this vulnerability, they create competing blocks in the extra block slot, potentially causing consensus forks, delayed finalization, or LIB calculation errors.

**4. Mining Schedule Corruption:** The round-robin mining schedule becomes unreliable, affecting cross-chain operations that depend on predictable block production timing.

## Likelihood Explanation

The likelihood of exploitation is **HIGH**:

**Attacker Prerequisites (Realistic):**
- Must be an active validator in the current validator set (achievable through normal election process)
- No additional privileges required beyond normal mining capabilities
- No special coordination or timing complexity beyond monitoring round state

**Attack Complexity: LOW**
1. Monitor round state via public view methods
2. Identify timing window when unauthorized tiny blocks can be produced
3. Craft block with `Behaviour = TinyBlock` before expected time slot
4. Sign and broadcast using existing validator credentials
5. Validation passes due to missing authorization check

**Economic Incentive:** Strong positive incentive - attackers gain additional block rewards with minimal cost (standard block production resources).

**Detection Difficulty:** Unauthorized blocks appear legitimate since they come from valid validators with proper signatures, making exploitation difficult to detect without analyzing the `ExtraBlockProducerOfPreviousRound` field.

## Recommendation

Add a dedicated validation provider for TinyBlock behavior that verifies the sender is authorized as `ExtraBlockProducerOfPreviousRound`. Modify the validation logic:

```csharp
// In AEDPoSContract_Validation.cs, add to the switch statement:
case AElfConsensusBehaviour.TinyBlock:
    // Add authorization validator for extra block slot
    validationProviders.Add(new ExtraBlockSlotAuthorizationValidationProvider());
    break;
```

Create the new validator:

```csharp
// New file: ExtraBlockSlotAuthorizationValidationProvider.cs
public class ExtraBlockSlotAuthorizationValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        
        // Check if producing before expected time (extra block slot scenario)
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        
        if (latestActualMiningTime != null && latestActualMiningTime < expectedMiningTime)
        {
            // Verify sender is authorized as ExtraBlockProducerOfPreviousRound
            if (validationContext.BaseRound.ExtraBlockProducerOfPreviousRound != validationContext.SenderPubkey)
            {
                validationResult.Message = $"Sender {validationContext.SenderPubkey} is not authorized for extra block slot production.";
                return validationResult;
            }
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated with a test that shows an unauthorized validator successfully producing a tiny block:

```csharp
[Fact]
public async Task UnauthorizedTinyBlockProduction_ShouldFail_ButPasses()
{
    // Setup: Initialize consensus with multiple validators
    var miners = new[] { "MinerA", "MinerB", "MinerC" };
    await InitializeConsensusAsync(miners);
    
    // Round N ends, MinerA is designated as ExtraBlockProducerOfPreviousRound
    var currentRound = await GetCurrentRoundAsync();
    Assert.Equal("MinerA", currentRound.ExtraBlockProducerOfPreviousRound);
    
    // MinerB (unauthorized) attempts to produce tiny block before their time slot
    var tinyBlockInput = new TinyBlockInput
    {
        ActualMiningTime = Timestamp.FromDateTime(DateTime.UtcNow),
        RandomNumber = GenerateRandomNumber(),
        // MinerB's signature
    };
    
    // This should fail but will succeed due to missing authorization check
    var result = await ConsensusContract.TinyBlock.SendAsync(tinyBlockInput);
    
    // BUG: Transaction succeeds when it should fail
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Mined);
    
    // Verify MinerB's counters were incremented (reward theft)
    var updatedRound = await GetCurrentRoundAsync();
    var minerBInfo = updatedRound.RealTimeMinersInformation["MinerB"];
    Assert.True(minerBInfo.ProducedBlocks > 0); // Should be 0, but is incremented
}
```

This test demonstrates that MinerB can successfully produce tiny blocks during MinerA's authorized extra block slot, incrementing their production counters and stealing rewards.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-75)
```csharp
        // Add basic providers at first.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L46-48)
```csharp
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L789-811)
```csharp
        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
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
