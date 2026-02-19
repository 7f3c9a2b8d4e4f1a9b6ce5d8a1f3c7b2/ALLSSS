# Audit Report

## Title
Insufficient Validation of ProducedBlocks in NextRound Allows Mining Reward Inflation

## Summary
The consensus contract's `NextRound` transaction processing accepts and stores `ProducedBlocks` values from miner-submitted input without validating them against the current round state. A malicious miner can inflate these values to multiply mining rewards, causing token supply inflation and corrupted election statistics.

## Finding Description
The vulnerability exists in the asymmetric treatment of `ProducedBlocks` validation between different consensus behaviors.

For `UpdateValue` transactions, the contract explicitly protects against manipulation by loading the current state and incrementing by 1, ignoring any submitted values: [1](#0-0) 

However, for `NextRound` transactions, the `ProcessNextRound` method accepts the input and stores it directly without validating the `ProducedBlocks` values: [2](#0-1) 

The `NextRoundInput` is converted to a `Round` object and stored via `AddRoundInformation` without any validation that the `ProducedBlocks` values match what they should be based on the current round state.

The validation system for NextRound only checks structural properties: [3](#0-2) 

Critically, there is NO validation that reconstructs the expected `ProducedBlocks` values and compares them against the submitted input.

While honest nodes generate next round information by copying `ProducedBlocks` from the current state: [4](#0-3) 

The contract does not enforce this invariant during validation. A malicious miner can modify their node to inflate these values before submitting the NextRound transaction.

## Impact Explanation
The inflated `ProducedBlocks` values directly impact mining reward calculations. During term changes, the `DonateMiningReward` method calculates total rewards by summing all miners' `ProducedBlocks` values: [5](#0-4) 

This sum is then multiplied by the reward per block: [6](#0-5) 

An attacker inflating `ProducedBlocks` values (e.g., doubling all counts from [10, 15, 12] to [20, 30, 24]) would double the mining rewards donated to Treasury (from 37 to 74 blocks worth), causing significant token supply inflation over multiple terms.

Additionally, these inflated values are sent to the Election contract for candidate statistics: [7](#0-6) 

This corrupts governance metrics and impacts future reward distributions based on production history.

## Likelihood Explanation
**Attacker Capabilities:** Any miner who produces a block triggering NextRound behavior. This occurs naturally at the end of each round when the extra block producer mines.

**Attack Complexity:** Moderate. The attacker must:
1. Run a modified node that alters the consensus extra data generation logic
2. Inflate `ProducedBlocks` values in the generated `NextRoundInput`
3. Produce a block at the appropriate time slot to trigger NextRound

**Feasibility:** High. Miners regularly produce NextRound blocks as part of normal consensus operation. The validation system checks only structural properties (round number incrementation, InValue nullity, mining order) but does NOT reconstruct and compare the expected `ProducedBlocks` values from current state.

**Detection:** Difficult. The manipulation occurs within consensus data that legitimately varies between rounds. Without explicit validation comparing submitted values against state-derived expectations, other nodes cannot detect the inflation during block validation.

## Recommendation
Add validation to `ProcessNextRound` or the NextRound validation providers that:

1. Loads the current round from state
2. Reconstructs expected `ProducedBlocks` values for each miner (copying from current state, with +1 for the current miner)
3. Compares the expected values against the submitted `NextRoundInput.RealTimeMinersInformation[].ProducedBlocks`
4. Rejects the transaction if values don't match

Example implementation approach:
```csharp
// In ProcessNextRound or a new validation provider
TryToGetCurrentRoundInformation(out var currentRound);
var expectedRound = new Round();
currentRound.GenerateNextRoundInformation(Context.CurrentBlockTime, 
    GetBlockchainStartTimestamp(), out expectedRound);

// Increment for current miner
expectedRound.RealTimeMinersInformation[_processingBlockMinerPubkey].ProducedBlocks =
    expectedRound.RealTimeMinersInformation[_processingBlockMinerPubkey].ProducedBlocks.Add(1);

// Validate all ProducedBlocks match
foreach (var miner in nextRound.RealTimeMinersInformation)
{
    Assert(miner.Value.ProducedBlocks == 
        expectedRound.RealTimeMinersInformation[miner.Key].ProducedBlocks,
        "Invalid ProducedBlocks count");
}
```

This mirrors the protection already in place for `UpdateValue` where the contract "does not use provided values" but instead recalculates from state.

## Proof of Concept
```csharp
// POC demonstrating the vulnerability
[Fact]
public async Task NextRound_InflatedProducedBlocks_AcceptsWithoutValidation()
{
    // Setup: Initialize consensus with miners
    await InitializeConsensusAsync();
    
    // Get current round - assume miners have legitimate ProducedBlocks = [10, 15, 12]
    var currentRound = await GetCurrentRoundAsync();
    var legitimateSum = currentRound.GetMinedBlocks(); // Returns 37
    
    // Attacker generates NextRound with inflated values [20, 30, 24]
    var maliciousNextRound = GenerateNextRoundWithInflatedProducedBlocks(currentRound, 2.0); // Double all values
    var inflatedSum = maliciousNextRound.GetMinedBlocks(); // Returns 74
    
    // Submit NextRound transaction
    var result = await ConsensusContract.NextRound.SendAsync(maliciousNextRound);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // PASSES - no validation!
    
    // Verify inflated values were stored
    var storedRound = await GetCurrentRoundAsync();
    storedRound.GetMinedBlocks().ShouldBe(inflatedSum); // Inflated values are now in state
    
    // Later, during NextTerm, mining rewards will be calculated on inflated sum
    // This causes 2x token inflation: (74 * rewardPerBlock) instead of (37 * rewardPerBlock)
}
```

## Notes
The vulnerability stems from inconsistent validation philosophy: `UpdateValue` explicitly distrusts user input and recalculates from state (with comment "do not use provided values"), while `NextRound` trusts the entire submitted round data structure including the critical `ProducedBlocks` values that directly control reward calculations. This asymmetry creates an exploitable gap in the consensus validation system.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

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

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L250-252)
```csharp
        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L124-127)
```csharp
    public long GetMinedBlocks()
    {
        return RealTimeMinersInformation.Values.Sum(minerInRound => minerInRound.ProducedBlocks);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L37-50)
```csharp
    private void UpdateCurrentMinerInformationToElectionContract(Round previousRound)
    {
        State.ElectionContract.UpdateMultipleCandidateInformation.Send(new UpdateMultipleCandidateInformationInput
        {
            Value =
            {
                previousRound.RealTimeMinersInformation.Select(i => new UpdateCandidateInformationInput
                {
                    Pubkey = i.Key,
                    RecentlyProducedBlocks = i.Value.ProducedBlocks,
                    RecentlyMissedTimeSlots = i.Value.MissedTimeSlots
                })
            }
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L118-120)
```csharp
        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
```
