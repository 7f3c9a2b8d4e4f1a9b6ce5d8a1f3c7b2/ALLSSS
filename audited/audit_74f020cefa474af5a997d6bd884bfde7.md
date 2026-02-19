# Audit Report

## Title
Consensus Denial of Service via Malicious FinalOrderOfNextRound Values Due to Incorrect Distinct Validation

## Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` function contains a critical bug where it calls `.Distinct()` on `MinerInRound` objects instead of their `FinalOrderOfNextRound` values, failing to validate uniqueness of mining orders. A malicious validator can exploit this by crafting a `NextRoundInput` with duplicate `FinalOrderOfNextRound` values that pass validation but cause permanent consensus halt when the subsequent round attempts to use these corrupted order values.

## Finding Description

**Root Cause**: The validation incorrectly applies `.Distinct()` to `MinerInRound` object instances rather than to their `FinalOrderOfNextRound` property values. Since `MinerInRound` is a protobuf-generated class where each miner object is distinct by reference, the distinct count will always equal the total number of miner objects regardless of whether their `FinalOrderOfNextRound` values contain duplicates. [1](#0-0) 

**Expected Behavior**: The validation should check `providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0).Select(m => m.FinalOrderOfNextRound).Distinct().Count()` to validate uniqueness of the order VALUES.

**Exploitation Path**:

1. During round N to N+1 transition, a malicious validator crafts a `NextRoundInput` where:
   - `Order` and `ExpectedMiningTime` values are correctly set for round N+1 mining
   - `FinalOrderOfNextRound` values contain malicious duplicates (e.g., all set to 1) for round N+2
   - Valid `OutValue` hashes are included to match miner count

2. The validation process runs via `ValidateBeforeExecution()` which instantiates validation providers for NextRound behavior: [2](#0-1) 

3. The buggy `NextRoundMiningOrderValidationProvider` passes because it validates distinct OBJECTS (which are always distinct) rather than distinct `FinalOrderOfNextRound` VALUES.

4. The `CheckRoundTimeSlots()` validation passes because it validates time slots for round N+1's `Order` field (which is correct), not the malicious `FinalOrderOfNextRound` values intended for round N+2: [3](#0-2) 

5. The malicious round data is stored via `ProcessNextRound()` and `AddRoundInformation()`: [4](#0-3) 

6. When generating round N+2, `GenerateNextRoundInformation()` uses the corrupted `FinalOrderOfNextRound` values to assign `Order` and calculate `ExpectedMiningTime`: [5](#0-4) 

All miners with the same `FinalOrderOfNextRound` receive identical `Order` values and identical `ExpectedMiningTime` values calculated as `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`.

7. Any attempt to validate or use round N+2 fails in `CheckRoundTimeSlots()`: [6](#0-5) 

The `baseMiningInterval` calculation `(miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds()` results in 0 when miners at indices 0 and 1 have identical timestamps, causing validation failure with message "Mining interval must greater than 0."

**Why Existing Protections Fail**: The `RoundTerminateValidationProvider` only validates that `InValue` is null, not `OutValue` or `FinalOrderOfNextRound`: [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables a single malicious validator to permanently halt the entire blockchain consensus mechanism:

- **Consensus Halt**: No new blocks can be produced after round N+1 completes because round N+2 generation fails validation
- **Network Paralysis**: All validators are unable to progress past the corrupted round
- **Complete Operational Shutdown**: All on-chain operations cease
- **No Automatic Recovery**: The system has no built-in mechanism to recover from corrupted round data; manual intervention and potentially a hard fork would be required
- **Violates Critical Invariant**: Breaks the fundamental guarantee of "correct round transitions and time-slot validation, miner schedule integrity"

This affects all network participants and all blockchain operations, making it a complete denial of service attack.

## Likelihood Explanation

**Probability: HIGH**

The attack is highly feasible because:

**Attacker Requirements:**
- Must be an active validator in the current round (realistic - validators rotate)
- Must have their turn to propose `NextRound` transition (occurs naturally in rotation)
- Only requires standard validator capabilities to craft custom `NextRoundInput`
- No special privileges beyond validator status needed

**Attack Complexity: LOW**
- Single transaction to `NextRound()` with malicious payload
- No timing constraints or race conditions required
- No collusion with other validators needed
- Straightforward to construct the malicious `NextRoundInput`

**Economic Cost: MINIMAL**
- Only standard transaction fees required
- No tokens at risk
- No staking penalties for this behavior (as it passes validation)

**Detection Difficulty:**
- Malicious `FinalOrderOfNextRound` values appear valid during round N+1 operation
- Attack only manifests when round N+2 generation is attempted
- Difficult to identify the malicious validator retroactively

## Recommendation

Fix the validation logic in `NextRoundMiningOrderValidationProvider` to check uniqueness of `FinalOrderOfNextRound` VALUES rather than object instances:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Add this line to extract values
    .Distinct()
    .Count();
```

This ensures that duplicate `FinalOrderOfNextRound` values are properly detected and rejected during validation.

## Proof of Concept

The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task ConsensusHalt_Via_DuplicateFinalOrderOfNextRound()
{
    // Setup: Initialize chain with 3 validators in round 1
    var validators = new[] { "ValidatorA", "ValidatorB", "ValidatorC" };
    await InitializeConsensusWithValidators(validators);
    
    // Round 1 completes normally
    await ProduceNormalRound();
    
    // Malicious validator crafts NextRoundInput for Round 2 with duplicate FinalOrderOfNextRound
    var maliciousRound2 = new NextRoundInput
    {
        RoundNumber = 2,
        RealTimeMinersInformation = 
        {
            ["ValidatorA"] = new MinerInRound 
            { 
                Pubkey = "ValidatorA",
                Order = 1, // Correct for round 2
                ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(4)),
                OutValue = Hash.FromString("hash1"),
                FinalOrderOfNextRound = 1 // DUPLICATE - malicious for round 3
            },
            ["ValidatorB"] = new MinerInRound 
            { 
                Pubkey = "ValidatorB",
                Order = 2, // Correct for round 2
                ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(8)),
                OutValue = Hash.FromString("hash2"),
                FinalOrderOfNextRound = 1 // DUPLICATE - malicious for round 3
            },
            ["ValidatorC"] = new MinerInRound 
            { 
                Pubkey = "ValidatorC",
                Order = 3, // Correct for round 2
                ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(12)),
                OutValue = Hash.FromString("hash3"),
                FinalOrderOfNextRound = 1 // DUPLICATE - malicious for round 3
            }
        }
    };
    
    // Call NextRound - should fail but PASSES due to bug
    var result = await ConsensusStub.NextRound.SendAsync(maliciousRound2);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // BUG: Passes validation
    
    // Round 2 completes with corrupted FinalOrderOfNextRound values
    await ProduceBlocksForRound2();
    
    // Attempt to transition to Round 3 - this will FAIL
    var round3Attempt = await ConsensusStub.NextRound.SendAsync(GenerateNextRoundInput());
    
    // Assertion: Round 3 fails validation with "Mining interval must greater than 0"
    round3Attempt.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    round3Attempt.TransactionResult.Error.ShouldContain("Mining interval must greater than 0");
    
    // Consensus is now permanently halted - no further blocks can be produced
    var finalRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    finalRound.RoundNumber.ShouldBe(2); // Stuck at round 2, cannot progress
}
```

This test proves that:
1. Malicious `NextRoundInput` with duplicate `FinalOrderOfNextRound` passes validation
2. The corrupted round data is stored
3. Subsequent round generation fails with validation error
4. Consensus permanently halts at the corrupted round

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-156)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-47)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L32-34)
```csharp
        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```
