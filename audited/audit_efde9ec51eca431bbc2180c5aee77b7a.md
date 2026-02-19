# Audit Report

## Title
Unvalidated TuneOrderInformation Allows Arbitrary Order Manipulation Breaking Consensus Timing and Continuous Mining Prevention

## Summary
The `ProcessUpdateValue` function in the AEDPoS consensus contract accepts arbitrary `FinalOrderOfNextRound` values through the `TuneOrderInformation` field without validating they fall within the valid range [1, minersCount]. This allows any active miner to manipulate mining orders, breaking consensus timing calculations, bypassing continuous mining prevention, and violating order uniqueness invariants that are fundamental to the AEDPoS consensus mechanism.

## Finding Description

**Root Cause:**

The vulnerability exists in `ProcessUpdateValue` where `TuneOrderInformation` values from user input are directly applied to miners' `FinalOrderOfNextRound` without any range or validity checks: [1](#0-0) 

The `UpdateValueInput` message structure defines `TuneOrderInformation` as a simple map accepting any int32 values: [2](#0-1) 

**Why Existing Protections Fail:**

1. **UpdateValueValidationProvider** only validates cryptographic fields (OutValue, Signature, PreviousInValue) but completely ignores `TuneOrderInformation`: [3](#0-2) 

2. **NextRoundMiningOrderValidationProvider** is only applied for `NextRound` behavior, NOT for `UpdateValue`: [4](#0-3) 

3. Even if it were applied, `NextRoundMiningOrderValidationProvider` only checks distinct count, not that orders are within valid range: [5](#0-4) 

**Execution Path:**

When `GenerateNextRoundInformation` processes the manipulated `FinalOrderOfNextRound` values, it directly orders miners by these values and uses them for timing calculations: [6](#0-5) 

The invalid order values (e.g., 1000) are multiplied by `miningInterval` to calculate `ExpectedMiningTime`, pushing mining slots far into the future and breaking the consensus schedule.

## Impact Explanation

**Concrete Harms:**

1. **Consensus Timing Manipulation**: The `ExpectedMiningTime` calculation directly multiplies order by miningInterval. An order of 1000 instead of a valid order (e.g., 1-10 for 10 miners) pushes the miner's time slot 100x further into the future than intended, completely breaking the round timing mechanism: [7](#0-6) 

2. **BreakContinuousMining Bypass**: The `BreakContinuousMining` function looks for `lastMinerOfNextRound` with `Order == minersCount`. When no miner has this order (because one has an invalid order like 1000), it returns null and exits early without performing the swap, allowing the same miner to produce both the last block and extra block consecutively: [8](#0-7) 

3. **Order Uniqueness Violation**: Multiple miners can be assigned identical orders through crafted `TuneOrderInformation`, violating the fundamental invariant that each miner has a unique sequential order in [1, minersCount].

4. **Extra Block Producer Selection**: The extra block calculation relies on order values, and invalid orders corrupt this selection mechanism.

**Severity**: HIGH - Breaks critical consensus invariants including miner schedule integrity, time-slot validation, and continuous mining prevention, enabling consensus disruption and potential chain stalling.

## Likelihood Explanation

**Attacker Capabilities**: Any active miner in the current round can execute this attack. The `UpdateValue` method is a public RPC accessible during the miner's designated time slot: [9](#0-8) 

The only access control is `PreCheck()` which validates the sender is in the miner list: [10](#0-9) 

**Attack Complexity**: LOW - The attacker simply crafts an `UpdateValueInput` with malicious `TuneOrderInformation` values and calls `UpdateValue`. No special privileges beyond being an active miner are required.

**Feasibility**: HIGH - Miners regularly call `UpdateValue` during normal operation. While the honest flow uses `ExtractInformationToUpdateConsensus` to build the input, there is no enforcement that miners must use this method. They can construct their own `UpdateValueInput` with arbitrary `TuneOrderInformation` values.

**Detection**: Difficult to detect proactively as the malicious transaction appears valid to all existing validation providers and would only be noticed when the next round generates with corrupted timing.

## Recommendation

Add validation in `ProcessUpdateValue` to ensure all `TuneOrderInformation` values are within the valid range:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate TuneOrderInformation before applying
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
            $"Invalid order {tuneOrder.Value} for miner {tuneOrder.Key}. Must be in range [1, {minersCount}].");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            $"Miner {tuneOrder.Key} not in current round.");
    }
    
    // Rest of existing code...
}
```

Additionally, consider enforcing uniqueness of the tuned orders to prevent duplicate order assignments.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a consensus round with 5 miners
2. Have an active miner call `UpdateValue` with crafted `UpdateValueInput` containing `TuneOrderInformation` with invalid order values (e.g., setting their own order to 1000)
3. Trigger `GenerateNextRoundInformation` 
4. Verify that:
   - The invalid order (1000) is assigned in the next round
   - `ExpectedMiningTime` for that miner is calculated as `currentTime + (1000 * miningInterval)`
   - `BreakContinuousMining` returns early without performing necessary swaps when searching for miner with `Order == 5`

The test would confirm that no validation prevents the invalid order assignment and that it corrupts the consensus timing and continuous mining prevention mechanisms.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-88)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L93-95)
```csharp
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
