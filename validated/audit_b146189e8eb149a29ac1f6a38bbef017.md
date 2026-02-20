# Audit Report

## Title
Round 1 ActualMiningTime Manipulation Allows Consensus Time Slot Bypass

## Summary
The first miner in Round 1 can manipulate consensus timing by providing a fabricated `ActualMiningTime` in their `UpdateValue` transaction that differs from the block header's `Context.CurrentBlockTime`. This manipulation bypasses validation and corrupts the blockchain start timestamp, affecting all subsequent miners' time slot calculations and enabling out-of-order block production.

## Finding Description

The AEDPoS consensus contract maintains two separate, unvalidated sources for `ActualMiningTime`:

**1. Block Header ActualMiningTime**: Set to `Context.CurrentBlockTime` during consensus extra data creation [1](#0-0) 

**2. Transaction ActualMiningTime**: Provided in `UpdateValueInput` and directly stored to state without validation [2](#0-1) 

The `UpdateValue` method is public and accessible to all miners [3](#0-2) 

**Critical Validation Gaps:**

**Gap 1**: Time slot validation is explicitly bypassed for Round 1, returning `true` immediately [4](#0-3) 

**Gap 2**: `ActualMiningTimes` are cleared before hash calculation, preventing post-execution integrity validation from detecting the discrepancy [5](#0-4) 

**Gap 3**: No validation exists comparing transaction `ActualMiningTime` to header `Context.CurrentBlockTime` [6](#0-5) 

**Attack Propagation:**

For Round 1, `IsTimeSlotPassed()` relies exclusively on the first miner's stored `ActualMiningTimes` to calculate which mining orders should be active [7](#0-6) 

This timing is used by `ConsensusBehaviourProviderBase` to determine consensus behavior [8](#0-7) [9](#0-8) 

Most critically, the blockchain start timestamp is permanently set from the first miner's manipulated `ActualMiningTimes` [10](#0-9) 

## Impact Explanation

**HIGH Severity - Consensus Integrity Violation**

This vulnerability breaks fundamental consensus invariants:

1. **Premature Time Slot Activation**: Setting `ActualMiningTime` 300 seconds earlier inflates the `expectedOrder` calculation, causing higher-order miners to believe their time slots have passed prematurely and produce blocks out of sequence.

2. **Blockchain Start Timestamp Corruption**: The blockchain start timestamp determines all term timing. Its manipulation affects every subsequent term's schedule and transition logic.

3. **Delayed Time Slot Activation**: Conversely, setting a later timestamp prevents legitimate miners from recognizing their turns, causing missed blocks and availability degradation.

The impact extends beyond Round 1 - the corrupted blockchain start timestamp affects the entire chain's consensus timing for all future terms.

## Likelihood Explanation

**HIGH Likelihood**

**Attacker Requirements:**
- Must be first miner (Order == 1) in Round 1 of any term
- Requires only standard miner permissions

**Attack Complexity:** LOW
1. Generate block header with legitimate consensus extra data containing correct `Context.CurrentBlockTime`
2. Manually craft `UpdateValue` transaction with arbitrary `ActualMiningTime` (e.g., `Context.CurrentBlockTime - 300 seconds`)
3. Include crafted transaction in block

**No Protections Exist:**
- Round 1 time slot validation explicitly bypassed
- No validation that transaction `ActualMiningTime` matches header timestamp
- `ActualMiningTimes` excluded from hash-based post-execution validation
- Public `UpdateValue` entry point accessible to all miners with no additional constraints beyond miner list membership

**Attack Surface:** Every term initialization (Round 1 of each term) presents an opportunity.

## Recommendation

Add validation in `ValidateBeforeExecution` to verify that the `ActualMiningTime` recovered from the block header extra data matches the expected current block time for the miner producing the block. Additionally, validate that the transaction's `ActualMiningTime` matches the header's value during `UpdateValueValidationProvider`:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation
private bool ValidateActualMiningTime(ConsensusValidationContext validationContext)
{
    var headerMinerInfo = validationContext.ProvidedRound
        .RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // Verify ActualMiningTime in header matches Context.CurrentBlockTime
    if (headerMinerInfo.ActualMiningTimes.Any())
    {
        var headerTime = headerMinerInfo.ActualMiningTimes.Last();
        // The header time should reasonably match the current block time
        // (allow small tolerance for block production time)
        var tolerance = new Duration { Seconds = 5 };
        if (Math.Abs((headerTime - validationContext.CurrentBlockTime).Seconds) > tolerance.Seconds)
            return false;
    }
    
    return true;
}
```

Additionally, include `ActualMiningTimes` in the hash calculation for Round 1 to enable post-execution validation to detect discrepancies.

## Proof of Concept

A valid proof of concept would require a full test environment setup demonstrating:

1. Miner in Round 1, Order == 1 position
2. Generation of block header with correct `Context.CurrentBlockTime` in `ActualMiningTimes`
3. Manual crafting of `UpdateValue` transaction with `ActualMiningTime` set to `Context.CurrentBlockTime - 300 seconds`
4. Successful block execution with manipulated timestamp stored to state
5. Verification that blockchain start timestamp is set to manipulated value
6. Demonstration that subsequent miner's `IsTimeSlotPassed` calculations return incorrect results based on manipulated timestamp

The vulnerability's validity is confirmed by code analysis showing the validation gap and direct state storage without cross-validation between header and transaction timestamps.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L117-123)
```csharp
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L39-39)
```csharp
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L92-98)
```csharp
        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;

        var actualStartTime = actualStartTimes.First();
        var runningTime = currentBlockTime - actualStartTime;
        var expectedOrder = runningTime.Seconds.Div(miningInterval.Div(1000)).Add(1);
        return minerInRound.Order < expectedOrder;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-193)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L35-35)
```csharp
            _isTimeSlotPassed = CurrentRound.IsTimeSlotPassed(_pubkey, _currentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-62)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```
