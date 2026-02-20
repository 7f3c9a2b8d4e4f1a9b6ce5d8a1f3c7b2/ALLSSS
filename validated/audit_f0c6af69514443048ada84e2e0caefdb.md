# Audit Report

## Title
Missing Validation of Next Round Order Values Allows Consensus Manipulation

## Summary
The AEDPoS consensus contract accepts miner-provided `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` values without validating they match the cryptographically-derived calculation from signatures. Combined with broken validation logic that compares an object with itself, malicious miners can manipulate mining order to control block production scheduling.

## Finding Description

**Root Cause: Unvalidated Direct Assignment**

In `ProcessUpdateValue`, the consensus order values are directly assigned from miner-provided `UpdateValueInput` without any validation against the cryptographic calculation: [1](#0-0) 

Additionally, `TuneOrderInformation` allows a miner to arbitrarily modify `FinalOrderOfNextRound` for ANY miner in the round: [2](#0-1) 

**Expected Calculation Exists But Not Enforced**

The correct calculation for `SupposedOrderOfNextRound` exists in `ApplyNormalConsensusData`, which cryptographically derives it from the miner's signature hash: [3](#0-2) 

This calculation is used when generating block header extra data [4](#0-3)  but is never validated against values in `UpdateValueInput`.

**Broken Validation Logic**

The `ValidateConsensusAfterExecution` method attempts validation by recovering the header Round: [5](#0-4) 

However, `RecoverFromUpdateValue` modifies and returns the same state object (`this`): [6](#0-5) 

This causes `headerInformation.Round` and `currentRound` to reference the same object, making the hash comparison always succeed regardless of manipulation: [7](#0-6) 

The `UpdateValueValidationProvider` only validates that OutValue and Signature are filled, not the order values: [8](#0-7) 

**Direct Impact on Next Round**

The manipulated `FinalOrderOfNextRound` values directly determine mining order and time slots in `GenerateNextRoundInformation`: [9](#0-8) 

## Impact Explanation

**CRITICAL Consensus Integrity Breach**

A malicious miner can:
- Assign themselves `FinalOrderOfNextRound = 1` to mine first repeatedly
- Push competing miners to late positions (orders 7-10 in a 10-miner setup)
- Use `TuneOrderInformation` to manipulate multiple miners simultaneously
- Maintain mining advantage across consecutive rounds

**Concrete Harm:**
1. **Block Production Control**: Attacker determines `ExpectedMiningTime` for all miners, controlling when blocks are produced
2. **Revenue Manipulation**: First mining position provides MEV extraction opportunities and guaranteed block rewards
3. **Consensus Disruption**: Breaks fair round-robin scheduling, causing honest miners to miss designated time slots
4. **Network Integrity**: Violates the fundamental AEDPoS invariant that mining order must be deterministically derived from cryptographic randomness

This directly compromises the "miner schedule integrity" guarantee that AEDPoS consensus relies upon for security.

## Likelihood Explanation

**HIGH Likelihood**

**Attacker Requirements:**
- Must be an active miner in current round (normal participation, no special privileges needed)
- No governance control or majority stake required

**Attack Steps:**
1. When producing a block, manipulate consensus extra data before including in block header
2. Set own `SupposedOrderOfNextRound` to 1 (or desired position)
3. Optionally include `TuneOrderInformation` to disrupt other miners' positions
4. Block passes validation due to broken `ValidateConsensusAfterExecution` logic
5. `ProcessUpdateValue` persists manipulated values to state
6. Next round uses these values for mining schedule via `GenerateNextRoundInformation`

**Execution Practicality:**

Entry point is the consensus-required `UpdateValue` method called during normal block production: [10](#0-9) 

The only check is that the sender must be in the miner list: [11](#0-10) 

**Detection Difficulty:**
- Validation passes successfully (broken comparison logic)
- Order values appear legitimate (integers 1-N within valid range)
- No events flag the manipulation
- Only detectable by analyzing next round's mining schedule discrepancies

**Economic Rationality:**
Attack cost is minimal (standard transaction fees). Benefit is immediate and persistent (preferential mining position). Risk/reward strongly favors exploitation.

## Recommendation

1. **Validate Order Calculations**: In `ProcessUpdateValue`, recalculate `SupposedOrderOfNextRound` from the provided signature and verify it matches the input value:

```csharp
// Calculate expected order from signature
var sigNum = updateValueInput.Signature.ToInt64();
var minersCount = currentRound.RealTimeMinersInformation.Count;
var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;

// Validate provided order matches calculation
Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
    "Invalid SupposedOrderOfNextRound: does not match signature-derived value");
```

2. **Fix Broken Validation**: Modify `RecoverFromUpdateValue` to return a new Round object instead of `this`, or change `ValidateConsensusAfterExecution` to create a deep copy before recovery:

```csharp
public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
{
    // Create a new Round object to avoid self-comparison
    var recovered = this.Clone();
    // ... perform recovery on 'recovered'
    return recovered;
}
```

3. **Restrict TuneOrderInformation**: Add validation that miners can only tune orders that actually have conflicts (where multiple miners would have the same `SupposedOrderOfNextRound`).

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanManipulateMiningOrder()
{
    // Setup: Initialize consensus with 5 miners
    var miners = GenerateMiners(5);
    await InitializeConsensus(miners);
    
    // Attacker is miner[0], wants to always mine first
    var attacker = miners[0];
    
    // Normal flow: attacker produces block with manipulated order
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateOutValue(attacker),
        Signature = GenerateSignature(attacker),
        SupposedOrderOfNextRound = 1, // Force first position
        TuneOrderInformation = 
        {
            { miners[1].PublicKey, 5 }, // Push competitor to last
            { miners[2].PublicKey, 4 }
        },
        // ... other required fields
    };
    
    // Execute UpdateValue
    await attacker.SendTransactionAsync(ConsensusContract.UpdateValue, maliciousInput);
    
    // Verify: Next round is generated with manipulated order
    var nextRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Assert: Attacker is first, competitors pushed back
    Assert.Equal(1, nextRound.RealTimeMinersInformation[attacker.PublicKey].Order);
    Assert.Equal(5, nextRound.RealTimeMinersInformation[miners[1].PublicKey].Order);
    Assert.Equal(4, nextRound.RealTimeMinersInformation[miners[2].PublicKey].Order);
}
```

## Notes

The vulnerability is rooted in the architectural assumption that consensus extra data generated by honest miners would always contain correctly calculated order values. However, the public `UpdateValue` entry point allows any miner to provide arbitrary values, and the validation mechanisms fail to enforce the cryptographic derivation requirement. The broken self-comparison in `ValidateConsensusAfterExecution` effectively disables the only validation point where order manipulation could be detected. This represents a fundamental break in the AEDPoS consensus security model.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L29-32)
```csharp
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
