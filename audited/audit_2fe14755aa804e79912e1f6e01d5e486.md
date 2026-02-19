### Title
Unvalidated SupposedOrderOfNextRound Causes Consensus Failure in Next Round Generation

### Summary
The `ExtractInformationToUpdateConsensus()` function includes `SupposedOrderOfNextRound` without validation, and `ProcessUpdateValue()` accepts this value directly from user input. A malicious miner can set this field to invalid values (0, negative, or exceeding miner count), causing next round generation to fail with exceptions when expected order positions cannot be found, resulting in consensus disruption.

### Finding Description

**Vulnerable Code Locations:**

1. **Extraction without validation:** [1](#0-0) 

The `SupposedOrderOfNextRound` is extracted directly from miner information and included in `UpdateValueInput` without any validation.

2. **Processing without validation:** [2](#0-1) 

The `ProcessUpdateValue()` method sets both `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` directly from the unvalidated input.

**Root Cause:**

The normal flow correctly calculates `SupposedOrderOfNextRound` using the formula `GetAbsModulus(sigNum, minersCount) + 1`, ensuring values are in range [1, minersCount]: [3](#0-2) 

However, the validation system does not verify that submitted `UpdateValueInput` contains correctly calculated values. The `UpdateValueValidationProvider` only checks that `OutValue` and `Signature` are filled and `PreviousInValue` is correct: [4](#0-3) 

**Why Protections Fail:**

During next round generation, invalid order values cause critical failures:

1. **When SupposedOrderOfNextRound = 0:** The miner is excluded from miners who mined: [5](#0-4) 

2. **When SupposedOrderOfNextRound is out of range:** The `BreakContinuousMining()` function expects specific order values to exist and throws exceptions when they don't: [6](#0-5) 

This code uses `First()` which throws "Sequence contains no matching element" if no miner has Order == 1 or Order == 2.

### Impact Explanation

**Consensus Integrity Failure:**
- Invalid `SupposedOrderOfNextRound` values break the next round generation process
- When no miner has the expected order positions (1, 2, minersCount, minersCount-1), `First()` calls in `BreakContinuousMining()` throw exceptions
- This prevents the consensus system from transitioning to the next round, halting block production

**Operational Impact:**
- Complete DoS of the consensus mechanism at round boundaries
- Chain halts until manual intervention or restart with recovered state
- Affects all network participants as no new blocks can be produced

**Who Is Affected:**
- All validators and users of the blockchain
- Network availability and liveness compromised

**Severity Justification:**
Medium-to-High severity because while it requires miner-level access, it causes complete consensus failure with minimal attacker cost. The attack is deterministic and guaranteed to succeed once triggered.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an active miner with block production rights
- This is a significant requirement but miners are the attack surface for consensus manipulation
- Malicious miner can modify their node software to alter consensus transactions

**Attack Complexity:**
- Low complexity: Modify the `UpdateValue` transaction's `SupposedOrderOfNextRound` field before including it in the block
- The consensus system generates correct transactions via `GenerateConsensusTransactions()`: [7](#0-6) 

However, a malicious miner controls what transactions actually go into their block and can substitute modified versions.

**Feasibility Conditions:**
- Attacker needs to be selected as a block producer at least once
- No cryptographic signature verification prevents transaction modification
- Attack succeeds immediately when the modified block is accepted

**Detection Constraints:**
- Difficult to attribute to specific miner before consensus breaks
- Impact is immediate and obvious (consensus failure) but root cause requires investigation

**Probability:**
Moderate-to-high given that any miner can execute this attack with modified client software.

### Recommendation

**Immediate Fix:**

Add validation in `ProcessUpdateValue()` to verify `SupposedOrderOfNextRound` is correctly calculated:

```csharp
// In ProcessUpdateValue, after line 245:
var minersCount = currentRound.RealTimeMinersInformation.Count;
var signature = updateValueInput.Signature;
var expectedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1;
Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
    "Invalid SupposedOrderOfNextRound value.");
Assert(updateValueInput.SupposedOrderOfNextRound > 0 && 
    updateValueInput.SupposedOrderOfNextRound <= minersCount,
    "SupposedOrderOfNextRound must be in range [1, minersCount].");
```

**Alternative Fix:**

Add a validation provider specifically for `SupposedOrderOfNextRound` in `UpdateValueValidationProvider`:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var minerInRound = extraData.Round.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
    var signature = minerInRound.Signature;
    var expectedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder &&
           minerInRound.SupposedOrderOfNextRound > 0 &&
           minerInRound.SupposedOrderOfNextRound <= minersCount;
}
```

**Test Cases:**

1. Test UpdateValue with SupposedOrderOfNextRound = 0 → should be rejected
2. Test UpdateValue with SupposedOrderOfNextRound = -5 → should be rejected  
3. Test UpdateValue with SupposedOrderOfNextRound = minersCount + 10 → should be rejected
4. Test UpdateValue with correctly calculated SupposedOrderOfNextRound → should succeed
5. Test that next round generation works correctly after fix

### Proof of Concept

**Required Initial State:**
- AEDPoS consensus is active with N miners (e.g., 7 miners)
- Current round in progress with at least one block produced
- Attacker is an active miner with block production rights

**Attack Steps:**

1. Attacker's turn to produce a block arrives
2. Attacker's node calls `GenerateConsensusTransactions()` which generates correct `UpdateValueInput` with `SupposedOrderOfNextRound` calculated as `GetAbsModulus(signature, 7) + 1` (e.g., value = 3)
3. Attacker modifies the transaction before including it in block, changing `SupposedOrderOfNextRound` to invalid value (e.g., 0 or 100)
4. Attacker produces block with modified transaction
5. Block is validated:
   - `ValidateConsensusBeforeExecution()` passes (no validation of SupposedOrderOfNextRound)
   - `UpdateValue` executes successfully, setting invalid value in state
   - `ValidateConsensusAfterExecution()` passes (hash comparison succeeds because both sides have same invalid value)
6. Current round completes with attacker's miner having invalid `SupposedOrderOfNextRound` in state
7. Next block producer attempts to generate next round:
   - Calls `GenerateNextRoundInformation()`
   - If attacker set value to 0: Attacker incorrectly excluded from `GetMinedMiners()`, treated as missed slot
   - If attacker set value to 100: `BreakContinuousMining()` calls `First(i => i.Order == 1)` but no miner has order 1 (attacker has 100)
   - Exception thrown: "Sequence contains no matching element"
8. Round transition fails, consensus halts

**Expected vs Actual Result:**
- Expected: UpdateValue transaction with invalid SupposedOrderOfNextRound should be rejected
- Actual: Transaction accepted, invalid value persisted, next round generation fails with exception

**Success Condition:**
Consensus system unable to transition to next round, network halted.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L43-43)
```csharp
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-84)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-146)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
```
