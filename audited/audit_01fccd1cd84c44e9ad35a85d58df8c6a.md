### Title
Missing Current OutValue Validation Enables Consensus Value Manipulation

### Summary
The `ValidatePreviousInValue()` function only validates that a miner's revealed `PreviousInValue` matches their previously published `OutValue`, but never validates that the current `OutValue` being published is correctly computed from the current `InValue`. This allows malicious miners to publish fraudulent `OutValue` and later provide fabricated `PreviousInValue` that matches, bypassing all validation checks and enabling mining order manipulation.

### Finding Description

The vulnerability exists in the consensus validation flow across multiple files:

**Root Cause - Missing Current Validation:**
The `ValidatePreviousInValue()` function only performs backward validation: [1](#0-0) 

This validation checks `Hash(PreviousInValue) == previousOutValue` (line 48), but there is no validation that the **current** `OutValue` being published equals `Hash(current InValue)`.

**Block Production - OutValue Computation:**
During block production, the current `OutValue` is correctly computed from `InValue`: [2](#0-1) 

However, the current `InValue` is **never published** in the block header - only `OutValue` is included. The current `InValue` only becomes `PreviousInValue` in the next round.

**Block Execution - Unchecked Assignment:**
When processing an UpdateValue block, the miner's provided `PreviousInValue` is accepted without cross-validation against reconstructed values: [3](#0-2) 

**Validation Bypass Points:**
The validation allows miners to skip providing `PreviousInValue`: [4](#0-3) 

Lines 42 and 46 allow `null` or `Hash.Empty` values to pass validation.

**Secret Sharing Reconstruction (Insufficient Mitigation):**
While secret sharing can reconstruct the real `InValue`, there is no enforcement comparing it with the miner's claimed value: [5](#0-4) 

Even when other miners set the correct `PreviousInValue` via `MinersPreviousInValues` (line 296), the attacker can overwrite it with their fabricated value (line 264 of the same file executes when they mine).

### Impact Explanation

**Consensus Integrity Compromise:**
- **Mining Order Manipulation**: The `Signature` field used to determine next-round mining order is calculated from `PreviousInValue`: [6](#0-5) 

By providing fraudulent `PreviousInValue`, attackers can manipulate their signature and influence their position in future rounds, potentially gaining favorable time slots.

- **Randomness Manipulation**: The consensus randomness mechanism relies on the integrity of `InValue`/`OutValue` chains. Manipulated values corrupt the random number generation used for miner selection and other consensus functions.

- **Reward Misallocation**: Favorable mining positions allow attackers to produce more blocks than they should, earning disproportionate mining rewards at the expense of honest miners. Over multiple rounds, this compounds to significant economic advantage.

**Severity Justification:**
This is a **HIGH** severity vulnerability because:
1. It violates the critical invariant "miner schedule integrity" 
2. Any miner can exploit it without requiring special privileges
3. Impact is direct and measurable (unfair block production/rewards)
4. Detection is difficult as fabricated values pass all validation checks

### Likelihood Explanation

**Attacker Capabilities:**
- Requires being an active consensus miner (feasible - miners are elected through staking)
- No special permissions or exploit of trusted roles needed
- Attack executable through normal consensus participation

**Attack Complexity:**
1. **Low Technical Barrier**: Attacker generates fake `OutValue_N ≠ Hash(InValue_N)` in round N
2. **Simple Execution**: In round N+1, provide fabricated `PreviousInValue_N'` where `Hash(PreviousInValue_N') == OutValue_N`
3. **Validation Bypass**: All checks pass because the hash relationship is satisfied by design

**Feasibility Conditions:**
- Miner must produce at least two blocks (one to publish fake `OutValue`, one to "validate" it)
- This is guaranteed in normal operation as miners produce multiple blocks per term
- No coordination with other parties required
- No race conditions or timing dependencies

**Detection Constraints:**
- Secret sharing can detect fraud by reconstructing real `InValue`, but no code enforces rejection
- Honest miners see inconsistency but the malicious block still gets accepted and finalized
- No on-chain penalty mechanism for providing incorrect values

**Probability Assessment:** 
High likelihood - the attack is straightforward, requires minimal resources, and offers clear economic benefit (better mining positions = more rewards). The only deterrent is potential off-chain reputation damage if discovered through secret sharing reconstruction.

### Recommendation

**Immediate Fix - Add Current OutValue Validation:**

Implement validation during block execution that compares the miner's claimed `PreviousInValue` (from next round) with the `OutValue` they published (in previous round) using data available in state:

1. **In ProcessUpdateValue**, after line 264, add validation:
```csharp
// Validate that if other miners reconstructed this miner's previous InValue via secret sharing,
// it matches what they're claiming
if (TryToGetPreviousRoundInformation(out var prevRound) && 
    prevRound.RealTimeMinersInformation.ContainsKey(_processingBlockMinerPubkey))
{
    var previousOutValue = prevRound.RealTimeMinersInformation[_processingBlockMinerPubkey].OutValue;
    if (previousOutValue != null && updateValueInput.PreviousInValue != Hash.Empty)
    {
        Assert(HashHelper.ComputeFrom(updateValueInput.PreviousInValue) == previousOutValue,
            "PreviousInValue does not match previously published OutValue");
    }
}
```

2. **Strengthen secret sharing enforcement** in `PerformSecretSharing` (line 287-297):
```csharp
// Check consistency between claimed PreviousInValue and reconstructed values
foreach (var previousInValue in input.MinersPreviousInValues)
{
    var targetMiner = round.RealTimeMinersInformation[previousInValue.Key];
    if (targetMiner.PreviousInValue != null && 
        targetMiner.PreviousInValue != Hash.Empty &&
        targetMiner.PreviousInValue != previousInValue.Value)
    {
        Context.LogWarning($"Mismatch: miner {previousInValue.Key} claimed {targetMiner.PreviousInValue} " +
            $"but secret sharing reconstructed {previousInValue.Value}");
        // Use reconstructed value, not claimed value
    }
    targetMiner.PreviousInValue = previousInValue.Value;
}
```

3. **Add validation test cases:**
    - Test that blocks with `OutValue ≠ Hash(InValue)` eventually fail validation
    - Test that fabricated `PreviousInValue` is rejected when secret sharing is enabled
    - Test that mining order calculation is deterministic and cannot be manipulated

### Proof of Concept

**Initial State:**
- Attacker is an elected consensus miner with pubkey "AttackerPubkey"
- Current round is Round N
- Attacker's turn to produce block in Round N

**Attack Sequence:**

**Step 1 - Round N (Attacker produces block with fake OutValue):**
- Attacker generates: `real_InValue_N = random_hash()`
- Attacker computes: `fake_OutValue_N = different_random_hash()` where `fake_OutValue_N ≠ Hash(real_InValue_N)`
- Attacker produces UpdateValue block publishing `fake_OutValue_N`
- **Expected**: Block validation should reject fake OutValue
- **Actual**: Validation passes because only `NewConsensusInformationFilled` is checked (OutValue is non-null), no hash validation occurs [7](#0-6) 

**Step 2 - Round N+1 (Attacker produces block with matching fake PreviousInValue):**
- Attacker generates: `fake_InValue_N' = preimage_of(fake_OutValue_N)` such that `Hash(fake_InValue_N') == fake_OutValue_N`
- Attacker produces UpdateValue block with `PreviousInValue = fake_InValue_N'`
- **Expected**: Validation should detect that `fake_InValue_N' ≠ real_InValue_N` (which was used for secret sharing)
- **Actual**: Validation passes because `Hash(fake_InValue_N') == fake_OutValue_N` satisfies the only check [8](#0-7) 

**Step 3 - Signature Calculation with Fake Value:**
- Next round's mining order is calculated using the fake `PreviousInValue`: [9](#0-8) 

The signature affects the `SupposedOrderOfNextRound` calculation: [10](#0-9) 

**Success Condition:**
- Attacker successfully publishes mismatched OutValue/InValue pair
- Both blocks are accepted and finalized
- Attacker's mining order in subsequent rounds is determined by manipulated signature
- No validation failure or penalty occurs
- Secret sharing may reconstruct real InValue but it doesn't prevent the attack

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L65-69)
```csharp
        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L263-264)
```csharp
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-297)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-22)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

```
