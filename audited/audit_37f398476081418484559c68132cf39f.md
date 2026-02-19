### Title
Unvalidated Revealed PreviousInValues Allow Malicious Miners to Cause Consensus DoS

### Summary
A malicious miner can inject incorrect `PreviousInValue` data for other miners through the `RevealedInValues` mechanism without cryptographic validation. These unvalidated values are written to consensus state and prevent legitimate miners from updating their correct values, causing signature calculation failures and potential denial-of-service against targeted miners.

### Finding Description

The vulnerability exists in the consensus data flow where revealed previous in-values are processed without validation:

**Location 1: Unvalidated Collection** [1](#0-0) 

This function collects ALL miners' `PreviousInValue` fields from the provided Round object without verifying their correctness.

**Location 2: Revealed Values Written Without Validation** [2](#0-1) 

When a miner produces a block, they can provide `RevealedInValues` for other miners. These are written to the Round object if the target miner's `PreviousInValue` is currently empty or null, with NO cryptographic verification.

**Location 3: Insufficient Validation** [3](#0-2) 

The validation only checks the SENDER's own `PreviousInValue` (line 38, 42, 45) by verifying `hash(PreviousInValue) == OutValue` from the previous round. It does NOT validate the `PreviousInValue` fields for OTHER miners in the Round object.

**Location 4: State Corruption via PerformSecretSharing** [4](#0-3) 

The unvalidated `PreviousInValue` data from `MinersPreviousInValues` dictionary is directly written to state without any hash verification against previous `OutValue` commitments.

**Location 5: Victim Cannot Overwrite** [5](#0-4) 

When the victim miner later produces their block with the correct `PreviousInValue`, this code only sets the value if it's currently empty or null. Since the malicious value was already set, the correct value cannot overwrite it.

**Root Cause:**
The consensus protocol expects miners to cryptographically commit to their `InValue` in round N (via `OutValue = hash(InValue)`), then reveal it as `PreviousInValue` in round N+1. The validation ensures `hash(PreviousInValue) == OutValue`, but this check is only applied to the block producer's own value, not to revealed values for other miners.

### Impact Explanation

**Consensus Disruption:**
A malicious miner can prevent targeted miners from participating correctly in consensus by corrupting their `PreviousInValue` in state. Since signature calculation for the next round depends on `PreviousInValue`: [6](#0-5) 

The victim miner will compute an incorrect signature, potentially causing their blocks to be rejected in subsequent rounds.

**Affected Parties:**
- Targeted miners: Cannot produce valid blocks, lose mining rewards
- Network: Reduced active miner count affects consensus liveness
- Chain security: If multiple miners are targeted, consensus could stall

**Severity Justification:**
Medium severity because:
1. Requires malicious miner (trusted role compromise)
2. Affects consensus integrity (critical invariant violation)
3. Limited to DoS (no fund theft)
4. Detectable through consensus monitoring
5. Recoverable through round transitions

### Likelihood Explanation

**Attacker Capabilities:**
Must be an active miner in the current round to produce blocks with UpdateValue behavior.

**Attack Complexity:**
Straightforward - attacker modifies the `AElfConsensusTriggerInformation.RevealedInValues` dictionary to include incorrect hash values for target miners before block production.

**Feasibility Conditions:**
1. Attacker must produce a block before the victim in round N+1
2. Victim's `PreviousInValue` must not yet be set in state
3. Secret sharing must be enabled: [7](#0-6) 

**Detection Constraints:**
Off-chain monitoring could detect mismatches between revealed values and expected hashes, but on-chain validation is missing.

**Probability:**
Medium - requires compromised miner but attack execution is simple and reliable.

### Recommendation

**Primary Fix: Add Validation for All Revealed PreviousInValues**

Modify `UpdateValueValidationProvider.ValidateHeaderInformation` to validate ALL `PreviousInValue` fields in the provided Round, not just the sender's:

```csharp
// Add after line 17 in UpdateValueValidationProvider.cs
if (!ValidateAllRevealedPreviousInValues(validationContext))
    return new ValidationResult { Message = "Incorrect revealed previous in values." };

private bool ValidateAllRevealedPreviousInValues(ConsensusValidationContext validationContext)
{
    var providedRound = validationContext.ExtraData.Round;
    var previousRound = validationContext.PreviousRound;
    
    foreach (var miner in providedRound.RealTimeMinersInformation)
    {
        var previousInValue = miner.Value.PreviousInValue;
        if (previousInValue == null || previousInValue == Hash.Empty) 
            continue;
            
        // Skip if miner wasn't in previous round (new/replacement miner)
        if (!previousRound.RealTimeMinersInformation.ContainsKey(miner.Key))
            continue;
            
        var previousOutValue = previousRound.RealTimeMinersInformation[miner.Key].OutValue;
        if (HashHelper.ComputeFrom(previousInValue) != previousOutValue)
            return false;
    }
    return true;
}
```

**Invariant to Enforce:**
For every miner M with non-empty `PreviousInValue` in round N, if M was in round N-1, then: `hash(Round[N].PreviousInValue[M]) == Round[N-1].OutValue[M]`

**Test Cases:**
1. Malicious miner provides incorrect `RevealedInValues` - block should be rejected during validation
2. Multiple miners reveal correct values simultaneously - all should be accepted
3. New replacement miner with no previous round data - should be allowed without validation

### Proof of Concept

**Initial State:**
- Round 100: Miner M2 produces block with `OutValue = hash(secret_value)`
- Round 101: Both M1 (malicious) and M2 are active miners
- Secret sharing is enabled

**Attack Steps:**

1. M1 prepares block for Round 101 with malicious trigger information:
   ```
   triggerInformation.RevealedInValues["M2_pubkey"] = fake_hash
   // where fake_hash != hash(secret_value)
   ```

2. M1's block is processed:
   - [2](#0-1)  writes `fake_hash` to Round object
   - Validation passes because only M1's own `PreviousInValue` is checked
   - [4](#0-3)  writes `fake_hash` to state for M2

3. M2 attempts to produce block later in Round 101:
   - M2 provides correct `PreviousInValue = hash^(-1)(OutValue_from_round_100)`
   - [5](#0-4)  prevents overwrite because value is non-empty
   - M2's correct value is NOT stored

4. Round 102: M2 computes signature using the incorrect `PreviousInValue = fake_hash`
   - Signature validation fails or produces wrong mining order
   - M2's blocks may be rejected
   - M2 suffers loss of mining rewards and reputation damage

**Expected vs Actual:**
- Expected: M2's correct `PreviousInValue` is stored and used for signature calculation
- Actual: M1's injected incorrect value remains in state, causing M2's consensus participation to fail

**Success Condition:**
Attack succeeds if `State.Rounds[101].RealTimeMinersInformation["M2_pubkey"].PreviousInValue == fake_hash` after M1's block, and M2 cannot correct it.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L122-125)
```csharp
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L14-16)
```csharp
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;
```
