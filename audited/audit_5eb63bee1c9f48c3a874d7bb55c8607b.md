### Title
Insufficient Validation of PreviousInValue Allows Secret Sharing Commitment Bypass and Miner Collusion

### Summary
The `RecoverFromUpdateValue` function copies `PreviousInValue` for all miners without validating that these values match their committed `OutValue` hashes. Only the sender's own `PreviousInValue` is validated, allowing malicious miners to submit arbitrary revealed secrets for other miners, breaking the commitment scheme and enabling coordinated manipulation of next round miner orders.

### Finding Description

**Vulnerable Code Locations:**

The vulnerability exists across multiple points in the validation and processing flow: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Root Cause:**

The AEDPoS consensus uses a commitment scheme where miners commit to random `InValue` by publishing `OutValue = Hash(InValue)`. In the next round, they reveal `PreviousInValue` which must satisfy `Hash(PreviousInValue) == OutValue` to prove honesty. Secret sharing allows recovery if miners fail to reveal.

However, the validation only checks the sender's own `PreviousInValue`. In `UpdateValueValidationProvider.ValidatePreviousInValue`, line 38 retrieves only the sender's public key, and line 45 validates only that miner's value. Lines 28-29 of `RecoverFromUpdateValue` copy ALL miners' `PreviousInValue` from the provided round without any validation against their respective `OutValue` commitments.

When `PerformSecretSharing` processes `input.MinersPreviousInValues` at lines 295-296, or when `UpdateLatestSecretPieces` processes `triggerInformation.RevealedInValues` at lines 148-152, these other miners' values are applied to state without commitment verification.

**Why Existing Protections Fail:** [5](#0-4) 

The validation flow calls `RecoverFromUpdateValue` before adding the `UpdateValueValidationProvider`, but the provider only validates the sender's value, not the copied values for other miners. The after-execution validation also fails to catch this because both the header and state contain the same unvalidated values. [6](#0-5) 

### Impact Explanation

**Consensus Integrity Compromise:**

The secret sharing mechanism is designed to prevent miners from colluding to manipulate next round orders. The commitment scheme (OutValue = Hash(InValue)) ensures miners cannot change their random values retroactively. This vulnerability completely bypasses that protection.

**Attack Scenario:**

Colluding miners A and B can:
1. Coordinate off-chain to choose favorable `InValue` combinations
2. Each miner includes fake `PreviousInValue` entries for the other in their `MinersPreviousInValues` field
3. These fake values are chosen to produce signatures that yield desired mining orders
4. The values bypass validation since only the sender's own value is checked
5. The fake values become part of consensus state and are used in order calculations [7](#0-6) 

**Affected Parties:**

- All honest miners suffer unfair competition from colluding miners who can secure favorable time slots
- Block production fairness is compromised
- The entire consensus randomness guarantee is defeated
- Network security degrades as collusion becomes profitable

**Severity Justification:**

HIGH severity because it breaks a fundamental consensus security property - the unpredictability and fairness of miner rotation. This enables systematic collusion that undermines the entire DPoS mechanism's integrity.

### Likelihood Explanation

**Attacker Capabilities Required:**

- Must be an active miner in the current round (already authorized)
- Requires coordination with at least one other malicious miner
- No special privileges beyond normal mining rights needed

**Attack Complexity:**

LOW - The attack is straightforward:
1. Coordinate with another miner off-chain
2. When producing UpdateValue block, include `MinersPreviousInValues` with fake entries
3. The validation automatically passes since it only checks the sender's value
4. No complex transaction sequences or timing requirements

**Feasibility Conditions:** [8](#0-7) 

Any miner can populate `MinersPreviousInValues` in their `UpdateValueInput`. The contract accepts and processes these values without validation.

**Detection Constraints:**

The attack is difficult to detect because:
- The fake values appear as legitimate "revealed" secrets
- No on-chain validation failure occurs
- Only off-chain verification of OutValue commitments would detect the discrepancy
- Collusion coordination happens off-chain

**Economic Rationality:**

Highly profitable for colluding miners who can:
- Secure favorable consecutive time slots for higher block production
- Coordinate to produce more blocks than their fair share
- Gain unfair competitive advantage with minimal cost (just coordination)

### Recommendation

**Primary Fix - Add Validation for All Miners' PreviousInValues:**

In `UpdateValueValidationProvider.ValidatePreviousInValue`, add validation loop for all miners whose `PreviousInValue` is being set:

```csharp
// After validating sender's PreviousInValue at line 48
// Add validation for all other miners in the provided round
foreach (var minerInfo in extraData.Round.RealTimeMinersInformation)
{
    if (minerInfo.Key == publicKey) continue; // Already validated sender
    
    if (minerInfo.Value.PreviousInValue != null && 
        minerInfo.Value.PreviousInValue != Hash.Empty &&
        validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(minerInfo.Key))
    {
        var minerPreviousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[minerInfo.Key].OutValue;
        if (HashHelper.ComputeFrom(minerInfo.Value.PreviousInValue) != minerPreviousOutValue)
        {
            return false;
        }
    }
}
```

**Secondary Fix - Validate in PerformSecretSharing:**

Add validation in `PerformSecretSharing` before setting `PreviousInValue` at line 296:

```csharp
// Before line 296
var targetMiner = round.RealTimeMinersInformation[previousInValue.Key];
if (targetMiner.OutValue != null && 
    HashHelper.ComputeFrom(previousInValue.Value) != targetMiner.OutValue)
{
    continue; // Skip invalid revealed values
}
```

**Test Cases:**

1. Test that UpdateValue fails when `MinersPreviousInValues` contains values that don't hash to committed `OutValues`
2. Test that only validated `PreviousInValue` entries are applied to state
3. Test secret sharing reconstruction still works with validation in place
4. Test that colluding miners cannot bypass commitment verification

### Proof of Concept

**Initial State:**
- 5 miners (A, B, C, D, E) in round N
- Miner A committed: `OutValue_A = Hash(InValue_A_real)` 
- Miner B committed: `OutValue_B = Hash(InValue_B_real)`
- Miners A and B collude off-chain

**Attack Execution:**

**Step 1:** Miners A and B coordinate and choose fake InValues:
- `InValue_A_fake` chosen to give favorable signature/order
- `InValue_B_fake` chosen to give favorable signature/order
- Neither hashes to the committed OutValues

**Step 2:** In round N+1, Miner B produces block first with UpdateValueInput:
- `PreviousInValue = InValue_B_real` (validates correctly for B)
- `MinersPreviousInValues = {A: InValue_A_fake}` (NOT validated!)

**Step 3:** Validation passes:
- `ValidatePreviousInValue` checks only B's value: `Hash(InValue_B_real) == OutValue_B` ✓
- Does NOT check: `Hash(InValue_A_fake) == OutValue_A` ✗ (missing validation)

**Step 4:** Processing applies fake value:
- `PerformSecretSharing` sets: `round.RealTimeMinersInformation[A].PreviousInValue = InValue_A_fake`
- State now contains fake value that doesn't match commitment

**Step 5:** Miner A produces block with UpdateValueInput:
- `PreviousInValue = InValue_A_real` (validates correctly for A's own value)
- But state already contains `InValue_A_fake` set by B
- A's real value updates their own field, but the fake value was already propagated

**Expected Result:** Validation should FAIL at Step 3 because `InValue_A_fake` doesn't hash to `OutValue_A`

**Actual Result:** Validation PASSES, fake value is accepted into consensus state, breaking the commitment scheme and enabling collusion to manipulate mining orders.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L136-153)
```csharp
    private void UpdateLatestSecretPieces(Round updatedRound, string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);

        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;

        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-47)
```csharp
    public Round ApplyNormalConsensusData(string pubkey, Hash previousInValue, Hash outValue, Hash signature)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return this;

        RealTimeMinersInformation[pubkey].OutValue = outValue;
        RealTimeMinersInformation[pubkey].Signature = signature;
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;

        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```
