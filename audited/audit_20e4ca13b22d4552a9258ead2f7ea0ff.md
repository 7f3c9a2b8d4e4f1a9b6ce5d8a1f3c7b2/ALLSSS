### Title
Unvalidated PreviousInValue Setting in Secret Sharing Mechanism Breaks VRF Property

### Summary
While `RevealSharedInValues()` itself does not cause a vulnerability (its modifications are not persisted), the broader secret sharing mechanism contains critical flaws where `PreviousInValue` is set for miners without validating it matches their actual previous in-value. This occurs in two code paths: `UpdateLatestSecretPieces()` processing `RevealedInValues` and `PerformSecretSharing()` processing `MinersPreviousInValues`, both of which bypass the VRF validation and allow manipulation of consensus randomness.

### Finding Description

The vulnerability exists in the UpdateValue consensus behavior path, where miners can set `PreviousInValue` for other miners without validation:

**Root Cause 1 - UpdateLatestSecretPieces:** [1](#0-0) 

Miners provide `triggerInformation.RevealedInValues` which directly sets other miners' `PreviousInValue` without verifying that `Hash(revealedInValue) == OutValue` from the previous round.

**Root Cause 2 - PerformSecretSharing:** [2](#0-1) 

The `UpdateValueInput.MinersPreviousInValues` map is processed and directly applied to set `PreviousInValue` for other miners without any hash validation.

**Validation Gap:** [3](#0-2) 

The `ValidatePreviousInValue` method only validates the sender's own `PreviousInValue` (using `validationContext.SenderPubkey`), not the values provided for other miners in `MinersPreviousInValues` or `RevealedInValues`.

**Impact on VRF:** [4](#0-3) 

The `PreviousInValue` is used in `CalculateSignature()` to compute signatures that determine mining order in the next round. [5](#0-4) 

The signature calculated from `PreviousInValue` determines `SupposedOrderOfNextRound` and `FinalOrderOfNextRound`, which controls the mining schedule.

**Note on RevealSharedInValues:** [6](#0-5) 

While this function also sets `PreviousInValue` without validation, it modifies `currentRound` during NextRound behavior, and these modifications are not persisted since only `nextRound` is returned. [7](#0-6) 

### Impact Explanation

**Consensus Integrity Breach:**
- Malicious miner can set arbitrary `PreviousInValue` for other miners via `MinersPreviousInValues` or `RevealedInValues`
- This breaks the VRF property where mining order should be determined by unpredictable, verifiable random values
- Attacker can influence signature calculations and manipulate mining order for subsequent rounds
- Multiple colluding miners could systematically bias the mining schedule in their favor

**Concrete Harm:**
- Mining rewards can be manipulated by controlling who mines in favorable time slots
- Block production fairness is compromised, allowing certain miners to produce more blocks
- The cryptographic guarantee of random, unpredictable mining order is broken
- May enable timing attacks where attackers position themselves to mine consecutive blocks

**Severity Justification: Critical**
- Violates core consensus invariant (correct round transitions and miner schedule integrity)
- Affects all participants in the consensus mechanism
- No fund theft, but enables gaming of consensus rewards and block production

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner in the current round
- Needs ability to produce valid blocks with UpdateValue behavior
- No special privileges required beyond being in the miner list

**Attack Complexity: Low**
- Entry point is public `UpdateValue()` method via `UpdateValueInput.MinersPreviousInValues` [8](#0-7) 

- Attacker simply provides false values in the `miners_previous_in_values` map
- No complex cryptographic operations or timing requirements needed
- Can target any other miner in the current round

**Feasibility:**
- Secret sharing is enabled when configuration is set [9](#0-8) 

- Attack succeeds immediately upon processing UpdateValueInput [10](#0-9) 

- State is permanently modified in round information [11](#0-10) 

**Detection Difficulty:**
- Incorrect values appear as legitimate secret sharing reveals
- No on-chain validation distinguishes malicious from honest values
- Impact may be subtle across multiple rounds

### Recommendation

**Add Validation in PerformSecretSharing:**
```
Before line 296, add:
foreach (var previousInValue in input.MinersPreviousInValues)
{
    if (TryToGetPreviousRoundInformation(out var previousRound) &&
        previousRound.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
    {
        var previousOutValue = previousRound.RealTimeMinersInformation[previousInValue.Key].OutValue;
        Assert(HashHelper.ComputeFrom(previousInValue.Value) == previousOutValue, 
               $"Invalid previous in value for miner {previousInValue.Key}");
    }
    round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
}
```

**Add Validation in UpdateLatestSecretPieces:**
```
Before line 152, add validation:
foreach (var revealedInValue in triggerInformation.RevealedInValues)
{
    if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
        (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
         updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
    {
        if (TryToGetPreviousRoundInformation(out var previousRound) &&
            previousRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
        {
            var previousOutValue = previousRound.RealTimeMinersInformation[revealedInValue.Key].OutValue;
            Assert(HashHelper.ComputeFrom(revealedInValue.Value) == previousOutValue,
                   $"Invalid revealed in value for miner {revealedInValue.Key}");
        }
        updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
    }
}
```

**Test Cases:**
- Verify rejection when `Hash(miners_previous_in_values[key])` ≠ `previousRound.OutValue[key]`
- Verify rejection when `Hash(revealed_in_values[key])` ≠ `previousRound.OutValue[key]`
- Verify legitimate secret sharing still functions correctly
- Verify mining order remains unpredictable and fair after mitigation

### Proof of Concept

**Initial State:**
- Round N: Miner A produces block with `OutValue_A = Hash(InValue_A)`
- Round N+1: Miner A and Miner B are both in miner list
- Secret sharing is enabled

**Attack Steps:**
1. Miner B produces block in Round N+1 with UpdateValue behavior
2. In `UpdateValueInput`, Miner B sets:
   ```
   miners_previous_in_values[A] = fake_InValue
   where Hash(fake_InValue) ≠ OutValue_A
   ```
3. Block passes validation because `UpdateValueValidationProvider` only checks Miner B's own `PreviousInValue`, not the `miners_previous_in_values` map
4. `PerformSecretSharing()` executes and sets:
   ```
   round.RealTimeMinersInformation[A].PreviousInValue = fake_InValue
   ```
5. Round information is updated in state with the incorrect value

**Expected Result:**
- Validation should reject the block because `Hash(fake_InValue) ≠ OutValue_A`

**Actual Result:**
- Block is accepted
- Miner A's `PreviousInValue` is set to attacker-controlled value
- When used for signature calculation, this affects mining order determination
- VRF property is broken as attacker can influence randomness

**Success Condition:**
- Query `State.Rounds[N+1].RealTimeMinersInformation[A].PreviousInValue` returns `fake_InValue`
- `Hash(fake_InValue) ≠ State.Rounds[N].RealTimeMinersInformation[A].OutValue`
- System accepts this inconsistency and uses it for subsequent consensus calculations

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-203)
```csharp
        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-46)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** protobuf/aedpos_contract.proto (L215-216)
```text
    // The InValue in the previous round, miner public key -> InValue.
    map<string, aelf.Hash> miners_previous_in_values = 11;
```
