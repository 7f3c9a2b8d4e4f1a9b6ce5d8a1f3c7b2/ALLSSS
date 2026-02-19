### Title
Mining Order Manipulation via Unvalidated Secret Sharing Data in Consensus Transactions

### Summary
The `GetConsensusBlockExtraData` method's boolean parameter creates two data paths: block headers omit secret sharing data (`false`), while transaction generation includes it (`true`). The `MinersPreviousInValues` field in consensus transactions is accepted without validation, allowing malicious miners to set incorrect `PreviousInValue` entries for offline miners. These manipulated values are used to calculate signatures that determine mining order in subsequent rounds, compromising consensus fairness.

### Finding Description

The vulnerability stems from a validation gap between block header data and transaction execution data: [1](#0-0) 

When `isGeneratingTransactions = true`, the full round information including `MinersPreviousInValues` is preserved. This data is then extracted into the `UpdateValueInput`: [2](#0-1) 

The transaction execution blindly accepts and stores these values without cryptographic validation: [3](#0-2) 

When the block header data is stripped of secret sharing information, the validation path cannot check these values: [4](#0-3) [5](#0-4) 

The validation provider only checks the current miner's own `PreviousInValue`, not values set for others: [6](#0-5) 

The manipulated `PreviousInValue` is then used when filling data for absent miners: [7](#0-6) 

This incorrect signature directly affects mining order calculation: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Compromise**: A malicious miner can manipulate the mining order of offline or slow miners by providing incorrect `PreviousInValue` entries. The signature calculated from these manipulated values determines the `SupposedOrderOfNextRound` through modulo arithmetic on the signature's integer representation. This allows attackers to:

- Consistently push specific miners to unfavorable time slots
- Bias mining positions to advantage colluding miners
- Disrupt fair rotation of mining responsibilities
- Indirectly affect mining reward distribution

**Affected Parties**: All miners in the consensus pool, particularly those who occasionally experience network delays or brief downtime. The protocol's consensus fairness guarantees are violated.

**Severity Justification**: Medium severity - while this doesn't enable direct fund theft, it compromises a critical consensus invariant (miner schedule integrity). The attack has practical constraints (requires target miners to be absent) but can be repeated and has measurable impact on consensus fairness.

### Likelihood Explanation

**Attacker Capabilities**: Any active consensus miner can execute this attack. The attacker only needs to include malicious data in their `UpdateValueInput` when producing a block.

**Attack Complexity**: Low - the attacker simply provides crafted `MinersPreviousInValues` in their consensus transaction. No complex cryptographic operations or timing attacks are required.

**Feasibility Conditions**: 
- Target miner must be slow to produce their block or temporarily offline (common in distributed systems)
- Attacker must be scheduled to mine before the target miner recovers
- Secret sharing must be enabled (checked via configuration)

**Detection Constraints**: The manipulation is difficult to detect because:
- The malicious data is not included in block headers
- Validation only checks the current miner's own values
- The incorrect signatures appear valid in structure
- Effects only manifest in mining order, which has natural variance

**Probability**: Medium - miner downtime/delays occur regularly in distributed consensus systems, providing frequent attack opportunities. The low cost and difficulty of detection make exploitation economically rational for miners seeking competitive advantage.

### Recommendation

**Code-Level Mitigation**:

1. Add cryptographic validation for `MinersPreviousInValues` entries - verify that each provided `PreviousInValue` hashes to the corresponding miner's `OutValue` from the previous round:

```csharp
// In PerformSecretSharing or a new validation method
foreach (var previousInValue in input.MinersPreviousInValues)
{
    var targetPubkey = previousInValue.Key;
    if (previousRound.RealTimeMinersInformation.ContainsKey(targetPubkey))
    {
        var expectedOutValue = previousRound.RealTimeMinersInformation[targetPubkey].OutValue;
        Assert(
            HashHelper.ComputeFrom(previousInValue.Value) == expectedOutValue,
            $"Invalid PreviousInValue provided for miner {targetPubkey}"
        );
    }
}
```

2. Only allow miners to set `PreviousInValue` for themselves, not for others. Remove the ability to populate `MinersPreviousInValues` with entries for other miners.

3. Add the cryptographic validation to `UpdateValueValidationProvider` so it checks during block validation, not just execution.

**Invariant Checks**:
- `MinersPreviousInValues` entries must satisfy: `Hash(value) == previousRound.OutValue[pubkey]`
- A miner can only provide `PreviousInValue` for miners they have successfully decoded via secret sharing threshold
- Secret sharing completeness should be verifiable on-chain before values can be submitted

**Test Cases**:
- Test that providing incorrect `MinersPreviousInValues` causes transaction rejection
- Test that mining order calculation is unaffected by malicious inputs
- Test secret sharing flow with validation enabled
- Test fallback to previous round's `InValue` when current round's `PreviousInValue` validation fails

### Proof of Concept

**Initial State**:
- Term with 5 miners (A, B, C, D, E) in current round
- Miner A scheduled to mine but experiences network delay (OutValue = null)
- Miner B scheduled next and mines successfully
- Secret sharing enabled via configuration

**Attack Sequence**:

1. **Miner B produces block** with malicious `UpdateValueInput`:
   - Include crafted entry in `MinersPreviousInValues`: `{A_pubkey: malicious_hash}`
   - The `malicious_hash` is chosen to produce a disadvantageous signature for Miner A
   - Transaction is accepted because no validation checks this field

2. **ProcessUpdateValue executes** (lines 287-297):
   - Line 296 stores: `round.RealTimeMinersInformation[A_pubkey].PreviousInValue = malicious_hash`
   - No validation occurs - the incorrect value is now in consensus state

3. **Next consensus transaction** (Miner C produces block):
   - `SupplyCurrentRoundInformation` called before processing
   - Line 191 reads the malicious `PreviousInValue` for Miner A (still hasn't mined)
   - Line 199 calculates: `signature = previousRound.CalculateSignature(malicious_hash)`
   - Lines 213-214 set Miner A's InValue and Signature using malicious data

4. **Next round generation**:
   - `ApplyNormalConsensusData` processes Miner A's data
   - Line 19: `var sigNum = malicious_signature.ToInt64()`
   - Line 21: `supposedOrderOfNextRound = GetAbsModulus(sigNum, 5) + 1`
   - Miner A assigned incorrect position (e.g., position 5 instead of expected position 2)

**Expected Result**: Miner A should maintain their fair position in mining rotation based on their actual cryptographic contribution.

**Actual Result**: Miner A is assigned position determined by Miner B's malicious input, violating consensus fairness.

**Success Condition**: Demonstrate that by controlling the `malicious_hash` value, Miner B can deterministically place Miner A in any desired position (1-5) in the next round, breaking the randomness and fairness guarantees of the mining order algorithm.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L72-72)
```csharp
        consensusInformation.MergeFrom(GetConsensusBlockExtraData(input, true).Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L31-31)
```csharp
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L50-50)
```csharp
        if (!isGeneratingTransactions) information.Round.DeleteSecretSharingInformation();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L188-199)
```csharp
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
