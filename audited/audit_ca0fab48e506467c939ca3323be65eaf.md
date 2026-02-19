### Title
Unvalidated MinersPreviousInValues Allows Consensus State Manipulation

### Summary
The `ExtractInformationToUpdateConsensus()` function collects all miners' PreviousInValues and includes them in `UpdateValueInput.MinersPreviousInValues`, which are then unconditionally applied to the round state without validation in `PerformSecretSharing()`. This allows any miner to inject arbitrary PreviousInValues for other miners, bypassing the secret sharing integrity mechanism and potentially corrupting the consensus randomness chain.

### Finding Description

The vulnerability exists across multiple files in the consensus update flow:

**Collection Phase**: [1](#0-0) 

All miners' PreviousInValues are collected indiscriminately and packaged into the UpdateValueInput.

**Application Phase**: [2](#0-1) 

The MinersPreviousInValues are unconditionally applied to the round state, directly overwriting each miner's PreviousInValue field without any validation.

**Validation Gap**: [3](#0-2) 

The validation only checks the SENDER's own PreviousInValue (line 38 retrieves `publicKey` which is `validationContext.SenderPubkey`, and line 45 only validates `extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue`). It does not iterate through or validate the MinersPreviousInValues map containing other miners' values.

**Root Cause**: The design assumes MinersPreviousInValues contains legitimately revealed values from secret sharing, but there is no enforcement of this invariant. Unlike `UpdateLatestSecretPieces` [4](#0-3)  which only sets PreviousInValue if it's currently empty, PerformSecretSharing unconditionally overwrites regardless of existing values.

### Impact Explanation

**Consensus Integrity Compromise**: An attacker can manipulate the consensus randomness chain by injecting fake PreviousInValues for other miners. This affects:

1. **Randomness Chain Corruption**: PreviousInValue is used to calculate signatures that determine next round ordering [5](#0-4) . When miners fail to produce blocks, their InValue and Signature are derived from PreviousInValue, affecting the `CalculateSignature()` result which determines `SupposedOrderOfNextRound`.

2. **State Overwrite Attack**: A miner who has correctly revealed their PreviousInValue can have it overwritten by any subsequent miner's UpdateValue transaction, potentially causing signature validation failures in future rounds.

3. **Secret Sharing Bypass**: The vulnerability undermines the cryptographic guarantees of the Shamir Secret Sharing mechanism, which is designed to prevent manipulation through threshold-based revelation.

**Severity**: Medium-High. While it doesn't directly steal funds, it corrupts a critical consensus invariant (correct round transitions and randomness integrity) and can affect miner ordering and consensus continuity.

### Likelihood Explanation

**Highly Exploitable**:

- **Entry Point**: Any active miner can trigger this via the public `UpdateValue` method [6](#0-5)  when producing their block.

- **Attack Complexity**: Low. The attacker simply needs to construct an UpdateValueInput with arbitrary values in the MinersPreviousInValues map [7](#0-6) .

- **No Special Privileges Required**: Any miner in the current round can execute this attack during their regular block production.

- **Detection Difficulty**: The manipulated values persist in the round state and appear legitimate since there's no validation to distinguish them from correctly revealed values.

### Recommendation

**Immediate Fix**: Add validation for MinersPreviousInValues in `PerformSecretSharing()`:

```csharp
foreach (var previousInValue in input.MinersPreviousInValues)
{
    // Skip sender's own value (validated separately)
    if (previousInValue.Key == publicKey) continue;
    
    // Only set if currently empty (like UpdateLatestSecretPieces)
    if (round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue == Hash.Empty ||
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue == null)
    {
        // Verify against previous round's OutValue
        if (validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
        {
            var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[previousInValue.Key].OutValue;
            if (HashHelper.ComputeFrom(previousInValue.Value) == previousOutValue)
            {
                round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
            }
        }
    }
}
```

**Additional Measures**:
1. Add a validation provider that checks each entry in MinersPreviousInValues against the previous round's OutValues
2. Restrict MinersPreviousInValues to only include values the sender has legitimately revealed through secret sharing (track which values each miner has decrypted)
3. Add test cases verifying rejection of fake PreviousInValues and protection against overwrite attacks

### Proof of Concept

**Initial State**: Round N with three miners (A, B, C) where A has produced a block and correctly set their PreviousInValue = Hash("A_secret").

**Attack Steps**:
1. Miner B produces their block in the same round
2. B constructs UpdateValueInput with:
   - Their own valid consensus data
   - MinersPreviousInValues["A"] = Hash("fake_value") (where Hash("fake_value") ≠ A's previous OutValue)
3. B calls UpdateValue with this input

**Expected Result**: B's transaction should be rejected due to invalid PreviousInValue for miner A.

**Actual Result**: 
- B's transaction succeeds
- Miner A's PreviousInValue in the round state is overwritten with the fake value
- If A fails to mine in subsequent rounds, the fake value will be used in SupplyCurrentRoundInformation, producing incorrect signatures
- The consensus randomness chain is corrupted without any validation failure

**Success Condition**: After B's block, querying `GetCurrentRoundInformation().RealTimeMinersInformation["A"].PreviousInValue` returns Hash("fake_value") instead of Hash("A_secret"), demonstrating successful state manipulation.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L191-199)
```csharp
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
```

**File:** protobuf/aedpos_contract.proto (L215-216)
```text
    // The InValue in the previous round, miner public key -> InValue.
    map<string, aelf.Hash> miners_previous_in_values = 11;
```
