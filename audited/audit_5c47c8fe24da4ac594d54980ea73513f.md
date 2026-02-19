### Title
Unvalidated Secret Sharing Allows Manipulation of Other Miners' PreviousInValue

### Summary
The AEDPoS consensus contract accepts and stores `MinersPreviousInValues` from UpdateValue transactions without validating that these revealed InValues match the corresponding OutValues from the previous round. An attacker can submit malicious decrypted secret sharing pieces off-chain, causing fake InValues to be computed and stored on-chain for victim miners, potentially corrupting randomness generation and consensus integrity until the victim corrects the value.

### Finding Description

The vulnerability exists in the secret sharing validation flow across multiple components:

**Root Cause:** In `PerformSecretSharing`, the contract unconditionally overwrites `PreviousInValue` for arbitrary miners without cryptographic validation: [1](#0-0) 

The `MinersPreviousInValues` map is populated during block production from `RevealedInValues`, which come from off-chain secret sharing reconstruction: [2](#0-1) 

During block production, `UpdateLatestSecretPieces` sets `PreviousInValue` from off-chain `RevealedInValues` without validation: [3](#0-2) 

The off-chain `RevealedInValues` are computed using `SecretSharingHelper.DecodeSecret` with attacker-provided decrypted pieces: [4](#0-3) 

**Why Protections Fail:** The `UpdateValueValidationProvider` only validates the **sender's** PreviousInValue, not the PreviousInValues being set for other miners: [5](#0-4) 

The validation at line 38 uses `validationContext.SenderPubkey`, checking only the transaction sender's value against their previous OutValue. There is no validation loop over `MinersPreviousInValues` entries.

**Execution Path:**
1. Round N: Victim publishes `OutValue_V = Hash(InValue_V)` and distributes encrypted secret shares
2. Round N+1: Attacker submits `UpdateValue` with malicious `decrypted_pieces`
3. Off-chain: `SecretSharingService.RevealPreviousInValues` uses malicious pieces to compute fake `InValue_V'`
4. Block production: Fake value flows to `RevealedInValues` → `MinersPreviousInValues`
5. Block execution: `PerformSecretSharing` stores `PreviousInValue = InValue_V'` for victim without validation
6. Round N+2: Victim can correct by revealing real `InValue_V`, but damage occurs for one round

### Impact Explanation

**Consensus Integrity Compromise:**
- Victim's `PreviousInValue` is corrupted in state for one round
- The signature calculation uses PreviousInValue via `CalculateSignature`: [6](#0-5) 

- Fake PreviousInValue values affect randomness used for mining order determination in `ApplyNormalConsensusData`: [7](#0-6) 

**Who is Affected:**
- All miners whose PreviousInValue can be manipulated by any active miner
- Consensus randomness and mining schedule integrity
- Network participants relying on fair miner rotation

**Severity Justification:**
- **Medium-High**: Temporary but impactful state corruption affecting consensus integrity
- One round of manipulation could bias mining order selection
- Multiple simultaneous attacks could cause consensus disruption
- Victim self-corrects in next round, limiting duration of impact

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner with UpdateValue transaction rights
- Can modify off-chain `decrypted_pieces` before submission
- No special permissions beyond normal miner status required

**Attack Complexity:**
- **Low**: Attacker modifies off-chain data structures before transaction submission
- Entry point is the public `UpdateValue` method: [8](#0-7) 

- Execution flows through `ProcessConsensusInformation`: [9](#0-8) 

**Feasibility Conditions:**
- Secret sharing must be enabled (checked via Configuration contract)
- Attacker must be current miner
- Standard block production flow applies

**Detection Constraints:**
- Difficult to detect until victim reveals correct value next round
- No immediate on-chain signal of manipulation
- Malicious values appear valid without OutValue cross-check

**Probability: Medium-High** - Attack is practical for any malicious miner with moderate technical capability.

### Recommendation

**Code-Level Mitigation:**

Add validation in `PerformSecretSharing` to verify each entry in `MinersPreviousInValues`:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);

    foreach (var previousInValue in input.MinersPreviousInValues)
    {
        // ADD VALIDATION: Only set if currently empty AND matches previous OutValue
        var targetMiner = round.RealTimeMinersInformation[previousInValue.Key];
        if (targetMiner.PreviousInValue == null || targetMiner.PreviousInValue == Hash.Empty)
        {
            // TODO: Retrieve previous round and validate
            // Assert(HashHelper.ComputeFrom(previousInValue.Value) == previousRound[previousInValue.Key].OutValue)
            targetMiner.PreviousInValue = previousInValue.Value;
        }
    }
}
```

**Invariant Checks to Add:**
1. Before accepting `MinersPreviousInValues[victim]`, verify: `Hash(value) == previousRound[victim].OutValue`
2. Add validation provider to check all `MinersPreviousInValues` entries, not just sender
3. Implement conditional write: only set if currently empty/null, similar to `ApplyNormalConsensusData` logic: [10](#0-9) 

**Test Cases:**
1. Test that malicious `MinersPreviousInValues` with wrong hash are rejected
2. Verify only miners can set their own `PreviousInValue` directly
3. Test secret sharing recovery produces values matching previous `OutValue`
4. Confirm protection against overwriting non-empty `PreviousInValue` via `MinersPreviousInValues`

### Proof of Concept

**Initial State:**
- Round N: Victim miner publishes `OutValue_V = Hash(InValue_V)`
- Victim distributes encrypted shares: `encrypted_pieces[Attacker]`, `encrypted_pieces[Miner2]`, etc.
- Attacker is an active miner in Round N+1

**Attack Steps:**

1. **Off-chain manipulation**: Attacker modifies `SecretSharingService` to provide fake `decrypted_pieces[Victim]` claiming to be decryption of victim's encrypted share

2. **Off-chain computation**: `RevealPreviousInValues` calls `SecretSharingHelper.DecodeSecret` with malicious pieces, producing `InValue_V' ≠ InValue_V`

3. **Block production**: Attacker's node includes `RevealedInValues[Victim] = InValue_V'` in trigger information

4. **Transaction submission**: Attacker calls `UpdateValue` with `MinersPreviousInValues[Victim] = InValue_V'`

5. **Execution**: `PerformSecretSharing` executes line 296, setting victim's `PreviousInValue = InValue_V'` without validation

6. **State verification**: Query `GetCurrentRoundInformation()` shows victim's `PreviousInValue = InValue_V'` (fake value stored)

**Expected vs Actual:**
- **Expected**: System rejects fake InValue because `Hash(InValue_V') ≠ OutValue_V`
- **Actual**: System accepts and stores fake InValue without validation, corrupting state until victim's next UpdateValue

**Success Condition:** 
Query Round N+1 state shows victim's `PreviousInValue` set to attacker-controlled fake value that doesn't hash to victim's Round N `OutValue`.

### Notes

The vulnerability demonstrates a critical gap between off-chain secret sharing computation and on-chain validation. While individual miners' self-reported `PreviousInValue` values are validated, the system trusts `MinersPreviousInValues` entries that purport to reveal other miners' InValues through secret sharing reconstruction. This trust is misplaced as the reconstruction depends on attacker-controllable `decrypted_pieces` without cryptographic proof that these pieces are valid decryptions of the original `encrypted_pieces`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L175-176)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L14-16)
```csharp
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-22)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
