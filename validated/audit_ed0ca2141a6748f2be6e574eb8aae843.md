# Audit Report

## Title
Unauthorized PreviousInValue Manipulation Breaks VRF Commit-Reveal Protocol in AEDPoS Consensus

## Summary
The AEDPoS consensus contract allows a malicious miner to inject arbitrary `PreviousInValue` data for other miners during block production. While validation checks the sender's own `PreviousInValue` cryptographically, it blindly trusts `PreviousInValue` data for ALL other miners included in the block header and transaction input. This breaks the VRF commit-reveal protocol and enables consensus randomness manipulation.

## Finding Description

The vulnerability exists across multiple code paths:

**1. Unvalidated Injection During Block Production**

When generating consensus extra data, `UpdateLatestSecretPieces` directly sets other miners' `PreviousInValue` from `triggerInformation.RevealedInValues` without any validation: [1](#0-0) 

The `RevealedInValues` comes from the node-side `SecretSharingService.GetRevealedInValues()`: [2](#0-1) 

A malicious node operator can modify their `SecretSharingService` to return fake values, bypassing the legitimate secret-sharing reconstruction that occurs in `RevealPreviousInValues`: [3](#0-2) 

**2. Propagation via Simplified Round**

The injected fake values are included in the simplified round sent in the block header: [4](#0-3) 

**3. Unconditional Overwrite During Validation**

During `ValidateBeforeExecution`, `RecoverFromUpdateValue` unconditionally overwrites ALL miners' `PreviousInValue` from the provided round data: [5](#0-4) [6](#0-5) 

**4. Insufficient Validation**

The `UpdateValueValidationProvider` ONLY validates the sender's `PreviousInValue`, ignoring all other miners: [7](#0-6) 

**5. State Persistence During Execution**

The transaction input is constructed from the round containing fake values: [8](#0-7) [9](#0-8) 

During execution, `PerformSecretSharing` applies these fake values to all miners without validation: [10](#0-9) 

These fake values persist to blockchain state: [11](#0-10) 

## Impact Explanation

**Critical Consensus Integrity Compromise:**

1. **VRF Commit-Reveal Protocol Violation**: The AEDPoS protocol requires each miner to commit to their `InValue` via `OutValue = Hash(InValue)` in one round, then reveal `InValue` as `PreviousInValue` when they mine. The contract validates this relationship ONLY for the sender. Allowing arbitrary injection of other miners' `PreviousInValue` completely breaks this cryptographic guarantee.

2. **Randomness Manipulation**: `PreviousInValue` is used to calculate signatures via `CalculateSignature` that feed into VRF-based random number generation. An attacker can influence consensus randomness by setting fake `PreviousInValues` for other miners, affecting block producer selection and election outcomes.

3. **State Corruption**: Once injected, fake `PreviousInValues` persist in blockchain state and propagate to subsequent blocks through the `MinersPreviousInValues` collection mechanism.

4. **No Cryptographic Verification**: There is no proof that the party setting another miner's `PreviousInValue` actually knows the corresponding `InValue` or that `Hash(PreviousInValue) == OutValue` for that miner.

## Likelihood Explanation

**High Likelihood:**

- **Attack Requirements**: Attacker needs only one miner position (standard in PoS/DPoS) and ability to modify their own node software (standard assumption for malicious operators).

- **Execution Simplicity**: Attacker modifies `SecretSharingService.GetRevealedInValues()` to return fake values, then produces blocks normally during their scheduled time slots.

- **Validation Bypass**: The contract-side validation explicitly checks only the sender's `PreviousInValue` cryptographically, trusting all other values unconditionally.

- **No Detection Mechanism**: No contract-side verification exists to distinguish legitimate secret-sharing-derived values from fake values injected by the block producer.

- **Economic Incentive**: Manipulating consensus randomness provides significant advantages in validator selection, election outcomes, and predictable/influenceable random values for protocol operations.

## Recommendation

Implement contract-side validation for all miners' `PreviousInValue` data:

1. **Validate Against OutValue**: For each miner's `PreviousInValue` in the provided round data, verify that `Hash(PreviousInValue) == miner.OutValue` from the previous round where they were expected to reveal.

2. **Restrict Secret-Sharing Path**: Only allow `PreviousInValue` to be set through the legitimate secret-sharing reconstruction path (`RevealSharedInValues` in the contract), not through arbitrary node-provided values.

3. **Remove Unvalidated Injection**: Remove or add validation to the `UpdateLatestSecretPieces` code that blindly trusts `triggerInformation.RevealedInValues`.

4. **Validate in RecoverFromUpdateValue**: Add validation in `RecoverFromUpdateValue` to ensure provided `PreviousInValue` data for all miners matches their committed `OutValue`.

## Proof of Concept

A malicious miner can exploit this by:

1. Modifying their node's `SecretSharingService.GetRevealedInValues()` to return:
   ```csharp
   return new Dictionary<string, Hash> {
       ["targetMinerPubkey"] = Hash.FromString("fake_value")
   };
   ```

2. Producing a block during their scheduled time slot with `UpdateValue` behavior.

3. The fake `PreviousInValue` flows through:
   - `UpdateLatestSecretPieces` → sets in `updatedRound`
   - `GetUpdateValueRound` → includes in block header
   - `RecoverFromUpdateValue` → applies during validation (only sender validated)
   - `ExtractInformationToUpdateConsensus` → includes in transaction input
   - `PerformSecretSharing` → persists to state

4. Result: Target miner's `PreviousInValue` is now set to an arbitrary fake value in blockchain state, breaking the commit-reveal protocol and enabling randomness manipulation.

The attack succeeds because contract-side validation only verifies: [12](#0-11) 

This checks only `extraData.Round.RealTimeMinersInformation[publicKey]` where `publicKey` is the sender, ignoring all other miners' `PreviousInValue` data.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L112-114)
```csharp
            var revealedInValues = _secretSharingService.GetRevealedInValues(hint.RoundId);
            foreach (var revealedInValue in revealedInValues)
                trigger.RevealedInValues.Add(revealedInValue.Key, revealedInValue.Value);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L175-180)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            Logger.LogDebug($"Revealed in value of {pubkey} of round {round.RoundNumber}: {revealedInValue}");

            revealedInValues[pubkey] = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L51-51)
```csharp
                    PreviousInValue = information.Value.PreviousInValue
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-146)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
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
