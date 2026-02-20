# Audit Report

## Title
Secret Sharing Validation Bypass Allows Mining Order Manipulation in AEDPoS Consensus

## Summary
The AEDPoS consensus contract fails to validate that reconstructed InValues from secret sharing match previously published OutValues. A malicious miner can publish OutValue = Hash(InValue_A) while providing encrypted pieces of InValue_B, where InValue_B ≠ InValue_A. This allows manipulation of signature calculations used for mining order determination, undermining the consensus protocol's randomness guarantees.

## Finding Description

The vulnerability exists in the secret sharing revelation mechanism where InValues are reconstructed from encrypted/decrypted pieces without cryptographic validation.

**Root Cause - Missing Validation in RevealSharedInValues:**

When `RevealSharedInValues` is invoked during round transitions, it reconstructs InValues from decrypted secret sharing pieces and directly assigns them to miners' `PreviousInValue` fields without any validation. [1](#0-0) 

The reconstructed InValue is computed via `SecretSharingHelper.DecodeSecret()` and immediately assigned. There is no check verifying that `Hash(reconstructed_InValue) == published_OutValue` from the previous round.

**Why Existing Protections Fail:**

The `UpdateValueValidationProvider` only validates PreviousInValues that miners explicitly provide in their UpdateValue transactions. [2](#0-1) 

This validation checks `extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue` (line 45), which is the value from the transaction context, not values set by the `RevealSharedInValues` mechanism during round transitions.

**Attack Execution Path:**

1. **Malicious UpdateValue Submission:** During `ProcessUpdateValue`, encrypted pieces are added without validation through the `PerformSecretSharing` helper. [3](#0-2) [4](#0-3) 

The attacker submits `OutValue = Hash(InValue_A)` but provides `EncryptedPieces(InValue_B)` where InValue_B ≠ InValue_A.

2. **NextRound Revelation:** When `NextRound` behavior is triggered, `RevealSharedInValues` is invoked. [5](#0-4) 

This reconstructs the fraudulent InValue_B and sets it as PreviousInValue without validation against the previously published OutValue.

3. **Signature Calculation Impact:** The revealed PreviousInValue is used for signature calculation when filling missing miner information in `SupplyCurrentRoundInformation`. [6](#0-5) 

The fraudulent InValue_B is read from `currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue` (line 191) and used to calculate signatures via `previousRound.CalculateSignature(previousInValue)` (line 199).

4. **Mining Order Determination:** The signature calculation XORs the InValue with all miners' signatures. [7](#0-6) 

These signatures directly affect mining order calculations through `ApplyNormalConsensusData`. [8](#0-7) 

The `SupposedOrderOfNextRound` is computed from the signature (lines 19-21), giving the attacker control over their mining position. The formula is `supposedOrderOfNextRound = GetAbsModulus(signature.ToInt64(), minersCount) + 1`, making the mining order directly dependent on the manipulated signature value.

## Impact Explanation

**Severity: HIGH - Consensus Integrity Violation**

This vulnerability directly compromises the consensus protocol's core security guarantees:

1. **Mining Order Manipulation:** Attackers can influence their `SupposedOrderOfNextRound` by controlling the InValue used in signature calculations, potentially securing earlier time slots or favorable positions in the mining schedule.

2. **Randomness Degradation:** The AEDPoS protocol relies on the unpredictability of XOR-combined signatures for randomness. If miners can inject arbitrary InValues through fraudulent secret sharing, this randomness becomes manipulable.

3. **Extra Block Producer Control:** The extra block producer selection algorithm uses signature values. Fraudulent InValues can influence which miner becomes the extra block producer, providing strategic advantages.

4. **Protocol Trust Breakdown:** If multiple miners exploit this, the fundamental assumption that InValues are bound to their OutValues through hash commitment breaks down, degrading the entire consensus mechanism.

While this doesn't immediately enable fund theft, it violates critical consensus invariants that ensure fair block production and network security.

## Likelihood Explanation

**Probability: HIGH**

**Attacker Prerequisites:**
- Must be an active miner in the consensus round (normal operational requirement)
- Ability to call `UpdateValue` (standard miner capability)
- No special permissions or administrative access required

**Attack Complexity: LOW**
1. Generate legitimate InValue_A and compute OutValue = Hash(InValue_A)
2. Create a different InValue_B
3. Use secret sharing to generate encrypted pieces of InValue_B
4. Submit UpdateValue with OutValue but encrypted pieces of InValue_B
5. Wait for round transition when pieces are revealed without validation

**Feasibility Conditions:**
Works whenever secret sharing is enabled. [9](#0-8) 

**Detection Difficulty: HARD**
The encrypted pieces are cryptographically valid and properly formatted. Only the semantic relationship between the revealed InValue and the published OutValue is incorrect, which cannot be detected by on-chain validation and requires off-chain monitoring of both values.

## Recommendation

Add validation in `RevealSharedInValues` to verify that the reconstructed InValue matches the previously published OutValue:

```csharp
private void RevealSharedInValues(Round currentRound, string publicKey)
{
    // ... existing code ...
    
    foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
    {
        // ... existing code ...
        
        var revealedInValue = 
            HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
        
        // ADD VALIDATION HERE
        var expectedOutValue = previousRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].OutValue;
        if (expectedOutValue != null && expectedOutValue != Hash.Empty)
        {
            Assert(HashHelper.ComputeFrom(revealedInValue) == expectedOutValue,
                $"Revealed InValue does not match published OutValue for miner {publicKeyOfAnotherMiner}");
        }
        
        currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
    }
}
```

This ensures that secret sharing cannot be abused to inject fraudulent InValues that don't correspond to previously committed OutValues.

## Proof of Concept

A test demonstrating this vulnerability would need to:
1. Set up a round with multiple miners and secret sharing enabled
2. Have a malicious miner call UpdateValue with OutValue=Hash(InValue_A) but EncryptedPieces(InValue_B)
3. Trigger NextRound to invoke RevealSharedInValues
4. Verify that the reconstructed PreviousInValue equals InValue_B (not InValue_A)
5. Show that this fraudulent InValue affects the signature calculation and mining order

The attack succeeds because there is no validation step between the secret decoding and the PreviousInValue assignment, allowing the mismatch between committed OutValue and revealed InValue to persist undetected.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L56-78)
```csharp
    private bool IsSecretSharingEnabled()
    {
        if (State.ConfigurationContract.Value == null)
        {
            var configurationContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
            if (configurationContractAddress == null)
            {
                // Which means Configuration Contract hasn't been deployed yet.
                return false;
            }

            State.ConfigurationContract.Value = configurationContractAddress;
        }

        var secretSharingEnabled = new BoolValue();
        secretSharingEnabled.MergeFrom(State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = AEDPoSContractConstants.SecretSharingEnabledConfigurationKey
        }).Value);

        return secretSharingEnabled.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-200)
```csharp
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-44)
```csharp
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
```
