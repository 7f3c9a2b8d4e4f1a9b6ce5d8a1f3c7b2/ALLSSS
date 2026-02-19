# Audit Report

## Title
Unvalidated RevealedInValues Injection Breaking VRF Chain and Secret Sharing Protocol

## Summary
The AEDPoS consensus contract accepts arbitrary `RevealedInValues` from block producers without cryptographic validation, allowing malicious miners to inject fake `previousInValue` data for miners who missed their time slots. This breaks the VRF chain integrity and compromises the secret sharing protocol's fundamental security assumptions.

## Finding Description

The vulnerability exists in the consensus data update flow where revealed InValues are processed without proper validation against the VRF chain.

**Primary Vulnerable Code Location:**

In `UpdateLatestSecretPieces`, the function iterates through `triggerInformation.RevealedInValues` and directly sets other miners' `PreviousInValue` fields without any cryptographic verification. The only check performed is whether the target value is currently empty or null - there is no validation that `Hash(revealedInValue) == previousOutValue` as required by the VRF chain protocol. [1](#0-0) 

**Insufficient Validation:**

The `ValidatePreviousInValue` method only validates the **sender's own** `previousInValue` by checking the hash matches their `previousOutValue`. Critically, it does NOT iterate through or validate the `RevealedInValues` that the sender provides for OTHER miners via the trigger information. [2](#0-1) 

The validation is explicitly limited to the sender's public key only (line 38), not the revealed values for other miners.

**Similar Issue in PerformSecretSharing:**

The same validation gap exists when processing `MinersPreviousInValues` during UpdateValue transactions, where values are directly assigned without verification. [3](#0-2) 

**Exploitation Path:**

When a miner produces a block with malicious `RevealedInValues`, these fake values are stored in the round state via `ApplyNormalConsensusData`, which accepts `previousInValue` as a parameter and sets it without validation beyond checking if empty. [4](#0-3) 

**Propagation of Fake Values:**

In `SupplyCurrentRoundInformation`, which fills in consensus data for miners who didn't produce blocks, the function retrieves `previousInValue` from the current round (line 191) - which could be a fake injected value - and uses it to calculate the miner's signature (line 199). These signatures directly influence consensus state and randomness. [5](#0-4) 

**Consensus Impact:**

The `CalculateSignature` method XORs the provided `inValue` with all existing miner signatures, meaning fake values directly affect the consensus randomness computation that determines mining order. [6](#0-5) 

## Impact Explanation

**VRF Chain Integrity Broken:**
The AEDPoS consensus protocol relies on a verifiable random function chain where each `OutValue = Hash(InValue)`, and the `previousInValue` in round N+1 must equal the actual `InValue` from round N. Without validating that revealed values satisfy `Hash(revealedInValue) == previousOutValue`, this cryptographic chain is broken.

**Secret Sharing Protocol Compromised:**
The secret sharing mechanism assumes that revealed InValues are authentic reconstructions from the distributed shares. Accepting arbitrary values without validation breaks this fundamental assumption, allowing attackers to corrupt the consensus state of miners who missed their time slots.

**Consensus State Manipulation:**
Fake `previousInValue` entries are:
1. Stored persistently in miners' round data
2. Used in signature calculations via `CalculateSignature` 
3. XORed into the aggregate randomness that determines next round mining order
4. Used to set miners' InValue fields when they don't produce blocks

This corrupts the consensus protocol's security guarantees regarding unpredictable and fair mining order assignment.

**Affected Parties:**
- Miners who miss time slots have their consensus data corrupted with unverifiable fake values
- The entire network suffers from compromised randomness integrity
- Protocol security assumptions are systematically violated

**Severity: HIGH** - This vulnerability breaks a critical security invariant (VRF chain validation) that the entire consensus mechanism depends upon for its randomness and fairness properties.

## Likelihood Explanation

**Attacker Capabilities:**
Any active miner in the network can exploit this vulnerability by modifying their node software to inject arbitrary `RevealedInValues` in the consensus trigger information. No special privileges beyond being a registered miner are required.

**Attack Complexity:**
Low - The attacker needs to:
1. Modify their node's off-chain `SecretSharingService` or trigger information generation to return fake values in `RevealedInValues`
2. Produce a block during their assigned time slot with the malicious trigger information
3. The fake values are automatically accepted on-chain and stored in state without any validation

**Feasibility Conditions:**
- Attacker must be an active miner (can produce blocks) - standard in adversarial consensus models
- Target miners must have empty/null `PreviousInValue` (naturally occurs when miners miss slots)
- Secret sharing must be enabled (standard configuration)
- No additional cryptographic or economic prerequisites required

**Detection Constraints:**
The attack is difficult to detect because:
- `RevealedInValues` are expected to vary based on secret sharing reconstruction, so arbitrary values don't appear anomalous
- No on-chain mechanism exists to verify the correctness of revealed values against the VRF chain
- The fake values have valid Hash format and appear structurally legitimate
- Only affects miners who miss slots, which is a normal occurrence

**Probability: HIGH** - The attack is straightforward for any miner with modified node software. Given that the AEDPoS consensus model explicitly considers adversarial miners (Byzantine fault tolerance model), this exploit path is realistic and should be expected.

## Recommendation

Add cryptographic validation for all `RevealedInValues` before accepting them into the consensus state. Specifically:

1. **Validate RevealedInValues in UpdateLatestSecretPieces:**
```csharp
foreach (var revealedInValue in triggerInformation.RevealedInValues)
{
    if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
        (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
         updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
    {
        // ADD VALIDATION: Verify the revealed value hashes to the expected OutValue
        if (TryToGetPreviousRoundInformation(out var previousRound) &&
            previousRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
        {
            var expectedOutValue = previousRound.RealTimeMinersInformation[revealedInValue.Key].OutValue;
            if (HashHelper.ComputeFrom(revealedInValue.Value) != expectedOutValue)
            {
                Context.LogDebug(() => $"Invalid revealed in value for {revealedInValue.Key}");
                continue; // Skip invalid revealed values
            }
        }
        
        updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
    }
}
```

2. **Apply same validation in PerformSecretSharing:**
Add similar hash validation when processing `input.MinersPreviousInValues` to ensure consistency.

3. **Consider adding a validation provider:**
Create a `RevealedInValuesValidationProvider` that validates all revealed values during the block validation phase before execution, similar to how `UpdateValueValidationProvider` validates the sender's own value.

## Proof of Concept

```csharp
[Fact]
public async Task UnvalidatedRevealedInValues_BreaksVRFChain()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(5);
    await InitializeConsensus(miners);
    
    // Round 1: Miner A produces block normally
    var minerA = miners[0];
    var round1 = await ProduceNormalBlock(minerA);
    
    // Miner B misses their slot (PreviousInValue becomes empty)
    var minerB = miners[1];
    
    // Round 2: Malicious Miner C produces block with FAKE RevealedInValue for Miner B
    var minerC = miners[2];
    var fakeInValue = HashHelper.ComputeFrom("FAKE_VALUE_NOT_FROM_SECRET_SHARING");
    
    // The fake value does NOT hash to Miner B's actual OutValue from previous round
    var minerBActualOutValue = round1.RealTimeMinersInformation[minerB.PublicKey].OutValue;
    Assert.NotEqual(HashHelper.ComputeFrom(fakeInValue), minerBActualOutValue);
    
    var trigger = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(minerC.PublicKey),
        InValue = GenerateRandomHash(),
        RevealedInValues = {
            { minerB.PublicKey, fakeInValue } // Inject fake value for Miner B
        }
    };
    
    // Execute: Produce block with fake RevealedInValues
    var round2 = await ProduceBlockWithTrigger(minerC, trigger);
    
    // Verify vulnerability: Fake value was accepted without validation
    Assert.Equal(fakeInValue, round2.RealTimeMinersInformation[minerB.PublicKey].PreviousInValue);
    
    // Demonstrate impact: In NextRound, SupplyCurrentRoundInformation uses the fake value
    await AdvanceToNextRound();
    var round3 = await GetCurrentRound();
    
    // The fake previousInValue was used to calculate Miner B's signature
    // This corrupts the consensus randomness used for mining order
    var minerBInfo = round3.RealTimeMinersInformation[minerB.PublicKey];
    Assert.NotNull(minerBInfo.Signature); // Signature was calculated
    Assert.Equal(fakeInValue, minerBInfo.InValue); // Based on fake value
    
    // Impact: VRF chain is broken - the InValue does not hash to the expected OutValue
    Assert.NotEqual(HashHelper.ComputeFrom(minerBInfo.InValue), minerBActualOutValue);
}
```

## Notes

This vulnerability represents a fundamental gap in the VRF chain validation that the AEDPoS consensus protocol relies upon. While the protocol correctly validates each miner's self-reported `previousInValue`, it fails to validate the revealed values that miners provide for OTHER miners through the secret sharing mechanism.

The attack is particularly concerning because:
1. It targets the consensus layer, affecting the entire network's security
2. It's easily exploitable by any miner without detection
3. It breaks a core cryptographic invariant that shouldn't be bypassable
4. The impact compounds over time as fake values propagate through rounds

The fix requires adding cryptographic validation at the point where `RevealedInValues` are accepted into the state, ensuring that `Hash(revealedInValue) == previousOutValue` holds for all revealed values, not just the sender's own value.

### Citations

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
