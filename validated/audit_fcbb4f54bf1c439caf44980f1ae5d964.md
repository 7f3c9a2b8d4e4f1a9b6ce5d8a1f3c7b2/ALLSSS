# Audit Report

## Title
Unvalidated MinersPreviousInValues Allows Consensus DoS via PreviousInValue Poisoning

## Summary
The AEDPoS consensus contract's `PerformSecretSharing()` function unconditionally writes attacker-supplied `MinersPreviousInValues` to on-chain state without cryptographic validation. This allows any active miner to poison other miners' `PreviousInValue` fields, causing victim blocks to fail validation and disrupting network consensus.

## Finding Description

The vulnerability stems from three interconnected flaws in the secret sharing mechanism:

**Flaw 1: Unconditional State Overwrite** [1](#0-0) 

The `PerformSecretSharing()` method iterates through all entries in `input.MinersPreviousInValues` and unconditionally writes them to the round state without any validation that these values correctly hash to the respective miners' previous `OutValue` fields.

**Flaw 2: Defensive Check Prevents Correction** [2](#0-1) 

The `ApplyNormalConsensusData()` function only sets `PreviousInValue` if it's currently `Hash.Empty` or `null`. This defensive check, intended to preserve already-set values, prevents victim miners from overwriting poisoned values with correct ones during their block generation phase.

**Flaw 3: Insufficient Validation Scope** [3](#0-2) 

The `UpdateValueValidationProvider.ValidatePreviousInValue()` method only validates the **sender's own** `PreviousInValue` by checking `validationContext.SenderPubkey`. It does not validate the `MinersPreviousInValues` entries for other miners that get written to state via `PerformSecretSharing()`.

**Attack Execution Flow:**

1. Malicious miner generates a block with modified consensus data containing poisoned `MinersPreviousInValues[VictimPubkey] = WrongHash` in both the block header Round data [4](#0-3)  and the UpdateValue transaction [5](#0-4) 

2. During validation, `UpdateValueValidationProvider` only checks the attacker's own `PreviousInValue`, allowing the poisoned values for other miners to pass

3. When `ProcessUpdateValue` executes [6](#0-5) , it calls `PerformSecretSharing` which writes the poisoned values to state

4. When the victim miner attempts to produce their next block:
   - They load the current round containing the poisoned `PreviousInValue`
   - The poisoned value is not overwritten due to the empty/null check in `ApplyNormalConsensusData`
   - Their block header contains the incorrect `PreviousInValue`
   - Validation fails: `HashHelper.ComputeFrom(previousInValue) != previousOutValue`
   - Block is rejected

## Impact Explanation

This vulnerability enables **critical consensus disruption**:

- **Individual Miner DoS**: Targeted miners cannot produce valid blocks for the remainder of the current round, losing all block rewards and transaction fees during that period
- **Cascading Network Impact**: A single malicious block can poison multiple miners simultaneously, as `MinersPreviousInValues` is a map supporting multiple entries
- **Consensus Degradation**: If a significant portion of miners are poisoned (e.g., more than 1/3), the network's consensus liveness is compromised
- **No Self-Recovery Mechanism**: Poisoned miners cannot fix their state themselves; they must wait for a round/term transition to reset their consensus data
- **Invariant Violation**: The fundamental security guarantee that "miners can only update their own consensus data" is broken, allowing arbitrary corruption of other miners' state

The severity is **HIGH** because this directly attacks the consensus layer's integrity, potentially halting block production network-wide.

## Likelihood Explanation

The attack has **HIGH likelihood**:

**Attacker Prerequisites:**
- Must be an active miner (achievable through normal staking and election processes)
- No elevated privileges beyond standard miner status required

**Technical Feasibility:**
- Miners control their own node software and can modify block data before signing
- Attack requires only modifying the `MinersPreviousInValues` field in the UpdateValue transaction and corresponding block header Round data
- No timing constraints, race conditions, or complex multi-transaction orchestration needed
- Deterministic success with no failure paths

**Economic Viability:**
- Cost is merely standard transaction fees (negligible)
- Potential benefits: eliminate competing miners to capture more rewards, extort the network, or disrupt specific competitors
- Risk-reward ratio heavily favors the attacker

**Detection Challenges:**
- Poisoned values are visible on-chain but indistinguishable from legitimate secret-sharing revelations without off-chain correlation analysis
- No built-in monitoring, alerting, or automatic defense mechanisms

The attack is continuously exploitable whenever secret sharing is enabled, which is a core operational feature of AEDPoS consensus.

## Recommendation

Implement comprehensive validation of `MinersPreviousInValues` entries in the `UpdateValueValidationProvider`:

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;
    
    // Validate sender's own PreviousInValue (existing logic)
    if (validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey))
    {
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue != null &&
            extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue != Hash.Empty)
        {
            var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
            var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
            if (HashHelper.ComputeFrom(previousInValue) != previousOutValue)
                return false;
        }
    }
    
    // **NEW: Validate ALL miners' PreviousInValues in the round data**
    foreach (var minerInfo in extraData.Round.RealTimeMinersInformation)
    {
        if (minerInfo.Key == publicKey) continue; // Already validated above
        
        if (minerInfo.Value.PreviousInValue != null && 
            minerInfo.Value.PreviousInValue != Hash.Empty &&
            validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(minerInfo.Key))
        {
            var expectedOutValue = validationContext.PreviousRound.RealTimeMinersInformation[minerInfo.Key].OutValue;
            if (HashHelper.ComputeFrom(minerInfo.Value.PreviousInValue) != expectedOutValue)
                return false; // Reject block with invalid other miner's PreviousInValue
        }
    }
    
    return true;
}
```

Additionally, modify `PerformSecretSharing` to validate entries before writing:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round, Round previousRound, string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);

    // **VALIDATE before writing to state**
    foreach (var previousInValue in input.MinersPreviousInValues)
    {
        if (previousRound != null && 
            previousRound.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
        {
            var expectedOutValue = previousRound.RealTimeMinersInformation[previousInValue.Key].OutValue;
            if (HashHelper.ComputeFrom(previousInValue.Value) == expectedOutValue)
            {
                round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
            }
            // Silently skip invalid entries
        }
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanPoisonVictimPreviousInValue()
{
    // Setup: Initialize consensus with 3 miners
    var initialMiners = new List<string> {"Miner1", "Miner2", "Victim"};
    await InitializeConsensus(initialMiners);
    
    // Round 1: All miners mine normally to establish previous OutValues
    await ProduceNormalBlock("Miner1");
    await ProduceNormalBlock("Miner2");
    await ProduceNormalBlock("Victim"); // Victim produces block, OutValue recorded
    
    // Round 2: Miner1 acts maliciously
    var currentRound = await GetCurrentRound();
    var victimPreviousOutValue = currentRound.RealTimeMinersInformation["Victim"].OutValue;
    
    // Attacker modifies MinersPreviousInValues to include wrong hash for victim
    var wrongHash = HashHelper.ComputeFrom("WRONG_VALUE");
    var maliciousInput = CreateMaliciousUpdateValueInput("Miner1", new Dictionary<string, Hash>
    {
        {"Victim", wrongHash} // Poisoned value - does NOT hash to victimPreviousOutValue
    });
    
    // Malicious block gets accepted (validation only checks Miner1's own value)
    await SubmitUpdateValueBlock("Miner1", maliciousInput);
    
    // Verify poisoned state was written
    var poisonedRound = await GetCurrentRound();
    Assert.Equal(wrongHash, poisonedRound.RealTimeMinersInformation["Victim"].PreviousInValue);
    
    // Victim attempts to mine next block
    var victimBlockResult = await AttemptProduceBlock("Victim");
    
    // **Proof of vulnerability: Victim's block is REJECTED**
    Assert.False(victimBlockResult.Success);
    Assert.Contains("Incorrect previous in value", victimBlockResult.ValidationError);
    
    // Victim cannot recover until round transition
    Assert.False(await CanMinerProduceValidBlock("Victim"));
}
```

## Notes

The vulnerability requires miners to control their node software (expected in DPoS systems). While the block signature ensures authenticity of the block producer, it does not validate the semantic correctness of the `MinersPreviousInValues` field for other miners. The fix must enforce cryptographic validation that `Hash(PreviousInValue) == PreviousOutValue` for ALL miners listed in the consensus data, not just the sender.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L14-16)
```csharp
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-48)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L51-51)
```csharp
                    PreviousInValue = information.Value.PreviousInValue
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```
