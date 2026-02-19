# Audit Report

## Title
Unvalidated MinersPreviousInValues Allows Consensus DoS via PreviousInValue Poisoning

## Summary
The `PerformSecretSharing()` function unconditionally accepts and writes attacker-supplied `MinersPreviousInValues` to on-chain state without validating their correctness. This allows any miner to poison other miners' `PreviousInValue` fields, causing victim blocks to fail validation and disrupting consensus.

## Finding Description

The vulnerability exists due to three interconnected design flaws in the AEDPoS consensus mechanism:

**1. Unconditional State Overwrite:** [1](#0-0) 

The `PerformSecretSharing()` function unconditionally writes all entries from `input.MinersPreviousInValues` to the on-chain round state with no validation that these values correctly hash to miners' previous `OutValue` fields.

**2. Defensive Check Becomes Attack Vector:** [2](#0-1) 

The `ApplyNormalConsensusData()` function only sets `PreviousInValue` if it's currently empty or null. This defensive check, intended to preserve already-set values, prevents victim miners from overwriting poisoned values with correct ones during block generation.

**3. Insufficient Validation Scope:** [3](#0-2) 

The `UpdateValueValidationProvider` only validates the **sender's own** `PreviousInValue` (line 38: `var publicKey = validationContext.SenderPubkey`). It does not validate the `MinersPreviousInValues` map that updates other miners' values.

**Attack Execution:**

A malicious miner can:
1. Produce an `UpdateValue` block with `input.MinersPreviousInValues[VictimPubkey] = WrongHash`
2. The on-chain execution via `ProcessUpdateValue` calls `PerformSecretSharing`, which writes the wrong value to state [4](#0-3) 

3. When the victim miner generates their next block:
   - They load the current round from state (containing the poisoned value)
   - Call `GetConsensusExtraDataToPublishOutValue` which invokes `ApplyNormalConsensusData` with their correct `PreviousInValue` [5](#0-4) 
   
   - But the poisoned value is not overwritten due to the empty/null check
   - The victim's block header contains the wrong `PreviousInValue`

4. During validation, the incorrect value fails the hash check, causing block rejection

**Additional Impact Path:** [6](#0-5) 

If the victim doesn't mine, `SupplyCurrentRoundInformation` uses their poisoned `PreviousInValue` to calculate their signature for the next round, further corrupting consensus state.

## Impact Explanation

This vulnerability enables **high-severity consensus disruption**:

- **Individual Miner DoS**: Targeted miners cannot produce valid blocks for the remainder of the current round
- **Network-Wide Impact**: An attacker can poison multiple miners simultaneously via a single malicious block
- **Revenue Loss**: Victim miners lose block rewards and transaction fees
- **Consensus Degradation**: If sufficient miners are targeted, the network cannot maintain consensus, leading to chain halts
- **No Self-Recovery**: Victims cannot fix the poisoned state themselves; recovery requires round/term transition

The attack breaks the fundamental security guarantee that miners can only update their own consensus data, allowing arbitrary corruption of other miners' state.

## Likelihood Explanation

The attack has **HIGH likelihood**:

**Attacker Prerequisites:**
- Must be an active miner (achievable via staking/election)
- No special privileges required beyond normal miner status

**Execution Simplicity:**
- Attack requires only modifying the `MinersPreviousInValues` field in a single `UpdateValue` transaction
- No timing constraints or complex coordination needed
- Deterministic success with no failure conditions

**Economic Feasibility:**
- Cost is merely transaction fees (negligible)
- Potential benefit: eliminate competing miners, extort network, or disrupt competitors

**Detection Difficulty:**
- Malicious values are visible on-chain but not easily distinguished from legitimate secret-sharing reveals
- No built-in monitoring or alerting mechanisms exist

The attack is feasible whenever secret sharing is enabled (a core AEDPoS feature), making it continuously exploitable.

## Recommendation

Implement validation of `MinersPreviousInValues` entries in `PerformSecretSharing`:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);

    // FIX: Validate each MinersPreviousInValues entry before writing
    foreach (var previousInValue in input.MinersPreviousInValues)
    {
        var targetPubkey = previousInValue.Key;
        var providedInValue = previousInValue.Value;
        
        // Skip if trying to set empty value
        if (providedInValue == null || providedInValue == Hash.Empty)
            continue;
            
        // Get previous round to validate
        if (TryToGetPreviousRound(out var previousRound) && 
            previousRound.RealTimeMinersInformation.ContainsKey(targetPubkey))
        {
            var expectedOutValue = previousRound.RealTimeMinersInformation[targetPubkey].OutValue;
            
            // Only set if the hash matches the previous OutValue
            if (HashHelper.ComputeFrom(providedInValue) == expectedOutValue)
            {
                round.RealTimeMinersInformation[targetPubkey].PreviousInValue = providedInValue;
            }
            // Otherwise silently skip invalid entry
        }
    }
}
```

Alternatively, restrict `MinersPreviousInValues` updates to only allow setting the **sender's own** value, with other miners' values populated only through cryptographic secret-sharing reveals.

## Proof of Concept

A malicious miner can execute this attack by:

1. Modifying their node to call `GetConsensusExtraData` and obtain the current round state
2. Before calling `ExtractInformationToUpdateConsensus`, injecting malicious entries:
   ```csharp
   updatedRound.RealTimeMinersInformation[victimPubkey].PreviousInValue = HashHelper.ComputeFrom("wrong_value");
   ```
3. Generating the `UpdateValueInput` from the modified round
4. Submitting the malicious `UpdateValue` transaction in their block

The poisoned value will be written to state via `PerformSecretSharing`, and the victim's subsequent block will fail validation when their `PreviousInValue` doesn't match their previous round's `OutValue`.

**Notes:**
- This vulnerability requires the attacker to be an active miner in the consensus set
- The attack is particularly effective because there is no validation that would detect or prevent malicious `MinersPreviousInValues` entries before they corrupt state
- Recovery requires waiting for a round or term transition, during which the victim cannot participate in consensus

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
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
