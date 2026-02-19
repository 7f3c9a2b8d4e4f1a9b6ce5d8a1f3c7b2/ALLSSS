### Title
First-Write-Wins Race Condition Allows Permanent Miner DoS via Malicious PreviousInValue Injection

### Summary
A malicious miner can permanently disrupt consensus by injecting incorrect `PreviousInValue` for other miners through unvalidated `RevealedInValues` in trigger information. The first-write-wins protection in `ApplyNormalConsensusData()` only guards the in-memory Round object during generation but does not prevent state pollution. Once an attacker sets a victim's `PreviousInValue` first, the victim cannot produce valid blocks because validation will fail when `hash(incorrect_value) ≠ actual_OutValue`.

### Finding Description

The vulnerability exists in the consensus data generation and state update flow:

**Root Cause #1: Unvalidated RevealedInValues** [1](#0-0) 

When generating consensus extra data for `UpdateValue` behavior, `UpdateLatestSecretPieces()` accepts arbitrary values from `triggerInformation.RevealedInValues` without cryptographic verification. While it has first-write-wins protection checking if the target miner's `PreviousInValue` is `Hash.Empty` or `null`, this only prevents overwriting within the Round object being generated, not the state.

**Root Cause #2: First-Write-Wins Only in Generation Path** [2](#0-1) 

The first-write-wins check in `ApplyNormalConsensusData()` operates on the in-memory Round object loaded from state. If an attacker has already poisoned the state with an incorrect value, legitimate miners loading this Round object will see the incorrect value (not `Hash.Empty`), causing the check to prevent updating to the correct value.

**Root Cause #3: State Update Without First-Write-Wins** [3](#0-2) 

When `UpdateValue` transactions execute, `PerformSecretSharing()` applies all values from `MinersPreviousInValues` directly to the state without any first-write-wins check. This overwrites existing values unconditionally.

**Root Cause #4: Values Extracted from Poisoned State** [4](#0-3) 

The `MinersPreviousInValues` included in `UpdateValueInput` is extracted from the Round object generated for that block. If the state already contains an incorrect value set by an attacker, this incorrect value propagates into the transaction and back into state.

**Why Protection Fails:**

The validation only checks the sender's own `PreviousInValue`: [5](#0-4) 

This validates that `hash(sender's PreviousInValue) == sender's previous OutValue` but does NOT validate the values in `MinersPreviousInValues` for other miners. An attacker can include arbitrary values for other miners, which get applied to state via `PerformSecretSharing()`.

### Impact Explanation

**Consensus Disruption:**
Once an attacker sets an incorrect `PreviousInValue` for a victim miner, the victim experiences permanent inability to produce valid blocks for that round:

1. When the victim calls `GetConsensusBlockExtraData()`, they load the Round from state containing the attacker's incorrect value
2. `ApplyNormalConsensusData()` sees the value is already set (not Empty), so first-write-wins prevents updating to the correct value
3. The victim's consensus data uses the incorrect value
4. Validation fails because `hash(incorrect_value) ≠ victim's_actual_OutValue` from previous round
5. Block rejection occurs, victim cannot participate in consensus

**Who Is Affected:**
- Target miner loses block rewards for the entire round
- Network consensus stability degraded if multiple miners targeted
- With sufficient coordination, attacker could target all other miners, monopolizing block production

**Severity Justification:**
- **High Impact**: Direct consensus disruption, miner DoS, potential reward theft through monopolization
- **Moderate Likelihood**: Requires attacker to be in miner list and produce blocks before victims, realistic in multi-miner scenarios
- **Critical Invariant Violation**: "Correct round transitions and miner schedule integrity" broken

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an authorized miner (verified by `PreCheck()` in consensus transaction processing) [6](#0-5) 

**Attack Complexity:**
1. **Low Complexity**: Attacker simply includes malicious `RevealedInValues` in their trigger information when calling `GetConsensusExtraData()`
2. **No cryptographic bypass needed**: The contract accepts unvalidated values
3. **No economic cost**: Standard block production

**Feasibility Conditions:**
- Attack window exists at round transition when all `PreviousInValue` fields reset to empty
- Attacker must produce a block before the target victim produces their first block in the new round
- In a network with N miners, attacker has ~1/N chance of producing the first block, but can target all other (N-1) miners in that block

**Detection/Operational Constraints:**
- Difficult to detect as malicious vs. incorrect secret sharing reconstruction
- Victim appears to have incorrect consensus data, not obviously an attack
- No on-chain mechanism for victims to dispute or recover

**Probability Reasoning:**
In typical AEDPoS operation with ~20 miners, an attacker has a reasonable chance of producing early blocks in each round. A coordinated attacker could systematically target different miners across rounds, accumulating significant disruption over time.

### Recommendation

**Immediate Mitigation:**

1. **Add cryptographic validation of revealed in values** in `UpdateLatestSecretPieces()`:

```csharp
// In UpdateLatestSecretPieces, before applying revealed values:
foreach (var revealedInValue in triggerInformation.RevealedInValues)
{
    if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
    {
        var targetMiner = updatedRound.RealTimeMinersInformation[revealedInValue.Key];
        
        // Validate using decrypted pieces if available
        if (targetMiner.DecryptedPieces.Count >= minimumThreshold)
        {
            var reconstructed = ReconstructFromPieces(targetMiner.DecryptedPieces);
            if (reconstructed != revealedInValue.Value)
            {
                // Reject invalid revealed value
                continue;
            }
        }
        
        // Apply first-write-wins check
        if (targetMiner.PreviousInValue == Hash.Empty || targetMiner.PreviousInValue == null)
            targetMiner.PreviousInValue = revealedInValue.Value;
    }
}
```

2. **Add first-write-wins protection in state update** (`PerformSecretSharing()`):

```csharp
foreach (var previousInValue in input.MinersPreviousInValues)
{
    // Only set if not already set
    if (round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue == Hash.Empty ||
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue == null)
    {
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
}
```

3. **Add validation that revealed values match expected OutValue hash** from previous round when setting `PreviousInValue` for other miners.

**Test Cases:**
- Test that attacker cannot inject incorrect `PreviousInValue` via `RevealedInValues`
- Test that first miner to set `PreviousInValue` wins, subsequent attempts rejected
- Test that victim can still produce valid blocks if attacker attempts injection
- Test secret sharing reconstruction validation logic

### Proof of Concept

**Initial State:**
- Round N completed, Miner A published `OutValue_A = hash(InValue_A)`
- Round N+1 starts, all `PreviousInValue` fields are `Hash.Empty`
- Attacker (Miner B) and Victim (Miner A) are both in the miner list

**Attack Sequence:**

**Step 1**: Attacker Miner B produces first block in Round N+1
- Trigger information includes: `RevealedInValues = {MinerA: IncorrectHash}`
- Where `IncorrectHash ≠ InValue_A` (arbitrary malicious value)
- `UpdateLatestSecretPieces()` accepts this value (no validation)
- State updated: `State.Rounds[N+1].RealTimeMinersInformation[MinerA].PreviousInValue = IncorrectHash`

**Step 2**: Victim Miner A attempts to produce block later in Round N+1
- Miner A calls `GetConsensusBlockExtraData()` with correct `previousInValue = InValue_A`
- Loads Round from state: `currentRound.RealTimeMinersInformation[MinerA].PreviousInValue = IncorrectHash` (already set!)
- `ApplyNormalConsensusData()` checks first-write-wins: value is not Empty, so does NOT update to correct `InValue_A`
- Generated `UpdateValueInput.PreviousInValue = IncorrectHash`
- Block produced with incorrect value

**Step 3**: Validation Failure
- `ValidateConsensusBeforeExecution()` → `UpdateValueValidationProvider.ValidatePreviousInValue()`
- Checks: `hash(IncorrectHash) == OutValue_A` from Round N?
- Result: **FALSE** (IncorrectHash is arbitrary, doesn't match)
- Block rejected with: "Incorrect previous in value"

**Expected Result**: Miner A should be able to set their own `PreviousInValue` to the correct value and produce valid blocks

**Actual Result**: Miner A permanently blocked from producing valid blocks in Round N+1 due to first-write-wins race condition

**Success Condition**: Attacker successfully prevents victim from block production for entire round, potential reward theft if attacker monopolizes remaining block production slots.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L14-16)
```csharp
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
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
