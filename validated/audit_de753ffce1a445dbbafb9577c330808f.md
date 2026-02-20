# Audit Report

## Title
Unvalidated Revealed PreviousInValues Allow Malicious Miners to Cause Consensus DoS

## Summary
A malicious miner can inject incorrect `PreviousInValue` data for other miners through the `RevealedInValues` mechanism without cryptographic validation. These unvalidated values are written to consensus state and prevent legitimate miners from producing valid blocks, causing denial-of-service against targeted miners.

## Finding Description

The AEDPoS consensus protocol has a critical validation gap where revealed previous in-values for OTHER miners are written to state without verifying the cryptographic commitment `hash(PreviousInValue) == OutValue`.

**Unvalidated Write Path 1:**

When a miner produces a block, the `UpdateLatestSecretPieces` method processes `RevealedInValues` from trigger information and writes them directly to the Round state if the target miner's `PreviousInValue` is currently empty or null, with NO cryptographic verification. [1](#0-0) 

The method iterates through `triggerInformation.RevealedInValues` and directly assigns values without any hash validation to verify they match the target miner's previous round `OutValue`.

**Unvalidated Write Path 2:**

During transaction execution, the `PerformSecretSharing` method writes `MinersPreviousInValues` dictionary entries directly to state without hash validation. [2](#0-1) 

This method unconditionally sets `PreviousInValue` for any miner included in the `UpdateValueInput.MinersPreviousInValues` dictionary.

**Insufficient Validation:**

The validation provider only checks the SENDER's own `PreviousInValue` by verifying that `hash(PreviousInValue) == OutValue` from the previous round, but does NOT validate the `PreviousInValue` fields for OTHER miners included in the Round object. [3](#0-2) 

The validation checks `validationContext.SenderPubkey` only, meaning it validates the current block producer's own `PreviousInValue`, not those of other miners in the round.

**First-Write-Wins Vulnerability:**

Once an incorrect value is written, the `ApplyNormalConsensusData` method prevents overwriting because it only sets `PreviousInValue` if currently empty or null. [4](#0-3) 

This first-write-wins behavior means that once an attacker poisons a victim's `PreviousInValue`, the victim cannot correct it even with valid trigger information.

**Attack Vector:**

The attack originates from off-chain manipulation of the `SecretSharingService`. The trigger information provider directly includes whatever values are returned by `GetRevealedInValues()` without validation. [5](#0-4) 

A malicious miner modifies their node's `SecretSharingService` to return arbitrary `Hash` values in `GetRevealedInValues()`, which then flow through to the consensus contract without on-chain validation.

**Transaction Generation Propagates Poisoned Values:**

When generating the UpdateValue transaction, the Round's `ExtractInformationToUpdateConsensus` method includes ALL miners' `PreviousInValues` in the transaction input. [6](#0-5) 

This causes poisoned values to be propagated into the `UpdateValueInput.MinersPreviousInValues` dictionary, which is then written to state by `PerformSecretSharing`.

**Complete Attack Flow:**

1. Attacker (miner A) produces a block in round N+1 before victim (miner B)
2. Attacker's modified `SecretSharingService.GetRevealedInValues()` returns `{B: fake_hash}`
3. `UpdateLatestSecretPieces` writes `updatedRound.RealTimeMinersInformation[B].PreviousInValue = fake_hash` to the consensus extra data
4. `GenerateTransactionListByExtraData` extracts this into `UpdateValueInput.MinersPreviousInValues = {B: fake_hash}`
5. `PerformSecretSharing` writes this to state: `round.RealTimeMinersInformation[B].PreviousInValue = fake_hash`
6. When B attempts to produce a block, `currentRound` from state contains the fake value
7. `ApplyNormalConsensusData` does not overwrite (first-write-wins)
8. B's UpdateValue transaction contains the fake `PreviousInValue`
9. Validation fails: `hash(fake_hash) != B's_OutValue_from_round_N`
10. B's block is rejected with "Incorrect previous in value" error

## Impact Explanation

**Consensus Disruption:**
A malicious miner can prevent targeted miners from participating in consensus by corrupting their `PreviousInValue` in state. When the victim attempts to produce a block, the validation performed by `UpdateValueValidationProvider` checks whether `hash(corrupted_PreviousInValue) == victim's_previous_OutValue`, which fails, causing the block to be rejected.

**Affected Parties:**
- **Targeted miners**: Cannot produce valid blocks until the round transitions, losing mining rewards and reputation
- **Network**: Reduced active miner count degrades consensus liveness and security  
- **Chain security**: If multiple miners are targeted simultaneously, consensus could experience significant disruption

**Duration and Recovery:**
The attack is limited to one round because new rounds do not copy `PreviousInValue` from the previous round. [7](#0-6) 

When `GenerateNextRoundInformation` creates a new `MinerInRound` object, it does not include the `PreviousInValue` field, meaning poisoned values are not carried forward to subsequent rounds.

**Severity:** Medium - Requires malicious miner (mis-scoped privilege), affects consensus integrity (critical system), limited to DoS (no fund theft), detectable through monitoring, recoverable through round transitions.

## Likelihood Explanation

**Attacker Capabilities:**
Must be an active miner in the current round to produce blocks with UpdateValue behavior and include `RevealedInValues` in trigger information.

**Attack Complexity:**
Straightforward execution - attacker modifies their off-chain node's `SecretSharingService` implementation to return arbitrary values in `GetRevealedInValues()`. Since this is an off-chain service injected via dependency injection, a malicious miner can easily override the implementation. [8](#0-7) 

The service returns values from an in-memory dictionary with no cryptographic proof required.

**Feasibility Conditions:**
1. Attacker must produce a block before the victim in round N+1 (timing dependent but achievable)
2. Victim's `PreviousInValue` must not yet be set in state (first-write-wins vulnerability)
3. Secret sharing must be enabled in the consensus configuration (checked by `IsSecretSharingEnabled()`)

**Probability:** Medium - requires compromised/malicious miner but attack execution is reliable once conditions are met.

## Recommendation

**Fix 1: Validate Revealed InValues On-Chain**

Add cryptographic validation in `UpdateLatestSecretPieces` to verify that each revealed in-value is correct:

```csharp
foreach (var revealedInValue in triggerInformation.RevealedInValues)
{
    if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
        (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
         updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
    {
        // Add validation: check that hash(revealedInValue) matches previous round's OutValue
        if (TryToGetPreviousRoundInformation(out var prevRound) && 
            prevRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
        {
            var expectedOutValue = prevRound.RealTimeMinersInformation[revealedInValue.Key].OutValue;
            if (HashHelper.ComputeFrom(revealedInValue.Value) == expectedOutValue)
            {
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
            }
        }
    }
}
```

**Fix 2: Validate MinersPreviousInValues in PerformSecretSharing**

Add similar validation in `PerformSecretSharing` before writing to state:

```csharp
foreach (var previousInValue in input.MinersPreviousInValues)
{
    // Only accept if we can verify it's correct
    if (TryToGetPreviousRoundInformation(out var prevRound) &&
        prevRound.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
    {
        var expectedOutValue = prevRound.RealTimeMinersInformation[previousInValue.Key].OutValue;
        if (HashHelper.ComputeFrom(previousInValue.Value) == expectedOutValue)
        {
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
        }
    }
}
```

**Fix 3: Extend Validation Provider**

Modify `UpdateValueValidationProvider` to validate ALL miners' `PreviousInValues` in the Round object, not just the sender's.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanInjectFakePreviousInValue_CausesVictimBlockRejection()
{
    // Setup: Initialize consensus with 3 miners
    var miners = new[] { "MinerA", "MinerB", "MinerC" };
    await InitializeConsensusAsync(miners);
    
    // Round N: All miners produce blocks normally
    await ProduceNormalRound(miners);
    var roundN = await GetCurrentRoundAsync();
    var minerBOutValue = roundN.RealTimeMinersInformation["MinerB"].OutValue;
    
    // Round N+1: Attacker (MinerA) produces first with malicious RevealedInValues
    var fakeHash = HashHelper.ComputeFrom("fake_value");
    var maliciousTrigger = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFromUtf8("MinerA"),
        Behaviour = AElfConsensusBehaviour.UpdateValue,
        RevealedInValues = { { "MinerB", fakeHash } } // Inject fake value for MinerB
    };
    
    await ProduceBlockAsync("MinerA", maliciousTrigger);
    
    // Verify: MinerB's PreviousInValue is now poisoned in state
    var roundN1 = await GetCurrentRoundAsync();
    Assert.Equal(fakeHash, roundN1.RealTimeMinersInformation["MinerB"].PreviousInValue);
    
    // Attempt: MinerB tries to produce block with correct PreviousInValue
    var victimTrigger = await GetNormalTriggerForMinerAsync("MinerB");
    var result = await ProduceBlockAsync("MinerB", victimTrigger);
    
    // Assert: Block is rejected due to validation failure
    Assert.False(result.Success);
    Assert.Contains("Incorrect previous in value", result.Message);
    
    // Verify: hash(fakeHash) != minerBOutValue (validation check that fails)
    Assert.NotEqual(HashHelper.ComputeFrom(fakeHash), minerBOutValue);
}
```

## Notes

This vulnerability exploits the trust assumption that miners will honestly execute the secret sharing protocol. The current implementation assumes `RevealedInValues` are correctly reconstructed via Shamir's Secret Sharing, but does not enforce this cryptographically on-chain. A malicious miner can bypass the off-chain reconstruction and inject arbitrary values, which are then trusted by the consensus contract.

The attack is temporary (limited to one round) but can cause significant disruption if multiple miners are targeted simultaneously or if the attack is repeated across rounds. The fix requires adding cryptographic validation to ensure all revealed in-values match the commitment (`OutValue`) from the previous round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L14-16)
```csharp
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L112-114)
```csharp
            var revealedInValues = _secretSharingService.GetRevealedInValues(hint.RoundId);
            foreach (var revealedInValue in revealedInValues)
                trigger.RevealedInValues.Add(revealedInValue.Key, revealedInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L84-93)
```csharp
    public Dictionary<string, Hash> GetRevealedInValues(long roundId)
    {
        _revealedInValues.TryGetValue(roundId, out var revealedInValues);
        Logger.LogDebug($"[GetRevealedInValues]Round id: {roundId}");
        if (revealedInValues != null)
            Logger.LogDebug($"Revealed {revealedInValues.Count} in values for round of id {roundId}");

        _revealedInValues.Remove(roundId);
        return revealedInValues ?? new Dictionary<string, Hash>();
    }
```
