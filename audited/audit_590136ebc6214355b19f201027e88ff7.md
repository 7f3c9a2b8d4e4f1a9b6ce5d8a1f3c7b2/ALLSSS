# Audit Report

## Title
Unvalidated RevealedInValues Allow PreviousInValue Poisoning Leading to Miner DoS

## Summary
The AEDPoS consensus contract's `UpdateLatestSecretPieces()` function accepts `RevealedInValues` from block producer trigger information without cryptographic validation and uses them to set other miners' `PreviousInValue` fields. A malicious consensus miner can inject fake revealed values to poison victim miners' `PreviousInValue`, preventing them from successfully producing blocks due to validation failures. This enables targeted denial-of-service attacks against specific miners.

## Finding Description

The vulnerability stems from a missing validation check in the secret sharing mechanism. When a miner produces a block, they provide `RevealedInValues` for other miners in their trigger information. The contract blindly applies these values without verifying their correctness.

**Root Cause**: The `UpdateLatestSecretPieces()` function unconditionally applies `RevealedInValues` from trigger information to other miners' `PreviousInValue` fields: [1](#0-0) 

The trigger information containing these values is created off-chain by the block producer's node software: [2](#0-1) 

**Missing Validation**: The consensus validation only checks the block producer's own `PreviousInValue`, not the `RevealedInValues` they provide for other miners: [3](#0-2) 

Note that line 38 uses `validationContext.SenderPubkey`, validating only the block producer's data.

**Why Protection Fails**: Once a `PreviousInValue` is set (even to a fake value), the `Hash.Empty`/`null` check in `ApplyNormalConsensusData` prevents legitimate updates: [4](#0-3) 

**Propagation Mechanism**: The poisoned values are propagated through the block header via `GetUpdateValueRound`: [5](#0-4) 

And then recovered during validation: [6](#0-5) 

**Attack Execution**:
1. Malicious Miner M modifies their node software to provide fake `RevealedInValues[Victim] = FakeHash`
2. M produces a block when Victim's `PreviousInValue` is `Hash.Empty` (victim missed previous mining)
3. `UpdateLatestSecretPieces` applies `FakeHash` to Victim's `PreviousInValue`
4. Block passes validation (only M's own data is validated)
5. When Victim tries to mine, their correct `PreviousInValue` cannot overwrite `FakeHash` due to the `Hash.Empty` check
6. Victim's block contains the poisoned value in the round data
7. Validation checks `hash(FakeHash)` against Victim's previous `OutValue`, which fails
8. Victim's block is rejected

## Impact Explanation

**Consensus Integrity Impact**: Malicious miners can arbitrarily prevent specific victim miners from producing blocks, directly violating consensus fairness guarantees. The attack enables targeted exclusion of competing miners from block production.

**Economic Impact**: Victim miners lose block production rewards for each rejected block. The `ProducedBlocks` count is not incremented while `MissedTimeSlots` increases, affecting reputation metrics and potentially future mining slot assignments.

**Operational Impact**: Network throughput can be reduced if multiple miners are targeted simultaneously. The attack creates unpredictability in consensus operations and can cascade across rounds if poisoned values propagate via `SupplyCurrentRoundInformation`: [7](#0-6) 

**Affected Parties**: Individual miners who missed mining in previous rounds become vulnerable. The network overall experiences reduced reliability, and token holders may experience delays in transaction finality.

## Likelihood Explanation

**Attacker Capabilities**: The attacker must be an authorized consensus miner (high privilege but within the adversarial threat model for consensus systems). They must modify their node software to inject fake `RevealedInValues` - a simple code change with no cryptographic complexity.

**Attack Complexity**: LOW - The attacker only needs to modify trigger information generation before producing a block. No timing precision or multi-step coordination is required.

**Feasibility Conditions**: 
- Victim must have missed mining in a previous round (common due to network issues, maintenance, restarts, or previous attacks)
- Attacker must produce a block before victim in the subsequent round (probability inversely proportional to miner count)
- Secret sharing must be enabled (configuration-dependent): [8](#0-7) 

**Detection Constraints**: While the attack is theoretically detectable by comparing on-chain `RevealedInValues` with legitimate secret sharing reconstruction, detection is post-facto. No in-contract prevention mechanism exists, and victims have no recourse once poisoned.

**Probability**: MEDIUM-HIGH - Miners routinely miss rounds due to operational issues. Malicious miners in competitive scenarios have strong economic incentives to exclude competitors, with zero cost and direct benefit.

## Recommendation

Add cryptographic validation of `RevealedInValues` in `UpdateLatestSecretPieces()` by reconstructing the expected revealed value using on-chain decrypted pieces and verifying it matches the provided value:

```csharp
foreach (var revealedInValue in triggerInformation.RevealedInValues)
{
    if (!updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
        continue;
        
    var targetMiner = updatedRound.RealTimeMinersInformation[revealedInValue.Key];
    
    // Only update if currently empty
    if (targetMiner.PreviousInValue != Hash.Empty && targetMiner.PreviousInValue != null)
        continue;
    
    // Validate the revealed value using decrypted pieces
    if (TryToGetPreviousRoundInformation(out var previousRound))
    {
        var minerInPreviousRound = previousRound.RealTimeMinersInformation[revealedInValue.Key];
        var minersCount = previousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        
        // Verify sufficient pieces exist
        if (minerInPreviousRound.DecryptedPieces.Count >= minersCount)
        {
            // Reconstruct the in value from decrypted pieces
            var orders = minerInPreviousRound.DecryptedPieces.Select((t, i) =>
                previousRound.RealTimeMinersInformation.Values
                    .First(m => m.Pubkey == minerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();
            
            var sharedParts = minerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();
            
            var expectedRevealedValue = HashHelper.ComputeFrom(
                SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
            
            // Only apply if it matches the expected value
            if (revealedInValue.Value == expectedRevealedValue)
                targetMiner.PreviousInValue = revealedInValue.Value;
        }
    }
}
```

Alternatively, remove the unvalidated `RevealedInValues` path entirely and rely solely on the validated `RevealSharedInValues()` method during round transitions.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanPoisonVictimPreviousInValue()
{
    // Setup: Initialize consensus with multiple miners
    var miners = new[] { "Miner1", "Miner2", "VictimMiner" };
    await InitializeConsensusAsync(miners);
    
    // Round 1: Victim mines successfully
    await VictimMinedSuccessfullyAsync("VictimMiner");
    var victimOutValue = GetMinerOutValue("VictimMiner");
    
    // Round 2: Victim misses their slot (PreviousInValue becomes Hash.Empty)
    await AdvanceRound();
    
    // Malicious miner produces block with fake RevealedInValues
    var fakePreviousInValue = HashHelper.ComputeFrom("fake_value");
    var maliciousTrigger = CreateTriggerWithFakeRevealedValues("Miner1", 
        "VictimMiner", fakePreviousInValue);
    
    // Attacker block passes validation
    var attackerBlock = await ProduceBlockAsync("Miner1", maliciousTrigger);
    Assert.True(attackerBlock.Success);
    
    // Verify victim's PreviousInValue is poisoned
    var victimInfo = await GetMinerInformationAsync("VictimMiner");
    Assert.Equal(fakePreviousInValue, victimInfo.PreviousInValue);
    
    // Round 3: Victim attempts to mine with correct PreviousInValue
    var correctPreviousInValue = GetVictimCorrectPreviousInValue("VictimMiner");
    var victimTrigger = CreateTriggerWithCorrectValue("VictimMiner", correctPreviousInValue);
    
    // Victim's block fails validation because poisoned value cannot be overwritten
    var victimBlock = await ProduceBlockAsync("VictimMiner", victimTrigger);
    Assert.False(victimBlock.Success);
    Assert.Contains("Incorrect previous in value", victimBlock.ValidationMessage);
    
    // Verify hash(fakePreviousInValue) != victimOutValue causes failure
    Assert.NotEqual(HashHelper.ComputeFrom(fakePreviousInValue), victimOutValue);
}
```

**Notes**: 
- This vulnerability requires the attacker to be a consensus miner, which is within scope for consensus security analysis
- The attack is deterministic once preconditions are met (victim has `Hash.Empty` PreviousInValue)
- The comparison with `RevealSharedInValues()` method shows the contract CAN validate revealed values on-chain using secret sharing reconstruction, but this validation is not performed in `UpdateLatestSecretPieces()`
- The poisoning persists until the next round transition when `RevealSharedInValues()` is called (NextRound behavior), potentially lasting many blocks

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L44-52)
```csharp
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L28-29)
```csharp
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-193)
```csharp
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;
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
