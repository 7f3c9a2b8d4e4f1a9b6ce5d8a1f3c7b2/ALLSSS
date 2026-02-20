# Audit Report

## Title
Unvalidated RevealedInValues Allow PreviousInValue Poisoning Leading to Miner DoS

## Summary
The `UpdateLatestSecretPieces()` function accepts `RevealedInValues` from off-chain trigger information without cryptographic validation, allowing malicious consensus miners to poison victim miners' `PreviousInValue` state. The poisoned state causes subsequent block validation failures, enabling targeted denial-of-service attacks against specific miners.

## Finding Description

The vulnerability exists in the secret sharing mechanism where miners provide consensus trigger information during block production. The `UpdateLatestSecretPieces()` function directly trusts `RevealedInValues` from this off-chain input without validation: [1](#0-0) 

The trigger information originates from the miner's off-chain node through deserialization: [2](#0-1) 

**Critical Validation Gap:** Block validation only verifies the block producer's own `PreviousInValue`, NOT the `RevealedInValues` used to set other miners' state: [3](#0-2) 

**Why Victims Cannot Recover:** Once `PreviousInValue` is set to a fake value, the conditional check in `ApplyNormalConsensusData` prevents legitimate updates: [4](#0-3) 

**Attack Execution Flow:**
1. Victim miner V misses mining in Round N, leaving `PreviousInValue = Hash.Empty` for Round N+1
2. Malicious miner M modifies their off-chain node to inject `RevealedInValues[V] = FakeHash`
3. M produces a block in Round N+1 before V mines
4. `UpdateLatestSecretPieces` sets V's `PreviousInValue = FakeHash` without validation
5. M's block passes validation (only M's own value is checked)
6. When V attempts to mine, `ApplyNormalConsensusData` skips updating the poisoned value (not `Hash.Empty`)
7. V's block validation fails: `Hash(FakeHash) ≠ V's previous OutValue`
8. V's block is rejected, causing missed time slot and lost rewards

The poisoned value propagates through subsequent operations including `ProcessUpdateValue`: [5](#0-4) 

## Impact Explanation

**HIGH Severity**

**Consensus Integrity Impact:**
- Breaks consensus fairness guarantee that honest miners can produce blocks during assigned time slots
- Enables targeted denial-of-service against specific miners without detection
- Disrupts predictable miner schedule and consensus reliability
- Undermines Byzantine fault tolerance assumptions

**Economic Impact:**
- Victim miners lose block production rewards for rejected blocks
- `MissedTimeSlots` counter increases, affecting reputation metrics
- Future mining slot assignments and profitability negatively impacted
- Attacker gains competitive advantage by eliminating rivals

**Operational Impact:**
- Network experiences reduced block production rate if multiple miners targeted
- Transaction finality and throughput uncertainty
- Poisoned state persists across rounds until miner list changes

**Affected Parties:**
- Individual consensus miners experiencing temporary failures (common operational scenario)
- Network through reduced consensus availability
- Token holders through transaction delays

## Likelihood Explanation

**MEDIUM Likelihood**

**Attacker Requirements:**
- Must be authorized consensus miner (high privilege but realistic in Byzantine threat model)
- Ability to modify node software (feasible - off-chain code under miner's control)
- No cryptographic capabilities required beyond miner set membership

**Attack Complexity:**
- LOW - Simple off-chain trigger information modification
- No precise timing required beyond producing block before victim in same round
- No multi-step coordination needed

**Preconditions:**
- Victim must miss mining in previous round (COMMON due to network latency, maintenance, restarts)
- Attacker produces block before victim in subsequent round (probability ~1/N where N = miner count)
- Secret sharing enabled (configurable feature): [6](#0-5) 

**Economic Incentives:**
- Strong competitive incentive to exclude rival miners
- Zero cost to attacker (software-only modification)
- Immediate benefit through reduced competition for block rewards

## Recommendation

Implement cryptographic validation of `RevealedInValues` before accepting them. The contract should verify that revealed values are consistent with the secret sharing reconstruction:

1. **Add validation in `UpdateLatestSecretPieces`**: Before setting `PreviousInValue`, verify the revealed value matches what can be reconstructed from available decrypted pieces using the existing `SecretSharingHelper.DecodeSecret` logic

2. **Reference the existing validation pattern**: Use similar cryptographic checks as in `RevealSharedInValues`: [7](#0-6) 

3. **Alternative mitigation**: Only allow miners to set their own `PreviousInValue` through authenticated trigger information, or require threshold signatures on `RevealedInValues` from multiple miners

4. **Additional protection**: Add mechanism for miners to self-correct poisoned `PreviousInValue` by providing valid proof

## Proof of Concept

A complete PoC requires multi-miner test environment setup with the following components:

```csharp
// Conceptual test outline - would need full AEDPoS test infrastructure
[Fact]
public async Task MaliciousMinerCanPoisonVictimPreviousInValue()
{
    // 1. Setup: Multiple miners in consensus
    // 2. Victim miner misses round N
    // 3. Attacker creates trigger info with fake RevealedInValues[victim] = fakeHash
    // 4. Attacker mines block - UpdateLatestSecretPieces accepts fake value
    // 5. Verify: Victim's PreviousInValue is set to fakeHash
    // 6. Victim attempts to mine with legitimate PreviousInValue
    // 7. Assert: Victim's block fails validation (Hash(fakeHash) != victim's previous OutValue)
    // 8. Assert: Victim cannot produce valid block, loses mining slot
}
```

The vulnerability is confirmed through code analysis showing:
- No validation of `RevealedInValues` in `UpdateLatestSecretPieces`
- Validation only covers block producer's own `PreviousInValue`
- `ApplyNormalConsensusData` prevents correction once poisoned
- Realistic attack path with Byzantine miner capability

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L15-16)
```csharp
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L14-16)
```csharp
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L263-264)
```csharp
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

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
