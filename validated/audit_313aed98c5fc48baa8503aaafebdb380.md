# Audit Report

## Title
Consensus Takeover via Unvalidated NextTerm Miner List - State Poisoning Leading to Complete Consensus Breach

## Summary
The AEDPoS consensus contract's `NextTerm` method accepts arbitrary miner lists without validating them against the Election contract's authoritative results. A malicious current miner can submit a `NextTerm` transaction with a custom miner list, which gets persisted to StateDb and used for all subsequent mining permission validation, enabling complete consensus takeover.

## Finding Description

The vulnerability exists in the validation and execution pipeline for `NextTerm` consensus transactions, which allows attackers to bypass the democratic election process and inject arbitrary miner lists into the consensus state.

**Validation Gap:**

When a NextTerm transaction is validated, the system only adds `RoundTerminateValidationProvider` to the validation chain. [1](#0-0) 

This provider only validates that round and term numbers increment correctly, not the miner list contents. [2](#0-1) 

**Execution Without Verification:**

The `ProcessNextTerm` method directly converts the input to a Round object and extracts the miner list from it without any Election contract verification. [3](#0-2) 

The miner list is created directly from `nextRound.RealTimeMinersInformation.Keys` and stored to state without cross-referencing the Election contract. [4](#0-3) 

The `SetMinerList` method persists this unvalidated list to both `State.MainChainCurrentMinerList` and `State.MinerListMap[termNumber]`. [5](#0-4) 

**Proper Generation Bypassed:**

While `GenerateFirstRoundOfNextTerm` correctly queries the Election contract's `GetVictories` to obtain legitimate elected miners, this is only used for generating the intended input structure, not for validation. [6](#0-5) 

The Election contract call that retrieves authoritative victories through `State.ElectionContract.GetVictories.Call(new Empty())` is never invoked during the validation or execution of NextTerm transactions. [7](#0-6) 

**Post-Execution Validation Insufficient:**

The `ValidateConsensusAfterExecution` method compares header information against state, but after execution both contain the same malicious miner list, so the comparison passes. [8](#0-7) 

**Future Impact on Mining Permission:**

Subsequent blocks validate mining permission by checking if the miner exists in `BaseRound.RealTimeMinersInformation`, which is loaded from the now-poisoned StateDb. [9](#0-8) 

**Attack Prerequisites:**

The attacker must be a current miner to pass the `PreCheck` authorization, which only verifies the sender is in the current or previous round's miner list. [10](#0-9) 

## Impact Explanation

This vulnerability breaks the fundamental security invariant that only democratically elected miners can participate in consensus, resulting in:

1. **Complete Consensus Takeover**: An attacker replaces the legitimate elected miner list with arbitrary addresses, gaining control over block production for the entire term duration.

2. **Democracy Nullification**: Election results from token holder votes are completely ignored. The Election contract maintains the correct winners, but the consensus contract uses the attacker's fabricated list.

3. **Legitimate Miner DoS**: Properly elected miners cannot produce blocks because the `MiningPermissionValidationProvider` checks against the corrupted `BaseRound`, which doesn't contain their public keys.

4. **Persistent State Poisoning**: The corrupted miner list remains in StateDb for the entire term, affecting all subsequent blocks until the next term transition.

5. **Censorship & MEV Exploitation**: Attacker-controlled miners can censor transactions, reorder blocks for MEV extraction, and manipulate consensus behavior without any checks.

This compromises the entire blockchain's integrity by severing the link between democratic election and consensus participation.

## Likelihood Explanation

**High Feasibility:**

1. **Attacker Pool**: Any current miner can attempt the attack. With typical configurations of 5-21 miners, multiple potential attackers exist.

2. **Frequent Opportunity**: Attackers get a chance at every term boundary (typically every few days based on `periodSeconds` configuration).

3. **Success Probability**: Attacker has approximately 1/N chance of producing the NextTerm block where N is the number of current miners. With N=17, that's ~6% probability per term transition.

4. **Multiple Attempts**: Failed attempts don't expose the attacker identity. They can retry at subsequent term transitions.

5. **Low Technical Barrier**: Attack requires only:
   - Being a current miner (legitimate but malicious insider)
   - Standard transaction crafting capability
   - Modifying the `RealTimeMinersInformation` field in NextTermInput

6. **No Cryptographic Complexity**: No cryptographic breaks, race conditions, or complex timing attacks required. Simple message field modification.

7. **Collusion Amplification**: Multiple malicious miners can coordinate to significantly increase attack success probability.

## Recommendation

Add miner list validation in the `ValidateBeforeExecution` method for NextTerm behavior:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new MinerListValidationProvider()); // NEW
    break;
```

Implement `MinerListValidationProvider` that:
1. Extracts the proposed miner list from `extraData.Round.RealTimeMinersInformation.Keys`
2. Queries `State.ElectionContract.GetVictories.Call(new Empty())` to get authoritative elected miners
3. Compares the two lists and rejects the transaction if they don't match

Additionally, add a runtime check in `ProcessNextTerm` before calling `SetMinerList`:

```csharp
// Verify miner list against Election contract
if (State.IsMainChain.Value && State.ElectionContract.Value != null)
{
    var victories = State.ElectionContract.GetVictories.Call(new Empty());
    var expectedMiners = victories.Value.Select(p => p.ToHex()).OrderBy(p => p).ToList();
    var proposedMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(p => p).ToList();
    
    Assert(expectedMiners.SequenceEqual(proposedMiners), 
        "Proposed miner list does not match Election contract victories.");
}
```

## Proof of Concept

The vulnerability can be demonstrated with a test that:
1. Sets up a blockchain with elected miners from the Election contract
2. Has a current miner craft a NextTerm transaction with modified `RealTimeMinersInformation` containing arbitrary addresses
3. Verifies the transaction is accepted and the malicious miner list is stored
4. Confirms legitimate elected miners are denied mining permission while malicious addresses are granted permission

The test would show that the validation pipeline allows arbitrary miner lists to be injected without cross-checking against the Election contract's `GetVictories` results.

## Notes

This vulnerability represents a complete breakdown of the consensus-election trust model in AElf. The separation between input generation (which correctly queries Election) and validation (which doesn't) creates a critical security gap. The attack is particularly dangerous because it's an insider threat that's difficult to detect until after state poisoning has occurred, and the damage persists for an entire term duration.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-163)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L76-77)
```csharp
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L87-101)
```csharp
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-17)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
```
