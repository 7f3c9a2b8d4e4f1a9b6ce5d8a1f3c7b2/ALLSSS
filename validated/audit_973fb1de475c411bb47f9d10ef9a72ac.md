# Audit Report

## Title
Malicious Miner Can Halt Blockchain by Calling NextTerm with Empty Miner List

## Summary
A malicious authorized miner can permanently halt the AElf blockchain by submitting a `NextTerm` transaction with an empty `RealTimeMinersInformation` dictionary. This bypasses all validation checks and sets an empty miner list, preventing all miners from producing subsequent blocks because the consensus command generation fails when no miners exist in the round.

## Finding Description

The vulnerability exists in the term transition logic of the AEDPoS consensus contract. The security guarantee that should be maintained is: **the miner list for any term must contain at least one miner to enable block production**.

### Attack Vector

1. **Entry Point**: The `NextTerm` method is a public method that accepts `NextTermInput` and processes consensus information without validating that the miner list is non-empty. [1](#0-0) 

2. **Insufficient Authorization**: The `PreCheck()` method only validates that the transaction sender is in the current or previous miner list, but does NOT validate the content of the `NextTermInput` parameter. [2](#0-1) 

3. **Validation Gap**: The `RoundTerminateValidationProvider` validates round and term number increments, but the critical check `extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)` returns false when the dictionary is empty (vacuous truth - no values means none have InValue != null), allowing validation to pass with `Success = true`. [3](#0-2) 

4. **Unchecked State Corruption**: In `ProcessNextTerm`, the miner list is created from `nextRound.RealTimeMinersInformation.Keys` without validation. An empty dictionary produces an empty `MinerList`. [4](#0-3) 

5. **No Bounds Check**: The `SetMinerList` method directly sets the state variables without any validation that the list contains at least one miner. [5](#0-4) 

6. **Consensus Failure**: When miners attempt to get a consensus command, `GetConsensusCommand` checks if the miner pubkey is in the current round's miner list. [6](#0-5) 

The `IsInMinerList` method returns `RealTimeMinersInformation.Keys.Contains(pubkey)`. With an empty dictionary, this always returns false for any miner, causing all miners to receive `InvalidConsensusCommand`. [7](#0-6) 

7. **Additional Failures**: Multiple code paths will fail with empty miner lists, including `GetNextMinerPubkey()` which calls `.First(m => m.IsExtraBlockProducer)` on an empty collection, which would throw an exception. [8](#0-7) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability achieves complete and permanent denial of service of the entire blockchain:

- **Consensus Breakdown**: Once the empty miner list is set, `GetConsensusCommand` returns `InvalidConsensusCommand` for ALL miners, meaning no miner can produce any blocks.
- **Permanent Halt**: There is no recovery mechanism in the contract code. The blockchain remains halted until extraordinary measures (hard fork or manual state intervention) are taken.
- **Network-Wide Impact**: All network participants lose access. Token holders cannot transfer assets, DApps become inoperable, cross-chain bridges halt, and all governance operations cease.
- **Economic Damage**: Complete loss of network functionality affects all stakeholders and could result in massive economic losses.

The impact is maximal because it breaks the fundamental consensus invariant (non-empty miner list) and has no programmatic recovery path.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is executable with minimal barriers:

- **Attacker Requirements**: Must be an authorized miner (in current or previous round). Since miners are elected through the Election contract and multiple miners exist in the network, this is a realistic constraint that many actors satisfy.
- **Attack Complexity**: VERY LOW. The attacker crafts a block with consensus extra data containing correct round/term numbers but an empty `RealTimeMinersInformation` dictionary. The validation logic has a gap and does not check for empty miner lists.
- **No Special Conditions**: No timing requirements, race conditions, or coordination needed. The attack can be executed during any term transition.
- **Low Cost**: Only requires producing a block during the attacker's normal mining time slot.
- **Validation Bypass**: The `RoundTerminateValidationProvider` only checks that no miners have `InValue != null`, which is vacuously true for an empty collection, allowing the malicious block to pass validation.

Any disgruntled or compromised miner can execute this attack with minimal effort.

## Recommendation

Add explicit validation in the `RoundTerminateValidationProvider` to ensure the miner list is non-empty:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Check that miner list is non-empty
    if (extraData.Round.RealTimeMinersInformation.Count == 0)
        return new ValidationResult { Message = "Miner list cannot be empty for next term." };

    // Is next term number correct?
    return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
        ? new ValidationResult { Message = "Incorrect term number for next round." }
        : new ValidationResult { Success = true };
}
```

Additionally, add a defensive check in `SetMinerList`:

```csharp
private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
{
    Assert(minerList != null && minerList.Pubkeys.Count > 0, "Miner list must contain at least one miner.");
    
    var minerListFromState = State.MinerListMap[termNumber];
    if (gonnaReplaceSomeone || minerListFromState == null)
    {
        State.MainChainCurrentMinerList.Value = minerList;
        State.MinerListMap[termNumber] = minerList;
        return true;
    }

    return false;
}
```

## Proof of Concept

The vulnerability can be demonstrated by creating a `NextTermInput` with:
- Correct `RoundNumber` = currentRound.RoundNumber + 1
- Correct `TermNumber` = currentTerm + 1  
- Empty `RealTimeMinersInformation` dictionary
- Valid `RoundIdForValidation`

This input would pass through the `ValidationForNextTerm` check because `RealTimeMinersInformation.Values.Any(m => m.InValue != null)` returns false (no values exist to check), resulting in validation success. The subsequent execution in `ProcessNextTerm` would create an empty `MinerList` from the empty Keys, which `SetMinerList` would accept without validation, corrupting the state and halting consensus.

## Notes

This vulnerability represents a critical validation gap in the consensus layer. While legitimate miners use proper generation methods (like `GenerateFirstRoundOfNextTerm`) that always produce non-empty miner lists, the validation logic must still defend against malicious inputs. The lack of an empty-list check in `RoundTerminateValidationProvider` allows this attack to succeed, breaking the fundamental invariant that every term must have at least one miner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-191)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L26-27)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L91-102)
```csharp
    public override StringValue GetNextMinerPubkey(Empty input)
    {
        if (TryToGetCurrentRoundInformation(out var round))
            return new StringValue
            {
                Value = round.RealTimeMinersInformation.Values
                            .FirstOrDefault(m => m.ExpectedMiningTime > Context.CurrentBlockTime)?.Pubkey ??
                        round.RealTimeMinersInformation.Values.First(m => m.IsExtraBlockProducer).Pubkey
            };

        return new StringValue();
    }
```
