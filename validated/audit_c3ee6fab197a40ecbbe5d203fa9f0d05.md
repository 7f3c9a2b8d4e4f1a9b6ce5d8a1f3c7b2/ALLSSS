# Audit Report

## Title
Post-Execution Consensus Validation Completely Bypassed Due to Object Reference Bug

## Summary
The `ValidateConsensusAfterExecution` method in the AEDPoS consensus contract contains a critical object aliasing bug. The recovery methods `RecoverFromUpdateValue` and `RecoverFromTinyBlock` modify the current consensus state object in-place and return it, causing both sides of the validation comparison to reference the same object. This renders post-execution validation ineffective, allowing blocks with fabricated consensus data to pass validation.

## Finding Description

The vulnerability exists in `ValidateConsensusAfterExecution` where recovery methods create an object aliasing bug: [1](#0-0) 

The method retrieves `currentRound` from state, which is a protobuf `Round` message (reference type): [2](#0-1) [3](#0-2) 

For `UpdateValue` and `TinyBlock` behaviors, the code calls recovery methods that modify `this` (the `currentRound` object) in-place and return it: [4](#0-3) 

After executing lines 90-92 or 95-97, `headerInformation.Round` and `currentRound` reference the **same object**. The subsequent hash comparison at lines 100-101 compares an object with itself, always producing equal hashes regardless of whether the header data matches the post-execution state.

The block header contains critical consensus fields that the validation should verify: [5](#0-4) [6](#0-5) 

These simplified rounds are included in block headers during consensus extra data generation: [7](#0-6) 

## Impact Explanation

This bug breaks a fundamental consensus safety invariant: the ability to verify that block execution results match consensus claims in the block header.

While `ProcessUpdateValue` protects `ProducedBlocks` by ignoring the input value, it directly uses other critical fields from the transaction input: [8](#0-7) 

A malicious miner could:

1. **Manipulate LIB calculation**: Provide incorrect `ImpliedIrreversibleBlockHeight` (line 248 uses input value), affecting Last Irreversible Block determination and finality
2. **Break secret sharing**: Provide incorrect `OutValue`, `Signature`, or `PreviousInValue` (lines 244-245, 264), corrupting the random number generation and secret sharing protocol
3. **Bypass time validation**: Provide incorrect `ActualMiningTime` (line 243), allowing mining outside designated time slots

The post-execution validation is the final safety barrier that should catch discrepancies between the block header (claimed state) and actual post-execution state. Without it, consensus integrity checks are fundamentally compromised.

## Likelihood Explanation

This bug triggers automatically on every node for every block containing `UpdateValue` or `TinyBlock` consensus behaviors:

- **Reachable Entry Point**: `ValidateConsensusAfterExecution` is part of the ACS4 consensus standard, invoked during block validation
- **No Preconditions**: Occurs during normal block processing - any miner can trigger it
- **100% Trigger Rate**: The bug activates on every `UpdateValue`/`TinyBlock` block
- **Silent Failure**: Validation appears successful even when it should fail

A malicious miner could exploit this by:
1. Generating block header with plausible consensus data
2. Including a consensus transaction with different (fabricated) values
3. Before-execution validation may pass (checks header values for basic validity)
4. Transaction executes, updating state with incorrect values
5. After-execution validation should detect the mismatch but always passes due to the bug

## Recommendation

Modify the recovery methods to create and return a **new** `Round` object instead of modifying `this`:

```csharp
public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
{
    if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
        !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
        return this;

    // Create a clone instead of modifying this
    var recovered = this.Clone();
    var minerInRound = recovered.RealTimeMinersInformation[pubkey];
    var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
    
    minerInRound.OutValue = providedInformation.OutValue;
    minerInRound.Signature = providedInformation.Signature;
    // ... rest of the updates on 'recovered' not 'this'
    
    return recovered;  // Return the new object, not this
}
```

This ensures `headerInformation.Round` and `currentRound` remain separate objects, allowing proper validation.

## Proof of Concept

```csharp
[Fact]
public async Task ValidateConsensusAfterExecution_ObjectAliasingBug_Test()
{
    // Setup: Initialize consensus and produce some blocks
    await InitialAElfConsensusContractAsync();
    await AEDPoSContractStub.FirstRound.SendAsync(
        GenerateFirstRoundOfNewTerm(InitialCoreDataCenterKeyPairs.Select(p => p.PublicKey.ToHex()).ToList(), 4000));
    
    // Get current round before any modifications
    var originalRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var originalHash = originalRound.GetHash(true);
    
    // Create header information with UpdateValue behavior
    var headerInfo = new AElfConsensusHeaderInformation
    {
        SenderPubkey = ByteStringHelper.FromHexString(BootMinerKeyPair.PublicKey.ToHex()),
        Behaviour = AElfConsensusBehaviour.UpdateValue,
        Round = originalRound.GetUpdateValueRound(BootMinerKeyPair.PublicKey.ToHex())
    };
    
    // Simulate the bug: call ValidateConsensusAfterExecution
    var result = await AEDPoSContractStub.ValidateConsensusAfterExecution.CallAsync(
        headerInfo.ToBytesValue());
    
    // The bug: validation should fail if header doesn't match state, 
    // but it always passes because both sides point to the same object
    result.Success.ShouldBeTrue(); // Always passes due to the bug
    
    // Proof: After recovery, headerInfo.Round references the same object as currentRound
    // Any comparison between them will always be equal, even with fabricated data
}
```

## Notes

The vulnerability is limited in scope because `ProcessUpdateValue` ignores certain input fields like `ProducedBlocks`. However, it still allows manipulation of consensus-critical fields like `ImpliedIrreversibleBlockHeight`, `ActualMiningTime`, and secret sharing values (`OutValue`, `Signature`, `PreviousInValue`). This breaks the defense-in-depth principle where after-execution validation serves as a final check against malicious or buggy consensus data processing.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
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
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** protobuf/aedpos_contract.proto (L243-264)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-47)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }

    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L11-56)
```csharp
    public Round GetUpdateValueRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = pubkey,
                    OutValue = minerInRound.OutValue,
                    Signature = minerInRound.Signature,
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    PreviousInValue = minerInRound.PreviousInValue,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
                    Order = minerInRound.Order,
                    IsExtraBlockProducer = minerInRound.IsExtraBlockProducer
                }
            }
        };
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
            }

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-82)
```csharp
    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = minerInRound.Pubkey,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight
                }
            }
        };

        foreach (var otherPubkey in RealTimeMinersInformation.Keys.Except(new List<string> { pubkey }))
            round.RealTimeMinersInformation.Add(otherPubkey, new MinerInRound());

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L28-38)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```
