# Audit Report

## Title
Dictionary Key Mismatch in RecoverFromUpdateValue Causes Consensus Validation DoS During Miner Replacement

## Summary
The `RecoverFromUpdateValue` function in the AEDPoS consensus contract contains a critical bug where it iterates over all miners in the provided round and directly accesses the current round's `RealTimeMinersInformation` dictionary without verifying key existence. During miner replacement scenarios, this causes a `KeyNotFoundException` that prevents proper consensus validation, resulting in a denial-of-service condition for legitimate block validation operations.

## Finding Description

The vulnerability exists in the `RecoverFromUpdateValue` method where unsafe dictionary access occurs during the foreach loop. [1](#0-0) 

**Root Cause:** While the function validates that the sender's pubkey exists in both rounds [2](#0-1) , it subsequently iterates over ALL miners in `providedRound.RealTimeMinersInformation` and directly accesses `RealTimeMinersInformation[information.Key]` without checking if each key exists in the current round. In C#, accessing a dictionary with a non-existent key using the indexer throws `KeyNotFoundException`.

**Trigger Mechanism:** During miner replacement via `RecordCandidateReplacement`, the current round's miner list is modified by removing the old pubkey and adding a new one. [3](#0-2)  When a block produced before the replacement (containing the old miner list) is validated after the replacement occurs, the provided round contains miners that no longer exist in the current round's dictionary.

**Validation Call Path:** Block validation flows through the consensus validation provider [4](#0-3) , which calls the contract's after-execution validation [5](#0-4) . At line 91, `RecoverFromUpdateValue` is called for UpdateValue behavior, where the exception occurs before reaching the designed miner replacement validation logic at lines 103-123.

**Pattern Violation:** The codebase consistently uses `ContainsKey` checks before accessing `RealTimeMinersInformation` throughout multiple methods: [6](#0-5) , [7](#0-6) , [8](#0-7) , and [9](#0-8) . The missing check in `RecoverFromUpdateValue` breaks this established defensive coding pattern.

## Impact Explanation

**High Severity DoS Impact:**

This vulnerability causes consensus validation failures during miner replacement operations, which are legitimate protocol features. Blocks containing consensus data from before a miner replacement fail validation with unhandled exceptions rather than being properly validated or gracefully rejected through the designed validation mechanism. [10](#0-9) 

The system has specific logic to detect and validate miner replacements by comparing header miners with state miners and verifying the replacement with the Election contract. However, this protection becomes unreachable because the `KeyNotFoundException` is thrown at line 91 before execution reaches line 103.

**Security Guarantees Broken:**
- Consensus validation should handle legitimate state transitions gracefully without exceptions
- Blocks following protocol rules should be validated correctly or rejected with proper error handling  
- Miner replacement, a normal protocol operation, should not cause validation failures

The impact extends to all nodes attempting to validate blocks during miner replacement timing windows, potentially causing network-wide consensus disruption during these transitions.

## Likelihood Explanation

**High Likelihood - Normal Operations:**

Miner replacement is a standard protocol feature accessible through the Election contract's `ReplaceCandidatePubkey` method. [11](#0-10)  This vulnerability triggers during legitimate operations without requiring malicious intent or special privileges.

**Realistic Triggering Scenario:**
1. Miner M1 is active in current round with miner list [M1, M2, M3]
2. Candidate admin calls `ReplaceCandidatePubkey` to replace M1 with M4
3. Node A produces a block with consensus data containing [M1, M2, M3] before processing the replacement
4. Node B processes the replacement, updating its current round to [M4, M2, M3]
5. Node B receives Node A's block for validation
6. `RecoverFromUpdateValue` iterates over [M1, M2, M3] from the block
7. Dictionary access for M1 fails because M1 was removed from current round
8. `KeyNotFoundException` thrown, validation fails

**Preconditions:** Only normal protocol operations are required:
- Miner replacement via Election contract (happens when candidates update keys)
- Block propagation timing differences between nodes (inherent in distributed systems)
- No attacker control or compromised keys needed

## Recommendation

Add a `ContainsKey` check before accessing the dictionary in the foreach loop, consistent with the pattern used throughout the codebase:

```csharp
foreach (var information in providedRound.RealTimeMinersInformation)
{
    if (!RealTimeMinersInformation.ContainsKey(information.Key))
        continue;
        
    RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
        information.Value.SupposedOrderOfNextRound;
    RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
        information.Value.FinalOrderOfNextRound;
    RealTimeMinersInformation[information.Key].PreviousInValue =
        information.Value.PreviousInValue;
}
```

This allows the validation to proceed to the miner replacement logic at lines 103-123, which properly handles scenarios where miners in the header don't match miners in state.

## Proof of Concept

```csharp
[Fact]
public async Task RecoverFromUpdateValue_MinerReplacement_CausesKeyNotFoundException()
{
    // Setup: Create initial round with miner M1
    var round = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation = 
        {
            ["M2"] = new MinerInRound { Pubkey = "M2", Order = 2 },
            ["M3"] = new MinerInRound { Pubkey = "M3", Order = 3 }
        }
    };
    
    // Simulate miner replacement - M1 removed, M4 added (this is what RecordCandidateReplacement does)
    // Current round now has [M2, M3] (M1 was replaced)
    
    // Create provided round from block with old miner list [M1, M2, M3]
    var providedRound = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation = 
        {
            ["M1"] = new MinerInRound { Pubkey = "M1", Order = 1, SupposedOrderOfNextRound = 1 },
            ["M2"] = new MinerInRound { Pubkey = "M2", Order = 2, SupposedOrderOfNextRound = 2 },
            ["M3"] = new MinerInRound { Pubkey = "M3", Order = 3, SupposedOrderOfNextRound = 3 }
        }
    };
    
    // This should throw KeyNotFoundException when trying to access M1
    var exception = Record.Exception(() => 
        round.RecoverFromUpdateValue(providedRound, "M2"));
    
    Assert.NotNull(exception);
    Assert.IsType<KeyNotFoundException>(exception);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L80-98)
```csharp
    public async Task<bool> ValidateBlockAfterExecuteAsync(IBlock block)
    {
        if (block.Header.Height == AElfConstants.GenesisBlockHeight)
            return true;

        var consensusExtraData = _consensusExtraDataExtractor.ExtractConsensusExtraData(block.Header);
        if (consensusExtraData == null || consensusExtraData.IsEmpty)
        {
            Logger.LogDebug($"Invalid consensus extra data {block}");
            return false;
        }

        var isValid = await _consensusService.ValidateConsensusAfterExecutionAsync(new ChainContext
        {
            BlockHash = block.GetHash(),
            BlockHeight = block.Header.Height
        }, consensusExtraData.ToByteArray());

        return isValid;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-98)
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

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L103-124)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L86-87)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L159-161)
```csharp
        return RealTimeMinersInformation.ContainsKey(publicKey)
            ? RealTimeMinersInformation[publicKey].ExpectedMiningTime
            : new Timestamp { Seconds = long.MaxValue };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L18-20)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return null;

        var minerInRound = RealTimeMinersInformation[pubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return this;

        RealTimeMinersInformation[pubkey].OutValue = outValue;
```
