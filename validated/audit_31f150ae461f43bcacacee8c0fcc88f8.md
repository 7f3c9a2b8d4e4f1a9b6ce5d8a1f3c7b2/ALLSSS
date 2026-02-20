# Audit Report

## Title
Missing Per-Round Block Production Limit Validation in AEDPoS Consensus System

## Summary
The AEDPoS consensus contract enforces per-round block production limits (MaximumTinyBlocksCount = 8) only during honest command generation but fails to validate these limits during block execution. A malicious miner can bypass the honest path and directly invoke `UpdateTinyBlockInformation` to produce unlimited blocks within their time slot, extracting disproportionate mining rewards and violating consensus fairness guarantees.

## Finding Description

The vulnerability stems from an architectural flaw where block production limits are checked during command generation but not during validation/execution.

**Command Generation (Honest Path):**
The limit check exists in `GetConsensusBehaviour()` where honest miners are restricted to `_maximumBlocksCount` blocks per time slot. [1](#0-0) 

Extra block producers with two time slots have extended limits based on blocks produced before the current round. [2](#0-1) 

**Missing Validation:**
During block validation, `ValidateBeforeExecution` instantiates only three basic validators. [3](#0-2) 

`MiningPermissionValidationProvider` only verifies miner list membership, not block count limits. [4](#0-3) 

`ContinuousBlocksValidationProvider` checks cross-miner continuous block production, not per-miner per-round limits. [5](#0-4) 

**Exploitation Path:**
A malicious miner directly calls the public `UpdateTinyBlockInformation` method. [6](#0-5) 

The method flows through `ProcessConsensusInformation` where `PreCheck()` only validates miner list membership without count verification. [7](#0-6) 

`ProcessTinyBlock` unconditionally adds the mining time and increments `ProducedBlocks` without checking `ActualMiningTimes.Count` against limits. [8](#0-7) 

The maximum blocks constant is defined as 8. [9](#0-8) 

## Impact Explanation

**Mining Reward Misallocation:**
The `DonateMiningReward` function calculates total mining rewards as `minedBlocks * miningRewardPerBlock` where `minedBlocks` is the sum of all miners' `ProducedBlocks`. [10](#0-9) 

`GetMinedBlocks()` aggregates all `ProducedBlocks` from round information. [11](#0-10) 

Each extra block produced beyond the limit results in additional rewards that were not allocated to that miner by the consensus economic model, effectively stealing from the reward pool intended for honest miners.

**Consensus Fairness Violation:**
The protocol design ensures equitable block production by limiting each miner to 8 blocks per time slot. By exceeding this limit, a malicious miner can dominate their time slot, produce disproportionate blocks, and centralize control within the round, undermining the decentralization guarantees of AEDPoS.

## Likelihood Explanation

**Low Attack Complexity:**
The exploit requires only crafting `TinyBlockInput` transactions with incremental `ActualMiningTime` values and calling the public `UpdateTinyBlockInformation` method. No cryptographic bypass, signature forgery, or complex state manipulation is needed.

**Realistic Preconditions:**
The attacker must be an elected miner in the current round, achievable through the standard election and staking process. Once elected, they have direct access to all consensus methods including the vulnerable entry point.

**Bypasses Honest Path:**
Honest miners request commands via `GetConsensusCommand`, which enforces limits. Malicious miners skip this entirely and directly invoke the processing method, which lacks equivalent validation checks.

## Recommendation

Add a validation provider to check `ActualMiningTimes.Count` against `MaximumTinyBlocksCount` during `ValidateBeforeExecution`. The validator should:

1. For regular miners: Verify `ActualMiningTimes.Count < MaximumTinyBlocksCount`
2. For extra block producers: Calculate blocks before current round and verify `ActualMiningTimes.Count < MaximumTinyBlocksCount + blocksBeforeCurrentRound`
3. Return validation failure if limits are exceeded

This mirrors the logic in `ConsensusBehaviourProviderBase` but applies it at validation time, preventing limit bypass regardless of the entry path.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_ExceedsBlockLimit_Test()
{
    // Setup: Initialize consensus and mine first round
    await InitializeCandidates();
    var firstRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var maliciousMiner = InitialCoreDataCenterKeyPairs[0];
    var maliciousPubkey = maliciousMiner.PublicKey.ToHex();
    
    // Produce 8 blocks (the maximum allowed)
    for (int i = 0; i < 8; i++)
    {
        var input = new TinyBlockInput
        {
            RoundId = firstRound.RoundId,
            ActualMiningTime = BlockTimeProvider.GetBlockTime().AddMilliseconds(i * 100),
            ProducedBlocks = i + 1,
            RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(maliciousMiner))
        };
        await GetAEDPoSContractStub(maliciousMiner).UpdateTinyBlockInformation.SendAsync(input);
    }
    
    var roundAfter8 = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    roundAfter8.RealTimeMinersInformation[maliciousPubkey].ActualMiningTimes.Count.ShouldBe(8);
    
    // VULNERABILITY: Produce 9th block beyond limit - should fail but succeeds
    var maliciousInput = new TinyBlockInput
    {
        RoundId = firstRound.RoundId,
        ActualMiningTime = BlockTimeProvider.GetBlockTime().AddMilliseconds(900),
        ProducedBlocks = 9,
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(maliciousMiner))
    };
    
    var result = await GetAEDPoSContractStub(maliciousMiner).UpdateTinyBlockInformation.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Succeeds when it should fail
    
    var finalRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    finalRound.RealTimeMinersInformation[maliciousPubkey].ActualMiningTimes.Count.ShouldBe(9); // Exceeded limit
    finalRound.RealTimeMinersInformation[maliciousPubkey].ProducedBlocks.ShouldBe(9); // Gets extra rewards
}
```

The test demonstrates that after producing the maximum 8 blocks, a malicious miner can continue producing additional blocks, incrementing their `ProducedBlocks` count which directly increases their mining rewards at term transition.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-24)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L108-112)
```csharp
    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L118-120)
```csharp
        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L124-127)
```csharp
    public long GetMinedBlocks()
    {
        return RealTimeMinersInformation.Values.Sum(minerInRound => minerInRound.ProducedBlocks);
    }
```
