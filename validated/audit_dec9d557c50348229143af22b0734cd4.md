# Audit Report

## Title
Missing Validation in BlockchainMiningStatusEvaluator Allows Invalid LIB Round Number Leading to Incorrect Consensus Status Evaluation

## Summary
The `BlockchainMiningStatusEvaluator` constructor lacks validation of the critical invariant that `currentConfirmedIrreversibleBlockRoundNumber <= currentRoundNumber`. A malicious miner can exploit this by submitting a `NextRound` transaction with an invalid `ConfirmedIrreversibleBlockRoundNumber` exceeding the current round number, causing the blockchain to incorrectly evaluate its mining status as Normal and bypass throttling mechanisms designed to handle LIB lag conditions.

## Finding Description

The vulnerability exists in the consensus status evaluation logic that determines block production limits. The `BlockchainMiningStatusEvaluator` constructor accepts parameters without validating their logical relationship: [1](#0-0) 

By definition, the Last Irreversible Block (LIB) cannot exist in a future round. However, when the `Deconstruct` method evaluates status with inverted values where `_libRoundNumber > _currentRoundNumber`, both conditional checks fail and incorrectly return `Normal` status: [2](#0-1) 

**Attack Vector:**

A miner can submit a malicious `NextRound` transaction with crafted `NextRoundInput` data via the public `NextRound` method: [3](#0-2) 

The validation providers for `NextRound` behavior are insufficient. Critically, `LibInformationValidationProvider` is NOT added for `NextRound` behavior (only added for `UpdateValue`): [4](#0-3) 

The `RoundTerminateValidationProvider` only validates round number increment by 1, not the LIB invariant: [5](#0-4) 

Even if `LibInformationValidationProvider` were added, it only prevents LIB from decreasing, not from exceeding current round: [6](#0-5) 

The invalid round data is then stored persistently without any validation of the LIB invariant: [7](#0-6) [8](#0-7) 

When `GetMaximumBlocksCount` later retrieves this corrupted data, it creates a `BlockchainMiningStatusEvaluator` with invalid parameters: [9](#0-8) 

## Impact Explanation

**Severity: HIGH - Consensus Integrity Compromise**

This vulnerability disables the blockchain's self-regulation mechanism for handling LIB lag. When the blockchain should enter `Abnormal` or `Severe` status due to LIB falling behind, the attacker prevents this by injecting inflated LIB round numbers.

**Specific Impacts:**

1. **Abnormal Throttling Bypass**: The system should reduce block production based on active miners when LIB lags: [10](#0-9) 

2. **Severe Throttling Bypass**: The system should limit production to 1 block and fire warning events when LIB lag is severe: [11](#0-10) 

3. **Persistent Corruption**: Invalid LIB values propagate to future rounds since new rounds copy these values: [12](#0-11) 

This prevents the blockchain from self-correcting during consensus stress, potentially worsening LIB lag and threatening chain finality guarantees.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Attacker Prerequisites:**
- Must be a current or previous round miner, verified in `PreCheck`: [13](#0-12) 

- Miner positions rotate regularly through the election system, making this privilege obtainable

**Attack Complexity: LOW**
1. Craft a `NextRoundInput` with `ConfirmedIrreversibleBlockRoundNumber > RoundNumber` (e.g., 105 > 100)
2. Submit via the public `NextRound` method
3. Transaction passes all validation checks due to missing validator
4. Invalid state persists and propagates to future rounds

**Detection Difficulty: HIGH**
The invalid state persists in contract storage with no alerts triggered until external monitoring detects anomalous consensus behavior.

## Recommendation

Add validation in the `BlockchainMiningStatusEvaluator` constructor to enforce the invariant:

```csharp
public BlockchainMiningStatusEvaluator(long currentConfirmedIrreversibleBlockRoundNumber,
    long currentRoundNumber, int maximumTinyBlocksCount)
{
    Assert(currentConfirmedIrreversibleBlockRoundNumber <= currentRoundNumber, 
        "LIB round number cannot exceed current round number.");
    _libRoundNumber = currentConfirmedIrreversibleBlockRoundNumber;
    _currentRoundNumber = currentRoundNumber;
    _maximumTinyBlocksCount = maximumTinyBlocksCount;
}
```

Alternatively, add a validation provider for `NextRound` behavior that checks this invariant before storing the round data.

## Proof of Concept

```csharp
[Fact]
public async Task Exploit_InvalidLIBRoundNumber_BypassesThrottling()
{
    // Setup: Initialize consensus with normal state
    await InitializeConsensusContract();
    
    // Current state: Round 100, LIB Round 98 (valid)
    var currentRound = await GetCurrentRoundInformation();
    Assert.Equal(100, currentRound.RoundNumber);
    Assert.Equal(98, currentRound.ConfirmedIrreversibleBlockRoundNumber);
    
    // Attack: Craft NextRoundInput with invalid LIB round number
    var maliciousNextRound = new NextRoundInput
    {
        RoundNumber = 101, // Valid: 100 + 1
        ConfirmedIrreversibleBlockRoundNumber = 105, // INVALID: > RoundNumber
        // ... other fields properly filled
    };
    
    // Execute attack via public NextRound method
    await ConsensusContract.NextRound(maliciousNextRound);
    
    // Verify: Invalid state persisted
    var corruptedRound = await GetCurrentRoundInformation();
    Assert.Equal(101, corruptedRound.RoundNumber);
    Assert.Equal(105, corruptedRound.ConfirmedIrreversibleBlockRoundNumber);
    Assert.True(105 > 101); // Invariant violated
    
    // Impact: GetMaximumBlocksCount returns incorrect status
    var maxBlocks = await ConsensusContract.GetMaximumBlocksCount(new Empty());
    
    // Should return reduced count (Abnormal/Severe), but returns max due to bypass
    Assert.Equal(8, maxBlocks.Value); // MaximumTinyBlocksCount returned instead of throttled value
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L24-37)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-55)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L57-67)
```csharp
        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L106-112)
```csharp
        public BlockchainMiningStatusEvaluator(long currentConfirmedIrreversibleBlockRoundNumber,
            long currentRoundNumber, int maximumTinyBlocksCount)
        {
            _libRoundNumber = currentConfirmedIrreversibleBlockRoundNumber;
            _currentRoundNumber = currentRoundNumber;
            _maximumTinyBlocksCount = maximumTinyBlocksCount;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L119-129)
```csharp
        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-20)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-71)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```
