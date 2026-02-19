# Audit Report

## Title
Insufficient Validation of Critical Round Fields in NextRound Consensus Behavior Enables State Corruption

## Summary
The AEDPoS consensus contract fails to validate critical Round object fields (`ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, and `IsMinerListJustChanged`) during NextRound transactions. These fields are excluded from hash-based validation and lack dedicated validation providers, allowing malicious miners to corrupt consensus state and cause DoS or finality tracking issues.

## Finding Description

The vulnerability exists across multiple validation gaps in the NextRound consensus flow:

**1. No Input Validation in NextRoundInput.Create** [1](#0-0) 

The `Create` method blindly copies all fields including `ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, and `IsMinerListJustChanged` without any validation.

**2. Transaction Generation Without Field Validation** [2](#0-1) 

The transaction is created directly from the consensus header information without validating critical fields.

**3. Incomplete Hash-Based Validation** [3](#0-2) 

The `GetCheckableRound` method used for hash validation only includes `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge` - explicitly excluding the vulnerable fields.

**4. Before-Execution Validation Gaps** [4](#0-3) 

The `RoundTerminateValidationProvider` for NextRound only validates round number increment and null InValues, not LIB fields.

**5. LibInformationValidationProvider Not Applied to NextRound** [5](#0-4) 

The `LibInformationValidationProvider` that validates LIB heights is only added for `UpdateValue` behavior (line 82), not for `NextRound` (lines 84-88).

**6. Direct State Storage Without Full Validation** [6](#0-5) 

The `ProcessNextRound` method converts the input to a Round and stores it via `AddRoundInformation` without validating the LIB fields. [7](#0-6) 

The round is stored directly to state without checking LIB field integrity.

**Attack Flow:**
1. Malicious miner calls `GenerateConsensusTransactions` to get legitimate NextRound transaction
2. Modifies `ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, or `IsMinerListJustChanged` in the consensus header before broadcasting
3. Before-execution validation passes (no LIB checks for NextRound)
4. Transaction executes and stores corrupt values
5. After-execution validation passes (hash excludes manipulated fields)

## Impact Explanation

**1. Consensus DoS via LIB Round Manipulation** [8](#0-7) 

A malicious miner can manipulate `ConfirmedIrreversibleBlockRoundNumber` to an artificially LOW value (note: the report incorrectly says "inflate" but "deflate" is needed). This causes a large gap between `currentRoundNumber` and `libRoundNumber`, triggering Severe blockchain status when `currentRoundNumber >= libRoundNumber + SevereStatusRoundsThreshold`. This reduces maximum blocks count to 1 and fires `IrreversibleBlockHeightUnacceptable` events, severely degrading network performance.

**2. LIB Finality Corruption**

Manipulating `ConfirmedIrreversibleBlockHeight` corrupts finality tracking throughout the consensus protocol. These values are used in blockchain health assessment and are not cross-validated against actual blockchain state.

**3. Secret Sharing Bypass** [9](#0-8) 

The `IsMinerListJustChanged` flag controls whether secret sharing events are fired. A malicious miner can flip this flag to bypass secret sharing when the miner list hasn't changed, or force unnecessary secret sharing when it has changed, disrupting the consensus random number generation mechanism.

**Severity: HIGH** - Enables operational DoS and consensus state corruption by a single malicious miner without requiring majority collusion.

## Likelihood Explanation

**Attacker Profile:** Any authorized miner in the consensus set

**Prerequisites:**
- Attacker must be in current miner list (realistic for any miner)
- No special blockchain state required
- Executable during any normal round transition

**Attack Complexity: LOW**
- Standard consensus flow through `GetConsensusCommand` and `GenerateConsensusTransactions`
- Simple modification of block header consensus data before broadcasting
- No cryptographic breaks or complex multi-step attacks required

**Detection Difficulty: HIGH**
- Before-execution validation has explicit gap (no `LibInformationValidationProvider` for NextRound)
- After-execution hash validation excludes the manipulated fields
- No cross-validation against actual blockchain state

**Probability: HIGH** - Any malicious or compromised miner can execute this attack during their normal block production turn.

## Recommendation

**1. Apply LibInformationValidationProvider to NextRound**

Modify the before-execution validation to include LIB validation for NextRound behavior:

```csharp
case AElfConsensusBehaviour.NextRound:
    // Is sender's order of next round correct?
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    // ADD THIS: Validate LIB fields don't go backwards
    validationProviders.Add(new LibInformationValidationProvider());
    break;
```

**2. Include Critical Fields in Hash Validation**

Modify `GetCheckableRound` to include LIB fields and `IsMinerListJustChanged` in the hash calculation, or add a separate validation step for these fields in after-execution validation.

**3. Add Explicit Validation in NextRoundInput.Create**

Validate that LIB fields are not decreasing relative to the current round:

```csharp
public static NextRoundInput Create(Round round, Round currentRound, ByteString randomNumber)
{
    // Validate LIB fields
    if (currentRound != null && round.ConfirmedIrreversibleBlockHeight < currentRound.ConfirmedIrreversibleBlockHeight)
        throw new AssertionException("LIB height cannot decrease");
    if (currentRound != null && round.ConfirmedIrreversibleBlockRoundNumber < currentRound.ConfirmedIrreversibleBlockRoundNumber)
        throw new AssertionException("LIB round number cannot decrease");
    
    return new NextRoundInput { /* ... */ };
}
```

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_ShouldReject_ManipulatedLIBFields()
{
    // Setup: Initialize consensus with normal round
    var initialRound = GenerateFirstRound();
    initialRound.ConfirmedIrreversibleBlockHeight = 100;
    initialRound.ConfirmedIrreversibleBlockRoundNumber = 5;
    await InitializeConsensus(initialRound);
    
    // Attack: Create NextRound with manipulated LIB values
    var nextRound = GenerateNextRound(initialRound);
    nextRound.ConfirmedIrreversibleBlockRoundNumber = 1; // Deflate to trigger Severe status
    
    var maliciousInput = NextRoundInput.Create(nextRound, GenerateRandomNumber());
    
    // Execute: Try to process malicious NextRound
    var result = await ConsensusContract.NextRound.SendAsync(maliciousInput);
    
    // Verify: Should be rejected but currently passes
    // Expected: Transaction should fail validation
    // Actual: Transaction succeeds and corrupts state
    var currentRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(1, currentRound.ConfirmedIrreversibleBlockRoundNumber); // Corruption confirmed
    
    // Verify DoS impact
    var maxBlocks = await ConsensusContract.GetMaximumBlocksCount.CallAsync(new Empty());
    Assert.Equal(1, maxBlocks.Value); // Network degraded to Severe status
}
```

## Notes

There is a technical error in the original impact description: it states a miner can "inflate" `ConfirmedIrreversibleBlockRoundNumber` to cause DoS, but actually the miner would need to DEFLATE (reduce) this value to create a large gap between `currentRoundNumber` and `libRoundNumber`, triggering Severe status. Despite this directional error, the core vulnerability and its exploitability are valid.

The vulnerability breaks the invariant that LIB values should only increase or remain stable during normal consensus operation, allowing arbitrary manipulation by any authorized miner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L7-23)
```csharp
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L164-171)
```csharp
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
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
