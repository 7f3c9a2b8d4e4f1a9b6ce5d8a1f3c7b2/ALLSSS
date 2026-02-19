# Audit Report

## Title
Missing LIB Round Number Validation Allows Consensus State Corruption in NextTerm/NextRound Operations

## Summary
The AEDPoS consensus contract fails to validate that `ConfirmedIrreversibleBlockRoundNumber` is less than the current `RoundNumber` when processing `NextTerm` and `NextRound` operations. A malicious miner can inject consensus state where the Last Irreversible Block (LIB) round number equals or exceeds the current round number, violating the fundamental invariant that LIB must lag behind the current round, causing permanent consensus state corruption and mining status miscalculations.

## Finding Description

The vulnerability exists in the validation logic for consensus round transitions. The validation framework selectively applies different validation providers based on the consensus behavior type. [1](#0-0) 

For `NextTerm` behavior, only `RoundTerminateValidationProvider` is applied, which validates round number increment, term number increment, and InValue nullity, but does not validate LIB constraints. [2](#0-1) 

The `RoundTerminateValidationProvider` implementation confirms it only checks round/term number progression and InValue state. [3](#0-2) 

The `LibInformationValidationProvider`, which could potentially validate LIB constraints, only checks that LIB values don't regress (go backwards), but never validates that `ConfirmedIrreversibleBlockRoundNumber < RoundNumber`. [4](#0-3) 

**Attack Execution:**

1. A malicious miner with block production rights for NextTerm/NextRound creates consensus input with:
   - Valid `RoundNumber = currentRound.RoundNumber + 1`  
   - Invalid `ConfirmedIrreversibleBlockRoundNumber >= RoundNumber`

2. Both the block header extra data and transaction input contain these same malicious values

3. Validation passes because LibInformationValidationProvider is not applied to NextTerm/NextRound behaviors

4. The malicious round is stored via `ProcessNextTerm` or `ProcessNextRound`. [5](#0-4) [6](#0-5) 

5. The corrupted LIB values persist and propagate to all subsequent rounds because `GenerateNextRoundInformation` copies these fields without validation. [7](#0-6) 

## Impact Explanation

**Severity: HIGH - Critical Consensus Invariant Violation**

**Consensus State Corruption:**
The blockchain consensus state will permanently contain the logically impossible condition where `ConfirmedIrreversibleBlockRoundNumber >= RoundNumber`. This fundamentally violates the consensus protocol's invariant that the Last Irreversible Block must always lag behind the current round, as irreversibility is determined retrospectively.

**Persistent Propagation:**
The corruption is permanent and self-perpetuating. Since future rounds copy LIB values from previous rounds without validation, the invalid state propagates indefinitely through the consensus mechanism.

**Mining Status Miscalculation:**
The `BlockchainMiningStatusEvaluator` determines blockchain health by comparing `_libRoundNumber` against `_currentRoundNumber` using arithmetic assumptions that `_libRoundNumber < _currentRoundNumber`. [8](#0-7) 

When the invariant is violated, the status evaluation logic produces incorrect results:
- Abnormal/Severe status conditions may never trigger when they should
- Normal status may be reported during actual blockchain issues
- Block production limits may be incorrectly calculated
- `IrreversibleBlockHeightUnacceptable` events may fire inappropriately

**Cross-Chain Impact:**
LIB information is fundamental to cross-chain operations, as it determines which blocks are considered finalized for cross-chain indexing and transaction verification. Corrupted LIB round numbers could compromise cross-chain security guarantees.

## Likelihood Explanation

**Probability: MEDIUM - Requires Miner Privileges**

**Attacker Requirements:**
- Must be an active miner in the current miner list (controlled via election/governance)
- Must wait for scheduled time slot to produce a NextTerm or NextRound block
- Must be capable of crafting custom consensus transaction input (requires modified node software)

**Attack Complexity:**
The attack is technically simple - merely requires modifying the `ConfirmedIrreversibleBlockRoundNumber` field in the NextTermInput/NextRoundInput to an invalid value. No sophisticated cryptographic attacks, timing exploits, or multi-transaction coordination required.

**Execution Feasibility:**
While normal miners use `GenerateConsensusTransactions` to create consensus data, there is no cryptographic binding or merkle commitment that prevents a malicious miner from crafting arbitrary input. The consensus contract itself validates the input, and as demonstrated, that validation is insufficient. A compromised miner running modified node software can execute this attack with certainty during their mining turn.

**Detection Difficulty:**
The corruption does not cause immediate failures or reverts - it silently corrupts state. The mining status miscalculations may not be obvious until specific threshold conditions are met. This makes detection challenging without explicit invariant monitoring.

## Recommendation

Add `LibInformationValidationProvider` to the validation chain for `NextRound` and `NextTerm` behaviors, and enhance it to validate the fundamental invariant:

```csharp
// In AEDPoSContract_Validation.cs, modify the switch statement:
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

And enhance `LibInformationValidationProvider` to validate the invariant:

```csharp
// In LibInformationValidationProvider.cs, add after line 21:
// Validate that LIB round number is strictly less than current round number
if (providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
    providedRound.ConfirmedIrreversibleBlockRoundNumber >= providedRound.RoundNumber)
{
    validationResult.Message = "LIB round number must be less than current round number.";
    return validationResult;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanCorruptConsensusState_WithInvalidLibRoundNumber()
{
    // Setup: Initialize consensus with normal first round
    var initialMiners = GenerateInitialMiners(3);
    await InitializeConsensus(initialMiners);
    
    // Advance to round 2 normally
    await ProduceNormalBlocks(1);
    var currentRound = await GetCurrentRound();
    Assert.Equal(2, currentRound.RoundNumber);
    
    // Attacker (miner at index 0) crafts malicious NextRound input
    // with ConfirmedIrreversibleBlockRoundNumber >= RoundNumber
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1, // Valid: 3
        ConfirmedIrreversibleBlockRoundNumber = 3, // INVALID: should be < 3
        ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight,
        RealTimeMinersInformation = { GenerateNextRoundMinerInfo(initialMiners) },
        TermNumber = currentRound.TermNumber,
        RandomNumber = GenerateRandomNumber()
    };
    
    // Attack: Submit malicious NextRound transaction
    var attackResult = await MinerExecuteConsensusTransaction(
        initialMiners[0], 
        nameof(AEDPoSContract.NextRound), 
        maliciousInput
    );
    
    // Vulnerability: Transaction succeeds despite invalid LIB round number
    Assert.True(attackResult.Status == TransactionResultStatus.Mined);
    
    // Verify: Corrupted state is stored
    var corruptedRound = await GetCurrentRound();
    Assert.Equal(3, corruptedRound.RoundNumber);
    Assert.Equal(3, corruptedRound.ConfirmedIrreversibleBlockRoundNumber); // Corruption persists
    Assert.True(corruptedRound.ConfirmedIrreversibleBlockRoundNumber >= corruptedRound.RoundNumber);
    
    // Verify: Corruption propagates to next round
    await ProduceNormalBlocks(1);
    var nextRound = await GetCurrentRound();
    Assert.Equal(4, nextRound.RoundNumber);
    Assert.Equal(3, nextRound.ConfirmedIrreversibleBlockRoundNumber); // Still corrupted
    
    // Verify: Mining status calculation is broken
    var maxBlocksCount = await ConsensusContract.GetMaximumBlocksCount.CallAsync(new Empty());
    // With corrupted state, BlockchainMiningStatusEvaluator produces incorrect results
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-174)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L87-129)
```csharp
    private class BlockchainMiningStatusEvaluator
    {
        private const int AbnormalThresholdRoundsCount = 2;

        /// <summary>
        ///     Stands for R
        /// </summary>
        private readonly long _currentRoundNumber;

        /// <summary>
        ///     Stands for R_LIB
        /// </summary>
        private readonly long _libRoundNumber;

        /// <summary>
        ///     Stands for CB0
        /// </summary>
        private readonly int _maximumTinyBlocksCount;

        public BlockchainMiningStatusEvaluator(long currentConfirmedIrreversibleBlockRoundNumber,
            long currentRoundNumber, int maximumTinyBlocksCount)
        {
            _libRoundNumber = currentConfirmedIrreversibleBlockRoundNumber;
            _currentRoundNumber = currentRoundNumber;
            _maximumTinyBlocksCount = maximumTinyBlocksCount;
        }

        /// <summary>
        ///     Stands for CB1
        /// </summary>
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);

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
