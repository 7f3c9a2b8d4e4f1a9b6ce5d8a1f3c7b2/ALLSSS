# Audit Report

## Title
Missing LIB Round Number Validation Allows Consensus State Corruption in NextTerm/NextRound Operations

## Summary
The AEDPoS consensus contract fails to validate that `ConfirmedIrreversibleBlockRoundNumber` is less than the current `RoundNumber` when processing `NextTerm` and `NextRound` operations. A malicious miner can inject consensus state where the Last Irreversible Block (LIB) round number equals or exceeds the current round number, violating the fundamental consensus invariant and causing permanent state corruption with mining status miscalculations.

## Finding Description

The vulnerability exists in the validation framework's selective application of validation providers based on consensus behavior type. For `NextTerm` and `NextRound` behaviors, the `LibInformationValidationProvider` that validates LIB constraints is not applied. [1](#0-0) 

The validation framework only applies `RoundTerminateValidationProvider` for `NextTerm` (which validates round/term number increment and InValue nullity) and adds `NextRoundMiningOrderValidationProvider` for `NextRound`, but critically omits `LibInformationValidationProvider` that is applied to `UpdateValue` operations. [2](#0-1) 

Even if `LibInformationValidationProvider` were applied, it only checks that LIB values don't regress backward, never validating the critical invariant that `ConfirmedIrreversibleBlockRoundNumber < RoundNumber`. [3](#0-2) 

**Attack Execution:**

A malicious miner crafts `NextTermInput` or `NextRoundInput` with valid `RoundNumber` increment but invalid `ConfirmedIrreversibleBlockRoundNumber >= RoundNumber` (or extremely high values). The malicious round is stored without additional validation. [4](#0-3) [5](#0-4) 

The corrupted LIB values persist because `GenerateNextRoundInformation` unconditionally copies these fields to subsequent rounds. [6](#0-5) 

If the attacker sets sufficiently high LIB values, the `ProcessUpdateValue` correction mechanism fails because its update condition requires `currentRound.ConfirmedIrreversibleBlockHeight < libHeight`, which evaluates to FALSE when the attacker-injected LIB is artificially inflated. [7](#0-6) 

## Impact Explanation

**Severity: HIGH - Critical Consensus Invariant Violation**

The blockchain consensus state permanently contains the logically impossible condition where `ConfirmedIrreversibleBlockRoundNumber >= RoundNumber`, fundamentally violating the protocol invariant that Last Irreversible Block must lag behind current round.

The `BlockchainMiningStatusEvaluator` determines blockchain health using arithmetic that assumes `_libRoundNumber < _currentRoundNumber`. [8](#0-7) 

When the invariant is violated (e.g., `_libRoundNumber = 200`, `_currentRoundNumber = 101`):
- Abnormal condition `_libRoundNumber + 2 < _currentRoundNumber` evaluates incorrectly (202 < 101 = FALSE)
- Severe condition `_currentRoundNumber >= _libRoundNumber + threshold` evaluates incorrectly (101 >= 208 = FALSE)
- Mining status reports Normal despite blockchain corruption
- Block production limits miscalculated
- `IrreversibleBlockHeightUnacceptable` events may fire inappropriately

LIB information is fundamental to cross-chain finality guarantees, potentially compromising cross-chain security.

## Likelihood Explanation

**Probability: MEDIUM - Requires Miner Privileges**

**Attacker Requirements:**
- Must be active miner in current list (obtainable through election/governance)
- Must wait for scheduled time slot to produce NextTerm/NextRound block
- Must craft custom consensus input (requires modified node software)

**Execution Feasibility:**
The attack is technically simple - modify `ConfirmedIrreversibleBlockRoundNumber` field to invalid values. No cryptographic attacks, timing exploits, or multi-transaction coordination required. A compromised miner with modified node software can execute this with certainty during their mining turn.

**Detection Difficulty:**
The corruption doesn't cause immediate failures or reverts - it silently corrupts state. Mining status miscalculations may not be obvious until specific threshold conditions are met, making detection challenging without explicit invariant monitoring.

## Recommendation

Add validation in the consensus validation framework to enforce the invariant that `ConfirmedIrreversibleBlockRoundNumber < RoundNumber` for all consensus behaviors:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
    providedRound.ConfirmedIrreversibleBlockRoundNumber >= providedRound.RoundNumber)
{
    validationResult.Message = "LIB round number must be less than current round number.";
    return validationResult;
}
```

Additionally, apply `LibInformationValidationProvider` to `NextTerm` and `NextRound` behaviors in `AEDPoSContract_Validation.cs`:

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

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanCorrupt_LIBRoundNumber()
{
    // Setup: Get to a valid consensus state with round 100
    await InitializeConsensusAsync();
    await AdvanceToRound(100);
    
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(100, currentRound.RoundNumber);
    Assert.True(currentRound.ConfirmedIrreversibleBlockRoundNumber < 100); // Normal invariant
    
    // Attack: Malicious miner produces NextRound with corrupted LIB
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = 101, // Valid increment
        ConfirmedIrreversibleBlockRoundNumber = 101, // INVALID: equals current round
        ConfirmedIrreversibleBlockHeight = 999999, // Set high to prevent auto-correction
        // ... other fields from GenerateNextRoundInformation
    };
    
    // Execute attack as authorized miner
    var result = await MinerConsensusStub.NextRound.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Attack succeeds
    
    // Verify corruption persisted
    var corruptedRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(101, corruptedRound.RoundNumber);
    Assert.Equal(101, corruptedRound.ConfirmedIrreversibleBlockRoundNumber); // INVARIANT VIOLATED
    
    // Verify mining status miscalculation
    var maxBlocksCount = await ConsensusStub.GetMaximumBlocksCount.CallAsync(new Empty());
    // Should trigger Abnormal/Severe status but reports Normal due to broken arithmetic
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
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

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
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
