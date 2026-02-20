# Audit Report

## Title
Consensus Permanent DoS via Unconstrained LIB Injection in NextTerm/NextRound Transactions

## Summary
The AEDPoS consensus contract lacks Last Irreversible Block (LIB) validation for `NextTerm` and `NextRound` behaviors. A malicious miner can inject arbitrarily high `ConfirmedIrreversibleBlockHeight` values during term/round transitions, permanently corrupting consensus state and halting all block production until a hard fork is deployed.

## Finding Description

The AEDPoS consensus system applies different validation rules based on the consensus behavior type. The validation logic in `ValidateBeforeExecution` correctly includes `LibInformationValidationProvider` for `UpdateValue` behavior to prevent Last Irreversible Block heights from decreasing. However, this critical validation is completely absent for `NextTerm` and `NextRound` behaviors. [1](#0-0) 

The `RoundTerminateValidationProvider`, which is the only validator applied to `NextTerm` and `NextRound` transactions, only validates round/term number increments and that `InValue` fields are null. It does not validate LIB values at all. [2](#0-1) 

When a `NextTerm` or `NextRound` transaction is processed, the transaction input's LIB values are directly copied to the new round without any validation through the `ToRound()` method. [3](#0-2) [4](#0-3) 

This corrupted round is then permanently persisted to blockchain state via `AddRoundInformation`. [5](#0-4) [6](#0-5) 

Once LIB is corrupted with an extremely high value (e.g., `Int64.MaxValue - 1000`), all subsequent `UpdateValue` transactions fail validation because `LibInformationValidationProvider` rejects any attempt to provide a lower LIB value, which it correctly interprets as backward movement. [7](#0-6) 

This creates a permanent consensus deadlock. When a miner hasn't produced a block yet (i.e., `OutValue` is `null`), the consensus behavior provider returns `UpdateValue` behavior. [8](#0-7) [9](#0-8) 

However, since the baseRound has corrupted (inflated) LIB and the providedRound has the real (lower) LIB, the `UpdateValue` transaction fails validation. Without `UpdateValue` succeeding, `OutValue` remains `null`, creating an infinite loop where no miner can produce blocks.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables a complete denial-of-service attack on the entire blockchain with catastrophic and permanent consequences:

1. **Complete Blockchain Halt**: All block production ceases immediately after the corrupted term/round transition when miners attempt to produce blocks. The consensus system cannot progress.

2. **Transaction Impossibility**: No transactions can be included in blocks, effectively freezing all on-chain activity including token transfers, smart contract executions, and governance operations.

3. **Hard Fork Requirement**: The only recovery mechanism is deploying a hard fork with manually corrected state, requiring coordinated emergency response from all validators and infrastructure providers.

4. **Economic Catastrophe**: All trading, DeFi operations, NFT transactions, and business operations built on the chain are halted indefinitely, causing massive financial losses.

5. **No Automated Recovery**: Unlike temporary network issues or consensus stalls that can self-correct, this state corruption is permanently stored in the blockchain state and cannot be reversed through any protocol mechanism.

The attack violates the fundamental consensus invariant that Last Irreversible Block height must monotonically increase. Once this invariant is violated through malicious state corruption (rather than legitimate consensus progression), the system enters an unrecoverable failure state.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible with minimal technical and economic barriers:

**Attacker Prerequisites:**
- Must be an active miner in the current consensus round
- Miners are elected through standard governance mechanisms, making this a realistic semi-privileged threat model
- Multiple independent miners exist in typical production deployments

**Attack Complexity: LOW**

The attack requires only four simple steps:
1. Wait for a legitimate term or round transition period (occurs regularly in normal operation)
2. Call `GenerateConsensusTransactions` to obtain a valid `NextTermInput` or `NextRoundInput`
3. Modify the `ConfirmedIrreversibleBlockHeight` field to an arbitrarily high value (e.g., `Int64.MaxValue - 1000`)
4. Sign and submit the modified transaction

**Technical Feasibility:**
- No cryptographic challenges or complex timing races required
- The validation gap is architectural and systematic, not a race condition
- Attack is 100% deterministic and reproducible
- Transaction appears valid during initial validation since LIB checks are absent

**Economic Cost:** Minimal - only standard transaction gas fees are required

**Detection Difficulty:** The malicious transaction may appear normal during validation, with the corruption only manifesting when subsequent miners attempt to produce blocks and all fail validation, making immediate detection challenging.

## Recommendation

Apply `LibInformationValidationProvider` to `NextTerm` and `NextRound` behaviors in addition to `UpdateValue` behavior. This ensures that LIB values cannot move backward during any consensus transition.

Modify `ValidateBeforeExecution` in `AEDPoSContract_Validation.cs`:

```csharp
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
}
```

This fix maintains the critical LIB monotonicity invariant across all consensus state transitions.

## Proof of Concept

```csharp
[Fact]
public async Task Test_LIB_Injection_Attack()
{
    // Setup: Initialize consensus with a miner
    var miner = GetMiner();
    await InitializeConsensus(miner);
    
    // Advance to a point where NextTerm is imminent
    await AdvanceToTermTransition();
    
    // Attacker (miner) generates legitimate NextTerm transaction
    var legitNextTermInput = await GenerateNextTermInput(miner);
    
    // ATTACK: Modify ConfirmedIrreversibleBlockHeight to inflated value
    legitNextTermInput.ConfirmedIrreversibleBlockHeight = long.MaxValue - 1000;
    
    // Submit the malicious NextTerm transaction - it passes validation!
    var result = await SubmitNextTermTransaction(miner, legitNextTermInput);
    result.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Corrupted LIB is now in state
    var currentRound = await GetCurrentRound();
    currentRound.ConfirmedIrreversibleBlockHeight.ShouldBe(long.MaxValue - 1000);
    
    // Attempt to produce next block - this will FAIL permanently
    var nextBlockAttempt = await AttemptBlockProduction(miner);
    nextBlockAttempt.Status.ShouldBe(TransactionResultStatus.Failed);
    nextBlockAttempt.Error.ShouldContain("Incorrect lib information");
    
    // Consensus is now PERMANENTLY HALTED - no recovery possible without hard fork
}
```

**Notes:**
- This vulnerability affects all in-scope consensus contract files
- The attack requires no compromised keys or consensus manipulation beyond normal miner privileges
- The validation gap is architectural, making it deterministically exploitable
- Impact is maximum severity: complete and permanent chain halt requiring emergency hard fork

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-163)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-115)
```csharp
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;

            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;

            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
        }
```
