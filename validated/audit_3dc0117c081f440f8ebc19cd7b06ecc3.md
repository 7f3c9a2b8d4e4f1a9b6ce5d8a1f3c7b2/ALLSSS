# Audit Report

## Title
Inconsistent LIB Fields in NextTerm Allow Manipulation of Mining Restrictions

## Summary
The NextTerm consensus transaction flow lacks validation for consistency between `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields. An authorized miner can provide inconsistent values during term transitions that pass all validation checks, are stored in consensus state, and subsequently manipulate the mining restriction logic to either bypass safety throttling or trigger unwarranted consensus DoS.

## Finding Description

The vulnerability exists because NextTerm accepts arbitrary LIB field values without validating their consistency, despite these fields being used independently for critical consensus decisions.

**Validation Gap**: The `NextTerm` method is public and accepts `NextTermInput` from authorized miners. [1](#0-0) 

The `NextTermInput.Create()` method directly copies both LIB fields from the input Round without any consistency validation between them: [2](#0-1) 

For NextTerm behavior, only `RoundTerminateValidationProvider` is added to the validation pipeline, which validates term/round number correctness but NOT the LIB fields: [3](#0-2) 

The `RoundTerminateValidationProvider` only checks that term number increments by 1, not LIB field consistency: [4](#0-3) 

The `LibInformationValidationProvider` (which validates LIB fields don't regress) is ONLY added for UpdateValue behavior, not for NextTerm: [5](#0-4) 

Moreover, even `LibInformationValidationProvider` only checks monotonicity (fields don't go backwards), not consistency between the two fields: [6](#0-5) 

**Hash Validation Bypass**: The `GetCheckableRound()` method used for hash calculation excludes LIB fields, only including RoundNumber, TermNumber, RealTimeMinersInformation, and BlockchainAge: [7](#0-6) 

This means inconsistent LIB values will not be detected by the after-execution hash comparison in `ValidateConsensusAfterExecution`. [8](#0-7) 

**Storage Without Validation**: The `ProcessNextTerm` method stores the round information without additional LIB field validation: [9](#0-8) 

**Attacker Control**: While the contract initially generates consistent LIB values from the current round, the miner receives the `NextTermInput` off-chain and can modify it before submission: [10](#0-9) [11](#0-10) 

## Impact Explanation

The inconsistent LIB values directly affect the `GetMaximumBlocksCount()` method, which uses both fields for different purposes: [12](#0-11) 

The `ConfirmedIrreversibleBlockRoundNumber` determines the mining status (Normal/Abnormal/Severe) via `BlockchainMiningStatusEvaluator`: [13](#0-12) 

While `ConfirmedIrreversibleBlockHeight` is used to calculate distance for event firing: [14](#0-13) 

These two fields should correspond to the same irreversible block, but no validation enforces this relationship.

**Attack Scenario 1 - Bypass Safety Restrictions:**
- Attacker sets `ConfirmedIrreversibleBlockRoundNumber` high (close to current round)
- Sets `ConfirmedIrreversibleBlockHeight` low (far behind actual LIB)
- Result: Status calculation shows Normal/Abnormal, allowing full mining capacity (8+ blocks per miner)
- Reality: Chain is far behind on irreversible blocks and should be in Severe status (1 block per miner)
- **Impact**: Undermines consensus safety mechanisms designed to throttle the chain when LIB falls behind, allowing excessive block production during unsafe conditions

**Attack Scenario 2 - Artificial Consensus DoS:**
- Attacker sets `ConfirmedIrreversibleBlockRoundNumber` low (many rounds behind)
- Sets `ConfirmedIrreversibleBlockHeight` high (close to current height)
- Result: Status calculation forces Severe status, restricting all miners to 1 block each
- Reality: Chain is healthy and should operate at normal capacity
- **Impact**: Artificially degrades consensus performance and chain throughput by 8x or more, effectively creating a denial of service

The impact fundamentally breaks consensus integrity by decoupling mining restrictions from actual chain finality state.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an authorized miner in the current or next term's miner list (elected position)
- Must be selected to mine the block performing the NextTerm transition (happens at term boundaries)

**Attack Feasibility:**
- Term transitions occur regularly in AEDPoS (every few days/weeks)
- With N miners, each has approximately 1/N chance per term transition
- Technical barrier is low: simply craft `NextTermInput` with inconsistent LIB values
- Transaction passes all validation checks (term/round number validation only)
- No automatic detection mechanism exists

**Probability Assessment:** Medium-High for a malicious elected miner
- Regular opportunities at predictable term boundaries
- Multiple miners could independently execute this attack
- Low complexity makes it an attractive attack vector for any malicious miner

## Recommendation

Add LIB field consistency validation to the NextTerm validation pipeline:

1. Add `LibInformationValidationProvider` to the NextTerm validation providers in `ValidateBeforeExecution`

2. Create a new validation provider that checks consistency between `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber`:

```csharp
public class LibFieldConsistencyValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        
        // If both LIB fields are set, validate they are consistent
        if (providedRound.ConfirmedIrreversibleBlockHeight > 0 && 
            providedRound.ConfirmedIrreversibleBlockRoundNumber > 0)
        {
            // Check that the LIB round number is not greater than current round
            if (providedRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.RoundNumber)
            {
                return new ValidationResult 
                { 
                    Message = "LIB round number cannot exceed current round number." 
                };
            }
            
            // Additional check: LIB height should be reasonable given the LIB round
            // (implementation depends on expected blocks per round)
        }
        
        return new ValidationResult { Success = true };
    }
}
```

3. Include LIB fields in the `GetCheckableRound()` hash calculation to detect manipulation during after-execution validation

## Proof of Concept

```csharp
[Fact]
public async Task NextTerm_InconsistentLIBFields_AllowsManipulation()
{
    // Setup: Initialize consensus with normal miners
    await InitializeConsensus();
    
    // Get current round information
    var currentRound = await GetCurrentRound();
    
    // Create NextTermInput with INCONSISTENT LIB values
    var maliciousNextTermInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber + 1,
        // Attack: Set round number high (appears close to current)
        ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber - 1,
        // But set height low (actually far behind)
        ConfirmedIrreversibleBlockHeight = 100,
        // Copy other required fields...
    };
    
    // Execute: Submit the malicious NextTerm transaction
    var result = await ConsensusContract.NextTerm.SendAsync(maliciousNextTermInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: The inconsistent values were stored
    var newRound = await GetCurrentRound();
    newRound.ConfirmedIrreversibleBlockRoundNumber.ShouldBe(currentRound.RoundNumber - 1);
    newRound.ConfirmedIrreversibleBlockHeight.ShouldBe(100);
    
    // Impact: GetMaximumBlocksCount uses inconsistent values
    var maxBlocks = await ConsensusContract.GetMaximumBlocksCount.CallAsync(new Empty());
    // Will return incorrect value based on manipulated LIB fields
}
```

## Notes

This vulnerability represents a fundamental flaw in the consensus validation logic where critical safety-related fields can be manipulated by authorized miners. The separation of concerns between round number validation and LIB field validation creates a gap that allows these fields to diverge from their expected consistent relationship. The impact is severe as it directly affects the chain's ability to self-regulate mining capacity based on finality progress, which is a core consensus safety mechanism.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L60-63)
```csharp
    public Hash GetHash(bool isContainPreviousInValue = true)
    {
        return HashHelper.ComputeFrom(GetCheckableRound(isContainPreviousInValue));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L172-179)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-37)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L106-129)
```csharp
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
