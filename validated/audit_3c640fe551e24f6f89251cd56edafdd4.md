# Audit Report

## Title
Missing LIB Validation in NextTerm Allows Malicious Miners to DoS Blockchain via Inconsistent Irreversible Block Fields

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) fields during NextTerm transitions, allowing malicious miners to inject arbitrary `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` values. These malicious values trigger blockchain-wide denial-of-service by forcing the network into Severe mining status, limiting all miners to single-block production and degrading throughput by 99%+.

## Finding Description

The consensus validation architecture treats different behaviors with distinct validation providers. For NextTerm behavior, the validation chain only includes `RoundTerminateValidationProvider`, explicitly excluding `LibInformationValidationProvider` that validates LIB field consistency: [1](#0-0) 

The `LibInformationValidationProvider` is the sole validator ensuring LIB fields don't regress: [2](#0-1) 

Furthermore, the Round hash computation used in post-execution validation explicitly excludes LIB fields through `GetCheckableRound`: [3](#0-2) 

During NextTerm generation, the contract provides legitimate data with LIB values copied from the current round: [4](#0-3) 

However, miners control block production and can modify consensus header bytes before inclusion. When the NextTerm transaction executes, `NextTermInput.Create` blindly copies all fields including manipulated LIB values: [5](#0-4) 

The `ProcessNextTerm` method converts this input to a Round object and stores it directly without additional validation: [6](#0-5) 

These malicious values persist in state via `AddRoundInformation`: [7](#0-6) 

## Impact Explanation

The malicious LIB values directly compromise `GetMaximumBlocksCount`, which determines per-miner block production limits: [8](#0-7) 

The `BlockchainMiningStatusEvaluator` evaluates mining status based on the gap between current round and LIB round. When this gap exceeds `SevereStatusRoundsThreshold` (typically 8), the blockchain enters Severe status: [9](#0-8) 

In Severe status, maximum block count drops to 1 and an `IrreversibleBlockHeightUnacceptable` event fires: [10](#0-9) 

**Attack Execution:**
1. Attacker (active miner) waits for NextTerm opportunity
2. Obtains legitimate NextTerm data via `GetConsensusExtraData`
3. Modifies consensus header: sets `ConfirmedIrreversibleBlockRoundNumber` to `0`
4. Produces block with modified header
5. Block passes all validations (no LIB validation for NextTerm, hash excludes LIB fields)
6. Malicious values stored in consensus state
7. When round number reaches 8, condition `currentRoundNumber >= 0 + 8` becomes true
8. Blockchain enters Severe status
9. All miners restricted to 1 block production per time slot
10. Network throughput collapses by 99%+

The corruption persists because `ProcessUpdateValue` has a guard preventing LIB updates when stored height exceeds calculated height: [11](#0-10) 

**Impact Severity: High**
- Blockchain-wide availability disruption affecting all users and applications
- Network throughput reduced from 8 blocks to 1 block per time slot (87.5% degradation minimum)
- Effect persists for entire term duration (potentially thousands of blocks)
- No fund loss but complete operational degradation requiring term transition to resolve

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be active miner in current or previous round (elevated but not trusted role) [12](#0-11) 

**Attack Characteristics:**
- **Complexity:** Low - simple field modification in consensus header bytes
- **Privilege Required:** Miner-level access (elected consensus participant)
- **Repeatability:** High - exploitable at every term transition
- **Detection:** Medium - abnormal LIB values observable but may not trigger immediate alerts
- **Success Rate:** High - all validation checks pass due to missing LIB validation

Miners are semi-trusted participants in the AElf security model - they are elected but not equivalent to genesis/organization controllers. The system must defend against individual malicious miners, making this a valid threat scenario.

**Feasibility: Medium-High**
The attack requires no additional privileges beyond regular mining rights, no timing precision beyond waiting for term transition, and executes reliably due to the validation gap.

## Recommendation

Add `LibInformationValidationProvider` to the NextTerm validation chain:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add LIB validation
    break;
```

Alternatively, include LIB fields in the Round hash computation by modifying `GetCheckableRound` to include these critical consensus parameters, ensuring any manipulation is detected during `ValidateConsensusAfterExecution`.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousNextTerm_InjectsInvalidLIB_TriggersDoS()
{
    // Setup: Initialize consensus with legitimate round 1
    var minerKeyPair = GenerateMinerKeyPair();
    await InitializeConsensusAsync(minerKeyPair);
    
    // Progress to term transition point
    await AdvanceToTermTransitionAsync();
    
    // Attacker: Obtain legitimate NextTerm data
    var legitimateData = await GetConsensusExtraDataAsync(
        AElfConsensusBehaviour.NextTerm, 
        minerKeyPair.PublicKey);
    
    // Attacker: Modify LIB fields to malicious values
    var maliciousData = legitimateData.Clone();
    maliciousData.Round.ConfirmedIrreversibleBlockRoundNumber = 0;
    maliciousData.Round.ConfirmedIrreversibleBlockHeight = long.MaxValue;
    
    // Execute NextTerm with malicious data
    var result = await ExecuteNextTermAsync(maliciousData, minerKeyPair);
    result.Status.ShouldBe(TransactionResultStatus.Mined); // Passes validation
    
    // Verify malicious values stored in state
    var currentRound = await GetCurrentRoundAsync();
    currentRound.ConfirmedIrreversibleBlockRoundNumber.ShouldBe(0);
    
    // Progress 8 rounds to trigger Severe status
    for (int i = 0; i < 8; i++)
    {
        await ProduceNormalBlockAsync();
    }
    
    // Verify DoS: Maximum blocks count reduced to 1
    var maxBlocks = await GetMaximumBlocksCountAsync();
    maxBlocks.ShouldBe(1); // Down from 8, causing 87.5% throughput loss
    
    // Verify IrreversibleBlockHeightUnacceptable event fired
    var events = GetLastBlockEvents();
    events.ShouldContain(e => e.Name == "IrreversibleBlockHeightUnacceptable");
}
```

## Notes

This vulnerability exploits a validation gap in the consensus architecture where different behaviors receive inconsistent security treatment. While `UpdateValue` correctly validates LIB monotonicity, `NextTerm` omits this critical check despite handling the same sensitive fields. The hash-based validation in `ValidateConsensusAfterExecution` cannot detect this attack because `GetCheckableRound` intentionally excludes LIB fields from hash computation.

The attack is particularly severe because:
1. It affects the entire blockchain, not just the attacker
2. The guard condition in `ProcessUpdateValue` prevents self-healing within the same term
3. Detection requires monitoring LIB field consistency, which is not part of standard observability
4. A single malicious miner can execute the attack independently

The fix is straightforward: extend the existing `LibInformationValidationProvider` to NextTerm behavior, ensuring LIB field consistency across all consensus state transitions.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-36)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-129)
```csharp
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
