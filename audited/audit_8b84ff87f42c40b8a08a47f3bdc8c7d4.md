# Audit Report

## Title
Unvalidated Extra Block Producer Invariant Enables Consensus DoS via Single() Exception

## Summary
The AEDPoS consensus contract fails to validate that exactly one extra block producer exists in round data submitted by miners. The `IsCurrentMiner` function uses `.Single()` to retrieve the extra block producer, which throws an `InvalidOperationException` when zero or multiple miners have `IsExtraBlockProducer=true`. Byzantine miners can exploit this by submitting malformed `NextRoundInput` or `NextTermInput` to cause denial of service in consensus and cross-chain operations.

## Finding Description

The vulnerability exists in the consensus round validation logic where critical invariants are not enforced.

**Root Cause:** The `IsCurrentMiner` function unconditionally uses `.Single()` to retrieve the extra block producer from the current round [1](#0-0) . This LINQ operator throws `InvalidOperationException` if the predicate matches zero or multiple elements.

Similarly, `GetExtraBlockProducerInformation` uses `.First()` which throws when no element matches [2](#0-1) .

**Attack Vector:** Miners submit consensus updates via `NextRound` [3](#0-2)  and `NextTerm` methods. These inputs are processed by `ProcessNextRound` [4](#0-3)  and `ProcessNextTerm` [5](#0-4) , which convert the input via `ToRound()` without validation [6](#0-5) .

**Missing Validation:** The validation pipeline checks round numbers, term numbers, and mining orders [7](#0-6) , but does NOT validate the extra block producer count. The `RoundTerminateValidationProvider` only validates round/term numbers and InValue fields [8](#0-7) .

**Contrast with Normal Behavior:** During legitimate round generation, the system always assigns exactly one extra block producer [9](#0-8) . However, miners providing their own round data bypass this logic.

**Permission Check:** The `PreCheck()` method only verifies the sender is in the current or previous round's miner list [10](#0-9) , but does not validate the structural integrity of the submitted round data.

## Impact Explanation

**Cross-Chain Communication Blocked:** The `IsCurrentMiner` check gates critical cross-chain indexing operations. Both `ProposeCrossChainIndexing` [11](#0-10)  and `ReleaseCrossChainIndexingProposal` [12](#0-11)  call `AssertAddressIsCurrentMiner`, which invokes `CheckCrossChainIndexingPermission` [13](#0-12) . This in turn calls `IsCurrentMiner` [14](#0-13) .

When the malicious round data violates the invariant, `IsCurrentMiner` throws an exception, completely blocking cross-chain indexing operations and halting parent-child chain communication.

**Consensus Operation Disruption:** Mining permission validation and extra block time slot checks depend on these functions. The exception propagates through the consensus system, preventing normal block production workflows.

**Severity: HIGH** - Complete disruption of consensus and cross-chain functionality until the malicious round data ages out of the system or requires governance intervention to recover.

## Likelihood Explanation

**Attacker Requirements:** Only active miners can call `NextRound` or `NextTerm` due to the permission check in `PreCheck()`. This requires a byzantine miner, which is a realistic threat model for consensus systems.

**Attack Complexity: TRIVIAL**
1. Construct `NextRoundInput` with `RealTimeMinersInformation` where zero or multiple miners have `IsExtraBlockProducer = true`
2. Submit via `NextRound` transaction during the attacker's mining turn
3. The corrupted round passes all existing validations
4. Gets stored in state
5. Subsequent `IsCurrentMiner` calls throw exceptions

**Detection:** The attack is immediately visible as it breaks consensus operations. The malicious miner is traceable from block data and could face slashing. However, the damage occurs before remediation.

**Probability: MEDIUM** - While requiring a byzantine miner reduces likelihood, the technical execution is trivial and the validation gap is definitive. Feasible for compromised nodes or attackers willing to sacrifice miner stake for temporary disruption.

## Recommendation

Add validation to enforce the extra block producer invariant before storing round data:

```csharp
private void ValidateExtraBlockProducerInvariant(Round round)
{
    var extraBlockProducerCount = round.RealTimeMinersInformation.Values
        .Count(m => m.IsExtraBlockProducer);
    Assert(extraBlockProducerCount == 1, 
        "Round must have exactly one extra block producer.");
}
```

Call this validation in both `ProcessNextRound` and `ProcessNextTerm` before calling `AddRoundInformation`:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    ValidateExtraBlockProducerInvariant(nextRound); // Add this line
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of method
}
```

Alternatively, add an `ExtraBlockProducerValidationProvider` to the validation pipeline that checks this invariant during the `ValidateBeforeExecution` phase.

## Proof of Concept

```csharp
[Fact]
public async Task ExtraBlockProducerInvariantDoS_Test()
{
    // Setup: Initialize consensus with valid miners
    var initialMiners = GenerateMiners(3);
    await InitializeConsensus(initialMiners);
    
    // Attack: Malicious miner constructs NextRoundInput with ZERO extra block producers
    var maliciousRound = new NextRoundInput
    {
        RoundNumber = 2,
        TermNumber = 1,
        RealTimeMinersInformation = 
        {
            initialMiners.Select(m => new KeyValuePair<string, MinerInRound>(
                m.PublicKey, 
                new MinerInRound { 
                    Pubkey = m.PublicKey,
                    IsExtraBlockProducer = false // ALL set to false - violates invariant
                }))
        }
    };
    
    // Submit malicious round (will succeed and store corrupted data)
    var result = await ConsensusStub.NextRound.SendAsync(maliciousRound);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify DoS: IsCurrentMiner now throws exception
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await ConsensusStub.IsCurrentMiner.CallAsync(initialMiners[0].Address);
    });
    exception.Message.ShouldContain("Sequence contains no matching element");
    
    // Verify cross-chain operations blocked
    var crossChainException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await CrossChainStub.ProposeCrossChainIndexing.SendAsync(new CrossChainBlockData());
    });
    // Cross-chain operations now fail due to IsCurrentMiner throwing
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L169-170)
```csharp
        var supposedExtraBlockProducer =
            currentRound.RealTimeMinersInformation.Single(m => m.Value.IsExtraBlockProducer).Key;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L39-42)
```csharp
    private MinerInRound GetExtraBlockProducerInformation()
    {
        return RealTimeMinersInformation.First(bp => bp.Value.IsExtraBlockProducer).Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-163)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-65)
```csharp
        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-286)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-297)
```csharp
    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```
