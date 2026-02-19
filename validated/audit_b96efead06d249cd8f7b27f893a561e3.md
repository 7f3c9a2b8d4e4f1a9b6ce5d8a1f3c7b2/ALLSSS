# Audit Report

## Title
Missing LIB Validation in NextRound/NextTerm Allows Arbitrary Irreversible Block Height Manipulation

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) values during NextRound and NextTerm transitions. The `LibInformationValidationProvider` is only applied to UpdateValue behavior, allowing malicious miners to submit arbitrary LIB values that will be accepted and stored without verification, corrupting consensus finality guarantees and blockchain health monitoring.

## Finding Description

The validation architecture conditionally applies different validators based on consensus behavior. For UpdateValue, the `LibInformationValidationProvider` is added to prevent LIB values from going backward [1](#0-0) . However, for NextRound and NextTerm behaviors, this validator is conspicuously absent [2](#0-1) .

The `LibInformationValidationProvider` itself contains logic to validate that provided LIB values don't decrease compared to the base round [3](#0-2) , but this validation is never applied to NextRound/NextTerm behaviors.

During NextRound processing, the input is directly converted to a Round object via `ToRound()` [4](#0-3) , which blindly copies the `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields without any validation. This converted Round is then stored directly into state [5](#0-4) .

The honest code path generates NextRound data using `GenerateNextRoundInformation`, which correctly copies LIB values from the current round [6](#0-5) . However, since `NextRound` is a public method accepting `NextRoundInput` as a parameter [7](#0-6) , there is no enforcement that the submitted data matches the honestly generated values. A malicious miner can modify the LIB fields before submission, and the contract will accept them.

## Impact Explanation

**Consensus Integrity Violation:** LIB values represent the blockchain's irreversible finality boundary. Arbitrary manipulation breaks the fundamental consensus guarantee that blocks below LIB cannot be reorganized.

**Blockchain Health Monitoring Corruption:** The `GetMaximumBlocksCount` function uses stored LIB values to assess blockchain health status [8](#0-7) . Inflated LIB values could prevent proper detection of abnormal/severe mining status, allowing continuous fork conditions that should trigger defensive measures.

**Cross-Chain Finality Propagation:** In multi-chain deployments, main chain LIB values inform side chains about which parent chain blocks are finalized. Corrupted LIB values could cause side chains to index unconfirmed main chain blocks as irreversible, leading to potential cross-chain reorganization vulnerabilities.

**State Corruption Persistence:** Once injected, corrupted LIB values affect subsequent UpdateValue operations, as the LIB calculation during UpdateValue compares against the stored LIB from previous rounds [9](#0-8) .

Impact severity: **High** - breaks consensus finality guarantees and can cascade across multi-chain deployments.

## Likelihood Explanation

**Attacker Profile:** Any miner in the validator set can execute this attack when they become the extra block producer for a round. In AEDPoS, this role rotates among miners based on cryptographic randomness, ensuring all miners eventually obtain this capability.

**Attack Complexity:** Low. The attack requires:
1. Wait for designation as extra block producer (happens naturally through rotation)
2. Generate honest consensus data via off-chain node software
3. Modify `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields in NextRoundInput
4. Submit the modified NextRound transaction

**Detection Difficulty:** Initial detection is difficult as the contract accepts the values without validation. Discrepancies would only emerge through external monitoring comparing stored LIB against actual block confirmation status, or when UpdateValue calculations produce inconsistent results.

**Preconditions:** Requires a malicious miner willing to corrupt consensus state. Given the economic incentives and reputation risks in a production blockchain, the probability of an intentional attack is moderate. However, the vulnerability could also be triggered accidentally by buggy miner software.

Likelihood: **Medium** - requires miner compromise but attack is straightforward once opportunity arises.

## Recommendation

Add `LibInformationValidationProvider` to the validation pipeline for both NextRound and NextTerm behaviors:

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

This ensures that LIB values in NextRound/NextTerm inputs are validated against the base round, preventing backward movement or arbitrary jumps in LIB height.

Additionally, consider adding an upper bound check to prevent LIB values from being set higher than the current block height, as LIB cannot exceed the tip of the chain.

## Proof of Concept

```csharp
// POC: Malicious miner submits NextRound with inflated LIB
[Fact]
public async Task MaliciousNextRound_ArbitraryLIB_Accepted()
{
    // Setup: Initialize consensus with first round
    await InitializeConsensusContract();
    
    // Normal progression: mine some blocks in round 1
    var currentRound = await GetCurrentRoundInformation();
    
    // Attacker: Become extra block producer and generate NextRound data
    var maliciousNextRound = GenerateNextRoundInformation(currentRound);
    
    // ATTACK: Inflate LIB values to arbitrary heights
    var maliciousInput = NextRoundInput.Create(maliciousNextRound, GenerateRandomNumber());
    maliciousInput.ConfirmedIrreversibleBlockHeight = 999999; // Arbitrary inflated value
    maliciousInput.ConfirmedIrreversibleBlockRoundNumber = 500; // Arbitrary inflated value
    
    // Submit malicious NextRound transaction
    var result = await ConsensusStub.NextRound.SendAsync(maliciousInput);
    
    // Verify: Contract accepts the malicious values without validation
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Corrupted LIB values are stored in state
    var storedRound = await GetCurrentRoundInformation();
    storedRound.ConfirmedIrreversibleBlockHeight.ShouldBe(999999);
    storedRound.ConfirmedIrreversibleBlockRoundNumber.ShouldBe(500);
    
    // Impact: Blockchain health assessment is corrupted
    var maxBlocksCount = await ConsensusStub.GetMaximumBlocksCount.CallAsync(new Empty());
    // GetMaximumBlocksCount now uses corrupted LIB for health status calculation
}
```

## Notes

The vulnerability exists because the validation architecture trusts that miners will submit honestly generated Round data. While the honest generation path (`GenerateNextRoundInformation`) correctly maintains LIB values, there is no cryptographic commitment or on-chain verification that the submitted NextRound data matches what the honest function would produce. This design assumes miners are honest, violating defense-in-depth principles for critical consensus parameters.

The same issue affects NextTermInput through an identical code path [10](#0-9) .

In contrast, UpdateValue behavior properly validates LIB values and recalculates them using `LastIrreversibleBlockHeightCalculator` [11](#0-10) , demonstrating that the system has the capability to validate LIB but simply doesn't apply it to NextRound/NextTerm.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-71)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L25-31)
```csharp
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");
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
