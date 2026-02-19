# Audit Report

## Title
LIB Height Can Decrease During NextRound and NextTerm Transitions Due to Missing Validation

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) height during `NextRound` and `NextTerm` transitions. The `LibInformationValidationProvider` is only applied for `UpdateValue` behavior, and the consensus hash validation explicitly excludes `ConfirmedIrreversibleBlockHeight`. This allows any elected miner to provide a `NextRound` or `NextTerm` block with a decreased LIB height, violating the critical consensus invariant that finality can only move forward.

## Finding Description

The vulnerability consists of three interconnected defects in the consensus validation flow:

**1. Missing LIB Validation for NextRound/NextTerm**

The validation logic only applies `LibInformationValidationProvider` for `UpdateValue` behavior: [1](#0-0) 

For `NextRound` (lines 84-88) and `NextTerm` (lines 89-91), only `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider` are added, but NOT `LibInformationValidationProvider` which checks LIB monotonicity.

The `LibInformationValidationProvider` contains the critical check that prevents LIB from decreasing: [2](#0-1) 

**2. Hash Validation Excludes ConfirmedIrreversibleBlockHeight**

The `GetCheckableRound` method used for consensus hash validation only includes specific fields: [3](#0-2) 

It explicitly excludes `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` from the hash calculation, allowing these fields to be modified without detection during hash validation.

**3. Direct State Save Without LIB Validation**

The `ProcessNextRound` method converts the input and saves it directly: [4](#0-3) 

The input is converted to a Round object (line 110) which includes the `ConfirmedIrreversibleBlockHeight`: [5](#0-4) 

Then saved directly via `AddRoundInformation` (line 156) without any LIB validation: [6](#0-5) 

**Attack Execution Path:**

1. When generating next round information, the current LIB is copied to the new round: [7](#0-6) 

2. A malicious miner scheduled to produce a `NextRound` or `NextTerm` block can modify `ConfirmedIrreversibleBlockHeight` to a lower value before block production

3. The modified block passes validation because:
   - `LibInformationValidationProvider` is not applied for NextRound/NextTerm
   - Hash validation doesn't include the modified field

4. The manipulated Round is saved to state with the decreased LIB height

## Impact Explanation

**Critical Consensus Invariant Violation:**
- LIB (Last Irreversible Block) represents the blockchain finality boundary - blocks below this height are considered permanently finalized and irreversible
- Decreasing LIB violates the fundamental consensus guarantee that finality only moves forward
- This breaks the core security model where confirmed blocks cannot be reorganized

**Cross-Chain Security Impact:**
- Cross-chain indexing and verification rely on LIB for security guarantees
- The cross-chain system uses irreversible block information for validation
- Decreasing LIB could invalidate previously accepted cross-chain transactions
- May enable double-spending attacks across chains if transactions were confirmed based on the original LIB

**Systemic Impact:**
- Applications and users relying on block finality guarantees lose security assurances
- Smart contracts depending on finality (e.g., time-locked operations, irreversible settlements) become vulnerable
- Treasury distributions, profit calculations, and other consensus-dependent operations may be compromised

The severity is **CRITICAL** because it breaks a fundamental blockchain invariant that underpins the entire security model.

## Likelihood Explanation

**Attacker Requirements:**
- Attacker must be an elected miner in the consensus miner list
- Must be scheduled to produce a NextRound or NextTerm block during their assigned time slot
- No additional privileges beyond normal miner status required

**Attack Complexity:**
- **Very Low**: Simply modify the `ConfirmedIrreversibleBlockHeight` field in the Round object before including it in the block header
- No cryptographic manipulation required
- No complex state race conditions to exploit
- The attack is deterministic and reproducible

**Feasibility:**
- NextRound transitions occur regularly (every round, typically every few minutes)
- NextTerm transitions occur periodically (every term, typically daily/weekly depending on configuration)
- Any miner will eventually be scheduled for these transitions
- No unusual blockchain state or timing requirements needed

**Detection:**
- No validation checks will catch the manipulation
- No events or logs specifically track LIB progression validation
- Attack succeeds silently unless external monitoring specifically tracks LIB monotonicity
- Standard consensus validation passes the malicious block

The likelihood is **HIGH** because any malicious miner can execute this attack with 100% success rate during their regularly scheduled NextRound/NextTerm block production.

## Recommendation

Apply `LibInformationValidationProvider` for all consensus behaviors that can modify the Round state, not just `UpdateValue`. Modify the validation logic in `AEDPoSContract_Validation.cs`:

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

Additionally, consider including `ConfirmedIrreversibleBlockHeight` in the consensus hash calculation in `GetCheckableRound` to provide defense-in-depth, though the validation fix is the primary mitigation.

## Proof of Concept

```csharp
// Test demonstrating LIB can decrease during NextRound transition
[Fact]
public async Task NextRound_CanDecreaseLIB_WithoutValidation()
{
    // Setup: Initialize consensus with current LIB = 1000
    var currentRound = GenerateRoundWithLIB(1000);
    await InitializeConsensus(currentRound);
    
    // Malicious miner generates NextRound with decreased LIB
    var nextRoundInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        ConfirmedIrreversibleBlockHeight = 500, // DECREASED from 1000
        ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber,
        RealTimeMinersInformation = { currentRound.RealTimeMinersInformation },
        // ... other required fields
    };
    
    // Execute NextRound transaction
    var result = await ConsensusContract.NextRound(nextRoundInput);
    
    // Verify: Transaction succeeds (no validation failure)
    result.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: LIB decreased in state
    var savedRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(500, savedRound.ConfirmedIrreversibleBlockHeight); // LIB decreased!
    
    // This violates the invariant: LIB should never decrease
    // Expected behavior: Transaction should have been rejected
}
```

## Notes

This vulnerability affects the core consensus finality mechanism. While the immediate impact requires a malicious elected miner, the consequences of successfully decreasing LIB are severe and affect the entire blockchain's security model. The fix should be prioritized as it addresses a fundamental consensus invariant violation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L199-205)
```csharp
        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
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
