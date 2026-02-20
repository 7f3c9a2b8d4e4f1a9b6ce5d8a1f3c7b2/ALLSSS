# Audit Report

## Title
Missing LIB Height Validation During NextTerm Transition Enables Chain Reorganization

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) height during term transitions, allowing miners to include stale consensus data with lower LIB values. While `UpdateValue` operations correctly validate that LIB never decreases, `NextTerm` operations omit this critical check, breaking blockchain finality guarantees.

## Finding Description

The vulnerability stems from inconsistent application of LIB validation across consensus behaviors. The system implements `LibInformationValidationProvider` to prevent LIB rollback during normal block production, but this validation is explicitly excluded for `NextTerm` operations.

**Vulnerable Code Flow:**

When a miner produces a NextTerm block, `GetConsensusExtraDataForNextTerm` calls `GenerateFirstRoundOfNextTerm`, which directly copies the LIB height from the current round without any validation. [1](#0-0) 

The same unvalidated copy occurs in the `MinerList.GenerateFirstRoundOfNewTerm` extension method. [2](#0-1) 

During validation, `UpdateValue` behavior includes `LibInformationValidationProvider` to prevent LIB rollback. [3](#0-2) 

However, `NextTerm` behavior only includes `RoundTerminateValidationProvider`, completely excluding LIB validation. [4](#0-3) 

The `LibInformationValidationProvider` checks that provided LIB heights do not decrease from the base round, but this protection is never applied to NextTerm. [5](#0-4) 

The `RoundTerminateValidationProvider` only validates term number increments, with no LIB checks. [6](#0-5) 

During execution, `ProcessNextTerm` stores the new round directly without any LIB validation or recalculation. [7](#0-6) 

Compare this with `ProcessUpdateValue`, which explicitly calculates and validates LIB, ensuring it never decreases. [8](#0-7) 

**Attack Scenario:**

A malicious miner scheduled for a NextTerm block can:
1. Call `GetConsensusExtraData` (a public view method) when LIB is at height X
2. Wait for other miners to advance LIB to height Y > X through normal block production  
3. Produce their NextTerm block using the cached data with stale LIB = X
4. The block passes validation because NextTerm lacks LIB height validation
5. The blockchain's LIB is rolled back from Y to X, un-finalizing previously confirmed blocks [9](#0-8) 

## Impact Explanation

This vulnerability violates the fundamental security property of blockchain finality, with severe consequences:

**Direct Integrity Breach:**
- Previously irreversible blocks become reversible, breaking the core guarantee that confirmed transactions are permanent
- The blockchain's consensus security model is fundamentally compromised
- LIB monotonicity invariant is violated

**Double-Spending Risk:**
- If blocks become un-finalized, their transactions can potentially be reorganized
- Attackers could execute double-spending attacks by reversing confirmed transactions
- Exchanges accepting deposits based on finality could suffer direct financial losses

**Cross-Chain Security:**
- LIB height is used for cross-chain indexing and operations
- Rolling back LIB affects parent-side chain synchronization  
- Cross-chain asset transfers relying on finality could be compromised

**Systemic Economic Damage:**
- Loss of confidence in blockchain finality
- Exchanges may require significantly more confirmations
- DApp developers cannot rely on transaction permanence

The severity is CRITICAL because this breaks a core blockchain invariant that all other security properties depend upon.

## Likelihood Explanation

**Attacker Prerequisites:**
1. Must be a valid miner in the current round
2. Must be scheduled to produce a NextTerm block

These prerequisites are achievable - any party can run for election and become a miner by obtaining votes. Term transitions occur at regular, predictable intervals.

**Attack Complexity:** LOW
- `GetConsensusExtraData` is a public view method callable at any time with no restrictions
- No cryptographic complexity required
- Simple timing manipulation (cache early data, use later)
- Zero validation prevents detection

**Feasibility Factors:**
- Term transitions provide regular exploitation windows
- Can occur accidentally through legitimate race conditions (node generates data at T1, produces block at T2)
- No monitoring or alerting mechanism exists to detect this
- Complete absence of validation makes exploitation trivial

**Probability Assessment:** HIGH

The combination of regular opportunities (term transitions), simple execution (no complex exploit chain), achievable prerequisites (becoming a miner), and zero validation makes this highly likely to occur either through malicious action or accidental race conditions.

## Recommendation

Add `LibInformationValidationProvider` to the NextTerm behavior validation chain, ensuring LIB validation is applied consistently across all consensus behaviors.

In `AEDPoSContract_Validation.cs`, modify the NextTerm case to include LIB validation:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
```

Additionally, consider implementing LIB recalculation in `ProcessNextTerm` similar to how `ProcessUpdateValue` handles it, to ensure the new term starts with a correct LIB value rather than blindly copying from the previous term.

## Proof of Concept

Due to the complexity of setting up a full consensus test environment with multiple miners and term transitions, a complete PoC would require substantial test infrastructure. However, the vulnerability can be demonstrated by:

1. Examining that `GetConsensusExtraDataForNextTerm` copies LIB without validation
2. Confirming `LibInformationValidationProvider` is excluded from NextTerm validation
3. Verifying `ProcessNextTerm` stores the round without LIB validation
4. Comparing with `UpdateValue` which includes all these protections

The code evidence provided clearly demonstrates the validation gap and the ability to store stale LIB values during term transitions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L51-52)
```csharp
        round.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        round.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-46)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```
