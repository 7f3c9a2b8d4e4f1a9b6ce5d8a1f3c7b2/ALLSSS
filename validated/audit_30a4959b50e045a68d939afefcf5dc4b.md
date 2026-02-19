# Audit Report

## Title
Bypass of Continuous Blocks Validation via Arbitrary Round Number in Block Headers

## Summary
The validation system fails to verify that `ProvidedRound.RoundNumber` matches `BaseRound.RoundNumber` for `UpdateValue` and `TinyBlock` consensus behaviors. While this does not enable round skipping at the state level, it allows malicious miners to bypass the continuous blocks limit check by setting an arbitrary round number in block headers, defeating the fork prevention mechanism.

## Finding Description

The AEDPoS consensus validation pipeline applies different validators based on the consensus behavior type. The `RoundTerminateValidationProvider`, which validates round number consistency, is only registered for `NextRound` and `NextTerm` behaviors: [1](#0-0) 

For `UpdateValue` and `TinyBlock` behaviors, no validator checks whether `ProvidedRound.RoundNumber` matches the actual round number from state (`BaseRound.RoundNumber`).

The `ContinuousBlocksValidationProvider` uses `ProvidedRound.RoundNumber` to determine whether to enforce the continuous blocks limit: [2](#0-1) 

The validation only runs when `ProvidedRound.RoundNumber > 2`. If a miner sets `ProvidedRound.RoundNumber = 1` in their block header while the actual state round is much higher, the continuous blocks check is skipped entirely.

**Attack Scenario:**

1. Miner produces excessive consecutive blocks beyond the allowed limit
2. `GetConsensusCommand` detects `LatestPubkeyToTinyBlocksCount.BlocksCount < 0` and forces `NextRound` behavior to prevent forks: [3](#0-2) 

3. Malicious miner ignores the command and crafts an `UpdateValue` block with `ProvidedRound.RoundNumber = 1`
4. Block validation runs `ContinuousBlocksValidationProvider`, which evaluates `ProvidedRound.RoundNumber > 2` as false
5. Continuous blocks limit check is bypassed, block is accepted
6. Miner continues producing unlimited consecutive blocks

**Why Round Skipping Does Not Occur:**

While `ProvidedRound.RoundNumber` can be arbitrary, the actual state's round number is only modified through `TryToUpdateRoundNumber`, which enforces strict sequential progression: [4](#0-3) 

The `ProcessUpdateValue` and `ProcessTinyBlock` methods retrieve the current round from state and never call `TryToUpdateRoundNumber`: [5](#0-4) [6](#0-5) 

Therefore, state-level round skipping is impossible through this vector.

## Impact Explanation

The continuous blocks mechanism is explicitly designed "to avoid too many forks": [7](#0-6) 

Its purpose is "to prevent one miner produces too many continues blocks (which may cause problems to other parts)": [8](#0-7) 

Bypassing this protection allows a malicious miner to:
1. **Violate consensus invariants** - produce unlimited consecutive blocks beyond the 8-block limit
2. **Increase fork risk** - the system dynamically adjusts `MaximumBlocksCount` during abnormal mining conditions to prevent forks, but this defense is defeated
3. **Enable potential DoS** - excessive consecutive blocks from a single miner can destabilize the chain and cause synchronization issues for other nodes
4. **Centralize block production** - allows one miner to dominate block creation, undermining the decentralized consensus model

## Likelihood Explanation

**High Likelihood:**
- Any miner can craft malicious block headers with arbitrary `ProvidedRound.RoundNumber` values
- No cryptographic or authorization barriers prevent exploitation
- The attack requires only deviating from the consensus command returned by `GetConsensusCommand`
- The vulnerability is always exploitable when a miner exceeds their continuous blocks quota

The only limiting factor is that the attacker must be a consensus miner, but no additional privileges or chain state conditions are required beyond normal mining participation.

## Recommendation

Add round number validation for `UpdateValue` and `TinyBlock` behaviors in the validation pipeline:

```csharp
// In AEDPoSContract_Validation.cs, after line 75
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        // ADD THIS:
        validationProviders.Add(new RoundNumberConsistencyValidationProvider());
        break;
    case AElfConsensusBehaviour.TinyBlock:
        // ADD THIS:
        validationProviders.Add(new RoundNumberConsistencyValidationProvider());
        break;
    // ... existing NextRound and NextTerm cases
}
```

Create a new validator:

```csharp
public class RoundNumberConsistencyValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.BaseRound.RoundNumber != validationContext.ProvidedRound.RoundNumber)
            return new ValidationResult 
            { 
                Message = $"Provided round number {validationContext.ProvidedRound.RoundNumber} " +
                         $"does not match current round {validationContext.BaseRound.RoundNumber}." 
            };
        
        return new ValidationResult { Success = true };
    }
}
```

## Proof of Concept

A malicious miner can bypass continuous blocks validation by:
1. Producing 8+ consecutive blocks to exceed the limit
2. Crafting the next block with `UpdateValue` behavior and `ProvidedRound.RoundNumber = 1`
3. Submitting the block, which passes validation despite violating the consecutive blocks invariant
4. Continuing to produce unlimited additional consecutive blocks using the same technique

This breaks the fork prevention guarantee that the continuous blocks mechanism is designed to enforce, allowing a single miner to dominate block production and potentially destabilize the blockchain through excessive forking.

## Notes

The claim correctly identifies that this vulnerability does NOT allow round skipping at the state level due to strict enforcement in `TryToUpdateRoundNumber`. However, the bypass of continuous blocks validation represents a genuine consensus integrity issue that violates the fork prevention mechanism—a critical security property of the AEDPoS consensus algorithm. The impact extends beyond a "minor side effect" as it fundamentally undermines the distributed nature of block production and the system's anti-fork protections.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-24)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L29-35)
```csharp
        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L91-97)
```csharp
    private bool TryToUpdateRoundNumber(long roundNumber)
    {
        var oldRoundNumber = State.CurrentRoundNumber.Value;
        if (roundNumber != 1 && oldRoundNumber + 1 != roundNumber) return false;
        State.CurrentRoundNumber.Value = roundNumber;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

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

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L18-19)
```csharp
    ///     Implemented GitHub PR #1952.
    ///     Adjust (mainly reduce) the count of tiny blocks produced by a miner each time to avoid too many forks.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L34-37)
```csharp
    /// <summary>
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
```
