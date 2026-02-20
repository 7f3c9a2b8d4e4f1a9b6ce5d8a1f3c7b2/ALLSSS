# Audit Report

## Title
Missing LIB Validation in NextRound/NextTerm Allows Manipulation of Consensus Irreversible Block Height

## Summary
The consensus validation logic applies `LibInformationValidationProvider` only to `UpdateValue` behavior, leaving `NextRound` and `NextTerm` behaviors without Last Irreversible Block (LIB) height validation. A malicious miner can inflate `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` in NextRound/NextTerm blocks, causing the consensus contract to store manipulated LIB values that suppress legitimate LIB updates and delay blockchain finality.

## Finding Description

The AEDPoS consensus contract implements behavior-specific validation through conditional addition of validation providers. The validation gap occurs because `LibInformationValidationProvider` is only added for `UpdateValue` behavior. [1](#0-0) 

For `UpdateValue`, the provider validates that LIB values don't regress: [2](#0-1) 

However, both `NextRoundInput` and `NextTermInput` include and preserve full LIB fields: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

When processing NextRound/NextTerm, the input is converted to a Round object and stored directly without LIB validation: [7](#0-6) [8](#0-7) [9](#0-8) 

The legitimate LIB calculation in `ProcessUpdateValue` only advances LIB if the calculated value exceeds the stored value: [10](#0-9) 

This check prevents LIB updates when an inflated stored value exceeds the legitimately calculated LIB, suppressing the `IrreversibleBlockFound` event.

The UpdateValue validation is ineffective because the simplified Round used for validation omits LIB fields entirely: [11](#0-10) 

Since the LIB fields default to 0, the validation short-circuits at the first condition check in `LibInformationValidationProvider`.

The system generates NextRound data with legitimate LIB values that are copied from the current round: [12](#0-11) 

A malicious miner can modify these values before block inclusion, and the block will pass validation because `LibInformationValidationProvider` is not applied to NextRound/NextTerm behaviors.

## Impact Explanation

**HIGH SEVERITY - Consensus Integrity Violation**

1. **Delayed Finality**: The Last Irreversible Block height determines when blocks become irreversible. Artificially inflating this value suppresses legitimate LIB updates for an extended period, creating a finality gap where blocks that should be irreversible remain reversible.

2. **Event Suppression**: The `IrreversibleBlockFound` event is consumed by the blockchain service to update the chain's system-wide LIB marker. Without these events, the entire network's finality tracking is affected.

3. **Mining Parameter Manipulation**: The inflated LIB directly affects `GetMaximumBlocksCount`, which evaluates blockchain mining status based on stored LIB values: [13](#0-12) 

This can cause incorrect throttling or allowance of block production based on falsified consensus state.

4. **Cross-Chain Impact**: Cross-chain operations depend on accurate LIB heights for parent/side chain indexing and merkle proof verification. An artificially inflated LIB could cause cross-chain message verification to incorrectly accept or reject proofs.

## Likelihood Explanation

**MEDIUM-HIGH - Feasible for Any Miner**

1. **Accessible Entry Point**: Any valid miner can execute this attack when they become the extra block producer, a role that rotates through miners providing regular opportunities.

2. **Low Attack Requirements**: The attacker only needs to be a valid miner with standard participation privileges. No special permissions are required beyond normal miner capabilities.

3. **No Technical Barriers**: The miner controls the consensus header data included in blocks. While the contract provides suggested data via `GetConsensusExtraData`, the miner can modify it before block creation. The missing validation allows manipulated LIB values to pass through.

4. **Difficult Detection**: Without comparing the consensus contract's LIB against the blockchain service's LIB or analyzing event logs for gaps in `IrreversibleBlockFound` events, the manipulation is difficult to detect.

5. **Economic Rationality**: Low cost (modification of header data) with high impact (delays finality for all network participants, potentially enabling double-spend windows or disrupting cross-chain operations).

## Recommendation

Add `LibInformationValidationProvider` to the validation chain for `NextRound` and `NextTerm` behaviors:

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

This ensures that LIB values in NextRound and NextTerm blocks are validated to not regress below the current stored values, preventing malicious inflation.

## Proof of Concept

A malicious miner can exploit this by:

1. Running a modified node that intercepts the consensus extra data returned by `GetConsensusExtraData`
2. When producing a NextRound or NextTerm block, inflating `ConfirmedIrreversibleBlockHeight` to a very high value (e.g., current height + 1000000)
3. Including the modified Round data in the block header
4. The block passes validation because `LibInformationValidationProvider` is not checked for NextRound/NextTerm
5. `ProcessNextRound`/`ProcessNextTerm` stores the manipulated Round to state
6. Subsequent `ProcessUpdateValue` calls calculate the legitimate LIB but cannot update it due to the check at line 272, suppressing finality progression

The attack succeeds because the validation logic trusts that NextRound/NextTerm data has non-regressing LIB values, but doesn't enforce this constraint.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L16-17)
```csharp
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L16-17)
```csharp
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-281)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L14-34)
```csharp
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = pubkey,
                    OutValue = minerInRound.OutValue,
                    Signature = minerInRound.Signature,
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    PreviousInValue = minerInRound.PreviousInValue,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
                    Order = minerInRound.Order,
                    IsExtraBlockProducer = minerInRound.IsExtraBlockProducer
                }
            }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L25-26)
```csharp
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
```
