# Audit Report

## Title
Round Number Manipulation Bypass in Continuous Blocks Validation Allows Unlimited Block Production

## Summary
A critical consensus vulnerability allows any valid miner to bypass continuous blocks validation by manipulating the `ProvidedRound.RoundNumber` field in consensus extra data. By setting `RoundNumber` to 1 or 2 while maintaining the correct `RoundId` through copied timing data, attackers can produce unlimited consecutive blocks, exceeding the 8-block limit and monopolizing consensus.

## Finding Description

The vulnerability exists in the consensus validation flow where the continuous blocks limit is enforced. The `ContinuousBlocksValidationProvider` checks whether a miner has produced too many consecutive blocks, but this check uses `ProvidedRound.RoundNumber` from miner-supplied data instead of the actual `BaseRound.RoundNumber` from contract state. [1](#0-0) 

The `ProvidedRound` is populated from consensus extra data supplied by the miner, while `BaseRound` correctly comes from contract state: [2](#0-1) 

For `UpdateValue` and `TinyBlock` consensus behaviors, the `RoundTerminateValidationProvider` (which validates round number progression) is only added for `NextRound` and `NextTerm` behaviors, leaving UpdateValue and TinyBlock vulnerable: [3](#0-2) 

The attacker can craft a `ProvidedRound` with `RoundNumber = 1` or `2` to bypass the continuous blocks check, while copying all `ExpectedMiningTime` values from the actual current round. Since `RoundId` is calculated solely from the sum of `ExpectedMiningTime.Seconds` values: [4](#0-3) 

The manipulated round will have a matching `RoundId` with the actual `BaseRound`, passing time slot validation in `TimeSlotValidationProvider`: [5](#0-4) 

The after-execution validation also fails to catch this because the recovery operations overwrite the manipulated data with the correct state data before comparison: [6](#0-5) 

## Impact Explanation

This vulnerability represents a **Critical** consensus integrity compromise. The continuous blocks mechanism is designed to prevent any single miner from monopolizing block production (limited to 8 consecutive blocks by `MaximumTinyBlocksCount`): [7](#0-6) 

By bypassing this limit, an attacker can:

1. **Monopolize Block Production**: Produce unlimited consecutive blocks within and across rounds
2. **Unfair Reward Distribution**: Capture all mining rewards during the monopoly period, depriving legitimate miners
3. **Consensus Centralization**: Gain disproportionate control over block production, approaching 51% attack capability
4. **Break Fairness Guarantees**: Violate the fundamental consensus invariant of fair miner rotation

This directly undermines the decentralization and security properties of the AEDPoS consensus mechanism.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be a valid miner in the current round (realistic - targets existing miners)

**Attack Complexity:** Low
- Simply modify the `RoundNumber` field in consensus extra data to 1 or 2
- Copy current round's miner information to maintain correct `RoundId`
- Execute through standard `UpdateValue` or `UpdateTinyBlockInformation` methods

**Detectability:** Low
- Blocks appear valid and pass all validation checks
- Only behavioral monitoring of continuous block patterns would reveal the attack
- By the time detection occurs, significant damage has occurred

**Reproducibility:** High
- Any miner can execute at any time
- No special timing or state conditions required
- Works at any round number beyond genesis

## Recommendation

Change the continuous blocks validation to use the actual round number from contract state instead of the miner-provided round number:

```csharp
// In ContinuousBlocksValidationProvider.cs, line 13:
// Change from:
if (validationContext.ProvidedRound.RoundNumber > 2 && ...

// To:
if (validationContext.BaseRound.RoundNumber > 2 && ...
```

This ensures the check uses the authoritative round number from state that cannot be manipulated by miners.

Alternatively, add `RoundTerminateValidationProvider` to the validation chain for `UpdateValue` and `TinyBlock` behaviors to enforce round number consistency across all consensus behaviors.

## Proof of Concept

A malicious miner at round 100 with valid mining permissions can execute:

1. Create `UpdateValueInput` with manipulated `ProvidedRound`:
   - Set `ProvidedRound.RoundNumber = 1`
   - Copy all `RealTimeMinersInformation` with `ExpectedMiningTime` values from actual round 100
   - This makes `ProvidedRound.RoundId` match `BaseRound.RoundId`

2. Submit the consensus transaction through `UpdateValue` method

3. Validation flow:
   - `MiningPermissionValidationProvider`: Passes (attacker is valid miner in `BaseRound`)
   - `TimeSlotValidationProvider`: Passes (RoundIds match, goes to else branch using `BaseRound`)
   - `ContinuousBlocksValidationProvider`: **Bypassed** (`ProvidedRound.RoundNumber = 1`, so condition is false)
   - `UpdateValueValidationProvider`: Passes (with valid OutValue/Signature data)

4. Block is accepted despite exceeding continuous blocks limit

5. Repeat indefinitely to produce unlimited consecutive blocks

The attack breaks the consensus fairness invariant by allowing unlimited consecutive block production beyond the 8-block limit designed to ensure fair miner rotation.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L19-27)
```csharp
    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L15-24)
```csharp
    public long RoundId
    {
        get
        {
            if (RealTimeMinersInformation.Values.All(bpInfo => bpInfo.ExpectedMiningTime != null))
                return RealTimeMinersInformation.Values.Select(bpInfo => bpInfo.ExpectedMiningTime.Seconds).Sum();

            return RoundIdForValidation;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-19)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
