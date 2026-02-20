# Audit Report

## Title
Round Number Manipulation Bypass in Continuous Blocks Validation Allows Unlimited Block Production

## Summary
A critical consensus vulnerability allows any valid miner to bypass the continuous blocks limit by manipulating the `ProvidedRound.RoundNumber` field in consensus extra data to 1 or 2, while maintaining correct `RoundId` through copied timing data. This enables unlimited consecutive block production, exceeding the 8-block limit and monopolizing consensus.

## Finding Description

The vulnerability exists in a trust mismatch where the continuous blocks validation incorrectly relies on miner-supplied round numbers instead of verified state data.

The `ContinuousBlocksValidationProvider` checks whether a miner has produced too many consecutive blocks, but uses `ProvidedRound.RoundNumber` from consensus extra data rather than `BaseRound.RoundNumber` from contract state. [1](#0-0)  The check is skipped when `RoundNumber <= 2`, allowing attackers to bypass validation by setting this field to 1 or 2.

The `ProvidedRound` comes from miner-supplied extra data while `BaseRound` comes from trusted state. [2](#0-1) 

For `UpdateValue` and `TinyBlock` behaviors, the `RoundTerminateValidationProvider` (which validates round number progression) is only applied to `NextRound` and `NextTerm` behaviors. [3](#0-2)  This leaves `UpdateValue` and `TinyBlock` vulnerable to round number manipulation.

An attacker can craft a `ProvidedRound` with manipulated `RoundNumber = 1` or `2`, while copying all `ExpectedMiningTime` values from the actual current round. Since `RoundId` is calculated as the sum of all `ExpectedMiningTime.Seconds` values, [4](#0-3)  the manipulated round will have a matching `RoundId` with the actual `BaseRound`.

This matching `RoundId` causes the `TimeSlotValidationProvider` to use the time-slot validation branch rather than rejecting the mismatched round, [5](#0-4)  allowing the attack to pass time slot checks.

The after-execution validation is also neutered because for `UpdateValue` and `TinyBlock` behaviors, it calls recovery methods that replace `headerInformation.Round` with the modified `currentRound` object before comparison. [6](#0-5)  Since both variables reference the same object after recovery, the hash comparison always succeeds.

## Impact Explanation

This represents a **Critical** consensus integrity compromise. The continuous blocks mechanism is designed to prevent any single miner from monopolizing block production, limited to 8 consecutive blocks. [7](#0-6) 

By bypassing this limit, an attacker can:

1. **Monopolize Block Production**: Produce unlimited consecutive blocks within and across rounds, gaining disproportionate control over transaction ordering and inclusion
2. **Unfair Reward Distribution**: Capture all mining rewards during the monopoly period, depriving legitimate miners of their fair share
3. **Consensus Centralization**: Gain excessive control over block production, undermining the decentralization guarantees of AEDPoS
4. **Break Fairness Guarantees**: Violate the fundamental consensus invariant that enforces fair miner rotation

This directly undermines the security and decentralization properties essential to the AEDPoS consensus mechanism.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be a valid miner in the current round (realistic - any existing miner can exploit this)

**Attack Complexity:** Low
- Simply modify the `RoundNumber` field in consensus extra data to 1 or 2
- Copy the current round's complete miner information to maintain correct `RoundId` calculation
- Execute through standard `UpdateValue` or `UpdateTinyBlockInformation` consensus methods

**Detectability:** Low
- Blocks appear valid and pass all validation checks
- Only continuous monitoring of block production patterns would reveal the anomaly
- By the time detection occurs through behavioral analysis, significant consensus damage has occurred

**Reproducibility:** High
- Any miner can execute this attack at any time
- No special timing windows or state conditions required
- Works reliably at any round number beyond the first two rounds

## Recommendation

Modify `ContinuousBlocksValidationProvider` to check `BaseRound.RoundNumber` (from trusted state) instead of `ProvidedRound.RoundNumber` (from miner-supplied data):

```csharp
if (validationContext.BaseRound.RoundNumber > 2 && // Use BaseRound, not ProvidedRound
    validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
{
    // ... existing validation logic
}
```

Additionally, consider adding explicit round number consistency validation for `UpdateValue` and `TinyBlock` behaviors to ensure `ProvidedRound.RoundNumber` matches `BaseRound.RoundNumber`.

## Proof of Concept

```csharp
// Test demonstrating the bypass
[Fact]
public async Task ContinuousBlocksBypass_RoundNumberManipulation()
{
    // Setup: Miner has produced 8 consecutive blocks (limit reached)
    var miner = InitialCoreDataCenterKeyPairs[0];
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Verify miner is at the limit
    var tinyBlocksCount = await ConsensusStub.GetLatestPubkeyToTinyBlocksCount.CallAsync(new Empty());
    tinyBlocksCount.BlocksCount.ShouldBe(-1); // Negative means exceeded limit
    
    // Attack: Craft malicious round with RoundNumber=1 but same RoundId
    var maliciousRound = new Round
    {
        RoundNumber = 1, // Manipulated to bypass check
        RoundId = currentRound.RoundId, // Maintained by copying ExpectedMiningTime values
        RealTimeMinersInformation = { currentRound.RealTimeMinersInformation }
    };
    
    // Execute UpdateValue with manipulated round
    var result = await ConsensusStub.UpdateValue.SendAsync(new UpdateValueInput
    {
        RoundId = maliciousRound.RoundId,
        ProvidedRound = maliciousRound,
        // ... other required fields
    });
    
    // Vulnerability: Block is accepted despite exceeding continuous blocks limit
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Attacker can continue producing unlimited blocks
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-14)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L22-27)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-31)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
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
