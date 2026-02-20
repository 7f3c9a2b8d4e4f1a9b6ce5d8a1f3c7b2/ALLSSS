# Audit Report

## Title
Continuous Blocks Validation Bypass via Manipulated Round Number in UpdateValue

## Summary
A malicious block producer can bypass the continuous blocks validation by manipulating the `RoundNumber` field in consensus headers to a value ≤ 2, while maintaining a correct `RoundIdForValidation`. This allows producing unlimited consecutive blocks beyond the permitted limit (defined by `MaximumTinyBlocksCount` = 8), violating AEDPoS consensus fairness guarantees. [1](#0-0) 

## Finding Description

**Root Cause - Insufficient Round Validation:**

The `RecoverFromUpdateValue()` function only validates pubkey existence in both rounds without checking critical round identity fields like `RoundNumber`: [2](#0-1) 

**Validation Pipeline Vulnerability:**

During `ValidateBeforeExecution()`, the consensus extra data's Round object is recovered before validation providers execute: [3](#0-2) 

However, the validation context exposes two different Round objects - `BaseRound` (recovered) and `ProvidedRound` (original from attacker): [4](#0-3) 

The `ContinuousBlocksValidationProvider` checks `ProvidedRound.RoundNumber > 2`, not `BaseRound.RoundNumber`: [5](#0-4) 

This check is intended to skip validation only during the first two rounds (bootstrap period). By setting `ProvidedRound.RoundNumber = 1`, an attacker bypasses this critical validation.

**Bypassing Other Protections:**

The `TimeSlotValidationProvider` validates `RoundId` matches, not `RoundNumber`: [6](#0-5) 

The `RoundId` computation falls back to `RoundIdForValidation` when `ExpectedMiningTime` is not populated: [7](#0-6) 

In simplified UpdateValue rounds created by honest miners, `ExpectedMiningTime` is NOT populated: [8](#0-7) 

An attacker can independently set `RoundIdForValidation` (to match current round) and `RoundNumber` (to ≤ 2), passing the RoundId check while bypassing continuous blocks validation.

The hash validation in `ValidateConsensusAfterExecution()` doesn't catch this because it operates on the recovered round (with corrected RoundNumber): [9](#0-8) 

The external signature validation only verifies the sender's identity, not Round content: [10](#0-9) 

## Impact Explanation

**Consensus Integrity Violation:**

The system is designed to prevent miners from producing too many continuous blocks. When `LatestPubkeyToTinyBlocksCount.BlocksCount` becomes negative, the system forces NextRound behavior: [11](#0-10) 

The counter decrements with each block produced by the same miner: [12](#0-11) 

By bypassing the continuous blocks validation, a malicious miner can:
1. Ignore the forced NextRound behavior when `BlocksCount < 0`
2. Monopolize block production and associated mining rewards
3. Prevent other miners from producing blocks (denial-of-service)
4. Centralize consensus control, undermining AEDPoS's distributed security model

**Severity: High** - This directly violates core consensus invariants, allowing a single miner to manipulate the block production schedule and capture disproportionate rewards while degrading network decentralization.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be an active miner with block production rights (realistic in AEDPoS)
- Can construct custom consensus headers before block submission

**Attack Steps:**
1. Produce blocks until `LatestPubkeyToTinyBlocksCount.BlocksCount < 0`
2. Instead of following the forced NextRound behavior, craft malicious consensus header
3. Set `ProvidedRound.RoundNumber = 1` (or 2)
4. Set `ProvidedRound.RoundIdForValidation` to current round's RoundId
5. Submit block with UpdateValue behavior
6. Validation passes because `RoundNumber ≤ 2` condition bypasses the check

**Feasibility: High** - While honest miners use `GetUpdateValueRound()` which sets fields correctly: [13](#0-12) 

A malicious producer can construct their own consensus header with manipulated fields. The consensus header is part of block extra data fully controlled by the block producer.

## Recommendation

Add explicit validation that `providedRound.RoundNumber` matches the expected current round number in `RecoverFromUpdateValue()` or in a dedicated validation provider:

```csharp
public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
{
    if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
        !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
        return this;
    
    // Add validation for RoundNumber
    if (providedRound.RoundNumber != this.RoundNumber)
        return this;  // Or throw exception
        
    // ... rest of method
}
```

Alternatively, add a validation provider that checks `ProvidedRound.RoundNumber == BaseRound.RoundNumber` before continuous blocks validation runs.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a test with a miner that has exhausted their continuous block quota (`BlocksCount < 0`)
2. Constructing a malicious `AElfConsensusHeaderInformation` with `Round.RoundNumber = 1` and correct `RoundIdForValidation`
3. Calling `ValidateConsensusBeforeExecution()` with this header
4. Observing that validation passes despite the miner exceeding their block production limit
5. The `ContinuousBlocksValidationProvider.ValidateHeaderInformation()` returns `Success = true` because the condition `ProvidedRound.RoundNumber > 2` evaluates to false, skipping the BlocksCount check

The validation providers can be tested in isolation by constructing appropriate `ConsensusValidationContext` objects with manipulated ProvidedRound data while BaseRound reflects the actual state.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L22-27)
```csharp
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-14)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-14)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L14-17)
```csharp
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L20-32)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L90-92)
```csharp
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L29-32)
```csharp
        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L352-357)
```csharp
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
```
