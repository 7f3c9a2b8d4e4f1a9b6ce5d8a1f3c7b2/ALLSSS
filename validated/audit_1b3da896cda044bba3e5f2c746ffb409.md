# Audit Report

## Title
Continuous Blocks Limit Bypass via RoundNumber Manipulation in UpdateValue/TinyBlock Behaviors

## Summary
A malicious miner can bypass the continuous blocks limit by manipulating the `RoundNumber` field in consensus extra data to values ≤ 2, allowing unlimited consecutive block production and enabling consensus monopolization.

## Finding Description

The vulnerability exists due to three critical gaps in the AEDPoS consensus validation logic:

**Gap 1: Unvalidated RoundNumber Copying**

The `GetUpdateValueRound` and `GetTinyBlockRound` methods copy `RoundNumber` directly from the current round without validation: [1](#0-0) [2](#0-1) 

These simplified rounds are included in the block header: [3](#0-2) [4](#0-3) 

**Gap 2: Missing RoundNumber Validation for UpdateValue/TinyBlock**

For NextRound and NextTerm behaviors, explicit validation ensures RoundNumber correctness: [5](#0-4) 

However, for UpdateValue and TinyBlock behaviors, the validation provider list does not include any check that validates RoundNumber: [6](#0-5) 

The `UpdateValueValidationProvider` only validates OutValue, Signature, and PreviousInValue fields, not RoundNumber: [7](#0-6) 

**Gap 3: Bypassable Continuous Blocks Check**

The `ContinuousBlocksValidationProvider` uses the unvalidated `ProvidedRound.RoundNumber` to decide whether to enforce the continuous blocks limit: [8](#0-7) 

The check at line 13 skips validation if `ProvidedRound.RoundNumber <= 2`. Since `ProvidedRound` comes directly from the block header: [9](#0-8) 

An attacker can set RoundNumber to 1 or 2 to bypass the continuous blocks protection.

**Why After-Execution Validation Doesn't Catch This**

The `ValidateConsensusAfterExecution` method calls `RecoverFromUpdateValue` or `RecoverFromTinyBlock`, which replace the header's round with the current round from state: [10](#0-9) 

These recovery methods modify and return the baseRound object, effectively replacing the fake RoundNumber: [11](#0-10) 

After recovery, both sides of the GetHash comparison use the same round object with the correct RoundNumber from state, so validation passes even though the original block header contained a manipulated value.

**Attack Execution:**
1. Legitimate miner generates consensus extra data via `GetConsensusExtraData`
2. Before including it in the block header, attacker modifies `RoundNumber` to 1 or 2
3. Block passes `ValidateBeforeExecution` because `ContinuousBlocksValidationProvider` skips its check (line 13 condition)
4. Block is executed, continuous blocks counter is updated: [12](#0-11) 

5. Block passes `ValidateAfterExecution` because `RecoverFrom*` methods replace the round
6. Attacker repeats indefinitely, bypassing the limit defined by: [13](#0-12) 

## Impact Explanation

This vulnerability completely undermines the fairness guarantees of the AEDPoS consensus mechanism:

1. **Consensus Monopolization**: The attacker bypasses the `MaximumTinyBlocksCount` limit (8 blocks) and produces unlimited consecutive blocks, gaining 100% control of block production instead of their fair share (1/N where N = number of miners)

2. **Miner Starvation**: Other legitimate miners are prevented from producing blocks, as the attacker continuously holds the block production slot

3. **Censorship Power**: With complete control over block production, the attacker can censor transactions, manipulate transaction ordering for MEV extraction, or exclude specific addresses

4. **Decentralization Failure**: The fundamental property of distributed consensus—that no single party can control the chain—is violated

The continuous blocks limit exists specifically to prevent this scenario: [14](#0-13) 

By bypassing this protection, an attacker breaks the core security assumption of the consensus mechanism.

## Likelihood Explanation

**High Likelihood - Trivially Exploitable:**

**Minimal Prerequisites:**
- Attacker must be in the current miner list (achievable through standard staking/election)
- No special privileges or compromised keys required

**Attack Simplicity:**
- Requires only modifying a single integer field (`RoundNumber`) in the consensus extra data
- No complex cryptographic manipulation needed
- No state setup or timing requirements beyond normal mining

**Economic Incentive:**
- Attack cost: Negligible (just a field modification)
- Attack benefit: Complete control of consensus, MEV extraction opportunities, censorship capability
- Risk/reward strongly favors the attacker

**Detection Difficulty:**
- The manipulation is in the block header, not in state
- State round information remains correct, making detection non-trivial
- The attack appears as normal UpdateValue/TinyBlock behavior

## Recommendation

Add a `RoundNumberValidationProvider` for UpdateValue and TinyBlock behaviors to ensure the provided RoundNumber matches the current round:

```csharp
public class RoundNumberValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ProvidedRound.RoundNumber != validationContext.BaseRound.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number." };
        
        return new ValidationResult { Success = true };
    }
}
```

Then add this provider to the validation chain in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.UpdateValue:
    validationProviders.Add(new RoundNumberValidationProvider());
    validationProviders.Add(new UpdateValueValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider());
    break;
case AElfConsensusBehaviour.TinyBlock:
    validationProviders.Add(new RoundNumberValidationProvider());
    break;
```

## Proof of Concept

```csharp
[Fact]
public async Task ContinuousBlocksLimitBypass_ViaRoundNumberManipulation()
{
    // Setup: Initialize consensus with multiple miners
    var miners = await InitializeConsensusAsync();
    var attackerKeyPair = miners[0];
    
    // Attacker produces blocks with manipulated RoundNumber
    for (int i = 0; i < 20; i++) // Far exceeding MaximumTinyBlocksCount (8)
    {
        // Get legitimate consensus extra data
        var triggerInfo = new AElfConsensusTriggerInformation
        {
            Pubkey = ByteString.CopyFrom(attackerKeyPair.PublicKey),
            Behaviour = AElfConsensusBehaviour.UpdateValue
        };
        
        var extraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
            triggerInfo.ToBytesValue());
        var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(extraData.Value);
        
        // ATTACK: Manipulate RoundNumber to bypass continuous blocks check
        headerInfo.Round.RoundNumber = 1; // Set to <= 2 to bypass validation
        
        // Block should pass validation despite exceeding limit
        var validationResult = await ConsensusStub.ValidateConsensusBeforeExecution.CallAsync(
            headerInfo.ToBytesValue());
        
        validationResult.Success.ShouldBeTrue(); // Validation bypassed!
        
        // Execute the block
        await ProduceBlockAsync(attackerKeyPair, headerInfo);
    }
    
    // Verify attacker produced 20 consecutive blocks (should have been limited to 8)
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerInfo = currentRound.RealTimeMinersInformation[attackerKeyPair.PublicKey.ToHex()];
    attackerInfo.ProducedBlocks.ShouldBe(20); // Attack succeeded!
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L11-16)
```csharp
    public Round GetUpdateValueRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-64)
```csharp
    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L28-31)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L165-170)
```csharp
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = currentRound.GetTinyBlockRound(pubkey),
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-30)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

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

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-97)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L333-365)
```csharp
    /// <summary>
    ///     To prevent one miner produced too many continuous blocks.
    /// </summary>
    /// <param name="minersCountInTheory"></param>
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
