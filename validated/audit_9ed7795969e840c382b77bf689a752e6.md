# Audit Report

## Title
Continuous Blocks Limit Bypass via RoundNumber Manipulation in UpdateValue/TinyBlock Behaviors

## Summary
A malicious miner can bypass the continuous blocks limit by manipulating the `RoundNumber` field in consensus extra data to values ≤ 2. The vulnerability exists because `GetUpdateValueRound` and `GetTinyBlockRound` copy `RoundNumber` without validation, and no validation provider verifies that the provided `RoundNumber` matches the current round for UpdateValue/TinyBlock behaviors. This allows unlimited consecutive block production, enabling consensus monopolization.

## Finding Description

The vulnerability chain consists of three critical gaps:

**Gap 1: Unvalidated RoundNumber Copying**

The `GetUpdateValueRound` and `GetTinyBlockRound` methods copy `RoundNumber` directly from the current round without any validation or cryptographic commitment: [1](#0-0) [2](#0-1) 

When generating consensus extra data, these simplified rounds are included in the block header: [3](#0-2) [4](#0-3) 

**Gap 2: Missing Validation for UpdateValue/TinyBlock**

For NextRound and NextTerm behaviors, explicit validation ensures the RoundNumber is correct: [5](#0-4) 

However, for UpdateValue and TinyBlock behaviors, the validation provider list does not include any check that validates the RoundNumber matches the current round: [6](#0-5) 

The `UpdateValueValidationProvider` only validates VRF fields and `PreviousInValue`, not RoundNumber: [7](#0-6) 

**Gap 3: Bypassable Continuous Blocks Check**

The `ContinuousBlocksValidationProvider` uses the unvalidated `ProvidedRound.RoundNumber` to decide whether to enforce the continuous blocks limit: [8](#0-7) 

The check at line 13 skips validation if `ProvidedRound.RoundNumber <= 2`. Since no validator ensures the provided RoundNumber matches the actual current round, an attacker can set RoundNumber to 1 or 2 to bypass this protection.

The only validation on block header consensus data is that `SenderPubkey` matches `SignerPubkey`: [9](#0-8) 

**Why After-Execution Validation Doesn't Catch This:**

The `ValidateConsensusAfterExecution` method calls `RecoverFromUpdateValue` or `RecoverFromTinyBlock`, which replace the header's round with the current round from state: [10](#0-9) 

These recovery methods modify the current round and return it, effectively replacing the fake RoundNumber: [11](#0-10) 

After recovery, both sides of the GetHash comparison use the same round object with the correct RoundNumber, so validation passes even though the original block header contained a manipulated value.

**Attack Execution:**

1. Attacker (a legitimate miner in the consensus set) calls `GetConsensusExtraData` to generate consensus header information
2. Before including it in the block header, attacker modifies `RoundNumber` to 1 or 2
3. Block passes `ValidateBeforeExecution` because `ContinuousBlocksValidationProvider` skips its check (line 13 condition)
4. Block is executed, and the continuous blocks counter is updated: [12](#0-11) 

5. Block passes `ValidateAfterExecution` because `RecoverFrom*` methods replace the round
6. Attacker repeats indefinitely, bypassing the maximum blocks limit: [13](#0-12) 

## Impact Explanation

**Critical Consensus Integrity Compromise:**

This vulnerability completely undermines the fairness guarantees of the AEDPoS consensus mechanism:

1. **Consensus Monopolization**: The attacker can bypass the `MaximumTinyBlocksCount` limit (8 blocks) and produce unlimited consecutive blocks, gaining 100% control of block production instead of their fair share (1/N where N = number of miners)

2. **Miner Starvation**: Other legitimate miners are prevented from producing blocks, as the attacker continuously holds the block production slot

3. **Censorship Power**: With complete control over block production, the attacker can censor transactions, manipulate transaction ordering for MEV extraction, or exclude specific addresses

4. **Decentralization Failure**: The fundamental property of distributed consensus—that no single party can control the chain—is violated

The continuous blocks limit exists specifically to prevent this scenario: [14](#0-13) 

By bypassing this protection, an attacker breaks the core security assumption of the consensus mechanism.

## Likelihood Explanation

**High Likelihood - Trivially Exploitable:**

**Minimal Prerequisites:**
- Attacker must be in the current miner list (standard requirement for any miner through staking/election)
- No special privileges or compromised keys required

**Attack Simplicity:**
1. The attack requires only modifying a single integer field (`RoundNumber`) in the consensus extra data
2. No complex cryptographic manipulation needed
3. No state setup or timing requirements beyond normal mining

**Economic Incentive:**
- Attack cost: Negligible (just a field modification)
- Attack benefit: Complete control of consensus, MEV extraction opportunities, censorship capability
- Risk/reward strongly favors the attacker

**Detection Difficulty:**
- The manipulation is in the block header, not in state
- State round information remains correct, making detection non-trivial
- The attack appears as normal UpdateValue/TinyBlock behavior

## Recommendation

Add explicit RoundNumber validation for UpdateValue and TinyBlock behaviors in `ValidateBeforeExecution`:

```csharp
// In AEDPoSContract_Validation.cs, add to the validation providers list
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        // ADD THIS:
        validationProviders.Add(new RoundNumberValidationProvider());
        break;
    case AElfConsensusBehaviour.TinyBlock:
        // ADD THIS:
        validationProviders.Add(new RoundNumberValidationProvider());
        break;
    // ... rest of switch
}
```

Create a new `RoundNumberValidationProvider`:

```csharp
public class RoundNumberValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ProvidedRound.RoundNumber != validationContext.BaseRound.RoundNumber)
        {
            return new ValidationResult 
            { 
                Message = $"Round number mismatch: provided {validationContext.ProvidedRound.RoundNumber}, " +
                         $"expected {validationContext.BaseRound.RoundNumber}" 
            };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

This ensures that UpdateValue and TinyBlock blocks cannot manipulate RoundNumber to bypass continuous blocks validation.

## Proof of Concept

```csharp
[Fact]
public async Task ContinuousBlocksLimitBypass_Via_RoundNumber_Manipulation()
{
    // Setup: Initialize consensus with multiple miners
    var initialMiners = await InitializeConsensusWithMiners(3);
    var attackerMiner = initialMiners[0];
    
    // Attacker produces blocks normally until continuous blocks limit would be reached
    for (int i = 0; i < MaximumTinyBlocksCount; i++)
    {
        await ProduceNormalBlock(attackerMiner);
    }
    
    // At this point, attacker should be forced to trigger NextRound
    // But attacker manipulates RoundNumber in consensus extra data
    
    // Generate legitimate consensus extra data
    var consensusExtraData = await GetConsensusExtraData(attackerMiner, AElfConsensusBehaviour.TinyBlock);
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData.Value);
    
    // ATTACK: Manipulate RoundNumber to bypass continuous blocks check
    var currentRound = await GetCurrentRound();
    Assert.True(currentRound.RoundNumber > 2, "Test requires round number > 2");
    
    // Set RoundNumber to 2 to bypass the check in ContinuousBlocksValidationProvider (line 13)
    headerInfo.Round.RoundNumber = 2;
    
    // Attempt to produce another block with manipulated RoundNumber
    var manipulatedExtraData = headerInfo.ToByteString();
    
    // Validation should fail but doesn't due to missing RoundNumber validation
    var validationResult = await ValidateConsensusBeforeExecution(manipulatedExtraData);
    
    // VULNERABILITY: Block passes validation despite exceeding continuous blocks limit
    Assert.True(validationResult.Success, "Malicious block incorrectly passed validation");
    
    // Attacker can continue producing unlimited blocks by repeating this attack
    // Expected: Validation should fail with "Round number mismatch" error
    // Actual: Validation passes, allowing consensus monopolization
}
```

The test demonstrates that a miner can bypass the `MaximumTinyBlocksCount` limit by manipulating `RoundNumber` in the consensus extra data to a value ≤ 2, causing `ContinuousBlocksValidationProvider` to skip its validation check.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-63)
```csharp
    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L28-31)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L155-168)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForTinyBlock(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = currentRound.GetTinyBlockRound(pubkey),
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-24)
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
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-32)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-97)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
