# Audit Report

## Title
Continuous Blocks Limit Bypass via RoundNumber Manipulation in UpdateValue/TinyBlock Behaviors

## Summary
A malicious miner can bypass the continuous blocks limit by manipulating the `RoundNumber` field in consensus extra data to values ≤ 2, enabling unlimited consecutive block production and complete consensus monopolization.

## Finding Description

The vulnerability exploits a validation gap in the AEDPoS consensus mechanism through three interconnected weaknesses:

**Gap 1: Unvalidated RoundNumber Copying**

The `GetUpdateValueRound` and `GetTinyBlockRound` methods copy `RoundNumber` directly from the current round without cryptographic commitment or validation: [1](#0-0) [2](#0-1) 

These simplified rounds are included in block headers during consensus extra data generation: [3](#0-2) 

**Gap 2: Missing RoundNumber Validation for UpdateValue/TinyBlock**

For NextRound and NextTerm behaviors, `RoundTerminateValidationProvider` explicitly validates that RoundNumber matches expectations: [4](#0-3) 

However, the validation provider list for UpdateValue and TinyBlock behaviors does NOT include any RoundNumber validation: [5](#0-4) 

The `UpdateValueValidationProvider` only validates VRF fields and `PreviousInValue`: [6](#0-5) 

**Gap 3: Bypassable Continuous Blocks Check**

The `ContinuousBlocksValidationProvider` uses the unvalidated `ProvidedRound.RoundNumber` from block header extra data to determine whether to enforce continuous blocks limits: [7](#0-6) 

The `ProvidedRound` property directly references the Round from consensus header extra data: [8](#0-7) 

The only validation at the kernel layer is that `SenderPubkey` matches `SignerPubkey`: [9](#0-8) 

**Why After-Execution Validation Fails to Catch This**

During `ValidateConsensusAfterExecution`, the recovery methods replace the header's round with the current round from state: [10](#0-9) 

The recovery methods modify `currentRound` and return it, effectively replacing the fake RoundNumber: [11](#0-10) 

The `GetHash` method includes RoundNumber in its checkable round calculation: [12](#0-11) 

After recovery, both sides of the hash comparison use the same RoundNumber (the correct one from state), so validation passes despite the original manipulation.

**Attack Execution Path:**

1. Attacker (legitimate miner) calls `GetConsensusExtraData` for UpdateValue/TinyBlock behavior
2. Before including data in block header, attacker modifies `RoundNumber` to 1 or 2
3. Block passes `ValidateBeforeExecution` because `ContinuousBlocksValidationProvider` skips its check (line 13 condition evaluates to false)
4. Block executes and continuous blocks counter is updated: [13](#0-12) 

5. Block passes `ValidateAfterExecution` because recovery replaces the manipulated round
6. Attacker repeats indefinitely, bypassing the maximum blocks limit: [14](#0-13) 

## Impact Explanation

**Critical Consensus Integrity Compromise**

This vulnerability completely undermines the fairness guarantees of the AEDPoS consensus mechanism:

1. **Consensus Monopolization**: The attacker bypasses the `MaximumTinyBlocksCount` limit (8 blocks) and produces unlimited consecutive blocks, gaining 100% control of block production instead of their fair share (1/N where N = number of miners)

2. **Miner Starvation**: Other legitimate miners are prevented from producing blocks as the attacker continuously monopolizes block production

3. **Censorship Power**: Complete control enables transaction censorship, MEV extraction through transaction ordering manipulation, and targeted address exclusion

4. **Decentralization Failure**: The fundamental distributed consensus property—that no single party controls the chain—is violated

The continuous blocks limit exists specifically to prevent single-miner monopolization. By bypassing this protection, the attacker breaks the core security assumption of the consensus mechanism.

## Likelihood Explanation

**High Likelihood - Trivially Exploitable**

**Minimal Prerequisites:**
- Attacker must be in the current miner list (standard requirement achieved through staking/election)
- No special privileges or compromised keys required

**Attack Simplicity:**
- Requires only modifying a single integer field (`RoundNumber`) in consensus extra data
- No complex cryptographic manipulation needed
- No special state setup or timing requirements beyond normal mining

**Economic Incentive:**
- Attack cost: Negligible (single field modification)
- Attack benefit: Complete consensus control, MEV extraction opportunities, censorship capability
- Risk/reward ratio strongly favors exploitation

**Detection Difficulty:**
- Manipulation occurs in block header, not state
- State round information remains correct, making detection non-trivial
- Attack appears as normal UpdateValue/TinyBlock behavior to observers

## Recommendation

Add a validation provider that explicitly checks the provided `RoundNumber` matches the current round for UpdateValue and TinyBlock behaviors:

```csharp
public class RoundNumberValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // For UpdateValue and TinyBlock, verify RoundNumber matches current round
        if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.UpdateValue ||
            validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
        {
            if (validationContext.ProvidedRound.RoundNumber != validationContext.CurrentRoundNumber)
            {
                return new ValidationResult 
                { 
                    Message = $"Incorrect round number: expected {validationContext.CurrentRoundNumber}, got {validationContext.ProvidedRound.RoundNumber}" 
                };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Add this provider to the validation chain in `ValidateBeforeExecution` for all behaviors, or specifically for UpdateValue and TinyBlock behaviors in the switch statement.

## Proof of Concept

A proof of concept would require:

1. Setting up an AElf testnet with multiple miners
2. Modifying one miner's node to manipulate RoundNumber in consensus extra data before block submission
3. Observing that the modified block passes validation
4. Demonstrating that the miner can produce blocks beyond the MaximumTinyBlocksCount limit
5. Showing that state LatestPubkeyToTinyBlocksCount becomes negative but validation still passes

The vulnerability is confirmed through code analysis showing the complete absence of RoundNumber validation for UpdateValue/TinyBlock behaviors, combined with the ContinuousBlocksValidationProvider's reliance on this unvalidated field.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L28-38)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L23-27)
```csharp

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
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
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
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
