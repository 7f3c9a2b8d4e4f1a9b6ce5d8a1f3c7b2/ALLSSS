# Audit Report

## Title
Round Number Manipulation Bypass in Continuous Blocks Validation Allows Unlimited Block Production

## Summary
A critical consensus vulnerability allows any valid miner to bypass continuous blocks validation by manipulating the `ProvidedRound.RoundNumber` field in consensus extra data. By setting `RoundNumber` to 1 or 2 while maintaining the correct `RoundId` through copied timing data, attackers can produce unlimited consecutive blocks, exceeding the 8-block limit and monopolizing consensus.

## Finding Description

The vulnerability exists in the consensus validation flow where the continuous blocks limit is enforced. The `ContinuousBlocksValidationProvider` checks whether a miner has produced too many consecutive blocks by verifying if `ProvidedRound.RoundNumber > 2` before checking the blocks count. [1](#0-0) 

The critical flaw is that `ProvidedRound` is populated directly from miner-supplied consensus extra data, not from trusted contract state. [2](#0-1) 

While `BaseRound` correctly comes from contract state (line 22), the continuous blocks validation incorrectly uses the attacker-controlled `ProvidedRound.RoundNumber` instead of `BaseRound.RoundNumber`.

For `UpdateValue` and `TinyBlock` consensus behaviors, the `RoundTerminateValidationProvider` (which validates round number progression) is only added for `NextRound` and `NextTerm` behaviors, leaving UpdateValue and TinyBlock vulnerable to round number manipulation. [3](#0-2) 

The attacker can craft a `ProvidedRound` with `RoundNumber = 1` or `2` to bypass the continuous blocks check, while copying all `ExpectedMiningTime` values from the actual current round. Since `RoundId` is calculated solely from the sum of `ExpectedMiningTime.Seconds` values, [4](#0-3)  the manipulated round will have a matching `RoundId` with the actual `BaseRound`, passing time slot validation. [5](#0-4) 

The after-execution validation also fails to catch this because the recovery operations overwrite the manipulated data with the correct state data before comparison. [6](#0-5)  The recovered round uses the correct `BaseRound` as the starting point, which already has the legitimate `RoundNumber` from state, making the hash comparison pass despite the initial manipulation.

## Impact Explanation

This vulnerability represents a **Critical** consensus integrity compromise. The continuous blocks mechanism is designed to prevent any single miner from monopolizing block production, limited to 8 consecutive blocks by `MaximumTinyBlocksCount`. [7](#0-6) 

By bypassing this limit, an attacker can:

1. **Monopolize Block Production**: Produce unlimited consecutive blocks within and across rounds, maintaining control indefinitely
2. **Unfair Reward Distribution**: Capture all mining rewards during the monopoly period, depriving legitimate miners of their earnings
3. **Consensus Centralization**: Gain disproportionate control over block production, approaching single-party control over the consensus mechanism
4. **Break Fairness Guarantees**: Violate the fundamental consensus invariant of fair miner rotation that AEDPoS is designed to provide

The system attempts to enforce this limit through `ResetLatestProviderToTinyBlocksCount` which decrements the counter, [8](#0-7)  but the validation check that should reject blocks when `BlocksCount < 0` is bypassed by the round number manipulation.

This directly undermines the decentralization and security properties of the AEDPoS consensus mechanism.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be a valid miner in the current round (realistic - targets existing miners, not external attackers)

**Attack Complexity:** Low
- Simply modify the `RoundNumber` field in consensus extra data to 1 or 2
- Copy current round's miner information to maintain correct `RoundId`
- Execute through standard `UpdateValue` or `UpdateTinyBlockInformation` public methods
- No cryptographic operations or complex state manipulation required

**Detectability:** Low
- Blocks appear structurally valid and pass all validation checks
- The manipulated `RoundNumber` is not logged or compared against state
- Only behavioral monitoring of continuous block production patterns would reveal the attack
- By the time manual detection occurs, significant damage has already occurred

**Reproducibility:** High
- Any miner can execute at any time
- No special timing windows or rare state conditions required
- Works at any round number beyond the initial rounds (RoundNumber > 2)
- Can be repeated indefinitely to maintain control

## Recommendation

Fix the continuous blocks validation to use the trusted `BaseRound.RoundNumber` instead of the attacker-controlled `ProvidedRound.RoundNumber`:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();

    // Use BaseRound.RoundNumber from state, not ProvidedRound.RoundNumber from miner data
    if (validationContext.BaseRound.RoundNumber > 2 && 
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

Additionally, consider adding `RoundTerminateValidationProvider` to the validation chain for `UpdateValue` and `TinyBlock` behaviors to ensure round number consistency across all consensus behaviors.

## Proof of Concept

```csharp
[Fact]
public async Task RoundNumberManipulation_BypassesContinuousBlocksLimit()
{
    // Setup: Miner has already produced 8 blocks (BlocksCount = -1)
    var miner = SampleAccount.Accounts[0].KeyPair;
    var currentRound = await GetCurrentRound();
    
    // Attacker crafts malicious consensus data
    var maliciousRound = currentRound.Clone();
    maliciousRound.RoundNumber = 1; // Bypass the > 2 check
    // RoundId remains valid because ExpectedMiningTime values are copied
    
    var consensusExtraData = new AElfConsensusHeaderInformation
    {
        Behaviour = AElfConsensusBehaviour.UpdateValue,
        Round = maliciousRound,
        SenderPubkey = ByteString.CopyFrom(miner.PublicKey)
    };
    
    // Validation should reject but passes due to vulnerability
    var validationResult = await ConsensusStub.ValidateConsensusBeforeExecution.CallAsync(
        new BytesValue { Value = consensusExtraData.ToByteString() }
    );
    
    // Vulnerability: validation passes despite exceeding block limit
    validationResult.Success.ShouldBeTrue();
    
    // Block is accepted, allowing unlimited consecutive blocks
    var updateResult = await ConsensusStub.UpdateValue.SendAsync(
        maliciousRound.ExtractInformationToUpdateConsensus(miner.PublicKey.ToHex())
    );
    
    updateResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
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
