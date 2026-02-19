# Audit Report

## Title
Missing Validation of ExtraBlockProducerOfPreviousRound Enables Fake Extra Block Attribution

## Summary
The AEDPoS consensus contract fails to validate the `ExtraBlockProducerOfPreviousRound` field during NextRound transitions, allowing any miner producing a NextRound block to arbitrarily assign extra block privileges to themselves or others, resulting in unfair mining reward distribution.

## Finding Description

The vulnerability exists in the NextRound consensus transition logic where the `ExtraBlockProducerOfPreviousRound` field can be manipulated without detection.

**Root Cause Analysis:**

When transitioning to the next round, `NextRoundInput.Create()` blindly copies the `ExtraBlockProducerOfPreviousRound` field from the Round object: [1](#0-0) 

The field is initially set by `GetConsensusExtraDataForNextRound` to the sender's pubkey: [2](#0-1) 

However, a critical validation gap exists. The `GetCheckableRound()` method used for hash verification during `ValidateConsensusAfterExecution` **excludes** `ExtraBlockProducerOfPreviousRound` from the checkable round: [3](#0-2) 

Notice that the checkable round only includes `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge` - the `ExtraBlockProducerOfPreviousRound` field is completely absent.

This means the hash comparison in `ValidateConsensusAfterExecution` cannot detect modifications to this field: [4](#0-3) 

Additionally, the NextRound validation providers only check round number increments and null InValues, completely ignoring the `ExtraBlockProducerOfPreviousRound` field: [5](#0-4) [6](#0-5) 

**Exploitation Path:**

1. Attacker is a legitimate miner scheduled to produce a NextRound block
2. Instead of using the legitimate `NextRoundInput`, they craft a modified transaction with `ExtraBlockProducerOfPreviousRound` set to an arbitrary value (their own pubkey, a colluder's pubkey, or a non-existent address)
3. The block passes `ValidateConsensusBeforeExecution` (validators don't check this field)
4. The block executes via `ProcessNextRound`, which calls `input.ToRound()`: [7](#0-6) 

5. The fake value is stored in state
6. Hash validation passes because the field is excluded from `GetCheckableRound()`

## Impact Explanation

**Direct Mining Privilege Abuse:**

The `ExtraBlockProducerOfPreviousRound` grants significant special privileges in the consensus mechanism:

1. **Pre-round tiny block production**: The extra block producer can mine tiny blocks BEFORE the round officially starts: [8](#0-7) 

2. **Double mining capacity**: During their normal time slot, they can produce up to double the normal `maximumBlocksCount`: [9](#0-8) 

**Unfair Reward Allocation:**

Mining rewards are calculated based on total blocks produced. The `DonateMiningReward` method calculates rewards as: [10](#0-9) 

Where `GetMinedBlocks()` sums all miners' `ProducedBlocks` counters: [11](#0-10) 

By gaining extra block production privileges, an attacker can mine significantly more blocks than intended, directly increasing their share of mining rewards. With typical rewards in the hundreds of thousands of tokens per term, even a 10-15% increase in block production represents substantial economic theft.

## Likelihood Explanation

**Attack Requirements (All Readily Met):**
- Attacker must be a legitimate miner in the current round (any elected miner can be an attacker)
- Attacker must produce a NextRound block (happens naturally in rotation for every miner)
- Attacker can construct arbitrary transaction inputs (standard capability)

**Attack Complexity: Very Low**
- Single field modification in `NextRoundInput`
- No cryptographic bypasses required
- No coordination with other parties needed
- Can be executed in a single transaction

**Detection Difficulty: High**
- No on-chain validation catches this manipulation
- The field value appears as a valid pubkey format
- Only detectable through off-chain forensic analysis comparing expected vs. actual extra block producers across rounds

**Economic Rationality: Extremely High**
- Zero additional cost beyond normal block production
- Direct, immediate reward increase
- Low risk of detection due to validation gaps
- Can be repeated every time the attacker produces a NextRound block
- No downside or penalty for attempting

## Recommendation

Add explicit validation in the NextRound processing flow to verify `ExtraBlockProducerOfPreviousRound`:

```csharp
// In ProcessNextRound or a new validation provider
private void ValidateExtraBlockProducer(NextRoundInput input)
{
    if (string.IsNullOrEmpty(input.ExtraBlockProducerOfPreviousRound))
        return; // Empty is acceptable
        
    // Verify the extra block producer exists in previous round
    if (TryToGetPreviousRoundInformation(out var previousRound))
    {
        Assert(
            previousRound.RealTimeMinersInformation.ContainsKey(input.ExtraBlockProducerOfPreviousRound),
            "Extra block producer must exist in previous round's miner list."
        );
    }
    
    // Verify it matches the sender of the NextRound transaction
    var sender = Context.RecoverPublicKey().ToHex();
    Assert(
        input.ExtraBlockProducerOfPreviousRound == sender,
        "Extra block producer must be the NextRound transaction sender."
    );
}
```

Alternatively, include `ExtraBlockProducerOfPreviousRound` in the `GetCheckableRound()` method so it's covered by hash validation:

```csharp
var checkableRound = new Round
{
    RoundNumber = RoundNumber,
    TermNumber = TermNumber,
    RealTimeMinersInformation = { minersInformation },
    BlockchainAge = BlockchainAge,
    ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound // Add this field
};
```

## Proof of Concept

```csharp
[Fact]
public async Task ExtraBlockProducerManipulation_ShouldBeDetected()
{
    // Setup: Get to a state where NextRound can be produced
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Attacker is legitimate miner scheduled to produce NextRound
    var attackerKeyPair = InitialCoreDataCenterKeyPairs[0];
    var attackerStub = GetAEDPoSContractStub(attackerKeyPair);
    
    // Create malicious NextRoundInput with fake ExtraBlockProducerOfPreviousRound
    var victimPubkey = InitialCoreDataCenterKeyPairs[1].PublicKey.ToHex();
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        RealTimeMinersInformation = { currentRound.RealTimeMinersInformation },
        ExtraBlockProducerOfPreviousRound = victimPubkey, // Set to victim instead of attacker
        // ... other fields
    };
    
    // Execute NextRound with malicious input
    var result = await attackerStub.NextRound.SendAsync(maliciousInput);
    
    // Bug: Transaction succeeds without validation
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify the fake value was stored
    var newRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    newRound.ExtraBlockProducerOfPreviousRound.ShouldBe(victimPubkey); // Attacker successfully manipulated the field
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L7-23)
```csharp
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-178)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L124-127)
```csharp
    public long GetMinedBlocks()
    {
        return RealTimeMinersInformation.Values.Sum(minerInRound => minerInRound.ProducedBlocks);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L99-102)
```csharp
            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
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

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-112)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L70-79)
```csharp

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L118-120)
```csharp
        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
```
