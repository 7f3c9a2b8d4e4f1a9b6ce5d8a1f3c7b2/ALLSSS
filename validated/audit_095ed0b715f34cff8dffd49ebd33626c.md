# Audit Report

## Title
Missing ActualMiningTimes Validation in Next Round Allows Consensus Manipulation

## Summary
The `ValidationForNextRound()` method fails to validate the `ActualMiningTimes` field when transitioning to a new consensus round, allowing malicious miners to pre-fill arbitrary timestamps that manipulate term change logic and deny tiny block production permissions to targeted miners.

## Finding Description

The AEDPoS consensus contract validates next round information through the `ValidationForNextRound()` method, which explicitly checks only two aspects: round number increment and InValue nullability. [1](#0-0) 

When legitimate next round information is generated, the `GenerateNextRoundInformation()` method creates fresh `MinerInRound` objects that only initialize specific fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots) without setting `ActualMiningTimes`. [2](#0-1) 

Only the extra block producer legitimately adds their timestamp to `ActualMiningTimes` when producing the round transition block. [3](#0-2) 

However, the `NextRound()` transaction processes input by converting it via `ToRound()`, which copies ALL fields from the protobuf structure including any pre-filled `ActualMiningTimes`. [4](#0-3)  The manipulated round is then directly stored without additional validation. [5](#0-4) 

**Attack Scenario**: A malicious miner producing the extra block generates legitimate next round information, then modifies the `NextRoundInput.RealTimeMinersInformation` map before submission to add fake timestamps to `ActualMiningTimes` for arbitrary miners. The validation passes because it only checks `InValue`, and the manipulated data is stored in contract state.

## Impact Explanation

Pre-filled `ActualMiningTimes` directly corrupts critical consensus mechanisms:

**1. Term Change Manipulation**: The `NeedToChangeTerm()` method uses the last `ActualMiningTime` of each miner to determine if term transitions should occur. [6](#0-5)  By injecting future timestamps, an attacker can force premature term changes, disrupting the election cycle and miner rotation. Conversely, past timestamps can prevent legitimate term changes, keeping a specific miner set in power longer than intended.

**2. Tiny Block Production Denial**: The consensus behavior logic determines if miners can produce tiny blocks by checking if `ActualMiningTimes.Count < maximumBlocksCount`. [7](#0-6)  By inflating the count to equal or exceed the limit, an attacker prevents targeted miners from producing tiny blocks, reducing network throughput and potentially causing consensus delays.

**3. First Round Timing Manipulation**: Time slot validation for the first round uses `ActualMiningTimes.First()` to establish timing baselines. [8](#0-7)  Manipulated initial timestamps can disrupt the entire round's timing calculations.

The vulnerability affects consensus integrity by allowing unauthorized manipulation of term lifecycles, block production schedules, and timing mechanisms.

## Likelihood Explanation

**High Likelihood** - This attack is practical and easily executable:

**Attacker Capabilities**: Any miner producing the extra block (the last block of a round) can execute this attack. The extra block producer role rotates through the miner set, giving each miner periodic opportunities.

**Attack Complexity**: Low - The attacker only needs to:
1. Generate legitimate next round information via the normal consensus flow
2. Modify the `NextRoundInput` structure locally before block production
3. Submit the modified `NextRound` transaction

**Feasibility Factors**:
- The `NextRound()` method is a standard public consensus entry point [9](#0-8) 
- No authorization beyond being the current extra block producer is required
- The validation explicitly omits `ActualMiningTimes` checks (as documented in the code comments)
- The protobuf definition allows the `actual_mining_times` repeated field to be arbitrarily populated [10](#0-9) 

**Detection**: The attack may initially go undetected since the manipulated `ActualMiningTimes` is stored in contract state and treated as legitimate by all subsequent consensus logic.

## Recommendation

Add validation in `ValidationForNextRound()` to ensure `ActualMiningTimes` contains at most one entry (for the extra block producer) and that all other miners have empty `ActualMiningTimes`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing validations
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // Validate InValue is null
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Validate ActualMiningTimes
    var extraBlockProducer = extraData.Round.ExtraBlockProducerOfPreviousRound;
    foreach (var miner in extraData.Round.RealTimeMinersInformation)
    {
        if (miner.Key == extraBlockProducer)
        {
            // Extra block producer should have exactly 1 ActualMiningTime
            if (miner.Value.ActualMiningTimes.Count != 1)
                return new ValidationResult { Message = "Extra block producer must have exactly one ActualMiningTime." };
        }
        else
        {
            // All other miners should have empty ActualMiningTimes
            if (miner.Value.ActualMiningTimes.Count != 0)
                return new ValidationResult { Message = "Only extra block producer can have ActualMiningTimes in next round." };
        }
    }
    
    return new ValidationResult { Success = true };
}
```

Additionally, consider adding similar validation in `ProcessNextRound()` as a defense-in-depth measure.

## Proof of Concept

```csharp
[Fact]
public async Task ActualMiningTimesManipulation_TermChangeExploit()
{
    // Setup: Initialize consensus with miners
    var miners = GenerateMiners(3);
    await InitializeConsensus(miners);
    
    // Progress to a point where term change is near
    await ProduceNormalBlocks(miners, roundsBeforeTermChange: 5);
    
    // Attacker (extra block producer) produces malicious NextRound
    var attacker = miners[0];
    var currentRound = await GetCurrentRound();
    var nextRound = GenerateNextRoundInformation(currentRound);
    
    // ATTACK: Pre-fill ActualMiningTimes with future timestamps for all miners
    var futureTime = Timestamp.FromDateTime(DateTime.UtcNow.AddDays(30));
    foreach (var miner in nextRound.RealTimeMinersInformation.Values)
    {
        // Add fake timestamps to force term change
        miner.ActualMiningTimes.Add(futureTime);
    }
    
    // Submit manipulated NextRound transaction
    var result = await attacker.NextRound(nextRound.ToNextRoundInput());
    
    // VERIFY: Transaction succeeds despite manipulated ActualMiningTimes
    result.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // VERIFY: Term change is triggered prematurely due to fake timestamps
    var termNumber = await GetCurrentTermNumber();
    var expectedTermNumber = await GetExpectedTermNumber(realTimestamp: DateTime.UtcNow);
    
    // Assert that term changed prematurely (using fake future timestamps)
    termNumber.ShouldBeGreaterThan(expectedTermNumber);
}
```

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L195-196)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L92-93)
```csharp
        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** protobuf/aedpos_contract.proto (L291-292)
```text
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
```
