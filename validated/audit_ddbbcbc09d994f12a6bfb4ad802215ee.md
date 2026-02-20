# Audit Report

## Title
Mining Interval Manipulation in NextRound Allows Strategic Block Production Time Limit Control

## Summary
A miner producing a NextRound block can manipulate the mining interval by crafting custom `ExpectedMiningTime` values in the consensus data. The validation logic only checks internal consistency within the provided round but fails to validate that the mining interval matches the previous round, allowing the attacker to control block production time limits for all miners in subsequent rounds.

## Finding Description

The vulnerability stems from insufficient validation during NextRound transitions in the AEDPoS consensus mechanism.

**Root Cause Chain:**

The `DefaultBlockMiningLimit` determines how much time miners have to produce blocks. This limit is calculated based on `MiningInterval` divided by the number of tiny blocks and then multiplied by 3/5. [1](#0-0) 

The `MiningInterval` comes from the current round's `GetMiningInterval()` method. [2](#0-1) 

The `GetMiningInterval()` method calculates the interval from the difference between the first two miners' `ExpectedMiningTime` values. [3](#0-2) 

When generating a NextRound honestly, `GenerateNextRoundInformation()` uses the current round's mining interval to set `ExpectedMiningTime` for all miners. [4](#0-3) 

**Validation Gap:**

The validation for NextRound behavior includes `TimeSlotValidationProvider`, which calls `CheckRoundTimeSlots()` on the provided round. [5](#0-4) 

However, `CheckRoundTimeSlots()` only validates internal consistency - ensuring all miners have equal intervals and that intervals are greater than zero. [6](#0-5) 

There is no check comparing the mining interval against the previous round's interval or against `State.MiningInterval.Value`.

The `RoundTerminateValidationProvider` only validates round number increment and that InValues are null. [7](#0-6) 

**Exploitation Path:**

1. Attacker is selected to produce the NextRound block (regular occurrence in protocol)
2. Instead of calling `GetConsensusExtraDataForNextRound()`, craft a custom `NextRoundInput` with modified `ExpectedMiningTime` values (e.g., 8000ms intervals instead of 4000ms)
3. Ensure internal consistency (all consecutive miners have equal spacing)
4. Submit via `NextRound` transaction [8](#0-7) 
5. Validation passes because `CheckRoundTimeSlots()` only checks internal consistency
6. The manipulated round is stored [9](#0-8) 
7. All miners generate consensus commands using this manipulated round's `GetMiningInterval()`
8. `DefaultBlockMiningLimit` changes for all miners according to the manipulated interval [10](#0-9) 

## Impact Explanation

This vulnerability breaks the consensus security guarantee that mining intervals should remain constant within a term. The impact is significant:

**Quantified Impact on Block Production:**
- Normal 4000ms interval → 300ms mining limit
- Doubled to 8000ms → 600ms limit (100% increase)
- Halved to 2000ms → 150ms limit (50% decrease)

**Strategic Advantages:**
1. **Timing Control**: Attacker chooses when manipulation activates
2. **Preparation Advantage**: Knows new limits before other miners
3. **Information Asymmetry**: Other miners discover change only when generating commands
4. **Persistence**: Manipulation propagates through subsequent rounds until NextTerm resets to `State.MiningInterval` [11](#0-10)  and [12](#0-11) 

**Consensus Impact:**
- Can make block production systematically harder or easier for all miners
- Affects consensus timing and block finalization rates
- Can be used to manipulate network conditions strategically
- Undermines fairness assumptions in the consensus protocol

## Likelihood Explanation

**Attacker Capabilities:**
- Must be in the miner set (required for consensus participation) [13](#0-12) 
- Must be selected to produce a NextRound block (happens regularly for each miner)
- Must modify node software to craft custom consensus data
- Must maintain internal consistency in the crafted round (technically feasible)

**Feasibility Assessment:**
- **Entry Point**: NextRound block production is a regular protocol occurrence
- **Preconditions**: Being in miner set and selected for NextRound (realistic)
- **Technical Barrier**: Requires node modification (non-trivial but achievable for sophisticated attacker)
- **Detection**: Changes are on-chain but require active monitoring to detect
- **Constraints**: Extreme changes obvious; subtle manipulation more effective

**Overall Probability**: Medium to High
- Opportunity occurs every round for each miner
- Requires technical sophistication (node modification)
- Detection requires active monitoring
- Economic incentive exists for strategic timing manipulation

## Recommendation

Add validation in `CheckRoundTimeSlots()` or in a new validation provider to compare the mining interval of the provided round against:
1. The previous round's mining interval (ensuring continuity)
2. The canonical `State.MiningInterval.Value` (ensuring consistency with protocol parameters)

Example fix:
```csharp
// In TimeSlotValidationProvider or new MiningIntervalValidationProvider
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var providedInterval = validationContext.ProvidedRound.GetMiningInterval();
    var baseInterval = validationContext.BaseRound.GetMiningInterval();
    
    if (providedInterval != baseInterval)
    {
        return new ValidationResult 
        { 
            Message = $"Mining interval mismatch: provided {providedInterval}ms, expected {baseInterval}ms" 
        };
    }
    
    return new ValidationResult { Success = true };
}
```

Add this provider to the validation pipeline for NextRound behavior in `AEDPoSContract_Validation.cs`.

## Proof of Concept

```csharp
[Fact]
public async Task MiningIntervalManipulation_NextRound_Test()
{
    // Setup: Initialize consensus with normal parameters
    var miner = SampleAccount.Accounts.First();
    await InitialAElfConsensusContract();
    await BlockMiningService.MineBlockAsync();
    
    // Get current round
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var normalInterval = currentRound.GetMiningInterval(); // Should be 4000ms
    
    // Craft malicious NextRound with doubled mining interval (8000ms instead of 4000ms)
    var manipulatedRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber
    };
    
    // Set ExpectedMiningTime with 8000ms intervals
    var startTime = TimestampHelper.GetUtcNow();
    int order = 1;
    foreach (var minerKey in currentRound.RealTimeMinersInformation.Keys)
    {
        manipulatedRound.RealTimeMinersInformation[minerKey] = new MinerInRound
        {
            Pubkey = minerKey,
            Order = order,
            ExpectedMiningTime = startTime.AddMilliseconds(8000 * order) // 8000ms instead of 4000ms
        };
        order++;
    }
    
    // Submit manipulated NextRound
    var nextRoundInput = NextRoundInput.Create(manipulatedRound, ByteString.Empty);
    await AEDPoSContractStub.NextRound.SendAsync(nextRoundInput);
    
    // Verify manipulation succeeded
    var newRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var manipulatedInterval = newRound.GetMiningInterval();
    
    // Assert: Mining interval was successfully manipulated
    Assert.Equal(8000, manipulatedInterval); // Doubled from 4000ms
    Assert.NotEqual(normalInterval, manipulatedInterval);
    
    // Impact: DefaultBlockMiningLimit changes
    // Normal: (4000/8)*3/5 = 300ms
    // Manipulated: (8000/8)*3/5 = 600ms (100% increase)
    var expectedManipulatedLimit = (manipulatedInterval / 8) * 3 / 5;
    Assert.Equal(600, expectedManipulatedLimit);
}
```

## Notes

The `State.MiningInterval` is defined as `ReadonlyState<int>` and is only set once during `FirstRound`. [14](#0-13) 

This canonical value should be used as the reference for validation, but currently no validation checks against it during NextRound transitions. The manipulation persists until a NextTerm transition occurs, which resets the interval back to `State.MiningInterval.Value`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L37-37)
```csharp
        protected int MiningInterval => CurrentRound.GetMiningInterval();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L42-49)
```csharp
        private int TinyBlockSlotInterval => MiningInterval.Div(TinyBlocksCount);

        protected int MinersCount => CurrentRound.RealTimeMinersInformation.Count;

        /// <summary>
        ///     Give 3/5 of producing time for mining by default.
        /// </summary>
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L20-36)
```csharp
        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L83-83)
```csharp
        State.MiningInterval.Value = input.GetMiningInterval();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L39-39)
```csharp
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L209-209)
```csharp
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L28-28)
```csharp
    public ReadonlyState<int> MiningInterval { get; set; }
```
