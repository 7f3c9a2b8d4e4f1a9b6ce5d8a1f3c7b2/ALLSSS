# Audit Report

## Title
Mining Interval Manipulation in NextRound Allows Strategic Block Production Time Limit Control

## Summary
A miner producing a NextRound block can manipulate the mining interval by crafting custom `ExpectedMiningTime` values in the consensus data. The validation logic only checks internal consistency within the provided round but fails to validate that the mining interval matches the previous round, allowing the attacker to control block production time limits for all miners in subsequent rounds.

## Finding Description

The vulnerability stems from insufficient validation during NextRound transitions in the AEDPoS consensus mechanism.

**Root Cause Chain:**

The `DefaultBlockMiningLimit` determines how much time miners have to produce blocks. This limit is calculated as `(MiningInterval / 8) * 3 / 5` [1](#0-0) , where `MiningInterval` comes from the current round's `GetMiningInterval()` method [2](#0-1) .

The `GetMiningInterval()` method calculates the interval from the difference between the first two miners' `ExpectedMiningTime` values [3](#0-2) .

When generating a NextRound honestly, `GenerateNextRoundInformation()` uses the current round's mining interval to set `ExpectedMiningTime` for all miners [4](#0-3)  and [5](#0-4) .

**Validation Gap:**

The validation for NextRound behavior includes `TimeSlotValidationProvider` [6](#0-5) , which calls `CheckRoundTimeSlots()` on the provided round [7](#0-6) .

However, `CheckRoundTimeSlots()` only validates internal consistency - ensuring all miners have equal intervals and that intervals are greater than zero [8](#0-7) . There is no check comparing the mining interval against the previous round's interval.

The `RoundTerminateValidationProvider` only validates round number increment and that InValues are null [9](#0-8) .

**Exploitation Path:**

1. Attacker is selected to produce the NextRound block (regular occurrence in protocol)
2. Instead of calling `GetConsensusExtraDataForNextRound()` [10](#0-9) , craft a custom `NextRoundInput` with modified `ExpectedMiningTime` values (e.g., 8000ms intervals instead of 4000ms)
3. Ensure internal consistency (all consecutive miners have equal spacing)
4. Submit via `NextRound` transaction [11](#0-10) 
5. Validation passes because `CheckRoundTimeSlots()` only checks internal consistency
6. The manipulated round is stored [12](#0-11) 
7. All miners generate consensus commands using this manipulated round's `GetMiningInterval()`
8. `DefaultBlockMiningLimit` changes for all miners according to the manipulated interval

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
4. **Persistence**: Manipulation propagates through subsequent rounds until NextTerm resets to `State.MiningInterval` [13](#0-12) 

**Consensus Impact:**
- Can make block production systematically harder or easier for all miners
- Affects consensus timing and block finalization rates
- Can be used to manipulate network conditions strategically
- Undermines fairness assumptions in the consensus protocol

## Likelihood Explanation

**Attacker Capabilities:**
- Must be in the miner set (required for consensus participation)
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

Add validation to enforce mining interval consistency across rounds within a term:

```csharp
// In TimeSlotValidationProvider or new dedicated validator
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    
    // Existing internal consistency check
    if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
    {
        validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
        if (!validationResult.Success) return validationResult;
        
        // NEW: Validate mining interval matches previous round
        var providedInterval = validationContext.ProvidedRound.GetMiningInterval();
        var baseInterval = validationContext.BaseRound.GetMiningInterval();
        
        if (Math.Abs(providedInterval - baseInterval) > 0)
        {
            validationResult.Message = "Mining interval must match previous round within same term.";
            validationResult.Success = false;
            return validationResult;
        }
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

This ensures the mining interval remains constant across rounds within a term, only allowing changes during NextTerm transitions which properly use `State.MiningInterval`.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a test where a miner crafts a `NextRoundInput` with `ExpectedMiningTime` values spaced at 8000ms intervals instead of 4000ms
2. Ensuring all miners maintain equal spacing (internal consistency)
3. Submitting via `NextRound` method
4. Verifying validation passes
5. Confirming `GetMiningInterval()` returns 8000ms
6. Verifying `DefaultBlockMiningLimit` increases from 300ms to 600ms

The test would validate that `CheckRoundTimeSlots()` [14](#0-13)  only checks internal consistency and does not compare against the previous round's interval, allowing the manipulation to succeed.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L37-37)
```csharp
        protected int MiningInterval => CurrentRound.GetMiningInterval();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L49-49)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L20-20)
```csharp
        var miningInterval = GetMiningInterval();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L33-33)
```csharp
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L17-17)
```csharp
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-34)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L209-209)
```csharp
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-165)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```
