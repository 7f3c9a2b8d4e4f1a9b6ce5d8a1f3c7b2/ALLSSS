# Audit Report

## Title
Missing Minimum Miner Participation Check in NextRound Validation Allows Premature Round Transitions Without Byzantine Fault Tolerance Consensus

## Summary
The `ValidationForNextRound()` function lacks validation to ensure that a minimum threshold of miners (MinersCountOfConsent = 2/3 + 1) have participated in the current round before allowing transition to the next round. This creates a critical inconsistency in consensus enforcement that allows minority miners to force round transitions, and if sustained for over 3 days, leads to honest majority miners being marked as evil and replaced—effectively enabling consensus takeover.

## Finding Description

The AEDPoS consensus system enforces a Byzantine Fault Tolerance threshold of `MinersCountOfConsent = RealTimeMinersInformation.Count * 2 / 3 + 1` for critical consensus operations, but this threshold is NOT enforced during round transitions. [1](#0-0) 

The `ValidationForNextRound()` method only validates:
1. Round number increments by exactly 1
2. All `InValue` fields in the next round are null [2](#0-1) 

The validation providers added for `NextRound` behavior include `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`, but neither checks minimum participation. [3](#0-2) 

This provider only validates that miners with `FinalOrderOfNextRound > 0` match those with `OutValue != null`, ensuring consistency but NOT a minimum count threshold.

In contrast, the system correctly enforces `MinersCountOfConsent` for:

**LIB Calculation:** [4](#0-3) 

**Term Changes:** [5](#0-4) 

**MinersCountOfConsent Definition:** [6](#0-5) 

**The Attack Flow:**

1. Any miner can call the public `NextRound()` method: [7](#0-6) 

2. In a network with 7 miners (MinersCountOfConsent = 5), if only 2 miners participate in round N, they can call `NextRound()` and pass all validations

3. The next round is generated including all miners: [8](#0-7) 

4. Miners who didn't participate get their `MissedTimeSlots` incremented, but the round still progresses

5. After sustained minority operation exceeding `TolerableMissedTimeSlotsCount` (4320 slots = 3 days): [9](#0-8) 

6. The honest majority miners are marked as evil: [10](#0-9) 

7. These "evil" miners are then reported and replaced: [11](#0-10) 

## Impact Explanation

**Critical Consensus Integrity Violation:**

The vulnerability breaks fundamental BFT consensus guarantees through two mechanisms:

**Immediate Impact:**
- Round transitions occur with minority participation (e.g., 2 out of 7 miners = 28%)
- While LIB advancement correctly requires 2/3+1, creating a "safety net," the network operates in a degraded state without finality
- Creates an architectural inconsistency where round progression doesn't respect the same consensus threshold as LIB and term changes

**Delayed Critical Impact (after 3+ days):**
- Honest majority miners accumulate `MissedTimeSlots` and eventually exceed `TolerableMissedTimeSlotsCount`
- The system incorrectly identifies the HONEST MAJORITY as "evil miners"
- These honest miners are marked as evil and replaced with alternates
- The minority miners (potentially malicious) remain in control and avoid punishment
- This inverts the security model: attackers remain, honest nodes are ejected
- Enables permanent consensus takeover even after network partition heals

**Affected Parties:**
- Network integrity: BFT consensus guarantees violated
- Honest validators: Incorrectly penalized and removed after sustained adverse conditions
- Users: Loss of finality guarantees during attack, potential for malicious minority control after 3 days

## Likelihood Explanation

**Likelihood Assessment: MEDIUM**

While the claim states HIGH likelihood, a more accurate assessment is MEDIUM because the critical impact (honest majority removal) requires specific sustained conditions:

**Prerequisites:**
- Network partition OR targeted DoS separating minority from majority miners
- Adverse conditions lasting >3 days (4,320 consecutive time slots)
- Minority miners (2+) continue functioning normally while majority (5+) cannot participate

**Feasibility:**
- Natural network partitions: Possible but rarely last 3+ days
- Targeted DoS: Requires resources and coordination but is realistic for motivated attackers
- The attack is technically straightforward once conditions exist

**Attack Complexity:**
- LOW technical complexity: Simply call `NextRound()` method
- HIGH operational complexity: Maintaining adverse conditions for 3+ days
- No special privileges required beyond being in the miner list

**Detection:**
- Gradual degradation makes early detection difficult
- No immediate alerts for insufficient round participation
- LIB halting would be visible but might be attributed to normal network issues

## Recommendation

Add a minimum participation check to the NextRound validation flow:

```csharp
// In ValidationForNextRound method or as a new validation provider
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Check minimum participation threshold
    var minedMinersCount = validationContext.BaseRound.GetMinedMiners().Count;
    if (minedMinersCount < validationContext.BaseRound.MinersCountOfConsent)
    {
        return new ValidationResult 
        { 
            Message = $"Insufficient miner participation for round transition. " +
                     $"Required: {validationContext.BaseRound.MinersCountOfConsent}, " +
                     $"Actual: {minedMinersCount}"
        };
    }
    
    // Existing validations
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

This ensures NextRound transitions align with the same BFT threshold enforced for LIB advancement and term changes.

## Proof of Concept

```csharp
[Fact]
public async Task MinorityCanForceNextRound_WithoutMinimumConsent()
{
    // Setup: 7-miner network, MinersCountOfConsent should be 5
    const int totalMiners = 7;
    const int participatingMiners = 2;
    const int requiredConsent = 5; // 7 * 2/3 + 1
    
    // Initialize round with 7 miners
    var initialMiners = GenerateMiners(totalMiners);
    var initialRound = GenerateNewRound(initialMiners, 1, 1);
    await InitializeConsensus(initialRound);
    
    // Simulate: Only 2 miners participate in round 1
    var participatingMinerKeys = initialMiners.Take(participatingMiners).ToList();
    foreach (var minerKey in participatingMinerKeys)
    {
        await ProducerBlockAndUpdateValue(minerKey);
    }
    
    // Current state: Only 2 out of 7 miners participated (< MinersCountOfConsent)
    var currentRound = await GetCurrentRound();
    var minedCount = currentRound.GetMinedMiners().Count;
    Assert.Equal(participatingMiners, minedCount);
    Assert.True(minedCount < requiredConsent); // 2 < 5
    
    // Attack: Minority miner calls NextRound - should fail but doesn't
    var nextRoundInput = GenerateNextRoundInput(currentRound, participatingMinerKeys[0]);
    var result = await AEDPoSContractStub.NextRound.SendAsync(nextRoundInput);
    
    // VULNERABILITY: NextRound succeeds despite insufficient participation
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Mined);
    
    // Verify round transitioned with only 2/7 participation
    var newRound = await GetCurrentRound();
    Assert.Equal(currentRound.RoundNumber + 1, newRound.RoundNumber);
    
    // Verify non-participating miners accumulated MissedTimeSlots
    var nonParticipatingMiners = initialMiners.Skip(participatingMiners).ToList();
    foreach (var minerKey in nonParticipatingMiners)
    {
        var minerInfo = newRound.RealTimeMinersInformation[minerKey];
        Assert.True(minerInfo.MissedTimeSlots > 0);
    }
    
    // If this continues for 4320 rounds (3 days), honest majority will be marked evil
}
```

**Notes:**
- This test demonstrates that NextRound validation accepts minority participation
- The expected behavior would be validation failure when `minedCount < MinersCountOfConsent`
- Current implementation allows consensus degradation without proper BFT threshold enforcement
- Extended operation under these conditions leads to honest majority being marked as evil nodes

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```
