# Audit Report

## Title
Term Change Indefinitely Delayed via Timestamp Manipulation by Coalition of ~1/3 Miners

## Summary
The AEDPoS consensus contract's `NeedToChangeTerm` function relies on miners' self-reported `ActualMiningTime` timestamps without validating they match `Context.CurrentBlockTime`. A coalition of approximately one-third of miners can indefinitely prevent term changes by submitting backdated timestamps, blocking miner rotation and election results.

## Finding Description

The vulnerability exists in the term change detection mechanism. The `MainChainConsensusBehaviourProvider` determines whether to trigger a term change by calling `NeedToChangeTerm`: [1](#0-0) 

The `NeedToChangeTerm` method counts how many miners have their **last** `ActualMiningTime` indicating term change is needed, requiring at least `MinersCountOfConsent` miners (calculated as N * 2 / 3 + 1): [2](#0-1) [3](#0-2) 

The `IsTimeToChangeTerm` check compares timestamps against the term period: [4](#0-3) 

**Root Cause**: When processing `UpdateValue` transactions, the `ActualMiningTime` from the input is directly added to the miner's list without validation: [5](#0-4) 

The same issue exists for `TinyBlock` transactions: [6](#0-5) 

**Why Existing Protections Fail**: 

The `TimeSlotValidationProvider` only validates the **previous** `ActualMiningTime` from the BaseRound (before current transaction execution), not the new timestamp being added: [7](#0-6) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` - it does not check `ActualMiningTime`: [8](#0-7) 

In contrast, the honest implementation sets `ActualMiningTime` to `Context.CurrentBlockTime`: [9](#0-8) 

## Impact Explanation

**Mathematical Attack Analysis**:
For N=21 total miners, `MinersCountOfConsent = (21 * 2 / 3) + 1 = 15`. If K=7 malicious miners provide backdated timestamps (before term threshold), only 14 honest miners indicate term change. Since 14 < 15, the term transition is blocked.

**Consensus Integrity Breach**:
- **Miner Rotation Blocked**: Term changes rotate the miner set based on election results. Preventing term changes allows the current miner set to remain in power indefinitely.
- **Election Results Ignored**: Voters' choices are nullified as newly elected miners cannot take their positions.
- **Governance Disruption**: Term-dependent mechanisms (Treasury distributions, profit scheme updates) are halted.
- **Centralization Risk**: Defeats the purpose of periodic miner rotation for decentralization.

This breaks a fundamental consensus invariant - term transitions should occur when the configured period elapses, regardless of miner preferences.

## Likelihood Explanation

**Attacker Capabilities Required**:
- Control approximately 1/3 of active miners (~7 out of 21)
- Ability to modify node software to provide backdated `ActualMiningTime`
- Continuous participation as active miners

**Attack Complexity**:
- **Low Technical Barrier**: Requires only modifying consensus transaction generation to use an old timestamp instead of `Context.CurrentBlockTime`
- **No Special Permissions**: Uses existing miner capabilities through normal `UpdateValue` transactions
- **Persistent Effect**: Can be maintained indefinitely with coalition coordination

**Feasibility**: While controlling ~1/3 of miners requires significant coordination, it's realistic in networks with concentrated mining power or collusion scenarios. The attack is technically trivial once coalition is formed.

**Detection Difficulty**: No automatic validation compares `ActualMiningTime` against block timestamps, making detection require manual analysis.

## Recommendation

Add validation in `ProcessUpdateValue` and `ProcessTinyBlock` to ensure `ActualMiningTime` matches `Context.CurrentBlockTime`:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // Add validation
    Assert(updateValueInput.ActualMiningTime == Context.CurrentBlockTime, 
        "ActualMiningTime must equal CurrentBlockTime");
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
    // ... rest of method
}
```

Apply the same fix to `ProcessTinyBlock`.

## Proof of Concept

```csharp
[Fact]
public async Task TermChange_BlockedByBackdatedTimestamps()
{
    // Setup: 21 miners, term period = 7 days
    const int totalMiners = 21;
    const int maliciousMiners = 7;
    const int termPeriodSeconds = 604800; // 7 days
    
    // Initialize consensus with 21 miners
    await InitializeConsensusWithMiners(totalMiners, termPeriodSeconds);
    
    // Fast forward time past term threshold
    var currentTime = TimestampHelper.GetUtcNow();
    var termChangeTime = currentTime.AddSeconds(termPeriodSeconds + 1);
    BlockTimeProvider.SetBlockTime(termChangeTime);
    
    // Simulate honest miners (14 miners) producing blocks with current time
    for (int i = 0; i < totalMiners - maliciousMiners; i++)
    {
        await ProduceBlockWithTimestamp(honestMiners[i], termChangeTime);
    }
    
    // Simulate malicious miners (7 miners) producing blocks with OLD timestamp
    var oldTimestamp = currentTime.AddSeconds(termPeriodSeconds - 100); // Before threshold
    for (int i = 0; i < maliciousMiners; i++)
    {
        await ProduceBlockWithBackdatedTimestamp(maliciousMiners[i], oldTimestamp);
    }
    
    // Verify term change is blocked
    var currentRound = await GetCurrentRound();
    var needTermChange = currentRound.NeedToChangeTerm(
        blockchainStartTimestamp, 
        currentTermNumber, 
        termPeriodSeconds);
    
    // Expected: needTermChange should be true (14 honest miners indicate change)
    // Actual: needTermChange is FALSE because only 14 < 15 required
    Assert.False(needTermChange); // Attack succeeds
}
```

## Notes

The vulnerability is mathematically sound: `MinersCountOfConsent` requires a supermajority (>2/3), so approximately 1/3 of miners can prevent consensus on term changes. The missing validation that `ActualMiningTime == Context.CurrentBlockTime` is the critical flaw enabling this attack. This breaks the fundamental assumption that term transitions occur automatically after the configured period, instead making them dependent on miner cooperation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-249)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-306)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L58-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```
