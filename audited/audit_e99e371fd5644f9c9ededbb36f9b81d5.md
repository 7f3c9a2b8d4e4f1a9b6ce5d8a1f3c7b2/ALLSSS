# Audit Report

## Title
Missing Order Value Validation in Round Structure Enables Consensus DoS Attack

## Summary
The AEDPoS consensus contract fails to validate that miner Order values in Round structures start from 1 and are sequential. The `GetMiningInterval()` method assumes miners with Order 1 and 2 exist and directly accesses array index [1] without bounds checking. A malicious miner can submit a `NextRoundInput` with invalid Order values (e.g., starting from 10), which passes all validation checks but causes all nodes to crash with `ArgumentOutOfRangeException` when retrieving consensus commands, completely halting block production.

## Finding Description

The vulnerability exists in the `GetMiningInterval()` method which filters for miners with `Order == 1 || Order == 2` and directly accesses index [1] of the resulting list without verifying it contains at least 2 elements: [1](#0-0) 

All consensus command strategy classes inherit from `CommandStrategyBase`, which exposes a `MiningInterval` property that calls this unsafe method: [2](#0-1) 

The validation logic in `CheckRoundTimeSlots()` only validates that `ExpectedMiningTime` is not null and time intervals are consistent, but does NOT validate that Order values start from 1: [3](#0-2) 

This validation is invoked by `TimeSlotValidationProvider` for new rounds: [4](#0-3) 

The `NextRoundMiningOrderValidationProvider` only validates `FinalOrderOfNextRound` consistency, not the Order values themselves: [5](#0-4) 

When a malicious `NextRoundInput` is processed, it passes validation and gets stored via `AddRoundInformation()`: [6](#0-5) 

The Round is stored without additional validation: [7](#0-6) 

Subsequently, when any miner requests a consensus command via `GetConsensusCommand()`, the malicious Round is retrieved and passed to strategy classes: [8](#0-7) 

All strategy implementations (`NormalBlockCommandStrategy`, `TinyBlockCommandStrategy`, `TerminateRoundCommandStrategy`) access the `MiningInterval` property, triggering the crash: [9](#0-8) [10](#0-9) [11](#0-10) 

## Impact Explanation

**Severity: HIGH**

Once a malicious Round with invalid Order values is stored in contract state, the entire blockchain stops producing blocks. The impact is catastrophic:

1. **Complete Consensus Halt**: All miners crash with unhandled `ArgumentOutOfRangeException` when calling `GetConsensusCommand()`, preventing any new blocks from being produced.

2. **Network-Wide DoS**: The attack affects all nodes simultaneously - every miner that attempts to retrieve a consensus command will crash.

3. **Persistent State Corruption**: The malicious Round remains in contract state until manual intervention, making the DoS permanent without coordinated recovery efforts.

4. **No User Transactions**: Users cannot submit transactions since no blocks are being produced.

5. **Recovery Complexity**: Requires coordinated manual intervention across all nodes to reset the corrupted state, which is operationally complex and time-consuming.

This breaks the fundamental availability guarantee of the blockchain consensus mechanism.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack requires the attacker to be an active miner, which is verified by `PreCheck()`: [12](#0-11) 

However, the attack complexity is LOW:

1. **Simple Exploit**: The attacker only needs to craft a `NextRoundInput` with miners having Order values that don't include 1 or 2 (e.g., starting from 10), set `ExpectedMiningTime` values correctly with consistent intervals, and submit it in a NextRound block.

2. **No Economic Cost**: Beyond being a miner, there is no additional cost. No stake is slashed, no special resources are required.

3. **Single Transaction**: Only one malicious block is needed to permanently halt the entire blockchain.

4. **Passes All Validation**: The malformed Round passes all validation checks because `CheckRoundTimeSlots()` and `NextRoundMiningOrderValidationProvider` don't validate Order values.

5. **Immediate Impact**: Once executed, the impact is immediate and affects all nodes on their next consensus command request.

6. **Difficult to Detect**: The attack is difficult to detect before execution because the malformed input passes all validation checks.

While limited to miners (reducing the attacker pool), the trivial execution complexity and maximum impact with minimal cost make this a realistic and dangerous attack vector.

## Recommendation

Add explicit validation for Order values in the `CheckRoundTimeSlots()` method to ensure Order values start from 1 and are sequential:

```csharp
public ValidationResult CheckRoundTimeSlots()
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    // NEW: Validate Order values start from 1 and are sequential
    for (var i = 0; i < miners.Count; i++)
    {
        if (miners[i].Order != i + 1)
            return new ValidationResult { Message = $"Invalid Order value. Expected {i + 1}, got {miners[i].Order}" };
    }

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

Alternatively, add bounds checking in `GetMiningInterval()`:

```csharp
public int GetMiningInterval()
{
    if (RealTimeMinersInformation.Count == 1)
        return 4000;

    var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
        .ToList();
    
    // Add bounds check
    Assert(firstTwoMiners.Count >= 2, "Round must contain miners with Order 1 and 2");

    return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
        .Milliseconds());
}
```

The first approach (validation in `CheckRoundTimeSlots()`) is preferred as it catches the issue during validation before the malicious Round is stored in state.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Create a `NextRoundInput` with miners having Order values starting from 10 (not 1)
2. Set `ExpectedMiningTime` correctly with consistent intervals
3. Call `NextRound()` method - this will pass validation
4. Call `GetConsensusCommand()` - this will throw `ArgumentOutOfRangeException` and crash

The test would show that the validation passes in step 3, but the system crashes in step 4, confirming the vulnerability chain is complete and exploitable.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-57)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L37-37)
```csharp
        protected int MiningInterval => CurrentRound.GetMiningInterval();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-156)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

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

        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L23-53)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();

        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();

        Context.LogDebug(() =>
            $"{currentRound.ToString(_processingBlockMinerPubkey)}\nArranged behaviour: {behaviour.ToString()}");

        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L38-38)
```csharp
                MiningDueTime = CurrentRound.GetExpectedMiningTime(Pubkey).AddMilliseconds(MiningInterval),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L34-38)
```csharp
                ? roundStartTime.AddMilliseconds(-MiningInterval)
                : CurrentRound.RoundNumber == 1
                    ? MinerInRound.ActualMiningTimes.First()
                    : MinerInRound.ExpectedMiningTime;
            var currentTimeSlotEndTime = currentTimeSlotStartTime.AddMilliseconds(MiningInterval);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L35-35)
```csharp
                MiningDueTime = arrangedMiningTime.AddMilliseconds(MiningInterval),
```
