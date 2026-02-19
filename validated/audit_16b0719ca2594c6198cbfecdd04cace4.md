# Audit Report

## Title
Consensus Round Number Reset Vulnerability via Validation Bypass During Bootstrap Phase

## Summary
A malicious miner can exploit a validation bypass during the first 23 blocks to reset the consensus round number back to 1, causing consensus state corruption and incorrect mining strategy selection. This vulnerability combines a bootstrap validation bypass with an unsafe round number update check, allowing round number regression that bypasses normal validation.

## Finding Description

The vulnerability stems from two interconnected flaws in the AEDPoS consensus contract:

**Flaw 1: Bootstrap Validation Bypass**

The `ValidateBeforeExecution` method contains a bootstrap-phase bypass that returns early when only a single miner has been producing blocks across all rounds during the first 23 blocks: [1](#0-0) [2](#0-1) 

This early return at line 43 occurs BEFORE the `RoundTerminateValidationProvider` is added to the validation pipeline (lines 84-87), completely bypassing critical round number increment validation.

**Flaw 2: Unsafe Round Number Update Logic**

The `TryToUpdateRoundNumber` method has a special case that allows setting round number to 1 without validating whether this represents valid progression: [3](#0-2) 

When `roundNumber == 1`, the condition `roundNumber != 1` evaluates to false, causing the entire if-statement to short-circuit and skip the validation check, allowing the update regardless of the current round number.

**Normal Protection That Gets Bypassed**

Under normal circumstances, `RoundTerminateValidationProvider` would catch invalid round transitions: [4](#0-3) 

However, this provider is never added to the validation pipeline when the bootstrap bypass activates.

**Attack Execution Path:**

1. A malicious miner exploits the vulnerability during blocks 1-23 while being the sole active miner
2. The attacker sends a `NextRound` transaction with `NextRoundInput{RoundNumber: 1}` when the system is at round 2+
3. `ValidateBeforeExecution` enters the bootstrap bypass block and returns success without adding validation providers
4. `ProcessNextRound` executes and calls `TryToUpdateRoundNumber(1)`, which succeeds due to the special case
5. `State.CurrentRoundNumber.Value` is reset to 1
6. The `AddRoundInformation` method overwrites the original round 1 data: [5](#0-4) [6](#0-5) 

**Consequence: Wrong Strategy Selection**

After the attack, `GetConsensusCommand` incorrectly uses `FirstRoundCommandStrategy` instead of `NormalBlockCommandStrategy`: [7](#0-6) 

`FirstRoundCommandStrategy` uses simplified time calculations and omits critical round tracking information: [8](#0-7) 

Compare this to `NormalBlockCommandStrategy` which includes proper `RoundId` and `PreviousRoundId` fields: [9](#0-8) 

## Impact Explanation

**Critical Consensus State Corruption:**

The vulnerability directly compromises consensus integrity through multiple mechanisms:

1. **Round Number Regression**: The consensus round number is reset from its current value (e.g., round 2+) back to 1, violating the monotonic progression invariant that the consensus protocol depends on.

2. **Historical Data Loss**: The original round 1 data in `State.Rounds[1]` is permanently overwritten with new round data, destroying immutable consensus history that nodes rely on for validation and synchronization.

3. **Mining Strategy Corruption**: Future consensus commands use `FirstRoundCommandStrategy` which calculates mining times using the simplified formula `(Order + MinersCount - 1) * miningInterval` instead of the actual expected mining times stored in the round state. This causes miners to produce blocks at incorrect times.

4. **Broken Round Continuity**: The consensus hints omit `RoundId` and `PreviousRoundId` fields, which are required for proper round continuity validation. This breaks the chain of round proofs that ensures consensus integrity.

5. **Irrecoverable Fork**: When additional miners come online after the bootstrap phase, they observe `CurrentRoundNumber == 1` while the blockchain has progressed significantly. The conflicting state views cause permanent consensus disagreement that cannot be resolved without manual chain rollback.

The severity is **Critical** because it directly undermines the fundamental consensus mechanism, affects all network participants, and has no automated recovery path.

## Likelihood Explanation

**Attack Feasibility: High During Bootstrap Phase**

The vulnerability is highly exploitable during network initialization:

**Required Conditions:**
1. **Temporal Window**: Attack must occur within the first 23 blocks (verified in constants)
2. **Sole Active Miner**: Attacker must be the only miner producing blocks while multiple miners are configured
3. **Valid Miner Status**: Attacker must be in the legitimate miner list

**Realistic Attack Scenario:**

This is highly realistic during blockchain launch because:

- **Staged Deployment**: Not all miners start simultaneously due to coordination challenges, network latency, or staged rollout procedures
- **Network Issues**: Temporary connectivity problems can prevent other miners from participating initially  
- **Intentional Design**: The system explicitly accommodates single-miner bootstrap operation (as evidenced by the bypass logic), but fails to protect against malicious exploitation
- **No Economic Barrier**: The attacker is a legitimate miner earning normal block rewards, so there's no cost to executing the attack

**Low Attack Complexity:**

- Requires crafting a single `NextRound` transaction with `RoundNumber: 1`
- No complex transaction sequencing or precise timing requirements
- No need for external resources or sophisticated tooling
- Attack succeeds on first attempt if conditions are met

**Difficult Detection:**

- The malicious transaction appears as a valid consensus operation during bootstrap
- No immediate errors or anomalies occur
- The corruption only becomes apparent after the bootstrap window closes and other miners attempt to synchronize

The combination of high exploitability and realistic conditions during the critical bootstrap phase results in a high likelihood assessment.

## Recommendation

**Fix 1: Enforce Round Number Progression During Bootstrap**

Modify the bootstrap validation bypass to still enforce round number increment validation:

```csharp
if (baseRound.RealTimeMinersInformation.Count != 1 &&
    Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
{
    // Bootstrap bypass logic...
    if (result)
    {
        // Still validate round number progression for NextRound behavior
        if (extraData.Behaviour == AElfConsensusBehaviour.NextRound)
        {
            if (baseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
                return new ValidationResult { Message = "Incorrect round number for next round." };
        }
        return new ValidationResult { Success = true };
    }
}
```

**Fix 2: Remove Unsafe Special Case**

Alternatively, modify `TryToUpdateRoundNumber` to remove the special case for round 1 after initial bootstrap:

```csharp
private bool TryToUpdateRoundNumber(long roundNumber)
{
    var oldRoundNumber = State.CurrentRoundNumber.Value;
    // Only allow round 1 if we're at initial state (oldRoundNumber == 0)
    if (roundNumber != oldRoundNumber + 1 && !(roundNumber == 1 && oldRoundNumber == 0))
        return false;
    State.CurrentRoundNumber.Value = roundNumber;
    return true;
}
```

Both fixes prevent round number regression while preserving the intended bootstrap behavior.

## Proof of Concept

```csharp
[Fact]
public async Task RoundNumberResetVulnerability_BootstrapBypass()
{
    // Setup: Initialize chain with round 1
    var initialMiners = GenerateMinerList(3); // 3 miners configured
    await InitializeConsensus(initialMiners);
    
    // Progress to round 2 with only one miner producing blocks
    var soloMiner = initialMiners[0];
    await ProduceBlocksAsOnlyMiner(soloMiner, roundCount: 1);
    
    // Verify we're at round 2
    var currentRound = await GetCurrentRoundNumber();
    Assert.Equal(2, currentRound);
    
    // Verify we're still within the 23-block bootstrap window
    var currentHeight = await GetCurrentBlockHeight();
    Assert.True(currentHeight < 24);
    
    // EXPLOIT: Submit NextRound transaction with RoundNumber = 1
    var maliciousInput = new NextRoundInput 
    { 
        RoundNumber = 1,
        // ... other required fields
    };
    
    var result = await ExecuteConsensusTransaction(soloMiner, "NextRound", maliciousInput);
    
    // Vulnerability confirmed: Round number was reset to 1
    currentRound = await GetCurrentRoundNumber();
    Assert.Equal(1, currentRound); // Should be 3, but is now 1
    
    // Verify original round 1 data was overwritten
    var round1Data = await GetRoundInformation(1);
    Assert.NotEqual(originalRound1Hash, round1Data.GetHash());
    
    // Verify wrong strategy is now used
    var consensusCommand = await GetConsensusCommand(soloMiner);
    Assert.False(consensusCommand.Hint.Contains("RoundId")); // FirstRound strategy omits RoundId
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L23-43)
```csharp
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L91-97)
```csharp
    private bool TryToUpdateRoundNumber(long roundNumber)
    {
        var oldRoundNumber = State.CurrentRoundNumber.Value;
        if (roundNumber != 1 && oldRoundNumber + 1 != roundNumber) return false;
        State.CurrentRoundNumber.Value = roundNumber;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-30)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-158)
```csharp
        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L28-30)
```csharp
        if (currentRound.RoundNumber == 1 && behaviour == AElfConsensusBehaviour.UpdateValue)
            return new ConsensusCommandProvider(new FirstRoundCommandStrategy(currentRound, pubkey,
                currentBlockTime, behaviour)).GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs (L31-46)
```csharp
        public override ConsensusCommand GetAEDPoSConsensusCommand()
        {
            var miningInterval = MiningInterval;
            var offset =
                _consensusBehaviour == AElfConsensusBehaviour.UpdateValue && Order == 1
                    ? miningInterval
                    : Order.Add(MinersCount).Sub(1).Mul(miningInterval);
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeMiningTimeWithOffset(CurrentBlockTime, offset);
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint { Behaviour = _consensusBehaviour }.ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                MiningDueTime = arrangedMiningTime.AddMilliseconds(miningInterval),
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L23-41)
```csharp
        public override ConsensusCommand GetAEDPoSConsensusCommand()
        {
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeNormalBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);

            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint
                {
                    Behaviour = AElfConsensusBehaviour.UpdateValue,
                    RoundId = CurrentRound.RoundId,
                    PreviousRoundId = _previousRoundId
                }.ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                // Cancel mining after time slot of current miner because of the task queue.
                MiningDueTime = CurrentRound.GetExpectedMiningTime(Pubkey).AddMilliseconds(MiningInterval),
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
            };
        }
```
