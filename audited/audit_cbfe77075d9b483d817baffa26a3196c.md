### Title
Consensus DoS via Missing Extra Block Producer Validation in Round Transition

### Summary
The `GetExtraBlockProducerInformation()` method uses `First()` (not `FirstOrDefault()` as stated in the question) which throws an `InvalidOperationException` when no miner has `IsExtraBlockProducer = true`. A malicious authorized miner can craft a `NextRoundInput` without an extra block producer, bypass validation, store it in state, and cause all subsequent consensus command generation to fail, halting the blockchain.

### Finding Description

**Root Cause:**
The `GetExtraBlockProducerInformation()` method unconditionally uses `First()` on miner information filtered by `IsExtraBlockProducer`: [1](#0-0) 

This method is called during consensus command generation for round termination: [2](#0-1) 

And also during next round generation: [3](#0-2) 

**Why Protections Fail:**

1. The `NextRound` method accepts arbitrary `NextRoundInput` from authorized miners: [4](#0-3) 

2. `NextRoundInput.ToRound()` performs no validation, just field copying: [5](#0-4) 

3. The `RoundTerminateValidationProvider` only validates round number increment and null InValues, but does NOT check for extra block producer existence: [6](#0-5) 

4. The malicious round gets stored in state: [7](#0-6) 

**Execution Path:**

When consensus command generation occurs with NextRound/NextTerm behavior, `TerminateRoundCommandStrategy` is instantiated: [8](#0-7) 

Which calls `ArrangeExtraBlockMiningTime`: [9](#0-8) 

Leading to the exception when `GetExtraBlockProducerInformation()` is invoked.

### Impact Explanation

**Harm:**
- Complete consensus failure - no miner can generate valid consensus commands
- Blockchain halts indefinitely until manual intervention
- All transaction processing stops
- Cross-chain operations fail
- Economic activities (staking, rewards, trading) freeze

**Affected Parties:**
- All network participants
- Dependent side chains
- DApp users and smart contracts

**Severity:** Critical - this is a complete denial of service of the entire blockchain's consensus mechanism. Once exploited, the chain cannot recover through normal consensus flow.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an authorized miner (in current miner list)
- Can craft and submit malicious `NextRoundInput` directly to `NextRound()` method

**Attack Complexity:**
- Low - requires only constructing a `NextRoundInput` with all `IsExtraBlockProducer` flags set to false
- No complex timing or state manipulation needed
- Single transaction exploit

**Feasibility:**
- Precondition is being an authorized miner (feasible for insider threat or compromised miner)
- The validation gap is structural, not race-condition dependent
- Exploitable immediately once access is obtained

**Detection:**
- Attack succeeds before detection - the malicious round is stored
- Subsequent consensus failure is obvious but irreversible through normal flow

**Probability:** Medium-High given that it requires miner compromise, but the exploit is trivial once that condition is met.

### Recommendation

**Code-Level Mitigation:**

Add validation in `RoundTerminateValidationProvider` to ensure exactly one miner has `IsExtraBlockProducer = true`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Validate extra block producer existence
    var extraBlockProducerCount = extraData.Round.RealTimeMinersInformation.Values
        .Count(m => m.IsExtraBlockProducer);
    
    if (extraBlockProducerCount != 1)
        return new ValidationResult { Message = "Exactly one extra block producer required." };
    
    return new ValidationResult { Success = true };
}
```

**Defensive Programming:**

Change `GetExtraBlockProducerInformation()` to fail gracefully:

```csharp
private MinerInRound GetExtraBlockProducerInformation()
{
    var extraBlockProducer = RealTimeMinersInformation
        .FirstOrDefault(bp => bp.Value.IsExtraBlockProducer).Value;
    
    Assert(extraBlockProducer != null, "No extra block producer found in round.");
    return extraBlockProducer;
}
```

**Test Cases:**
1. Attempt to submit `NextRoundInput` with zero extra block producers - should fail validation
2. Attempt to submit `NextRoundInput` with multiple extra block producers - should fail validation
3. Verify normal round generation always sets exactly one extra block producer

### Proof of Concept

**Initial State:**
- Miner M is authorized in current round
- Current round has proper extra block producer

**Attack Steps:**

1. Miner M constructs malicious `NextRoundInput`:
   - Set `RoundNumber = CurrentRound.RoundNumber + 1`
   - Copy all miners from current round to `RealTimeMinersInformation`
   - Set all miners' `IsExtraBlockProducer = false`
   - Set all miners' `InValue = null`

2. Miner M calls `NextRound(maliciousInput)`

3. Validation passes because:
   - Round number increments correctly
   - All InValues are null
   - No extra block producer check exists

4. Malicious round stored in state via `AddRoundInformation()`

5. Next miner attempts to get consensus command

6. `GetConsensusCommand()` is called with behavior = NextRound/NextTerm

7. `TerminateRoundCommandStrategy` created with malicious round

8. `GetAEDPoSConsensusCommand()` calls `ArrangeExtraBlockMiningTime()`

9. `ArrangeAbnormalMiningTime()` calls `GetExtraBlockProducerInformation()`

10. `First()` throws `InvalidOperationException` - no miner has `IsExtraBlockProducer = true`

**Expected Result:** Consensus command generation succeeds

**Actual Result:** Exception thrown, consensus halts, blockchain stops

**Success Condition:** When monitoring logs show repeated failures in `GetConsensusCommand()` with "Sequence contains no matching element" exception, and no new blocks are produced.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L26-26)
```csharp
        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L39-42)
```csharp
    private MinerInRound GetExtraBlockProducerInformation()
    {
        return RealTimeMinersInformation.First(bp => bp.Value.IsExtraBlockProducer).Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L80-80)
```csharp
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L39-44)
```csharp
            case AElfConsensusBehaviour.NextRound:
            case AElfConsensusBehaviour.NextTerm:
                return new ConsensusCommandProvider(
                        new TerminateRoundCommandStrategy(currentRound, pubkey, currentBlockTime,
                            behaviour == AElfConsensusBehaviour.NextTerm))
                    .GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L25-26)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
```
