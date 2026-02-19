# Audit Report

## Title
Non-Extra-Block-Producer Can Usurp Extra Block Privileges Through NextRound Transaction

## Summary
The AEDPoS consensus contract fails to validate that only the designated extra block producer (marked with `IsExtraBlockProducer = true`) can execute NextRound/NextTerm transactions. Any miner whose time slot has passed can trigger round termination, and whoever successfully executes NextRound will be incorrectly recorded as `ExtraBlockProducerOfPreviousRound` in the next round, granting them undeserved privileges including pre-round mining rights and increased tiny block limits.

## Finding Description

The vulnerability exists in the consensus command generation and validation flow where multiple security checks fail to enforce extra block producer authorization.

**Root Cause - Unconditional Assignment:**

When generating consensus extra data for NextRound, the contract unconditionally assigns the sender's public key as `ExtraBlockProducerOfPreviousRound` without verifying they are the actual designated extra block producer. [1](#0-0) 

The protocol intentionally designates exactly one miner per round as the extra block producer during round generation, marked with `IsExtraBlockProducer = true` through a deterministic calculation. [2](#0-1) 

**Missing Authorization Checks:**

The behavior determination logic allows any miner whose time slot has passed to receive NextRound behavior through the termination path. [3](#0-2) 

The validation providers for NextRound behavior fail to check if the sender has `IsExtraBlockProducer = true`. The validation only adds `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`, neither of which validate extra block producer status. [4](#0-3) 

The `MiningPermissionValidationProvider` only verifies the sender is in the current miner list, not that they are the designated extra block producer. [5](#0-4) 

**Privilege Escalation Path:**

Once incorrectly recorded as `ExtraBlockProducerOfPreviousRound`, the miner gains the privilege to mine blocks before the round officially starts. [6](#0-5) 

Additionally, they receive extended tiny block production limits beyond normal miners. [7](#0-6) 

## Impact Explanation

**Consensus Integrity Violation:**
This vulnerability fundamentally breaks the AEDPoS consensus protocol's deterministic round termination mechanism. The extra block producer role is carefully calculated to ensure fair rotation and predictable consensus behavior. When wrong miners assume this role, the consensus schedule becomes unpredictable and the protocol's fairness guarantees are violated.

**Operational Impact:**
Miners who usurp extra block privileges can produce blocks outside their designated time slots, specifically before the round officially starts. This creates opportunities for transaction ordering manipulation, potential censorship during the privilege window, and unfair advantage in block production. The extended tiny block limits compound this advantage by allowing more blocks than intended.

**Reward Misallocation:**
Extra block producers receive rewards for their privileged blocks. When the wrong miner assumes this role, they receive rewards that should have gone to the legitimately designated producer, creating economic unfairness in the consensus system.

## Likelihood Explanation

**Attack Feasibility: HIGH**

This vulnerability is highly exploitable under normal network conditions:

1. **Low Barrier to Entry:** Any miner in the current miner list can attempt this attack. No special governance privileges or compromised keys are required.

2. **Natural Trigger Conditions:** The vulnerability can be triggered naturally through:
   - Network latency causing the designated extra block producer to be slow
   - The extra block producer experiencing temporary downtime
   - Round overtime scenarios where multiple miners simultaneously evaluate their next behavior
   - Any timing variance in the distributed consensus system

3. **Race Condition Dynamics:** When a round exceeds its expected duration, multiple miners whose time slots have passed can simultaneously receive NextRound behavior. The first to successfully execute their NextRound transaction becomes the recorded extra block producer, regardless of whether they were designated for that role. [8](#0-7) 

4. **Detection Difficulty:** The incorrect assignment appears as valid state on-chain with no distinguishing events or logs to identify usurpation versus legitimate termination.

## Recommendation

Add explicit validation that the sender of NextRound/NextTerm transactions must be the designated extra block producer:

```csharp
// In AEDPoSContract_Validation.cs, add a new validation provider
public class ExtraBlockProducerValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        
        if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextRound ||
            validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextTerm)
        {
            var extraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation
                .FirstOrDefault(m => m.Value.IsExtraBlockProducer).Key;
            
            if (extraBlockProducer != validationContext.SenderPubkey)
            {
                validationResult.Message = 
                    $"Only the designated extra block producer can execute NextRound/NextTerm. " +
                    $"Expected: {extraBlockProducer}, Got: {validationContext.SenderPubkey}";
                return validationResult;
            }
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}

// In ValidateBeforeExecution method, add the provider for NextRound/NextTerm:
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new ExtraBlockProducerValidationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new ExtraBlockProducerValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

## Proof of Concept

```csharp
[Fact]
public async Task NonExtraBlockProducerCanUsurpPrivileges_Test()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(5);
    await InitializeConsensusAsync(miners);
    
    // Progress through a round until time slots pass
    var currentRound = await GetCurrentRoundAsync();
    var designatedExtraBlockProducer = currentRound.RealTimeMinersInformation
        .First(m => m.Value.IsExtraBlockProducer).Key;
    
    // Select a different miner (not the designated extra block producer)
    var wrongMiner = miners.First(m => m != designatedExtraBlockProducer);
    
    // Advance time so the wrong miner's time slot passes
    await AdvanceTimeToPassTimeSlot(wrongMiner);
    
    // Wrong miner attempts NextRound
    var result = await ExecuteConsensusActionAsync(wrongMiner);
    
    // Verify the wrong miner successfully executed NextRound
    Assert.True(result.Success);
    
    // Verify the wrong miner is now recorded as ExtraBlockProducerOfPreviousRound
    var nextRound = await GetCurrentRoundAsync();
    Assert.Equal(wrongMiner, nextRound.ExtraBlockProducerOfPreviousRound);
    
    // Verify the wrong miner gained pre-round mining privileges
    var canMineBeforeRoundStart = await CanMineBeforeRoundStartAsync(wrongMiner);
    Assert.True(canMineBeforeRoundStart);
    
    // Verify extended tiny block limits were granted
    var tinyBlockLimit = await GetTinyBlockLimitAsync(wrongMiner);
    Assert.True(tinyBlockLimit > GetMaximumBlocksCount());
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-178)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-65)
```csharp
        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L39-83)
```csharp
        public AElfConsensusBehaviour GetConsensusBehaviour()
        {
            // The most simple situation: provided pubkey isn't a miner.
            // Already checked in GetConsensusCommand.
//                if (!CurrentRound.IsInMinerList(_pubkey))
//                {
//                    return AElfConsensusBehaviour.Nothing;
//                }

            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
            }

            return GetConsensusBehaviourToTerminateCurrentRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L19-37)
```csharp
    public Timestamp ArrangeAbnormalMiningTime(string pubkey, Timestamp currentBlockTime,
        bool mustExceededCurrentRound = false)
    {
        var miningInterval = GetMiningInterval();

        var minerInRound = RealTimeMinersInformation[pubkey];

        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
        }

        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
    }
```
