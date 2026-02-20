# Audit Report

## Title
Non-Extra-Block-Producer Can Usurp Extra Block Privileges Through NextRound Transaction

## Summary
The AEDPoS consensus contract fails to validate that only the designated extra block producer can execute NextRound transactions. Any miner whose time slot has passed can trigger round termination, and whoever successfully executes NextRound will be incorrectly recorded as `ExtraBlockProducerOfPreviousRound` in the next round, granting them undeserved privileges including pre-round mining rights and increased tiny block limits.

## Finding Description

**Root Cause - Unconditional Assignment:**

When generating consensus extra data for NextRound, the contract unconditionally assigns the sender's public key as `ExtraBlockProducerOfPreviousRound` without verifying they are the actual designated extra block producer. [1](#0-0) 

The protocol intentionally designates exactly one miner per round as the extra block producer during round generation, marked with `IsExtraBlockProducer = true` through a deterministic calculation based on the first miner's signature. [2](#0-1) 

**Missing Authorization Checks:**

The behavior determination logic allows any miner whose time slot has passed to receive NextRound behavior through the termination path. [3](#0-2) 

The validation for NextRound behavior only adds `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`, neither of which validate extra block producer status. [4](#0-3) 

The `MiningPermissionValidationProvider` only verifies the sender is in the current miner list, not that they are the designated extra block producer. [5](#0-4) 

The `PreCheck()` method in transaction processing also only validates that the sender is in the current or previous miner list, without checking `IsExtraBlockProducer` status. [6](#0-5) 

**Privilege Escalation Path:**

Once incorrectly recorded as `ExtraBlockProducerOfPreviousRound`, the miner gains the privilege to mine tiny blocks before the round officially starts, when current time is before the round start time. [7](#0-6) 

Additionally, they receive extended tiny block production limits beyond normal miners, being allowed to produce `maximumBlocksCount + blocksBeforeCurrentRound` blocks due to having "two time slots" recorded. [8](#0-7) 

## Impact Explanation

**Consensus Integrity Violation:**
This vulnerability fundamentally breaks the AEDPoS consensus protocol's deterministic round termination mechanism. The extra block producer role is calculated to ensure fair rotation and predictable consensus behavior. When wrong miners assume this role, the consensus schedule becomes unpredictable and the protocol's fairness guarantees are violated.

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

3. **Race Condition Dynamics:** When a round exceeds its expected duration, the `IsTimeSlotPassed` check returns true for any miner whose `ExpectedMiningTime + miningInterval < currentBlockTime`. [9](#0-8)  Multiple miners whose time slots have passed can simultaneously receive NextRound behavior. The first to successfully execute their NextRound transaction becomes the recorded extra block producer, regardless of whether they were designated for that role.

4. **Detection Difficulty:** The incorrect assignment appears as valid state on-chain with no distinguishing events or logs to identify usurpation versus legitimate termination.

## Recommendation

Add validation in `AEDPoSContract_Validation.cs` to check that the sender has `IsExtraBlockProducer = true` when executing NextRound behavior:

```csharp
case AElfConsensusBehaviour.NextRound:
    // Validate that sender is the designated extra block producer
    validationProviders.Add(new ExtraBlockProducerValidationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

Create a new `ExtraBlockProducerValidationProvider` that verifies:
```csharp
public class ExtraBlockProducerValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var senderPubkey = validationContext.SenderPubkey;
        var baseRound = validationContext.BaseRound;
        
        if (!baseRound.RealTimeMinersInformation.ContainsKey(senderPubkey))
            return new ValidationResult { Message = "Sender not in miner list." };
            
        if (!baseRound.RealTimeMinersInformation[senderPubkey].IsExtraBlockProducer)
            return new ValidationResult { Message = "Only designated extra block producer can execute NextRound." };
            
        return new ValidationResult { Success = true };
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test network with multiple miners
2. Allowing a round to exceed its expected duration (simulating slow/offline designated extra block producer)
3. Having a non-designated miner execute NextRound transaction
4. Observing that the non-designated miner is recorded as `ExtraBlockProducerOfPreviousRound` in the next round
5. Verifying the miner gains pre-round mining privileges and extended tiny block limits

The key test would verify that after a non-designated miner executes NextRound, the `nextRound.ExtraBlockProducerOfPreviousRound` field contains their pubkey instead of the legitimately designated extra block producer's pubkey, and that they subsequently receive TinyBlock behavior when `currentBlockTime < nextRound.GetRoundStartTime()`, which should only be available to the legitimate extra block producer.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-83)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L83-90)
```csharp
    public bool IsTimeSlotPassed(string publicKey, Timestamp currentBlockTime)
    {
        var miningInterval = GetMiningInterval();
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
        if (RoundNumber != 1)
            return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } <
                   currentBlockTime;
```
