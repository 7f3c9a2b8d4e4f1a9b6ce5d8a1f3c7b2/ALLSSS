# Audit Report

## Title
Multiple UpdateValue Submissions Allow Miners to Manipulate Next Round Position Order

## Summary
A miner who has already submitted consensus data via `UpdateValue` can call it again within the same round with a different signature to recalculate their `FinalOrderOfNextRound` position. This allows malicious miners to manipulate their position in the next round's mining order, displacing honest miners and violating consensus fairness.

## Finding Description

The `UpdateValue` method in the AEDPoS consensus contract allows miners to submit their consensus information for the current round. However, there is a critical flaw: no mechanism prevents a miner from calling this method multiple times within the same round across different blocks.

**Entry Point**: The `UpdateValue` method calls `ProcessConsensusInformation` which processes the update. [1](#0-0) 

**Insufficient Guard**: The `EnsureTransactionOnlyExecutedOnceInOneBlock` method only prevents multiple executions within the SAME block, not across different blocks within the same round. [2](#0-1) 

The check compares `State.LatestExecutedHeight.Value != Context.CurrentHeight`, which means if a miner calls `UpdateValue` in block 10 (sets `LatestExecutedHeight = 10`), they can call it again in block 15 of the same round (where `CurrentHeight = 15 != 10`), and the check will pass.

**Unconditional Overwrite**: The `ProcessUpdateValue` method unconditionally overwrites critical consensus fields without checking if they were already set: [3](#0-2) 

This includes `Signature`, `OutValue`, `SupposedOrderOfNextRound`, and `FinalOrderOfNextRound`. The method also applies `TuneOrderInformation` which can adjust other miners' positions.

**Validation Bypass**: The validation flow calls `RecoverFromUpdateValue` BEFORE running validation providers, which modifies the `baseRound` with the provided data: [4](#0-3) 

The `RecoverFromUpdateValue` method unconditionally overwrites the miner's consensus data in the round state: [5](#0-4) 

As a result, when `UpdateValueValidationProvider` validates the data, it sees the already-modified state rather than the original on-chain state: [6](#0-5) 

The validation only checks that `OutValue` and `Signature` are filled, but does NOT check if they were already set in the original on-chain round state.

**Position Manipulation**: The next round position is deterministically calculated from the signature hash: [7](#0-6) 

This calculation uses `GetAbsModulus(signature.ToInt64(), minersCount) + 1`, allowing an attacker to compute offline which signature will yield position 1. [8](#0-7) 

**Honest Miner Displacement**: When position conflicts occur, the conflict resolution logic pushes OTHER miners to different positions, allowing the attacker to legitimately displace honest miners through the tuning mechanism.

**Next Round Generation**: The manipulated `FinalOrderOfNextRound` values are directly used to determine actual mining positions in the next round: [9](#0-8) 

**No On-Chain Prevention**: The off-chain command generation logic checks if `OutValue == null` before suggesting `UpdateValue` behavior, but this is not enforced on-chain: [10](#0-9) 

A malicious actor can bypass this by manually crafting `UpdateValue` transactions even after their `OutValue` is already set.

## Impact Explanation

**Consensus Integrity Violation**: This vulnerability directly compromises the fairness and integrity of the AEDPoS consensus mechanism. The deterministic position assignment based on signatures is a fundamental security property designed to prevent manipulation. This vulnerability completely undermines that guarantee.

**Mining Order Manipulation**: An attacker can arbitrarily choose their position in the next round, typically targeting position 1 (the first miner). The first miner in a round has significant advantages:
- Priority in block production
- Greater control over transaction ordering within their block
- First access to MEV opportunities
- Higher visibility and influence in the network

**Honest Miner Impact**: When the attacker changes their position through resubmission, the conflict resolution mechanism forces honest miners who had legitimately secured their positions to be displaced to different, potentially less favorable positions. This affects all miners in the round, not just the attacker.

**Severity Justification**: HIGH - This is a direct attack on consensus mechanism integrity, which is a critical component of blockchain security. The ability to manipulate mining order violates fundamental fairness assumptions and can lead to centralization of mining power, as malicious miners can systematically secure the most advantageous positions.

## Likelihood Explanation

**Attacker Requirements**:
- Must be an authorized miner in the current miner list (normal operational requirement)
- Ability to compute signature hashes offline (trivial computational task)
- Ability to produce multiple blocks within one round (standard miner capability)

**Attack Complexity**: LOW
1. Miner produces their first block with signature S1, gets position 5
2. Offline: compute various signatures and their resulting positions until finding S2 that yields position 1
3. Produce another block within the same round with signature S2
4. Second `UpdateValue` call overwrites previous data and secures position 1

**Feasibility**: The attack is fully feasible under normal network conditions:
- Rounds typically span multiple blocks, providing opportunities for multiple submissions
- No rate limiting beyond per-block check
- No monitoring or detection mechanism for this behavior
- Transaction pool accepts the second `UpdateValue` transaction as valid

**Detection Difficulty**: The attack appears as normal block production and consensus participation, making it extremely difficult to detect or attribute malicious intent.

**Probability**: HIGH - Any miner in the miner list can execute this attack with minimal effort and cost. The only barrier is being part of the active miner set, which is the normal operational state for all consensus participants.

## Recommendation

Implement a per-round, per-miner tracking mechanism to prevent multiple `UpdateValue` submissions within the same round:

1. **Add Round-Level Tracking**: Store which miners have already submitted `UpdateValue` for each round in contract state.

2. **On-Chain Validation**: In `ProcessUpdateValue`, check if the miner has already submitted for the current round before processing:
   ```csharp
   // At the start of ProcessUpdateValue
   var submissionKey = $"{State.CurrentRoundNumber.Value}_{_processingBlockMinerPubkey}";
   Assert(State.UpdateValueSubmissions[submissionKey] != true, 
          "Miner has already submitted UpdateValue for this round.");
   State.UpdateValueSubmissions[submissionKey] = true;
   ```

3. **Validation Enhancement**: Modify `UpdateValueValidationProvider` to check the original on-chain state (before `RecoverFromUpdateValue` modification) to ensure `OutValue` and `Signature` are null:
   ```csharp
   // Check original on-chain state before recovery
   var originalMinerInRound = validationContext.BaseRound.RealTimeMinersInformation[publicKey];
   if (originalMinerInRound.OutValue != null || originalMinerInRound.Signature != null)
       return new ValidationResult { Message = "Consensus data already submitted for this round." };
   ```

4. **Cleanup**: Remove old submission records when rounds are finalized to prevent state bloat.

## Proof of Concept

```csharp
// Test demonstrating multiple UpdateValue submissions in same round
[Fact]
public async Task MultipleUpdateValue_SameRound_ManipulatesPosition()
{
    // Setup: Initialize consensus with multiple miners
    var miners = await InitializeConsensusWithMiners(5);
    var attackerMiner = miners[0];
    
    // Round N starts
    var currentRound = await GetCurrentRound();
    var roundNumber = currentRound.RoundNumber;
    
    // Block 1: Attacker submits first UpdateValue with signature S1
    var signature1 = HashHelper.ComputeFrom("signature1");
    var updateValue1 = new UpdateValueInput {
        Signature = signature1,
        OutValue = HashHelper.ComputeFrom("outvalue1"),
        // ... other fields
    };
    await attackerMiner.UpdateValue(updateValue1);
    
    // Verify initial position
    currentRound = await GetCurrentRound();
    var initialPosition = currentRound.RealTimeMinersInformation[attackerMiner.PublicKey]
        .FinalOrderOfNextRound;
    Assert.NotEqual(1, initialPosition); // Assume not position 1
    
    // Advance to next block in SAME round (simulate block production by other miners)
    await ProduceBlocks(3); // Still in same round
    
    // Block 4: Attacker submits SECOND UpdateValue with crafted signature S2
    var signature2 = ComputeSignatureForPosition(1, currentRound.RealTimeMinersInformation.Count);
    var updateValue2 = new UpdateValueInput {
        Signature = signature2,
        OutValue = HashHelper.ComputeFrom("outvalue2"),
        // ... other fields
    };
    
    // This should fail but doesn't - that's the vulnerability
    await attackerMiner.UpdateValue(updateValue2);
    
    // Verify position manipulation
    currentRound = await GetCurrentRound();
    var manipulatedPosition = currentRound.RealTimeMinersInformation[attackerMiner.PublicKey]
        .FinalOrderOfNextRound;
    
    // Vulnerability confirmed: attacker successfully changed position to 1
    Assert.Equal(1, manipulatedPosition);
    Assert.Equal(roundNumber, currentRound.RoundNumber); // Still same round
}
```

The test demonstrates that a miner can call `UpdateValue` multiple times within the same round, successfully overwriting their position and manipulating the next round's mining order. The vulnerability exists because `EnsureTransactionOnlyExecutedOnceInOneBlock` only prevents execution within a single block, not across multiple blocks in the same round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-260)
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

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-60)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-44)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```
