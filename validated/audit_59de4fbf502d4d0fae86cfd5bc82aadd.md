# Audit Report

## Title
Unbounded TuneOrderInformation Allows Consensus DoS via Integer Overflow in Round Generation

## Summary
A malicious miner can exploit the unvalidated `TuneOrderInformation` field in `UpdateValue` to set arbitrary `FinalOrderOfNextRound` values (e.g., int.MaxValue) for any miner. When the next round is generated, this corrupted order value causes an integer overflow exception during mining time calculation, permanently blocking round progression and halting consensus.

## Finding Description

The vulnerability exists in the consensus round update flow where `TuneOrderInformation` is applied without bounds validation.

In `ProcessUpdateValue`, the `TuneOrderInformation` map from `UpdateValueInput` is directly applied to update miners' `FinalOrderOfNextRound` values without any validation of whether the values are within the valid range [1, minersCount]: [1](#0-0) 

The intended use of `TuneOrderInformation` is to communicate order conflict resolutions that occur when multiple miners calculate the same supposed order. The `ExtractInformationToUpdateConsensus` method populates this field by extracting miners whose `FinalOrderOfNextRound` differs from `SupposedOrderOfNextRound`: [2](#0-1) 

However, there is no validation that the provided `TuneOrderInformation` matches what should be extracted from the round state. A malicious miner can provide arbitrary int32 values (including int.MaxValue) for any miner's public key in the map.

When the next round is generated, the corrupted `FinalOrderOfNextRound` becomes the `Order` field in the next round's miner information: [3](#0-2) 

The `Order` value (now int.MaxValue) is then multiplied by `miningInterval` to calculate `ExpectedMiningTime` at line 33. Since AElf uses checked arithmetic, this multiplication will overflow: [4](#0-3) 

The typical `miningInterval` is 4000 milliseconds: [5](#0-4) 

When `order` is int.MaxValue (2,147,483,647), the calculation `4000 * 2,147,483,647 = 8,589,934,588,000` exceeds int.MaxValue and throws `OverflowException`.

The overflow occurs during block generation when `GetConsensusExtraDataForNextRound` calls `GenerateNextRoundInformation`: [6](#0-5) 

This method wraps the actual round generation logic: [7](#0-6) 

**Validation Gaps:**

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` - it does NOT validate `TuneOrderInformation` bounds: [8](#0-7) 

The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with determined `FinalOrderOfNextRound` equals the count of miners who mined blocks - it does NOT validate whether the order values are within the valid range [1, minersCount]: [9](#0-8) 

**Access Control:**

Any miner in the current or previous round can call `UpdateValue`, as verified by the `PreCheck` method: [10](#0-9) 

**Checked Arithmetic Requirement:**

AElf mandates checked arithmetic for all contracts: [11](#0-10) 

## Impact Explanation

**Consensus Halt (Critical)**: Once a miner corrupts another miner's order to int.MaxValue through `UpdateValue`, the corrupted `FinalOrderOfNextRound` is persisted in state. Subsequently, when ANY miner attempts to generate a NextRound block, the block generation process fails with `OverflowException` during the `GenerateNextRoundInformation` call. This prevents the creation of valid NextRound blocks entirely.

The blockchain cannot progress to the next round, causing a permanent consensus deadlock. All network participants are affected - validators cannot produce blocks, transactions cannot be processed, and the entire chain is frozen.

**Recovery requires manual intervention**: The only recovery paths are:
1. Contract upgrade to add validation and/or fix the corrupted state
2. State database rollback to before the corruption
3. Hard fork with state migration

**Severity Justification**: This is a consensus-layer DoS with permanent, protocol-wide impact. Unlike temporary DoS attacks, this corruption persists in the contract state and blocks normal consensus progression. The attack requires only miner privileges (which all consensus validators have by definition) and causes complete blockchain halt affecting all users and validators.

## Likelihood Explanation

**Attacker Capabilities**: Any current miner (consensus validator) can execute this attack. The attacker only needs to be in the current or previous round's miner list to pass the `PreCheck` permission validation.

**Attack Complexity**: Very low - the attack requires only one `UpdateValue` transaction with a malicious `TuneOrderInformation` parameter containing `{targetMinerPubkey: int.MaxValue}`. There are no complex state manipulation requirements, timing constraints, or multi-step coordination needed.

**Feasibility Conditions**: The attack is practical in normal operation. Miners regularly call `UpdateValue` as part of standard consensus operation, so this transaction type is expected and will not raise suspicion. The corruption is applied during `UpdateValue` execution but only manifests when the next miner attempts to generate a NextRound block, making attribution difficult.

**Detection/Operational Constraints**: The state corruption happens immediately when `UpdateValue` executes, but the overflow exception occurs later during block generation for NextRound. By the time the overflow is detected, the malicious state is already persisted on-chain. The separation between corruption time and failure time makes the attack difficult to detect and attribute to the malicious miner.

**Probability**: High - The attack vector is straightforward, requires minimal resources (only transaction fees for one `UpdateValue` call), and can be executed by any consensus validator. There are no preconditions beyond being an active miner, and no monitoring systems can prevent the attack since `UpdateValue` with `TuneOrderInformation` is a legitimate consensus operation.

## Recommendation

Add bounds validation for `TuneOrderInformation` values in `ProcessUpdateValue`:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // ... existing code ...
    
    // Validate TuneOrderInformation bounds before applying
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
            $"Invalid order value {tuneOrder.Value}. Must be between 1 and {minersCount}.");
        currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
    }
    
    // ... rest of existing code ...
}
```

Alternatively, add validation in `UpdateValueValidationProvider` or `NextRoundMiningOrderValidationProvider` to check that all `FinalOrderOfNextRound` values are within the valid range [1, minersCount].

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousTuneOrderInformation_CausesOverflowAndConsensusHalt()
{
    // Setup: Initialize consensus with multiple miners
    await InitializeConsensus();
    var miners = await GetCurrentMiners();
    var maliciousMiner = miners[0];
    var victimMiner = miners[1];
    
    // Attacker: Malicious miner calls UpdateValue with int.MaxValue for victim
    var maliciousInput = new UpdateValueInput
    {
        // ... normal UpdateValue fields ...
        TuneOrderInformation = 
        {
            { victimMiner.PublicKey, int.MaxValue } // Malicious order value
        }
    };
    
    // Execute malicious UpdateValue - this should succeed and corrupt state
    await maliciousMiner.UpdateValue(maliciousInput);
    
    // Verify: The victim's FinalOrderOfNextRound is now int.MaxValue
    var round = await GetCurrentRound();
    Assert.Equal(int.MaxValue, round.RealTimeMinersInformation[victimMiner.PublicKey].FinalOrderOfNextRound);
    
    // Attempt to generate next round - this should throw OverflowException
    await Assert.ThrowsAsync<OverflowException>(async () =>
    {
        await AnyMiner.GenerateNextRoundBlock();
    });
    
    // Consensus is now permanently halted - no miner can generate NextRound blocks
}
```

## Notes

The vulnerability fundamentally violates the consensus safety invariant that `FinalOrderOfNextRound` values must always be within [1, minersCount] to ensure overflow-free arithmetic during round generation. The missing bounds validation on external input (`TuneOrderInformation`) allows a malicious miner to inject invalid state that breaks this invariant, causing permanent consensus failure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L13-19)
```csharp
    public static int Mul(this int a, int b)
    {
        checked
        {
            return a * b;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-74)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L285-346)
```csharp
    private void GenerateNextRoundInformation(Round currentRound, Timestamp currentBlockTime, out Round nextRound)
    {
        TryToGetPreviousRoundInformation(out var previousRound);
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();
        var isMinerListChanged = false;
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
        }

        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
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

**File:** docs-sphinx/architecture/smart-contract/restrictions/project.md (L20-30)
```markdown
- It is required to enable `CheckForOverflowUnderflow` for both Release and Debug mode so that your contract will use arithmetic operators that will throw `OverflowException` if there is any overflow. This is to ensure that execution will not continue in case of an overflow in your contract and result with unpredictable output.

```xml
<PropertyGroup Condition=" '$(Configuration)' == 'Debug' ">
  <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
</PropertyGroup>

<PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
  <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
</PropertyGroup>
```
```
