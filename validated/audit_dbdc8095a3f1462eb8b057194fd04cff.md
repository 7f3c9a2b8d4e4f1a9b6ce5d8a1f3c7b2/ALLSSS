# Audit Report

## Title
Unvalidated TuneOrderInformation Allows Mining Order Manipulation Leading to Consensus Breakdown

## Summary
The AEDPoS consensus mechanism fails to validate the `TuneOrderInformation` field in `UpdateValueInput`, allowing malicious miners to assign duplicate `FinalOrderOfNextRound` values. This results in next round generation with duplicate mining orders, breaking critical consensus invariants that require each miner to have a unique mining position.

## Finding Description

**Vulnerability Root Cause:**

When a miner produces a block with UpdateValue behavior, they provide `TuneOrderInformation` - a map that adjusts `FinalOrderOfNextRound` for miners. The `ProcessUpdateValue` method blindly applies these tuned orders without any validation: [1](#0-0) 

The legitimate flow extracts this information using `ExtractInformationToUpdateConsensus`, which only includes miners where `FinalOrderOfNextRound` differs from `SupposedOrderOfNextRound`: [2](#0-1) 

However, there is NO enforcement that miners must use this legitimate extraction method. A malicious miner can craft arbitrary `TuneOrderInformation` values in their `UpdateValueInput` transaction.

**Why Validation Protections Fail:**

1. **UpdateValueValidationProvider** only validates OutValue/Signature and PreviousInValue fields, completely ignoring `TuneOrderInformation`: [3](#0-2) 

2. **NextRoundMiningOrderValidationProvider** has a critical flaw - it uses `Distinct()` on `MinerInRound` objects rather than on the integer order values themselves: [4](#0-3) 

Since `Distinct()` operates on object references without a custom equality comparer (and `MinerInRound` is a protobuf message class [5](#0-4) ), it checks for duplicate object instances, not duplicate `FinalOrderOfNextRound` integer values. This validation completely fails to detect duplicate order assignments.

3. **GenerateNextRoundInformation** directly uses the corrupted `FinalOrderOfNextRound` values to assign mining orders in the next round: [6](#0-5) 

If multiple miners have identical `FinalOrderOfNextRound` values (e.g., MinerA and MinerB both have value 1), they will both be assigned `Order = 1` in the next round, violating the critical consensus invariant that each miner must have a unique mining position.

**Attack Execution Path:**

A malicious miner can:
1. Generate consensus extra data and modify the Round to contain duplicate `FinalOrderOfNextRound` values
2. Create an `UpdateValueInput` transaction with `TuneOrderInformation` matching those duplicate values
3. Include both in the block (header and transaction with consistent malicious data)
4. The block passes `ValidateConsensusAfterExecution` because it uses `RecoverFromUpdateValue` which copies the malicious orders from the header [7](#0-6) , making header and state match [8](#0-7) 
5. Corrupted `FinalOrderOfNextRound` values are persisted to state
6. When `GenerateNextRoundInformation` creates the next round, multiple miners receive identical `Order` values

## Impact Explanation

**Critical Consensus Integrity Breakdown:**

1. **Duplicate Mining Orders:** Multiple miners receive identical `Order` values in a round, causing them to believe they should mine at the same time slot. This fundamentally violates the consensus protocol's assumption of unique, sequential mining positions.

2. **Time Slot Calculation Failure:** The `GetMiningInterval()` method calculates the mining interval by finding miners with Order 1 and Order 2: [9](#0-8) 

With duplicate Order values (e.g., two miners with Order=1 having the same `ExpectedMiningTime`), this calculation produces a mining interval of zero milliseconds, breaking time slot scheduling throughout the consensus system.

3. **Round Progression Denial of Service:** Invalid round structures with duplicate orders can cause round transition failures, potentially halting consensus entirely. The consensus system cannot proceed with corrupted mining schedules.

4. **Miner Position Manipulation:** A malicious miner can consistently assign themselves Order=1 (first mining position) or manipulate competitors' orders to create scheduling conflicts, gaining unfair mining advantages.

**Severity Assessment:** HIGH - This directly violates core consensus invariants requiring correct round transitions, time-slot validation, and miner schedule integrity. The ability to corrupt mining orders threatens the entire consensus mechanism's reliability.

## Likelihood Explanation

**Attacker Capabilities:** Any active miner in the consensus set can execute this attack when they produce a block with UpdateValue behavior. This is a standard consensus operation that occurs regularly.

**Attack Complexity:** LOW
- The entry point is the public `UpdateValue` method accessible to all miners: [10](#0-9) 
- Authorization only checks miner list membership via `PreCheck()`: [11](#0-10) 
- No validation prevents malicious order manipulation
- The attacker simply needs to craft a block with duplicate `FinalOrderOfNextRound` values in both header and transaction

**Feasibility:** HIGH
- No rate limiting or anomaly detection exists for order assignments
- The validation flaw (`Distinct()` on objects) guarantees the attack bypasses checks
- Effects manifest when the next round is generated, making pre-detection difficult
- The attack requires only standard miner privileges (block production)

**Economic Rationality:** Highly rational for:
- Griefing attacks to disrupt consensus (low cost, high impact)
- Competitive advantage in mining position
- Minimal cost (just producing one malicious block)

## Recommendation

**Fix 1: Add TuneOrderInformation validation in UpdateValueValidationProvider**

Validate that `TuneOrderInformation` does not create duplicate `FinalOrderOfNextRound` values:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation
var allFinalOrders = validationContext.ProvidedRound.RealTimeMinersInformation.Values
    .Select(m => m.FinalOrderOfNextRound)
    .Where(order => order > 0)
    .ToList();
    
if (allFinalOrders.Count != allFinalOrders.Distinct().Count())
    return new ValidationResult { Message = "Duplicate FinalOrderOfNextRound detected in TuneOrderInformation." };
```

**Fix 2: Correct NextRoundMiningOrderValidationProvider to check distinct order values**

Replace the buggy `Distinct()` call:

```csharp
// In NextRoundMiningOrderValidationProvider.ValidateHeaderInformation
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Select the order value, not the object
    .Distinct().Count();
    
if (distinctOrderCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound - duplicate orders detected.";
    return validationResult;
}
```

**Fix 3: Add bounds validation**

Ensure all `FinalOrderOfNextRound` values are within valid range (1 to miner count) to prevent array access errors.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanCreateDuplicateMiningOrders()
{
    // Setup: Initialize consensus with 3 miners
    var miners = await InitializeConsensusAsync(3);
    var maliciousMiner = miners[0];
    var victimMiner = miners[1];
    
    // Malicious miner produces a block with UpdateValue
    await maliciousMiner.ProduceNormalBlockAsync();
    
    // Craft malicious UpdateValueInput with duplicate TuneOrderInformation
    var maliciousInput = new UpdateValueInput
    {
        OutValue = Hash.Generate(),
        Signature = Hash.Generate(),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = 
        {
            { maliciousMiner.PublicKey, 1 },  // Assign self Order=1
            { victimMiner.PublicKey, 1 }      // Also assign victim Order=1 (DUPLICATE!)
        },
        // ... other required fields
    };
    
    // Execute malicious UpdateValue transaction
    var result = await maliciousMiner.UpdateValueAsync(maliciousInput);
    result.Status.ShouldBe(TransactionResultStatus.Mined); // Should be REJECTED but passes!
    
    // Verify: Advance to next round
    await AdvanceToNextRoundAsync();
    var nextRound = await GetCurrentRoundAsync();
    
    // Assert: Both miners have duplicate Order=1
    var maliciousMinerInfo = nextRound.RealTimeMinersInformation[maliciousMiner.PublicKey];
    var victimMinerInfo = nextRound.RealTimeMinersInformation[victimMiner.PublicKey];
    
    maliciousMinerInfo.Order.ShouldBe(1);
    victimMinerInfo.Order.ShouldBe(1);  // DUPLICATE! Consensus invariant broken!
    
    // Mining interval calculation fails or returns 0
    var miningInterval = nextRound.GetMiningInterval();
    miningInterval.ShouldBe(0);  // Broken time slot calculation!
}
```

## Notes

This vulnerability represents a critical failure in consensus validation that allows any miner to corrupt the mining schedule. The combination of missing validation in `UpdateValueValidationProvider` and the buggy `Distinct()` implementation in `NextRoundMiningOrderValidationProvider` creates a complete bypass of order uniqueness checks. The attack is particularly dangerous because:

1. It requires no special privileges beyond standard mining rights
2. The corrupted state persists and affects future rounds
3. The zero mining interval breaks time slot calculations system-wide
4. The validation architecture provides a false sense of security while being fundamentally flawed

The recommended fixes should be implemented together to provide defense-in-depth, as fixing only one validator still leaves the attack surface partially exposed.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-290)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
