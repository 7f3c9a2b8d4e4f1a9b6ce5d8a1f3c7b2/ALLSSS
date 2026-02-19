### Title
Non-Deterministic Miner Selection in FirstMiner() Due to MapField Iteration Order Dependency

### Summary
The `FirstMiner()` function relies on `MapField.Values.FirstOrDefault()` to find the miner with `Order == 1`, but protobuf MapField does not guarantee deterministic iteration order. While normal operation should produce unique orders, there is no validation preventing duplicate `Order` values in externally-submitted Round data. If duplicate orders exist, different nodes would return different miners from `FirstMiner()`, causing consensus failure and chain forks.

### Finding Description

The vulnerability exists in the `FirstMiner()` method which uses non-deterministic iteration: [1](#0-0) 

The `RealTimeMinersInformation` field is a protobuf map type: [2](#0-1) 

**Root Cause:**
1. Google.Protobuf's `MapField<TKey, TValue>` does not guarantee deterministic iteration order across different nodes or serialization cycles
2. If multiple miners have `Order == 1`, `FirstOrDefault()` returns whichever miner appears first in the iteration sequence
3. Different nodes may have different iteration orders, causing them to return different miners

**Why Protections Fail:**

Round data comes from external block proposer input via `NextRound`: [3](#0-2) 

The `NextRoundInput` is converted to a `Round` and processed: [4](#0-3) 

Validation occurs in `ValidateBeforeExecution`, but the `NextRoundMiningOrderValidationProvider` only validates `FinalOrderOfNextRound` uniqueness, NOT `Order` field uniqueness: [5](#0-4) 

No validation provider checks for duplicate `Order` values in the Round being processed.

**Related Critical Issue:**

Additionally, `GenerateNextRoundInformation` contains definitively non-deterministic code that selects the extra block producer without any ordering when the expected producer is null: [6](#0-5) 

### Impact Explanation

**Consensus Break (Critical):**
- If different nodes return different miners from `FirstMiner()`, they would have inconsistent consensus state
- Methods using `FirstMiner()` include consensus command generation and round start time calculation: [7](#0-6) [8](#0-7) 

**Chain Fork:**
- Divergent consensus states would cause nodes to reject each other's blocks
- The blockchain would fork, halting normal operation
- Network would lose finality guarantees

**Affected Parties:**
- All nodes in the network
- Users unable to transact during consensus failure
- Protocol integrity compromised

### Likelihood Explanation

**Attack Complexity:**
Medium - Requires crafting malicious `NextRoundInput` with duplicate orders or exploiting a bug in round generation

**Feasible Preconditions:**
1. Attacker must be a valid miner (to submit blocks)
2. Must craft `NextRoundInput` that passes all validation except duplicate order check
3. Or discover/trigger a bug that generates duplicate orders

**Why Validation is Insufficient:**
The validation explicitly checks FinalOrderOfNextRound but not Order field uniqueness. Round generation code assumes uniqueness but doesn't enforce it: [9](#0-8) 

The `BreakContinuousMining` function swaps orders and temporarily creates a state where two miners have the same order, though this resolves before the method returns: [10](#0-9) 

**Detection Difficulty:**
High - Non-determinism would appear as random consensus failures, difficult to diagnose

**Probability:**
Low-Medium - Current code likely generates unique orders, but lack of validation means any bug or future change could introduce duplicates without detection

### Recommendation

**1. Add Explicit Order Uniqueness Validation:**
Add a validation provider that checks for duplicate `Order` values in Round data before processing:

```csharp
// New validation provider
public class OrderUniquenessValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext context)
    {
        var orders = context.ProvidedRound.RealTimeMinersInformation.Values
            .Select(m => m.Order).ToList();
        var distinctOrders = orders.Distinct().Count();
        
        if (distinctOrders != orders.Count)
            return new ValidationResult { Message = "Duplicate Order values detected in Round" };
            
        return new ValidationResult { Success = true };
    }
}
```

Register this provider in `ValidateBeforeExecution`: [11](#0-10) 

**2. Use Deterministic Ordering:**
Always use `OrderBy(m => m.Order)` before `First()` or `FirstOrDefault()`:

```csharp
public MinerInRound FirstMiner()
{
    return RealTimeMinersInformation.Count > 0
        ? RealTimeMinersInformation.Values.OrderBy(m => m.Order).FirstOrDefault(m => m.Order == 1)
        : new MinerInRound();
}
```

**3. Fix Non-Deterministic Extra Block Producer Selection:**
Replace the unfiltered `.First()` call at line 63 with deterministic ordering:

```csharp
if (expectedExtraBlockProducer == null)
    nextRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).First().IsExtraBlockProducer = true;
```

**4. Add Invariant Checks:**
Add assertions in `GenerateNextRoundInformation` and other Round manipulation functions to verify order uniqueness before returning.

### Proof of Concept

**Required Initial State:**
- Active AEDPoS consensus with multiple miners
- Attacker is a valid miner with block production rights

**Attack Sequence:**

1. **Craft Malicious NextRoundInput:**
   - Generate valid Round with all required fields
   - Intentionally assign `Order = 1` to two different miners
   - Calculate valid `round_id_for_validation`

2. **Submit Block with Malicious Consensus Data:**
   - Include crafted `NextRoundInput` in block's consensus extra data
   - Block passes validation (no duplicate order check exists)

3. **Consensus Divergence:**
   - Node A's MapField iteration returns Miner X as `FirstMiner()`
   - Node B's MapField iteration returns Miner Y as `FirstMiner()`
   - Subsequent consensus decisions diverge

**Expected vs Actual Result:**

Expected: All nodes agree on `FirstMiner()` identity, consensus proceeds normally

Actual: Different nodes return different miners from `FirstMiner()`, causing:
- Inconsistent `GetRoundStartTime()` calculations
- Divergent consensus behavior determinations
- Block rejection and chain fork

**Success Condition:**
Network splits into factions, each rejecting the other's blocks due to consensus state mismatch, demonstrating complete consensus failure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L105-108)
```csharp
    public Timestamp GetRoundStartTime()
    {
        return FirstMiner().ExpectedMiningTime;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L142-148)
```csharp
    public MinerInRound FirstMiner()
    {
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1)
            // Unlikely.
            : new MinerInRound();
    }
```

**File:** protobuf/aedpos_contract.proto (L243-247)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-111)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-56)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L73-90)
```csharp
    private void BreakContinuousMining(ref Round nextRound)
    {
        var minersCount = RealTimeMinersInformation.Count;
        if (minersCount <= 1) return;

        // First miner of next round != Extra block producer of current round
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-102)
```csharp
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-92)
```csharp
        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```
