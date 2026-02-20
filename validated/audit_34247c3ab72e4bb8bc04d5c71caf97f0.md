# Audit Report

## Title
Mining Order Manipulation via Unchecked FinalOrderOfNextRound in Consensus Extra Data

## Summary
A malicious miner can arbitrarily manipulate the mining order for the next round by injecting malicious `FinalOrderOfNextRound` values through consensus extra data. The validation system fails to verify these values during `UpdateValue` behavior, allowing attackers to reorder the mining schedule and compromise consensus integrity.

## Finding Description

The AEDPoS consensus mechanism contains a critical validation gap that allows miners to inject arbitrary `FinalOrderOfNextRound` values for all miners without detection.

**Vulnerable Flow:**

During `UpdateValue` behavior validation, `RecoverFromUpdateValue` blindly copies all miners' `FinalOrderOfNextRound` values from the block header into the current round state, including for miners other than the sender. [1](#0-0) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, but completely ignores `FinalOrderOfNextRound`. [2](#0-1) 

The `NextRoundMiningOrderValidationProvider` that could validate `FinalOrderOfNextRound` is only applied for `NextRound` behavior, not `UpdateValue`. [3](#0-2) 

**Hash Validation Bypass:**

The hash validation in `ValidateConsensusAfterExecution` fails due to a same-object comparison bug. After calling `RecoverFromUpdateValue` which returns `this` (the modified currentRound), the method assigns this same object to `headerInformation.Round`, then compares its hash to itself. [4](#0-3) [5](#0-4) 

**State Persistence:**

The malicious `FinalOrderOfNextRound` values are extracted as `TuneOrderInformation` for miners where `FinalOrderOfNextRound != SupposedOrderOfNextRound`. [6](#0-5) 

These values are then applied to persistent state in `ProcessUpdateValue`. [7](#0-6) 

**Direct Impact on Next Round:**

When generating the next round, miners are ordered directly by their `FinalOrderOfNextRound` values, which now contain the attacker's malicious values. [8](#0-7) 

The legitimate calculation uses deterministic signature-based ordering with conflict resolution, but this is never validated against header-provided values during `UpdateValue`. [9](#0-8) 

**Attack Vector:**

When a miner produces a block with `UpdateValue` behavior, the consensus extra data generation calls `GetUpdateValueRound` which includes `FinalOrderOfNextRound` for all miners in the simplified round object. [10](#0-9) 

Since the miner controls block construction, they can modify these values before including the extra data in the block header. The validation system fails to detect this manipulation.

## Impact Explanation

**CRITICAL - Consensus Integrity Violation**: This vulnerability directly breaks the core consensus invariant of fair, deterministic miner scheduling. A malicious miner can:

1. **Arbitrarily Reorder Mining Schedule**: Set any order for the next round, positioning themselves or colluding miners in advantageous positions (e.g., promoting themselves from order 5 to order 1)

2. **Enable Targeted Censorship**: Control which miners mine first, allowing strategic transaction/block censorship

3. **Extract MEV**: Optimize block ordering across multiple blocks for maximum extractable value

4. **Disrupt Network Operation**: Force honest miners into unfavorable time slots, causing them to miss blocks and potentially be marked as "evil miners"

5. **Setup Chain Reorganization**: Create specific block production sequences as precursors to more sophisticated attacks

The entire network's consensus mechanism is compromised, affecting all participants - miners lose fair scheduling guarantees, and users experience potential transaction censorship and reduced network security.

## Likelihood Explanation

**HIGH Likelihood**: The attack is highly feasible with minimal complexity:

**Attacker Requirements:**
- Must be a valid miner in the current round (normal operational role)
- No special privileges or compromised keys required
- Controls their own node software and block construction

**Attack Complexity:**
- Obtain legitimate consensus extra data via `GetConsensusExtraData`
- Modify `FinalOrderOfNextRound` values in the returned Round object
- Include modified data in block header
- Submit block for validation

**No Effective Barriers:**
- No validation of `FinalOrderOfNextRound` for `UpdateValue` behavior
- Hash check fails due to same-object comparison
- Values within valid ranges (1 to miner count) appear legitimate
- No detection mechanisms or audit trails for order manipulation

**Economic Incentive:**
- MEV opportunities provide direct financial motivation
- Competitive advantage over other miners
- Can be exploited repeatedly every round without detection

## Recommendation

Implement comprehensive validation of `FinalOrderOfNextRound` values for `UpdateValue` behavior:

1. **Add FinalOrderOfNextRound validation to UpdateValueValidationProvider**: Verify that only the sender's `FinalOrderOfNextRound` is updated, or that any changes match legitimate conflict resolution logic.

2. **Fix hash validation logic**: Ensure `ValidateConsensusAfterExecution` compares the original state against the header-provided state, not the same modified object. Create a deep copy before calling `RecoverFromUpdateValue`.

3. **Validate against legitimate calculation**: In `UpdateValueValidationProvider`, verify that provided `FinalOrderOfNextRound` values match those that would result from `ApplyNormalConsensusData` with the provided signature.

4. **Restrict TuneOrderInformation scope**: Only allow miners to modify their own `FinalOrderOfNextRound`, not other miners' values, unless through the legitimate conflict resolution mechanism.

## Proof of Concept

```
Attack Flow:
1. Malicious miner is scheduled to mine at position 5 in current round
2. Miner calls GetConsensusExtraData with UpdateValue behavior
3. Legitimate extra data shows miner's FinalOrderOfNextRound = 5 (calculated from signature)
4. Before submitting block, miner modifies the Round object:
   - Sets their own FinalOrderOfNextRound = 1
   - Sets current position-1 miner's FinalOrderOfNextRound = 5
5. Miner includes modified extra data in block header and submits block
6. ValidateBeforeExecution:
   - RecoverFromUpdateValue copies malicious values (lines 22-30 of Round_Recover.cs)
   - UpdateValueValidationProvider only checks OutValue/Signature (no FinalOrderOfNextRound check)
   - Validation passes
7. ValidateConsensusAfterExecution:
   - Calls RecoverFromUpdateValue again, returns same modified object
   - Hash comparison compares object to itself (lines 89-101 of AEDPoSContract_ACS4)
   - Validation passes
8. ProcessUpdateValue:
   - Extracts TuneOrderInformation with malicious orders (lines 259-260)
   - Saves to state
9. Next round generation:
   - GenerateNextRoundInformation orders by FinalOrderOfNextRound (line 26 of Round_Generation.cs)
   - Attacker now mines at position 1 instead of position 5

Result: Attacker successfully manipulates mining order without detection, gaining first mining position in next round.
```

## Notes

The vulnerability exists because the consensus extra data in block headers includes `FinalOrderOfNextRound` for all miners (not just the sender), but validation assumes only the sender's values can be modified. The same-object comparison bug in hash validation provides no defense against manipulation. This breaks the fundamental assumption that mining order is determined by deterministic signature-based calculation with conflict resolution.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L32-32)
```csharp
        return this;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-88)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L35-53)
```csharp
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
            }
```
