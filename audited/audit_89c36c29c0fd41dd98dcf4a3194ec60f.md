# Audit Report

## Title
Mining Order Manipulation via Unvalidated FinalOrderOfNextRound in UpdateValue Blocks

## Summary
The AEDPoS consensus validation logic fails to validate `FinalOrderOfNextRound` values in block headers for `UpdateValue` behavior. A malicious miner can manipulate these order values in their block header to control the mining sequence of the next round, bypassing the intended randomized consensus mechanism and conflict resolution logic.

## Finding Description

The vulnerability exists in the consensus header validation flow for `UpdateValue` blocks. When a miner produces an `UpdateValue` block, the block header contains a `Round` object with `FinalOrderOfNextRound` values for all miners.

**The Intended Flow:**
The honest flow calls `GetConsensusExtraDataToPublishOutValue`, which applies conflict resolution via `ApplyNormalConsensusData`. [1](#0-0)  This function calculates `SupposedOrderOfNextRound` from the miner's signature and detects order conflicts, reassigning conflicting miners to different positions. [2](#0-1) 

**The Attack Vector:**
However, miners control the block header content before signing. A malicious miner can modify the `Round` object in the header to set arbitrary `FinalOrderOfNextRound` values for all miners after (or instead of) calling the proper preparation logic.

**The Validation Gap:**
When the block is validated in `ValidateBeforeExecution`, the code calls `RecoverFromUpdateValue` which blindly overwrites `FinalOrderOfNextRound` values from the provided header. [3](#0-2) [4](#0-3) 

The validation for `UpdateValue` behavior only uses `UpdateValueValidationProvider`, which checks that `OutValue` and `Signature` are filled and validates `PreviousInValue` hash correctness - but does NOT validate order values. [5](#0-4) 

Critically, `NextRoundMiningOrderValidationProvider` (which validates `FinalOrderOfNextRound` distinctness and correctness) is only added for `NextRound` behavior, NOT for `UpdateValue`. [6](#0-5) 

**State Corruption:**
During execution, `ProcessUpdateValue` applies the manipulated `TuneOrderInformation` directly to state without validation. [7](#0-6) 

**Impact Propagation:**
When the next round is generated, `GenerateNextRoundInformation` orders miners by their `FinalOrderOfNextRound` values, directly using the attacker's manipulated values to determine mining order and time slots. [8](#0-7) 

## Impact Explanation

**Consensus Integrity Compromise:**
- Attackers can arbitrarily control the mining order for the next round
- This fundamentally breaks the signature-based randomized consensus mechanism
- Miners can guarantee themselves position 1 (first miner slot) for timing advantages
- Can manipulate which miner becomes the extra block producer (which affects rewards)

**Economic Harm:**
- Priority manipulation for potential MEV extraction
- Can delay competing miners by pushing them to later time slots
- Affects reward distribution calculations tied to mining order
- Miners can avoid penalty detection by manipulating their positions

**Protocol Degradation:**
- Once one miner exploits this, others must follow to remain competitive
- Undermines the fairness and unpredictability of AEDPoS consensus
- Long-term erosion of trust in the randomness mechanism

## Likelihood Explanation

**High Likelihood** - all exploitation conditions are satisfied:

**Attacker Requirements:**
- Must be an active miner in the consensus set (achievable through standard election/staking)
- Requires modifying their node software to manipulate block headers before signing (straightforward)

**Attack Complexity:**
- **Low** - Single-step attack: modify `FinalOrderOfNextRound` values in block header
- No timing windows, race conditions, or multi-party coordination needed
- No cryptographic barriers (signature only covers block hash, not individual consensus fields)

**Feasibility:**
- Entry point accessible: Any miner produces `UpdateValue` blocks during normal operation
- No economic barriers beyond standard mining costs
- Repeatable on every `UpdateValue` block the attacker produces

**Detection Difficulty:**
- Manipulated headers appear structurally valid
- No on-chain evidence distinguishes malicious from honest blocks
- The hash comparison in `ValidateConsensusAfterExecution` is ineffective because it compares the header with state that already includes the manipulated values [9](#0-8) 

## Recommendation

Add `FinalOrderOfNextRound` validation for `UpdateValue` behavior by:

1. **Add mining order validation to UpdateValue:** Include `NextRoundMiningOrderValidationProvider` in the validation providers for `UpdateValue` behavior, not just `NextRound`.

2. **Validate order correctness:** Add a new validation provider that verifies `FinalOrderOfNextRound` values match what would be produced by `ApplyNormalConsensusData` based on the miners' signatures.

3. **Cryptographic commitment:** Consider adding a commitment to the order values in the signature to prevent post-hoc manipulation.

Suggested code change in `AEDPoSContract_Validation.cs`:

```csharp
case AElfConsensusBehaviour.UpdateValue:
    validationProviders.Add(new UpdateValueValidationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider()); // Add this
    validationProviders.Add(new LibInformationValidationProvider());
    break;
```

## Proof of Concept

Due to the complexity of the AEDPoS consensus test setup, a full PoC requires:

1. Setting up a test consensus network with multiple miners
2. Modifying a miner node to manipulate `FinalOrderOfNextRound` values in the block header
3. Observing that the manipulated block passes validation
4. Verifying that the next round uses the manipulated mining order

The vulnerability can be confirmed by:
- Examining that `UpdateValueValidationProvider` does not check order values
- Verifying that `NextRoundMiningOrderValidationProvider` is not in the UpdateValue validation chain
- Tracing that `RecoverFromUpdateValue` blindly copies header values
- Confirming `GenerateNextRoundInformation` uses these unchecked values

A minimal test would involve crafting an `UpdateValue` input with manipulated `FinalOrderOfNextRound` values and verifying it passes `ValidateBeforeExecution`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
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
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
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
