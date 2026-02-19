### Title
Mining Order Manipulation via Unvalidated FinalOrderOfNextRound in UpdateValue Blocks

### Summary
The `RecoverFromUpdateValue` function blindly overwrites `FinalOrderOfNextRound` values from block headers without validating that proper conflict resolution was performed. A malicious miner can manipulate these values in their block header to control the mining order in the next round, bypassing the intended randomized consensus mechanism and conflict resolution logic in `ApplyNormalConsensusData`.

### Finding Description

The vulnerability exists in the consensus header validation flow for `UpdateValue` behavior: [1](#0-0) 

When a miner produces an `UpdateValue` block, the header contains a full `Round` object with all miners' information including `FinalOrderOfNextRound` values. The intended flow is:

1. The miner's node calls `GetConsensusExtraDataToPublishOutValue` which applies conflict resolution via `ApplyNormalConsensusData`: [2](#0-1) 

2. The conflict resolution logic detects when multiple miners have the same `SupposedOrderOfNextRound` and reassigns conflicting miners to different positions: [3](#0-2) 

However, **miners control the block header content** and can manipulate the `Round` object after or instead of calling `ApplyNormalConsensusData`. When the block is validated, there is **no validation** that the `FinalOrderOfNextRound` values in the header are correct.

The validation for `UpdateValue` behavior only includes: [4](#0-3) 

Notably, `NextRoundMiningOrderValidationProvider` (which validates `FinalOrderOfNextRound` distinctness) is only used for `NextRound` behavior: [5](#0-4) 

The manipulated header values propagate to state execution because `ExtractInformationToUpdateConsensus` is called on the manipulated header round: [6](#0-5) 

This extracts `TuneOrderInformation` based on the manipulated values: [7](#0-6) 

During execution, these manipulated tunings are applied to state: [8](#0-7) 

Finally, the next round generation uses these manipulated `FinalOrderOfNextRound` values to determine mining order: [9](#0-8) 

### Impact Explanation

**Consensus Integrity Compromise:**
- Attackers can arbitrarily manipulate the mining order for the next round
- This breaks the randomized, signature-based consensus mechanism that is fundamental to AEDPoS
- Miners who should have early time slots can be pushed to later slots and vice versa

**Economic and Operational Harm:**
- **Priority manipulation**: Attacker can guarantee themselves position 1 (first miner), which typically has advantages in block production timing and potential MEV extraction
- **Penalty avoidance**: Miners can manipulate orders to avoid being detected for missing time slots by moving themselves to later positions
- **Reward distribution impact**: Mining order affects reward calculations and the likelihood of becoming the extra block producer
- **Censorship potential**: By controlling mining order, attackers can delay specific miners' blocks or create timing advantages for transaction ordering

**Protocol-level damage:**
- Undermines the fairness and unpredictability of the consensus mechanism
- Once one miner exploits this, others must follow to remain competitive, creating a race to exploit
- Long-term degradation of trust in the consensus randomness

### Likelihood Explanation

**High likelihood** - all conditions for exploitation are present:

**Attacker Requirements:**
- Must be an active miner in the consensus set (achievable through staking/election)
- Requires modifying their node software to manipulate block headers before signing (straightforward for any competent attacker)

**Attack Complexity:**
- **Low** - The exploit requires only manipulating the `Round` object in the block header before submission
- No complex timing, race conditions, or multi-step coordination needed
- Single transaction attack vector

**Feasibility Conditions:**
- ✅ Entry point accessible: Any miner can produce `UpdateValue` blocks
- ✅ No cryptographic barriers: The header is set by the miner before signing
- ✅ No economic barriers: Normal block production cost
- ✅ No timing constraints: Works on any `UpdateValue` block the miner produces

**Detection Constraints:**
- Extremely difficult to detect because the manipulated header looks structurally valid
- The hash comparison in `ValidateConsensusAfterExecution` is ineffective because it compares an object to itself after modification
- No on-chain evidence distinguishes malicious from honest blocks

**Execution Practicality:**
- Fully executable under normal AElf block production flow
- Does not require compromise of other miners or infrastructure
- Can be repeated on every block the attacker produces

### Recommendation

**Immediate Fix:**
Add validation of `FinalOrderOfNextRound` values during `UpdateValue` behavior processing:

1. **Add mining order validation for UpdateValue**: Include `NextRoundMiningOrderValidationProvider` in the validation providers for `UpdateValue` behavior, or create a dedicated validator that:
   - Verifies all `FinalOrderOfNextRound` values are distinct
   - Validates that conflict resolution was correctly applied by recomputing `ApplyNormalConsensusData` and comparing results
   - Ensures `TuneOrderInformation` matches the expected conflict adjustments

2. **Validate conflict resolution logic**: Before accepting `TuneOrderInformation`, verify it matches what `ApplyNormalConsensusData` would produce given the miner's signature and current state.

3. **Fix the tautological validation**: The hash comparison in `ValidateConsensusAfterExecution` after calling `RecoverFromUpdateValue` is ineffective because it modifies the comparison object. Either:
   - Clone `currentRound` before calling `RecoverFromUpdateValue`, or
   - Remove the `RecoverFromUpdateValue` call and directly validate the header round against state

4. **Add invariant checks**: 
   - Assert no duplicate `FinalOrderOfNextRound` values exist in state after `ProcessUpdateValue`
   - Log and alert when `TuneOrderInformation` contains unexpected entries

**Code-level Changes:**
In `AEDPoSContract_Validation.cs`, add validation:
```csharp
case AElfConsensusBehaviour.UpdateValue:
    validationProviders.Add(new UpdateValueValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider());
    validationProviders.Add(new UpdateValueMiningOrderValidationProvider()); // NEW
    break;
```

Create `UpdateValueMiningOrderValidationProvider` to verify conflict resolution correctness.

### Proof of Concept

**Initial State:**
- 5 miners in current round: A (attacker), B, C, D, E
- All miners have produced blocks and set their `SupposedOrderOfNextRound` values
- Normal conflict resolution should assign: A→3, B→1, C→5, D→2, E→4

**Attack Sequence:**

1. **Miner A prepares malicious UpdateValue block:**
   - Calls `GetConsensusExtraDataToPublishOutValue` normally
   - **Manipulates the returned header** before creating the block:
     - Sets A.FinalOrderOfNextRound = 1 (instead of 3)
     - Sets B.FinalOrderOfNextRound = 3 (instead of 1)  
     - Keeps other values or adjusts as desired
   - Creates and signs the block with manipulated header

2. **Block validation passes:**
   - `ValidateBeforeExecution`: Passes (only checks time slots, permissions, continuous blocks)
   - `ValidateConsensusBeforeExecution`: No check for FinalOrderOfNextRound correctness
   - Block executes successfully

3. **State modification:**
   - `ExtractInformationToUpdateConsensus` extracts manipulated `TuneOrderInformation`
   - `ProcessUpdateValue` applies: A.FinalOrderOfNextRound = 3 (from SupposedOrderOfNextRound), B.FinalOrderOfNextRound = 3 (from TuneOrderInformation)
   - Wait, both can't be 3... Let me reconsider.

Actually, the attacker would manipulate it such that after `ExtractInformationToUpdateConsensus` runs on the manipulated round, the resulting `TuneOrderInformation` causes the desired state. For example:
   - Header has: A.Supposed=3, A.Final=1; B.Supposed=1, B.Final=3
   - `ExtractInformationToUpdateConsensus` sees A.Final≠A.Supposed, so includes A→1 in TuneOrderInformation
   - `ProcessUpdateValue` sets A.Final=3 (line 247), then overwrites with A.Final=1 (line 260)
   - Result: A gets position 1 in next round

4. **Next round generation:**
   - `GenerateNextRoundInformation` sorts by `FinalOrderOfNextRound`
   - Attacker A mines at position 1 (first slot) instead of position 3

**Expected vs Actual:**
- **Expected**: Mining order based on signature-derived randomness with proper conflict resolution
- **Actual**: Attacker controls their position and can manipulate other miners' positions

**Success Condition**: Attacker consistently mines in their chosen position across multiple rounds despite signature randomness that should prevent this.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L139-146)
```csharp
                    $"Previous in value in extra data:{round.RealTimeMinersInformation[pubkey.ToHex()].PreviousInValue}");
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L25-36)
```csharp
        // Set next round miners' information of miners who successfully mined during this round.
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
