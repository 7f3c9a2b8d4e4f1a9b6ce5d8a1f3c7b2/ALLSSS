### Title
Byzantine Miner Can Corrupt Consensus State Through Ineffective Round Validation

### Summary
The `ValidateConsensusAfterExecution` method contains a critical logic flaw where it compares a Round object to itself after the `RecoverFromUpdateValue` operation, making hash-based validation completely ineffective. This allows a Byzantine miner to inject false Round information (particularly `FinalOrderOfNextRound` and `PreviousInValue` for other miners) into the blockchain state, which honest miners subsequently read when calling `GetConsensusCommand`, causing incorrect consensus decisions in `ConsensusBehaviourProviderBase`.

### Finding Description

**Root Cause:**

The validation logic in `ValidateConsensusAfterExecution` has an object aliasing bug. [1](#0-0) 

The `RecoverFromUpdateValue` method modifies the `currentRound` object in-place and returns `this`: [2](#0-1) 

After line 91 executes, both `headerInformation.Round` and `currentRound` reference the same object. The subsequent hash comparison at lines 100-101 compares the object to itself, which always succeeds: [3](#0-2) 

**Attack Vector:**

1. A Byzantine miner crafts a block with consensus extra data containing a Round with false information about other miners (particularly `FinalOrderOfNextRound`, `SupposedOrderOfNextRound`, and `PreviousInValue`)

2. When `RecoverFromUpdateValue` executes, it copies ALL miners' order and previous-in-value information from the provided round into the base round: [4](#0-3) 

3. The hash validation fails to detect the false base state because it compares the same object

4. When the block is executed, `ProcessUpdateValue` writes the false information to state, specifically updating other miners' `FinalOrderOfNextRound` via `TuneOrderInformation`: [5](#0-4) 

5. The false information originates from `ExtractInformationToUpdateConsensus`, which extracts tune order information from the Byzantine miner's provided round: [6](#0-5) 

6. Honest miners subsequently call `GetConsensusCommand`, which reads the corrupted state: [7](#0-6) 

7. The false `CurrentRound` is passed to `ConsensusBehaviourProviderBase` constructor: [8](#0-7) 

8. Consensus decisions are made based on false state, affecting time slot validation, mining order, and block production behavior: [9](#0-8) 

**Why Existing Protections Fail:**

The `GetCheckableRound` method excludes `ActualMiningTimes`, `EncryptedPieces`, and `DecryptedPieces` from hash calculation: [10](#0-9) 

However, the hash validation itself is broken due to object aliasing, so even fields that ARE included in the hash provide no protection.

Individual validation providers check the current miner's own information but do not validate whether the Byzantine miner has falsified information about OTHER miners: [11](#0-10) 

### Impact Explanation

**Consensus Integrity Compromise:**
A Byzantine miner can manipulate the mining order and time slot information for ALL miners in the network. By setting arbitrary `FinalOrderOfNextRound` values, they can:
- Cause honest miners to believe they should mine at incorrect time slots
- Reorder the mining schedule to give themselves additional mining opportunities
- Make miners skip their actual time slots, believing they've already mined

**Operational Impact:**
False `PreviousInValue` injection can cause honest miners to fail validation when they attempt to mine, as their actual previous-in-value won't match the corrupted state. This can lead to:
- Chain liveness issues if multiple honest miners are blocked from mining
- Consensus deadlock if the extra block producer has false state
- Inconsistent round transitions

**Protocol Security:**
The `ConsensusBehaviourProviderBase` makes critical decisions based on the corrupted round state, including whether to produce `UpdateValue`, `TinyBlock`, `NextRound`, or `NextTerm` transactions. False state causes honest miners to choose incorrect behaviors, breaking the consensus protocol's safety and liveness guarantees.

### Likelihood Explanation

**Attacker Capabilities:**
Requires Byzantine miner to be selected for block production (elected miner with valid mining slot). No additional privileges needed beyond normal miner capabilities.

**Attack Complexity:**
Low complexity. The attacker simply needs to:
1. Modify their local Round object before generating consensus extra data
2. Set arbitrary `FinalOrderOfNextRound` values for target miners
3. Produce their block normally

**Feasibility:**
The attack is highly feasible because:
- The validation flaw exists in production code
- No additional state manipulation required
- The false data automatically propagates through `ExtractInformationToUpdateConsensus` and `ProcessUpdateValue`
- Subsequent blocks will build on the corrupted state

**Detection Constraints:**
The attack is difficult to detect because:
- The corrupted blocks pass all validation checks
- The false Round information appears legitimate
- Only deep inspection of state transitions would reveal the manipulation
- Affected honest miners would appear to be misbehaving (skipping slots, mining at wrong times)

**Probability:**
High probability of exploitation if a Byzantine miner understands the validation flaw. The economic incentive exists to manipulate mining order for increased block rewards.

### Recommendation

**Immediate Fix:**

Modify `ValidateConsensusAfterExecution` to properly clone the `currentRound` before recovery operations: [12](#0-11) 

```csharp
if (TryToGetCurrentRoundInformation(out var currentRound))
{
    var baseRoundClone = currentRound.Clone(); // Add Clone method to Round
    
    if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRoundClone.RecoverFromUpdateValue(headerInformation.Round,
            headerInformation.SenderPubkey.ToHex());
    
    if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
        baseRoundClone.RecoverFromTinyBlock(headerInformation.Round,
            headerInformation.SenderPubkey.ToHex());
    
    // Now compare recovered clone against original header round
    if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
        baseRoundClone.GetHash(isContainPreviousInValue))
    {
        // validation logic
    }
}
```

**Additional Validation:**

Add explicit validation for `TuneOrderInformation` in `UpdateValueValidationProvider` to verify that order changes are justified by actual signature-based conflicts, not arbitrary modifications.

**Test Cases:**

1. Test that attempts to modify other miners' `FinalOrderOfNextRound` without valid conflicts are rejected
2. Test that recovery operations produce different objects for comparison
3. Test Byzantine scenarios where miners provide rounds with modified base state
4. Regression test ensuring hash validation actually detects state mismatches

### Proof of Concept

**Initial State:**
- Blockchain has miners A, B, C elected for current round
- State shows: Miner B with `FinalOrderOfNextRound = 2`, Miner C with `FinalOrderOfNextRound = 3`

**Attack Steps:**

1. Byzantine Miner A's turn to produce block
2. Miner A calls `GetConsensusCommand`, receives `UpdateValue` behavior
3. Miner A modifies their local Round object before generating extra data:
   - Sets Miner B's `FinalOrderOfNextRound = 3`
   - Sets Miner C's `FinalOrderOfNextRound = 2`
   - (No valid signature conflict exists)
4. Miner A generates consensus extra data with this false Round
5. Miner A produces block with false consensus information

**Validation Flow:**
6. `ValidateConsensusBeforeExecution` passes (individual validators don't check other miners' orders)
7. `ValidateConsensusAfterExecution` called:
   - Line 91: `headerInformation.Round = currentRound.RecoverFromUpdateValue(headerInformation.Round, "A")`
   - `RecoverFromUpdateValue` copies false orders from header into `currentRound` (lines 24-27 of Round_Recover.cs)
   - Returns `currentRound` (same object)
   - Line 100-101: Compares `currentRound` hash to `currentRound` hash (same object) → PASSES
8. Block accepted

**State Corruption:**
9. `ProcessUpdateValue` executes, line 259-260 applies false `TuneOrderInformation`
10. State now shows: Miner B with `FinalOrderOfNextRound = 3`, Miner C with `FinalOrderOfNextRound = 2` (SWAPPED)

**Honest Miner Impact:**
11. Honest Miner B calls `GetConsensusCommand`
12. Reads corrupted state showing `FinalOrderOfNextRound = 3` instead of 2
13. `ConsensusBehaviourProviderBase` initialized with false `CurrentRound`
14. Miner B makes consensus decisions based on false order
15. May mine at wrong time slot or with incorrect expectations for next round

**Success Condition:**
State verification after attack shows `FinalOrderOfNextRound` values don't match legitimate consensus protocol outcomes, causing honest miners to deviate from intended behavior.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L23-24)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L87-97)
```csharp
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L99-113)
```csharp
            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L26-37)
```csharp
        protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;

            _pubkey = pubkey;
            _maximumBlocksCount = maximumBlocksCount;
            _currentBlockTime = currentBlockTime;

            _isTimeSlotPassed = CurrentRound.IsTimeSlotPassed(_pubkey, _currentBlockTime);
            _minerInRound = CurrentRound.RealTimeMinersInformation[_pubkey];
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
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
