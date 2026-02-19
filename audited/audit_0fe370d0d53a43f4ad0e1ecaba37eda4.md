### Title
Predictable Extra Block Producer Selection Enables Miner Withholding Attack

### Summary
Miners can calculate their signature's effect on extra block producer selection before producing blocks, enabling them to strategically withhold blocks when the outcome is unfavorable. The deterministic signature calculation combined with insufficient withholding penalties allows miners to manipulate consensus round transitions for up to 3 days before facing consequences.

### Finding Description

The vulnerability exists in the `CalculateNextExtraBlockProducerOrder()` function which uses the first miner's signature (by order) to determine the next round's extra block producer. [1](#0-0) 

The root cause is that signatures are calculated deterministically from known values. When a miner produces a block, their signature is computed as: [2](#0-1) 

This calculation uses `CalculateSignature(PreviousInValue)` which XORs the miner's previous round InValue with all signatures from the previous round: [3](#0-2) 

Since all inputs to this calculation are known to the miner BEFORE they produce a block (their PreviousInValue and all previous round signatures are on-chain), they can:

1. Calculate their signature: `XOR(PreviousInValue, all_previous_signatures)`
2. Determine the extra block producer: `GetAbsModulus(signature.ToInt64(), minerCount) + 1`
3. If unfavorable, withhold the block

The selection mechanism uses the first miner by order who has a signature: [4](#0-3) 

When a miner withholds, the system falls back to the next miner's signature. The only penalty is incrementing the `MissedTimeSlots` counter: [5](#0-4) 

Evil miner detection only triggers after 4,320 missed slots (3 days at 1 minute per slot): [6](#0-5) [7](#0-6) 

### Impact Explanation

**Consensus Integrity Impact**: Miners can manipulate the extra block producer selection, undermining the intended randomness and fairness of the consensus mechanism. While the extra block producer role doesn't provide direct additional mining rewards, it enables:

1. **Strategic Gaming**: Miners can ensure allies receive the role or prevent competitors from receiving it
2. **Round Transition Control**: The extra block producer triggers round transitions, giving them temporal control advantages
3. **Collusion Amplification**: Multiple miners (especially those with low orders) can coordinate withholding to cycle through signatures until finding a favorable outcome

**Affected Parties**: All network participants are affected as consensus fairness is compromised. Honest miners may be systematically excluded from extra block producer selection through coordinated withholding attacks.

**Severity Justification**: Medium severity because:
- Breaks consensus randomness and fairness guarantees
- No immediate economic theft but enables strategic manipulation
- Difficult to detect as it appears like normal missed blocks
- Long tolerance window (3 days) allows extended manipulation

### Likelihood Explanation

**Attacker Capabilities**: Any miner in the consensus set can execute this attack. The only requirement is the ability to:
1. Calculate signatures from on-chain data (straightforward XOR operation)
2. Withhold block production (inherent capability)
3. Accept temporary reputational cost of missing blocks

**Attack Complexity**: LOW - The attack is technically simple:
- All required data is public and on-chain
- Signature calculation is deterministic
- No special cryptographic knowledge needed
- Can be implemented in standard mining software

**Feasibility Conditions**: 
- Miner must be willing to miss blocks (opportunity cost exists but may be acceptable for strategic gains)
- Miners with lower order numbers (especially order 1) have more influence
- 4,320-slot tolerance provides ample time for short-term manipulation
- No cryptographic commitment prevents prediction

**Detection Constraints**: Attack is STEALTHY - appears identical to legitimate network issues or miner downtime. The 3-day tolerance before evil miner marking makes detection and response slow.

**Probability Assessment**: MEDIUM-HIGH for short-term attacks (< 3 days), especially when:
- Strategic advantages of extra block producer selection exist
- Multiple miners collude
- Miner has low order number (order 1 has maximum influence)

### Recommendation

**Primary Mitigation**: Implement cryptographic commitment for signatures to prevent predictability:

1. Add a two-phase commit-reveal scheme where miners commit to a hash of their signature before revealing
2. Modify signature calculation to include unpredictable elements only available after commitment (e.g., hash of current block)
3. Use verifiable delay functions (VDF) or verifiable random functions (VRF) for signature generation

**Immediate Fix**: Reduce tolerance and add economic penalties:

1. Lower `TolerableMissedTimeSlotsCount` from 4,320 to a much smaller value (e.g., 100 slots)
2. Implement immediate economic penalties for missed blocks (e.g., reduced mining rewards proportional to miss rate)
3. Add slashing for patterns indicating strategic withholding (e.g., missing only specific ordered slots)

**Additional Safeguards**:

1. Use multiple miners' signatures in the calculation (not just first miner)
2. Add randomness from block hash or other unpredictable sources
3. Implement reputation scoring that decays faster with missed blocks
4. Add monitoring for suspicious patterns (e.g., order-1 miner consistently missing blocks at round transitions)

**Test Cases**:
1. Verify miners cannot predict extra block producer before signature submission
2. Test that rapid penalties apply for missed blocks
3. Validate that strategic withholding patterns trigger alerts
4. Ensure commitment-reveal scheme prevents manipulation

### Proof of Concept

**Initial State**:
- Round N is in progress with miners [M1, M2, M3, M4, M5] (orders 1-5)
- All miners from round N-1 have published signatures (on-chain)
- M1 (order 1) is about to produce next block

**Attack Steps**:

1. **Pre-computation** (M1 before producing block):
   - Retrieve M1's `PreviousInValue` from previous round
   - Retrieve all miners' signatures from round N-1
   - Calculate: `signature = XOR(PreviousInValue, XOR(all_previous_signatures))`
   - Calculate: `extraBlockProducerOrder = GetAbsModulus(signature.ToInt64(), 5) + 1`
   - Result shows: extraBlockProducerOrder = 3 (M3 would be selected)

2. **Decision Point**:
   - If M1 wants M3 to be extra block producer → produce block
   - If M1 does NOT want M3 → withhold block

3. **Withholding Execution** (assuming unfavorable):
   - M1 does not call `UpdateValue` during their time slot
   - M1's `MissedTimeSlots` increments by 1
   - System falls back to M2's signature for calculation

4. **Iterative Manipulation**:
   - M2 produces block with their signature
   - M2's signature determines different extra block producer (e.g., M5)
   - If still unfavorable, M3 could also withhold
   - Attack continues until favorable outcome or too many slots missed

**Expected vs Actual Result**:
- **Expected**: Extra block producer selection should be unpredictable to prevent manipulation
- **Actual**: Miners can calculate outcome in advance and selectively withhold blocks with only minor penalties (1 missed slot per withholding, up to 4,320 before banning)

**Success Condition**: 
After 10 block productions where M1 withholds on 3 occasions (when calculation shows unfavorable outcomes), M1 has only 3 missed slots (far below 4,320 threshold) and successfully influenced extra block producer selection 3 times. M1 remains in good standing while having manipulated consensus.

### Notes

The vulnerability is particularly concerning because:
1. The fallback mechanism (using next miner's signature) intended as redundancy actually enables iterative manipulation
2. The 3-day tolerance is designed for network resilience but creates a large attack window
3. The attack is indistinguishable from legitimate network behavior
4. Colluding miners exponentially increase attack effectiveness (e.g., orders 1-3 colluding can try 3 different signatures per round transition)

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L54-54)
```csharp
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```
