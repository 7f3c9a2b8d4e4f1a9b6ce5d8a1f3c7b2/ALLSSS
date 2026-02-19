### Title
VRF Manipulation via Invalid PreviousInValue Leading to Mining Order Control

### Summary
When a miner provides an invalid `PreviousInValue` that fails the self-check, the code sets `previousInValue = Hash.Empty` but still calculates the signature using the invalid value. This allows malicious miners to manipulate their position in the next mining round by choosing arbitrary values that produce favorable signatures, breaking the VRF (Verifiable Random Function) fairness guarantee of the consensus mechanism.

### Finding Description

The vulnerability exists in `GetConsensusExtraDataToPublishOutValue()` function where a critical logic error allows miners to manipulate their mining order in the next round.

**Root Cause:**

When a miner produces a block, they should reveal their `PreviousInValue` which must hash to their committed `OutValue` from the previous round. The self-check validation occurs at: [1](#0-0) 

When this check fails (provided value doesn't hash to stored OutValue), the code sets `previousInValue = Hash.Empty` as a failure indicator. However, the signature calculation happens OUTSIDE the validation block: [2](#0-1) 

This signature is calculated from the invalid `triggerInformation.PreviousInValue` regardless of whether the self-check passed or failed. The mismatched values (previousInValue=Hash.Empty, signature calculated from invalid value) are then passed to: [3](#0-2) 

In `ApplyNormalConsensusData`, the signature directly determines the miner's position in the next round: [4](#0-3) [5](#0-4) [6](#0-5) 

**Why Protections Fail:**

The validation system explicitly allows `PreviousInValue = Hash.Empty`: [7](#0-6) 

This was designed to handle legitimate edge cases (first round, new miners), but it also permits the exploited scenario. There is no verification that the stored signature matches `CalculateSignature(PreviousInValue)` after the round completes.

**Execution Path:**

When generating the next round, miners are ordered by their `FinalOrderOfNextRound` value (set from the manipulated signature): [8](#0-7) 

The `order` determines each miner's `ExpectedMiningTime`, giving earlier positions to miners with lower order numbers.

### Impact Explanation

**What Harm Occurs:**
- **VRF Security Breach**: The consensus mechanism relies on VRF (Verifiable Random Function) to ensure fair, unpredictable mining order. By allowing miners to choose arbitrary values instead of revealing their committed secrets, the system loses its verifiable randomness property.
- **Mining Order Manipulation**: Malicious miners can position themselves at order 1 (first position) in every round, mining at the earliest time slot.
- **Unfair Advantage**: Earlier mining positions provide multiple benefits:
  - Higher certainty of successful block production (less network risk)
  - Transaction ordering control and MEV opportunities
  - Consistent first-position rewards

**Who Is Affected:**
- Honest miners lose fair chances at early positions
- The entire consensus fairness guarantee is compromised
- Users expecting transaction ordering fairness

**Severity Justification:**
Medium severity because:
1. Breaks a critical consensus invariant (verifiable randomness)
2. Requires attacker to be an authorized miner (limited attack surface)
3. Does not directly steal funds but provides systemic advantage
4. Exploitable in every round with minimal cost

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an authorized miner in the current round
- Can compute hash operations off-chain
- No special cryptographic capabilities required

**Attack Complexity:**
- LOW: Miner computes `CalculateSignature(candidateValue)` for various `candidateValue` options off-chain
- Selects the value producing desired `FinalOrderOfNextRound` (e.g., order=1)
- Submits block with chosen invalid `PreviousInValue`

**Feasibility Conditions:**
- Entry point is the standard block production flow (UpdateValue behavior)
- No additional permissions needed beyond being an active miner
- Computationally trivial (just hash operations)
- Can be repeated every round

**Detection/Operational Constraints:**
- Difficult to detect: `PreviousInValue = Hash.Empty` is allowed by design for legitimate cases
- No penalty mechanism exists for this behavior (evil miner detection only checks missed time slots) [9](#0-8) 

- No logs or alerts for self-check failures beyond debug logging

**Probability:** HIGH for any motivated miner seeking consistent early positions.

### Recommendation

**Code-Level Mitigation:**

1. **Fix the signature calculation logic** - Move line 92 inside the else block (lines 88-90) so signature is only calculated from valid PreviousInValue:

```csharp
else
{
    previousInValue = triggerInformation.PreviousInValue;
    signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
}
```

For failed self-checks, either:
- Use a deterministic fallback (e.g., hash of pubkey) instead of allowing arbitrary values
- Assign default order rather than signature-derived order
- Mark the block as having reduced trust

2. **Add post-round verification** - After all blocks in a round are produced, verify that each miner's stored `Signature` equals `previousRound.CalculateSignature(PreviousInValue)` when `PreviousInValue != Hash.Empty`.

3. **Tighten validation** - In `UpdateValueValidationProvider`, distinguish between legitimately empty `PreviousInValue` (first round, new miner) versus suspicious cases (miner existed in previous round and produced blocks but now has Hash.Empty).

**Invariant Checks:**
- ASSERT: If miner existed in previous round with OutValue set, then either PreviousInValue hashes to OutValue OR miner's order is assigned by fallback mechanism (not from signature)
- ASSERT: Signature must be calculable from PreviousInValue when PreviousInValue is not Hash.Empty

**Test Cases:**
1. Test that miner providing invalid PreviousInValue gets assigned fallback order, not signature-derived order
2. Test that legitimate Hash.Empty cases (first round, new miner) still work correctly
3. Test that manipulated signatures are rejected or neutralized in order assignment

### Proof of Concept

**Required Initial State:**
- Blockchain with active AEDPoS consensus
- Attacker is an authorized miner in current round
- Previous round exists with attacker's OutValue committed

**Transaction Steps:**

1. **Off-chain preparation:**
   - Attacker computes their correct `PreviousInValue` that hashes to stored `OutValue`
   - Attacker generates 10 candidate fake values: `fake1, fake2, ..., fake10`
   - For each: computes `sig_i = previousRound.CalculateSignature(fake_i)`
   - For each: computes `order_i = (sig_i.ToInt64() % minersCount) + 1`
   - Selects `fake_best` that gives `order = 1` (first position)

2. **Block production:**
   - Attacker produces block during their time slot
   - Provides `fake_best` as `triggerInformation.PreviousInValue`
   - Self-check fails (line 81-82): `Hash(fake_best) != storedOutValue`
   - `previousInValue` set to `Hash.Empty` (line 85)
   - Signature calculated from `fake_best` (line 92)
   - `ApplyNormalConsensusData` stores this signature
   - Validation passes (Hash.Empty allowed at line 46 of UpdateValueValidationProvider)

3. **Next round generation:**
   - When next round is generated, attacker's `FinalOrderOfNextRound = 1`
   - Attacker assigned `order = 1` and earliest `ExpectedMiningTime`

**Expected vs Actual Result:**
- **Expected:** Attacker's order determined by their committed InValue, unpredictable
- **Actual:** Attacker chooses order=1 by selecting appropriate fake value

**Success Condition:**
Attacker consistently achieves order=1 position in subsequent rounds by repeating this attack, demonstrating broken VRF randomness and mining order manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L80-86)
```csharp
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L13-13)
```csharp
        RealTimeMinersInformation[pubkey].Signature = signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-182)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
```
