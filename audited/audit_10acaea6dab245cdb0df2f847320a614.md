### Title
Predictable Miner Ordering in First Round of New Term Due to Empty InValue Chain

### Summary
The `GenerateFirstRoundOfNewTerm()` function sets `PreviousInValue = Hash.Empty` for all miners and prevents InValue generation by setting `IsMinerListJustChanged = true`. This causes all miners to produce blocks with identical InValue (Hash.Empty), resulting in identical OutValue and Signature values. Since next-round miner ordering is determined by signature-based modulo calculation, the block production order for round 2 becomes completely predictable and manipulable.

### Finding Description

**Root Cause:**

In `GenerateFirstRoundOfNewTerm()`, all miners have their `PreviousInValue` set to `Hash.Empty` and the round is marked with `IsMinerListJustChanged = true`: [1](#0-0) [2](#0-1) 

This flag prevents the `SecretSharingInformation` event from firing, which would normally trigger InValue generation: [3](#0-2) 

**Broken InValue Chain:**

When miners request consensus commands, the `InValueCache.GetInValue()` returns `Hash.Empty` because no InValue was cached: [4](#0-3) 

During block production, the system computes OutValue and Signature from the empty InValue: [5](#0-4) 

For the first round of the current term, the conditional block that normally differentiates signatures is skipped: [6](#0-5) 

**Predictable Ordering:**

The signature is used to calculate `SupposedOrderOfNextRound` via modulo operation: [7](#0-6) 

Since all miners have identical signatures (derived from Hash.Empty), they all calculate the same order. The next round generation uses `FinalOrderOfNextRound` to determine mining sequence: [8](#0-7) 

The extra block producer selection also relies on signature: [9](#0-8) 

### Impact Explanation

**Consensus Integrity Breach:**
- All miners in round 1 of any new term produce identical OutValue and Signature values
- The deterministic conflict resolution creates a predictable mining order for round 2
- Miners can calculate the exact block production sequence before it occurs

**Manipulation Opportunities:**
- Colluding miners can coordinate to selectively skip blocks, manipulating which miner gets specific orders
- The extra block producer for round 2 is predictable, allowing targeted attacks on that position
- Miners can optimize their participation strategy based on known future ordering

**Affected Parties:**
- All network participants relying on consensus randomness
- Honest miners disadvantaged by information asymmetry
- Applications depending on unpredictable block producer selection

**Severity Justification:**
This is Critical because it breaks a fundamental consensus property—unpredictable and unmanipulable miner ordering. The vulnerability occurs systematically at every term change, affecting core blockchain security guarantees.

### Likelihood Explanation

**Attacker Capabilities:**
- Any miner in the network can exploit this (no special privileges required)
- Requires basic ability to observe on-chain state and calculate hash operations
- Multiple miners can coordinate off-chain to maximize manipulation impact

**Attack Complexity:**
- LOW: The vulnerability is inherent in the design, no complex exploit needed
- Miners simply need to compute: `GetAbsModulus(HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Hash.Empty), Hash.Empty).ToInt64(), minersCount) + 1`
- All information needed is publicly available on-chain

**Feasibility Conditions:**
- Occurs automatically at every new term initialization
- No special blockchain state required
- No economic cost to observe and predict the ordering

**Probability:**
- CERTAIN: Happens at every term change when miner list is updated
- The condition `IsMinerListJustChanged = true` is set by design in `GenerateFirstRoundOfNewTerm()`
- No randomness source can compensate since VRF verification operates independently from miner ordering calculation

### Recommendation

**Immediate Fix:**

1. **Generate proper InValues for new term's first round:**
   - Before or immediately after calling `GenerateFirstRoundOfNewTerm()`, trigger InValue generation for all miners
   - Use a deterministic-but-unpredictable seed (e.g., hash of previous term's final signatures combined with new term number)
   - Cache these InValues so miners can use them during block production

2. **Add validation check:**
   In `GetConsensusExtraDataToPublishOutValue()`, add assertion:
   ```csharp
   if (IsFirstRoundOfCurrentTerm(out _))
   {
       Assert(triggerInformation.InValue != null && triggerInformation.InValue != Hash.Empty, 
              "InValue must not be empty in first round of new term");
   }
   ```

3. **Alternative signature calculation for first round:**
   When `IsFirstRoundOfCurrentTerm()` is true, incorporate miner's public key into signature calculation:
   ```csharp
   signature = HashHelper.ConcatAndCompute(
       HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue),
       HashHelper.ComputeFrom(pubkey)
   );
   ```

**Test Cases:**
- Verify all miners in first round of new term have unique, non-empty InValues
- Verify signatures differ between miners in first round
- Verify round 2 order is unpredictable from round 1 public information
- Verify conflict resolution doesn't produce predictable patterns

### Proof of Concept

**Initial State:**
- Term N is ending, term N+1 is about to begin with new miner list
- Miners: [M1, M2, M3, M4, M5]

**Exploitation Steps:**

1. **Term transition occurs:**
   - `NextTerm` is called, triggering `GenerateFirstRoundOfNewTerm()`
   - All miners get `PreviousInValue = Hash.Empty`
   - `IsMinerListJustChanged = true` prevents InValue generation

2. **Round 1 block production:**
   - Each miner M1-M5 produces their block with:
     - InValue = Hash.Empty (from cache miss)
     - OutValue = HashHelper.ComputeFrom(Hash.Empty) = `0x<fixed_hash>`
     - Signature = HashHelper.ConcatAndCompute(OutValue, Hash.Empty) = `0x<same_fixed_hash>`

3. **Order calculation for Round 2:**
   - All miners calculate: `SupposedOrderOfNextRound = GetAbsModulus(signature.ToInt64(), 5) + 1`
   - All get the same value (e.g., order = 3)
   - Conflict resolution assigns orders deterministically: M1→3, M2→4, M3→5, M4→1, M5→2

4. **Attacker prediction before Round 1 ends:**
   - By observing that all signatures are identical (visible on-chain)
   - Calculate the deterministic conflict resolution outcome
   - Know exact mining order for Round 2 before Round 2 begins

**Expected vs Actual:**
- **Expected:** Each miner has unique, unpredictable signature → random order in next round
- **Actual:** All miners have identical signature → deterministic, predictable order in next round

**Success Condition:**
An observer can predict the exact mining order for round 2 with 100% certainty before round 2 begins, by computing the hash of Hash.Empty and applying the modulo + conflict resolution logic.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L35-35)
```csharp
            minerInRound.PreviousInValue = Hash.Empty;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IInValueCache.cs (L31-32)
```csharp
        _inValues.TryGetValue(roundId, out var inValue);
        return inValue ?? Hash.Empty;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L65-70)
```csharp
        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L72-72)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-28)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L118-122)
```csharp
        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
```
