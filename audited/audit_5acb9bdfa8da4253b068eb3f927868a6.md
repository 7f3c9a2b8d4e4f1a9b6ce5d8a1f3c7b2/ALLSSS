### Title
Extra Block Producer Selection Manipulation via Predictable Signature and Strategic Time Slot Skipping

### Summary
The first miner in each round can predict their own signature and potentially other miners' signatures due to deterministic signature calculation from publicly revealed `previousInValue` data. By selectively skipping their time slot when unfavorable, they can manipulate which miner's signature is used in `CalculateNextExtraBlockProducerOrder()`, thereby influencing who becomes the extra block producer and receives additional mining rewards in the next round.

### Finding Description

The vulnerability exists in the extra block producer selection mechanism: [1](#0-0) 

The `CalculateNextExtraBlockProducerOrder()` function uses the signature of the first miner (by order) who produced a block in the current round. This signature is converted to an integer and used with modulus arithmetic to determine the next extra block producer.

**Root Cause:** Signatures are deterministically calculated from `previousInValue` and the previous round's signatures: [2](#0-1) [3](#0-2) 

The `CalculateSignature` method XORs the `previousInValue` with all miners' signatures from the previous round. Since previous round signatures are publicly available on-chain and `previousInValue` fields are revealed through secret sharing: [4](#0-3) 

These revealed values are stored in the current round and publicly readable: [5](#0-4) 

**Why Protections Fail:**

1. Time slot validation allows miners to skip slots with minimal penalty (1 missed slot, threshold is 4320): [6](#0-5) 

2. The selection uses `OrderBy(m => m.Order)` so if the first miner skips, the second miner's signature is used instead, which can be predicted if their `previousInValue` was revealed.

3. `PreviousInValue` can be revealed either through secret sharing or direct publication: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
- Extra block producers earn additional mining rewards by producing an extra block per round: [8](#0-7) 

- Higher `ProducedBlocks` counts result in larger shares of mining rewards distributed through the Treasury contract
- Manipulation allows the first miner to influence whether they, their allies, or competitors become extra block producers

**Affected Parties:**
- Honest miners who should fairly receive extra block producer opportunities
- Overall consensus fairness and unpredictability
- Economic balance of mining reward distribution

**Severity:** High - While not direct theft, this enables systematic reward misallocation and undermines consensus randomness, violating the critical invariant of "miner schedule integrity" and "reward distribution accuracy."

### Likelihood Explanation

**Attacker Capabilities:**
- Any miner with order 1 in a round can execute this attack
- Requires ability to read blockchain state (public `GetCurrentRoundInformation`)
- Requires ability to compute hashes and perform basic arithmetic
- No special privileges needed beyond being a miner

**Attack Complexity:**
- Low - Simply requires:
  1. Reading current round and previous round data from state
  2. Computing potential signature outcomes for self and next miner(s)
  3. Choosing not to mine if outcome is unfavorable
  
**Feasibility Conditions:**
- Secret sharing must successfully reveal at least one other miner's `previousInValue` (requires 2/3 miners to properly share encrypted pieces): [9](#0-8) 

- OR miners directly publish their `previousInValue` in `UpdateValue` transactions
- These conditions are met in normal consensus operation

**Economic Rationality:**
- Cost: 1 missed time slot penalty (insignificant compared to 4320 threshold)
- Benefit: Directing extra block producer status and associated rewards
- If exploited across multiple rounds or coordinated among colluding miners, cumulative benefit significantly exceeds minimal cost

**Probability:** High - The attack is practical in production environments where secret sharing is enabled and functioning normally.

### Recommendation

**Immediate Mitigations:**

1. **Add commitment-reveal scheme for randomness source:**
   - Instead of using signatures directly, require miners to commit to a random value in round N that gets revealed in round N+1
   - Use revealed values from round N+1 to determine extra block producer for round N+2
   - This prevents miners from knowing the outcome before committing

2. **Use VRF-based selection:**
   - Replace deterministic signature-based selection with verifiable random function (VRF)
   - VRF output cannot be predicted until after the block is produced
   - Existing VRF infrastructure is already used for random number generation: [10](#0-9) 

3. **Combine multiple miners' signatures:**
   - Instead of using only the first miner's signature, XOR or hash all miners' signatures from the current round
   - This prevents any single miner from manipulating the outcome through selective participation
   
4. **Increase skip penalty or add detection:**
   - Implement pattern detection for suspicious skipping behavior
   - Increase missed slot penalties for early-round miners
   - Add slashing conditions for detected manipulation

**Code-Level Fix Example:**
In `CalculateNextExtraBlockProducerOrder()`, aggregate all signatures instead of using just the first:

```csharp
private int CalculateNextExtraBlockProducerOrder()
{
    var allSignatures = RealTimeMinersInformation.Values
        .Where(m => m.Signature != null)
        .OrderBy(m => m.Order)
        .Select(m => m.Signature)
        .ToList();
        
    if (allSignatures.Count == 0) return 1;
    
    var combinedSignature = allSignatures.Aggregate(Hash.Empty, 
        (current, sig) => HashHelper.XorAndCompute(current, sig));
    var sigNum = combinedSignature.ToInt64();
    var blockProducerCount = RealTimeMinersInformation.Count;
    return GetAbsModulus(sigNum, blockProducerCount) + 1;
}
```

**Test Cases:**
- Verify that skipping time slot changes which signature is used
- Verify that first miner cannot predict final extra block producer when using aggregated randomness
- Test that colluding miners cannot coordinate to manipulate selection

### Proof of Concept

**Required Initial State:**
- Round N-1 completed with all miners having produced blocks
- Round N started with secret sharing enabled
- Miner A has order 1 in Round N
- `previousInValue` for Miner A and Miner B revealed through secret sharing

**Attack Steps:**

1. **Miner A reads state before their time slot:**
   - Call `GetCurrentRoundInformation()` to get Round N data
   - Call `GetPreviousRoundInformation()` to get Round N-1 signatures
   - Extract `previousInValue` for self and Miner B from Round N
   - Extract all signatures from Round N-1

2. **Miner A calculates potential outcomes:**
   ```
   my_signature = Round_N-1.CalculateSignature(my_previousInValue)
   my_outcome = (my_signature.ToInt64() % miner_count) + 1
   
   miner_b_signature = Round_N-1.CalculateSignature(miner_b_previousInValue)  
   miner_b_outcome = (miner_b_signature.ToInt64() % miner_count) + 1
   ```

3. **Miner A decides whether to mine:**
   - If `my_outcome` favors Miner A or allies: Mine normally
   - If `miner_b_outcome` is more favorable: Skip time slot
   - Miner B mines instead, their signature is used

4. **At end of Round N:**
   - `CalculateNextExtraBlockProducerOrder()` uses whichever miner's signature was chosen
   - Extra block producer for Round N+1 is determined accordingly

**Expected vs Actual:**
- **Expected:** Extra block producer selection should be unpredictable at time of mining decision
- **Actual:** First miner can predict and manipulate selection through strategic skipping

**Success Condition:** 
Demonstrate that across 100 rounds, a miner with order 1 who always checks and conditionally skips achieves statistically higher extra block producer assignments for themselves or specific allies compared to random distribution.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L191-194)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L13-54)
```csharp
    private void RevealSharedInValues(Round currentRound, string publicKey)
    {
        Context.LogDebug(() => "About to reveal shared in values.");

        if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L21-24)
```csharp
    public override Round GetCurrentRoundInformation(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var currentRound) ? currentRound : new Round();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L76-80)
```csharp
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L263-264)
```csharp
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```
