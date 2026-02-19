### Title
Continuous Block Limit Bypass via Pubkey Replacement Attack

### Summary
A malicious miner can bypass the continuous block production limit (MaximumTinyBlocksCount) by repeatedly replacing their public key via the Election contract's `ReplaceCandidatePubkey` method. The `LatestPubkeyToTinyBlocksCount` mechanism tracks blocks by the signing pubkey rather than the miner's original identity, causing the counter to reset when a new pubkey is used. This allows unlimited consecutive block production, breaking a fundamental consensus security mechanism designed to prevent mining monopolization.

### Finding Description

The vulnerability exists in the interaction between three components:

**1. Continuous Block Counter Mechanism:**
The `ResetLatestProviderToTinyBlocksCount` function decrements a counter when the same pubkey produces consecutive blocks, but resets the counter when a different pubkey is detected. [1](#0-0) 

The counter comparison uses `_processingBlockMinerPubkey`, which is set to the actual signing pubkey recovered from the block signature. [2](#0-1) 

**2. Pubkey Replacement Without Restrictions:**
The `ReplaceCandidatePubkey` function in the Election contract allows a candidate admin to replace any candidate's pubkey with only basic checks (candidate status, banned status, admin permission). Critically, there is NO rate limiting, cooldown period, or restriction preventing replacement during active mining. [3](#0-2) 

The old pubkey is banned after replacement, preventing reuse, but the attacker can simply generate unlimited new keypairs at no cost. [4](#0-3) 

**3. Immediate Round Information Update:**
When a pubkey is replaced, the consensus contract's `RecordCandidateReplacement` immediately updates the current round's miner information if the candidate is an active miner, replacing the old pubkey with the new one. [5](#0-4) 

**4. Validation Does Not Prevent Attack:**
The `ValidateConsensusAfterExecution` function validates miner replacements by checking that new miners match the results from `GetNewestPubkey`, but this only ensures the replacement is officially recorded—it does not prevent the continuous block counter reset. [6](#0-5) 

**Root Cause:**
The `LatestPubkeyToTinyBlocksCount` state tracks blocks by the literal signing pubkey rather than tracking by the miner's canonical/original identity. There is no mapping from replacement pubkeys back to the original miner identity for continuous block limit enforcement purposes.

### Impact Explanation

**Consensus Integrity Breach:**
- The continuous block limit exists specifically to prevent a single miner from monopolizing block production and creating excessive forks (as documented in GitHub PR #1952). [7](#0-6) 

- An attacker can produce unlimited consecutive blocks by replacing their pubkey every 8 blocks, completely circumventing this protection.

**Operational Impact:**
- Monopolization of block production prevents other miners from participating in consensus
- Excessive forking makes chain convergence difficult
- Can delay the Last Irreversible Block (LIB) height progression
- In severe cases, triggers abnormal/severe blockchain status, further degrading network performance [8](#0-7) 

**Affected Parties:**
- All network participants (honest miners excluded from consensus, users experiencing degraded chain performance)
- Chain security and decentralization fundamentally compromised

**Severity Justification:**
HIGH - This vulnerability breaks a core consensus security invariant designed to maintain fair miner participation and prevent mining centralization. The attack is trivial to execute with no economic cost.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an elected miner (requires votes, but this is the baseline requirement for any miner attack)
- Must have candidate admin permission for their pubkey (standard in miner operations)
- Can generate unlimited fresh keypairs at negligible computational cost

**Attack Complexity:**
- Very Low - Single transaction call to `ReplaceCandidatePubkey` per reset
- No complex timing or coordination required
- No need to compromise other roles or contracts

**Feasibility Conditions:**
- Works during any round/term (no waiting period required) [9](#0-8) 
- No rate limiting or cooldown to circumvent
- Old pubkeys banned but attacker doesn't need to reuse them

**Detection Constraints:**
- Repeated pubkey replacements by the same candidate admin would be visible on-chain
- However, by the time excessive blocks are detected, damage is already done
- No automated prevention mechanism exists

**Economic Rationality:**
- Zero direct cost (only gas fees for replacement transaction)
- High reward (monopolize block rewards, potential chain manipulation)
- Risk/reward heavily favors attack execution

**Probability:**
HIGH - All preconditions are easily met, attack is trivial to execute, and provides significant advantage to a malicious miner.

### Recommendation

**Short-term Mitigation:**
Modify `ResetLatestProviderToTinyBlocksCount` to track continuous blocks by the miner's canonical identity (initial pubkey) rather than the current signing pubkey:

```plaintext
In AEDPoSContract_ProcessConsensusInformation.cs, line 337-365:
1. Before checking currentValue.Pubkey == _processingBlockMinerPubkey
2. Resolve both pubkeys to their initial pubkeys using GetNewestPubkey mapping
3. Compare initial pubkeys instead of current pubkeys
4. This ensures the counter persists across pubkey replacements
```

**Additional Protections:**
Add rate limiting to `ReplaceCandidatePubkey`:
```plaintext
In ElectionContract_Maintainence.cs, after line 181:
1. Add state mapping: State.LastReplacementTimestamp[pubkey] = Timestamp
2. Check: Assert(Context.CurrentBlockTime >= State.LastReplacementTimestamp[input.OldPubkey].AddMinutes(1440), "Cooldown period not elapsed")
3. Set minimum 24-hour cooldown between replacements
```

**Invariant Checks:**
- Assert that continuous block counting considers miner canonical identity, not current pubkey
- Add monitoring for frequent pubkey replacements by same candidate admin
- Test case: Verify that replacing pubkey during consecutive block production does NOT reset the counter

**Test Cases:**
1. Test miner produces 8 blocks with PubkeyA, replaces to PubkeyB, attempts 9th block → Should be rejected
2. Test multiple rapid replacements → Should be prevented by cooldown
3. Test `GetNewestPubkey` resolution in continuous block counter logic → Should track original identity

### Proof of Concept

**Initial State:**
- Attacker is elected miner with PubkeyA in current round
- `State.LatestPubkeyToTinyBlocksCount.Value = { Pubkey: "PubkeyA", BlocksCount: 0 }`
- MaximumTinyBlocksCount = 8

**Attack Sequence:**

**Step 1:** Miner produces 8 consecutive blocks with PubkeyA
- After 8th block: `LatestPubkeyToTinyBlocksCount.BlocksCount = -1`
- Validation check at line 19 of ContinuousBlocksValidationProvider would reject 9th block [10](#0-9) 

**Step 2:** Attacker calls `Election.ReplaceCandidatePubkey({ OldPubkey: "PubkeyA", NewPubkey: "PubkeyB" })`
- Permission check passes (attacker is candidate admin)
- `RecordCandidateReplacement` updates current round to replace PubkeyA with PubkeyB
- `State.LatestPubkeyToTinyBlocksCount` still contains `{ Pubkey: "PubkeyA", BlocksCount: -1 }`

**Step 3:** Attacker produces block #9 signed with PubkeyB
- `_processingBlockMinerPubkey = "PubkeyB"` (recovered from signature)
- In `ResetLatestProviderToTinyBlocksCount`:
  - `currentValue.Pubkey ("PubkeyA") != _processingBlockMinerPubkey ("PubkeyB")` → TRUE
  - Counter RESETS: `BlocksCount = minersCountInTheory.Sub(1) = 7` [11](#0-10) 

**Step 4:** Attacker produces another 8 consecutive blocks with PubkeyB
- Counter decrements from 7 to -1 again

**Step 5:** Repeat with PubkeyC, PubkeyD, etc.
- Unlimited consecutive blocks achieved

**Expected Result:** Miner should be limited to 8 consecutive blocks total, forced to yield to other miners

**Actual Result:** Miner can produce unlimited consecutive blocks by replacing pubkey every 8 blocks

**Success Condition:** Attacker successfully produces >16 consecutive blocks (double the intended limit), demonstrating complete bypass of the continuous block protection mechanism.

---

**Notes:**

The vulnerability confirmation required tracing the complete interaction between Election contract's pubkey replacement mechanism and Consensus contract's continuous block tracking. The key insight is that `LatestPubkeyToTinyBlocksCount` uses literal pubkey comparison without resolving to canonical miner identity, creating a trivial reset vector. The absence of any rate limiting on `ReplaceCandidatePubkey` makes this attack both practical and cost-free for any elected miner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L321-321)
```csharp
        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L246-246)
```csharp
        State.BannedPubkeyMap[input.OldPubkey] = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L136-146)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L116-123)
```csharp
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L17-19)
```csharp
    /// <summary>
    ///     Implemented GitHub PR #1952.
    ///     Adjust (mainly reduce) the count of tiny blocks produced by a miner each time to avoid too many forks.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }

        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L17-23)
```csharp
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
```
