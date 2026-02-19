### Title
Hex String Case Sensitivity Bypass in Miner Replacement Logic Allows Consensus Manipulation

### Summary
The `GetMinerReplacementInformation` function uses case-sensitive string comparison to exclude current miners from replacement candidates, but the consensus contract accepts user-supplied `NextRoundInput` with arbitrary hex string casing in miner pubkeys. A malicious miner can submit uppercase pubkeys in a new round, causing the exclusion filter to fail and enabling duplicate miner selection or consensus denial-of-service.

### Finding Description

**Root Cause:** Lack of hex string case normalization before storage and comparison operations. [1](#0-0) 

The vulnerable code at line 390 filters initial miners using:
```csharp
.Where(k => !input.CurrentMinerList.Contains(k))
```

Where `k` is a lowercase hex string (from `.ToHex()` conversion), and `input.CurrentMinerList` contains pubkeys from `currentRound.RealTimeMinersInformation.Keys`. [2](#0-1) 

The `ToHex()` method always produces lowercase hex strings: [3](#0-2) 

**Attack Vector:** The `NextRoundInput` message directly converts to `Round` without case normalization: [4](#0-3) 

This round is stored directly via `ProcessNextRound`: [5](#0-4) 

**Why Protections Fail:** The `PreCheck()` authorization validates the sender against the *current* round (with lowercase keys), not the *incoming* round data: [6](#0-5) 

Since C# string comparison is case-sensitive, uppercase pubkeys in the new round won't match lowercase initial miner pubkeys during the `Contains()` check.

### Impact Explanation

**Primary Impact - Consensus Denial-of-Service:**
Once uppercase pubkeys are stored in a round, all subsequent miners are locked out because their recovered pubkeys (lowercase via `.ToHex()`) won't pass the `IsInMinerList()` authorization check: [7](#0-6) 

This completely halts block production and consensus progression.

**Secondary Impact - Incorrect Miner Replacement:**
Before the DOS occurs, if `GetMinerReplacementInformation` is called with uppercase current miner keys but lowercase initial miner candidates, the exclusion filter fails. Initial miners who are *actually* current miners won't be filtered out, leading to:
- Duplicate miners in the miner list
- Incorrect miner replacement selection
- Violation of consensus invariants

**Severity:** Critical - A single malicious miner can permanently DOS the consensus mechanism.

### Likelihood Explanation

**Attacker Requirements:**
- Must be an authorized current miner (can pass PreCheck)
- Must control mining software to craft malicious `NextRoundInput`
- Must wait for their mining time slot

**Attack Complexity:** Low - Requires only modifying the hex string casing in one transaction.

**Feasibility:** High - While miners are semi-trusted, the attack is trivial to execute and has devastating impact. The code should be resilient to case variations regardless of trust assumptions.

**Detection:** The attack would be immediately visible in logs (uppercase pubkeys) and would cause immediate consensus failure, but by then the damage is done.

**Economic Rationality:** While DOS'ing one's own chain seems irrational, this could be exploited by:
- Compromised miner keys
- Malicious miners in adversarial scenarios
- Accidental bugs in mining software
- Cross-chain attacks where economic incentives differ

### Recommendation

**1. Normalize hex strings before storage:**

Add case normalization in `NextRoundInput.ToRound()`:
```csharp
public Round ToRound()
{
    var round = new Round
    {
        RoundNumber = RoundNumber,
        // ... other fields
    };
    
    // Normalize all pubkey keys to lowercase
    foreach (var kvp in RealTimeMinersInformation)
    {
        var normalizedKey = kvp.Key.ToLower();
        round.RealTimeMinersInformation[normalizedKey] = kvp.Value;
        round.RealTimeMinersInformation[normalizedKey].Pubkey = normalizedKey;
    }
    
    return round;
}
```

**2. Add case-insensitive comparison:**

Alternatively, use `StringComparer.OrdinalIgnoreCase` for all pubkey comparisons:
```csharp
.Where(k => !input.CurrentMinerList.Contains(k, StringComparer.OrdinalIgnoreCase))
```

**3. Add validation in ProcessNextRound:**

Verify all pubkeys in incoming rounds match the expected format (lowercase hex) before storage.

**4. Add regression tests:**

Test cases should verify:
- NextRoundInput with uppercase pubkeys is rejected or normalized
- GetMinerReplacementInformation handles mixed-case inputs correctly
- IsInMinerList performs case-insensitive lookups

### Proof of Concept

**Initial State:**
- Consensus running normally with lowercase pubkeys in rounds
- Attacker is an authorized miner with pubkey "abc123..." (lowercase)

**Attack Steps:**

1. Attacker waits for their mining time slot
2. Attacker crafts `NextRoundInput` with uppercase pubkeys:
   ```
   NextRoundInput {
     RealTimeMinersInformation: {
       "ABC123...": MinerInRound {...},
       "DEF456...": MinerInRound {...},
       // All keys in uppercase
     }
   }
   ```

3. Attacker submits via `NextRound()` transaction
4. `PreCheck()` passes because it validates against current round (lowercase keys)
5. `ProcessNextRound()` stores the new round with uppercase keys

**Expected Result:**
- New round stored with normalized lowercase keys
- Consensus continues normally
- Miner replacement logic works correctly

**Actual Result:**
- New round stored with uppercase keys
- Next miner's transaction fails PreCheck (lowercase "abc123..." ∉ uppercase keys)
- Consensus halts - no blocks can be produced
- If `GetMinerReplacementInformation` runs first: initial miners not filtered, causing duplicates

**Success Condition:**
Consensus stops producing blocks after the malicious round is committed.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L387-391)
```csharp
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** src/AElf.Types/Extensions/ByteStringExtensions.cs (L24-28)
```csharp
                b = (byte)(bytes[bx] >> 4);
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = (byte)(bytes[bx] & 0x0F);
                c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```
