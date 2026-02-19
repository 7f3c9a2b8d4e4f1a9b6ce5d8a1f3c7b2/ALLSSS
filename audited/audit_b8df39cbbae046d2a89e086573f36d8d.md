### Title
Non-Deterministic Miner Selection When Candidates Have Identical Vote Amounts

### Summary
The `GetVictories()` method sorts candidates by `ObtainedActiveVotedVotesAmount` without a secondary tiebreaker, relying on LINQ's `OrderByDescending` stability for deterministic ordering when candidates have equal votes. This creates a theoretical risk of non-deterministic miner selection across nodes if different .NET runtime implementations process the sort differently, potentially causing consensus failure.

### Finding Description

The vulnerability exists in the `GetVictories()` private method in the Election contract: [1](#0-0) 

The code orders candidates by vote amount alone and takes the top `State.MinersCount.Value` candidates:

The input to this sort comes from `GetValidCandidates()` which iterates through the on-chain candidate list: [2](#0-1) 

Candidates are added to `State.Candidates.Value.Value` in announcement order: [3](#0-2) 

**Root Cause:** The code relies on LINQ `OrderByDescending` being a stable sort (preserving input order for equal keys) without explicitly specifying a secondary sort criterion (e.g., by pubkey). While .NET documents `OrderBy` as stable, this is an implementation detail rather than a language-level guarantee.

**Why This Matters:** This result is consumed by the consensus contract to determine the miner list for each term: [4](#0-3) 

**Evidence of Concern:** The codebase shows awareness that explicit ordering matters for consensus. When computing a miner list hash, the code explicitly sorts by pubkey: [5](#0-4) 

This explicit sorting demonstrates that developers recognize deterministic pubkey ordering is critical for consensus, yet `GetVictories()` lacks this safeguard.

### Impact Explanation

**Consensus Integrity Impact:** If different nodes produce different miner lists when candidates have identical vote amounts, the network would fork as nodes disagree on who should produce blocks. This would halt the blockchain entirely.

**Affected Parties:**
- All network participants (block production stops)
- Token holders (network becomes unusable)
- Validators (conflicting views of valid chain)

**Severity Justification:** Consensus failure is the most critical failure mode in any blockchain system. Even a theoretical possibility of non-determinism in miner selection is unacceptable because:
1. Recovery requires manual intervention and network-wide coordination
2. Results in complete network halt until resolved
3. Could occur during a .NET runtime upgrade across node operators
4. The uncertainty itself undermines confidence in the protocol

### Likelihood Explanation

**Preconditions Required:**
1. Multiple candidates must have exactly equal `ObtainedActiveVotedVotesAmount`
2. The number of tied candidates must exceed available miner slots (for the tie to matter)
3. Different nodes must process the LINQ sort differently (requires different .NET runtimes/versions or future implementation changes)

**Probability Assessment:**
- **Vote amount ties:** MODERATE - Vote weights are calculated with factors, making exact ties less common but still possible, especially in early election rounds or with coordinated voting
- **Different runtime behavior:** LOW - Currently all nodes likely use the same .NET runtime version
- **Future risk:** MODERATE - Network upgrades, heterogeneous node implementations, or .NET runtime changes could introduce behavioral differences

**Attack Complexity:** None required - this is an accidental non-determinism risk rather than an exploitable attack. However, the impact is catastrophic if conditions align.

**Detection:** Would manifest as nodes disagreeing on the current miner list, causing consensus to halt. Would be immediately visible but difficult to debug without recognizing the root cause.

### Recommendation

Add an explicit secondary sort by pubkey (in hex string form) to ensure deterministic ordering when vote amounts are equal:

```csharp
victories = validCandidates.Select(k => State.CandidateVotes[k])
    .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount)
    .ThenBy(v => v.Pubkey.ToHex())  // Add explicit tiebreaker
    .Select(v => v.Pubkey)
    .Take(State.MinersCount.Value)
    .ToList();
```

**Additional Recommendations:**
1. Apply the same fix to line 475 in ElectionContract_Elector.cs where `OrderBy(x => x.Value)` is used without a secondary sort
2. Apply to line 693 in ElectionContract_Elector.cs where `OrderByDescending` is used for candidate selection
3. Add test cases that explicitly create candidates with identical vote amounts and verify deterministic ordering
4. Document the requirement for explicit tie-breaking in all consensus-critical sorting operations

**Test Case to Add:**
```csharp
// Create N+1 candidates with identical vote amounts where N = MinersCount
// Verify GetVictories() returns the same N candidates every time
// Verify the selection is lexicographically first N by pubkey
```

### Proof of Concept

**Initial State:**
1. Configure `State.MinersCount.Value = 5`
2. Announce election for 6 candidates (A, B, C, D, E, F) in that order
3. Each candidate receives exactly 100 votes (same `ObtainedActiveVotedVotesAmount`)

**Execution:**
1. Call `GetVictories()` from consensus contract during term transition
2. Method orders all 6 candidates by vote amount (all = 100)
3. Takes top 5 using `Take(5)`

**Expected Result (with stable sort):**
Candidates A, B, C, D, E are selected (first 5 in announcement order)

**Actual Result:**
Currently works correctly due to LINQ stability, BUT:
- No test verifies this behavior with identical vote amounts
- No explicit guarantee across different .NET implementations
- The test at lines 405-444 in GQL/ElectionTests.cs gives all candidates identical amounts but doesn't verify selection order when there are more candidates than slots [6](#0-5) 

**Success Condition for Exploit:**
Network fork occurs when different nodes select different miners from the tied set, causing them to have conflicting views of the valid chain.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-81)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L86-95)
```csharp
    private List<string> GetValidCandidates()
    {
        if (State.Candidates.Value == null) return new List<string>();

        return State.Candidates.Value.Value
            .Where(c => State.CandidateVotes[c.ToHex()] != null &&
                        State.CandidateVotes[c.ToHex()].ObtainedActiveVotedVotesAmount > 0)
            .Select(p => p.ToHex())
            .ToList();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L174-174)
```csharp
        State.Candidates.Value.Value.Add(pubkeyByteString);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L356-360)
```csharp
    private static Hash GetMinerListHash(IEnumerable<string> minerList)
    {
        return HashHelper.ComputeFrom(
            minerList.OrderBy(p => p).Aggregate("", (current, publicKey) => current + publicKey));
    }
```

**File:** test/AElf.Contracts.Election.Tests/GQL/ElectionTests.cs (L416-426)
```csharp
        var validCandidates = ValidationDataCenterKeyPairs
            .Take(EconomicContractsTestConstants.InitialCoreDataCenterCount - 1).ToList();
        foreach (var keyPair in validCandidates)
            await VoteToCandidateAsync(VoterKeyPairs[0], keyPair.PublicKey.ToHex(), 100 * 86400, amount);

        foreach (var votedFullNodeKeyPair in ValidationDataCenterKeyPairs.Take(EconomicContractsTestConstants
                     .InitialCoreDataCenterCount - 1))
        {
            var votes = await ElectionContractStub.GetCandidateVote.CallAsync(new StringValue
                { Value = votedFullNodeKeyPair.PublicKey.ToHex() });
            votes.ObtainedActiveVotedVotesAmount.ShouldBe(amount);
```
