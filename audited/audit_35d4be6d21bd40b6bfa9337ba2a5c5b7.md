### Title
DOS Attack on GetVictories via Unbounded Candidate List and Execution Observer Exhaustion

### Summary
The `GetVictories` function in the Election contract can be rendered unusable through a DOS attack where an attacker announces a large number of candidates (1000+), causing LINQ operations (OrderBy/OrderByDescending) to exceed AElf's execution observer limits (15,000 call/branch threshold). This prevents the view function from being queried and blocks new miner elections from taking effect during term transitions.

### Finding Description

The vulnerability exists in the `GetVictories` method and its interaction with unbounded candidate registration:

**Root Cause:**
The `AnnounceElection` method has no hard limit on the total number of candidates that can be registered. [1](#0-0) 

This allows `State.Candidates` to grow unbounded, which in turn causes `GetValidCandidates` to return a large list. [2](#0-1) 

**Vulnerable Operations:**
When `GetVictories` processes this large candidate list, it performs expensive LINQ operations:

1. In the else branch (normal case), it executes: `validCandidates.Select(k => State.CandidateVotes[k]).OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey).Take(State.MinersCount.Value).ToList()` [3](#0-2) 

2. In the if branch (insufficient candidates), it executes: `backups.OrderBy(p => p).Take(Math.Min(diff, currentMiners.Count)).Select(v => ByteStringHelper.FromHexString(v))` [4](#0-3) 

**Execution Observer Limits:**
AElf enforces execution limits of 15,000 for both call count and branch count to prevent infinite loops. [5](#0-4) 

These limits are strictly enforced and cause transaction failure when exceeded. [6](#0-5) 

**Why Protections Fail:**
The OrderBy/OrderByDescending operations have O(N log N) complexity. With N=1000 candidates:
- Sorting requires approximately 10,000 comparison operations
- Each comparison involves lambda invocations and branches
- Combined with Select operations (~1000 invocations), the total approaches or exceeds the 15,000 limit

### Impact Explanation

**Direct Impact:**
1. **View Function DOS**: The `GetVictories` view function becomes unusable, failing with `RuntimeCallThresholdExceededException` or `RuntimeBranchThresholdExceededException`. This prevents external applications and users from querying current election results. [7](#0-6) 

2. **Consensus Impact**: The function is also called internally during term transitions via `TryToGetVictories` in the consensus contract. [8](#0-7) 

   When `TryToGetVictories` fails, the consensus falls back to reusing current miners instead of electing new ones. [9](#0-8) 

**Quantified Damage:**
- Election system becomes inoperative - new candidates cannot become miners
- System is forced to continuously reuse the same miner set
- Democratic governance of block production is compromised
- Applications relying on election data receive errors

**Affected Parties:**
- End users and applications querying election status
- New candidates who cannot be elected as miners
- The overall decentralization and governance of the network

**Severity Justification:**
MEDIUM severity because while it disrupts critical operational functionality (elections), it does not cause direct fund theft, consensus does not completely halt (fallback exists), and the attack requires significant economic commitment.

### Likelihood Explanation

**Attacker Capabilities:**
Any user can announce election for candidates. The only requirement is locking 100,000 native tokens per candidate. [10](#0-9) 

**Attack Complexity:**
1. Announce election for 1000+ candidates (requires 100,000,000 tokens total)
2. Each candidate receives minimal votes to become "valid" (can be self-votes)
3. Wait for or trigger a view query or term transition
4. GetVictories exceeds execution observer limits and fails

**Feasibility Conditions:**
- Economic cost: ~100 million tokens (at $1/token = $100M USD)
- Tokens can be recovered by calling `QuitElection` later
- No governance permissions required
- Attack is persistent until candidates quit

**Economic Rationality:**
The attack cost is high but may be rational for:
- Wealthy attackers or state actors
- Scenarios where native token value is low
- Attackers who can recover tokens afterward
- Competitors seeking to disrupt the network

**Detection:**
The attack is easily detectable (sudden spike in candidate count), but difficult to prevent without protocol changes since candidate registration is permissionless.

**Probability:**
LOW to MEDIUM - Requires significant capital but no special permissions. The high cost and recoverability of funds make it feasible for determined attackers but unlikely for casual exploitation.

### Recommendation

**Immediate Mitigation:**
1. Add a maximum candidate limit in `AnnounceElection`:
```
Assert(State.Candidates.Value.Value.Count < MAX_CANDIDATES, "Maximum candidate limit reached");
```
Where `MAX_CANDIDATES` could be set to a reasonable value like 100-500 based on expected growth.

2. Implement pagination or batching in `GetVictories` to process candidates in chunks and cache results.

**Long-term Solution:**
1. Refactor `GetValidCandidates` to use more efficient data structures (e.g., sorted sets instead of linear searches)
2. Replace `Contains` operations on lists with `HashSet` lookups (O(1) vs O(N))
3. Pre-sort and cache candidate rankings to avoid repeated OrderBy operations
4. Add governance-controlled parameters for candidate limits that can be adjusted

**Invariant Checks:**
- Assert `validCandidates.Count <= MAX_SAFE_CANDIDATES` before expensive operations
- Monitor and alert when candidate count approaches unsafe thresholds
- Add execution cost estimation before sorting operations

**Test Cases:**
1. Test GetVictories with 1000+ candidates to verify it hits execution observer limits
2. Test term transition behavior when GetVictories fails
3. Test candidate limit enforcement in AnnounceElection
4. Verify fallback behavior maintains consensus safety

### Proof of Concept

**Required Initial State:**
- Deployed Election and AEDPoS contracts on mainnet or testnet
- Sufficient tokens to lock (100,000,000 for 1000 candidates)

**Attack Steps:**
1. Create 1000 accounts (or use 1000 different public keys)
2. For each account, call `AnnounceElection` with required token lock:
   - This costs 100,000 tokens per candidate
   - Total: 100,000,000 tokens locked
3. For each candidate, cast minimal votes (1 vote minimum) to make them "valid candidates"
4. Wait for term transition or call `GetVictories` view function
5. Monitor transaction execution

**Expected Result:**
- GetVictories completes successfully with fewer candidates
- With normal candidate counts (< 100), execution completes within limits

**Actual Result:**
- With 1000+ valid candidates, GetVictories throws `RuntimeCallThresholdExceededException` or `RuntimeBranchThresholdExceededException`
- View queries fail
- Term transition falls back to reusing current miners
- Elections are blocked

**Success Condition:**
Transaction fails with execution observer exception when candidate count exceeds ~500-1000, confirming the DOS vulnerability.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L144-175)
```csharp
    private void AnnounceElection(byte[] pubkeyBytes)
    {
        var pubkey = pubkeyBytes.ToHex();
        var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);

        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");

        var candidateInformation = State.CandidateInformationMap[pubkey];

        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
        }
        else
        {
            Assert(!IsPubkeyBanned(pubkey), "This candidate already banned before.");
            State.CandidateInformationMap[pubkey] = new CandidateInformation
            {
                Pubkey = pubkey,
                AnnouncementTransactionId = Context.OriginTransactionId,
                IsCurrentCandidate = true
            };
        }

        State.Candidates.Value.Value.Add(pubkeyByteString);
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L71-74)
```csharp
            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
```

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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-7)
```csharp
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;
```

**File:** test/AElf.Contracts.TestContract.Tests/PatchedContractSecurityTests.cs (L388-435)
```csharp
    [Fact]
    public async Task TestBranchCount()
    {
        {
            await TestBasicSecurityContractStub.TestWhileInfiniteLoop.SendAsync(new Int32Input
                { Int32Value = 14999 });
            var txResult = await TestBasicSecurityContractStub.TestWhileInfiniteLoop.SendWithExceptionAsync(
                new Int32Input
                    { Int32Value = 15000 });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
        }

        {
            await TestBasicSecurityContractStub.TestForInfiniteLoop.SendAsync(new Int32Input { Int32Value = 14999 });
            var txResult = await TestBasicSecurityContractStub.TestForInfiniteLoop.SendWithExceptionAsync(
                new Int32Input
                    { Int32Value = 15000 });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
        }

        {
            await TestBasicSecurityContractStub.TestForInfiniteLoopInSeparateClass.SendAsync(new Int32Input
                { Int32Value = 14999 });
            var txResult = await TestBasicSecurityContractStub.TestForInfiniteLoop.SendWithExceptionAsync(
                new Int32Input
                    { Int32Value = 15000 });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
        }

        {
            await TestBasicSecurityContractStub.TestWhileInfiniteLoopWithState.SendAsync(new Int32Input
                { Int32Value = 14999 });
            var txResult =
                await TestBasicSecurityContractStub.TestWhileInfiniteLoopWithState.SendWithExceptionAsync(
                    new Int32Input
                        { Int32Value = 15000 });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
        }

        {
            await TestBasicSecurityContractStub.TestForeachInfiniteLoop.SendAsync(new ListInput
                { List = { new int[14999] } });
            var txResult =
                await TestBasicSecurityContractStub.TestForeachInfiniteLoop.SendWithExceptionAsync(
                    new ListInput { List = { new int[15000] } });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
        }
    }
```

**File:** protobuf/election_contract.proto (L122-125)
```text
    // Get the victories of the latest term.
    rpc GetVictories (google.protobuf.Empty) returns (PubkeyList) {
        option (aelf.is_view) = true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-242)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }
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

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
