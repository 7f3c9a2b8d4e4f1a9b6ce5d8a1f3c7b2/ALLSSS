### Title
Empty Pubkey Candidate Registration Causes Consensus Failure During Term Transition

### Summary
The Election Contract's `AnnounceElectionFor` method lacks validation to prevent registration of empty pubkey strings. When an empty pubkey candidate receives sufficient votes and is elected as a miner, the subsequent term transition fails with an `IndexOutOfRangeException` in `GenerateFirstRoundOfNewTerm`, halting blockchain consensus indefinitely.

### Finding Description

**Root Cause:**

The Election Contract's candidate registration flow fails to validate that pubkeys are non-empty. In `AnnounceElectionFor`, the input pubkey string is converted to a byte array without length validation: [1](#0-0) 

This empty byte array is then passed to the internal `AnnounceElection` method, which creates an empty `ByteString` and adds it to the candidates list: [2](#0-1) 

When users vote for this empty candidate, `State.CandidateVotes[""]` is populated with an empty `ByteString` as the `Pubkey`: [3](#0-2) 

**Attack Path:**

During term transitions, the Consensus Contract queries the Election Contract for the new miner list via `GetVictories`. If the empty pubkey candidate has accumulated sufficient votes to rank in the top N candidates, it will be included in the returned victories: [4](#0-3) 

The Consensus Contract then calls `GenerateFirstRoundOfNewTerm` on the returned `MinerList`. This function attempts to sort miners by accessing the first byte of each pubkey using `miner[0]`: [5](#0-4) 

When `miner` is an empty `ByteString` (length = 0), the indexing operation `miner[0]` throws an `IndexOutOfRangeException`, crashing the term generation process.

**Why Existing Protections Fail:**

The Election Contract validates several conditions during candidate registration (initial miner status, banned status, duplicate announcements, token deposit), but critically omits pubkey length validation: [6](#0-5) 

The `GetValidCandidates` method filters candidates by vote amounts but does not validate pubkey structure: [7](#0-6) 

### Impact Explanation

**Direct Harm:**
- Complete denial of service of the blockchain's consensus mechanism
- The blockchain cannot transition to new terms, preventing miner list updates
- Block production may halt entirely if all current miners lose authorization
- All consensus-dependent operations (block validation, finalization, cross-chain communication) become impossible

**Protocol Damage:**
- Indefinite blockchain freeze requiring emergency intervention or hard fork
- Loss of network liveness and availability for all users
- Potential economic losses from halted transactions and frozen funds
- Severe reputational damage to the blockchain network

**Affected Parties:**
- All network participants (users, dApps, validators)
- The entire AElf mainchain or affected sidechain

**Severity Justification:**
This is a **HIGH severity** vulnerability despite economic barriers because:
1. It completely disables the consensus mechanism
2. Recovery requires emergency measures or manual intervention
3. Impact affects the entire blockchain network
4. The attack is persistent until resolved

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Lock 100,000 ELF tokens as candidate registration deposit
2. Acquire or coordinate sufficient voting power to place the empty pubkey in the top N miners (typically requires millions of locked ELF tokens depending on network participation)

**Attack Complexity:**
- **Low technical complexity**: Single contract call to register empty pubkey, standard voting operations
- **High economic cost**: Requires substantial capital (100K ELF deposit + voting power)
- **Medium coordination**: Can be executed by single wealthy actor or requires coordinating multiple voters

**Feasibility Conditions:**
- Attacker must either control significant voting power directly or manipulate voters through social engineering
- Voting period allows accumulation of votes over time (typically days)
- Network must not detect and mitigate the empty candidate before term transition

**Detection Constraints:**
- Empty pubkey candidate is visible in candidate list
- Unusual voting patterns may be detected if monitored
- Attack becomes obvious only during term transition when blockchain halts

**Probability Assessment:**
**MEDIUM likelihood** because:
- Entry point is unrestricted (public method)
- Economic barrier is high but feasible for well-funded attackers
- Attack requires either large capital or social engineering success
- One-time cost can cause persistent DoS until fixed
- No technical complexity barrier

### Recommendation

**Immediate Fix:**

Add pubkey length validation in `AnnounceElection`:

```csharp
private void AnnounceElection(byte[] pubkeyBytes)
{
    Assert(pubkeyBytes != null && pubkeyBytes.Length > 0, 
        "Invalid pubkey: cannot be null or empty.");
    Assert(pubkeyBytes.Length == 33 || pubkeyBytes.Length == 65, 
        "Invalid pubkey length: must be 33 (compressed) or 65 (uncompressed) bytes.");
    
    var pubkey = pubkeyBytes.ToHex();
    // ... rest of existing code
}
```

**Additional Protections:**

1. Add defensive validation in `GenerateFirstRoundOfNewTerm`:
```csharp
var sortedMiners =
    (from obj in Pubkeys
            .Where(miner => miner.Length > 0)  // Filter empty pubkeys
            .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
        orderby obj.Value descending
        select obj.Key).ToList();

Assert(sortedMiners.Any(), "No valid miners in list.");
```

2. Add pubkey format validation in `GetVictories` to filter malformed candidates before returning them to Consensus Contract

**Test Cases:**
1. Attempt to call `AnnounceElectionFor` with empty string pubkey - should fail with clear error
2. Attempt to call `AnnounceElectionFor` with invalid length pubkey - should fail
3. Verify `GenerateFirstRoundOfNewTerm` handles edge cases gracefully with defensive checks
4. Add integration test simulating full attack flow to ensure mitigation

### Proof of Concept

**Required Initial State:**
- Attacker has at least 100,000 ELF tokens for candidate deposit
- Attacker controls or can coordinate sufficient voting power to rank in top N miners (typically millions of locked ELF)
- Current term is approaching expiration

**Attack Sequence:**

1. **Register empty candidate** (Block X):
   ```
   Call: ElectionContract.AnnounceElectionFor({pubkey: "", admin: attackerAddress})
   Cost: 100,000 ELF locked
   Result: Empty ByteString added to State.Candidates
   ```

2. **Accumulate votes** (Blocks X+1 to Y):
   ```
   Call: ElectionContract.Vote({candidatePubkey: "", amount: votingAmount, lockTime: 90 days})
   Repeat until empty candidate ranks in top MinersCount candidates
   Result: State.CandidateVotes[""] has sufficient ObtainedActiveVotedVotesAmount
   ```

3. **Wait for term transition** (Block Z when term expires):
   ```
   Miner produces block triggering NextTerm behavior
   Consensus Contract calls: GetVictories() -> returns MinerList with empty ByteString
   Consensus Contract calls: MinerList.GenerateFirstRoundOfNewTerm()
   ```

4. **Consensus crash** (Block Z):
   ```
   Expected: New term generated successfully, block Z+1 produced
   Actual: IndexOutOfRangeException at miner[0] access
          Term generation fails
          Blockchain halts - no more blocks produced
   ```

**Success Condition:**
Blockchain stops producing blocks after term expiration due to unhandled exception in term generation. Network becomes unresponsive and requires emergency intervention.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-126)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L144-174)
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
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L546-570)
```csharp
    private long UpdateCandidateInformation(string candidatePublicKey, long amount, Hash voteId)
    {
        var candidateVotes = State.CandidateVotes[candidatePublicKey];
        if (candidateVotes == null)
        {
            candidateVotes = new CandidateVote
            {
                Pubkey = ByteStringHelper.FromHexString(candidatePublicKey),
                ObtainedActiveVotingRecordIds = { voteId },
                ObtainedActiveVotedVotesAmount = amount,
                AllObtainedVotedVotesAmount = amount
            };
        }
        else
        {
            candidateVotes.ObtainedActiveVotingRecordIds.Add(voteId);
            candidateVotes.ObtainedActiveVotedVotesAmount =
                candidateVotes.ObtainedActiveVotedVotesAmount.Add(amount);
            candidateVotes.AllObtainedVotedVotesAmount =
                candidateVotes.AllObtainedVotedVotesAmount.Add(amount);
        }

        State.CandidateVotes[candidatePublicKey] = candidateVotes;

        return candidateVotes.ObtainedActiveVotedVotesAmount;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```
