# Audit Report

## Title
Empty Pubkey Candidate Registration Causes Consensus Failure During Term Transition

## Summary
The Election Contract's `AnnounceElectionFor` method accepts empty pubkey strings without validation. When an empty pubkey candidate is elected as a miner through voting, the consensus contract's term transition crashes with an `IndexOutOfRangeException` when attempting to sort miners by their first byte, permanently halting blockchain consensus.

## Finding Description

The vulnerability exists across the election and consensus contract interaction:

**Root Cause - Missing Validation:**

The `AnnounceElectionFor` method converts the input pubkey string to a byte array without validating its length. [1](#0-0) 

This empty byte array is passed to the internal `AnnounceElection` method, which creates an empty `ByteString` and adds it to the candidates list without any length checks. [2](#0-1) 

The existing validation checks verify initial miner status, banned status, and duplicate announcements, but critically omit pubkey length validation. [3](#0-2) 

**Attack Propagation:**

Once registered, the empty pubkey candidate can accumulate votes. The `GetValidCandidates` method filters by vote amounts but does not validate pubkey structure. [4](#0-3) 

During elections, `GetVictories` sorts candidates by vote amount and returns the top N, which may include the empty pubkey if it has sufficient votes. [5](#0-4) 

**Consensus Crash:**

During term transitions, the consensus contract retrieves election victories and creates a miner list. [6](#0-5) 

The miner list is then passed to `GenerateFirstRoundOfNewTerm`, which attempts to create a dictionary mapping each miner's hex string to their first byte using `miner => miner[0]`. [7](#0-6) 

When `miner` is an empty `ByteString` (length = 0), the indexing operation `miner[0]` throws an `IndexOutOfRangeException`, crashing the consensus term generation process and preventing any further term transitions.

## Impact Explanation

This is a **HIGH severity** vulnerability because it causes complete denial of service of the blockchain's consensus mechanism:

1. **Consensus Halt**: The blockchain cannot transition to new terms, freezing the miner list
2. **Block Production Failure**: If current miners lose authorization or the term expires, block production may halt entirely
3. **Network-Wide Impact**: All network participants (users, dApps, validators) are affected
4. **Recovery Complexity**: Requires emergency intervention, potentially including a hard fork
5. **Economic Damage**: Halted transactions lead to frozen funds and potential economic losses

The vulnerability breaks the fundamental consensus invariant that term transitions must always succeed, affecting the entire blockchain's liveness and availability.

## Likelihood Explanation

This is **MEDIUM likelihood** because:

**Attacker Requirements:**
- Lock 100,000 ELF tokens as candidate registration deposit [8](#0-7) 
- Coordinate sufficient voting power to place the empty candidate in the top N miners (typically requiring millions of locked ELF depending on network participation)

**Feasibility Factors:**
- **Low Technical Complexity**: Single public contract call to register, standard voting operations
- **High Economic Barrier**: Requires substantial capital for deposit and voting power
- **Medium Coordination**: Can be executed by a single well-funded actor or coordinated voter group
- **Detection Window**: Attack is visible in candidate lists but may not be detected until term transition

**Assessment**: While economically expensive, the attack is technically trivial and could be executed by a determined, well-funded adversary. The one-time cost causes persistent DoS until fixed.

## Recommendation

Add pubkey length validation in the candidate registration flow:

```csharp
public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
{
    var pubkey = input.Pubkey;
    Assert(!string.IsNullOrEmpty(pubkey), "Pubkey cannot be empty.");
    
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
    Assert(pubkeyBytes.Length > 0, "Pubkey byte array cannot be empty.");
    
    // Rest of existing implementation...
}
```

Additionally, add defensive validation in `GenerateFirstRoundOfNewTerm`:

```csharp
internal Round GenerateFirstRoundOfNewTerm(int miningInterval,
    Timestamp currentBlockTime, long currentRoundNumber = 0, long currentTermNumber = 0)
{
    // Validate all pubkeys are non-empty
    Assert(Pubkeys.All(pk => pk.Length > 0), "All miner pubkeys must be non-empty.");
    
    var sortedMiners =
        (from obj in Pubkeys
                .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
            orderby obj.Value descending
            select obj.Key).ToList();
    
    // Rest of existing implementation...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task EmptyPubkey_ShouldCauseConsensusFailure()
{
    // Step 1: Register empty pubkey candidate
    var result = await ElectionContractStub.AnnounceElectionFor.SendAsync(
        new AnnounceElectionForInput
        {
            Pubkey = "", // Empty pubkey
            Admin = DefaultSender
        });
    
    // Candidate should be registered (missing validation allows this)
    var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    Assert.Contains(ByteString.Empty, candidates.Value);
    
    // Step 2: Vote for empty candidate to get it into top miners
    await VoteForCandidate("", sufficientVotes);
    
    // Step 3: Trigger term transition
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    Assert.Contains(ByteString.Empty, victories.Value);
    
    // Step 4: Attempt to generate first round of new term - this should crash
    var minerList = new MinerList { Pubkeys = { victories.Value } };
    
    // This will throw IndexOutOfRangeException when accessing empty ByteString[0]
    Assert.Throws<IndexOutOfRangeException>(() =>
        minerList.GenerateFirstRoundOfNewTerm(4000, TimestampHelper.GetUtcNow()));
}
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L192-194)
```csharp
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Lock for announcing election."
        });
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-83)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-282)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```
