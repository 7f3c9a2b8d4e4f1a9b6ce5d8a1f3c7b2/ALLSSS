# Audit Report

## Title
Empty Pubkey Candidate Registration Causes Consensus Failure During Term Transition

## Summary
The Election Contract's `AnnounceElectionFor` method accepts empty pubkey strings without validation. When an empty pubkey candidate is elected as a miner through voting, the consensus contract's term transition crashes with an `IndexOutOfRangeException` when attempting to sort miners by their first byte, permanently halting blockchain consensus.

## Finding Description

The vulnerability exists across the election and consensus contract interaction through three critical stages:

**Root Cause - Missing Validation:**

The `AnnounceElectionFor` method converts the input pubkey string to a byte array without validating its length. [1](#0-0) 

When an empty string is passed, `ByteArrayHelper.HexStringToByteArray` returns an empty byte array. [2](#0-1) 

This empty byte array is passed to the internal `AnnounceElection` method, which creates an empty `ByteString` and adds it to the candidates list without any length checks. [3](#0-2) 

The existing validation checks verify initial miner status, banned status, and duplicate announcements, but critically omit pubkey length validation. [4](#0-3) 

**Attack Propagation:**

Once registered, the empty pubkey candidate can accumulate votes through the standard voting mechanism. The `GetValidCandidates` method filters candidates by vote amounts but does not validate pubkey structure or length. [5](#0-4) 

During elections, `GetVictories` sorts valid candidates by vote amount and returns the top N, which may include the empty pubkey if it has sufficient votes. [6](#0-5) 

**Consensus Crash:**

During term transitions, the consensus contract retrieves election victories and creates a miner list. [7](#0-6) 

The miner list is then passed to `GenerateFirstRoundOfNewTerm`, which is called during term transition consensus operations. [8](#0-7) 

This method attempts to create a dictionary mapping each miner's hex string to their first byte using `miner => miner[0]`. [9](#0-8) 

When `miner` is an empty `ByteString` (length = 0), the indexing operation `miner[0]` throws an `IndexOutOfRangeException`, crashing the consensus term generation process and preventing any further term transitions. This occurs during the `GetConsensusExtraDataForNextTerm` operation. [10](#0-9) 

## Impact Explanation

This is a **HIGH severity** vulnerability because it causes complete denial of service of the blockchain's consensus mechanism:

1. **Consensus Halt**: The blockchain cannot transition to new terms, freezing the miner list
2. **Block Production Failure**: If current miners lose authorization or the term expires, block production may halt entirely
3. **Network-Wide Impact**: All network participants (users, dApps, validators) are affected
4. **Recovery Complexity**: Requires emergency intervention, potentially including a hard fork or contract upgrade
5. **Economic Damage**: Halted transactions lead to frozen funds and potential economic losses

The vulnerability breaks the fundamental consensus invariant that term transitions must always succeed, affecting the entire blockchain's liveness and availability.

## Likelihood Explanation

This is **MEDIUM likelihood** because:

**Attacker Requirements:**
- Lock 100,000 ELF tokens as candidate registration deposit [11](#0-10) 
- Coordinate sufficient voting power to place the empty candidate in the top N miners (typically requiring millions of locked ELF depending on network participation)

**Feasibility Factors:**
- **Low Technical Complexity**: Single public contract call to register, standard voting operations
- **High Economic Barrier**: Requires substantial capital for deposit and voting power
- **Medium Coordination**: Can be executed by a single well-funded actor or coordinated voter group
- **Detection Window**: Attack is visible in candidate lists but may not be detected until term transition

**Assessment**: While economically expensive, the attack is technically trivial and could be executed by a determined, well-funded adversary. The one-time cost causes persistent DoS until fixed.

## Recommendation

Add pubkey length validation to the `AnnounceElection` method:

```csharp
private void AnnounceElection(byte[] pubkeyBytes)
{
    // Add validation for minimum pubkey length
    Assert(pubkeyBytes != null && pubkeyBytes.Length >= 33, "Invalid pubkey: must be at least 33 bytes.");
    
    var pubkey = pubkeyBytes.ToHex();
    var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);
    
    // ... rest of existing code
}
```

Additionally, add validation in `AnnounceElectionFor` before conversion:

```csharp
public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
{
    var pubkey = input.Pubkey;
    Assert(!string.IsNullOrEmpty(pubkey) && pubkey.Length >= 66, "Invalid pubkey format.");
    
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
    // ... rest of existing code
}
```

## Proof of Concept

```csharp
[Fact]
public async Task EmptyPubkey_CausesConsensusFailure_Test()
{
    // Arrange: Setup election contract and approve tokens
    var sponsor = Accounts[0].Address;
    await ApproveTokensAsync(sponsor, 100_000_00000000);
    
    // Act: Register candidate with empty pubkey
    var emptyPubkey = "";
    var result = await ElectionContractStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Pubkey = emptyPubkey,
        Admin = sponsor
    });
    
    // Verify registration succeeded
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Mined);
    
    // Vote for empty pubkey candidate
    await VoteForCandidate(emptyPubkey, 10_000_000_00000000);
    
    // Get victories - should include empty pubkey
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    Assert.Contains(victories.Value, v => v.Length == 0);
    
    // Attempt term transition - should crash with IndexOutOfRangeException
    var minerList = new MinerList { Pubkeys = { victories.Value } };
    
    // This will throw IndexOutOfRangeException
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        var round = minerList.GenerateFirstRoundOfNewTerm(4000, TimestampHelper.GetUtcNow(), 0, 0);
    });
    
    Assert.Contains("Index", exception.Message);
}
```

## Notes

This vulnerability demonstrates a critical input validation failure that cascades through multiple contract layers. The empty pubkey passes all existing validation checks because they focus on business logic (initial miner status, banned status, duplicate prevention) rather than data integrity. The crash occurs deterministically during the sorting operation in `GenerateFirstRoundOfNewTerm`, making this a reproducible consensus-level failure.

The fix should be applied at the earliest possible point (in `AnnounceElectionFor` and `AnnounceElection`) to prevent invalid data from entering the system. A minimum length of 33 bytes (compressed public key) or 65 bytes (uncompressed) should be enforced depending on the expected key format.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L124-126)
```csharp
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

**File:** src/AElf.Types/Helper/ByteArrayHelper.cs (L8-18)
```csharp
        public static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
                hex = hex.Substring(2);
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];

            for (var i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return bytes;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-83)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L86-94)
```csharp
    private List<string> GetValidCandidates()
    {
        if (State.Candidates.Value == null) return new List<string>();

        return State.Candidates.Value.Value
            .Where(c => State.CandidateVotes[c.ToHex()] != null &&
                        State.CandidateVotes[c.ToHex()].ObtainedActiveVotedVotesAmount > 0)
            .Select(p => p.ToHex())
            .ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-282)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-210)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
