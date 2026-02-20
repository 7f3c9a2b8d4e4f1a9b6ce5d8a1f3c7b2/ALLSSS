# Audit Report

## Title
Case Sensitivity in ReplaceCandidatePubkey Causes Vote Data Loss and Incorrect Miner Selection

## Summary
The `ReplaceCandidatePubkey` function in the Election Contract lacks case normalization for pubkey string inputs, causing silent migration failure when pubkeys with different casing are provided. This results in vote data being orphaned while candidate lists are updated, leading to incorrect exclusion of legitimate candidates from miner selection and potential consensus disruption.

## Finding Description

The vulnerability arises from the interaction between case-sensitive state dictionary lookups and missing input normalization in the candidate pubkey replacement logic.

**Root Cause:**

The `ToHex()` extension method deterministically produces lowercase hexadecimal strings. The arithmetic formula `b + 0x37 + 0x20` generates lowercase ASCII characters 'a' through 'f' for hex digits 10-15. [1](#0-0) 

During candidate registration via `AnnounceElection`, pubkey bytes are converted to lowercase strings using `ToHex()` before storage in `State.CandidateInformationMap`. [2](#0-1) 

Vote data is stored in `State.CandidateVotes` using the candidate pubkey string directly as the key. Since regular candidates are registered with lowercase keys, votes are typically stored with lowercase keys. [3](#0-2) 

**The Critical Flaw:**

The `ReplaceCandidatePubkey` function uses input strings directly without normalization. State dictionaries use case-sensitive string keys. [4](#0-3) 

When an admin provides pubkeys with different casing than stored keys, the vote data lookup fails and returns null, causing the migration block to be skipped entirely. [5](#0-4) 

Similarly, the candidate information migration fails due to case mismatch, leaving the old data orphaned. [6](#0-5) 

**Why Validation Passes:**

The validation check uses `IsCurrentCandidateOrInitialMiner`, which for initial miners converts hex strings to bytes using `ByteArrayHelper.HexStringToByteArray` - a case-insensitive operation using `Convert.ToByte` with base 16. [7](#0-6) [8](#0-7) 

The `State.Candidates` update succeeds because it uses byte-level comparison, which is case-insensitive. [9](#0-8) 

**Impact on Miner Selection:**

The `GetValidCandidates` method converts candidate bytes to lowercase via `ToHex()` and queries `State.CandidateVotes`. After failed migration, the new pubkey's lowercase representation has no vote data, causing the candidate to be filtered out despite having legitimate votes orphaned at the old key. [10](#0-9) 

## Impact Explanation

**Consensus Integrity Compromise:**
Candidates with legitimate votes are incorrectly excluded from `GetVictories()` results, corrupting miner selection for AEDPoS consensus rounds. This directly impacts the validator set determination mechanism.

**Vote Data Loss:**
Elector-locked tokens become associated with orphaned state entries unreachable through the new pubkey. The accumulated voting power is effectively nullified, violating the invariant that vote weight must accurately reflect in candidate selection.

**State Inconsistency:**
The contract enters an internally inconsistent state where `State.Candidates` reflects the new pubkey while `State.CandidateVotes` and `State.CandidateInformationMap` retain orphaned entries at the old pubkey key, breaking the relationship between candidate registration and vote tracking.

**Operational Impact:**
This disrupts the election mechanism's core function of determining block producers, potentially leading to governance disputes when high-vote candidates are excluded from consensus participation.

Severity: **Medium** - While it compromises consensus integrity and causes data loss, it requires admin-level access and only affects candidates undergoing pubkey replacement.

## Likelihood Explanation

**Preconditions:**
- Requires candidate admin role with permissions to call `ReplaceCandidatePubkey`
- Candidate must have existing vote data for measurable impact  
- Admin must provide input strings with different casing than stored keys

**Execution Simplicity:**
The vulnerability triggers with a single transaction calling `ReplaceCandidatePubkey` with mismatched case pubkey strings. No complex sequences or timing required.

**Realistic Scenario:**
This can occur unintentionally when an admin uses uppercase hex strings without realizing the case sensitivity of state dictionary keys. The absence of input validation or documentation about case requirements makes this a realistic operational mistake. Existing tests only use lowercase strings via `ToHex()`, failing to catch this edge case. [11](#0-10) 

Probability: **Medium** - While requiring privileged access, the non-obvious case sensitivity requirement and lack of validation make honest mistakes feasible during key rotation operations.

## Recommendation

Normalize all pubkey string inputs in `ReplaceCandidatePubkey` by converting them to lowercase before performing any state lookups or updates:

```csharp
public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
{
    // Normalize inputs to lowercase
    var oldPubkey = input.OldPubkey.ToLower();
    var newPubkey = input.NewPubkey.ToLower();
    
    Assert(IsCurrentCandidateOrInitialMiner(oldPubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(oldPubkey) && !IsPubkeyBanned(newPubkey),
        "Pubkey is in already banned.");

    // Permission check using normalized key
    Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = oldPubkey }), "No permission.");

    // Continue with normalized keys...
}
```

Alternatively, convert pubkey bytes to hex strings using `ToHex()` before any operations:

```csharp
var oldPubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.OldPubkey);
var newPubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.NewPubkey);
var oldPubkey = oldPubkeyBytes.ToHex();
var newPubkey = newPubkeyBytes.ToHex();
```

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_CaseMismatch_LosesVotes()
{
    // Setup: Announce election (stores with lowercase key)
    var candidateKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = ValidationDataCenterKeyPairs.Last();
    var adminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
    await AnnounceElectionAsync(candidateKeyPair, adminAddress);
    
    // Cast votes for the candidate (stores at lowercase key)
    var voterKeyPair = VoterKeyPairs.First();
    await VoteMinerAsync(voterKeyPair, candidateKeyPair.PublicKey.ToHex(), 100_00000000);
    
    // Verify votes exist
    var votesBefore = await ElectionContractStub.GetCandidateVote.CallAsync(
        new StringValue { Value = candidateKeyPair.PublicKey.ToHex() });
    votesBefore.ObtainedActiveVotedVotesAmount.ShouldBe(100_00000000);
    
    // Replace with UPPERCASE old pubkey (case mismatch)
    var newKeyPair = ValidationDataCenterKeyPairs.Skip(1).First();
    var adminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, candidateAdmin);
    await adminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = candidateKeyPair.PublicKey.ToHex().ToUpper(), // UPPERCASE
        NewPubkey = newKeyPair.PublicKey.ToHex()
    });
    
    // Verify: Votes NOT migrated to new pubkey
    var votesAfter = await ElectionContractStub.GetCandidateVote.CallAsync(
        new StringValue { Value = newKeyPair.PublicKey.ToHex() });
    votesAfter.ObtainedActiveVotedVotesAmount.ShouldBe(0); // LOST!
    
    // Verify: Candidate excluded from valid candidates despite having votes
    var validCandidates = await ElectionContractStub.GetVotedCandidates.CallAsync(new Empty());
    validCandidates.Value.ShouldNotContain(ByteString.CopyFrom(newKeyPair.PublicKey));
}
```

## Notes

This vulnerability specifically affects initial miners or candidates where case inconsistency exists between initialization and subsequent admin operations. Regular candidates registered through `AnnounceElection` use `ToHex()` consistently, but initial miners configured during contract initialization may have their pubkeys stored with arbitrary casing, creating the preconditions for this exploit when admins later call `ReplaceCandidatePubkey` with different case variations.

### Citations

**File:** src/AElf.Types/Extensions/ByteExtensions.cs (L38-41)
```csharp
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = (byte)(bytes[bx] & 0x0F);
                c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L75-82)
```csharp
    private bool IsCurrentCandidateOrInitialMiner(string pubkey)
    {
        var isCurrentCandidate = State.CandidateInformationMap[pubkey] != null &&
                                 State.CandidateInformationMap[pubkey].IsCurrentCandidate;
        var isInitialMiner = State.InitialMiners.Value.Value.Contains(
            ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(pubkey)));
        return isCurrentCandidate || isInitialMiner;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L144-147)
```csharp
    private void AnnounceElection(byte[] pubkeyBytes)
    {
        var pubkey = pubkeyBytes.ToHex();
        var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);
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

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L21-23)
```csharp
    public MappedState<string, CandidateVote> CandidateVotes { get; set; }

    public MappedState<string, CandidateInformation> CandidateInformationMap { get; set; }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L189-197)
```csharp
        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L229-235)
```csharp
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L237-243)
```csharp
        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }
```

**File:** src/AElf.Types/Helper/ByteArrayHelper.cs (L8-19)
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

**File:** test/AElf.Contracts.Election.Tests/BVT/ReplaceCandidateTests.cs (L38-42)
```csharp
        await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
        {
            OldPubkey = announceElectionKeyPair.PublicKey.ToHex(),
            NewPubkey = newKeyPair.PublicKey.ToHex()
        });
```
