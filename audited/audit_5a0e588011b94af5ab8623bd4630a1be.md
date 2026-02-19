### Title
Unbounded Candidate List Causes Consensus Failure via ExecutionBranchThreshold Breach

### Summary
An attacker can announce election for 15,001+ candidates using different public keys, causing the `SavePreviousTermInformation` method to exceed AElf's ExecutionBranchThreshold (15,000 iterations) during term transitions. This results in a `RuntimeBranchThresholdExceededException` that halts blockchain consensus, as the `TakeSnapshot` operation called by `ProcessNextTerm` cannot complete.

### Finding Description

**Entry Point:**
The `AnnounceElection` and `AnnounceElectionFor` methods allow any user to register as a candidate by locking 100,000 ELF tokens. [1](#0-0) [2](#0-1) 

**Root Cause:**
Each candidate announcement adds a public key to `State.Candidates.Value.Value` without any maximum limit check. [3](#0-2) 

The only protection prevents the same public key from announcing twice if `IsCurrentCandidate` is true, but does not limit total candidates across different public keys. [4](#0-3) 

**Critical Unbounded Iteration:**
During term transitions, `SavePreviousTermInformation` iterates through ALL candidates without pagination or limits: [5](#0-4) 

This method is called by `TakeSnapshot`, which is invoked by the consensus contract during `ProcessNextTerm`: [6](#0-5) 

**ExecutionBranchThreshold Violation:**
AElf enforces an ExecutionBranchThreshold of 15,000 iterations per transaction to prevent infinite loops. [7](#0-6) 

When the candidates list exceeds 15,000 entries, the `foreach` loop in `SavePreviousTermInformation` breaches this threshold, throwing a `RuntimeBranchThresholdExceededException` that propagates up and causes the entire term transition to fail.

**Why Existing Protections Fail:**
- The candidate count check at lines 112 and 134 only determines eligibility for DataCenter subsidy registration, not total candidate limits. [8](#0-7) 
- No maximum candidate limit exists in the codebase (grep search for "MaximumCandidates" returned zero results)
- While `GetPageableCandidateInformation` uses pagination for queries, it is not used in the critical snapshot path. [9](#0-8) 

### Impact Explanation

**Consensus Halt:**
The `ProcessNextTerm` function is a critical consensus operation that must succeed for the blockchain to transition to the next term. When `TakeSnapshot` fails due to the iteration threshold breach, the term transition cannot complete, effectively halting blockchain consensus.

**Quantified Damage:**
- All block production stops when the current term expires
- All transactions cease processing
- Network requires emergency intervention (hard fork or coordinated recovery)
- Economic damage extends to entire network ecosystem
- Validator rewards cannot be distributed

**Who is Affected:**
- All blockchain validators (cannot produce blocks)
- All users (cannot submit transactions)
- All dApps (service interruption)
- Token holders (trading/transfers frozen)

**Severity Justification:**
This represents a complete denial-of-service of the blockchain's core consensus mechanism. Unlike application-level DoS, this attack halts the fundamental operation of the network.

### Likelihood Explanation

**Attacker Capabilities:**
- Must possess approximately 1.5 billion ELF tokens (100,000 ELF × 15,001 candidates)
- Can generate 15,001+ different public key pairs (trivial)
- Can submit 15,001+ transactions calling `AnnounceElectionFor`

**Economic Rationality:**
The locked tokens are **recoverable** via `QuitElection` after the attack, making the capital requirement temporary rather than permanent. [10](#0-9) 

An attacker with sufficient capital could:
1. Lock 1.5B ELF across 15,001 candidates
2. Wait for next term transition
3. Consensus halts when snapshot exceeds ExecutionBranchThreshold
4. After chaos/economic damage, quit election and recover all funds

**Attack Complexity:**
- Low technical complexity (simple repeated contract calls)
- No privileged access required
- No race conditions or timing dependencies
- Deterministic outcome once candidate count exceeds 15,000

**Detection/Operational Constraints:**
- The candidate list growth is publicly visible on-chain
- However, no automated circuit breaker exists to prevent threshold breach
- By the time 15,000 candidates are announced, the attack vector is already armed
- Current test coverage only validates up to 35 candidates, far below the danger threshold [11](#0-10) 

### Recommendation

**Immediate Fix:**
Add a maximum candidate limit check in the `AnnounceElection` private method:

```csharp
private void AnnounceElection(byte[] pubkeyBytes)
{
    var pubkey = pubkeyBytes.ToHex();
    var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);
    
    // Add maximum candidate limit check
    Assert(State.Candidates.Value.Value.Count < 10000, 
        "Maximum candidate limit reached.");
    
    Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
        "Initial miner cannot announce election.");
    // ... rest of method
}
```

**Long-term Mitigation:**
1. Implement pagination in `SavePreviousTermInformation` to process candidates in batches across multiple blocks
2. Add governance-controlled parameter for maximum candidates
3. Consider gas/fee escalation for announcements beyond a threshold
4. Add monitoring alerts when candidate count approaches danger levels

**Invariant to Enforce:**
`State.Candidates.Value.Value.Count < ExecutionBranchThreshold - SafetyMargin`

Where SafetyMargin accounts for other operations in the loop.

**Test Cases:**
1. Verify rejection when candidate count reaches limit
2. Test term transition with candidate count near limit (e.g., 9,999)
3. Negative test: attempt to add 15,001+ candidates and verify snapshot failure
4. Test pagination implementation if adopted

### Proof of Concept

**Initial State:**
- Attacker controls an address with 1.5+ billion ELF tokens
- Blockchain is operating normally with current term N

**Attack Sequence:**

1. **Flood Candidate List:**
   ```
   For i = 1 to 15,001:
     - Generate new key pair[i]
     - Call AnnounceElectionFor(pubkey=keypair[i].PublicKey, admin=attacker_address)
     - Lock 100,000 ELF per call
   Total locked: 1,500,100,000 ELF
   ```

2. **Wait for Term Transition:**
   - Current term N reaches its scheduled end
   - Consensus miner generates NextTerm transaction

3. **Consensus Failure:**
   - `ProcessNextTerm` calls `ElectionContract.TakeSnapshot.Send()`
   - `TakeSnapshot` calls `SavePreviousTermInformation()`
   - Loop iterates: `foreach (var pubkey in State.Candidates.Value.Value)` 
   - Iteration count: 15,001
   - ExecutionBranchThreshold breach at iteration 15,001
   - Exception: `RuntimeBranchThresholdExceededException`
   - Term transition fails

**Expected vs Actual:**
- **Expected:** Term N transitions to Term N+1, consensus continues
- **Actual:** Term transition transaction fails, blockchain consensus halts

**Success Condition:**
The attack succeeds when the term transition fails and no new blocks are produced after the term expiration time.

**Recovery Options:**
Post-attack, attacker can call `QuitElection` 15,001 times to recover all locked tokens, making the attack economically viable for well-capitalized actors seeking to disrupt the network.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-119)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;

        LockCandidateNativeToken();

        AddCandidateAsOption(pubkey);

        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-142)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
        var admin = input.Admin ?? Context.Sender;
        State.CandidateAdmins[pubkey] = admin;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
        LockCandidateNativeToken();
        AddCandidateAsOption(pubkey);
        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-280)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });

        // Update candidate information.
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;

        // Remove candidate public key from the Voting Item options.
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
        var dataCenterList = State.DataCentersRankingList.Value;
        if (dataCenterList.DataCenters.ContainsKey(pubkey))
        {
            dataCenterList.DataCenters[pubkey] = 0;
            UpdateDataCenterAfterMemberVoteAmountChanged(dataCenterList, pubkey, true);
            State.DataCentersRankingList.Value = dataCenterList;
        }

        var managedCandidatePubkey = State.ManagedCandidatePubkeysMap[Context.Sender];
        managedCandidatePubkey.Value.Remove(ByteString.CopyFrom(pubkeyBytes));
        if (managedCandidatePubkey.Value.Any())
            State.ManagedCandidatePubkeysMap[Context.Sender] = managedCandidatePubkey;
        else
            State.ManagedCandidatePubkeysMap.Remove(Context.Sender);

        State.CandidateSponsorMap.Remove(pubkey);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L459-479)
```csharp
    private void SavePreviousTermInformation(TakeElectionSnapshotInput input)
    {
        var snapshot = new TermSnapshot
        {
            MinedBlocks = input.MinedBlocks,
            EndRoundNumber = input.RoundNumber
        };

        if (State.Candidates.Value == null) return;

        foreach (var pubkey in State.Candidates.Value.Value)
        {
            var votes = State.CandidateVotes[pubkey.ToHex()];
            var validObtainedVotesAmount = 0L;
            if (votes != null) validObtainedVotesAmount = votes.ObtainedActiveVotedVotesAmount;

            snapshot.ElectionResult.Add(pubkey.ToHex(), validObtainedVotesAmount);
        }

        State.Snapshots[input.TermNumber] = snapshot;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-7)
```csharp
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L240-258)
```csharp
    public override GetPageableCandidateInformationOutput GetPageableCandidateInformation(PageInformation input)
    {
        var output = new GetPageableCandidateInformationOutput();
        var candidates = State.Candidates.Value;

        var count = candidates.Value.Count;
        if (count <= input.Start) return output;

        var length = Math.Min(Math.Min(input.Length, 20), candidates.Value.Count.Sub(input.Start));
        foreach (var candidate in candidates.Value.Skip(input.Start).Take(length))
            output.Value.Add(new CandidateDetail
            {
                CandidateInformation = State.CandidateInformationMap[candidate.ToHex()],
                ObtainedVotesAmount = GetCandidateVote(new StringValue { Value = candidate.ToHex() })
                    .ObtainedActiveVotedVotesAmount
            });

        return output;
    }
```

**File:** test/AElf.Contracts.Economic.TestBase/EconomicContractsTestConstants.cs (L13-13)
```csharp
    public const int ValidateDataCenterCount = 35;
```
