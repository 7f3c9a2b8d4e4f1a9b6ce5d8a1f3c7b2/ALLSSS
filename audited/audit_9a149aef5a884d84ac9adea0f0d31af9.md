### Title
Admin-Controlled Parliament Members Can Vote Multiple Times by Redistributing Managed Pubkeys Across Admin Addresses

### Summary
The check at lines 132-133 in `GetAndCheckActualParliamentMemberAddress()` prevents an admin from voting when they manage multiple parliament member pubkeys, but fails to prevent vote multiplication when the same entity redistributes those pubkeys across multiple admin addresses they control. An attacker controlling N parliament member nodes can use `SetCandidateAdmin` to assign each pubkey to a separate admin address, then vote N times on the same proposal, bypassing the one-vote-per-member governance invariant.

### Finding Description

The vulnerability exists in the parliament voting mechanism's admin delegation system. When an admin attempts to vote on behalf of a parliament member, the system retrieves all pubkeys managed by that admin address and validates the count: [1](#0-0) 

This check correctly prevents voting when a single admin manages multiple pubkeys. However, the root cause of the vulnerability is that there is no validation to prevent the same entity from controlling multiple admin addresses, each managing one pubkey.

The attack exploits the `SetCandidateAdmin` function, which allows transferring pubkey management between admin addresses: [2](#0-1) 

The permission check only validates that the current admin (Context.Sender) authorizes the transfer, but doesn't prevent the same entity from controlling both the old and new admin addresses. After redistribution, each admin address manages exactly one pubkey, allowing the count check to pass.

The voting flow records votes by parliament member address, not by admin address: [3](#0-2) 

The duplicate vote check only verifies that each parliament member address hasn't voted yet: [4](#0-3) 

Since each admin votes on behalf of a different parliament member address, this check passes for each vote. The threshold calculations then count all votes as legitimate: [5](#0-4) 

### Impact Explanation

**Governance Manipulation**: An attacker controlling M out of N parliament member nodes can multiply their voting power by M times, potentially reaching proposal approval thresholds they shouldn't be able to reach alone. For example, if the approval threshold is 60% and an attacker controls 3 out of 10 parliament members (30%), they can vote 3 times to reach 30% approval - not enough alone. But if there are legitimate votes bringing total to 50%, their triple-vote brings it to 80%, passing the threshold when it shouldn't.

**Authority Impact**: This breaks the fundamental governance invariant that each parliament member gets exactly one vote per proposal. The attacker gains unauthorized influence over system configuration changes, treasury operations, consensus parameter updates, and cross-chain settings.

**Severity Justification**: High severity because it directly compromises the integrity of the governance system, allowing unauthorized proposal execution that could affect fund flows, consensus rules, or system parameters.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must control multiple parliament member nodes (miners). This is realistic as large mining operations often run multiple nodes. The attacker needs to create additional addresses (trivial) and call `SetCandidateAdmin` to redistribute pubkeys.

**Attack Complexity**: Low - the attack requires only calling `SetCandidateAdmin` for each pubkey to transfer management to a new admin address the attacker controls, then submitting voting transactions from each admin address. No complex state manipulation or timing requirements.

**Feasibility Conditions**: 
- Attacker controls 2+ parliament member nodes (realistic for major miners)
- No rate limiting or restrictions on admin changes
- Election contract properly initialized (standard deployment state)

**Detection Constraints**: The attack is difficult to detect because:
- Each admin address appears to manage only one pubkey (passing validation)
- Each vote appears legitimate (from valid parliament member addresses)
- No on-chain mechanism tracks that multiple admin addresses are controlled by the same entity
- Transaction patterns look normal (multiple separate approve transactions)

**Economic Rationality**: The attack cost is minimal (gas fees for `SetCandidateAdmin` calls and voting transactions), while the benefit is multiplied governance influence worth potentially millions in controlled proposals.

### Recommendation

**Code-Level Mitigation**: Implement one of the following approaches:

1. **Prevent Admin Changes During Active Proposals**: Add a check in `SetCandidateAdmin` to prevent admin changes while the pubkey's parliament member address has pending (not expired/released) proposals:

```csharp
// In SetCandidateAdmin, after line 23:
var memberAddress = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey));
Assert(!HasActivePendingProposals(memberAddress), 
       "Cannot change admin while member has active pending proposals.");
```

2. **Cooldown Period**: Implement a cooldown period after admin changes before the new admin can vote:

```csharp
// Add state: MappedState<Address, Timestamp> LastAdminChangeTime
// In SetCandidateAdmin, after line 42:
State.LastAdminChangeTime[Address.FromPublicKey(pubkeyBytes)] = Context.CurrentBlockTime;

// In GetAndCheckActualParliamentMemberAddress, after line 135:
var lastChange = State.LastAdminChangeTime[actualMemberAddress];
Assert(lastChange == null || Context.CurrentBlockTime > lastChange.AddDays(7),
       "Admin recently changed, voting not allowed during cooldown period.");
```

3. **Track Original Admin**: Store and validate against the original admin who first announced the candidate:

```csharp
// Add state: MappedState<string, Address> OriginalCandidateAdmin
// Prevent voting unless using original admin or pubkey owner directly
```

**Invariant Checks**: Add monitoring to detect multiple admin addresses voting on the same proposal from managed pubkeys, flagging suspicious patterns where different admins' managed pubkeys all vote identically.

**Test Cases**: Add regression tests that:
- Attempt to redistribute pubkeys and vote multiple times
- Verify admin change restrictions are enforced
- Validate cooldown periods work correctly
- Ensure legitimate admin changes for operational reasons still function

### Proof of Concept

**Initial State**:
- Parliament has 10 members: PubKey1 through PubKey10
- Attacker controls nodes for PubKey1, PubKey2, PubKey3
- All three initially managed by AdminA (attacker's primary address)
- AdminA cannot vote due to managing 3 pubkeys (count > 1)

**Attack Steps**:

1. Attacker creates two additional addresses: AdminB, AdminC (both controlled by attacker)

2. Transaction from AdminA: `SetCandidateAdmin(pubkey: PubKey2, admin: AdminB)`
   - Transfers PubKey2 management to AdminB
   - State after: AdminA manages [PubKey1, PubKey3], AdminB manages [PubKey2]

3. Transaction from AdminA: `SetCandidateAdmin(pubkey: PubKey3, admin: AdminC)`
   - Transfers PubKey3 management to AdminC  
   - State after: AdminA manages [PubKey1], AdminB manages [PubKey2], AdminC manages [PubKey3]

4. Proposal X created requiring 60% approval (6 out of 10 votes)

5. Transaction from AdminA: `Approve(ProposalX)`
   - GetManagedPubkeys(AdminA) returns [PubKey1] (count=1, passes check)
   - Returns Address(PubKey1), adds to proposal.Approvals
   - Success: 1 vote recorded

6. Transaction from AdminB: `Approve(ProposalX)`
   - GetManagedPubkeys(AdminB) returns [PubKey2] (count=1, passes check)
   - Returns Address(PubKey2), adds to proposal.Approvals
   - Success: 2 votes recorded

7. Transaction from AdminC: `Approve(ProposalX)`
   - GetManagedPubkeys(AdminC) returns [PubKey3] (count=1, passes check)
   - Returns Address(PubKey3), adds to proposal.Approvals
   - Success: 3 votes recorded

**Expected vs Actual Result**:
- **Expected**: Entity controlling 3 nodes should contribute 3 votes total, but be blocked from voting if admin setup suggests manipulation
- **Actual**: Same entity successfully votes 3 separate times, each vote counted in threshold calculations

**Success Condition**: After step 7, `proposal.Approvals.Count` contains 3 addresses controlled by the same entity, each counted toward the approval threshold. If 3 legitimate members also approve, the proposal reaches 6/10 (60%) and can be released, even though effective consensus is only 6 unique entities (not the required 6 independent votes).

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L80-92)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached = IsVoteThresholdReached(proposal, organization, parliamentMembers);
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L129-133)
```csharp
        var managedPubkey = State.ElectionContract.GetManagedPubkeys.Call(Context.Sender);
        if (!managedPubkey.Value.Any()) throw new AssertionException("Unauthorized sender.");

        if (managedPubkey.Value.Count > 1)
            throw new AssertionException("Admin with multiple managed pubkeys cannot handle proposal.");
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L190-199)
```csharp
    private void AssertProposalNotYetVotedByMember(ProposalInfo proposal, Address parliamentMemberAddress)
    {
        Assert(!CheckProposalAlreadyVotedBy(proposal, parliamentMemberAddress), "Already approved.");
    }

    private bool CheckProposalAlreadyVotedBy(ProposalInfo proposal, Address address)
    {
        return proposal.Approvals.Contains(address) || proposal.Rejections.Contains(address) ||
               proposal.Abstentions.Contains(address);
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L19-57)
```csharp
    public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

        // Permission check
        var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
            }
        }

        State.CandidateAdmins[pubkey] = input.Admin;

        var pubkeyByteString = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(pubkey));

        var newAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[input.Admin] ?? new PubkeyList();
        if (!newAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            newAdminManagedPubkeys.Value.Add(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[input.Admin] = newAdminManagedPubkeys;

        var oldAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender] ?? new PubkeyList();
        if (oldAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            oldAdminManagedPubkeys.Value.Remove(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[Context.Sender] = oldAdminManagedPubkeys;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L78-94)
```csharp
    public override Empty Approve(Hash input)
    {
        var parliamentMemberAddress = GetAndCheckActualParliamentMemberAddress();
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedByMember(proposal, parliamentMemberAddress);
        proposal.Approvals.Add(parliamentMemberAddress);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = parliamentMemberAddress,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Approve),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
```
