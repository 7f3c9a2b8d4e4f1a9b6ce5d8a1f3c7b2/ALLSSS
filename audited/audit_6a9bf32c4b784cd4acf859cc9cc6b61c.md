### Title
Approval Count Race Condition: Membership Changes Can Invalidate Legitimately Approved Proposals

### Summary
The Association contract filters approval votes by current membership at release time, allowing legitimately approved proposals to become un-releaseable if approving members are removed between approval and release. This creates a governance denial-of-service vector where adversaries can block proposals by strategically removing members who have already voted, causing the approval count to retroactively fall below the required threshold.

### Finding Description

The vulnerability exists in the `CheckEnoughVoteAndApprovals` function where approval counting uses current organization membership rather than membership at the time of voting. [1](#0-0) 

At line 49, the code filters approvals by checking if each approving address is in the **current** `organization.OrganizationMemberList`. The proposal's approval list contains addresses that were valid members when they voted, but these are rechecked against the organization's current membership at release time.

Organization membership can be modified through three methods that are callable by the organization itself: [2](#0-1) [3](#0-2) 

When a proposal is released, the threshold check is performed: [4](#0-3) 

The `IsReleaseThresholdReached` call at line 188 ultimately invokes `CheckEnoughVoteAndApprovals`, which recounts approvals using the current membership. If members have been removed, their prior approvals no longer count, potentially dropping the count below `MinimalApprovalThreshold`.

The approval storage structure shows that votes are stored as address lists without membership snapshots: [5](#0-4) 

### Impact Explanation

**Operational Impact - Governance Denial of Service:**
- Proposals that legitimately met approval thresholds become permanently un-releaseable
- Critical governance actions (security fixes, emergency responses, parameter updates) can be blocked
- Adversaries with sufficient voting power can systematically block any proposal by:
  1. Allowing it to gather approvals
  2. Creating and rushing through a competing proposal to remove one approver
  3. The original proposal fails with "Not approved" when release is attempted

**Affected Parties:**
- Organizations relying on Association multi-sig governance
- Proposal creators whose legitimate proposals are invalidated
- Systems depending on timely governance execution

**Severity Justification:**
This is HIGH severity (approaching Critical for governance-critical systems) because:
- It allows targeted denial of service on specific governance proposals
- It violates the governance invariant that approved proposals remain approved
- It can be weaponized in contentious governance scenarios
- While it doesn't directly steal funds, blocking governance can enable or extend other attacks
- The validation checks at line 272 prevent permanent governance lockup but not selective proposal blocking [6](#0-5) 

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker needs voting power to approve member removal proposals
- If attacker has this power, they likely have enough influence to cause governance disruption
- Does not require external/untrusted role - can be executed by organization members

**Attack Complexity:**
- Moderate complexity: requires coordinating two proposals (target proposal + member removal)
- Timing window exists between when proposal meets threshold and when proposer attempts release
- Release can only be called by the original proposer, giving a predictable window [7](#0-6) 

**Feasibility Conditions:**
- More likely in organizations with frequent membership changes
- Can occur accidentally (legitimate member removal invalidates pending proposals) or maliciously
- Window of vulnerability is proportional to delay between approval completion and release attempt
- No on-chain monitoring would detect this as abnormal until release fails

**Economic Rationality:**
- Low cost if attacker already has voting power
- High benefit if blocking specific proposals is valuable (e.g., preventing unfavorable governance changes)
- More probable in contentious governance situations with competing factions

### Recommendation

**Option 1: Snapshot Membership at Proposal Creation (Recommended)**
Modify `ProposalInfo` to include a membership snapshot and use it for vote counting:

```protobuf
message ProposalInfo {
    // ... existing fields ...
    OrganizationMemberList membership_snapshot = 14;
}
```

In `CreateNewProposal`, capture membership:
```csharp
var organization = State.Organizations[input.OrganizationAddress];
proposal.MembershipSnapshot = organization.OrganizationMemberList;
```

In `CheckEnoughVoteAndApprovals`, use the snapshot:
```csharp
var approvedMemberCount = proposal.Approvals.Count(proposal.MembershipSnapshot.Contains);
```

**Option 2: Count All Historical Votes**
Remove the membership filter entirely and count all votes:
```csharp
var approvedMemberCount = proposal.Approvals.Count();
```

This accepts that votes from former members persist, which may be undesirable.

**Option 3: Invalidate Proposals on Membership Changes**
When membership changes, emit events identifying affected proposals and allow cleanup. This is complex and error-prone.

**Test Cases to Add:**
1. Test where member is removed after approving, then release is attempted → should still succeed (with fix)
2. Test where member is changed (old member had voted) → verify vote counting
3. Test edge case where removing member would cause threshold to become impossible → should fail validation

### Proof of Concept

**Initial State:**
- Organization with members: `[AddressA, AddressB, AddressC, AddressD, AddressE]`
- `MinimalApprovalThreshold = 3`
- `MinimalVoteThreshold = 3`

**Transaction Sequence:**

1. **Proposer creates Proposal_Target:**
   - `CreateProposal` to execute some target action
   - Stored with empty approval list

2. **Members approve Proposal_Target:**
   - `AddressA.Approve(Proposal_Target)` → approvals: [A]
   - `AddressB.Approve(Proposal_Target)` → approvals: [A, B]
   - `AddressC.Approve(Proposal_Target)` → approvals: [A, B, C]
   - At this point: `approvedMemberCount = 3 >= 3` ✓ threshold met

3. **Adversary blocks proposal:**
   - `CreateProposal(Proposal_RemoveMember)` to call `RemoveMember(AddressA)`
   - Quickly gather approvals and `Release(Proposal_RemoveMember)`
   - `AddressA` is removed from `OrganizationMemberList`
   - Organization now: `[AddressB, AddressC, AddressD, AddressE]`

4. **Original proposer attempts release:**
   - `Proposer.Release(Proposal_Target)`
   - `CheckEnoughVoteAndApprovals` executes:
     - `proposal.Approvals = [A, B, C]`
     - `organization.OrganizationMemberList.Contains(A)` → FALSE
     - `organization.OrganizationMemberList.Contains(B)` → TRUE
     - `organization.OrganizationMemberList.Contains(C)` → TRUE
     - `approvedMemberCount = 2`
   - Check: `2 >= 3` → FALSE
   - Transaction fails with error: "Not approved"

**Expected Result:** Proposal_Target should release successfully since it met threshold when approved.

**Actual Result:** Proposal_Target cannot be released due to retroactive approval invalidation.

**Success Condition:** Transaction reverts with "Not approved" message, confirming the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-59)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-201)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);

        Context.Fire(new ProposalReleased
        {
            ProposalId = input,
            OrganizationAddress = proposalInfo.OrganizationAddress
        });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L248-264)
```csharp
    public override Empty ChangeMember(ChangeMemberInput input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
        Assert(removeResult, "Remove member failed.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberChanged
        {
            OrganizationAddress = Context.Sender,
            OldMember = input.OldMember,
            NewMember = input.NewMember
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L266-280)
```csharp
    public override Empty RemoveMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input);
        Assert(removeResult, "Remove member failed.");
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberRemoved
        {
            OrganizationAddress = Context.Sender,
            Member = input
        });
        return new Empty();
    }
```

**File:** protobuf/association_contract.proto (L76-103)
```text
message ProposalInfo {
    // The proposal ID.
    aelf.Hash proposal_id = 1;
    // The method that this proposal will call when being released.
    string contract_method_name = 2;
    // The address of the target contract.
    aelf.Address to_address = 3;
    // The parameters of the release transaction.
    bytes params = 4;
    // The date at which this proposal will expire.
    google.protobuf.Timestamp expired_time = 5;
    // The address of the proposer of this proposal.
    aelf.Address proposer = 6;
    // The address of this proposals organization.
    aelf.Address organization_address = 7;
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
    // Url is used for proposal describing.
    string proposal_description_url = 11;
    // Title of this proposal.
    string title = 12;
    // Description of this proposal.
    string description = 13;
}
```
