### Title
Inconsistent Membership Filtering in Vote Threshold Check Allows Governance Bypass

### Summary
The `CheckEnoughVoteAndApprovals` function inconsistently applies membership filtering when checking vote thresholds. While approval, rejection, and abstention counts filter by current organization membership, the total vote count includes votes from removed members. This allows proposals to meet the MinimalVoteThreshold requirement with artificially inflated participation from ex-members, undermining governance quorum requirements.

### Finding Description
The vulnerability exists in the `CheckEnoughVoteAndApprovals` function [1](#0-0) . 

The root cause is an inconsistent application of membership filtering across threshold checks:

**Consistent membership filtering (current members only):**
- Approval count: [2](#0-1) 
- Rejection count: [3](#0-2) 
- Abstention count: [4](#0-3) 

**Missing membership filtering (counts all voters including ex-members):**
- Total vote threshold check: [5](#0-4) 

When members vote and are subsequently removed via `RemoveMember` [6](#0-5) , their votes remain in the proposal's vote lists [7](#0-6)  but they are removed from the organization member list. The `RemoveMember` operation does not clear existing votes from proposals.

This creates a state where approval/rejection/abstention checks correctly reflect only current member votes, but the total vote count incorrectly includes votes from ex-members, allowing proposals to pass the MinimalVoteThreshold with lower actual participation than intended.

### Impact Explanation
**Governance Integrity Compromise:** Proposals can be released without meeting the intended minimum participation requirement from current active members. 

**Quantified Impact:** In an organization with MinimalVoteThreshold = 7 and 10 members, an attacker can:
1. Obtain 5 approvals + 2 abstentions (7 total votes, meets threshold)
2. Have the 2 abstaining members removed
3. Proposal still releasable with only 5/8 (62.5%) current member participation instead of the intended 7/8 (87.5%)

**Affected Parties:** All Association-based organizations relying on MinimalVoteThreshold for governance quorum enforcement. This undermines the core governance model where proposals should require a certain level of active member participation.

**Severity Justification:** HIGH - This directly violates the governance invariant that "organization thresholds must be correctly enforced." It enables systematic bypass of participation requirements through normal member management operations.

### Likelihood Explanation
**Attacker Capabilities:** Requires being in the proposer whitelist [8](#0-7)  and ability to coordinate with some organization members. Does not require compromising any privileged roles beyond normal proposer access.

**Attack Complexity:** LOW - Uses standard contract methods (CreateProposal, Approve/Abstain, RemoveMember) without any complex timing or state manipulation. Member removal is a normal governance operation accessible through proposals.

**Feasibility Conditions:** 
- Organization must use MinimalVoteThreshold > MinimalApprovalThreshold (common configuration to ensure broad participation)
- Ability to coordinate member voting then removal (either through proposal or if attacker controls the organization address)
- The RemoveMember method [6](#0-5)  requires Context.Sender to be the organization address, achievable through proposal execution

**Detection Constraints:** Difficult to detect as member additions/removals are legitimate operations. The exploit leaves no obvious traces beyond normal governance activity.

**Probability:** MEDIUM-HIGH - While requiring coordination, the attack uses only standard governance operations and the vulnerability is present in every Association organization using MinimalVoteThreshold.

### Recommendation
**Code-Level Mitigation:**
Modify line 56-57 in `CheckEnoughVoteAndApprovals` to filter votes by current membership:

```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
    proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
    proposal.Rejections.Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**Alternative Approach:**
When removing members, optionally clear their votes from active proposals or add a grace period during which removed members' votes are still counted.

**Invariant Checks:**
Add validation in `IsReleaseThresholdReached` [9](#0-8)  to ensure all threshold calculations use consistent membership filtering.

**Test Cases:**
1. Test that MinimalVoteThreshold check only counts current members
2. Test proposal status changes after member removal
3. Test edge case where removing voters causes proposal to no longer meet thresholds

### Proof of Concept
**Initial State:**
- Organization: 10 members {M1, M2, M3, M4, M5, M6, M7, M8, M9, M10}
- MinimalVoteThreshold = 7
- MinimalApprovalThreshold = 5
- MaximalAbstentionThreshold = 2
- Proposer: M1 (in whitelist)

**Attack Sequence:**
1. M1 creates proposal via `CreateProposal` [10](#0-9) 
2. M2, M3, M4, M5, M6 call `Approve` on proposal (5 approvals)
3. M7, M8 call `Abstain` on proposal (2 abstentions)
4. Total votes = 7, meets MinimalVoteThreshold; Approvals = 5, meets MinimalApprovalThreshold
5. Before release, organization executes proposal to call `RemoveMember` for M7 and M8
6. Organization now has 8 members, but proposal vote lists unchanged

**Expected Result:** Proposal should fail threshold check as only 5/8 current members voted (62.5% < 87.5%)

**Actual Result:** 
- Line 49 counts: 5 approvals from current members ≥ 5 ✓
- Line 43 counts: 0 abstentions from current members ≤ 2 ✓
- Line 56-57 counts: 7 total votes (including M7, M8) ≥ 7 ✓
- Proposal passes all checks and can be released via `Release` [11](#0-10) 

**Success Condition:** Proposal releases successfully despite only 5 of 8 current members participating, bypassing the intended 7-member minimum participation requirement.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-32)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-37)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-43)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
```

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

**File:** contract/AElf.Contracts.Association/Association.cs (L107-112)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
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

**File:** protobuf/association_contract.proto (L91-96)
```text
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
```
