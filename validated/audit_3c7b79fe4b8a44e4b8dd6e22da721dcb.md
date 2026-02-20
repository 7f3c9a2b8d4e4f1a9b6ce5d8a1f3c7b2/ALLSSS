# Audit Report

## Title
Member Removal Invalidates Previously Approved Proposals Due to Retroactive Vote Counting

## Summary
The Association contract's `RemoveMember` function allows removal of organization members after they have voted on proposals. The vote counting logic only considers votes from current members, causing previously approved proposals to become permanently unreleasable when voting members are removed, breaking the fundamental governance invariant that approved proposals remain executable.

## Finding Description

The vulnerability exists in the interaction between member removal and vote counting mechanisms in the Association contract.

**Vote Counting Logic:** The proposal release threshold check filters votes by current membership. [1](#0-0)  The approval counting at line 49 uses `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)` which only counts votes from addresses currently in the organization member list. [2](#0-1)  The rejection counting similarly filters by current membership. [3](#0-2)  The abstention counting also filters by current membership.

**Member Removal Function:** [4](#0-3)  The `RemoveMember` function removes members from the organization and validates only structural organization constraints. It does not check whether the removed member has voted on any active proposals, nor does it clean up their votes from existing proposals.

**Insufficient Validation:** [5](#0-4)  The `Validate` method checks structural constraints between thresholds and member count but does not prevent removal of members who have voted on active proposals.

**Root Cause:** [6](#0-5)  Proposals store voter addresses permanently in their approval lists via the `Approve` method. [7](#0-6)  Similarly for rejections. [8](#0-7)  And abstentions. However, the counting logic filters these lists by current membership using `organization.OrganizationMemberList.Contains()`. [9](#0-8)  When a member who has voted is removed, their vote disappears from all threshold calculations retroactively, despite still being in the proposal's vote lists.

## Impact Explanation

**Governance Deadlock:** Proposals that had achieved the required approval threshold become permanently stuck and unreleasable after voting members are removed. [10](#0-9)  The `Release` method checks `IsReleaseThresholdReached` at line 188, which will fail for proposals whose voting members were removed. The proposal remains valid (not expired) but can never reach the threshold again if enough voting members are removed.

**Concrete Example:**
- Organization: 5 members [A, B, C, D, E]
- Thresholds: MinimalApprovalThreshold=3, MaximalRejectionThreshold=1
- Proposal receives 3 approvals from A, B, C (meets threshold, ready to release)
- Member A is removed via governance action
- New member count: 4 members [B, C, D, E]
- Validation passes: MaximalRejectionThreshold + MinimalApprovalThreshold = 1 + 3 = 4 ≤ 4 ✓ (checked at lines 79-80 of Validate)
- Approval count recalculated: only 2 (B, C counted) - A's vote no longer counts
- Proposal now fails threshold check: 2 < 3 (permanently unreleasable)

**Who is Affected:** All Association organizations, particularly those with active proposals during member transitions. This affects critical governance operations including treasury management, parameter changes, and cross-contract calls.

**Severity Justification:** HIGH - This breaks a fundamental governance invariant (approved proposals remain approved) and can lead to permanent loss of governance capability for critical operations.

## Likelihood Explanation

**Reachable Entry Point:** [4](#0-3)  The `RemoveMember` function is a public method callable through the organization's own governance process. It uses `Context.Sender` as the organization address at line 268, meaning it must be called via the organization's virtual address through a governance proposal.

**Feasible Preconditions:**
- Organization exists with active proposals (normal state)
- Members vote on proposals (intended functionality)
- Organization needs to remove members (normal operation for member turnover, departures, or security reasons)

**Execution Practicality:** 
1. Organization creates and votes on proposal X (reaches approval threshold)
2. Organization creates proposal Y to remove a member who voted on X
3. Proposal Y is approved and released via the normal `Release` method
4. Member is removed via `RemoveMember`
5. Proposal X becomes unreleasable despite having previously met threshold

**Attack Complexity:** Low - Can occur accidentally during normal operations or be exploited maliciously. An organization member could vote to approve a critical proposal, then propose and execute their own removal to block the critical proposal from ever executing.

**Economic Rationality:** Removing members costs only governance proposal execution fees. The damage (blocked proposals) far exceeds the cost, making this economically rational for malicious actors.

## Recommendation

Add validation in `RemoveMember` to prevent removal of members who have voted on any active (non-expired, non-released) proposals. Alternatively, implement a cleanup mechanism that removes the member's votes from all active proposals when they are removed from the organization.

**Option 1: Prevent removal of voting members**
- Before removing a member, iterate through active proposals
- Check if the member has voted (appears in Approvals, Rejections, or Abstentions)
- Reject removal if the member has voted on any active proposal

**Option 2: Clean up votes on removal**
- When removing a member, iterate through all active proposals
- Remove the member's address from Approvals, Rejections, and Abstentions lists
- This preserves the snapshot behavior where votes reflect current membership

## Proof of Concept

```csharp
[Fact]
public async Task RemoveMember_InvalidatesPreviouslyApprovedProposal_Test()
{
    // Setup: Create organization with 5 members and threshold of 3
    var minimalApproveThreshold = 3;
    var minimalVoteThreshold = 3;
    var maximalAbstentionThreshold = 0;
    var maximalRejectionThreshold = 1;
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3, DefaultSender, Accounts[4].Address }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = minimalApproveThreshold,
            MinimalVoteThreshold = minimalVoteThreshold,
            MaximalAbstentionThreshold = maximalAbstentionThreshold,
            MaximalRejectionThreshold = maximalRejectionThreshold
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer1 }
        }
    };
    
    var organizationAddress = (await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput)).Output;
    
    // Create a proposal
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    await TransferToOrganizationAddressAsync(organizationAddress);
    
    // Get 3 approvals (meets threshold)
    await ApproveAsync(Reviewer1KeyPair, proposalId);
    await ApproveAsync(Reviewer2KeyPair, proposalId);
    await ApproveAsync(Reviewer3KeyPair, proposalId);
    
    // Verify proposal is ready to release
    var proposalOutput = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalOutput.ToBeReleased.ShouldBeTrue(); // Proposal is approved
    
    // Now remove Reviewer1 via governance
    var removeMemberProposal = await CreateAssociationProposalAsync(
        Reviewer1KeyPair, 
        Reviewer1, 
        nameof(AssociationContractStub.RemoveMember), 
        organizationAddress);
    
    await ApproveAsync(Reviewer2KeyPair, removeMemberProposal);
    await ApproveAsync(Reviewer3KeyPair, removeMemberProposal);
    await ApproveAsync(DefaultSenderKeyPair, removeMemberProposal);
    
    // Release the removal proposal (using organization's virtual address)
    var organizationStub = GetAssociationContractTester(Reviewer1KeyPair);
    await organizationStub.Release.SendAsync(removeMemberProposal);
    
    // Now check the original proposal - it should no longer be releasable
    proposalOutput = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalOutput.ToBeReleased.ShouldBeFalse(); // BUG: Proposal is no longer approved!
    proposalOutput.ApprovalCount.ShouldBe(3); // Vote records still exist
    
    // Attempting to release now fails
    var releaseResult = await organizationStub.Release.SendWithExceptionAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved.");
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-39)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L41-45)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-81)
```csharp
    private bool Validate(Organization organization)
    {
        if (organization.ProposerWhiteList.Empty() ||
            organization.ProposerWhiteList.AnyDuplicate() ||
            organization.OrganizationMemberList.Empty() ||
            organization.OrganizationMemberList.AnyDuplicate())
            return false;
        if (organization.OrganizationAddress == null || organization.OrganizationHash == null)
            return false;
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var organizationMemberCount = organization.OrganizationMemberList.Count();
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L123-141)
```csharp
    public override Empty Approve(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Approve),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L143-161)
```csharp
    public override Empty Reject(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Rejections.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Reject),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L163-181)
```csharp
    public override Empty Abstain(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Abstentions.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Abstain),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
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

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L17-20)
```csharp
    public bool Contains(Address address)
    {
        return organizationMembers_.Contains(address);
    }
```
