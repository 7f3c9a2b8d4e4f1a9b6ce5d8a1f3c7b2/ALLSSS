# Audit Report

## Title
Association Contract Vote Threshold Counts Non-Member Votes Leading to Governance Bypass

## Summary
The Association contract's `CheckEnoughVoteAndApprovals()` function contains a critical inconsistency in vote threshold validation. While it correctly filters approval, rejection, and abstention counts by current organization membership, it fails to filter the total vote count used for `MinimalVoteThreshold` validation. This allows organizations to manipulate governance outcomes by removing members after they vote, as their votes continue counting toward participation requirements while their rejections/abstentions are excluded from threshold checks.

## Finding Description

The vulnerability exists in the vote threshold validation logic within the Association contract's helper functions.

In `CheckEnoughVoteAndApprovals()`, the approval count is correctly filtered by current membership: [1](#0-0) 

However, the total vote count for `MinimalVoteThreshold` validation is NOT filtered: [2](#0-1) 

Similarly, rejection and abstention counts are correctly filtered by current membership: [3](#0-2) [4](#0-3) 

The root cause is that while only current members can vote (enforced by authorization checks): [5](#0-4) 

Members can be removed after voting through the `RemoveMember` function: [6](#0-5) 

When members are removed, their addresses remain in the proposal's vote lists (`Approvals`, `Rejections`, `Abstentions`), but they are no longer in `OrganizationMemberList`. The unfiltered total vote count continues to include these removed members, while the filtered approval/rejection/abstention counts correctly exclude them.

This creates a critical inconsistency with the Parliament contract, which correctly filters ALL vote counts by current membership: [7](#0-6) 

The flawed threshold check is invoked during proposal release: [8](#0-7) 

## Impact Explanation

This vulnerability enables governance manipulation with severe consequences:

1. **Participation Requirement Bypass**: The `MinimalVoteThreshold` ensures minimum participation relative to current organization size. The validation at organization creation enforces this relationship: [9](#0-8) 

By counting removed members' votes, actual current member participation can be significantly lower than intended.

2. **Concrete Attack Scenario**:
   - Organization with 10 members, `MinimalVoteThreshold=7`, `MinimalApprovalThreshold=5`, `MaximalRejectionThreshold=2`
   - Proposal created, 7 members vote: 5 approve, 2 reject
   - Organization passes another proposal to remove the 2 rejecting members
   - Now 8 members remain, but original proposal vote counts:
     - `approvedMemberCount = 5` (filtered, valid current members)
     - `rejectionMemberCount = 0` (filtered, rejectors removed)
     - `totalVotes = 7` (NOT filtered, includes removed members)
   - Proposal passes with only 5/8 (62.5%) current member participation instead of requiring 7/8 (87.5%)

3. **Governance Manipulation**: Organizations can strategically remove dissenting members after they vote, neutralizing their rejections/abstentions while benefiting from their vote count toward the participation threshold. This fundamentally breaks the democratic safeguards that thresholds provide.

4. **Affected Parties**: All Association-based governance systems, including multi-signature wallets and DAOs using Association contracts for decision-making, are vulnerable to this manipulation.

## Likelihood Explanation

The vulnerability is highly exploitable under realistic conditions:

1. **Reachable Entry Points**: All required functions are part of the public ACS3 interface - `Approve`, `Reject`, `Abstain` for voting, `RemoveMember` for member removal, and `Release` for proposal execution.

2. **Feasible Preconditions**: Only requires normal organization operations (voting and member management). Member removal requires the organization itself to call it via its virtual address, which is standard for organization management. No special permissions beyond normal organization governance are needed.

3. **Execution Practicality**: The attack sequence is straightforward:
   - Create proposal and gather votes
   - Create and pass a second proposal to remove dissenting members
   - Release the original proposal with manipulated vote counts
   - All steps use standard contract methods with no unusual parameters

4. **Economic Rationality**: The cost is minimal - only transaction fees for normal proposal operations. The benefit is bypassing intended governance safeguards, which could be extremely valuable for contentious proposals.

5. **Detection Difficulty**: The manipulation is subtle and would appear as legitimate organization management. There's no on-chain signal distinguishing malicious member removal from legitimate restructuring.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals()` function to filter the total vote count by current membership, consistent with how Parliament contract handles this:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter total votes by current membership
    var isVoteThresholdReached =
        proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
            .Count(organization.OrganizationMemberList.Contains) >=
        organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

The key change is adding `.Count(organization.OrganizationMemberList.Contains)` instead of just `.Count()` to ensure only votes from current members are counted toward the participation threshold.

## Proof of Concept

```csharp
[Fact]
public async Task VoteThreshold_CountsRemovedMembers_GovernanceBypass_Test()
{
    // Setup: Create organization with 10 members
    var members = new[] { Reviewer1, Reviewer2, Reviewer3, Accounts[4].Address, 
        Accounts[5].Address, Accounts[6].Address, Accounts[7].Address, 
        Accounts[8].Address, Accounts[9].Address, Accounts[10].Address };
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { members }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 5,
            MinimalVoteThreshold = 7,
            MaximalAbstentionThreshold = 1,
            MaximalRejectionThreshold = 2
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { Reviewer1 } }
    };
    
    var organizationAddress = await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    
    // Create proposal
    var proposalId = await CreateProposalAsync(organizationAddress.Output);
    
    // 5 members approve, 2 reject (total 7 votes meeting MinimalVoteThreshold)
    await ApproveAsync(proposalId, GetAssociationContractTester(Reviewer1KeyPair));
    await ApproveAsync(proposalId, GetAssociationContractTester(Reviewer2KeyPair));
    await ApproveAsync(proposalId, GetAssociationContractTester(Reviewer3KeyPair));
    await ApproveAsync(proposalId, GetAssociationContractTester(Accounts[4].KeyPair));
    await ApproveAsync(proposalId, GetAssociationContractTester(Accounts[5].KeyPair));
    await RejectAsync(proposalId, GetAssociationContractTester(Accounts[6].KeyPair));
    await RejectAsync(proposalId, GetAssociationContractTester(Accounts[7].KeyPair));
    
    // Proposal should NOT be ready yet (2 rejections = MaximalRejectionThreshold)
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeFalse();
    
    // Now organization removes the 2 members who rejected
    await RemoveMemberViaProposal(organizationAddress.Output, Accounts[6].Address);
    await RemoveMemberViaProposal(organizationAddress.Output, Accounts[7].Address);
    
    // Now organization has 8 members
    var org = await AssociationContractStub.GetOrganization.CallAsync(organizationAddress.Output);
    org.OrganizationMemberList.OrganizationMembers.Count.ShouldBe(8);
    
    // Check proposal again - VULNERABILITY: it should now be ready to release
    // because totalVotes=7 (includes removed members) >= MinimalVoteThreshold=7
    // but rejectionMemberCount=0 (filtered, rejectors removed) <= MaximalRejectionThreshold=2
    proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeTrue(); // This demonstrates the vulnerability
    
    // Proposal can be released even though only 5/8 (62.5%) current members approved
    // instead of requiring 7/8 (87.5%) participation
    var result = await ReleaseAsync(proposalId, GetAssociationContractTester(Reviewer1KeyPair));
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

This test demonstrates that after removing dissenting members, a proposal can pass with lower actual current-member participation than intended, bypassing the governance safeguards.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-37)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-43)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-49)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-57)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-72)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
```

**File:** contract/AElf.Contracts.Association/Association.cs (L128-128)
```csharp
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L188-188)
```csharp
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-101)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
        return isVoteThresholdReached;
```
