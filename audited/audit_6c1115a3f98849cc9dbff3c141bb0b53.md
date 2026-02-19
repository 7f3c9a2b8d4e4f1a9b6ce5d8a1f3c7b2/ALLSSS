# Audit Report

## Title
Inconsistent Vote Counting Allows Governance Threshold Bypass Through Member Removal

## Summary
The Association contract contains a critical inconsistency in vote threshold validation. While rejection and abstention checks correctly filter votes by current membership, the minimum vote threshold check counts ALL votes including those from removed members. This allows attackers to bypass `MaximalAbstentionThreshold` and `MaximalRejectionThreshold` by removing opposing members after they vote.

## Finding Description

The vulnerability exists in the vote counting logic that determines whether a proposal can be released. When checking if sufficient votes have been cast, the contract inconsistently applies membership filtering.

The `IsProposalAbstained()` function correctly filters abstentions to only count votes from current organization members: [1](#0-0) 

Similarly, `IsProposalRejected()` filters rejections by current membership: [2](#0-1) 

However, in `CheckEnoughVoteAndApprovals()`, while approvals are correctly filtered by current membership at line 49, the total vote count at lines 55-57 does NOT filter by current membership: [3](#0-2) 

This inconsistency is exploitable because `RemoveMember()` can be called to remove members who have already voted, without any validation of active proposals or vote invalidation: [4](#0-3) 

While voting methods correctly enforce that only current members can vote at the time of voting: [5](#0-4) 

Once votes are cast, they remain in the proposal's vote lists (defined as `repeated aelf.Address` fields) even after member removal: [6](#0-5) 

The attack flow:
1. Malicious proposal P1 is created and voted on
2. Honest members abstain/reject, blocking the proposal due to `MaximalAbstentionThreshold` or `MaximalRejectionThreshold`
3. Attackers create and pass proposal P2 to remove the opposing members
4. Proposal P1 now passes because:
   - Abstentions/rejections from removed members no longer count (filtered check passes)
   - But their votes still count toward `MinimalVoteThreshold` (unfiltered check passes)
   - Approvals from current members meet `MinimalApprovalThreshold`

## Impact Explanation

This vulnerability allows attackers to completely bypass two critical governance safeguards designed to protect against minority-opposed proposals:
- `MaximalAbstentionThreshold`: Blocks proposals with too many abstentions (indicating lack of engagement)
- `MaximalRejectionThreshold`: Blocks proposals with too much active opposition

The concrete attack scenario:
- Organization with 15 members, thresholds: `MinimalVoteThreshold=10`, `MinimalApprovalThreshold=6`, `MaximalAbstentionThreshold=3`
- Attackers control 6 members, honest members are 9
- Malicious proposal created, 6 approve, 7 abstain
- Proposal correctly blocked (7 abstentions > 3 threshold)
- Attackers pass a second proposal removing the 7 abstaining members
- First proposal now evaluates as: Total votes=13 (includes removed members) ≥ 10, Approvals from current=6 ≥ 6, Abstentions from current=0 ≤ 3
- Malicious proposal executes despite originally failing governance checks

This compromises the integrity of Association governance, potentially leading to unauthorized fund transfers, configuration changes, or other malicious actions that the organization's threshold design intended to prevent.

## Likelihood Explanation

The attack is highly practical with realistic preconditions:

**Entry Points:** All standard public methods on the Association contract - `Approve()`, `Abstain()`, `RemoveMember()`, and `Release()` as defined in the ACS3 standard: [7](#0-6) 

**Feasible Preconditions:** Attackers need:
- Sufficient members to meet `MinimalApprovalThreshold` for both proposals (typically majority or significant minority)
- Access to proposer whitelist, which is often granted to organization members
- This is realistic for scenarios where attackers have significant but not complete organizational control

**Execution Practicality:** The attack sequence uses only standard governance operations without any special privileges beyond normal proposal execution rights.

**Detection:** While the attack leaves on-chain evidence (member removal followed by proposal release), by the time it's detected, the malicious proposal has already executed and caused damage.

**Economic Rationality:** If the malicious proposal yields sufficient value (e.g., transferring organization treasury funds), the cost of executing two proposals is negligible, making this economically rational for attackers.

## Recommendation

Modify `CheckEnoughVoteAndApprovals()` to filter the total vote count by current organization membership, maintaining consistency with how abstentions and rejections are counted:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;
    
    // FIX: Filter total votes by current membership
    var currentMemberVotes = proposal.Abstentions.Where(organization.OrganizationMemberList.Contains)
        .Concat(proposal.Approvals.Where(organization.OrganizationMemberList.Contains))
        .Concat(proposal.Rejections.Where(organization.OrganizationMemberList.Contains))
        .Count();
    
    var isVoteThresholdReached =
        currentMemberVotes >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

Alternatively, consider invalidating all active proposals when organization membership changes, or adding a check in `RemoveMember()` to prevent removal of members who have voted on active proposals.

## Proof of Concept

```csharp
[Fact]
public async Task VoteCountingBypass_ThroughMemberRemoval_Test()
{
    // Setup: Organization with 15 members
    // Thresholds: MinimalVote=10, MinimalApproval=6, MaximalAbstention=3
    var members = Enumerable.Range(0, 15).Select(i => SampleAddress.AddressList[i]).ToList();
    var organization = await CreateOrganizationAsync(
        members, 
        minimalApprovalThreshold: 6,
        minimalVoteThreshold: 10, 
        maximalAbstentionThreshold: 3
    );
    
    // Step 1: Create malicious proposal
    var maliciousProposal = await CreateProposalAsync(organization, "MaliciousAction");
    
    // Step 2: 6 attackers approve, 7 honest members abstain
    for (int i = 0; i < 6; i++)
        await ApproveAsync(maliciousProposal, members[i]);
    for (int i = 6; i < 13; i++)
        await AbstainAsync(maliciousProposal, members[i]);
    
    // Step 3: Verify proposal is blocked due to too many abstentions (7 > 3)
    var canRelease1 = await IsProposalReleasable(maliciousProposal);
    Assert.False(canRelease1); // Correctly blocked
    
    // Step 4: Create and approve proposal to remove abstaining members
    var removalProposal = await CreateProposalAsync(organization, "RemoveMember", 
        targetMember: members[6]); // Remove first abstaining member
    for (int i = 0; i < 6; i++)
        await ApproveAsync(removalProposal, members[i]);
    await ReleaseAsync(removalProposal);
    
    // Repeat for all 7 abstaining members...
    for (int i = 7; i < 13; i++) {
        var proposal = await CreateProposalAsync(organization, "RemoveMember", targetMember: members[i]);
        for (int j = 0; j < 6; j++)
            await ApproveAsync(proposal, members[j]);
        await ReleaseAsync(proposal);
    }
    
    // Step 5: Verify malicious proposal now passes
    var canRelease2 = await IsProposalReleasable(maliciousProposal);
    // BUG: Returns true because:
    // - Total votes = 13 (includes removed members) >= 10 ✓
    // - Approvals from current = 6 >= 6 ✓
    // - Abstentions from current = 0 <= 3 ✓
    Assert.True(canRelease2); // VULNERABILITY: Should still be false!
    
    // Malicious proposal can now be released despite originally failing governance checks
    await ReleaseAsync(maliciousProposal);
}
```

## Notes

This vulnerability affects the core governance invariants of the Association contract. The threshold parameters `MaximalAbstentionThreshold` and `MaximalRejectionThreshold` are explicitly designed to prevent proposals from passing when there's insufficient support or too much opposition. The inconsistent vote counting undermines this security guarantee.

The same pattern should be reviewed in Parliament and Referendum contracts to ensure they don't have similar inconsistencies in their threshold checking logic.

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

**File:** protobuf/acs3.proto (L19-60)
```text
service AuthorizationContract {
    // Create a proposal for which organization members can vote. 
    // When the proposal is released, a transaction will be sent to the specified contract.
    // Return id of the newly created proposal.
    rpc CreateProposal (CreateProposalInput) returns (aelf.Hash) {
    }
    
    // Approve a proposal according to the proposal ID.
    rpc Approve (aelf.Hash) returns (google.protobuf.Empty) {
    }
    
    // Reject a proposal according to the proposal ID.
    rpc Reject(aelf.Hash) returns (google.protobuf.Empty) {
    }

    // Abstain a proposal according to the proposal ID.
    rpc Abstain(aelf.Hash) returns (google.protobuf.Empty){
    }

    // Release a proposal according to the proposal ID and send a transaction to the specified contract.
    rpc Release(aelf.Hash) returns (google.protobuf.Empty){
    }
    
    // Change the thresholds associated with proposals.
    // All fields will be overwritten by the input value and this will affect all current proposals of the organization. 
    // Note: only the organization can execute this through a proposal.
    rpc ChangeOrganizationThreshold(ProposalReleaseThreshold)returns(google.protobuf.Empty) {
    }
    
    // Change the white list of organization proposer.
    // This method overrides the list of whitelisted proposers.
    rpc ChangeOrganizationProposerWhiteList(ProposerWhiteList) returns (google.protobuf.Empty){
    }
    
    // Create a proposal by system contracts,
    // and return id of the newly created proposal.
    rpc CreateProposalBySystemContract(CreateProposalBySystemContractInput) returns (aelf.Hash){
    }
    
    // Remove the specified proposal. If the proposal is in effect, the cleanup fails.
    rpc ClearProposal(aelf.Hash) returns (google.protobuf.Empty){
    }
```
