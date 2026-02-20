# Audit Report

## Title
Association Governance Bypass via Post-Vote Member List Manipulation

## Summary
The Association contract's rejection threshold enforcement can be bypassed by removing members who voted to reject a proposal after voting has occurred but before the proposal is released. The rejection count is recalculated using the current member list rather than a snapshot at voting time, enabling execution of proposals that should remain permanently rejected.

## Finding Description

The vulnerability exists in the rejection threshold calculation logic. When the `Release` method is called, it invokes `IsReleaseThresholdReached()` to validate the proposal can be executed. [1](#0-0)  This function checks if the proposal has been rejected by calling `IsProposalRejected()`. [2](#0-1) 

The critical flaw is in how `IsProposalRejected()` counts rejections. It filters the stored rejection addresses against the CURRENT organization member list. [3](#0-2)  This creates a time-of-check/time-of-use (TOCTOU) vulnerability because:

1. **At voting time**: When members call `Reject()`, their addresses are permanently stored in `proposal.Rejections`. [4](#0-3) 

2. **Between voting and release**: The organization can modify its member list through `RemoveMember`, `AddMember`, or `ChangeMember` methods. [5](#0-4)  These functions require only that the sender is the organization itself and contain no validation for active proposals or impact on existing votes.

3. **At release time**: The rejection count is recalculated by filtering stored rejection addresses against the CURRENT (potentially modified) member list, not the member list at voting time.

The organization can call its own member manipulation functions through the virtual call mechanism. When `Release` executes a proposal, it uses `SendVirtualInlineBySystemContract` to call the target method with the organization address as sender. [6](#0-5) 

**Attack Sequence:**
- Organization has 10 members, `MaximalRejectionThreshold = 3`
- Proposal A (malicious) receives 6 approvals and 4 rejections (rejected: 4 > 3)
- Create Proposal B targeting `RemoveMember` for one rejector
- Proposal B receives 6 approvals, 3 rejections (passes: 3 ≤ 3)
- Release Proposal B (removes member M)
- Proposal A's rejection count recalculates as 3 (member M no longer counted)
- Release Proposal A (now passes: 3 ≤ 3)

## Impact Explanation

**CRITICAL Severity** - This vulnerability completely undermines the rejection threshold protection mechanism, which is a fundamental governance safeguard in the Association contract.

**Broken Invariant**: The security guarantee that "proposals with rejections exceeding MaximalRejectionThreshold cannot be released" is violated. Once a proposal receives sufficient rejections to be permanently blocked, it should remain blocked regardless of subsequent organization changes.

**Concrete Harm**:
- Organizations can execute arbitrary proposals that were legitimately rejected by sufficient members
- Minority protections are nullified - members who voted to reject actions can have their votes retroactively invalidated
- No external compromise required - legitimate organization mechanisms are misused
- All Association-based governance organizations are affected, particularly those relying on rejection thresholds to prevent harmful actions (fund transfers, parameter changes, permission grants)

The impact is governance integrity breach rather than direct fund loss, but the consequences can be severe depending on what the manipulated proposals control (treasury funds, contract permissions, protocol parameters).

## Likelihood Explanation

**MEDIUM Likelihood** - The attack requires coordination among organization members but is fully executable through normal contract interactions.

**Attacker Profile**: This is not an external attack but rather collusion among organization members who control sufficient votes to pass a member removal proposal. They must meet `MinimalApprovalThreshold` but NOT `MaximalRejectionThreshold + 1` on the removal proposal.

**Preconditions**:
- At least one proposal with excessive rejections exists (target)
- Attackers can create and pass a member manipulation proposal (easier threshold)
- Multiple proposals can be active simultaneously (confirmed - no code prevents this)
- No time restrictions prevent sequential releases

**Attack Complexity**: 
- Create malicious Proposal A that receives excessive rejections
- Create Proposal B targeting RemoveMember/ChangeMember for rejector(s)
- Coordinate votes to pass Proposal B while keeping rejections ≤ threshold
- Release Proposal B first, then Proposal A
- Total cost: transaction fees for 2 proposals + coordination cost

**Detection**: The manipulation creates an audit trail (MemberRemoved events) but may not trigger real-time alerts before the vulnerable proposal is released.

**Economic Rationality**: For high-value governance decisions (e.g., treasury access, protocol upgrades), the benefit of bypassing rejection threshold far exceeds transaction costs.

## Recommendation

Implement a snapshot mechanism that captures the organization member list at proposal creation or first vote time, and use this snapshot for all threshold calculations:

```csharp
// In ProposalInfo, add a snapshot field
repeated aelf.Address member_list_snapshot = 14;

// In CreateNewProposal, capture snapshot
proposal.MemberListSnapshot.AddRange(organization.OrganizationMemberList.OrganizationMembers);

// In IsProposalRejected, use snapshot instead of current list
private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
{
    var memberListToCheck = proposal.MemberListSnapshot.Any() 
        ? proposal.MemberListSnapshot 
        : organization.OrganizationMemberList;
    var rejectionMemberCount = proposal.Rejections.Count(memberListToCheck.Contains);
    return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
}
```

Alternatively, prevent member list modifications when active proposals exist, or finalize vote counts before release eligibility.

## Proof of Concept

```csharp
[Fact]
public async Task GovernanceBypass_RemoveMemberAfterRejection_Test()
{
    // Setup organization with 10 members, MaximalRejectionThreshold = 3
    var members = new[] { Reviewer1, Reviewer2, Reviewer3, 
        Accounts[4].Address, Accounts[5].Address, Accounts[6].Address,
        Accounts[7].Address, Accounts[8].Address, Accounts[9].Address, Accounts[10].Address };
    
    var organizationAddress = await AssociationContractStub.CreateOrganization.SendAsync(
        new CreateOrganizationInput
        {
            OrganizationMemberList = new OrganizationMemberList { OrganizationMembers = { members } },
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 6,
                MaximalRejectionThreshold = 3,
                MinimalVoteThreshold = 6
            },
            ProposerWhiteList = new ProposerWhiteList { Proposers = { Reviewer1 } }
        });

    // Create malicious Proposal A
    var proposalA = await AssociationContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        OrganizationAddress = organizationAddress.Output,
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContractStub.Transfer),
        Params = new TransferInput { To = DefaultSender, Amount = 1000 }.ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });

    // Vote on Proposal A: 6 approvals, 4 rejections (BLOCKED: 4 > 3)
    for (int i = 0; i < 6; i++)
        await GetAssociationContractTester(Accounts[i+1].KeyPair).Approve.SendAsync(proposalA.Output);
    for (int i = 6; i < 10; i++)
        await GetAssociationContractTester(Accounts[i+1].KeyPair).Reject.SendAsync(proposalA.Output);

    // Verify Proposal A is blocked
    var proposalAInfo = await AssociationContractStub.GetProposal.CallAsync(proposalA.Output);
    proposalAInfo.ToBeReleased.ShouldBe(false);

    // Create Proposal B to remove one rejector
    var proposalB = await AssociationContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        OrganizationAddress = organizationAddress.Output,
        ToAddress = AssociationContractAddress,
        ContractMethodName = nameof(AssociationContractStub.RemoveMember),
        Params = Accounts[10].Address.ToByteString(), // Remove last rejector
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });

    // Vote on Proposal B: 6 approvals, 3 rejections (PASSES: 3 <= 3)
    for (int i = 0; i < 6; i++)
        await GetAssociationContractTester(Accounts[i+1].KeyPair).Approve.SendAsync(proposalB.Output);
    for (int i = 6; i < 9; i++)
        await GetAssociationContractTester(Accounts[i+1].KeyPair).Reject.SendAsync(proposalB.Output);

    // Release Proposal B (removes member)
    await AssociationContractStub.Release.SendAsync(proposalB.Output);

    // NOW Proposal A should pass (rejection count recalculates: 3 <= 3)
    var proposalAInfoAfter = await AssociationContractStub.GetProposal.CallAsync(proposalA.Output);
    proposalAInfoAfter.ToBeReleased.ShouldBe(true); // VULNERABILITY: Now releasable!
    
    // Can release previously blocked proposal
    var releaseResult = await AssociationContractStub.Release.SendAsync(proposalA.Output);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L150-150)
```csharp
        proposal.Rejections.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L188-188)
```csharp
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L26-28)
```csharp
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```
