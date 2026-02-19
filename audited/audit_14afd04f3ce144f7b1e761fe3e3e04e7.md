# Audit Report

## Title
Insufficient MaximalRejectionThreshold Validation Allows Governance Bypass Through Threshold Misconfiguration

## Summary
The Association contract's organization validation allows `MaximalRejectionThreshold` to be set to `organizationMemberCount - MinimalApprovalThreshold`, enabling proposals to pass with minimal approvals despite overwhelming opposition. The rejection check uses strict greater-than comparison, meaning a proposal with 1 approval and 99 rejections (in a 100-member organization) can still be released, fundamentally subverting multi-signature governance.

## Finding Description

The vulnerability exists in the organization validation logic where `MaximalRejectionThreshold` can be configured to effectively disable rejection capability. The validation constraint permits `MaximalRejectionThreshold + MinimalApprovalThreshold <= organizationMemberCount` [1](#0-0) , which allows setting `MaximalRejectionThreshold = organizationMemberCount - MinimalApprovalThreshold`.

The rejection check uses a strict greater-than comparison where a proposal is only rejected when `rejectionMemberCount > MaximalRejectionThreshold` [2](#0-1) . This means when rejections equal `MaximalRejectionThreshold`, the proposal is NOT rejected.

Combined with the permissive validation, in a 100-member organization with `MinimalApprovalThreshold = 1` and `MaximalRejectionThreshold = 99`:
- 99 rejections result in `rejectionMemberCount = 99`
- Check: `99 > 99` evaluates to FALSE
- Proposal is NOT rejected despite 99% opposition

The proposal release flow confirms this vulnerability [3](#0-2)  where if the proposal is not rejected and has sufficient approvals, it can be released [4](#0-3) .

This validation occurs during organization creation via the publicly accessible `CreateOrganization` method [5](#0-4)  and can be updated through `ChangeOrganizationThreshold` [6](#0-5) .

## Impact Explanation

**Governance Subversion**: Organizations can be created or configured where the rejection mechanism is functionally disabled. A single approver (or minimal minority) can push through proposals against the will of the vast majority of members.

**Concrete Scenario**:
- 100-member organization with `MinimalApprovalThreshold = 1`, `MaximalRejectionThreshold = 99`, `MinimalVoteThreshold = 100`
- Attacker (organization member) proposes malicious action
- 1 member approves, 99 members reject
- Proposal passes and executes despite 99% rejection rate

**Severity**: This violates the fundamental purpose of Association contracts as multi-signature governance mechanisms. Organizations controlling significant protocol authority (cross-chain operations, token minting, treasury management) become vulnerable to minority control, affecting all contracts using Association organizations for governance.

## Likelihood Explanation

**Reachable Entry Point**: The `CreateOrganization` method is publicly accessible to any user with no special privileges required [5](#0-4) .

**Feasible Preconditions**:
- No barriers to creating organizations with malicious threshold configurations
- The validation passes for mathematically valid but semantically broken configurations [7](#0-6) 
- Once created, the organization address is immutable and the thresholds persist

**Execution Practicality**:
1. Attacker creates organization with manipulated thresholds
2. Gets minimal members to join or uses Sybil members
3. Proposes malicious actions (if in proposer whitelist)
4. Single approval from attacker suffices regardless of other rejections
5. Releases and executes proposal

**Detection Difficulty**: The configuration appears mathematically valid but is semantically broken. External observers may not realize the rejection mechanism is effectively disabled until malicious proposals pass.

## Recommendation

The validation should enforce a stricter constraint to prevent the rejection mechanism from being disabled. Two possible fixes:

**Option 1**: Change the rejection check to use greater-than-or-equal:
```csharp
return rejectionMemberCount >= organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**Option 2**: Strengthen the validation constraint to ensure meaningful rejection capability:
```csharp
proposalReleaseThreshold.MaximalRejectionThreshold + 
proposalReleaseThreshold.MinimalApprovalThreshold < organizationMemberCount;
```

This ensures that there's always at least one vote that, if cast as rejection, would actually reject the proposal, preventing configurations where the rejection threshold is unreachable.

## Proof of Concept

```csharp
[Fact]
public async Task GovernanceBypass_MinimalApprovalOverwhelmsRejection()
{
    // Create organization with 100 members, minimal approval=1, maximal rejection=99
    var members = new List<Address>();
    for (int i = 0; i < 100; i++)
    {
        members.Add(SampleAddress.AddressList[i]);
    }
    
    var createInput = new CreateOrganizationInput
    {
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 1,
            MaximalRejectionThreshold = 99,
            MinimalVoteThreshold = 100,
            MaximalAbstentionThreshold = 0
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { members[0] } },
        OrganizationMemberList = new OrganizationMemberList { OrganizationMembers = { members } }
    };
    
    var organizationAddress = await AssociationContractStub.CreateOrganization.SendAsync(createInput);
    
    // Create proposal
    var proposalId = await AssociationContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        OrganizationAddress = organizationAddress.Output,
        ContractMethodName = nameof(AssociationContractStub.ClearProposal),
        ToAddress = AssociationContractAddress,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
        Params = proposalId.ToByteString()
    });
    
    // 1 approval from attacker
    await AssociationContractStub.Approve.SendAsync(proposalId.Output);
    
    // 99 rejections from other members
    for (int i = 1; i < 100; i++)
    {
        var memberStub = GetAssociationContractStub(members[i]);
        await memberStub.Reject.SendAsync(proposalId.Output);
    }
    
    // Proposal should be rejected but can still be released
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId.Output);
    Assert.Equal(1, proposal.ApprovalCount);
    Assert.Equal(99, proposal.RejectionCount);
    Assert.True(proposal.ToBeReleased); // Vulnerability: can be released despite 99% rejection
    
    // Release succeeds
    var releaseResult = await AssociationContractStub.Release.SendAsync(proposalId.Output);
    Assert.True(releaseResult.TransactionResult.Status == TransactionResultStatus.Mined);
}
```

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-39)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L69-94)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            ProposerWhiteList = input.ProposerWhiteList,
            OrganizationMemberList = input.OrganizationMemberList,
            OrganizationHash = organizationHash,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization.");
        if (State.Organizations[organizationAddress] == null)
        {
            State.Organizations[organizationAddress] = organization;
            Context.Fire(new OrganizationCreated
            {
                OrganizationAddress = organizationAddress
            });
        }

        return organizationAddress;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L203-216)
```csharp
    public override Empty ChangeOrganizationThreshold(ProposalReleaseThreshold input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationThresholdChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerReleaseThreshold = input
        });
        return new Empty();
    }
```
