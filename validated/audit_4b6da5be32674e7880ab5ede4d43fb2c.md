# Audit Report

## Title
Association Contract Threshold Validation Allows Governance Deadlock

## Summary
The `Validate(Organization)` function in the Association contract contains insufficient threshold validation that allows creation of organizations where proposals can enter permanent deadlock states. The validation checks two separate pairwise sum constraints but fails to verify that the combined sum of all three thresholds guarantees deterministic proposal outcomes.

## Finding Description

The vulnerability exists in the threshold validation logic [1](#0-0)  which performs two independent checks but misses a critical combined constraint.

The validation ensures:
1. `MaximalAbstentionThreshold + MinimalApprovalThreshold <= organizationMemberCount`
2. `MaximalRejectionThreshold + MinimalApprovalThreshold <= organizationMemberCount`

However, this does not prevent configurations where `MaximalRejectionThreshold + MaximalAbstentionThreshold + MinimalApprovalThreshold = organizationMemberCount + 1`.

When proposals are evaluated for release [2](#0-1) , the system checks three mutually exclusive conditions:

- **Rejected** if `rejectionMemberCount > MaximalRejectionThreshold` (strict inequality) [3](#0-2) 
- **Abstained** if `abstentionMemberCount > MaximalAbstentionThreshold` (strict inequality) [4](#0-3) 
- **Approved** if `approvedMemberCount >= MinimalApprovalThreshold` (non-strict inequality) [5](#0-4) 

The asymmetry between strict and non-strict inequalities creates a gap where all three conditions can simultaneously fail, resulting in an undecidable proposal state.

**Concrete Example:**
For an organization with 10 members and thresholds:
- `MinimalApprovalThreshold = 5`
- `MaximalRejectionThreshold = 3`
- `MaximalAbstentionThreshold = 3`
- Sum = 11 = memberCount + 1

This passes validation (3+5=8≤10 ✓, 3+5=8≤10 ✓).

When all 10 members vote as: 4 approvals, 3 rejections, 3 abstentions:
- Not rejected: 3 > 3 = FALSE
- Not abstained: 3 > 3 = FALSE
- Not approved: 4 >= 5 = FALSE

The proposal enters deadlock and cannot be released [6](#0-5) .

## Impact Explanation

**HIGH Severity - Governance DoS**

The vulnerability directly violates the fundamental governance invariant that all proposals must reach a deterministic outcome. Organizations with deadlock-prone configurations experience:

1. **Critical Governance Paralysis**: Time-sensitive proposals (emergency responses, parameter updates, fund releases) cannot be executed, rejected, or resolved, leaving the organization incapable of responding to urgent situations.

2. **Irreversible Configuration Lock**: Organization thresholds can only be changed through proposals [7](#0-6) . If a threshold-change proposal itself enters deadlock, the organization permanently loses the ability to fix its broken configuration.

3. **Resource Exhaustion**: Deadlocked proposals remain in state until expiration [8](#0-7) , occupying proposal slots and preventing new proposals from being created if there are slot limits.

4. **Protocol Trust Degradation**: Members who vote in good faith see their collective will ignored with no resolution path, fundamentally breaking the social contract of decentralized governance.

## Likelihood Explanation

**HIGH Likelihood - Easily Triggerable**

The vulnerability has high exploitability:

1. **Unrestricted Entry Point**: The `CreateOrganization` method [9](#0-8)  is public with no authorization checks, allowing any user to create organizations with malicious threshold configurations.

2. **Zero Economic Barrier**: Organization creation requires no staking, approval, or fee beyond transaction costs, making both malicious and accidental misconfiguration trivial.

3. **Trivial Attack Calculation**: An attacker only needs to calculate threshold values satisfying `MaximalRejectionThreshold + MaximalAbstentionThreshold + MinimalApprovalThreshold = organizationMemberCount + 1` while passing the existing validation constraints.

4. **Legitimate Misconfiguration Risk**: Organizations attempting balanced governance (e.g., "require 60% approval, allow max 30% rejection, tolerate 20% abstention") can inadvertently create deadlock-prone configurations without malicious intent.

5. **Delayed Detection**: The validation passes during organization creation, and the deadlock only manifests during actual voting, making it difficult to detect before proposals become stuck.

## Recommendation

Add a combined threshold validation constraint to ensure deterministic outcomes:

```csharp
// In Association_Helper.cs Validate() method, add after line 80:
proposalReleaseThreshold.MaximalRejectionThreshold + 
proposalReleaseThreshold.MaximalAbstentionThreshold + 
proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount
```

This ensures that for any complete vote distribution, at least one of the three conditions (rejected, abstained, or approved) must be satisfied, guaranteeing deterministic proposal outcomes.

## Proof of Concept

```csharp
[Fact]
public async Task CreateOrganization_Deadlock_Configuration_Test()
{
    // Setup: 10 member organization with deadlock-prone thresholds
    var memberCount = 10;
    var members = Accounts.Take(memberCount).Select(a => a.Address).ToList();
    
    var createInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { members }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 5,      // Need 5 to approve
            MaximalRejectionThreshold = 3,     // Max 3 rejections allowed
            MaximalAbstentionThreshold = 3,    // Max 3 abstentions allowed
            MinimalVoteThreshold = 10          // All must vote
            // Sum = 5 + 3 + 3 = 11 = memberCount + 1 (DEADLOCK CONFIG)
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { members[0] }
        }
    };
    
    // Create organization - validation passes incorrectly
    var orgResult = await AssociationContractStub.CreateOrganization.SendAsync(createInput);
    orgResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var orgAddress = orgResult.Output;
    
    // Create proposal
    var proposalInput = new CreateProposalInput
    {
        OrganizationAddress = orgAddress,
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContractStub.Transfer),
        Params = new TransferInput { To = members[1], Amount = 100, Symbol = "ELF" }.ToByteString(),
        ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(1)
    };
    
    var proposer = GetAssociationContractTester(Accounts[0].KeyPair);
    var proposalResult = await proposer.CreateProposal.SendAsync(proposalInput);
    var proposalId = proposalResult.Output;
    
    // Vote: 4 approve, 3 reject, 3 abstain (sums to 10)
    for (int i = 0; i < 4; i++)
        await GetAssociationContractTester(Accounts[i].KeyPair).Approve.SendAsync(proposalId);
    
    for (int i = 4; i < 7; i++)
        await GetAssociationContractTester(Accounts[i].KeyPair).Reject.SendAsync(proposalId);
    
    for (int i = 7; i < 10; i++)
        await GetAssociationContractTester(Accounts[i].KeyPair).Abstain.SendAsync(proposalId);
    
    // Check proposal state - should show ToBeReleased = false despite all votes cast
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ApprovalCount.ShouldBe(4);   // 4 < 5 (not approved)
    proposal.RejectionCount.ShouldBe(3);  // 3 = 3 (not rejected, needs >)
    proposal.AbstentionCount.ShouldBe(3); // 3 = 3 (not abstained, needs >)
    proposal.ToBeReleased.ShouldBe(false); // DEADLOCK: Cannot be released!
    
    // Attempt to release - should fail
    var releaseResult = await proposer.Release.SendWithExceptionAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved");
    
    // Proposal is permanently stuck until expiration
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L77-80)
```csharp
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L282-289)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
    }
```
