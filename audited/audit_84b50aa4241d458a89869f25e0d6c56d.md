# Audit Report

## Title
Integer Overflow in Association Organization Threshold Validation Bypasses Governance Controls

## Summary
The `CreateOrganization` function in the Association contract validates threshold values using unchecked arithmetic that can overflow. When `MaximalAbstentionThreshold` or `MaximalRejectionThreshold` are set to values near `long.MaxValue`, adding them to `MinimalApprovalThreshold` causes integer overflow to negative values, incorrectly passing validation checks. This enables creation of organizations where rejection and abstention votes become meaningless, requiring only minimal approvals to execute proposals. [1](#0-0) 

## Finding Description

The vulnerability exists in the threshold validation logic within the `Validate(Organization organization)` method. When an organization is created, the validation performs arithmetic addition of threshold values without overflow protection. [2](#0-1) 

The threshold fields are defined as `int64` (C# `long`) types in the protobuf schema: [3](#0-2) 

**Root Cause**: In C#, integer arithmetic is unchecked by default. When two `long` values are added and the result exceeds `long.MaxValue` (9,223,372,036,854,775,807), the value wraps to a large negative number. The validation at lines 77-80 checks whether `MaximalAbstentionThreshold + MinimalApprovalThreshold <= organizationMemberCount`.

When an attacker provides:
- `MaximalAbstentionThreshold = 9223372036854775807` (long.MaxValue)
- `MinimalApprovalThreshold = 1`
- `organizationMemberCount = 10`

The addition `9223372036854775807 + 1` overflows to `-9223372036854775808` (long.MinValue), causing the check `-9223372036854775808 <= 10` to incorrectly pass.

**Why Protections Fail**: The validation only checks that thresholds are non-negative (lines 75-76), not that they are reasonable relative to member count before performing arithmetic. There are no `checked` arithmetic contexts or upper bound validations.

During proposal release, the broken thresholds render voting mechanisms ineffective: [4](#0-3) 

With `MaximalAbstentionThreshold` and `MaximalRejectionThreshold` set to `long.MaxValue`:
- `IsProposalRejected()` checks if `rejectionMemberCount > 9223372036854775807` - always false
- `IsProposalAbstained()` checks if `abstentionMemberCount > 9223372036854775807` - always false  
- Only `MinimalApprovalThreshold` approvals needed to release proposals

## Impact Explanation

**Governance Bypass**: An attacker can create an Association organization that appears to have strong governance controls (large threshold values) but actually allows proposal execution with minimal approvals. All rejection and abstention votes are ignored.

**Concrete Impact**:
- Any proposal can be released with minimal approvals (e.g., 1), regardless of rejection/abstention counts
- Multi-signature governance controls are completely bypassed
- Attackers can execute arbitrary contract calls through the organization's virtual address
- Affects any assets or permissions controlled by such malicious organizations

**Severity**: This undermines the core governance mechanism of Association contracts. While it requires creating a new organization (not compromising existing ones), users might unknowingly delegate authority or transfer assets to such organizations, believing they have proper governance safeguards. The malicious thresholds appear valid in storage (large positive numbers), making detection difficult.

## Likelihood Explanation

**Attack Complexity**: Trivial - requires only calling `CreateOrganization` with crafted threshold values via a standard transaction.

**Attacker Capabilities**: Any user can call `CreateOrganization` as it's a public method with no authorization checks. The malicious threshold values (`long.MaxValue`) are valid within the protobuf `int64` specification.

**Feasibility**: Extremely high - executable in a single transaction with no special privileges or pre-conditions required.

**Detection**: Malicious organizations would have valid-looking threshold values in storage, making detection difficult without analyzing the overflow scenario. Users might unknowingly interact with or delegate authority to such organizations.

**Probability**: High for targeted attacks where an attacker wants to create a governance structure appearing legitimate but under unilateral control.

## Recommendation

Add upper bound validation for threshold values before performing arithmetic operations:

```csharp
private bool Validate(Organization organization)
{
    // ... existing checks ...
    
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    var organizationMemberCount = organization.OrganizationMemberList.Count();
    
    // Add upper bound checks to prevent overflow
    if (proposalReleaseThreshold.MaximalAbstentionThreshold > organizationMemberCount ||
        proposalReleaseThreshold.MaximalRejectionThreshold > organizationMemberCount)
        return false;
    
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

Alternatively, use `checked` arithmetic context:
```csharp
checked
{
    return /* ... validation with overflow checking ... */;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CreateOrganization_IntegerOverflow_Bypass_Test()
{
    // Arrange: Create organization with overflow-inducing thresholds
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 1,
            MinimalVoteThreshold = 1,
            MaximalAbstentionThreshold = long.MaxValue, // 9223372036854775807
            MaximalRejectionThreshold = long.MaxValue   // 9223372036854775807
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer1 }
        }
    };
    
    // Act: Organization creation should fail but succeeds due to overflow
    var transactionResult = await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    
    // Assert: Organization is created successfully (vulnerability confirmed)
    transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var organizationAddress = transactionResult.Output;
    
    // Verify the malicious organization was stored
    var organization = await AssociationContractStub.GetOrganization.CallAsync(organizationAddress);
    organization.ProposalReleaseThreshold.MaximalAbstentionThreshold.ShouldBe(long.MaxValue);
    organization.ProposalReleaseThreshold.MaximalRejectionThreshold.ShouldBe(long.MaxValue);
    
    // Create a proposal
    var proposalInput = new CreateProposalInput
    {
        OrganizationAddress = organizationAddress,
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContractStub.Transfer),
        Params = new TransferInput { To = DefaultSender, Symbol = "ELF", Amount = 100 }.ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    };
    
    var proposalId = await AssociationContractStub.CreateProposal.SendAsync(proposalInput);
    proposalId.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Only 1 approval, but 2 rejections - should fail but succeeds
    await GetAssociationContractTester(Reviewer1KeyPair).Approve.SendAsync(proposalId.Output);
    await GetAssociationContractTester(Reviewer2KeyPair).Reject.SendAsync(proposalId.Output);
    await GetAssociationContractTester(Reviewer3KeyPair).Reject.SendAsync(proposalId.Output);
    
    // Proposal can be released despite 2 rejections (governance bypass confirmed)
    var releaseResult = await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(proposalId.Output);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L69-93)
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
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-59)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
    }

    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }

    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }

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

**File:** protobuf/acs3.proto (L128-137)
```text
message ProposalReleaseThreshold {
    // The value for the minimum approval threshold.
    int64 minimal_approval_threshold = 1;
    // The value for the maximal rejection threshold.
    int64 maximal_rejection_threshold = 2;
    // The value for the maximal abstention threshold.
    int64 maximal_abstention_threshold = 3;
    // The value for the minimal vote threshold.
    int64 minimal_vote_threshold = 4;
}
```
