# Audit Report

## Title
Missing Threshold Sum Validation Allows Creation of Unreleasable Referendum Organizations

## Summary
The Referendum contract's organization validation function fails to verify that the sum of approval, rejection, and abstention thresholds can mathematically satisfy the minimum vote threshold. This allows creation of organizations where proposals can never be released, causing permanent governance deadlock and token locks.

## Finding Description

The Referendum contract's `Validate(Organization)` method checks individual threshold constraints but omits critical sum validation that exists in both Association and Parliament contracts. [1](#0-0) 

The release logic enforces four simultaneous conditions that must all be met for a proposal to pass: total votes must reach the minimal vote threshold, rejection count must not exceed its maximum, abstention count must not exceed its maximum, and approval count must reach its minimum. [2](#0-1) 

If thresholds are configured such that `MinimalApprovalThreshold + MaximalRejectionThreshold + MaximalAbstentionThreshold < MinimalVoteThreshold`, no combination of votes can simultaneously satisfy all conditions. For example, with `MinimalVoteThreshold=1000`, `MinimalApprovalThreshold=500`, `MaximalRejectionThreshold=200`, `MaximalAbstentionThreshold=200`, the maximum achievable total is 900 votes, which cannot reach the required 1000.

The Association contract correctly validates this by checking that `MaximalAbstentionThreshold + MinimalApprovalThreshold <= organizationMemberCount` and `MaximalRejectionThreshold + MinimalApprovalThreshold <= organizationMemberCount`. [3](#0-2) 

The Parliament contract enforces identical constraints: `MaximalAbstentionThreshold + MinimalApprovalThreshold <= AbstractVoteTotal` and `MaximalRejectionThreshold + MinimalApprovalThreshold <= AbstractVoteTotal`. [4](#0-3) 

The flawed validation is invoked during organization creation through the public `CreateOrganization` method. [5](#0-4) 

The same validation is used when modifying thresholds via `ChangeOrganizationThreshold`, which can only be called by the organization address itself. [6](#0-5)  Since the organization address executes actions only through released proposals, misconfigured organizations cannot fix themselves.

Token holders who vote by calling `Approve`, `Reject`, or `Abstain` have their tokens locked in the proposal via the `LockToken` function. [7](#0-6)  While tokens can be reclaimed after proposal expiry, they remain locked during the proposal lifetime.

## Impact Explanation

**Permanent Governance Deadlock:** Organizations created with mathematically impossible thresholds cannot execute any proposals. The `IsReleaseThresholdReached` check will always fail because the required conditions are mutually exclusive.

**Irretrievable Assets:** Any funds, tokens, or permissions controlled by the dysfunctional organization become permanently inaccessible. Since `ChangeOrganizationThreshold` requires organizational authorization (Context.Sender must be the organization address), and organizations can only act through approved proposals, the deadlock is unbreakable.

**Token Holder Impact:** Users who vote on proposals lock tokens that cannot be released until proposal expiry, losing governance participation rights and token liquidity during that period.

**Affected Stakeholders:**
- Organization creators who unintentionally misconfigure thresholds
- Token holders who participate in voting
- Smart contracts or treasuries controlled by the broken organization

**Severity Assessment:** Medium - Complete DoS of governance functionality with permanent fund/permission lock, but requires user configuration error or malicious setup during creation (not exploitable against existing well-configured organizations).

## Likelihood Explanation

**Accessibility:** The `CreateOrganization` method is publicly accessible without authorization requirements, allowing any user to create a referendum organization. [8](#0-7) 

**Realistic Preconditions:**
- No special permissions needed to create organizations
- Simple arithmetic misconfiguration is a realistic user error (users may not understand the mathematical relationship between thresholds)
- No validation warnings or pre-flight checks exist to catch this error
- The validation only checks basic constraints, not mathematical feasibility

**Execution Simplicity:** A single `CreateOrganization` transaction with misconfigured parameters creates the broken organization. No complex state manipulation or multi-step process required.

**Discovery Delay:** Users may not discover the impossibility until after creating proposals, obtaining token allowances, accumulating votes, and attempting release - by which point multiple users' tokens are already locked in unreleasable proposals.

## Recommendation

Add sum validation checks to the `Validate(Organization)` method matching the constraints in Association and Parliament contracts. The validation should ensure that valid vote combinations can reach the minimal vote threshold:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");

    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold +
           proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MaximalRejectionThreshold +
           proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold;
}
```

This ensures that at least one valid vote combination exists where the minimal approval threshold is met while rejection and abstention remain within their maximums, and the total reaches the minimal vote threshold.

## Proof of Concept

```csharp
[Fact]
public async Task CreateOrganization_WithImpossibleThresholds_ShouldCreateButNeverRelease()
{
    // Configure mathematically impossible thresholds
    var createOrganizationInput = new CreateOrganizationInput
    {
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalVoteThreshold = 1000,      // Requires 1000 total votes
            MinimalApprovalThreshold = 500,   // Requires 500 approvals
            MaximalRejectionThreshold = 200,  // Allows max 200 rejections
            MaximalAbstentionThreshold = 200  // Allows max 200 abstentions
            // Maximum possible total: 500 + 200 + 200 = 900 < 1000 (IMPOSSIBLE)
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { DefaultSender } },
        TokenSymbol = "ELF"
    };
    
    // This should fail but doesn't - organization is created
    var result = await ReferendumContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    var organizationAddress = result.Output;
    organizationAddress.ShouldNotBeNull();
    
    // Create a proposal
    var proposalInput = new CreateInput { Symbol = "TEST", TokenName = "Test Token", TotalSupply = 1000, Issuer = organizationAddress };
    var proposalId = await CreateReferendumProposalAsync(DefaultSenderKeyPair, proposalInput, 
        nameof(TokenContractStub.Create), organizationAddress, TokenContractAddress);
    
    // Even with maximum valid votes (500 approval + 200 rejection + 200 abstention = 900),
    // total is less than MinimalVoteThreshold (1000), so release will ALWAYS fail
    await ApproveAllowanceAsync(Accounts[0].KeyPair, 500, proposalId);
    await ApproveAsync(Accounts[0].KeyPair, proposalId);
    
    await ApproveAllowanceAsync(Accounts[1].KeyPair, 200, proposalId);
    await RejectAsync(Accounts[1].KeyPair, proposalId);
    
    await ApproveAllowanceAsync(Accounts[2].KeyPair, 200, proposalId);
    await AbstainAsync(Accounts[2].KeyPair, proposalId);
    
    var proposal = await ReferendumContractStub.GetProposal.CallAsync(proposalId);
    proposal.ApprovalCount.ShouldBe(500);
    proposal.RejectionCount.ShouldBe(200);
    proposal.AbstentionCount.ShouldBe(200);
    proposal.ToBeReleased.ShouldBeFalse(); // Can never be true - mathematical impossibility
    
    // Release fails permanently
    var releaseResult = await ReferendumContractStub.Release.SendWithExceptionAsync(proposalId);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved");
}
```

## Notes

This vulnerability demonstrates an inconsistency in validation logic across AElf's governance contracts. While Association and Parliament properly validate threshold feasibility, Referendum omits these critical checks. The mathematical impossibility creates a permanent deadlock that cannot be resolved through any on-chain action, making this a high-impact governance DoS vulnerability despite requiring configuration error during creation.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L12-29)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var enoughVote = proposal.RejectionCount.Add(proposal.AbstentionCount).Add(proposal.ApprovalCount) >=
                         proposalReleaseThreshold.MinimalVoteThreshold;
        if (!enoughVote)
            return false;

        var isRejected = proposal.RejectionCount > proposalReleaseThreshold.MaximalRejectionThreshold;
        if (isRejected)
            return false;

        var isAbstained = proposal.AbstentionCount > proposalReleaseThreshold.MaximalAbstentionThreshold;
        if (isAbstained)
            return false;

        return proposal.ApprovalCount >= proposalReleaseThreshold.MinimalApprovalThreshold;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L39-72)
```csharp
    private ReferendumReceiptCreated LockToken(string symbol, long amount, Hash proposalId, Address lockedAddress,
        Address organizationAddress)
    {
        Assert(State.LockedTokenAmount[lockedAddress][proposalId] == null, "Already locked.");

        var lockId = Context.GenerateId(Context.Self,
            HashHelper.ConcatAndCompute(proposalId, HashHelper.ComputeFrom(lockedAddress)));
        RequireTokenContractStateSet();
        Context.SendVirtualInline(proposalId, State.TokenContract.Value,
            nameof(TokenContractContainer.TokenContractReferenceState.TransferFrom), new TransferFromInput
            {
                From = Context.Sender,
                To = GetProposalVirtualAddress(proposalId),
                Symbol = symbol,
                Amount = amount,
                Memo = "Referendum."
            });
        State.LockedTokenAmount[Context.Sender][proposalId] = new Receipt
        {
            Amount = amount,
            LockId = lockId,
            TokenSymbol = symbol
        };

        return new ReferendumReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = proposalId,
            Amount = amount,
            Symbol = symbol,
            Time = Context.CurrentBlockTime,
            OrganizationAddress = organizationAddress
        };
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L90-102)
```csharp
    private bool Validate(Organization organization)
    {
        if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
            organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
            return false;
        Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");

        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L77-80)
```csharp
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L151-154)
```csharp
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L12-40)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            TokenSymbol = input.TokenSymbol,
            OrganizationHash = organizationHash,
            ProposerWhiteList = input.ProposerWhiteList,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization data.");

        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;

        State.Organizations[organizationAddress] = organization;
        Context.Fire(new OrganizationCreated
        {
            OrganizationAddress = organizationAddress
        });

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L124-137)
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
