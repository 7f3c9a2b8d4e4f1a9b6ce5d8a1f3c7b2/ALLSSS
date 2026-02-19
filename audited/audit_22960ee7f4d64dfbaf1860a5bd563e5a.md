# Audit Report

## Title
Insufficient Threshold Validation in Referendum Contract Allows Creation of Permanently Non-Functional Governance Organizations

## Summary
The Referendum contract's `CreateOrganization` function lacks validation to ensure `ProposalReleaseThreshold` values are achievable relative to the token's total supply. This allows creation of organizations with approval thresholds that exceed available token supply, rendering them permanently unable to release any proposals.

## Finding Description

The Referendum contract's `Validate` method performs insufficient validation when creating organizations. [1](#0-0) 

The validation only checks:
- Token existence (but not its supply)
- `MinimalApprovalThreshold <= MinimalVoteThreshold`
- `MinimalApprovalThreshold > 0`
- Non-negative maximal thresholds

Critically, it does NOT validate whether threshold values are achievable given the token's total supply.

In stark contrast, the Parliament contract validates thresholds against `AbstractVoteTotal` to ensure they cannot exceed what's mathematically possible: [2](#0-1) 

Similarly, the Association contract validates thresholds against `organizationMemberCount` to ensure achievability: [3](#0-2) 

When proposals attempt to be released, the system checks if the approval count meets the threshold: [4](#0-3) 

The approval count accumulates token allowances from voters: [5](#0-4) 

If `MinimalApprovalThreshold` exceeds the token's total supply, then even if all tokens vote to approve, `proposal.ApprovalCount` can never reach the threshold, making proposal release impossible.

The `CreateOrganization` function is publicly accessible as an RPC method: [6](#0-5) 

The existing validation tests confirm that supply-based validation is missing: [7](#0-6) 

## Impact Explanation

**Direct Governance Impact:**
- Organizations created with impossibly high thresholds become permanently non-functional
- No proposals can ever be released under such organizations, regardless of voting participation
- Violates the core governance invariant that organizations passing validation should be operable

**Token Locking:**
- Users who vote on proposals under broken organizations have their tokens locked via `TransferFrom`
- Locked tokens cannot be reclaimed until proposal expiration
- This represents a temporary but forced token lock for participants

**Severity Amplification:**
- If a broken organization is adopted as a `MethodFeeController` or other governance authority, it creates permanent protocol-level deadlock
- This scenario requires existing authority approval but demonstrates cascading risk

**Typical token supplies** range from 10^17 to 10^18 as shown in: [8](#0-7) 

An organization with thresholds exceeding these values would be permanently broken.

## Likelihood Explanation

**Entry Point Accessibility:**
`CreateOrganization` is a public RPC method callable by any user without preconditions.

**Execution Simplicity:**
- Attacker simply calls `CreateOrganization` with `MinimalApprovalThreshold = 10^20` and `MinimalVoteThreshold = 10^20`
- These values satisfy all existing validation checks (`MinimalApprovalThreshold <= MinimalVoteThreshold` and `> 0`)
- No special permissions or complex setup required

**Realistic Scenarios:**
1. **User Error (High Likelihood)**: Legitimate users confusing percentage-based values with absolute values, accidentally setting thresholds like `10^18` when intending `67%`
2. **Malicious Creation (Low Direct Harm)**: Attacker creates broken organization, but must convince others to use it
3. **Governance Authority Risk (Low Likelihood, High Impact)**: Broken organization adopted as authority, but requires existing governance approval

**Cost-Benefit:**
- Cost: Minimal (just transaction gas)
- Benefit to attacker: Limited unless organization is adopted
- Risk to users: High if they create/adopt such organizations

Overall likelihood: **Medium** - easy to trigger accidentally, moderate impact without social engineering.

## Recommendation

Add token supply validation to the Referendum contract's `Validate` method, similar to Parliament and Association contracts:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    
    var tokenInfo = GetTokenInfo(organization.TokenSymbol);
    Assert(!string.IsNullOrEmpty(tokenInfo.Symbol), "Token not exists.");

    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    
    // NEW: Validate thresholds against token supply
    var tokenSupply = tokenInfo.Supply;
    if (proposalReleaseThreshold.MinimalApprovalThreshold > tokenSupply ||
        proposalReleaseThreshold.MinimalVoteThreshold > tokenSupply)
        return false;
    
    // Also validate sum constraints like Association does
    if (proposalReleaseThreshold.MaximalAbstentionThreshold + 
        proposalReleaseThreshold.MinimalApprovalThreshold > tokenSupply)
        return false;
    
    if (proposalReleaseThreshold.MaximalRejectionThreshold + 
        proposalReleaseThreshold.MinimalApprovalThreshold > tokenSupply)
        return false;
    
    return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CreateOrganization_With_Impossible_Threshold_Should_Fail()
{
    // Get token info to determine actual supply
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
    {
        Symbol = "ELF"
    });
    
    var tokenSupply = tokenInfo.Supply; // e.g., 10^18
    var impossibleThreshold = tokenSupply + 1_000_000_00000000; // Exceeds supply
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = impossibleThreshold,
            MinimalVoteThreshold = impossibleThreshold,
            MaximalAbstentionThreshold = 0,
            MaximalRejectionThreshold = 0
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { DefaultSender }
        },
        TokenSymbol = "ELF"
    };
    
    // Currently PASSES but should FAIL - organization is created but permanently broken
    var result = await ReferendumContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // BUG: Should fail
    
    var organizationAddress = result.Output;
    
    // Create a proposal under this organization
    var proposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
    
    // Even if all tokens approve, threshold cannot be reached
    // Proposal can NEVER be released, creating permanent deadlock
    var releaseResult = await ReferendumContractStub.Release.SendWithExceptionAsync(proposalId);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved");
}
```

## Notes

The vulnerability is validated through:
1. **Missing validation confirmed** in Referendum vs Parliament/Association implementations
2. **Public accessibility** of the vulnerable entry point
3. **Concrete impact** on governance operations and token locking
4. **Inconsistency** with other governance contracts' validation patterns

The root cause is architectural: Referendum uses absolute token amounts for thresholds while Parliament uses proportional voting (AbstractVoteTotal = 10000) and Association uses member counts. This requires supply-aware validation that is currently missing.

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L142-155)
```csharp
    private bool Validate(Organization organization)
    {
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;

        return proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L70-82)
```csharp
    public override Empty Approve(Hash input)
    {
        var proposal = GetValidProposal(input);
        var organization = State.Organizations[proposal.OrganizationAddress];
        var allowance = GetAllowance(Context.Sender, organization.TokenSymbol, input);

        proposal.ApprovalCount = proposal.ApprovalCount.Add(allowance);
        State.Proposals[input] = proposal;
        var referendumReceiptCreated = LockToken(organization.TokenSymbol, allowance, input, Context.Sender,
            proposal.OrganizationAddress);
        referendumReceiptCreated.ReceiptType = nameof(Approve);
        Context.Fire(referendumReceiptCreated);
        return new Empty();
```

**File:** protobuf/referendum_contract.proto (L23-25)
```text
    // Create an organization and return its address.  
    rpc CreateOrganization (CreateOrganizationInput) returns (aelf.Address) {
    }
```

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L1127-1177)
```csharp
    public async Task CreateOrganization_With_Invalid_Input_Test()
    {
        // token symbol is null or empty
        {
            var validInput = GetValidCreateOrganizationInput();
            validInput.TokenSymbol = string.Empty;
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }

        // no proposer in proposeWhiteList
        {
            var validInput = GetValidCreateOrganizationInput();
            validInput.ProposerWhiteList.Proposers.Clear();
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }

        //MinimalApprovalThreshold > MinimalVoteThreshold
        {
            var validInput = GetValidCreateOrganizationInput();
            validInput.ProposalReleaseThreshold.MinimalApprovalThreshold =
                validInput.ProposalReleaseThreshold.MinimalVoteThreshold + 1;
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }

        //MinimalApprovalThreshold == 0
        {
            var validInput = GetValidCreateOrganizationInput();
            validInput.ProposalReleaseThreshold.MinimalApprovalThreshold = 0;
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }

        //MaximalAbstentionThreshold < 0
        {
            var validInput = GetValidCreateOrganizationInput();
            validInput.ProposalReleaseThreshold.MaximalAbstentionThreshold = -1;
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }

        //MaximalRejectionThreshold < 0
        {
            var validInput = GetValidCreateOrganizationInput();
            validInput.ProposalReleaseThreshold.MaximalRejectionThreshold = -1;
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L11-25)
```csharp
    public const long ResourceTokenTotalSupply = 500_000_000_00000000;

    public const int ResourceTokenDecimals = 8;

    //resource to sell
    public const long ResourceTokenInitialVirtualBalance = 100_000;

    public const string NativeTokenPrefix = "nt";

    public const long NativeTokenToResourceBalance = 10_000_000_00000000;

    // Election related.
    public const string ElectionTokenSymbol = "VOTE";
    public const string ShareTokenSymbol = "SHARE";
    public const long ElectionTokenTotalSupply = 1_000_000_000_00000000;
```
