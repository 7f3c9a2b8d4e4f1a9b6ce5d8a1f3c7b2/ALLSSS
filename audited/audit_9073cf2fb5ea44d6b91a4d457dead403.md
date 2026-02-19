# Audit Report

## Title
Weak Referendum Thresholds Enable Governance Bypass for User Fee Changes

## Summary
The referendum controller for user transaction fee changes uses critically weak voting thresholds (MinimalApprovalThreshold=1, MaximalRejectionThreshold=0, MaximalAbstentionThreshold=0), allowing Parliament to circumvent community consensus. A referendum proposal can pass with just 1 token of approval if no community member votes against it before expiration, enabling manipulation of user fee coefficients without meaningful community participation.

## Finding Description

The UserFeeController governance structure is designed with three layers: a root Association controller requiring approval from both Parliament and a Referendum organization. However, the referendum organization is configured with extremely weak thresholds that defeat its purpose as a community check on Parliament power.

The `GetReferendumControllerCreateInputForUserFee` method creates the referendum organization with these thresholds: [1](#0-0) 

Parliament is designated as the sole authorized proposer through the whitelist: [2](#0-1) 

The referendum release threshold validation logic requires these conditions to be met: [3](#0-2) 

With the configured thresholds, a proposal passes if:
- Total votes (approval + rejection + abstention) >= 1
- Rejection count <= 0 (must be exactly 0)
- Abstention count <= 0 (must be exactly 0)  
- Approval count >= 1

Critically, there is no minimum proposal duration enforced - proposals only need to expire in the future: [4](#0-3) 

This referendum organization is part of the UserFeeController governance protecting user fee coefficient changes: [5](#0-4) 

The Association root controller requires both Parliament and Referendum organizations to approve: [6](#0-5) 

**Attack Path:**
1. Parliament creates a referendum proposal with short expiration (e.g., 1 hour)
2. A controlled address approves with just 1 token via the Approve method: [7](#0-6) 
3. Before community can react, the proposal expires with 0 rejections and 0 abstentions
4. Parliament releases the referendum proposal
5. The referendum organization approves in the Association
6. Parliament also approves in the Association (2/2 threshold met)
7. Execute user fee coefficient change

## Impact Explanation

**HIGH Severity** - This vulnerability allows manipulation of critical economic parameters affecting all network users:

The protected resource is user transaction fee coefficients that control how much every user pays: [8](#0-7) 

**Concrete Harm:**
- Parliament can arbitrarily increase transaction fees (e.g., from x/800 to x/8, a 100x increase) without genuine community approval
- All network users pay higher fees for every transaction
- Economic parameters explicitly designed for community governance become centrally controlled
- Undermines trust in the governance system's checks and balances

**Affected Parties:** All network users - every blockchain operation requires paying transaction fees based on these coefficients.

**Severity Justification:** While Parliament is a semi-trusted role, the governance design explicitly includes referendum oversight to prevent unilateral Parliament actions. The weak threshold circumvents this intended safeguard, constituting a governance bypass of critical economic parameters with network-wide impact.

## Likelihood Explanation

**MEDIUM-HIGH Probability** - The attack is straightforward to execute:

**Attacker Capabilities:** Parliament (semi-trusted role) plus any single token holder (potentially a controlled address).

**Attack Complexity:** LOW
- Parliament creates referendum proposal via standard CreateProposal mechanism: [9](#0-8) 
- Controlled address approves with 1 token
- Release before community can monitor and react
- Complete Association approval process
- Execute fee change

**Feasibility Conditions:**
- No minimum proposal duration (validated above - only requires future expiration)
- No mandatory notification delay or voting period
- Events only observable after proposal creation
- Short expiration times exploit timezone differences or low-activity periods

**Detection Constraints:** Community members must actively monitor ProposalCreated events and vote reject/abstain before expiration, which may be minutes or hours.

**Economic Rationality:** Cost is minimal (1 token + transaction fees). Benefits could be significant if Parliament wishes to change fees to attract users, generate revenue, or for any policy reason.

**Probability Assessment:** While requiring Parliament cooperation, the governance design explicitly includes referendum oversight as a check on Parliament, indicating system designers intended community participation. The weak threshold defeats this design intent, making exploitation straightforward if Parliament desires to act without community consensus.

## Recommendation

Implement stronger referendum thresholds that ensure meaningful community participation:

1. **Increase MinimalApprovalThreshold** to a percentage of total token supply (e.g., 5-10%) rather than 1 token
2. **Set MinimalVoteThreshold** to require substantial participation (e.g., 10-20% of circulating supply)
3. **Implement minimum proposal duration** (e.g., 7 days) to allow adequate community review and voting time
4. **Add time-lock mechanisms** requiring a delay between proposal passage and execution

Example fix for the threshold configuration:

```csharp
private CreateOrganizationBySystemContractInput GetReferendumControllerCreateInputForUserFee(
    Address parliamentAddress)
{
    var whiteList = new List<Address> { parliamentAddress };
    var tokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
    var tokenInfo = GetTokenInfo(tokenSymbol);
    var totalSupply = tokenInfo.Supply;
    
    return new CreateOrganizationBySystemContractInput
    {
        OrganizationCreationInput = new CreateOrganizationInput
        {
            TokenSymbol = tokenSymbol,
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = totalSupply.Div(20), // 5% of supply
                MinimalVoteThreshold = totalSupply.Div(10),     // 10% of supply
                MaximalRejectionThreshold = totalSupply.Div(20), // max 5% rejection
                MaximalAbstentionThreshold = totalSupply.Div(10) // max 10% abstention
            },
            ProposerWhiteList = new ProposerWhiteList
            {
                Proposers = { whiteList }
            }
        }
    };
}
```

Additionally, add minimum duration validation in the Referendum contract's Validate method:

```csharp
private bool Validate(ProposalInfo proposal)
{
    if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    var minimumDuration = 604800; // 7 days in seconds
    return proposal.ExpiredTime != null && 
           Context.CurrentBlockTime < proposal.ExpiredTime &&
           proposal.ExpiredTime.Seconds >= Context.CurrentBlockTime.Seconds + minimumDuration;
}
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```csharp
[Fact]
public async Task WeakReferendumThreshold_AllowsGovernanceBypass()
{
    // Setup: Initialize UserFeeController with weak referendum thresholds
    await TokenContractStub.InitializeAuthorizedController.SendAsync(new Empty());
    
    // Get the referendum organization address
    var userFeeController = await TokenContractStub.GetUserFeeController.CallAsync(new Empty());
    var referendumAddress = userFeeController.ReferendumController.OwnerAddress;
    
    // Parliament creates a proposal to change user fee coefficients
    var updateInput = new UpdateCoefficientsInput
    {
        PieceNumbers = { 1 },
        Coefficients = new CalculateFeeCoefficients
        {
            FeeTokenType = (int)FeeTypeEnum.Tx,
            PieceCoefficientsList =
            {
                new CalculateFeePieceCoefficients
                {
                    Value = { 1000000, 1, 1, 8 } // Changed from x/800 to x/8 (100x increase)
                }
            }
        }
    };
    
    var proposalId = await ParliamentCreateProposalAsync(
        referendumAddress,
        nameof(TokenContractStub.UpdateCoefficientsForSender),
        updateInput,
        TimestampHelper.GetUtcNow().AddHours(1) // Just 1 hour expiration
    );
    
    // Attacker approves with just 1 token
    await ApproveReferendumWithMinimalTokens(proposalId, 1);
    
    // Advance time past expiration with zero rejections/abstentions
    await AdvanceTime(3600);
    
    // Release the referendum proposal - passes with 1 token approval
    await ReferendumContractStub.Release.SendAsync(proposalId);
    
    // Parliament approves in Association
    var associationProposalId = await CreateAssociationProposal(updateInput);
    await ApproveWithParliament(associationProposalId);
    await ApproveWithReferendum(associationProposalId);
    
    // Execute the fee change
    await AssociationContractStub.Release.SendAsync(associationProposalId);
    
    // Verify: User fees increased 100x without community consensus
    var newCoefficients = await TokenContractStub.GetCalculateFeeCoefficientsOfType
        .CallAsync(new Int32Value { Value = (int)FeeTypeEnum.Tx });
    
    Assert.Equal(8, newCoefficients.PieceCoefficientsList[0].Value[3]); // Divisor changed from 800 to 8
}
```

This test demonstrates that a proposal can pass the referendum with just 1 token approval and zero community participation, then proceed through the Association to modify critical fee parameters.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L136-136)
```csharp
        var whiteList = new List<Address> { parliamentAddress };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L143-149)
```csharp
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = 1,
                    MinimalVoteThreshold = 1,
                    MaximalRejectionThreshold = 0,
                    MaximalAbstentionThreshold = 0
                },
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L171-177)
```csharp
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = proposers.Count,
                    MinimalVoteThreshold = proposers.Count,
                    MaximalRejectionThreshold = 0,
                    MaximalAbstentionThreshold = 0
                },
```

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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L104-113)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L25-32)
```csharp
    public override Empty UpdateCoefficientsForSender(UpdateCoefficientsInput input)
    {
        Assert(input.Coefficients != null, "Invalid input coefficients.");
        AssertUserFeeController();
        input.Coefficients.FeeTokenType = (int)FeeTypeEnum.Tx; // The only possible for now.
        UpdateCoefficients(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L274-312)
```csharp
    private CalculateFeeCoefficients GetTxFeeInitialCoefficient()
    {
        return new CalculateFeeCoefficients
        {
            FeeTokenType = (int)FeeTypeEnum.Tx,
            PieceCoefficientsList =
            {
                new CalculateFeePieceCoefficients
                {
                    // Interval [0, 1000000]: x / 800 + 1 / 10000
                    Value =
                    {
                        1000000,
                        1, 1, 800,
                        0, 1, 10000
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (1000000, 5000000): x / 80
                    Value =
                    {
                        5000000,
                        1, 1, 80
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (5000000, ∞): x / 80 + x^2 / 100000
                    Value =
                    {
                        int.MaxValue,
                        1, 1, 80,
                        2, 1, 100000
                    }
                }
            }
        };
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-59)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L70-83)
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
    }
```
