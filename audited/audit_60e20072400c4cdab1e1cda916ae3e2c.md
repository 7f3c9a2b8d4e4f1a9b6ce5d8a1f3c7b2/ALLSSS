### Title
Governance DoS via Overly Restrictive Referendum Thresholds in Three-Tier UserFeeController

### Summary
The three-tier UserFeeController architecture introduces a critical governance DoS vulnerability through overly restrictive referendum organization thresholds. Any token holder possessing even a single token can permanently block all user fee governance by rejecting referendum proposals, as the referendum threshold configuration sets `MaximalRejectionThreshold = 0` and `MaximalAbstentionThreshold = 0`. Since the Association root controller requires approval from both Parliament AND Referendum members, a DoS'd referendum completely paralyzes user fee governance with no escape mechanism.

### Finding Description

The vulnerability exists in the three-tier governance structure initialized by `GetDefaultUserFeeController()`. [1](#0-0) 

**Root Cause:** The referendum organization is created with critically flawed thresholds: [2](#0-1) 

These thresholds require:
- `MinimalApprovalThreshold = 1` (at least 1 token must approve)
- `MinimalVoteThreshold = 1` (at least 1 token must vote)
- `MaximalRejectionThreshold = 0` (ANY rejection blocks the proposal)
- `MaximalAbstentionThreshold = 0` (ANY abstention blocks the proposal)

**Why Protections Fail:** The `IsReleaseThresholdReached` logic enforces these thresholds strictly: [3](#0-2) 

If `RejectionCount > 0` or `AbstentionCount > 0`, the method returns false, preventing proposal release even if the proposer (Parliament) attempts to release it. [4](#0-3) 

**Critical Dependency Chain:** The Association root controller requires BOTH Parliament and Referendum to approve: [5](#0-4) 

With `MinimalApprovalThreshold = proposers.Count = 2`, both members must approve. If Referendum is blocked, the Association cannot release any proposals, and the authorization check for user fee operations fails: [6](#0-5) 

### Impact Explanation

**Operational Impact - Complete Governance DoS:**
- All user fee coefficient updates via `UpdateCoefficientsForSender` become permanently blocked [7](#0-6) 
- The `ChangeUserFeeController` escape mechanism cannot be invoked as it requires the stuck RootController's approval [8](#0-7) 
- No ability to update transaction fee calculation parameters, freezing fee economics
- Affects entire user base's transaction costs and protocol fee revenue

**Who is Affected:**
- All users paying transaction fees (frozen coefficients may become misaligned with network conditions)
- Protocol governance (complete loss of user fee parameter control)
- System administrators unable to respond to economic changes

**Severity Justification:**
HIGH severity - this is a complete denial of service for a critical governance function with no recovery mechanism. The attack cost is minimal (1 token) while the impact is permanent protocol-level governance paralysis.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires possession of ≥1 token of the primary token symbol (readily available)
- Can be executed by any token holder, including malicious actors or those with genuine disagreement
- No special privileges or access required

**Attack Complexity:**
LOW - The attack requires only:
1. Approve tokens to referendum proposal virtual address
2. Call `Referendum.Approve` with rejection vote (or call `Reject` directly) [9](#0-8) 

**Feasibility Conditions:**
- Attacker must monitor for new referendum proposals (created when Parliament attempts governance changes)
- Timing window is between proposal creation and release (typically hours based on governance cycles)
- Referendum voting is public and permissionless [10](#0-9) 

**Economic Rationality:**
- Cost: 1 token + gas fees (negligible)
- Benefit to attacker: Permanent governance disruption, potential competitive advantage, or ideological motivation
- Detection is immediate but response is impossible due to catch-22: fixing the threshold requires passing a proposal through the stuck organization

**Probability Assessment:**
HIGH - Given the minimal cost and public nature of governance proposals, this attack is highly probable in adversarial scenarios or during contentious governance decisions.

### Recommendation

**Immediate Fix:**
1. Update `GetReferendumControllerCreateInputForUserFee` to use reasonable thresholds: [2](#0-1) 

```
Recommended thresholds:
- MinimalApprovalThreshold: Meaningful percentage (e.g., 10% of total supply)
- MinimalVoteThreshold: Meaningful participation (e.g., 15% of total supply)
- MaximalRejectionThreshold: Reasonable majority (e.g., 40% of total supply)
- MaximalAbstentionThreshold: Allow abstentions (e.g., 30% of total supply)
```

2. Add emergency escape mechanism: Implement a Parliament-only emergency override path that activates after a timeout period when referendum proposals fail to reach quorum, allowing governance to continue with reduced (but not blocked) legitimacy.

3. Implement proposal cancellation: Allow Parliament to cancel stuck referendum proposals and recreate them, preventing permanent blocks.

**Invariant Checks to Add:**
- Assert that `MaximalRejectionThreshold > 0` during organization creation for governance-critical organizations
- Validate that thresholds allow for realistic proposal passage scenarios
- Test governance recovery paths when threshold deadlock occurs

**Test Cases to Prevent Regression:**
- Test referendum proposal with single token rejection
- Verify root controller can still operate when referendum rejects
- Test emergency governance override mechanisms
- Validate threshold updates don't introduce new deadlock scenarios

### Proof of Concept

**Required Initial State:**
- UserFeeController initialized with three-tier structure via `InitializeAuthorizedController` [11](#0-10) 
- Attacker holds ≥1 of primary token symbol
- Parliament attempts to update user fee coefficients

**Attack Sequence:**
1. Parliament creates Association proposal to call `UpdateCoefficientsForSender`
2. Parliament approves the Association proposal
3. Parliament creates Referendum proposal to approve Association proposal (via `CreateProposal` on referendum organization)
4. **Attacker monitors referendum proposal creation**
5. Attacker calls `TokenContract.Approve` to approve tokens to referendum proposal virtual address
6. **Attacker calls `ReferendumContract.Reject(proposalId)`** [9](#0-8) 
7. Parliament attempts to release referendum proposal via `ReferendumContract.Release(proposalId)`
8. **Release fails** with "Not approved" error because `IsReleaseThresholdReached` returns false (RejectionCount = 1 > MaximalRejectionThreshold = 0) [12](#0-11) 
9. Referendum cannot approve Association proposal
10. Association proposal cannot be released (needs 2 approvals, only has 1 from Parliament)
11. All subsequent user fee governance attempts fail with the same pattern

**Expected vs Actual Result:**
- Expected: Governance with reasonable token-holder participation requirements
- Actual: Single token holder can permanently block governance

**Success Condition:**
Governance remains blocked indefinitely. Any attempt to call `UpdateCoefficientsForSender` or `ChangeUserFeeController` fails the authorization check. [6](#0-5)

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L16-43)
```csharp
    public override Empty InitializeAuthorizedController(Empty input)
    {
        var defaultParliamentController = GetDefaultParliamentController();
        if (State.UserFeeController.Value == null)
        {
            var defaultUserFeeController = GetDefaultUserFeeController(defaultParliamentController);
            CreateReferendumControllerForUserFee(defaultParliamentController.OwnerAddress);
            CreateAssociationControllerForUserFee(defaultParliamentController.OwnerAddress,
                defaultUserFeeController.ReferendumController.OwnerAddress);
            State.UserFeeController.Value = defaultUserFeeController;
        }

        if (State.DeveloperFeeController.Value == null)
        {
            var developerController = GetDefaultDeveloperFeeController(defaultParliamentController);
            CreateDeveloperController(defaultParliamentController.OwnerAddress);
            CreateAssociationControllerForDeveloperFee(defaultParliamentController.OwnerAddress,
                developerController.DeveloperController.OwnerAddress);
            State.DeveloperFeeController.Value = developerController;
        }

        if (State.SideChainCreator.Value == null || State.SideChainRentalController.Value != null) return new Empty();
        var sideChainRentalController = GetDefaultSideChainRentalController(defaultParliamentController);
        CreateAssociationControllerForSideChainRental(State.SideChainCreator.Value,
            defaultParliamentController.OwnerAddress);
        State.SideChainRentalController.Value = sideChainRentalController;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L70-78)
```csharp
    public override Empty ChangeUserFeeController(AuthorityInfo input)
    {
        AssertUserFeeController();
        Assert(CheckOrganizationExist(input), "Invalid authority input.");
        State.UserFeeController.Value.RootController = input;
        State.UserFeeController.Value.ParliamentController = null;
        State.UserFeeController.Value.ReferendumController = null;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L133-156)
```csharp
    private CreateOrganizationBySystemContractInput GetReferendumControllerCreateInputForUserFee(
        Address parliamentAddress)
    {
        var whiteList = new List<Address> { parliamentAddress };
        var tokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
        return new CreateOrganizationBySystemContractInput
        {
            OrganizationCreationInput = new CreateOrganizationInput
            {
                TokenSymbol = tokenSymbol,
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = 1,
                    MinimalVoteThreshold = 1,
                    MaximalRejectionThreshold = 0,
                    MaximalAbstentionThreshold = 0
                },
                ProposerWhiteList = new ProposerWhiteList
                {
                    Proposers = { whiteList }
                }
            }
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L158-184)
```csharp
    private Association.CreateOrganizationBySystemContractInput GetAssociationControllerCreateInputForUserFee(
        Address parliamentAddress, Address referendumAddress)
    {
        var proposers = new List<Address>
            { referendumAddress, parliamentAddress };
        return new Association.CreateOrganizationBySystemContractInput
        {
            OrganizationCreationInput = new Association.CreateOrganizationInput
            {
                OrganizationMemberList = new OrganizationMemberList
                {
                    OrganizationMembers = { proposers }
                },
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = proposers.Count,
                    MinimalVoteThreshold = proposers.Count,
                    MaximalRejectionThreshold = 0,
                    MaximalAbstentionThreshold = 0
                },
                ProposerWhiteList = new ProposerWhiteList
                {
                    Proposers = { proposers }
                }
            }
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L324-352)
```csharp
    private UserFeeController GetDefaultUserFeeController(AuthorityInfo defaultParliamentController)
    {
        if (State.AssociationContract.Value == null)
            State.AssociationContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);

        if (State.ReferendumContract.Value == null)
            State.ReferendumContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);

        var userFeeController = new UserFeeController
        {
            RootController = new AuthorityInfo(),
            ParliamentController = new AuthorityInfo(),
            ReferendumController = new AuthorityInfo()
        };
        userFeeController.ParliamentController = defaultParliamentController;
        userFeeController.ReferendumController.ContractAddress = State.ReferendumContract.Value;
        userFeeController.ReferendumController.OwnerAddress =
            State.ReferendumContract.CalculateOrganizationAddress.Call(
                GetReferendumControllerCreateInputForUserFee(defaultParliamentController.OwnerAddress)
                    .OrganizationCreationInput);
        userFeeController.RootController.ContractAddress = State.AssociationContract.Value;
        userFeeController.RootController.OwnerAddress = State.AssociationContract.CalculateOrganizationAddress.Call(
            GetAssociationControllerCreateInputForUserFee(defaultParliamentController.OwnerAddress,
                    userFeeController.ReferendumController.OwnerAddress)
                .OrganizationCreationInput);
        return userFeeController;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L391-397)
```csharp
    private void AssertUserFeeController()
    {
        Assert(State.UserFeeController.Value != null,
            "controller does not initialize, call InitializeAuthorizedController first");
        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == State.UserFeeController.Value.RootController.OwnerAddress, "no permission");
    }
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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L85-98)
```csharp
    public override Empty Reject(Hash input)
    {
        var proposal = GetValidProposal(input);
        var organization = State.Organizations[proposal.OrganizationAddress];
        var allowance = GetAllowance(Context.Sender, organization.TokenSymbol, input);

        proposal.RejectionCount = proposal.RejectionCount.Add(allowance);
        State.Proposals[input] = proposal;
        var referendumReceiptCreated = LockToken(organization.TokenSymbol, allowance, input, Context.Sender,
            proposal.OrganizationAddress);
        referendumReceiptCreated.ReceiptType = nameof(Reject);
        Context.Fire(referendumReceiptCreated);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L163-177)
```csharp
    public override Empty Release(Hash input)
    {
        var proposal = GetValidProposal(input);
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
        var organization = State.Organizations[proposal.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposal.ToAddress,
            proposal.ContractMethodName, proposal.Params);

        Context.Fire(new ProposalReleased { ProposalId = input });
        State.Proposals.Remove(input);

        return new Empty();
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
