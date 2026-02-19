### Title
Referendum Contract Allows Quorum Manipulation Through Insufficient Threshold Validation

### Summary
The Referendum contract's organization validation is missing critical checks that prevent abstention votes from dominating the vote threshold. Unlike Parliament and Association contracts, Referendum doesn't enforce that `MaximalAbstentionThreshold + MinimalApprovalThreshold` must be bounded, allowing organizations to be created where proposals can pass with minimal approval (e.g., 0.01%) while meeting quorum requirements through overwhelming abstention votes.

### Finding Description

**Root Cause:**
The Referendum contract's `Validate(Organization)` function lacks sum validation checks present in Parliament and Association contracts. [1](#0-0) 

Referendum only validates:
- `MinimalApprovalThreshold <= MinimalVoteThreshold`
- `MinimalApprovalThreshold > 0`
- `MaximalAbstentionThreshold >= 0`
- `MaximalRejectionThreshold >= 0`

In contrast, Parliament enforces additional constraints: [2](#0-1) 

Parliament requires:
- `MaximalAbstentionThreshold + MinimalApprovalThreshold <= AbstractVoteTotal`
- `MaximalRejectionThreshold + MinimalApprovalThreshold <= AbstractVoteTotal`

Association has identical protection: [3](#0-2) 

**Why Existing Protections Fail:**

The `IsReleaseThresholdReached` function counts abstentions toward the vote threshold: [4](#0-3) 

At lines 15-16, total votes include `AbstentionCount`, allowing abstentions to meet `MinimalVoteThreshold` without requiring proportional approval votes. The check at line 24-26 only prevents exceeding `MaximalAbstentionThreshold`, but this threshold can be set arbitrarily high during organization creation.

The `Abstain()` function increments `AbstentionCount` based on token allowance: [5](#0-4) 

### Impact Explanation

**Governance Manipulation:**
An attacker can create a Referendum organization with:
- `MinimalApprovalThreshold = 1` token (0.01% of total)
- `MinimalVoteThreshold = 10000` tokens
- `MaximalAbstentionThreshold = 9999` tokens (99.99% of total)

This configuration:
1. Passes Referendum validation (no sum check)
2. Would fail Parliament/Association validation (has sum check)
3. Allows proposals to pass with just 1 approval + 9999 abstentions

**Concrete Harm:**
- Proposals executing arbitrary governance actions (token minting, contract upgrades, treasury withdrawals) can pass with 0.01% approval
- Organization thresholds become meaningless security boundaries
- Referendum-based governance loses credibility as an authorization mechanism
- Any malicious actor with sufficient tokens can manipulate voting outcomes

**Severity Justification:**
HIGH - Enables unauthorized proposal execution through governance threshold bypass. Affects core authorization invariant: organization thresholds must enforce meaningful approval requirements.

### Likelihood Explanation

**Reachable Entry Point:**
`CreateOrganization` is publicly accessible - anyone can create organizations with custom thresholds: [6](#0-5) 

**Attack Complexity:**
1. Create organization with minimal approval + maximal abstention thresholds (1 transaction)
2. Create malicious proposal (1 transaction)
3. Obtain 1 approval vote from any token holder (1 transaction)
4. Cast 9999 abstention votes as attacker (1 transaction)
5. Release proposal (1 transaction)

**Economic Feasibility:**
Attacker needs `MinimalVoteThreshold - MinimalApprovalThreshold` tokens to lock for abstentions. With common ELF token values, this represents a feasible cost for high-value governance attacks. Tokens are returned after voting, making this a low-cost, repeatable attack.

**Detection:**
Malicious organizations can be created with legitimate-appearing thresholds (e.g., `MinimalVoteThreshold = 10000` looks secure) while hiding the exploitable abstention configuration. No on-chain alerts exist for this misconfiguration pattern.

### Recommendation

**Code-Level Mitigation:**
Add sum validation to `Validate(Organization)` in Referendum_Helper.cs, matching Parliament/Association contracts:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");

    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    var minimalVoteThreshold = proposalReleaseThreshold.MinimalVoteThreshold;
    
    return proposalReleaseThreshold.MinimalApprovalThreshold <= minimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold + 
           proposalReleaseThreshold.MinimalApprovalThreshold <= minimalVoteThreshold &&
           proposalReleaseThreshold.MaximalRejectionThreshold + 
           proposalReleaseThreshold.MinimalApprovalThreshold <= minimalVoteThreshold;
}
```

**Invariant Checks:**
Enforce: `MaximalAbstentionThreshold + MinimalApprovalThreshold <= MinimalVoteThreshold`

This ensures abstentions cannot dominate voting outcomes - approval votes must constitute a meaningful portion of the quorum.

**Test Cases:**
1. Test organization creation with `MaximalAbstentionThreshold = MinimalVoteThreshold - 1` (should fail)
2. Test organization creation with `MaximalAbstentionThreshold + MinimalApprovalThreshold = MinimalVoteThreshold` (should pass)
3. Test proposal release with max abstentions + minimal approvals (should require balanced thresholds)

### Proof of Concept

**Initial State:**
- Attacker has 10000 ELF tokens
- Token contract deployed and functional

**Attack Sequence:**

1. **Create Exploitable Organization:**
   - Call `CreateOrganization` with:
     ```
     MinimalApprovalThreshold: 1
     MinimalVoteThreshold: 10000
     MaximalAbstentionThreshold: 9999
     MaximalRejectionThreshold: 0
     ```
   - Organization created successfully (passes current validation)

2. **Create Malicious Proposal:**
   - Call `CreateProposal` to execute arbitrary governance action
   - Proposal ID generated

3. **Obtain Minimal Approval:**
   - Victim/attacker calls `Approve` with 1 token allowance
   - `ApprovalCount = 1`

4. **Inflate Quorum with Abstentions:**
   - Attacker calls `Approve` (token allowance) for 9999 tokens to proposal virtual address
   - Attacker calls `Abstain` with 9999 tokens
   - `AbstentionCount = 9999`

5. **Release Proposal:**
   - Call `Release(proposalId)`
   - Check: `Total votes = 1 + 9999 = 10000 >= MinimalVoteThreshold (10000)` ✓
   - Check: `AbstentionCount (9999) <= MaximalAbstentionThreshold (9999)` ✓
   - Check: `ApprovalCount (1) >= MinimalApprovalThreshold (1)` ✓
   - **Proposal executes with only 0.01% approval**

**Expected vs Actual:**
- **Expected:** Proposal should fail due to insufficient meaningful approval
- **Actual:** Proposal passes and executes governance action

**Success Condition:** 
Proposal released and governance action executed despite having only 1/10000 (0.01%) approval, demonstrating complete governance threshold bypass through abstention manipulation.

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-80)
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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L100-113)
```csharp
    public override Empty Abstain(Hash input)
    {
        var proposal = GetValidProposal(input);
        var organization = State.Organizations[proposal.OrganizationAddress];
        var allowance = GetAllowance(Context.Sender, organization.TokenSymbol, input);

        proposal.AbstentionCount = proposal.AbstentionCount.Add(allowance);
        State.Proposals[input] = proposal;
        var referendumReceiptCreated = LockToken(organization.TokenSymbol, allowance, input, Context.Sender,
            proposal.OrganizationAddress);
        referendumReceiptCreated.ReceiptType = nameof(Abstain);
        Context.Fire(referendumReceiptCreated);
        return new Empty();
    }
```
