### Title
Governance Rejection Threshold Boundary Inconsistency Allows Proposals to Pass When They Should Be Rejected

### Summary
The governance contracts (Parliament, Association, Referendum) use strict inequality (`>`) to check rejection thresholds, while the official documentation specifies proposals should be rejected when rejections reach or exceed the threshold (`>=`). This discrepancy allows proposals with exactly at the MaximalRejectionThreshold (10% by default) to pass governance when they should be rejected, creating an exploitable edge case that violates documented governance rules.

### Finding Description

The MaximalRejectionThreshold constant is defined as 1000 (representing 10% in basis points): [1](#0-0) 

However, all three governance contract implementations use the **wrong comparison operator**:

**Parliament Contract** uses strict greater-than in rejection check: [2](#0-1) 

**Association Contract** uses strict greater-than: [3](#0-2) 

**Referendum Contract** uses strict greater-than: [4](#0-3) 

The official documentation explicitly states the correct releasability requirement uses strict less-than for rejection counts, meaning rejection should occur at **greater-than-or-equal**: [5](#0-4) [6](#0-5) [7](#0-6) 

The root cause is using `>` instead of `>=` for the rejection condition. At exactly the threshold percentage, the code incorrectly allows proposals to pass:
- **Code behavior**: Rejects only when `rejections > threshold` 
- **Documented behavior**: Should reject when `rejections >= threshold`

### Impact Explanation

**Concrete Harm:**
1. **Governance Bypass**: Proposals with exactly 10% rejection (1 out of 10 parliament members, or equivalent in Association/Referendum) incorrectly pass when they should be rejected per governance rules
2. **Protocol Damage**: Violates critical governance invariant that documented thresholds must be enforced correctly
3. **Affected Parties**: All organizations using default thresholds (Emergency Response Organization, cross-chain organizations, default parliament organization)

**Quantified Impact Example:**
- Parliament with 10 members, MaximalRejectionThreshold = 1000 (10%)
- Calculation: `(1 rejection * 10000) > (1000 * 10)` → `10000 > 10000` → **FALSE** (not rejected)
- Documentation requires: `1 rejection / 10 members < 10%` → **FALSE** (should be rejected)
- Result: Malicious proposal passes with exactly 1 rejection when it should fail

**Severity: MEDIUM**
- Allows governance rule violation at deterministic boundary
- Undermines trust in documented governance guarantees
- Exploitable in coordinated attacks on governance

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to create proposals (standard governance participation)
- Knowledge of organization member count and voting patterns
- Coordination to achieve exactly threshold-level rejections

**Attack Complexity:**
- **LOW**: Exploit is deterministic - always occurs at exact threshold boundary
- No special privileges required beyond proposal creation rights
- Execution is straightforward governance participation

**Feasibility Conditions:**
- Organizations with predictable member counts (e.g., 10-member parliaments)
- Scenarios where exactly 1 vote difference matters
- Real organizations use affected defaults: [8](#0-7) 

**Detection/Operational Constraints:**
- Boundary condition may not be noticed in typical governance flows
- No error or event indicates threshold bypass occurred
- Silent failure of documented governance rules

**Probability: MEDIUM** - Requires specific vote count but is deterministic and exploitable in controlled governance scenarios

### Recommendation

**Code-Level Mitigation:**

Change all rejection threshold comparisons from `>` to `>=`:

**Parliament Contract:**
Replace line 68-69 to use:
```csharp
return rejectionMemberCount * AbstractVoteTotal >= 
       organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
```

**Association Contract:**
Replace line 38 to use:
```csharp
return rejectionMemberCount >= organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**Referendum Contract:**
Replace line 20 to use:
```csharp
var isRejected = proposal.RejectionCount >= proposalReleaseThreshold.MaximalRejectionThreshold;
```

**Invariant Checks to Add:**
Add explicit test coverage for exact threshold boundary:
- Test case: exactly 10% rejection with threshold=1000 should REJECT proposal
- Test case: 9.99% rejection should NOT reject proposal
- Test case: 10.01% rejection should REJECT proposal

**Regression Prevention:**
Add boundary test similar to existing tests but specifically for the exact threshold value: [9](#0-8) 

### Proof of Concept

**Initial State:**
1. Parliament organization with 10 members
2. MaximalRejectionThreshold = 1000 (10%)
3. Create proposal requiring governance approval

**Attack Steps:**
1. Attacker creates proposal via `CreateProposal`
2. Coordinate to get exactly 1 out of 10 members to reject (10%)
3. Get sufficient approvals to meet MinimalApprovalThreshold
4. Call `Release` on the proposal

**Expected vs Actual Result:**
- **Expected (per documentation)**: Proposal rejected because `1/10 = 10% >= 10% threshold`
  - Calculation per docs: `COUNT(rejection)/COUNT(members) < THRESHOLD` → `1/10 < 0.10` → FALSE (not releasable)
- **Actual (current code)**: Proposal passes because `1/10 = 10% NOT > 10% threshold`
  - Calculation in code: `(1 * 10000) > (1000 * 10)` → `10000 > 10000` → FALSE (not rejected, can release)

**Success Condition:**
Proposal is successfully released via the Release method despite having exactly the maximum rejection percentage, violating the documented governance rule that proposals should be rejected when rejection count reaches the maximal threshold.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L9-9)
```csharp
    private const int MaximalRejectionThreshold = 1000;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L64-70)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var rejectionMemberCount = proposal.Rejections.Count(parliamentMembers.Contains);
        return rejectionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L314-330)
```csharp
    private void CreateEmergencyResponseOrganization()
    {
        var createOrganizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 9000,
                MinimalVoteThreshold = 9000,
                MaximalAbstentionThreshold = 1000,
                MaximalRejectionThreshold = 1000
            },
            ProposerAuthorityRequired = false,
            ParliamentMemberProposingAllowed = true
        };

        State.EmergencyResponseOrganizationAddress.Value = CreateOrganization(createOrganizationInput);
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

**File:** docs/public-chain/auth-contract.md (L85-87)
```markdown
Requirements for a proposal to be *releasable*:
  
    COUNT(approval) >= THRESHOLD(approval) &&  COUNT(rejection) < THRESHOLD(rejection) && COUNT(abstention) < THRESHOLD(abstention) && SUM(COUNT(approval), COUNT(rejection), COUNT(abstention)) >= THRESHOLD(SUM)
```

**File:** docs/public-chain/auth-contract.md (L110-112)
```markdown
Requirements for a proposal to be *releasable*:
  
    COUNT(approval_token) >= THRESHOLD(approval_token) &&  COUNT(rejection_token) < THRESHOLD(rejection_token) && COUNT(abstention_token) < THRESHOLD(abstention_token) && SUM(COUNT(approval_token), COUNT(rejection_token), COUNT(abstention_token)) >= THRESHOLD(locked_token)
```

**File:** docs/public-chain/auth-contract.md (L141-143)
```markdown
Requirements for a proposal to be *releasable*:
  
    COUNT(approval) / COUNT (MINER_LIST) >= THRESHOLD(approval) &&  COUNT(rejection) / COUNT (MINER_LIST) < THRESHOLD(rejection) && COUNT(abstention) / COUNT (MINER_LIST) < THRESHOLD(abstention) && SUM(COUNT(approval), COUNT(rejection), COUNT(abstention)) / COUNT (MINER_LIST) >= THRESHOLD(SUM)
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L1390-1432)
```csharp
    [Fact]
    public async Task Check_ValidProposal_With_Rejected_Test()
    {
        // await InitializeParliamentContracts();

        var minimalApprovalThreshold = 6000;
        var maximalAbstentionThreshold = 1;
        var maximalRejectionThreshold = 1;
        var minimalVoteThreshold = 6000;
        var organizationAddress = await CreateOrganizationAsync(minimalApprovalThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, minimalVoteThreshold);

        //reject proposal
        var proposalTobeRejectedId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
        var parliamentContractStub = GetParliamentContractTester(InitialMinersKeyPairs[2]);
        var validProposals = await parliamentContractStub.GetNotVotedPendingProposals.CallAsync(new ProposalIdList
        {
            ProposalIds = { proposalTobeRejectedId }
        });
        validProposals.ProposalIds.Count.ShouldBe(1);

        await RejectionAsync(InitialMinersKeyPairs[0], proposalTobeRejectedId);
        validProposals = await parliamentContractStub.GetNotVotedPendingProposals.CallAsync(new ProposalIdList
        {
            ProposalIds = { proposalTobeRejectedId }
        });
        validProposals.ProposalIds.Count.ShouldBe(0);

        //abstain proposal
        var proposalTobeAbstainedId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
        validProposals = await parliamentContractStub.GetNotVotedPendingProposals.CallAsync(new ProposalIdList
        {
            ProposalIds = { proposalTobeAbstainedId }
        });
        validProposals.ProposalIds.Count.ShouldBe(1);

        await AbstainAsync(InitialMinersKeyPairs[0], proposalTobeAbstainedId);
        validProposals = await parliamentContractStub.GetNotVotedPendingProposals.CallAsync(new ProposalIdList
        {
            ProposalIds = { proposalTobeAbstainedId }
        });
        validProposals.ProposalIds.Count.ShouldBe(0);
    }
```
