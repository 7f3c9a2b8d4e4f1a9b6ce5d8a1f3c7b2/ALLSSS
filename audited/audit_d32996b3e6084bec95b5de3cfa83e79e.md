### Title
Abstention Vote Stuffing Allows Proposal Release with Minimal Approval

### Summary
The Referendum contract's `IsReleaseThresholdReached` function counts Abstain votes toward `MinimalVoteThreshold` without requiring corresponding approval support. An attacker can exploit organizations configured with `MinimalApprovalThreshold` significantly lower than `MinimalVoteThreshold` by casting minimal approval votes and stuffing the remainder with abstention votes to artificially inflate participation and bypass meaningful community approval requirements.

### Finding Description

The vulnerability exists in the threshold validation logic of the Referendum contract. The `IsReleaseThresholdReached` function calculates total votes by summing all three vote types (Rejection, Abstention, Approval) and checks if this total meets `MinimalVoteThreshold`. [1](#0-0) 

The function then validates that abstention and rejection counts don't exceed their maximal thresholds: [2](#0-1) 

Finally, it checks if approval count meets the minimal approval threshold: [3](#0-2) 

The organization validation only enforces that `MinimalApprovalThreshold <= MinimalVoteThreshold` with no restriction on the gap size: [4](#0-3) 

The Abstain function allows any token holder to cast abstention votes with their token allowance, which are added to the proposal's abstention count: [5](#0-4) 

**Root Cause:** Abstain votes contribute to meeting the participation threshold (`MinimalVoteThreshold`) but represent neither support nor opposition. This creates a loophole where proposals can be released with minimal real approval if the organization's thresholds have a wide gap.

**Why Protections Fail:** The validation logic assumes that meeting `MinimalVoteThreshold` implies meaningful community engagement. However, when `MinimalApprovalThreshold` is much lower than `MinimalVoteThreshold`, an attacker can satisfy the participation requirement primarily through abstention votes while meeting only the bare minimum approval requirement.

### Impact Explanation

**Governance Bypass:** Proposals can be released without broad community support, undermining the democratic intent of the referendum governance mechanism. If an organization is configured with:
- `MinimalVoteThreshold = 10,000 tokens`
- `MinimalApprovalThreshold = 100 tokens`
- `MaximalAbstentionThreshold = 9,900 tokens`

An attacker controlling or coordinating 10,000 tokens can release a proposal with only 1% actual approval (100 tokens) by casting 9,900 tokens as abstention votes. This represents a 99% participation without meaningful approval.

**Affected Parties:**
- Token holders whose governance power is diluted by artificial participation
- The organization itself, which may execute proposals lacking true community consensus
- Downstream contracts/systems affected by released proposals

**Severity Justification:** High severity due to direct governance impact, allowing attackers to bypass the intended approval requirements and potentially execute malicious proposals that would not gain legitimate community support.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Control sufficient tokens (directly or through coordination) to cast abstention votes bridging the gap between `MinimalApprovalThreshold` and `MinimalVoteThreshold`
2. Obtain minimal approval votes to meet `MinimalApprovalThreshold`
3. Organization must be configured with a significant gap between the two thresholds

**Attack Complexity:** Medium - The attack requires:
- Token acquisition/coordination for abstention voting
- Temporary token locking during voting period (tokens are reclaimable after release or expiration per line 115-122 of Referendum.cs)
- No special permissions beyond token ownership

**Feasibility Conditions:**
- Organizations where governance creators set `MinimalApprovalThreshold` far below `MinimalVoteThreshold` (the validation allows this)
- Economic viability when proposal value exceeds token acquisition/locking costs
- Sufficient `MaximalAbstentionThreshold` to accommodate stuffing votes

**Detection:** The attack is detectable on-chain through vote distribution analysis showing disproportionate abstention votes, but may not be caught before proposal release.

**Probability:** Medium likelihood - While requiring specific threshold configurations, the validation logic permits such configurations without warning, and the economic barrier (temporary token locking) is surmountable for high-value proposals.

### Recommendation

**Code-Level Mitigation:**

Strengthen the organization validation to enforce tighter coupling between `MinimalApprovalThreshold` and `MinimalVoteThreshold`. Add a validation check in the `Validate` function:

```csharp
// In Referendum_Helper.cs, modify Validate function around line 98
return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
       proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
       // NEW: Require MinimalApprovalThreshold to be at least a meaningful percentage of MinimalVoteThreshold
       proposalReleaseThreshold.MinimalApprovalThreshold >= proposalReleaseThreshold.MinimalVoteThreshold.Mul(50).Div(100) && // At least 50%
       proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
       proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
```

**Alternative Approach:** Modify `IsReleaseThresholdReached` to exclude abstention votes from the participation threshold calculation, or require that approval votes alone constitute a minimum percentage of total votes.

**Invariant Checks:**
- `MinimalApprovalThreshold >= MinimalVoteThreshold * MINIMUM_APPROVAL_RATIO` (where MINIMUM_APPROVAL_RATIO ≥ 0.5)
- Organizations should be prevented from having configurations that enable vote stuffing

**Test Cases:**
1. Test creating organization with `MinimalApprovalThreshold = 100` and `MinimalVoteThreshold = 10000` - should fail
2. Test releasing proposal with high abstention votes but minimal approval - should fail with stricter validation
3. Test that legitimate voting patterns (balanced distribution) still work correctly

### Proof of Concept

**Required Initial State:**
1. Organization created with:
   - `MinimalVoteThreshold = 10,000 tokens`
   - `MinimalApprovalThreshold = 100 tokens`
   - `MaximalAbstentionThreshold = 9,900 tokens`
   - `MaximalRejectionThreshold = 0 tokens`
   - `TokenSymbol = "ELF"`
2. Attacker controls or coordinates 10,000 ELF tokens
3. A proposal is created targeting a sensitive action

**Transaction Steps:**
1. Attacker approves 100 ELF allowance to proposal virtual address
2. Attacker calls `Approve(proposalId)` with 100 tokens → `ApprovalCount = 100`
3. Attacker approves 9,900 ELF allowance to proposal virtual address (from same or different addresses)
4. Attacker calls `Abstain(proposalId)` with 9,900 tokens → `AbstentionCount = 9,900`
5. Proposer calls `Release(proposalId)`

**Expected vs Actual Result:**

Expected (secure behavior): Proposal should not release because only 1% of participation represents actual approval.

Actual (vulnerable behavior):
- Line 15-16 check: `(0 + 9900 + 100) = 10,000 >= 10,000` ✓ Pass
- Line 20 check: `0 > 0` ✗ Pass (no rejection)
- Line 24 check: `9,900 > 9,900` ✗ Pass (equal is allowed)
- Line 28 check: `100 >= 100` ✓ Pass
- **Proposal is released successfully**

**Success Condition:** The proposal releases and executes its target action despite having only 100 out of 10,000 tokens (1%) as actual approval, with the remaining 9,900 tokens being neutral abstention votes that artificially inflated participation to meet the threshold.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L15-16)
```csharp
        var enoughVote = proposal.RejectionCount.Add(proposal.AbstentionCount).Add(proposal.ApprovalCount) >=
                         proposalReleaseThreshold.MinimalVoteThreshold;
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L20-26)
```csharp
        var isRejected = proposal.RejectionCount > proposalReleaseThreshold.MaximalRejectionThreshold;
        if (isRejected)
            return false;

        var isAbstained = proposal.AbstentionCount > proposalReleaseThreshold.MaximalAbstentionThreshold;
        if (isAbstained)
            return false;
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L28-28)
```csharp
        return proposal.ApprovalCount >= proposalReleaseThreshold.MinimalApprovalThreshold;
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L98-99)
```csharp
        return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L100-112)
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
```
