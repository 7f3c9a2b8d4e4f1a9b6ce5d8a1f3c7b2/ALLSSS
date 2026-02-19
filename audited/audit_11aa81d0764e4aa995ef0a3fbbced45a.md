### Title
Referendum Contract Allows Setting Unbounded MinimalVoteThreshold Leading to Permanent Governance Lockout

### Summary
The Referendum contract's `ChangeOrganizationThreshold` function lacks upper bound validation for `MinimalVoteThreshold`, allowing an organization to set this value to `Int64.MaxValue` or any unreachably high number. This makes all future proposals impossible to release, permanently locking the organization's governance functionality. Unlike Parliament and Association contracts which enforce maximum threshold limits, Referendum has no such protection.

### Finding Description

The vulnerability exists in the threshold validation logic of the Referendum contract. When `ChangeOrganizationThreshold` is called, it updates the organization's `ProposalReleaseThreshold` and validates it using the `Validate` method. [1](#0-0) 

The `Validate` method only checks relative relationships between threshold values but imposes no upper bound on `MinimalVoteThreshold`: [2](#0-1) 

The validation only requires:
- `MinimalApprovalThreshold <= MinimalVoteThreshold`
- `MinimalApprovalThreshold > 0`
- `MaximalAbstentionThreshold >= 0`
- `MaximalRejectionThreshold >= 0`

There is **no check** preventing `MinimalVoteThreshold` from being set to `Int64.MaxValue` (9,223,372,036,854,775,807).

When proposals attempt to release, the `IsReleaseThresholdReached` method checks if total votes meet the threshold: [3](#0-2) 

If `MinimalVoteThreshold` is set to `Int64.MaxValue`, line 15-16 will never be satisfied since the total token supply in any realistic scenario is far less than `Int64.MaxValue`.

**Contrast with Other Governance Contracts:**

The Parliament contract enforces an upper bound using `AbstractVoteTotal = 10000`: [4](#0-3) [5](#0-4) 

The Association contract enforces that `MinimalVoteThreshold` cannot exceed the organization member count: [6](#0-5) 

**Referendum contract is the only governance contract missing this critical validation.**

### Impact Explanation

**Severity: HIGH - Permanent Governance DoS**

Once an organization's `MinimalVoteThreshold` is set to an unreachable value, the organization's governance becomes **permanently non-functional**:

1. **Complete Governance Lockout**: All existing and future proposals can never be released because the vote threshold at line 15-16 of `IsReleaseThresholdReached` can never be satisfied.

2. **No Recovery Mechanism**: Since `ChangeOrganizationThreshold` itself requires a proposal to be released, and proposals cannot be released, the organization cannot fix its own thresholds. This creates an unrecoverable state.

3. **Affected Parties**: All members of the affected Referendum organization lose their governance rights permanently. Any critical operations that require governance approval (upgrades, parameter changes, fund releases) become impossible.

4. **Protocol Impact**: If critical protocol operations are controlled by Referendum organizations, this could impact the entire protocol's ability to adapt or upgrade.

The attack is **irreversible** and causes **total loss of governance functionality** for the affected organization.

### Likelihood Explanation

**Likelihood: HIGH - Single Malicious Proposal Attack**

**Attacker Capabilities Required:**
- Must be in the organization's proposer whitelist (standard requirement for creating proposals)
- Must successfully pass one malicious proposal through the organization's current approval process

**Attack Complexity: LOW**
1. Attacker creates a proposal calling `ChangeOrganizationThreshold` with `MinimalVoteThreshold = Int64.MaxValue` and `MinimalApprovalThreshold = Int64.MaxValue`
2. The proposal needs to pass current voting thresholds (one-time requirement)
3. Attacker or any authorized party releases the proposal
4. Organization is permanently locked

**Feasibility Conditions:**
- **Social Engineering**: The attack could be disguised as a "security improvement" to increase voting requirements
- **Compromised Proposer**: A single compromised or malicious whitelisted proposer can initiate this attack
- **Majority Collusion**: If enough organization members collude, they can deliberately lock the organization

**Economic Cost: MINIMAL**
- Only requires gas fees to create and release one proposal
- No financial stake or capital requirements beyond normal proposal creation

**Detection Difficulty:**
- The malicious threshold change may not be immediately obvious
- Organizations may not realize they're locked until attempting to release the next proposal
- No automatic alerts or warnings exist for extreme threshold values

**Probability Assessment: MEDIUM-HIGH**
While requiring proposal approval is a barrier, the combination of low cost, irreversible impact, and potential for social engineering or insider attacks makes this a realistic threat vector.

### Recommendation

**Immediate Fix:**
Add maximum value validation to the `Validate` method in `Referendum_Helper.cs`. Since Referendum uses token-based voting (unlike Parliament's percentage-based system), the upper bound should be tied to the token's total supply:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");
    
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    var tokenInfo = GetTokenInfo(organization.TokenSymbol);
    var maxSupply = tokenInfo.TotalSupply; // Or tokenInfo.Supply for circulating supply
    
    return proposalReleaseThreshold.MinimalVoteThreshold <= maxSupply &&
           proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold + 
           proposalReleaseThreshold.MinimalApprovalThreshold <= maxSupply &&
           proposalReleaseThreshold.MaximalRejectionThreshold + 
           proposalReleaseThreshold.MinimalApprovalThreshold <= maxSupply;
}
```

**Additional Invariant Checks:**
- Add sanity checks ensuring `MinimalVoteThreshold <= tokenTotalSupply` during both `CreateOrganization` and `ChangeOrganizationThreshold`
- Consider adding additional validation that `MinimalApprovalThreshold <= tokenTotalSupply`

**Test Cases to Add:**
1. Test attempting to set `MinimalVoteThreshold` to `Int64.MaxValue` - should fail
2. Test attempting to set `MinimalVoteThreshold` above token total supply - should fail
3. Test attempting to set thresholds that sum to more than token supply - should fail
4. Test legitimate threshold changes within bounds - should succeed

### Proof of Concept

**Initial State:**
- Referendum organization exists with address `0xREFORG`
- Organization has token symbol "ELF" with total supply 1,000,000,000 (1 billion)
- Organization has normal thresholds: `MinimalVoteThreshold = 500,000,000`, `MinimalApprovalThreshold = 400,000,000`
- Attacker is in proposer whitelist

**Attack Sequence:**

**Step 1**: Attacker creates malicious proposal
```
CreateProposal({
  contract_method_name: "ChangeOrganizationThreshold",
  to_address: 0xREFORG,
  organization_address: 0xREFORG,
  params: ProposalReleaseThreshold {
    minimal_vote_threshold: 9223372036854775807 (Int64.MaxValue),
    minimal_approval_threshold: 9223372036854775807 (Int64.MaxValue),
    maximal_rejection_threshold: 0,
    maximal_abstention_threshold: 0
  }
})
```

**Step 2**: Proposal passes validation and gets created (proposal ID: `0xPROP1`)

**Step 3**: Attacker or colluding members approve proposal
- Members call `Approve(0xPROP1)` until current thresholds are met
- Proposal reaches `IsReleaseThresholdReached = true` under **current** thresholds

**Step 4**: Attacker releases proposal
```
Release(0xPROP1)
```

**Step 5**: Proposal executes `ChangeOrganizationThreshold`
- Line 128-130 in Referendum.cs: Organization threshold is updated
- Line 129: `Validate(organization)` passes because it only checks relative constraints
- Organization now has `MinimalVoteThreshold = Int64.MaxValue`

**Step 6**: Verify governance lockout
- Any user creates a new legitimate proposal (`0xPROP2`)
- Users attempt to approve and release `0xPROP2`
- Even if ALL 1 billion tokens approve, total votes = 1,000,000,000
- Line 15-16 in `IsReleaseThresholdReached`: `1,000,000,000 >= 9,223,372,036,854,775,807` evaluates to `false`
- `Release(0xPROP2)` fails with "Not approved." error

**Expected Result**: Proposal `0xPROP2` should be releasable after sufficient votes

**Actual Result**: Proposal `0xPROP2` can NEVER be released because vote threshold is mathematically impossible to reach

**Success Condition**: Organization governance is permanently non-functional, no proposals can ever be released again

### Citations

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
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
