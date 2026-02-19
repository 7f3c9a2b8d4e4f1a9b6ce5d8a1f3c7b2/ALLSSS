### Title
Parliament Organization Governance Lock via Impossible Threshold Configuration

### Summary
The `ChangeOrganizationThreshold()` function validates new thresholds only against the constant `AbstractVoteTotal` (10,000) but never checks if the thresholds are achievable given the actual current parliament size. An attacker can pass a single malicious proposal that sets mathematically valid but practically impossible thresholds (e.g., 100% approval with 0% tolerance for rejection/abstention), permanently locking the organization since no future proposal—including one to restore reasonable thresholds—can ever reach consensus.

### Finding Description

The vulnerability exists in the `ChangeOrganizationThreshold()` method which allows organizations to update their governance thresholds through a proposal mechanism. [1](#0-0) 

The function retrieves the organization and updates its `ProposalReleaseThreshold`, then validates using the `Validate(organization)` helper method: [2](#0-1) 

The validation only checks that thresholds are mathematically consistent with the constant `AbstractVoteTotal` (10,000, representing 100% in basis points): [3](#0-2) 

**Root Cause**: The validation never compares thresholds against the actual current parliament member count. It only ensures thresholds don't exceed 10,000 and maintain internal consistency.

**Why Protection Fails**: An attacker can set extreme but "valid" thresholds such as:
- `MinimalApprovalThreshold = 10000` (100% approval required)
- `MinimalVoteThreshold = 10000` (100% participation required)  
- `MaximalRejectionThreshold = 0` (any single rejection blocks the proposal)
- `MaximalAbstentionThreshold = 0` (any single abstention blocks the proposal)

These values pass all validation checks (10000 ≤ 10000, 10000 ≤ 10000, 10000 > 0, etc.), but create an impossible governance condition.

The approval logic shows why this is unachievable: [4](#0-3) 

With 100% thresholds and 0% tolerance, the formula `approvedMemberCount * 10000 >= 10000 * parliamentMembers.Count` requires ALL members to approve, while the rejection check `rejectionMemberCount * 10000 > 0 * parliamentMembers.Count` means even ONE rejection blocks the proposal: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Harm**: The organization's governance becomes permanently non-functional. No proposals can pass, including proposals to restore reasonable thresholds.

**Operational Damage**: 
- All governance operations cease immediately after the malicious threshold change
- Critical system upgrades, parameter adjustments, or emergency responses become impossible
- If this affects the default Parliament organization (which governs core system contracts), the entire AElf blockchain governance could be paralyzed

**Affected Parties**:
- Organization members lose all governance capabilities
- Users depending on the organization's governance decisions
- The broader AElf ecosystem if the default organization is affected

**Severity Justification**: HIGH
- Complete governance DoS with no recovery path
- Requires only one malicious proposal to be approved under current thresholds
- Impact is immediate and permanent
- Can affect critical system governance organizations

### Likelihood Explanation

**Attacker Capabilities**: 
- Attacker needs ability to create and pass ONE proposal under the current organization thresholds
- For organizations with reasonable thresholds (e.g., 51% approval), this requires either:
  - Compromising/colluding with a majority of current members, OR
  - Being an authorized proposer with majority support for a "threshold update" that appears legitimate

**Attack Complexity**: LOW
- Single proposal with carefully crafted but validation-passing threshold values
- No complex transaction sequences or timing dependencies
- No exploitation of race conditions or reentrancy

**Feasibility Conditions**:
- Organization must allow threshold changes (which is the intended design)
- Attacker must have proposal creation rights and enough support to pass ONE proposal
- More likely in smaller organizations or during governance transitions

**Detection Constraints**: 
- The malicious proposal may appear as a "security hardening" measure ("requiring unanimous approval for critical decisions")
- No automatic detection of impossible threshold configurations
- Impact only becomes evident when the next proposal fails to reach consensus

**Probability**: MEDIUM-HIGH
- Social engineering risk: framing as "security enhancement"
- Accidental misconfiguration also possible (honest mistake setting thresholds)
- Lower barrier if organization already has lax governance

### Recommendation

**Code-Level Mitigation**:

Add a validation check in `Validate(Organization organization)` method that enforces a maximum approval threshold relative to practical governance needs:

```csharp
private bool Validate(Organization organization)
{
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    
    // Existing checks...
    var baseChecks = proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
                     proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
                     proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
                     proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
                     proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
                     proposalReleaseThreshold.MaximalAbstentionThreshold +
                     proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
                     proposalReleaseThreshold.MaximalRejectionThreshold +
                     proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
    
    if (!baseChecks) return false;
    
    // NEW CHECK: Prevent impossible threshold combinations
    // Ensure there's at least 1% margin for practical governance
    // MaximalRejection + MinimalApproval must leave room for at least 1% non-participation
    var impossibleThreshold = proposalReleaseThreshold.MaximalRejectionThreshold + 
                              proposalReleaseThreshold.MinimalApprovalThreshold > AbstractVoteTotal - 100;
    
    var impossibleAbstention = proposalReleaseThreshold.MaximalAbstentionThreshold + 
                               proposalReleaseThreshold.MinimalApprovalThreshold > AbstractVoteTotal - 100;
    
    // Prevent 100% approval requirement with 0% rejection/abstention tolerance
    var unanimousWithZeroTolerance = proposalReleaseThreshold.MinimalApprovalThreshold >= AbstractVoteTotal &&
                                     (proposalReleaseThreshold.MaximalRejectionThreshold == 0 || 
                                      proposalReleaseThreshold.MaximalAbstentionThreshold == 0);
    
    return !impossibleThreshold && !impossibleAbstention && !unanimousWithZeroTolerance;
}
```

**Alternative/Additional Mitigation**:
Implement a "threshold change cooldown" mechanism where threshold changes cannot make governance more restrictive than a maximum hardcoded limit (e.g., cannot require >95% approval, cannot set rejection/abstention tolerance <5%).

**Test Cases to Add**:
1. Test that setting `MinimalApprovalThreshold = 10000, MaximalRejectionThreshold = 0` fails validation
2. Test that setting `MinimalApprovalThreshold = 10000, MaximalAbstentionThreshold = 0` fails validation
3. Test that threshold changes preserving at least 5% governance margin succeed
4. Test attempting to lock governance and verify the organization can still pass a recovery proposal

### Proof of Concept

**Initial State**:
- Parliament organization exists with reasonable thresholds (e.g., 60% approval, 7500 vote threshold, 20% max rejection, 20% max abstention)
- Parliament has 10 active members
- Attacker can create proposals and has support of 6+ members (60% to pass current threshold)

**Attack Steps**:

1. **Create Malicious Threshold Change Proposal**:
   - Create proposal calling `ChangeOrganizationThreshold` with:
     - `MinimalApprovalThreshold = 10000` (100%)
     - `MinimalVoteThreshold = 10000` (100%)
     - `MaximalRejectionThreshold = 0` (0%)
     - `MaximalAbstentionThreshold = 0` (0%)
   - Frame as "security enhancement requiring unanimous approval"

2. **Get Proposal Approved Under Current Thresholds**:
   - Obtain 6 approvals (60% of 10 members)
   - Proposal passes current 60% threshold
   - Proposer calls `Release()` to execute

3. **Threshold Change Executes**:
   - `ChangeOrganizationThreshold()` validates the new thresholds
   - All validation checks pass (10000 ≤ 10000, 10000 + 0 ≤ 10000, etc.)
   - New impossible thresholds are saved to state

4. **Verify Governance Lock**:
   - Create any proposal (including proposal to restore old thresholds)
   - Attempt to get it approved:
     - Need all 10 members to approve (100% requirement)
     - If 9 approve and 1 rejects: rejection check `1 * 10000 > 0 * 10` → proposal blocked
     - If 9 approve and 1 abstains: abstention check `1 * 10000 > 0 * 10` → proposal blocked
     - If 9 approve and 1 doesn't vote: only 9 votes, need 10 → proposal blocked
   - Proposal cannot reach consensus under any realistic scenario

**Expected Result**: Proposal to change thresholds should be rejected during validation

**Actual Result**: Malicious thresholds pass validation and permanently lock the organization's governance

**Success Condition**: After attack, no new proposals can pass, including proposals to restore governance functionality. The organization requires simultaneous unanimous participation with zero dissent—an impossible standard in any decentralized system.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L147-160)
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L72-78)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(parliamentMembers.Contains);
        return abstentionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalAbstentionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L80-92)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached = IsVoteThresholdReached(proposal, organization, parliamentMembers);
        return isVoteThresholdReached;
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
