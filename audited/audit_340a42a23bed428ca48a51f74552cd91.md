### Title
Association Organization Permanent Deadlock via 100% Vote Threshold Requirement

### Summary
The validation in `Association_Helper.cs` allows `MinimalVoteThreshold` to equal `organizationMemberCount`, enabling organizations to require 100% member participation for proposals. This creates a permanent deadlock scenario where a single unavailable or malicious member can prevent all future governance actions, including member removal and threshold changes, effectively locking any funds or permissions controlled by the organization.

### Finding Description

The vulnerability exists in the organization validation logic: [1](#0-0) 

The validation uses `<=` which allows `MinimalVoteThreshold` to equal `organizationMemberCount`. When this configuration is chosen, the organization requires unanimous participation (100% of members must vote) for any proposal to reach the release threshold. [2](#0-1) 

The vote counting logic requires at least `MinimalVoteThreshold` total votes. Combined with the fact that all organization modification methods require proposals to execute: [3](#0-2) [4](#0-3) 

This creates an unbreakable deadlock when `MinimalVoteThreshold = organizationMemberCount`:
1. If one member becomes unavailable/malicious, no proposal can reach `MinimalVoteThreshold`
2. Cannot remove the unavailable member (requires passing a proposal first)
3. Cannot lower the threshold (requires passing a proposal first)
4. Cannot add new members to compensate (requires passing a proposal first)

All modification methods call `Validate(organization)` after changes, preventing any escape from this state.

### Impact Explanation

**Permanent Loss of Organization Control:**
- Organizations using this configuration lose all governance capability if a single member becomes unavailable
- Any tokens, permissions, or assets controlled by the organization become permanently inaccessible
- No recovery mechanism exists

**Griefing/Extortion Attack:**
- A malicious founding member can intentionally create an organization with `MinimalVoteThreshold = memberCount`
- After other members deposit funds or assign permissions to the organization
- The malicious member refuses to participate, holding all other members' assets hostage
- Other members cannot remove the malicious actor or modify the organization

**Affected Users:**
- All Association organizations created with `MinimalVoteThreshold = organizationMemberCount`
- Particularly severe for financial organizations controlling significant token amounts
- Any multi-party agreements relying on Association contract governance

While system contracts intentionally use this pattern with contract members (which are always available), user-created organizations with human members face real unavailability risks (lost keys, death, malicious behavior). [5](#0-4) 

### Likelihood Explanation

**High Likelihood Factors:**
- `MinimalVoteThreshold = memberCount` appears to be a reasonable governance choice for organizations wanting strong consensus
- No warning exists that this creates unrecoverable deadlock risk
- Member unavailability is common (lost keys, inactive users, disputes)
- Griefing attack cost is zero - malicious member simply stops participating

**Execution Path:**
1. Attacker or well-meaning user creates organization via `CreateOrganization` with `MinimalVoteThreshold = memberCount`
2. Organization operates normally while all members participate
3. One member becomes unavailable (accident) or refuses to participate (malicious)
4. Organization is permanently locked - no proposals can pass, no modifications possible

**No Recovery Mechanism:**
All organization state changes require `Context.Sender = organizationAddress`, which means they must be executed through the organization's own governance process. There is no admin override or emergency mechanism. [6](#0-5) 

### Recommendation

**Option 1: Prevent Unsafe Configuration (Breaking Change)**
Change the validation to require strict inequality:
```csharp
// Line 72 in Association_Helper.cs
return proposalReleaseThreshold.MinimalVoteThreshold < organizationMemberCount && // Changed from <=
```

This ensures at least one member can be absent while still allowing proposals to pass, preventing permanent deadlock.

**Option 2: Add Emergency Override (Non-Breaking)**
Add an emergency escape mechanism for user-created organizations that have been inactive for an extended period, allowing a supermajority of remaining members to override the threshold.

**Option 3: Distinguish System vs User Organizations**
Allow `MinimalVoteThreshold = memberCount` only for system contracts where members are other contracts (always available), but enforce `<` for user-created organizations.

**Recommended Approach:**
Implement Option 1 for new organizations and Option 2 as a safety valve for existing ones. Add documentation warning about 100% participation requirements.

**Test Cases to Add:**
- Test that `MinimalVoteThreshold = organizationMemberCount` is rejected during creation
- Test that member removal fails when it would violate the new threshold constraint  
- Test recovery paths when organizations approach deadlock conditions

### Proof of Concept

**Initial State:**
- 5 users: A (creator), B, C, D, E
- Organization created with:
  - `OrganizationMemberList = {A, B, C, D, E}`
  - `MinimalVoteThreshold = 5`
  - `MinimalApprovalThreshold = 3`

**Attack Sequence:**

1. **Organization Creation (Success):**
   - User A calls `CreateOrganization` with above parameters
   - Validation passes: `5 <= 5` ✓
   - Organization address returned

2. **Transfer Funds to Organization (Success):**
   - Users transfer 1000 ELF total to organization address
   - Organization now controls 1000 ELF

3. **Member E Becomes Unavailable (or Malicious):**
   - Member E loses private key / refuses to participate

4. **Attempt to Remove Member E (Fails):**
   - Create proposal to call `RemoveMember(E)`
   - Members A, B, C, D vote (4 votes)
   - Proposal cannot be released: `4 < 5` (MinimalVoteThreshold not met) ❌

5. **Attempt to Lower Threshold (Fails):**
   - Create proposal to call `ChangeOrganizationThreshold` (reduce to 4)
   - Members A, B, C, D vote (4 votes)
   - Proposal cannot be released: `4 < 5` ❌

6. **Attempt Any Other Action (Fails):**
   - All proposals require 5 votes but only 4 members are available
   - **PERMANENT DEADLOCK**

**Expected vs Actual Result:**
- Expected: Organization should have recovery mechanism or prevent unsafe configuration
- Actual: Organization is permanently locked, 1000 ELF is permanently inaccessible

**Success Condition for Attack:**
- Organization cannot execute any proposals
- Funds remain locked indefinitely
- No legitimate recovery path exists

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-58)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-72)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
```

**File:** contract/AElf.Contracts.Association/Association.cs (L203-209)
```csharp
    public override Empty ChangeOrganizationThreshold(ProposalReleaseThreshold input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L235-236)
```csharp
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L266-273)
```csharp
    public override Empty RemoveMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input);
        Assert(removeResult, "Remove member failed.");
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L641-642)
```csharp
                MinimalApprovalThreshold = organizationMembers.ToList().Count,
                MinimalVoteThreshold = organizationMembers.ToList().Count,
```
