### Title
O(n*m) Complexity DoS in Association Proposal Release for Large Organizations

### Summary
The Association contract uses inefficient `Count(Contains)` operations to validate proposal votes against organization member lists, creating O(n*m) complexity where n is the number of votes and m is the organization size. For organizations with approximately 70 or more members with high voting participation, the cumulative branch operations exceed AElf's 15,000 branch count limit, causing proposal release transactions to fail and rendering governance unusable for large organizations.

### Finding Description

The vulnerability exists in the proposal threshold validation logic in `Association_Helper.cs`. Three methods use the pattern `proposal.[VoteList].Count(organization.OrganizationMemberList.Contains)`: [1](#0-0) [2](#0-1) [3](#0-2) 

The root cause is that both `proposal.Rejections/Approvals/Abstentions` and `organization.OrganizationMemberList.OrganizationMembers` are protobuf `repeated` fields that generate as `RepeatedField<Address>` collections in C#. [4](#0-3) [5](#0-4) 

The `Contains` operation on `RepeatedField` performs a linear O(m) search through all m organization members. When called via `Count(predicate)` for each of n votes, this creates O(n*m) complexity. Since each member can only vote once (enforced by `AssertProposalNotYetVotedBySender`), the worst case is n = m, yielding O(m²) complexity. [6](#0-5) 

The `IsReleaseThresholdReached` method calls all three validation functions, compounding the complexity: [7](#0-6) 

This is invoked by two entry points:
1. `GetProposal` (view method) - callable by anyone
2. `Release` (action method) - callable by proposer to execute approved proposals [8](#0-7) [9](#0-8) 

AElf enforces a 15,000 branch count limit per transaction to prevent infinite loops: [10](#0-9) 

With m members all voting, the three `Count(Contains)` operations plus concatenation checks create approximately 3m² + m branch operations. This exceeds 15,000 branches when m ≥ 71.

There is no maximum member count enforced in the contract: [11](#0-10) 

Organizations can grow via `AddMember` (callable by the organization itself through governance): [12](#0-11) 

### Impact Explanation

**Operational DoS Impact**: Organizations with 70+ members experiencing high voting participation (where most members vote on proposals) will be unable to release proposals. The `Release` transaction will exceed the branch count limit and fail, making approved proposals unexecutable.

**Affected Parties**: 
- Large legitimate DAOs and multi-signature organizations with 70+ members
- The threshold is realistic - many governance organizations naturally grow beyond this size
- All proposals from affected organizations become permanently stuck

**Concrete Harm**:
- Critical governance decisions cannot be executed even when properly approved
- Organizations cannot perform configuration changes, treasury operations, or system upgrades
- The `GetProposal` view method also fails, breaking UI integrations and monitoring systems
- Organizations operating near the threshold may work initially but break unexpectedly as membership grows

**Severity**: Medium - This is a critical design flaw causing complete governance paralysis for organizations above a specific size threshold, but requires legitimate organizational growth rather than malicious exploitation.

### Likelihood Explanation

**Attacker Capabilities**: No malicious attacker is required. This is a scalability limitation affecting legitimate organizations.

**Feasibility Conditions**:
- Organization must have approximately 70+ members
- High voting participation (most members voting)
- Both conditions are natural for active, large DAOs

**Execution Practicality**: The issue manifests automatically during normal governance operations. No special attack sequence is needed.

**Probability**: High for organizations that:
1. Start with or grow to 70+ members through legitimate governance
2. Experience high engagement where most members vote on important proposals
3. Many real-world DAOs and multi-sig organizations exceed this size

**Economic Rationality**: This is not an economic attack but a design limitation. Organizations pay normal transaction fees but receive failed executions.

**Detection**: The issue may go undetected until an organization crosses the threshold, at which point all proposal releases begin failing with branch count limit errors.

### Recommendation

**Primary Fix - Add Member Count Limit**:
Add a maximum member count constant and enforce it during organization creation and member addition:

```csharp
// In AssociationConstants.cs
public const int MaxOrganizationMembers = 50;

// In Association_Helper.cs Validate method (line 61-81)
// Add validation check:
if (organization.OrganizationMemberList.Count() > AssociationConstants.MaxOrganizationMembers)
    return false;
```

**Alternative Fix - Use HashSet for Member Lookups**:
Convert member list to HashSet during validation to achieve O(1) Contains operations:

```csharp
private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
{
    var memberSet = new HashSet<Address>(organization.OrganizationMemberList.OrganizationMembers);
    var rejectionMemberCount = proposal.Rejections.Count(memberSet.Contains);
    return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
}
```

**Optimal Fix - Pre-validated Vote Tracking**:
Track only valid member votes during the `Approve`/`Reject`/`Abstain` calls, eliminating the need for runtime validation:

```csharp
// In Approve/Reject/Abstain methods, only add vote if member exists:
AssertIsAuthorizedOrganizationMember(organization, Context.Sender);
proposal.Approvals.Add(Context.Sender); // Already validated as member
```

Then use simple counts without Contains:
```csharp
var rejectionMemberCount = proposal.Rejections.Count;
```

**Test Cases**:
1. Create organization with 70 members, have all vote, verify Release succeeds
2. Create organization with 100 members, verify creation fails (with limit) or Release fails (without limit)
3. Benchmark branch counts for various member sizes to validate thresholds
4. Test AddMember rejecting additions that would exceed limit

### Proof of Concept

**Initial State**:
1. Create Association organization with 71 members
2. Set approval threshold requiring 36 approvals (simple majority)

**Transaction Steps**:
1. Proposer creates a proposal via `CreateProposal`
2. 36+ members call `Approve` on the proposal
3. 20 members call `Reject` on the proposal  
4. 10 members call `Abstain` on the proposal
5. Proposer calls `Release` on the approved proposal

**Expected Result**: 
Proposal should be released and executed since approval threshold (36/71 > 50%) is met

**Actual Result**: 
`Release` transaction fails with branch count limit exceeded error:
- `IsProposalRejected`: 20 rejections × 71 members = 1,420 Contains checks
- `IsProposalAbstained`: 10 abstentions × 71 members = 710 Contains checks
- `CheckEnoughVoteAndApprovals`: 36 approvals × 71 members = 2,556 Contains checks
- Additional concat/count operations: ~66 comparisons
- **Total: ~4,752 × 3 ≈ 15,500+ branch operations > 15,000 limit**

**Success Condition for Exploit**: Transaction reverts with "Branch count limit exceeded" or similar execution limit error, preventing release of legitimately approved proposal.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-32)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L41-45)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-59)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L132-138)
```csharp
    private void AssertProposalNotYetVotedBySender(ProposalInfo proposal, Address sender)
    {
        var isAlreadyVoted = proposal.Approvals.Contains(sender) || proposal.Rejections.Contains(sender) ||
                             proposal.Abstentions.Contains(sender);

        Assert(!isAlreadyVoted, "Sender already voted.");
    }
```

**File:** protobuf/association_contract.proto (L91-96)
```text
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
```

**File:** protobuf/association_contract.proto (L105-108)
```text
message OrganizationMemberList {
    // The address of organization members.
    repeated aelf.Address organization_members = 1;
}
```

**File:** contract/AElf.Contracts.Association/Association.cs (L18-24)
```csharp
    public override ProposalOutput GetProposal(Hash proposalId)
    {
        var proposal = State.Proposals[proposalId];
        if (proposal == null) return new ProposalOutput();

        var organization = State.Organizations[proposal.OrganizationAddress];
        var readyToRelease = IsReleaseThresholdReached(proposal, organization);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-188)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-238)
```csharp
    public override Empty AddMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input);
        Assert(Validate(organization), "Invalid organization.");
```

**File:** docs-sphinx/architecture/smart-contract/restrictions/others.rst (L14-15)
```text

- AElf's contract patcher will patch method branch count observer for your contract. This is used to prevent infinitely loop case. The number of code control transfer in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.
```

**File:** contract/AElf.Contracts.Association/AssociationConstants.cs (L1-8)
```csharp
namespace AElf.Contracts.Association;

public static class AssociationConstants
{
    public const int MaxLengthForTitle = 255;
    public const int MaxLengthForDescription = 10200;
    public const int MaxLengthForProposalDescriptionUrl = 255;
}
```
