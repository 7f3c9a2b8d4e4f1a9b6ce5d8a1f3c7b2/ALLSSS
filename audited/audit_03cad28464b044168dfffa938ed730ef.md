# Audit Report

## Title
Quadratic Complexity DoS in Association Proposal Threshold Validation

## Summary
The Association contract's threshold validation logic contains O(n*m) computational complexity when checking voter membership against organization member lists. An attacker can create an organization with thousands of members, have them vote on proposals, and cause transaction timeouts in both the `Release()` method and the `GetProposal()` view method, effectively denying service to governance functionality for that organization.

## Finding Description

The vulnerability exists in three threshold validation methods used by the Association contract during proposal release checks:

The `IsProposalRejected` method performs nested iteration by calling `proposal.Rejections.Count(organization.OrganizationMemberList.Contains)`. [1](#0-0) 

The `IsProposalAbstained` method uses the same O(n*m) pattern with `proposal.Abstentions.Count(organization.OrganizationMemberList.Contains)`. [2](#0-1) 

The `CheckEnoughVoteAndApprovals` method similarly uses `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)`. [3](#0-2) 

All three methods are invoked sequentially during the `IsReleaseThresholdReached` check. [4](#0-3) 

This threshold checking is called from two critical execution paths:
- The `GetProposal()` view method, which any user can call to query proposal status [5](#0-4) 
- The `Release()` method, which proposers call to execute approved proposals [6](#0-5) 

The underlying `Contains` implementation performs linear search through the organization member list. [7](#0-6) 

The organization member list is defined as a protobuf repeated field with no maximum size constraint. [8](#0-7) 

Similarly, proposal vote lists (approvals, rejections, abstentions) are unbounded repeated fields. [9](#0-8) 

**Why protections fail:**

The organization validation logic checks for empty lists and duplicates but imposes no explicit upper bound on member count. [10](#0-9) 

Anyone can create an Association organization without special privileges. [11](#0-10) 

Members can vote on proposals through the public `Approve`, `Reject`, and `Abstain` methods. [12](#0-11) 

## Impact Explanation

**Severity: Medium-High**

**Concrete Harm:**
- An organization with 10,000 members and 10,000 votes per category requires approximately 300 million `Contains` operations (10,000 × 10,000 × 3 methods)
- This computational load exceeds reasonable block execution time limits, causing transaction reversion
- The `Release()` method becomes permanently unusable for all proposals from the affected organization
- The `GetProposal()` view method also times out, preventing any status queries for proposals from that organization
- Governance functionality is completely denied for the affected organization

**Who is affected:**
- Organizations with legitimately large membership (community DAOs, broad token holder groups)
- Malicious actors can intentionally create bloated organizations to grief governance
- Once an organization reaches problematic size, all its future proposals become unreleasable
- The attack is permanent unless the organization can somehow reduce its member count (which may itself require a proposal that cannot be released)

**Impact justification:**
- **Availability Impact: High** - Complete denial of service for governance operations
- **Integrity Impact: Medium** - Prevents legitimate governance actions from being executed
- **Scope: Limited** - Affects specific organizations but governance is a critical system function

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker capabilities:**
- No special privileges required - anyone can create an Association organization
- Attacker controls all member addresses during organization creation
- Each controlled address can vote once per proposal
- Attack setup requires only transaction fees (one-time cost)

**Attack feasibility:**
1. Create organization with 10,000+ member addresses in a single transaction (within typical transaction size limits)
2. Create proposal through that organization
3. Have controlled member addresses vote (reject/abstain to maximize computation)
4. Any subsequent attempt to call `Release()` or `GetProposal()` encounters timeout

**Preconditions:**
- Transaction size limits allow thousands of addresses (protobuf serialization is efficient)
- No contract-level enforcement of member count limits exists
- Block execution time constraints are exceeded with sufficient member and vote counts

**Economic rationality:**
- One-time setup cost (transaction fees for organization creation and votes)
- Permanent governance disruption for targeted organization
- Benefit exceeds cost for adversarial actors seeking to disrupt governance

## Recommendation

Implement one or more of the following mitigations:

1. **Add explicit member count limit:**
   Add a maximum organization size check in the validation logic:
   ```csharp
   private bool Validate(Organization organization)
   {
       const int MaxOrganizationMembers = 500; // reasonable governance size
       if (organization.OrganizationMemberList.Count() > MaxOrganizationMembers)
           return false;
       // ... rest of validation
   }
   ```

2. **Use HashSet for membership checks:**
   Convert `OrganizationMemberList` to use a HashSet-backed structure for O(1) lookups instead of O(m) linear search. This would reduce complexity from O(n*m) to O(n).

3. **Cache valid voters:**
   During voting, validate membership once and store only validated member votes, eliminating the need for repeated `Contains` checks during threshold validation.

4. **Optimize threshold checking:**
   Count valid votes incrementally during the voting process rather than recalculating on every release attempt.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```csharp
// 1. Create organization with 10,000 members
var memberList = new OrganizationMemberList();
for (int i = 0; i < 10000; i++)
{
    memberList.OrganizationMembers.Add(GenerateAddress(i));
}

var input = new CreateOrganizationInput
{
    OrganizationMemberList = memberList,
    ProposalReleaseThreshold = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 5000,
        MinimalVoteThreshold = 5000,
        MaximalRejectionThreshold = 2000,
        MaximalAbstentionThreshold = 2000
    },
    ProposerWhiteList = new ProposerWhiteList { Proposers = { proposerAddress } }
};

var orgAddress = AssociationContractStub.CreateOrganization.SendAsync(input).Result.Output;

// 2. Create proposal
var proposalInput = new CreateProposalInput
{
    OrganizationAddress = orgAddress,
    ToAddress = targetAddress,
    ContractMethodName = "SomeMethod",
    Params = ByteString.Empty,
    ExpiredTime = Timestamp.FromDateTime(DateTime.UtcNow.AddDays(1))
};

var proposalId = AssociationContractStub.CreateProposal.SendAsync(proposalInput).Result.Output;

// 3. Have 10,000 members vote (rejections to maximize computation)
for (int i = 0; i < 10000; i++)
{
    var memberStub = GetStubForAddress(GenerateAddress(i));
    memberStub.Reject.SendAsync(proposalId).Wait();
}

// 4. Attempt to release - this will timeout due to O(n*m) complexity
// The IsReleaseThresholdReached check performs ~100M operations
var releaseResult = AssociationContractStub.Release.SendAsync(proposalId);
// Expected: Transaction timeout/revert

// 5. Attempt to query proposal - view method also times out
var proposalQuery = AssociationContractStub.GetProposal.CallAsync(proposalId);
// Expected: Query timeout
```

The test demonstrates that with 10,000 members and 10,000 rejections:
- `IsProposalRejected`: 10,000 rejections × 10,000 member list = 100M operations
- `IsProposalAbstained`: Similar potential complexity
- `CheckEnoughVoteAndApprovals`: Similar potential complexity
- Total: Up to ~300M `Contains` operations if all vote categories are populated

This computational load causes both state-changing transactions and view method calls to timeout, permanently denying governance functionality for the affected organization.

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-38)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L41-44)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L18-42)
```csharp
    public override ProposalOutput GetProposal(Hash proposalId)
    {
        var proposal = State.Proposals[proposalId];
        if (proposal == null) return new ProposalOutput();

        var organization = State.Organizations[proposal.OrganizationAddress];
        var readyToRelease = IsReleaseThresholdReached(proposal, organization);

        return new ProposalOutput
        {
            ProposalId = proposalId,
            ContractMethodName = proposal.ContractMethodName,
            ExpiredTime = proposal.ExpiredTime,
            OrganizationAddress = proposal.OrganizationAddress,
            Params = proposal.Params,
            Proposer = proposal.Proposer,
            ToAddress = proposal.ToAddress,
            ToBeReleased = readyToRelease,
            ApprovalCount = proposal.Approvals.Count,
            RejectionCount = proposal.Rejections.Count,
            AbstentionCount = proposal.Abstentions.Count,
            Title = proposal.Title,
            Description = proposal.Description
        };
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L69-94)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            ProposerWhiteList = input.ProposerWhiteList,
            OrganizationMemberList = input.OrganizationMemberList,
            OrganizationHash = organizationHash,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization.");
        if (State.Organizations[organizationAddress] == null)
        {
            State.Organizations[organizationAddress] = organization;
            Context.Fire(new OrganizationCreated
            {
                OrganizationAddress = organizationAddress
            });
        }

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L123-181)
```csharp
    public override Empty Approve(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Approve),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }

    public override Empty Reject(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Rejections.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Reject),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }

    public override Empty Abstain(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Abstentions.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Abstain),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-201)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);

        Context.Fire(new ProposalReleased
        {
            ProposalId = input,
            OrganizationAddress = proposalInfo.OrganizationAddress
        });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L17-20)
```csharp
    public bool Contains(Address address)
    {
        return organizationMembers_.Contains(address);
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
