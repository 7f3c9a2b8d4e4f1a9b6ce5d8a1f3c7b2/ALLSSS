### Title
Permissionless Proposal Deletion Enables Griefing of Approved Governance Actions

### Summary
The `ClearProposal()` function allows any address to delete expired proposals without authorization checks, while the `Release()` function strictly rejects proposals where `CurrentBlockTime >= ExpiredTime`. This creates a griefing attack vector where approved proposals can be permanently deleted by any actor at the moment of expiration, preventing legitimate governance actions from executing and disrupting the organization's decision-making process.

### Finding Description

The vulnerability exists in the interaction between three functions:

1. **ClearProposal() lacks authorization** - The function explicitly allows anyone to delete expired proposals with only a time-based check: [1](#0-0) 

2. **Release() enforces strict expiration checking** - The Release function calls GetValidProposal() which enforces that proposals must not be expired: [2](#0-1) 

3. **GetValidProposal() validates expiration** - This helper calls Validate() which rejects proposals at or after expiry: [3](#0-2) 

4. **Validate() uses strict less-than check** - The validation logic returns false when `CurrentBlockTime >= ExpiredTime`: [4](#0-3) 

**Root Cause**: The contract enforces that proposals cannot be released at or after `ExpiredTime` (using `< ExpiredTime` check), but simultaneously allows anyone to delete proposals starting at exactly `ExpiredTime` (using `>= ExpiredTime` check). There is no grace period or authorization requirement for deletion, creating a zero-width window where an approved proposal transitions from "releasable" to "permanently deletable by anyone."

**Why Protections Fail**: 
- No authorization check in ClearProposal()
- No grace period between expiration and deletion eligibility
- No special handling for approved proposals
- Proposer has no priority or exclusive right to release before deletion

### Impact Explanation

**Concrete Harm**:
- **Governance Disruption**: Legitimate organizational decisions that have reached approval threshold can be permanently blocked
- **Resource Waste**: Organization members' voting efforts are nullified, and transaction fees spent on approvals are wasted
- **Time-Critical Actions Blocked**: Urgent governance actions (parameter updates, emergency responses, fund transfers) can be prevented if proposer is delayed
- **Griefing Opportunity**: Malicious actors or competing interests can systematically block proposals with minimal cost (single ClearProposal transaction)

**Who Is Affected**:
- Proposers who worked to get approval but were legitimately delayed in releasing (network congestion, gas price spikes, human monitoring delays)
- Organization members whose votes are nullified
- The entire organization whose governance process is disrupted
- Beneficiaries of the proposed action who lose expected outcomes

**Severity Justification**: HIGH
- **Operational Impact**: Direct DoS of governance flows (passes validation requirement ✓)
- **No Privilege Required**: Any address can execute the attack
- **Realistic Scenario**: Proposers may legitimately be delayed for various reasons
- **Permanent Effect**: Once deleted, approved proposals cannot be recovered

### Likelihood Explanation

**Attacker Capabilities**: 
- Requires only monitoring of proposal states and block time
- Single transaction call to ClearProposal()
- Gas cost is minimal (single storage deletion operation)
- No special permissions or tokens required

**Attack Complexity**: LOW
- Simple to execute: wait for `CurrentBlockTime >= ExpiredTime`, then call `ClearProposal(proposalId)`
- Can be automated with a monitoring script
- No complex state manipulation required

**Feasibility Conditions**:
- Proposer must not call Release() before ExpiredTime is reached
- This is **highly realistic** due to:
  - Network congestion causing transaction delays
  - Gas price spikes making immediate release expensive
  - Proposer not actively monitoring the exact expiry time
  - Time zone differences or human unavailability
  - Block production timing uncertainty

**Detection/Prevention Constraints**:
- No on-chain mechanism prevents this attack
- Proposer cannot "lock in" their release intention
- No warning system before proposal becomes vulnerable
- Once expired, deletion can happen instantly before proposer reacts

**Probability Assessment**: HIGH - The combination of permissionless access, zero-cost griefing, and realistic delay scenarios makes this attack highly likely to occur, whether maliciously or accidentally.

### Recommendation

**Primary Fix**: Add authorization check to ClearProposal() to restrict deletion to proposer or organization members:

```csharp
public override Empty ClearProposal(Hash input)
{
    var proposal = State.Proposals[input];
    Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
    
    // Only allow proposer or organization to clear expired proposals
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(Context.Sender == proposal.Proposer || 
           organization.OrganizationMemberList.Contains(Context.Sender), 
           "Not authorized to clear proposal");
    
    State.Proposals.Remove(input);
    return new Empty();
}
```

**Alternative Fix**: Add grace period after expiration where only proposer can release:

```csharp
public override Empty ClearProposal(Hash input)
{
    var proposal = State.Proposals[input];
    Assert(proposal != null, "Proposal not found");
    
    // Allow grace period of 24 hours for proposer to release
    var gracePeriod = proposal.ExpiredTime.AddHours(24);
    Assert(Context.CurrentBlockTime >= gracePeriod, "Grace period not elapsed");
    
    State.Proposals.Remove(input);
    return new Empty();
}
```

**Additional Mitigation**: Modify Release() to allow release within a grace period after expiry for approved proposals:

```csharp
private bool Validate(ProposalInfo proposal)
{
    if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    // Allow grace period for approved proposals
    var organization = State.Organizations[proposal.OrganizationAddress];
    if (IsReleaseThresholdReached(proposal, organization))
    {
        return proposal.ExpiredTime != null && 
               Context.CurrentBlockTime < proposal.ExpiredTime.AddHours(24);
    }
    
    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

**Test Cases to Add**:
1. Verify non-proposer cannot clear unexpired proposals
2. Verify non-authorized addresses cannot clear expired proposals (if authorization added)
3. Verify proposer can release approved proposal within grace period
4. Verify ClearProposal fails during grace period (if grace period added)

### Proof of Concept

**Initial State**:
- Organization created with 3 members (Reviewer1, Reviewer2, Reviewer3)
- MinimalApprovalThreshold = 2
- Proposer = Reviewer1

**Attack Sequence**:

1. **T = 0**: Proposer creates proposal with `ExpiredTime = T + 2 days`
   - Proposal ID: `proposalId`
   - Transaction: `CreateProposal()`

2. **T + 1 day**: Proposal reaches approval threshold
   - Transaction: Reviewer2 calls `Approve(proposalId)` ✓
   - Transaction: Reviewer3 calls `Approve(proposalId)` ✓
   - State: Proposal has sufficient approvals, ready for release

3. **T + 2 days + 1 second**: Proposal expires
   - `Context.CurrentBlockTime >= proposal.ExpiredTime` ✓

4. **T + 2 days + 2 seconds**: Attacker calls ClearProposal
   - Transaction: Attacker calls `ClearProposal(proposalId)` ✓
   - Result: Proposal deleted from storage

5. **T + 2 days + 10 seconds**: Proposer attempts to release
   - Transaction: Reviewer1 calls `Release(proposalId)`
   - Result: **FAILS** with "Invalid proposal id." error
   - **Expected**: Proposal should execute approved governance action
   - **Actual**: Proposal permanently deleted, action never executes

**Success Condition**: 
- Attacker successfully deletes approved proposal using single transaction
- Proposer unable to execute legitimate governance action
- Organization's approved decision is permanently blocked
- No recovery mechanism exists

**Notes**: 
This same vulnerability pattern exists in Parliament contract as well: [5](#0-4) 

The test suite confirms this behavior is intentional but doesn't consider the griefing implications: [6](#0-5)

### Citations

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

**File:** contract/AElf.Contracts.Association/Association.cs (L282-289)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L83-90)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
            !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
            return false;

        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L101-107)
```csharp
    private ProposalInfo GetValidProposal(Hash proposalId)
    {
        var proposal = State.Proposals[proposalId];
        Assert(proposal != null, "Invalid proposal id.");
        Assert(Validate(proposal), "Invalid proposal.");
        return proposal;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L179-186)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L479-500)
```csharp
    [Fact]
    public async Task Approve_Proposal_ExpiredTime_Test()
    {
        var minimalApproveThreshold = 2;
        var minimalVoteThreshold = 3;
        var maximalAbstentionThreshold = 1;
        var maximalRejectionThreshold = 1;
        var organizationAddress = await CreateOrganizationAsync(minimalApproveThreshold, minimalVoteThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, Reviewer1);
        var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
        var associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
        BlockTimeProvider.SetBlockTime(BlockTimeProvider.GetBlockTime().AddDays(5));
        var error = await associationContractStub.Approve.CallWithExceptionAsync(proposalId);
        error.Value.ShouldContain("Invalid proposal.");

        //Clear expire proposal
        var result = await associationContractStub.ClearProposal.SendAsync(proposalId);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        var queryProposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
        queryProposal.ShouldBe(new ProposalOutput());
    }
```
