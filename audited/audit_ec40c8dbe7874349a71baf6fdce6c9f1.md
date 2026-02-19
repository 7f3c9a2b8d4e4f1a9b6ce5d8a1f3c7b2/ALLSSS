### Title
Removed Proposers Can Still Release Previously Created Proposals

### Summary
The Association, Parliament, and Referendum contracts validate ProposerWhiteList only during proposal creation but not during proposal release. When an organization removes a proposer from the whitelist after they've created proposals, those proposals remain releasable by the removed proposer if approved. This undermines the governance control mechanism and prevents organizations from fully revoking a proposer's privileges.

### Finding Description

The vulnerability exists in the proposal release flow across all three governance contracts (Association, Parliament, and Referendum). 

**Proposer Authorization at Creation:**
During proposal creation, the contract validates that the proposer is in the ProposerWhiteList. [1](#0-0) [2](#0-1) 

**Whitelist Modification:**
Organizations can change the ProposerWhiteList through the `ChangeOrganizationProposerWhiteList` method, which updates the whitelist state without affecting existing proposals. [3](#0-2) 

**Missing Validation at Release:**
The Release method only verifies that the caller matches the original proposer stored in the proposal (`Context.Sender == proposalInfo.Proposer`), but does NOT re-validate that the proposer is still in the current ProposerWhiteList. [4](#0-3) 

This same pattern exists in Parliament and Referendum contracts: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Governance Control Bypass:**
When an organization removes a proposer from the whitelist (e.g., due to detected malicious behavior, key compromise, or change in governance structure), the reasonable expectation is that the proposer loses all proposal-related privileges. However, the removed proposer retains the ability to release any proposals they created before removal.

**Affected Parties:**
- Organizations cannot fully revoke a compromised or malicious proposer's privileges
- If a proposer's key is compromised after creating proposals, the attacker can release those proposals even after the organization removes the compromised address
- Members' approval votes may have been cast before the proposer was identified as problematic

**Severity Justification:**
This is rated MEDIUM severity because while the removed proposer can still execute approved proposals, they cannot create new proposals or execute arbitrary actions. The proposals still require member approval, limiting the scope of potential harm. However, it represents a significant governance control weakness that contradicts the intended security model of the ProposerWhiteList mechanism.

### Likelihood Explanation

**Attack Scenario:**
1. ProposerA is authorized and creates ProposalX
2. ProposalX gets approved by organization members
3. Organization discovers ProposerA is compromised/malicious
4. Organization changes whitelist to remove ProposerA
5. ProposerA (or attacker with ProposerA's key) can still release ProposalX

**Feasibility:**
- All steps are normal contract operations available through public methods
- Organizations regularly need to remove proposers for security reasons
- The removed proposer only needs previously approved proposals to exist
- No special privileges or complex attack setup required
- Attack complexity is low - simply call Release after being removed

**Practicality:**
The scenario is highly realistic in governance systems where proposer privileges need to be revoked for security reasons. The time window between approval and release provides opportunity for exploitation.

### Recommendation

**Code-Level Mitigation:**
Add proposer whitelist re-validation in the Release method. Modify all three governance contracts (Association, Parliament, Referendum):

```csharp
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    
    // Add whitelist validation
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    AssertIsAuthorizedProposer(proposalInfo.OrganizationAddress, Context.Sender);
    
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    // ... execute proposal
}
```

**Invariant to Add:**
"A proposer must be in the current ProposerWhiteList at both proposal creation AND proposal release time."

**Test Cases:**
Add regression tests that verify:
1. Create proposal with authorized proposer
2. Approve proposal by members
3. Change whitelist to remove proposer
4. Attempt to release proposal - should fail with "Unauthorized to propose"
5. Verify removed proposer also cannot create new proposals

### Proof of Concept

**Initial State:**
- Organization created with ProposerWhiteList = [ProposerA, ProposerB]
- OrganizationMemberList = [Member1, Member2, Member3]
- MinimalApprovalThreshold = 2

**Exploitation Steps:**

1. **ProposerA creates ProposalX:**
   - Call `CreateProposal` with ProposerA's key
   - ProposalX targets TokenContract.Transfer (100 tokens to ProposerA)
   - Validation passes: ProposerA is in whitelist ✓

2. **Members approve ProposalX:**
   - Member1 calls `Approve(ProposalX)` ✓
   - Member2 calls `Approve(ProposalX)` ✓
   - Approval threshold reached (2/3)

3. **Organization removes ProposerA:**
   - Members create and approve ProposalY to call `ChangeOrganizationProposerWhiteList`
   - New whitelist = [ProposerB]
   - ProposerB releases ProposalY
   - ProposerA is now removed from whitelist

4. **ProposerA releases ProposalX:**
   - Call `Release(ProposalX)` with ProposerA's key
   - **Expected Result:** Transaction fails with "Unauthorized to propose"
   - **Actual Result:** Transaction succeeds ✗
   - Proposal executes: 100 tokens transferred to ProposerA

**Success Condition:**
The vulnerability is confirmed because ProposerA successfully released ProposalX despite being removed from the ProposerWhiteList. The contract only validated that `Context.Sender == proposalInfo.Proposer` without checking the current whitelist state.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L107-112)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L218-231)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposerWhiteList = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-145)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

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
