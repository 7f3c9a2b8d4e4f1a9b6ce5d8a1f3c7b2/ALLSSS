### Title
Proposer Whitelist Bypass - Removed Proposers Can Execute Approved Proposals

### Summary
The `Release` method in Association, Parliament, and Referendum contracts only validates that the caller is the original proposer without re-checking if the proposer is still in the organization's whitelist. This allows proposers who have been removed from the whitelist via `ChangeOrganizationProposerWhiteList` to retain execution authority for previously approved proposals, completely bypassing the whitelist authorization mechanism.

### Finding Description

The vulnerability exists in the authorization logic across all three governance contracts. When a proposal is created, the system validates that the proposer is in the whitelist: [1](#0-0) 

This validation occurs through the helper method: [2](#0-1) 

However, when releasing an approved proposal, the authorization check is insufficient: [3](#0-2) 

The `Release` method only verifies `Context.Sender == proposalInfo.Proposer` without re-validating whether the proposer is still in the current whitelist. Meanwhile, organizations can update their proposer whitelist at any time: [4](#0-3) 

This creates a critical authorization gap: once a proposer creates and gets approval for a proposal, they retain the ability to execute it even after being explicitly removed from the whitelist. The whitelist check using the `Contains` extension method is never re-evaluated at release time: [5](#0-4) 

The same vulnerability pattern exists in Parliament and Referendum contracts with identical authorization checks at release time.

### Impact Explanation

**Authorization Bypass**: Organizations use the proposer whitelist as a critical security control to manage who can interact with their governance. Removing a proposer from the whitelist (via `ChangeOrganizationProposerWhiteList`) is an explicit revocation of trust and authority. However, this control is completely ineffective for existing proposals - removed proposers retain full execution rights.

**Real-World Harm Scenarios**:
1. **Compromised Account**: When a legitimate proposer's account is compromised, the organization removes them from the whitelist immediately. However, the attacker can still execute any approved proposals, potentially draining funds or changing critical configurations.

2. **Malicious Proposer Discovery**: If a proposer's malicious intent is discovered after their proposal was approved (through social engineering, parameter obfuscation, or deceptive descriptions), removing them from the whitelist does not prevent execution.

3. **Changed Circumstances**: A previously-approved proposal becomes harmful due to changed conditions. The organization removes the proposer to prevent new harm, but cannot stop execution of the old proposal.

**Concrete Damage**: Approved proposals can execute arbitrary contract methods on behalf of the organization through `Context.SendVirtualInlineBySystemContract`, including fund transfers, contract upgrades, permission changes, and other privileged operations. Organizations have no mechanism to revoke release rights for approved but not-yet-expired proposals.

**Severity Justification**: HIGH - This violates the fundamental authorization invariant that whitelist membership controls proposal authority. The only mitigation (waiting for expiration and using `ClearProposal`) requires waiting for the entire proposal lifetime, during which the removed proposer can execute at will.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Must initially be in the proposer whitelist (normal operational state for legitimate proposers)
- Must create a proposal that gets approved by organization members
- No special technical exploits or economic resources required

**Attack Complexity**: LOW - The exploit is straightforward:
1. Create proposal while whitelisted
2. Wait for member approval (normal operation)
3. After being removed from whitelist, call `Release` method
4. The method executes because it only checks original proposer identity

**Feasibility Conditions**: 
- Extremely feasible - this is the normal proposal flow with one additional step (whitelist removal)
- The attack window extends from approval until expiration (typically days)
- No race conditions or timing attacks needed

**Operational Constraints**:
- Detection is easy (transaction is on-chain), but prevention is impossible once a proposal is approved
- Organizations cannot defend against this - `ClearProposal` only works after expiration

**Probability Reasoning**: HIGH - The scenarios triggering this (account compromise, discovered malicious intent, changed circumstances) are realistic operational events that organizations must handle. The inability to revoke release authority represents a critical security gap in the governance model.

### Recommendation

Add proposer whitelist re-validation in the `Release` method before allowing execution. This ensures only current whitelist members can release proposals, even if they were the original proposer:

**Code-Level Mitigation**:
In `Association.cs`, `Parliament.cs`, and `Referendum.cs`, modify the `Release` method to add:

```csharp
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    
    // ADD THIS CHECK:
    AssertIsAuthorizedProposer(proposalInfo.OrganizationAddress, Context.Sender);
    
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    // ... rest of method
}
```

This leverages the existing `AssertIsAuthorizedProposer` helper method that already performs the whitelist validation.

**Invariant to Enforce**: 
"A proposer must be in the current whitelist at BOTH proposal creation AND release time to execute organizational actions."

**Test Cases to Add**:
1. Test that a proposer removed from whitelist cannot release their approved proposal
2. Test that after whitelist change, only new whitelist members can create and release proposals
3. Test that `ValidateProposerInWhiteList` returns false for removed proposers attempting to release

This fix aligns the release authorization with the creation authorization, ensuring whitelist changes immediately affect all proposal operations.

### Proof of Concept

**Initial State**:
- Organization exists with Alice in the proposer whitelist
- Organization has member list [Bob, Carol, Dave] with approval threshold of 2
- Organization has 1000 ELF tokens that can be transferred via proposals

**Attack Sequence**:

1. **Alice Creates Malicious Proposal** (while in whitelist):
   - Alice calls `CreateProposal` to create a proposal transferring 1000 ELF to Alice's personal address
   - Proposal passes `AssertIsAuthorizedProposer` check because Alice is in whitelist
   - Proposal is created with `proposalInfo.Proposer = Alice`

2. **Members Approve Proposal**:
   - Bob calls `Approve(proposalId)` 
   - Carol calls `Approve(proposalId)`
   - Proposal now meets the approval threshold (`IsReleaseThresholdReached` returns true)

3. **Organization Discovers Malicious Intent**:
   - Organization realizes Alice's proposal is harmful
   - Organization creates and approves a proposal to call `ChangeOrganizationProposerWhiteList`
   - New whitelist = [Bob, Carol, Dave] (Alice removed)
   - `ChangeOrganizationProposerWhiteList` executes, updating the whitelist

4. **Alice Executes Bypass**:
   - Alice calls `Release(proposalId)`
   - Method checks: `Context.Sender (Alice) == proposalInfo.Proposer (Alice)` ✓ Passes
   - Method checks: `IsReleaseThresholdReached(proposalInfo, organization)` ✓ Passes
   - Method does NOT check if Alice is still in whitelist
   - Proposal executes: 1000 ELF transferred to Alice

**Expected Behavior**: Release should fail with "Unauthorized to propose" because Alice is no longer in the whitelist.

**Actual Behavior**: Release succeeds and executes the fund transfer because the `Release` method never re-validates whitelist membership.

**Success Condition**: Alice successfully releases and executes an approved proposal after being explicitly removed from the proposer whitelist, demonstrating complete bypass of the whitelist authorization mechanism.

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

**File:** contract/AElf.Contracts.Association/Association_Extensions.cs (L29-32)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
    }
```
