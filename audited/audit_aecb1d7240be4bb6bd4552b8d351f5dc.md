### Title
Removed Proposers Can Still Release Approved Proposals Due to Missing Whitelist Validation in Release Function

### Summary
The Referendum, Association, and Parliament governance contracts check proposer whitelist membership during proposal creation but fail to re-validate whitelist membership during proposal release. This allows a proposer who has been removed from the whitelist (indicating loss of trust) to still execute their previously created and approved proposals, violating the organization's intent to revoke governance privileges.

### Finding Description

The vulnerability exists across all three governance contracts (Referendum, Association, and Parliament) and stems from incomplete authorization checks in the proposal lifecycle.

**Referendum Contract:**
During proposal creation, the `CreateProposal` function enforces whitelist validation by calling `AssertIsAuthorizedProposer`: [1](#0-0) 

The `AssertIsAuthorizedProposer` helper explicitly checks whitelist membership using the `Contains` extension method: [2](#0-1) 

The `Contains` method checks if the proposer exists in the whitelist: [3](#0-2) 

However, the `Release` function only validates that the caller is the original proposer and that approval thresholds are met—it does NOT re-check whitelist membership: [4](#0-3) 

Organizations can modify their proposer whitelist at any time using `ChangeOrganizationProposerWhiteList`: [5](#0-4) 

**The same vulnerability exists in Association and Parliament contracts:**

Association Release function (no whitelist check): [6](#0-5) 

Parliament Release function (no whitelist check): [7](#0-6) 

### Impact Explanation

**Authorization & Governance Impact:**

1. **Trust Revocation Bypass**: When an organization removes a proposer from the whitelist (via `ChangeOrganizationProposerWhiteList`), they explicitly signal loss of trust in that individual. However, the removed proposer retains the ability to execute governance actions through their pending proposals.

2. **Unauthorized Proposal Execution**: A removed proposer can release proposals that execute arbitrary contract methods with the organization's authority via virtual inline transactions. This includes critical operations like:
   - Token transfers from organization addresses
   - Contract upgrades or configuration changes
   - Treasury fund releases
   - Authority modifications

3. **Malicious Insider Attack**: A bad actor could:
   - Create multiple benign-looking proposals while authorized
   - Wait for them to be approved
   - Get removed from whitelist due to suspicious behavior
   - Still execute all approved proposals after removal

4. **No Mitigation Path**: Organizations have limited options to prevent this:
   - Must actively vote to reject each proposal (requires coordination)
   - Wait for proposals to expire (may be too late)
   - Cannot revoke release permission directly

The impact violates the critical invariant: "Organization thresholds, proposer whitelist checks" must be enforced throughout the proposal lifecycle.

### Likelihood Explanation

**Attack Feasibility:**

1. **Reachable Entry Point**: The `Release` function is a public method callable by any address. The check at line 166 only verifies the caller is the original proposer, not their current whitelist status.

2. **Realistic Preconditions**:
   - Attacker must initially be in the proposer whitelist (legitimate access)
   - Must create proposals while authorized
   - Proposals must reach approval threshold (requires organization member votes)
   - Attacker gets removed from whitelist (indicates actual trust loss scenario)

3. **Execution Practicality**:
   - All steps are executable through standard contract calls
   - No special privileges required beyond initial whitelist membership
   - The approval threshold provides a window of opportunity between approval and detection/removal

4. **Economic Rationality**:
   - Cost is minimal (standard transaction fees)
   - Potential gain is high (execute privileged operations)
   - Particularly attractive for disgruntled ex-members or compromised accounts

5. **Detection Challenges**: Organizations may not immediately realize a removed proposer still has pending approved proposals, especially in high-activity organizations with many proposals.

The likelihood is **MEDIUM** because it requires the proposal to be approved first, but this is a normal part of governance flow and provides a realistic exploitation window.

### Recommendation

**Code-Level Mitigation:**

Add a whitelist validation check in the `Release` function for all three governance contracts (Referendum, Association, Parliament):

```csharp
public override Empty Release(Hash input)
{
    var proposal = GetValidProposal(input);
    Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
    
    // ADD THIS CHECK:
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(organization.ProposerWhiteList.Contains(proposal.Proposer), 
        "Proposer no longer authorized.");
    
    Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
    // ... rest of release logic
}
```

**Invariant to Enforce:**
- A proposer must be in the organization's whitelist at BOTH proposal creation AND proposal release time
- Whitelist membership should be a continuous requirement throughout the proposal lifecycle

**Test Cases to Add:**
1. Create proposal while in whitelist
2. Remove proposer from whitelist via `ChangeOrganizationProposerWhiteList`
3. Approve proposal to meet threshold
4. Attempt release by removed proposer
5. **Expected**: Transaction should fail with "Proposer no longer authorized."
6. **Current**: Transaction succeeds (vulnerability)

### Proof of Concept

**Initial State:**
- Organization exists with DefaultSender in proposer whitelist
- DefaultSender creates Proposal X targeting a sensitive operation
- Organization members approve Proposal X (reaches threshold)

**Attack Steps:**

1. **Proposal Creation** (DefaultSender is authorized):
   ```
   CreateProposal(organizationAddress, targetMethod, params)
   → proposalId = Hash(...)
   → AssertIsAuthorizedProposer passes ✓
   ```

2. **Whitelist Removal** (organization loses trust):
   ```
   ChangeOrganizationProposerWhiteList(newWhiteList without DefaultSender)
   → organization.ProposerWhiteList updated
   → DefaultSender no longer in whitelist
   ```

3. **Proposal Approval** (members don't notice):
   ```
   Members vote Approve(proposalId)
   → proposal.ApprovalCount >= threshold
   → IsReleaseThresholdReached returns true
   ```

4. **Malicious Release** (removed proposer executes):
   ```
   DefaultSender calls Release(proposalId)
   → Line 166: Context.Sender.Equals(proposal.Proposer) ✓ (passes)
   → Line 168: IsReleaseThresholdReached ✓ (passes)
   → NO whitelist check performed ✗
   → Line 169-171: SendVirtualInlineBySystemContract executes
   → Sensitive operation executed by untrusted proposer
   ```

**Expected Result**: Release should fail with "Proposer no longer authorized."

**Actual Result**: Release succeeds, allowing the removed (untrusted) proposer to execute governance actions on behalf of the organization.

**Success Condition**: The vulnerability is confirmed if a proposer removed from the whitelist can still release their approved proposals, which is the current behavior in all three governance contracts.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-59)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L139-152)
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L200-205)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "Organization not found.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L18-21)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
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
