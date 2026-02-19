### Title
Removed Proposers Can Still Release Previously Created Proposals Due to Missing Whitelist Re-validation

### Summary
The `Release` function in Referendum, Parliament, and Association contracts does not re-validate whether the proposer is still in the organization's whitelist. When a proposer is removed via `ChangeOrganizationProposerWhiteList`, they retain the ability to release proposals they created before removal, creating an authorization inconsistency that bypasses whitelist access control.

### Finding Description

The vulnerability exists in the `Release` function which only verifies two conditions before executing a proposal:

1. The caller must be the original proposer: [1](#0-0) 
2. The approval threshold must be reached: [2](#0-1) 

However, it does **not** re-check if the proposer is still authorized in the whitelist at release time.

The proposer whitelist validation only occurs during proposal creation via `AssertIsAuthorizedProposer`: [3](#0-2) 

This validation checks the whitelist at creation time: [4](#0-3) 

When an organization changes its proposer whitelist: [5](#0-4) 

The change updates the organization's whitelist in storage but does not invalidate existing proposals. Since `Release` only checks that `Context.Sender` equals the stored `proposal.Proposer` and never re-validates whitelist membership, removed proposers can still execute their previously created proposals.

**The same vulnerability exists in Parliament and Association contracts:**
- Parliament Release: [6](#0-5) 
- Association Release: [7](#0-6) 

### Impact Explanation

**Authorization Inconsistency**: The intent of removing a proposer from the whitelist is to revoke their governance privileges. However, they can still execute proposals created before removal, maintaining execution power despite being de-authorized.

**Governance Bypass**: A malicious proposer can:
1. Create multiple proposals while whitelisted
2. Delay their release until after being removed from whitelist
3. Execute sensitive governance actions even after losing proposer privileges

**Who is Affected**: All organizations using Referendum, Parliament, or Association contracts that rely on proposer whitelist changes for access control.

**Documentation Inconsistency**: `ChangeOrganizationThreshold` explicitly states it "will affect all current proposals of the organization" [8](#0-7) , but `ChangeOrganizationProposerWhiteList` lacks this clarification [9](#0-8) , suggesting inconsistent retroactive behavior.

### Likelihood Explanation

**Attack Complexity**: Low - requires no special privileges beyond initial whitelist membership.

**Attack Vector**:
1. Proposer creates proposal while whitelisted (legitimate action)
2. Organization removes proposer from whitelist (legitimate governance action)
3. Voting reaches approval threshold (legitimate voting)
4. Removed proposer calls `Release` and successfully executes proposal (bypasses whitelist control)

**Feasibility**: High - no complex preconditions needed. The proposer simply needs to:
- Create proposals before removal (normal operation)
- Wait for approval threshold (normal operation)
- Call Release after being removed (single transaction)

**Detection**: Difficult - the Release transaction appears legitimate as it comes from the original proposer and meets threshold requirements. The authorization gap is not visible in transaction logs.

**Practical Scenarios**:
- Malicious insider creates proposal, gets removed due to suspicious behavior, but releases proposal anyway
- Compromised proposer account creates malicious proposals, organization removes them from whitelist, but proposals can still execute
- Former organization members who lost trust retain governance execution power

### Recommendation

**Code-Level Mitigation**: Add whitelist re-validation in the `Release` function before execution:

```csharp
public override Empty Release(Hash input)
{
    var proposal = GetValidProposal(input);
    Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
    
    // ADD THIS CHECK:
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(organization.ProposerWhiteList.Contains(proposal.Proposer), 
           "Proposer no longer in whitelist.");
    
    Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
    // ... rest of release logic
}
```

Apply this fix to:
- `contract/AElf.Contracts.Referendum/Referendum.cs` (Release method)
- `contract/AElf.Contracts.Parliament/Parliament.cs` (Release method)  
- `contract/AElf.Contracts.Association/Association.cs` (Release method)

**Alternative Approach**: Store a snapshot of the whitelist state in the proposal at creation time and validate against that snapshot. However, this contradicts the documented behavior of `ChangeOrganizationThreshold` affecting existing proposals, suggesting the intended design is retroactive application.

**Test Cases to Add**:
1. Create proposal while whitelisted → Remove proposer → Verify Release fails with "Proposer no longer in whitelist"
2. Create proposal → Remove proposer → Re-add proposer → Verify Release succeeds
3. Multiple proposals from same proposer → Remove proposer → Verify all pending releases fail

### Proof of Concept

**Initial State**:
- Organization exists with proposer A in whitelist
- TokenSymbol configured for voting
- Sufficient token allowances set up

**Attack Sequence**:

1. **Proposer A creates malicious proposal** (while whitelisted):
   ```
   ReferendumContract.CreateProposal({
     OrganizationAddress: orgAddress,
     ToAddress: targetContract,
     ContractMethodName: "SensitiveMethod",
     Params: maliciousParams,
     ExpiredTime: futureTime
   })
   → Proposal created successfully (whitelist check passes)
   → Returns proposalId
   ```

2. **Organization removes Proposer A from whitelist**:
   ```
   ReferendumContract.ChangeOrganizationProposerWhiteList({
     Proposers: [otherAddresses] // excludes Proposer A
   })
   → Whitelist updated successfully
   ```

3. **Verify Proposer A cannot create new proposals**:
   ```
   ReferendumContract.CreateProposal(newProposal)
   → Transaction fails: "Unauthorized to propose." ✓
   ```
   This is tested in: [10](#0-9) 

4. **Voting reaches approval threshold** (legitimate voters):
   ```
   Multiple voters call Approve(proposalId)
   → proposal.ApprovalCount >= MinimalApprovalThreshold
   ```

5. **Proposer A releases the proposal** (VULNERABILITY):
   ```
   ReferendumContract.Release(proposalId) as Proposer A
   → Expected: Transaction fails due to whitelist removal
   → Actual: Transaction succeeds, malicious action executed ✗
   ```

**Success Condition**: The removed proposer successfully executes `Release` and the proposal's target method is invoked, despite the proposer no longer being in the whitelist. This demonstrates the authorization inconsistency where whitelist changes do not affect release privileges for existing proposals.

### Notes

This vulnerability affects all three ACS3-compliant governance contracts uniformly. The root cause is a design decision to check authorization only at proposal creation time, not at execution time. While this may have been intentional for operational reasons, it creates a significant authorization gap that contradicts the expected security model of whitelist-based access control.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L55-55)
```csharp
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L166-166)
```csharp
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L168-168)
```csharp
        Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
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

**File:** docs/resources/smart-contract-apis/referendum.md (L292-292)
```markdown
This method changes the thresholds associated with proposals. All fields will be overwritten by the input value and this will affect all current proposals of the organization. Note: only the organization can execute this through a proposal.
```

**File:** docs/resources/smart-contract-apis/referendum.md (L322-322)
```markdown
This method overrides the list of whitelisted proposers.
```

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L844-847)
```csharp
        ReferendumContractStub = GetReferendumContractTester(DefaultSenderKeyPair);
        var result = await ReferendumContractStub.CreateProposal.SendWithExceptionAsync(createProposalInput);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        result.TransactionResult.Error.ShouldContain("Unauthorized to propose.");
```
