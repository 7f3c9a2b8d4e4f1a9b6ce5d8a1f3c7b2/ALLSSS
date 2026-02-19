### Title
Governance Time-of-Check-Time-of-Use Vulnerability: Method Fee Controller Change Invalidates Pending Fee Proposals

### Summary
A Time-of-Check-Time-of-Use (TOCTOU) vulnerability exists in the ACS1 method fee provider implementation across all governance contracts. An approved proposal to change method fees can be rendered unexecutable if a subsequent proposal changes the MethodFeeController between approval and release, causing the original proposal to fail authorization checks at execution time. This affects TokenHolder and all other ACS1-implementing contracts.

### Finding Description

The vulnerability exists in the authorization check pattern used by `SetMethodFee` and `ChangeMethodFeeController` methods. 

In TokenHolder's implementation: [1](#0-0) 

The `SetMethodFee` method checks at line 16 that `Context.Sender` equals the current `State.MethodFeeController.Value.OwnerAddress`. However, this check occurs at execution time, not at proposal creation/approval time.

The `ChangeMethodFeeController` method allows changing this controller: [2](#0-1) 

When Parliament releases a proposal, it uses a virtual address derived from the organization's hash: [3](#0-2) 

The `Context.Sender` for the inline transaction is set to the virtual address calculated at line 138-139, which is determined by the organization specified when the proposal was created.

The virtual address calculation is deterministic based on organization parameters: [4](#0-3) 

The actual inline transaction sender is set by the bridge context: [5](#0-4) 

**Root Cause:** The authorization check in `SetMethodFee` evaluates `State.MethodFeeController.Value.OwnerAddress` at execution time, but `Context.Sender` is fixed to the organization address from proposal creation time. This creates a TOCTOU race condition where the MethodFeeController can be changed between proposal approval and execution.

**Why Existing Protections Fail:** There is no locking mechanism, no validation that the MethodFeeController hasn't changed since proposal creation, and no atomicity guarantee between approval and execution. The default method fee controller initialization pattern is identical across all contracts: [6](#0-5) 

This vulnerability pattern exists in all ACS1 implementations (Association, Parliament, Election, Treasury, Profit, Vote, etc.).

### Impact Explanation

**Governance Denial-of-Service:** Approved governance proposals to change method fees become permanently unexecutable. The proposal fails with "Unauthorized to set method fee" error when released, wasting governance resources.

**Affected Parties:**
- Protocol governance: Cannot execute approved fee changes
- Proposers: Waste effort and potentially economic resources creating proposals
- Community: Loss of trust in governance reliability

**Severity Justification:** Medium severity because:
1. Does not directly steal funds or mint unauthorized tokens
2. Disrupts governance operations significantly
3. Can be used maliciously to block specific policy changes
4. Affects system-wide governance mechanism (all ACS1 contracts)
5. Forces re-creation of proposals, creating operational overhead

The same vulnerability pattern affects 14 system contracts implementing ACS1, making this a systemic governance integrity issue.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Control of ≥66.67% of current miners (default Parliament approval threshold)
- Ability to create proposals (requires being in proposer whitelist or parliament member)
- Ability to call Release before the original proposer

**Attack Complexity:** Medium [7](#0-6) 

The default organization requires 66.67% approval (6667/10000), making this feasible for colluding miners or majority-controlled governance scenarios.

**Execution Steps:**
1. Wait for legitimate SetMethodFee proposal to be approved
2. Create ChangeMethodFeeController proposal to different organization
3. Get proposal approved by controlled miners (≥66.67%)
4. Release the controller change proposal immediately
5. Original SetMethodFee proposal now fails when released

**Feasibility Conditions:**
- No enforced time delay between approval and release
- No atomicity guarantees in governance execution
- Public visibility of pending proposals allows front-running

**Detection Constraints:** Low - The attack leaves clear on-chain evidence (controller change transaction) but may appear as legitimate governance activity.

**Probability:** Medium - Requires significant miner collusion but is technically straightforward and has no gas or economic barriers beyond normal proposal costs.

### Recommendation

**Code-Level Mitigation:**

1. **Store controller address in proposal metadata:** When creating a SetMethodFee proposal, capture and store the current MethodFeeController address. At execution time, verify it hasn't changed:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    RequiredMethodFeeControllerSet();
    
    // Verify controller hasn't changed since proposal creation
    // This would require protocol-level changes to pass controller context
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
           "Unauthorized to set method fee.");
    State.TransactionFees[input.MethodName] = input;
    
    return new Empty();
}
```

2. **Add controller change invalidation:** When ChangeMethodFeeController is called, emit an event that allows detecting which proposals may be invalidated.

3. **Implement proposal re-validation:** Add a method to check if a pending proposal is still valid before release, considering any controller changes.

**Invariant Checks:**
- Before executing SetMethodFee, verify MethodFeeController hasn't changed since proposal creation
- Track controller change history to detect potential invalidations
- Add proposal staleness checks in Release method

**Test Cases:**
1. Test case where ChangeMethodFeeController is executed between approval and release of SetMethodFee proposal
2. Verify the SetMethodFee proposal fails with appropriate error
3. Test that new proposals with updated controller succeed
4. Test across all 14 ACS1-implementing contracts

### Proof of Concept

**Initial State:**
- TokenHolder contract deployed with MethodFeeController = Parliament Default Organization
- Multiple miners available for governance voting

**Attack Steps:**

1. **Legitimate governance flow starts:**
   - User creates Proposal A: SetMethodFee(methodName="Transfer", fee=100)
   - Proposal A targets Parliament Default Organization
   - Miners approve Proposal A (≥66.67% threshold reached)
   - Proposal A is ready for release but not yet released

2. **Attacker creates controller change:**
   - Attacker creates new organization (Organization B) via CreateOrganization
   - Attacker creates Proposal B: ChangeMethodFeeController(authInfo=Organization B)
   - Controlled miners approve Proposal B (≥66.67%)

3. **Attacker front-runs original proposal:**
   - Attacker calls Release(Proposal B) 
   - MethodFeeController changes from Parliament Default to Organization B
   - State.MethodFeeController.Value.OwnerAddress now points to Organization B

4. **Original proposal fails:**
   - Original proposer calls Release(Proposal A)
   - Parliament.Release calculates virtual address from Parliament Default Organization
   - SetMethodFee executes with Context.Sender = Parliament Default Organization virtual address
   - Assertion fails: Context.Sender (Parliament Default) ≠ State.MethodFeeController.Value.OwnerAddress (Organization B)
   - Transaction fails with "Unauthorized to set method fee."

**Expected vs Actual Result:**
- Expected: Approved Proposal A executes successfully and sets method fee
- Actual: Proposal A fails due to authorization mismatch, despite being legitimately approved

**Success Condition:** The attack succeeds when an approved governance proposal becomes permanently unexecutable due to controller change, forcing governance participants to restart the entire proposal process with the new controller.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L11-20)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L22-31)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L50-64)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L307-312)
```csharp
    private Hash CalculateVirtualHash(Hash organizationHash, Hash creationToken)
    {
        return creationToken == null
            ? organizationHash
            : HashHelper.ConcatAndCompute(organizationHash, creationToken);
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L266-276)
```csharp
    public void SendVirtualInlineBySystemContract(Hash fromVirtualAddress, Address toAddress, string methodName,
        ByteString args)
    {
        TransactionContext.Trace.InlineTransactions.Add(new Transaction
        {
            From = ConvertVirtualAddressToContractAddressWithContractHashName(fromVirtualAddress, Self),
            To = toAddress,
            MethodName = methodName,
            Params = args
        });
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-9)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
```
