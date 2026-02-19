### Title
Invalid Contract Method Names Bypass Validation Causing Silent Governance Execution Failure

### Summary
The Referendum contract's `Validate(ProposalInfo)` function only checks that `ContractMethodName` is not null/empty but does not verify the method actually exists on the target contract. This allows proposals with invalid method names to be created, voted on, and "released" successfully, while the actual governance action silently fails in the inline transaction, wasting voter resources and creating misleading on-chain state.

### Finding Description

The root cause is in the proposal validation logic: [1](#0-0) 

The validation only checks `!string.IsNullOrWhiteSpace(proposal.ContractMethodName)` at line 107, with no verification that this method exists on the `ToAddress` contract. This same pattern exists in Parliament and Association contracts: [2](#0-1) 

When a proposal with an invalid method name is released, the execution flow is:

1. `Release` creates an inline transaction via `SendVirtualInlineBySystemContract`: [3](#0-2) 

2. The inline transaction is executed by `Executive.Execute()`, which attempts to find the method handler: [4](#0-3) 

3. When the method doesn't exist (line 133-137), a `RuntimeException` is thrown with message "Failed to find handler for {methodName}". This exception is caught at line 148-152, setting `ExecutionStatus = SystemError` and adding the error to the trace.

4. **Critical Issue**: The `Release` method does not check if the inline transaction succeeded. It always removes the proposal from state and fires the `ProposalReleased` event (lines 173-174), making it appear successful even though the governance action failed.

### Impact Explanation

**Who is affected:** All voters who participated in the proposal, and the governance system's integrity.

**Concrete harm:**
1. **Governance Failure**: The intended governance action (e.g., minting tokens, changing configuration) never executes, defeating the purpose of the proposal
2. **Wasted Voting Costs**: Voters spent gas on Approve/Reject/Abstain transactions for a proposal that could never succeed
3. **Opportunity Cost**: Voters' tokens were locked during the voting period (via `LockToken`) and couldn't be used elsewhere
4. **Misleading State**: The `ProposalReleased` event fires and proposal is removed from state, suggesting successful execution when the action actually failed
5. **Off-chain Confusion**: UIs and explorers would display the proposal as "Released/Executed" while the actual governance action silently failed in the inline transaction trace

**Quantified damage:** For each invalid proposal, voters collectively pay gas for N approval transactions plus token lock opportunity costs, all for zero governance value.

### Likelihood Explanation

**Attacker capabilities required:**
- Must be in the organization's `ProposerWhiteList` to create proposals

**Attack complexity:** Low
- Simply create a proposal with a typo in the method name, a non-existent method, or outdated method name from a contract upgrade
- Can be accidental (human error/typo) or intentional (malicious proposer)

**Feasibility conditions:**
- Proposer whitelist provides some access control, but doesn't prevent mistakes
- No validation tool or warning system to catch invalid method names before voting begins
- The proposer themselves may not realize the method name is invalid until after release

**Detection constraints:**
- The error only appears in the inline transaction trace, not the main transaction result
- Voters and off-chain systems may not check inline traces
- The `ProposalReleased` event gives false confidence of success

**Probability:** Medium - requires proposer error or malice, but human error in typing method names is realistic, especially for:
- Complex method names with multiple words
- Methods that were renamed in contract upgrades
- Copy-paste errors from documentation

### Recommendation

**Option 1 - Validate inline transaction success (recommended):**

Modify the `Release` method to check inline transaction execution status. After calling `SendVirtualInlineBySystemContract`, verify the inline transaction succeeded before removing the proposal:

```csharp
// In Referendum.cs Release method, after line 171
Context.SendVirtualInlineBySystemContract(...);

// Add validation here
var inlineTransactions = Context.Trace.InlineTransactions;
if (inlineTransactions.Count > 0)
{
    var lastInline = Context.Trace.InlineTraces.LastOrDefault();
    Assert(lastInline != null && lastInline.ExecutionStatus == ExecutionStatus.Executed, 
           "Proposal execution failed.");
}

Context.Fire(new ProposalReleased { ProposalId = input });
State.Proposals.Remove(input);
```

**Option 2 - Add method existence validation:**

If contract-level descriptor access becomes available, add method validation in `Validate(ProposalInfo)` to check that `ContractMethodName` exists on `ToAddress` before allowing proposal creation.

**Test cases to add:**
1. Create proposal with non-existent method name, verify it's rejected at creation OR fails at release with clear error
2. Create proposal with valid method name, verify release succeeds and inline transaction executes
3. Verify inline transaction failure causes Release to revert, keeping proposal in state for retry or expiration

### Proof of Concept

**Initial State:**
- Referendum organization exists with token symbol "ELF" and threshold requirements
- Proposer is in the ProposerWhiteList
- Target contract (e.g., TokenContract) exists at known address

**Attack Steps:**

1. **Create Proposal** with invalid method name:
```
CreateProposal({
  OrganizationAddress: <referendum_org>,
  ToAddress: <token_contract>,
  ContractMethodName: "NonExistentMethod",  // Invalid method
  Params: <encoded_params>,
  ExpiredTime: <future_time>
})
```
✓ Succeeds - passes `!string.IsNullOrWhiteSpace` check

2. **Voters Approve:**
Multiple voters call `Approve(proposalId)`, locking their tokens

3. **Release Proposal:**
Proposer calls `Release(proposalId)` when threshold reached

**Expected Result:** 
Release should fail with clear error about invalid method, keeping proposal in state

**Actual Result:**
- Release transaction succeeds (returns Empty)
- `ProposalReleased` event fired
- Proposal removed from state
- But inline transaction has `ExecutionStatus = SystemError` with error: "Failed to find handler for NonExistentMethod"
- Governance action never executed
- Voters wasted gas and token lock time

**Success Condition:** 
Check the transaction trace to find the inline transaction with `ExecutionStatus = SystemError` and error message about missing handler, while the outer Release transaction shows success.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L104-113)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L157-166)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = CheckProposalNotExpired(proposal);
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
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

**File:** src/AElf.Runtime.CSharp/Executive.cs (L123-152)
```csharp
    public void Execute()
    {
        var s = CurrentTransactionContext.Trace.StartTime = TimestampHelper.GetUtcNow().ToDateTime();
        var methodName = CurrentTransactionContext.Transaction.MethodName;
        var observer =
            new ExecutionObserver(CurrentTransactionContext.ExecutionObserverThreshold.ExecutionCallThreshold,
                CurrentTransactionContext.ExecutionObserverThreshold.ExecutionBranchThreshold);

        try
        {
            if (!_callHandlers.TryGetValue(methodName, out var handler))
                throw new RuntimeException(
                    $"Failed to find handler for {methodName}. We have {_callHandlers.Count} handlers: " +
                    string.Join(", ", _callHandlers.Keys.OrderBy(k => k))
                );

            _smartContractProxy.SetExecutionObserver(observer);

            ExecuteTransaction(handler);

            if (!handler.IsView())
                CurrentTransactionContext.Trace.StateSet = GetChanges();
            else
                CurrentTransactionContext.Trace.StateSet = new TransactionExecutingStateSet();
        }
        catch (Exception ex)
        {
            CurrentTransactionContext.Trace.ExecutionStatus = ExecutionStatus.SystemError;
            CurrentTransactionContext.Trace.Error += ex + "\n";
        }
```
