### Title
Zero Address Bypasses Validation and Causes Permanent Proposal Lock in Association Contract

### Summary
The `Validate(ProposalInfo)` function only checks if `ToAddress` is null, allowing proposals with zero addresses (32 bytes of zeros) to be created and approved. When such proposals are released, the inline transaction to the non-existent zero address fails with "Invalid contract address", causing the entire Release transaction to fail and roll back. This leaves the proposal in a locked state where it has reached approval threshold but cannot be executed, only clearable after expiration.

### Finding Description

The root cause is an insufficient address validation in the `Validate(ProposalInfo)` method: [1](#0-0) 

This check only detects if the Address object reference is null, not if it contains a zero value. In protobuf3, an Address message with 32 zero bytes is a valid non-null object that passes this validation.

When a proposal with a zero address reaches the release stage, the following execution path occurs:

1. The `Release` method creates an inline transaction to the zero address: [2](#0-1) 

2. The inline transaction is added to the transaction trace for execution: [3](#0-2) 

3. During inline transaction execution, `GetExecutiveAsync` attempts to retrieve the contract at the zero address: [4](#0-3) 

4. Since no contract exists at the zero address, a `SmartContractFindRegistrationException` is thrown: [5](#0-4) 

5. This exception is caught and the inline transaction fails with "Invalid contract address": [6](#0-5) 

6. The `IsSuccessful()` method checks all inline transactions, and any failure causes the parent transaction to be marked as failed: [7](#0-6) 

7. All state changes from the Release method (including proposal removal) are rolled back: [8](#0-7) 

### Impact Explanation

**Operational Impact - Governance DoS**: Approved proposals become permanently locked until expiration. Organization members' approval votes are wasted. The proposal occupies state and cannot execute its intended action.

**Affected parties**: 
- Organization members who spend time and gas approving invalid proposals
- Proposers whose legitimate governance actions are blocked by stuck proposals
- The entire organization's governance flow is disrupted

**Severity justification**: Medium severity because while it doesn't result in direct fund theft, it causes significant operational disruption. An attacker with proposer privileges can repeatedly create such proposals to DoS the organization's governance process. The only recovery is waiting for proposal expiration (potentially weeks): [9](#0-8) 

### Likelihood Explanation

**Attacker capabilities**: Attacker must be in the organization's proposer whitelist, verified here: [10](#0-9) 

**Attack complexity**: Very low - attacker simply creates a proposal with `ToAddress` set to 32 bytes of zeros. The Address type accepts any 32-byte value: [11](#0-10) 

**Feasibility conditions**: Highly feasible - the attack requires only proposer privileges (which are intended for trusted parties but may be compromised) and standard proposal creation capability.

**Economic rationality**: Attack cost is minimal (only gas for CreateProposal transaction), while impact is significant (governance disruption).

### Recommendation

Add explicit validation to reject zero addresses and non-existent contract addresses in the `Validate(ProposalInfo)` method:

```csharp
private bool Validate(ProposalInfo proposal)
{
    if (proposal.ToAddress == null || proposal.ToAddress.Value.IsEmpty || 
        string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;
    
    // Additional check: verify ToAddress is not all zeros
    if (proposal.ToAddress.Value.ToByteArray().All(b => b == 0))
        return false;

    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

**Additional mitigations**:
1. Consider adding a contract existence check by querying the Genesis contract during proposal validation
2. Add unit tests verifying that proposals with zero addresses are rejected
3. Document that ToAddress must be a valid deployed contract address

### Proof of Concept

**Initial state**:
- Association organization exists with proposer whitelist and members
- Attacker is in proposer whitelist

**Attack sequence**:
1. Attacker calls `CreateProposal` with:
   - `ToAddress`: Address object with Value = 32 bytes of zeros (0x0000...0000)
   - `ContractMethodName`: "TestMethod"
   - Valid `OrganizationAddress`, `ExpiredTime`, etc.

2. Proposal creation succeeds (bypasses validation at line 85)

3. Organization members approve the proposal until threshold is reached

4. Proposer calls `Release` on the approved proposal

5. **Expected result**: Proposal is released and action is executed

6. **Actual result**: 
   - Release transaction fails with "Invalid contract address"
   - Proposal remains in state, approved but unexecutable
   - ProposalReleased event is NOT fired
   - Proposal cannot be released again (same failure)
   - Proposal can only be removed via `ClearProposal` after expiration

**Success condition**: Attacker has successfully locked an approved proposal, wasting organization members' approval votes and blocking governance until expiration.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L85-85)
```csharp
        if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L282-288)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L269-275)
```csharp
        TransactionContext.Trace.InlineTransactions.Add(new Transaction
        {
            From = ConvertVirtualAddressToContractAddressWithContractHashName(fromVirtualAddress, Self),
            To = toAddress,
            MethodName = methodName,
            Params = args
        });
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L152-154)
```csharp
            executive = await _smartContractExecutiveService.GetExecutiveAsync(
                internalChainContext,
                singleTxExecutingDto.Transaction.To);
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L156-160)
```csharp
        catch (SmartContractFindRegistrationException)
        {
            txContext.Trace.ExecutionStatus = ExecutionStatus.ContractError;
            txContext.Trace.Error += "Invalid contract address.\n";
            return trace;
```

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractExecutiveService.cs (L196-197)
```csharp
        throw new SmartContractFindRegistrationException(
            $"failed to find registration from zero contract {txContext.Trace.Error}");
```

**File:** src/AElf.Kernel.Core/Extensions/TransactionTraceExtensions.cs (L8-19)
```csharp
    public static bool IsSuccessful(this TransactionTrace txTrace)
    {
        if (txTrace.ExecutionStatus != ExecutionStatus.Executed) return false;

        if (txTrace.PreTraces.Any(trace => !trace.IsSuccessful())) return false;

        if (txTrace.InlineTraces.Any(trace => !trace.IsSuccessful())) return false;

        if (txTrace.PostTraces.Any(trace => !trace.IsSuccessful())) return false;

        return true;
    }
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L209-213)
```csharp
        if (!CurrentTransactionContext.Trace.IsSuccessful())
        {
            changes.Writes.Clear();
            changes.Deletes.Clear();
        }
```

**File:** src/AElf.Types/Types/Address.cs (L49-58)
```csharp
        public static Address FromBytes(byte[] bytes)
        {
            if (bytes.Length != AElfConstants.AddressHashLength)
                throw new ArgumentException("Invalid bytes.", nameof(bytes));

            return new Address
            {
                Value = ByteString.CopyFrom(bytes)
            };
        }
```
