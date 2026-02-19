### Title
Insufficient Address Validation in Governance Contracts Enables Griefing Attack via Unexecutable Proposals

### Summary
The Association, Parliament, and Referendum contracts only validate that `ToAddress` is not null but fail to check if `ToAddress.Value` is empty or valid. An attacker can create proposals with non-null but empty/invalid addresses that pass validation at both creation and release time, but fail during inline transaction execution, causing the Release transaction to revert and leaving approved proposals permanently unexecutable until expiry.

### Finding Description

The validation logic in the Association contract's `Validate(ProposalInfo proposal)` method only checks if the ToAddress object reference is null: [1](#0-0) 

This validation is insufficient because protobuf Address types consist of an object reference and an internal `Value` byte array. The proper validation pattern used elsewhere in the codebase checks both the object and its internal value: [2](#0-1) 

The same insufficient validation exists in Parliament and Referendum contracts: [3](#0-2) [4](#0-3) 

During proposal creation, this insufficient validation is applied: [5](#0-4) 

And the same insufficient validation is applied again during Release: [6](#0-5) 

When a proposal with an empty/invalid address reaches Release execution, the inline transaction is created but will fail: [7](#0-6) 

The inline transaction is added to the execution trace without immediate validation: [8](#0-7) 

When the inline transaction executes with an invalid address, it fails, causing the entire Release transaction to revert. The proposal removal at line 198 never executes, leaving the proposal in state.

### Impact Explanation

**Governance DoS**: Organization members waste time reviewing, voting on, and approving proposals that can never be executed. This disrupts the organization's governance process and decision-making capability.

**Resource Waste**: Approved proposals remain stuck in state until they expire (potentially days or weeks), consuming storage and preventing the organization from efficiently managing its proposals.

**Griefing Attack**: Any whitelisted proposer can repeatedly create such proposals, forcing the organization to deal with multiple unexecutable proposals simultaneously. This can overwhelm the organization and prevent legitimate governance work.

**Trust Erosion**: Repeated failures to execute approved proposals damage member confidence in the governance system and waste their engagement efforts.

The severity is **Medium** because while it doesn't directly steal funds, it significantly disrupts critical governance operations and can be repeated by any malicious whitelisted proposer.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be in the organization's proposer whitelist, which is a moderate barrier but realistic in multi-organization ecosystems where multiple parties participate.

**Attack Complexity**: The attack is trivial to execute - simply create a proposal with `new Address() { Value = ByteString.Empty }` or an address pointing to a non-existent contract. No complex state manipulation or timing requirements exist.

**Feasibility Conditions**: The attack works in normal operational conditions with no special preconditions. The validation consistently fails to catch empty addresses at both creation and release time.

**Detection**: The issue is difficult to detect before Release execution since the validation passes. Organization members may not realize a proposal is unexecutable until after investing effort in voting.

**Economic Rationality**: The attack costs only transaction fees to create proposals, making it economically feasible for sustained griefing campaigns.

The likelihood is **Medium** due to the low technical barrier and realistic attacker profile (whitelisted proposer).

### Recommendation

**Immediate Fix**: Update the validation methods in Association_Helper.cs, Parliament_Helper.cs, and Referendum_Helper.cs to use the proper address validation pattern:

```csharp
private bool Validate(ProposalInfo proposal)
{
    if (proposal.ToAddress == null || proposal.ToAddress.Value.IsNullOrEmpty() || 
        string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

**Additional Enhancement**: Consider adding validation that the ToAddress corresponds to a deployed contract by checking if code exists at that address.

**Test Cases**: Add test cases that specifically verify:
1. Proposals with `new Address() { Value = ByteString.Empty }` are rejected
2. Proposals with addresses pointing to non-existent contracts are rejected
3. Existing null-address test coverage remains intact

### Proof of Concept

**Initial State**:
- Organization created with attacker in proposer whitelist
- Organization members configured with voting thresholds

**Attack Steps**:

1. Attacker calls CreateProposal with:
   ```
   CreateProposalInput {
     ToAddress = new Address() { Value = ByteString.Empty },
     ContractMethodName = "SomeMethod",
     Params = ByteString.Empty,
     ExpiredTime = CurrentTime + 7 days,
     OrganizationAddress = targetOrganization
   }
   ```

2. Validation at line 162 passes because `proposal.ToAddress == null` evaluates to false (the Address object exists, only its Value is empty)

3. Proposal is created and stored successfully

4. Organization members review and vote to approve the proposal

5. Proposer calls Release(proposalId)

6. Validation at line 105 passes again with same insufficient check

7. SendVirtualInlineBySystemContract is called with the empty address at line 189

8. During inline transaction execution, the transaction fails due to invalid target address

9. Entire Release transaction reverts

10. Proposal remains in state (line 198 never executes)

**Expected Result**: Proposal creation should fail with "Invalid input address" error

**Actual Result**: Proposal is created successfully but becomes permanently unexecutable, wasting organization resources

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L85-86)
```csharp
        if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
            !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L105-105)
```csharp
        Assert(Validate(proposal), "Invalid proposal.");
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L162-162)
```csharp
        Assert(Validate(proposal), "Invalid proposal.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L159-160)
```csharp
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L106-107)
```csharp
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
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
