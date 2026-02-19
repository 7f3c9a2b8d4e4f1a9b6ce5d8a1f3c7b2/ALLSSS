### Title
Malicious Contract Can Permanently Capture Method Fee Control Through Unchecked External Call

### Summary
The `ChangeMethodFeeController` function in the Parliament contract performs an external call to validate organization existence without verifying that the target contract is a legitimate governance contract. An attacker can deploy a malicious contract that always returns true for `ValidateOrganizationExist`, enabling permanent capture of method fee control either through direct unauthorized access or by creating an irrecoverable lock on fee configuration.

### Finding Description

The vulnerability exists in the `ChangeMethodFeeController` function which updates the method fee controller authority. [1](#0-0) 

The root cause is in the `CheckOrganizationExist` helper method that makes an unchecked external call to the `ContractAddress` specified in the input: [2](#0-1) 

The code blindly trusts whatever contract address is provided in `authorityInfo.ContractAddress` and accepts its response as authoritative. There is no validation that this address points to a legitimate governance contract (Parliament, Association, or Referendum).

**Attack Execution Path:**

1. Attacker deploys a malicious contract implementing a fake `ValidateOrganizationExist` method that always returns true
2. A governance proposal is created through the current controller to call `ChangeMethodFeeController` with the malicious contract as `ContractAddress`
3. Miners approve the proposal (the proposal appears normal - just address changes)
4. Upon proposal release, the Parliament organization's virtual address executes `ChangeMethodFeeController`
5. The authorization check passes because the sender is the current controller's virtual address [3](#0-2) 
6. The malicious contract returns true, bypassing validation [4](#0-3) 
7. The controller is updated to the malicious setup [5](#0-4) 

For context, legitimate implementations only return true for organizations that actually exist in their state: [6](#0-5) 

### Impact Explanation

**Governance Bypass Scenario:** If the attacker sets `OwnerAddress` to their personal address, they gain direct control over `SetMethodFee` without requiring any governance approval. [7](#0-6) 

The attacker can arbitrarily set transaction fees for all Parliament contract methods, potentially:
- Setting fees to zero for their own benefit
- Setting excessive fees to DOS legitimate users
- Extracting value through fee manipulation

**Permanent Lock Scenario:** If the attacker sets `OwnerAddress` to a non-existent organization address, the method fee configuration becomes permanently frozen. Future calls to `ChangeMethodFeeController` or `SetMethodFee` will fail authorization checks, and since the malicious contract has no real organization logic (as stated in the vulnerability question), no proposals can be created, approved, or released to regain control.

**Severity Justification:** This is CRITICAL because:
- Completely breaks the governance model for fee control
- Affects all methods in the Parliament contract
- Once captured, extremely difficult or impossible to recover
- Can lead to either unauthorized fee manipulation or permanent operational lock

### Likelihood Explanation

**Attacker Capabilities:** Attacker only needs ability to:
- Deploy a simple malicious contract (low cost)
- Craft a governance proposal with specific addresses

**Attack Complexity:** LOW - The malicious contract implementation is trivial (single method returning true). The proposal creation uses standard governance processes.

**Feasibility Conditions:** Requires governance approval, but detection is difficult because:
- The proposal only shows address changes without contract code
- Miners may not verify that `ContractAddress` points to a legitimate governance contract
- The proposal appears similar to legitimate controller updates
- No on-chain mechanism exists to validate contract legitimacy

**Detection Constraints:** The malicious contract can be deployed on any address, and its bytecode doesn't need to match known governance contracts. The Parliament contract has no whitelist or validation of permitted controller contracts.

**Probability:** MEDIUM-HIGH - While requiring governance approval adds friction, the lack of visibility into contract behavior and the routine nature of administrative proposals make successful social engineering plausible.

### Recommendation

**Code-Level Mitigation:**

Add validation in `CheckOrganizationExist` to ensure `ContractAddress` is a registered system governance contract:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Add validation that ContractAddress is a legitimate governance contract
    var systemContracts = Context.GetSystemContractNameToAddressMapping();
    var validGovernanceContracts = new[] {
        systemContracts[SmartContractConstants.ParliamentContractSystemName],
        systemContracts[SmartContractConstants.AssociationContractSystemName],
        systemContracts[SmartContractConstants.ReferendumContractSystemName]
    };
    
    Assert(validGovernanceContracts.Contains(authorityInfo.ContractAddress),
        "ContractAddress must be a valid governance contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
}
```

**Invariant Checks:**
- Method fee controller's `ContractAddress` must always be a registered system governance contract
- Method fee controller's `OwnerAddress` must be a valid organization within the specified contract

**Test Cases:**
1. Test that `ChangeMethodFeeController` rejects non-system contract addresses
2. Test that malicious contracts returning true are blocked
3. Test that only Parliament, Association, and Referendum contracts are accepted
4. Regression test ensuring legitimate controller changes still work

This same fix should be applied to all contracts implementing ACS1 (Association, Referendum, Token, Configuration, Consensus, CrossChain, Economic, Election, Genesis, Profit, TokenHolder, Treasury, Vote).

### Proof of Concept

**Initial State:**
- Parliament contract initialized with default organization as method fee controller
- Default organization requires 2/3 miner approval for proposals

**Attack Steps:**

1. **Deploy Malicious Contract:**
```
Contract MaliciousGovernance {
    public BoolValue ValidateOrganizationExist(Address input) {
        return new BoolValue { Value = true };
    }
}
```

2. **Create Proposal:**
    - Proposer: Any authorized miner
    - Target: Parliament contract
    - Method: `ChangeMethodFeeController`
    - Parameters: `AuthorityInfo { ContractAddress: MaliciousGovernance, OwnerAddress: AttackerAddress }`

3. **Approve Proposal:**
    - Miners approve (2/3 threshold met)
    - Miners don't detect malicious contract

4. **Release Proposal:**
    - Proposer calls `Release` [8](#0-7) 
    - Virtual address of Parliament organization executes `ChangeMethodFeeController`
    - Malicious contract returns true for validation
    - Controller updated successfully

5. **Post-Attack Verification:**
    - Call `GetMethodFeeController` - returns `{ ContractAddress: MaliciousGovernance, OwnerAddress: AttackerAddress }`
    - Attacker directly calls `SetMethodFee` as `AttackerAddress` - succeeds (governance bypassed)
    - Any other address calling `SetMethodFeeController` or `SetMethodFee` - fails authorization

**Expected vs Actual:**
- **Expected:** Only legitimate governance contracts should be accepted as method fee controllers
- **Actual:** Any contract can be set as controller if it returns true for `ValidateOrganizationExist`

**Success Condition:** Attacker gains unauthorized control of method fees or creates permanent lock, as demonstrated by ability to call `SetMethodFee` without governance approval or inability of anyone to modify fees.

### Citations

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L15-15)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L56-60)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```
