### Title
Method Fee Controller Bypass Through Malicious Contract Validation

### Summary
The `ChangeMethodFeeController` method across all AElf system contracts fails to validate that the new controller's `ContractAddress` is a legitimate system contract (Parliament, Association, or Referendum). An attacker can deploy a malicious contract that implements `ValidateOrganizationExist` to always return true, then use a governance proposal to set this malicious contract as the controller, permanently bypassing all governance requirements for method fee management.

### Finding Description

The vulnerability exists in the `CheckOrganizationExist` method used by `ChangeMethodFeeController` across 15 system contracts including Parliament, Association, MultiToken, CrossChain, Consensus, Treasury, and others. [1](#0-0) [2](#0-1) 

The `CheckOrganizationExist` method makes a cross-contract call to the `ContractAddress` specified in the input `AuthorityInfo`: [3](#0-2) 

**Root Cause**: The method accepts ANY contract address and calls its `ValidateOrganizationExist` method, without verifying that the contract address is a legitimate system contract. The codebase has the proper validation mechanism available via `Context.GetSystemContractNameToAddressMapping()` but it is not used: [4](#0-3) 

The same pattern correctly validates system contracts in other contexts, but this validation is missing from `CheckOrganizationExist`.

**Why Protections Fail**: The current implementation only validates that:
1. The sender is the current MethodFeeController owner (authorization check passes for legitimate governance)
2. The target contract returns `true` for `ValidateOrganizationExist` (trivially bypassable with malicious contract)

It does NOT validate that the `ContractAddress` is in the set of legitimate governance contracts (Parliament, Association, Referendum).

**Affected Contracts**: This vulnerability pattern exists identically in 15 system contracts:
- Parliament, Association, Referendum (governance)
- MultiToken, TokenConverter, TokenHolder (token system)
- AEDPoS (consensus), CrossChain, Election, Vote
- Genesis, Configuration, Economic, Treasury, Profit [5](#0-4) [6](#0-5) 

### Impact Explanation

**Governance Bypass**: Once exploited, the attacker gains direct control over method fees without any governance oversight. The intended security model requires all method fee changes to go through proposal-vote-release cycles in governance contracts. This vulnerability allows permanent bypass of this model.

**Systemic Risk**: Since this affects all 15 system contracts, an attacker could:
- Set arbitrary method fees across the entire protocol
- Make critical contract methods prohibitively expensive (economic DoS)
- Make malicious operations free to enable other attacks
- Permanently lock out legitimate governance by setting the controller to an inaccessible address

**Concrete Harm**:
1. **Economic manipulation**: Set fees to zero for profit-generating operations or infinity for defensive operations
2. **Governance lockout**: Once control is transferred to a malicious address, legitimate governance cannot regain control without contract upgrade
3. **Cross-contract exploitation**: Control of fees in one contract (e.g., MultiToken) enables attacks on dependent contracts

**Severity Justification**: CRITICAL - This enables complete bypass of a core security invariant (governance-controlled configuration) across all system contracts. The impact is protocol-wide governance failure.

### Likelihood Explanation

**Reachable Entry Point**: The `ChangeMethodFeeController` method is a standard ACS1 interface method callable through governance proposals.

**Attacker Capabilities Required**:
1. Deploy a malicious contract implementing `ValidateOrganizationExist` (user contract deployment is permitted)
2. Get a governance proposal approved by current MethodFeeController organization (requires convincing parliament/association members OR compromised governance)

**Attack Complexity**: LOW-MEDIUM
- Technical complexity: Low (simple malicious contract)
- Social engineering: May require misleading governance participants about the purpose of the controller change
- Cost: Minimal (contract deployment + proposal fees)

**Feasibility Conditions**:
- Works on any chain where user contracts can be deployed
- Requires one-time governance approval (the proposal might appear legitimate if framed as "updating to new governance structure")
- After initial exploit, attacker has permanent control without further governance involvement

**Detection Constraints**: 
- Difficult to detect pre-exploit: The malicious contract can appear legitimate
- Post-exploit: Governance participants may not immediately notice the controller change
- No on-chain mechanism prevents this attack

**Probability Assessment**: MEDIUM - While it requires governance proposal approval, the attack is not immediately obvious. A proposal to "update governance structure" or "migrate to improved organization contract" could be approved by well-meaning governance participants who don't recognize the malicious contract address.

### Recommendation

**Primary Fix**: Add system contract address validation to `CheckOrganizationExist` in all affected contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate that ContractAddress is a legitimate system contract
    var systemContractAddresses = Context.GetSystemContractNameToAddressMapping().Values;
    Assert(systemContractAddresses.Contains(authorityInfo.ContractAddress),
        "Contract address must be a system contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
}
```

**Additional Safeguards**:
1. Consider maintaining a whitelist of approved governance contract addresses (Parliament, Association, Referendum) rather than all system contracts
2. Add events when MethodFeeController is changed to enable monitoring
3. Implement a time-lock or two-step process for controller changes

**Invariant Checks to Add**:
- Assert `authorityInfo.ContractAddress` is in the system contract mapping
- Optionally: Assert `authorityInfo.ContractAddress` is specifically one of the three governance contracts

**Test Cases**:
1. Test `ChangeMethodFeeController` with non-system-contract address (should fail)
2. Test with system contract that isn't a governance contract (should fail with stricter whitelist)
3. Test with legitimate Parliament/Association/Referendum contracts (should succeed)
4. Test with user-deployed malicious contract implementing `ValidateOrganizationExist` (should fail after fix)

### Proof of Concept

**Initial State**:
- MethodFeeController is set to default Parliament organization
- Attacker can deploy user contracts

**Attack Steps**:

1. **Deploy Malicious Contract**:
```csharp
public class MaliciousValidator : ContractBase {
    public BoolValue ValidateOrganizationExist(Address input) {
        return new BoolValue { Value = true }; // Always returns true
    }
}
```

2. **Create Governance Proposal**:
    - Proposer creates proposal in Parliament to call `ChangeMethodFeeController`
    - Proposal parameters:
  - `ContractAddress`: Address of deployed malicious contract
  - `OwnerAddress`: Attacker's controlled address

3. **Get Proposal Approved**:
    - Parliament members approve the proposal (may be deceived about purpose)
    - Proposal reaches approval threshold

4. **Release Proposal**:
    - Execute proposal via `Release` method
    - `ChangeMethodFeeController` is called with malicious parameters

5. **Exploit Result**:
    - `CheckOrganizationExist` calls malicious contract's `ValidateOrganizationExist`
    - Malicious contract returns `true`
    - Validation passes, `State.MethodFeeController.Value` is updated
    - Current state: MethodFeeController = {ContractAddress: MaliciousContract, OwnerAddress: AttackerAddress}

6. **Post-Exploit Control**:
    - Attacker directly calls `SetMethodFee` (sender check passes because sender equals OwnerAddress)
    - No proposals/voting required
    - Complete governance bypass achieved

**Expected vs Actual**:
- Expected: `ChangeMethodFeeController` should reject non-governance contract addresses
- Actual: Any contract address is accepted if it returns `true` for organization validation

**Success Condition**: After step 5, attacker can directly call `SetMethodFee` on any affected contract without requiring any governance approval, demonstrating complete bypass of the governance model.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L116-121)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L39-48)
```csharp
    public override Address CreateOrganizationBySystemContract(CreateOrganizationBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to create organization.");
        var organizationAddress = CreateNewOrganization(input.OrganizationCreationInput);
        if (!string.IsNullOrEmpty(input.OrganizationAddressFeedbackMethod))
            Context.SendInline(Context.Sender, input.OrganizationAddressFeedbackMethod, organizationAddress);

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L70-74)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }
```
