### Title
Unvalidated Authorization Contract Address Allows Method Fee Controller Bypass

### Summary
The `CheckOrganizationExist()` function in `ConfigurationContract_ACS1_TransactionFeeProvider.cs` calls `authorityInfo.ContractAddress` without verifying it is a legitimate authorization contract (Parliament, Association, or Referendum). An attacker can deploy a malicious contract that always returns true for `ValidateOrganizationExist`, trick governance into approving a controller change, and gain unilateral control over method fees, completely bypassing the intended multi-signature governance mechanism.

### Finding Description

**Root Cause:**

The `CheckOrganizationExist()` helper function performs cross-contract validation without verifying the target contract's legitimacy: [1](#0-0) 

The function accepts any `AuthorityInfo.ContractAddress` and calls its `ValidateOrganizationExist` method. There is no check to ensure this address corresponds to a legitimate system authorization contract.

**Why Existing Protections Fail:**

The `ChangeMethodFeeController()` method requires the current controller's authorization and validates organization existence: [2](#0-1) 

However, line 27 only verifies the organization exists *within the provided contract*, not that the contract itself is legitimate. Legitimate authorization contracts validate by checking state: [3](#0-2) [4](#0-3) 

A malicious contract can implement the ACS3 interface and always return true, bypassing this validation entirely.

**Exploitation Path:**

1. Attacker deploys a malicious contract implementing the ACS3 `ValidateOrganizationExist` method to always return `new BoolValue { Value = true }`
2. Attacker creates a governance proposal to change the method fee controller with `AuthorityInfo` containing:
   - `ContractAddress`: malicious contract address
   - `OwnerAddress`: attacker-controlled address
3. Parliament approves the proposal (through social engineering, assuming the addresses look legitimate)
4. Proposal is released and executes `ChangeMethodFeeController()`
5. `CheckOrganizationExist()` calls the malicious contract, which returns true
6. Validation passes, new controller is set
7. Attacker now controls method fees unilaterally via `SetMethodFee()`

**Pattern Prevalence:**

This vulnerability affects multiple contracts using the identical pattern: [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Governance Impact:**

Once the malicious controller is set, the attacker gains complete unilateral control over method transaction fees via `SetMethodFee()`: [8](#0-7) 

This bypasses the intended governance requirement that method fees be controlled by a multi-signature organization.

**Economic and Operational Impact:**

- **DoS Attack**: Attacker can set method fees arbitrarily high, making contract functions economically infeasible to call
- **Economic Manipulation**: Setting fees too low undermines the protocol's economic model and fee burn mechanisms
- **User Impact**: All users calling methods on the Configuration contract face unexpected fee changes without governance approval
- **Trust Violation**: Complete subversion of the governance model for a critical system parameter

**Severity Justification:**

Critical severity because:
1. Complete bypass of multi-signature governance control
2. Affects fundamental system parameters (transaction fees)
3. No recovery mechanism once controller is changed (requires new governance action)
4. Impact extends to all contract users
5. Exploitation is technically straightforward once governance is deceived

### Likelihood Explanation

**Attack Prerequisites:**

- Ability to deploy contracts (generally permissioned but achievable)
- Crafting a governance proposal that appears legitimate
- Parliament approval through social engineering

**Feasibility Assessment:**

**High Feasibility** because:

1. **Reachable Entry Point**: `ChangeMethodFeeController()` is a standard governance operation
2. **Low Technical Barrier**: Deploying a malicious contract with one method returning true is trivial
3. **Social Engineering Vector**: Governance proposals containing contract addresses may not be thoroughly audited by voters, especially if the organization address appears valid
4. **Realistic Preconditions**: The attack doesn't require compromising Parliament itself, only deceiving voters into approving a malicious proposal
5. **No Runtime Detection**: The malicious contract's behavior cannot be detected during the proposal approval process

**Attack Complexity**: Medium

- Requires creating a plausible governance proposal
- Depends on Parliament members not verifying the contract address is a legitimate system contract
- One-time setup cost to deploy malicious contract

**Economic Rationality**: High

- Low cost to execute (contract deployment + proposal submission)
- High reward (control over system fees, potential for extortion or DoS)
- No on-chain detection before execution

**Detection Difficulty**: High

Voters would need to manually verify that `ContractAddress` matches a known system contract address by checking against: [9](#0-8) 

This is not enforced programmatically and relies on manual due diligence.

### Recommendation

**Immediate Fix:**

Add validation in `CheckOrganizationExist()` to ensure the contract address is a legitimate system authorization contract:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate contract address is a legitimate authorization contract
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress ||
        authorityInfo.ContractAddress == associationAddress ||
        authorityInfo.ContractAddress == referendumAddress,
        "Invalid authorization contract address.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Apply to All Affected Contracts:**

The same fix must be applied to:
- `TreasuryContract_ACS1_TransactionFeeProvider.cs`
- `TokenContract_ACS1_MethodFeeProvider.cs`
- `BasicContractZero_Helper.cs`
- Any other contracts using this pattern

**Test Coverage:**

Add test cases to verify:
1. `ChangeMethodFeeController` rejects non-system contract addresses
2. `ChangeMethodFeeController` accepts only Parliament/Association/Referendum addresses
3. Attempting to use a custom contract implementing ACS3 fails with appropriate error message

### Proof of Concept

**Initial State:**
- Configuration contract initialized with Parliament default organization as method fee controller

**Attack Sequence:**

1. **Deploy Malicious Contract:**
```csharp
public class MaliciousAuthContract : AuthorizationContractContainer.AuthorizationContractBase
{
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = true }; // Always returns true
    }
    // Other ACS3 methods stubbed
}
```

2. **Create Governance Proposal:**
   - Proposer: Legitimate Parliament member
   - Target: ConfigurationContract.ChangeMethodFeeController
   - Parameters: 
     ```
     AuthorityInfo {
       ContractAddress: <MaliciousAuthContract address>
       OwnerAddress: <Attacker-controlled address>
     }
     ```

3. **Parliament Approval:**
   - Proposal appears to change controller to a new organization
   - Voters approve without verifying ContractAddress legitimacy

4. **Execute Proposal:**
   - Proposal is released
   - `ChangeMethodFeeController()` is called
   - `CheckOrganizationExist()` calls malicious contract
   - Malicious contract returns true
   - Validation passes, controller is changed

5. **Exploit:**
   - Attacker directly calls `SetMethodFee()` as the OwnerAddress
   - Sets arbitrary fees without any governance approval

**Expected Result:** Transaction should fail with "Invalid authorization contract address"

**Actual Result:** Transaction succeeds, attacker gains controller access

**Success Condition:** New method fee controller set to attacker's address, enabling unilateral fee changes bypassing governance.

### Citations

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L11-21)
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

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L23-32)
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

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L72-77)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract_ACS1_TransactionFeeProvider.cs (L71-76)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L180-185)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L18-36)
```csharp
    public static readonly Hash ParliamentContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Parliament");

    public static readonly Hash VoteContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Vote");
    public static readonly Hash ProfitContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Profit");

    public static readonly Hash CrossChainContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.CrossChain");

    public static readonly Hash TokenConverterContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.TokenConverter");

    public static readonly Hash EconomicContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Economic");

    public static readonly Hash ReferendumContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Referendum");

    public static readonly Hash AssociationContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Association");
```
