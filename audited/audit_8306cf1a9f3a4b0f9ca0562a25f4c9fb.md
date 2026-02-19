### Title
Insufficient Controller Validation Enables Permanent Bricking of Method Fee Management

### Summary
The `ChangeMethodFeeController()` function fails to validate that `input.ContractAddress` is a legitimate authorization contract (Parliament, Association, or Referendum). A malicious or compromised controller can set the contract address to a fake contract that always returns true for `ValidateOrganizationExist`, combined with an uncontrollable `OwnerAddress`, permanently bricking the method fee management system with no recovery path.

### Finding Description

The vulnerability exists in the `ChangeMethodFeeController()` function at line 23-32: [1](#0-0) 

The function only validates that the target contract has a `ValidateOrganizationExist` method that returns true for the provided address: [2](#0-1) 

**Root Cause**: There is no validation that `input.ContractAddress` is one of the legitimate system authorization contracts. The `CheckOrganizationExist` method uses `Context.Call` to invoke `ValidateOrganizationExist`, which will succeed on ANY contract that implements this method, regardless of whether it's a legitimate ACS3 authorization contract.

**Why Existing Protections Fail**: 
- The validation only checks method existence and return value, not contract legitimacy
- No whitelist check against known system contracts (Parliament, Association, Referendum)
- The ACS3 `ValidateOrganizationExist` interface is simple and can be trivially implemented by malicious contracts: [3](#0-2) 

Legitimate implementations check actual organization state: [4](#0-3) 

But a malicious contract can simply return `true` for any address.

**Execution Path**:
1. Current controller (requires compromise of Parliament default org with 2/3+ miners, or previously changed controller)
2. Deploy malicious contract with fake `ValidateOrganizationExist` that returns true
3. Call `ChangeMethodFeeController` with malicious `ContractAddress` and uncontrollable `OwnerAddress`
4. Validation passes at line 27-28, controller updated at line 30
5. All future `SetMethodFee` calls require sender match at line 17: [5](#0-4) 

6. Future `ChangeMethodFeeController` calls also blocked by authorization check at line 26

### Impact Explanation

**Harm**: Complete and permanent loss of method fee governance for the Configuration contract. Once the controller is set to an uncontrollable address:
- No one can call `SetMethodFee` to update transaction fees for any method
- No one can call `ChangeMethodFeeController` to fix the controller
- The damage is irreversible through normal governance processes

**Quantified Damage**: 
- All method fee management becomes permanently unusable
- Cannot adjust fees in response to economic conditions
- Cannot restore governance even if attacker keys are recovered
- Affects the entire Configuration contract's fee structure

**Who is Affected**: All users and applications relying on the Configuration contract, as method fees cannot be adjusted. The entire AElf ecosystem loses the ability to manage Configuration contract fees.

**Severity Justification**: HIGH - This enables an irrevocable attack that permanently disables critical governance functionality. While it requires initial controller compromise, the attack creates permanent damage that cannot be undone, which is more severe than temporary control.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Must already control the `MethodFeeController` (initially Parliament's default organization requiring 2/3+ miner approval)
- Ability to deploy a malicious contract (standard blockchain capability)

**Attack Complexity**: Low once access obtained
- Deploy simple malicious contract (10 lines of code)
- Single transaction to `ChangeMethodFeeController`
- No complex exploit chain or race conditions

**Feasibility Conditions**:
- Controller compromise via governance (malicious proposal approved by miners)
- OR controller previously changed to attacker-controlled organization
- Malicious contract deployment (~0.1-1 ELF gas cost, trivial)

**Detection/Operational Constraints**: The attack is not easily detectable until after execution, and cannot be reversed through standard recovery procedures.

**Probability Reasoning**: While requiring controller compromise elevates the attack threshold, the *irreversibility* of the damage makes this a critical security gap. Proper validation would prevent this specific attack vector even under controller compromise scenarios.

### Recommendation

**Code-Level Mitigation**: Add validation that `input.ContractAddress` is a whitelisted system contract before line 30:

```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
    
    // ADD: Validate ContractAddress is a system contract
    var systemContracts = Context.GetSystemContractNameToAddressMapping();
    Assert(
        systemContracts.Values.Contains(input.ContractAddress),
        "Controller contract must be a system contract."
    );
    
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");

    State.MethodFeeController.Value = input;
    return new Empty();
}
```

**Invariant Checks**:
1. Controller `ContractAddress` must be in the system contract mapping
2. Controller `ContractAddress` must be Parliament, Association, or Referendum contract
3. Controller `OwnerAddress` must be a valid organization in the specified contract

**Test Cases**:
1. Test `ChangeMethodFeeController` with non-system contract address (should fail)
2. Test with malicious contract implementing `ValidateOrganizationExist` (should fail)
3. Test with legitimate system contract but invalid organization (should fail - already covered)
4. Test with legitimate Parliament/Association/Referendum organization (should succeed)

### Proof of Concept

**Required Initial State**:
- Configuration contract deployed with default MethodFeeController (Parliament default organization)
- Attacker controls the current MethodFeeController (via governance compromise)

**Transaction Steps**:
1. Deploy malicious contract:
```csharp
public class MaliciousAuthContract {
    public BoolValue ValidateOrganizationExist(Address input) {
        return new BoolValue { Value = true }; // Always returns true
    }
}
```

2. Create proposal to call `ChangeMethodFeeController` with:
```
AuthorityInfo {
    ContractAddress = <MaliciousAuthContract address>,
    OwnerAddress = <Zero address or uncontrollable address>
}
```

3. Approve and release proposal through current controller

**Expected vs Actual Result**:
- **Expected**: Transaction should fail with "Invalid contract address" or "Contract not in system whitelist"
- **Actual**: Transaction succeeds, controller updated to uncontrollable state

**Success Condition**: 
- After execution, `GetMethodFeeController()` returns the malicious configuration
- Any subsequent call to `SetMethodFee()` fails with "Unauthorized to set method fee"
- Any subsequent call to `ChangeMethodFeeController()` fails with "Unauthorized behavior"
- Method fee management is permanently disabled

**Notes**

This vulnerability exists identically in multiple system contracts using the same pattern, including MultiToken, Treasury, Profit, and others. The same validation gap appears in `ChangeConfigurationController` within the same codebase: [6](#0-5) 

The pattern requires systematic review across all contracts implementing controller change functionality.

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

**File:** protobuf/acs3.proto (L67-70)
```text
    // Check the existence of an organization.
    rpc ValidateOrganizationExist(aelf.Address) returns (google.protobuf.BoolValue){
        option (aelf.is_view) = true;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract.cs (L29-36)
```csharp
    public override Empty ChangeConfigurationController(AuthorityInfo input)
    {
        AssertPerformedByConfigurationController();
        Assert(input != null, "invalid input");
        Assert(CheckOrganizationExist(input), "Invalid authority input.");
        State.ConfigurationController.Value = input;
        return new Empty();
    }
```
