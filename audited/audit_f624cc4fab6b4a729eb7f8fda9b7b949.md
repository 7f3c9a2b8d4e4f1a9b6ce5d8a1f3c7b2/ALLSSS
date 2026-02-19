### Title
MethodFeeController Can Be Permanently Locked by Setting Malicious Contract Address

### Summary
The `ChangeMethodFeeController` method in the Configuration contract lacks validation to ensure the new controller's `ContractAddress` is a legitimate authorization contract (Parliament, Association, or Referendum). A malicious contract can pass the organization existence check but prevent all subsequent fee updates by reverting on proposal execution. Once set, there is no recovery mechanism, permanently freezing the fee structure.

### Finding Description

The vulnerability exists in the `ChangeMethodFeeController` implementation: [1](#0-0) 

The method only validates the controller by calling `CheckOrganizationExist`: [2](#0-1) 

This implementation calls `Context.Call` on **any** address provided in `authorityInfo.ContractAddress` without verifying it's a legitimate authorization contract. An attacker can deploy a malicious contract that:

1. Implements `ValidateOrganizationExist` to return `true` (passing the check at line 27)
2. Reverts or fails on any actual proposal execution attempts

Once the controller is changed, all subsequent operations requiring controller authorization fail. The `SetMethodFee` method requires the sender to be the controller's owner address: [3](#0-2) 

To satisfy this requirement, a proposal must be executed through the controller contract. When the controller contract reverts on proposal execution, the sender requirement cannot be satisfied.

**No Recovery Mechanism**: Unlike `SetConfiguration` which allows the Zero Contract (Genesis) to override: [4](#0-3) 

The `ChangeMethodFeeController` and `SetMethodFee` methods have NO such emergency override - they ONLY check sender equality with no fallback mechanism. [5](#0-4) 

### Impact Explanation

**Operational Impact - Permanent DoS:**
- All method fee updates for the Configuration contract are permanently frozen
- Cannot adjust transaction costs for configuration-related operations
- Cannot recover by changing the controller back to a working one
- Fee structure remains locked at current values regardless of economic conditions

**Severity Justification:**
This is a permanent, irrecoverable lock of a critical governance parameter. While it doesn't directly steal funds, it removes the protocol's ability to adapt fee structures, which is essential for long-term operational viability.

### Likelihood Explanation

**Preconditions Required:**
- Current MethodFeeController (Parliament default organization) must approve a proposal to change the controller
- This requires either:
  - Governance compromise (malicious miners/proposers)
  - Social engineering attack tricking governance
  - Accidental approval of malicious proposal

**Attack Complexity:**
1. Deploy a malicious contract implementing `ValidateOrganizationExist` returning `true`
2. Create a proposal through Parliament to call `ChangeMethodFeeController` with malicious `AuthorityInfo`
3. Get proposal approved by required threshold (miners)
4. Release and execute proposal

**Feasibility Assessment:**
The attack is technically straightforward but requires governance-level participation. This is not exploitable by unauthorized attackers alone - it requires the current controller to approve the change. However, governance attacks through social engineering or compromise are realistic threats in blockchain systems.

**Probability:** Medium-to-High in scenarios where governance is compromised or makes operational errors. The lack of validation creates an unnecessary attack surface.

### Recommendation

**Immediate Fix:**
Add validation in `CheckOrganizationExist` to ensure `ContractAddress` is one of the known authorization contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate ContractAddress is a known authorization contract
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress ||
        authorityInfo.ContractAddress == associationAddress ||
        authorityInfo.ContractAddress == referendumAddress,
        "Invalid contract address. Must be Parliament, Association, or Referendum contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Additional Safeguards:**
1. Add emergency override capability allowing Zero Contract to reset MethodFeeController
2. Implement time-delayed controller changes with a grace period for cancellation
3. Add comprehensive test cases validating rejection of malicious contract addresses

**Test Cases:**
- Attempt to set MethodFeeController to arbitrary contract address (should fail)
- Attempt to set MethodFeeController to valid organization in unknown contract (should fail)
- Verify only Parliament/Association/Referendum contracts are accepted

### Proof of Concept

**Initial State:**
- Configuration contract deployed with MethodFeeController = Parliament default organization

**Attack Steps:**

1. Deploy malicious contract `MaliciousController`:
```csharp
public class MaliciousController {
    public BoolValue ValidateOrganizationExist(Address input) {
        return new BoolValue { Value = true };
    }
    // All other methods revert or don't exist
}
```

2. Create Parliament proposal to call `ChangeMethodFeeController`:
```csharp
Input: new AuthorityInfo {
    ContractAddress = MaliciousControllerAddress,
    OwnerAddress = AnyAddress  // Can be any address since ValidateOrganizationExist returns true
}
```

3. Parliament miners approve and release proposal

4. `ChangeMethodFeeController` executes:
   - Line 27: `CheckOrganizationExist(input)` calls malicious contract's `ValidateOrganizationExist`
   - Returns `true`, check passes
   - Line 30: `State.MethodFeeController.Value = input` sets controller to malicious contract

5. Attempt to update fees via `SetMethodFee`:
   - Line 17: Requires `Context.Sender == State.MethodFeeController.Value.OwnerAddress`
   - To satisfy this, create proposal through MaliciousController
   - Proposal cannot be executed (malicious contract reverts)
   - Fee updates permanently blocked

6. Attempt to fix via `ChangeMethodFeeController`:
   - Same authorization requirement
   - Cannot execute proposal through malicious controller
   - Permanently locked

**Expected Result:** Fee updates succeed after controller change

**Actual Result:** All fee update attempts fail permanently with "Unauthorized" or execution reverts

**Success Condition:** MethodFeeController is permanently locked and cannot be changed or used to update fees

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

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L32-43)
```csharp
    private void AssertPerformedByConfigurationControllerOrZeroContract()
    {
        if (State.ConfigurationController.Value == null)
        {
            var defaultConfigurationController = GetDefaultConfigurationController();
            State.ConfigurationController.Value = defaultConfigurationController;
        }

        Assert(
            State.ConfigurationController.Value.OwnerAddress == Context.Sender ||
            Context.GetZeroSmartContractAddress() == Context.Sender, "No permission.");
    }
```
