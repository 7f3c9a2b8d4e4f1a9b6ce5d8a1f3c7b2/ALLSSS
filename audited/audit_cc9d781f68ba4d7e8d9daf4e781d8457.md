### Title
ConfigurationController Can Be Changed to Attacker-Controlled Contract Bypassing Organization-Based Governance

### Summary
The `ChangeConfigurationController` method in the Configuration contract lacks validation that the new controller's `ContractAddress` is a legitimate governance contract (Parliament, Association, or Referendum). An attacker can deploy a malicious contract implementing a fake `ValidateOrganizationExist` method that always returns true, then use a single governance proposal to permanently bypass multi-signature governance, gaining unilateral control over critical system configurations.

### Finding Description

**Root Cause:**

The `CheckOrganizationExist` method in the Configuration contract performs insufficient validation when changing the ConfigurationController. [1](#0-0) 

This method makes a cross-contract call to the `ContractAddress` specified in the `AuthorityInfo` parameter, calling its `ValidateOrganizationExist` method. However, it does not validate that the `ContractAddress` is one of the legitimate system governance contracts.

**Vulnerable Execution Path:**

1. The `ChangeConfigurationController` method only checks that the sender is the current controller and that `CheckOrganizationExist(input)` returns true. [2](#0-1) 

2. The ConfigurationController is lazily initialized to Parliament's default organization. [3](#0-2) 

3. When permissions are checked, the system only verifies the sender matches the controller's OwnerAddress. [4](#0-3) 

**Why Existing Protections Fail:**

Unlike legitimate governance contracts that validate organizations exist in their state mappings [5](#0-4) , a malicious contract can implement `ValidateOrganizationExist` to always return true.

The codebase provides a validation pattern used by governance contracts to check if an address is a system contract [6](#0-5) , but this pattern is NOT applied in `CheckOrganizationExist`.

### Impact Explanation

**Critical Governance Bypass:**

After a single governance approval, an attacker gains permanent unilateral control over the Configuration contract, which manages critical system parameters including:
- `BlockTransactionLimit` - maximum transactions per block
- `RequiredAcsInContracts` - required ACS standards for contract deployment
- Other system-wide configuration parameters [7](#0-6) 

**Who Is Affected:**

- **All users:** System-wide configuration changes affect the entire blockchain
- **Contract developers:** RequiredAcsInContracts changes can block legitimate contracts
- **Network operators:** BlockTransactionLimit manipulation can cause DoS or enable spam

**Severity Justification:**

This is a **CRITICAL** vulnerability because:
1. Completely bypasses the multi-signature organization-based governance model
2. Converts a decentralized governance system into single-address control
3. Enables unauthorized modification of critical system parameters without proposals, approvals, or oversight
4. Violates the core Authorization & Governance invariant that organization thresholds and authority must be enforced

### Likelihood Explanation

**Attack Complexity: MEDIUM**

The attack requires:
1. **Deploy malicious contract:** Users can deploy contracts on AElf [8](#0-7) 
2. **One governance approval:** Must get Parliament to approve a single proposal changing the ConfigurationController
3. **Social engineering:** The proposal could appear legitimate if disguised as changing to an "improved governance contract"

**Feasibility Conditions:**

- Initial governance approval barrier (medium-high)
- Could succeed through:
  * Compromised governance members
  * Social engineering ("upgrading to new governance contract")
  * Malicious proposal hidden in legitimate-looking changes
- After setup, exploitation is trivial (direct function calls)

**Detection Constraints:**

Governance members reviewing proposals may not recognize that:
- The new ContractAddress is not a legitimate system contract
- The check only validates that `ValidateOrganizationExist` exists, not that it's trustworthy
- Once approved, the change is permanent and irreversible through normal governance

**Economic Rationality:**

Attack cost is low (contract deployment + proposal submission). Potential gain is complete control over system configuration, enabling various attack vectors or ransom scenarios.

### Recommendation

**Primary Fix - Validate System Contracts:**

Add validation in the `CheckOrganizationExist` method to ensure the `ContractAddress` is a legitimate governance system contract:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate that the contract address is a legitimate governance contract
    var systemContracts = Context.GetSystemContractNameToAddressMapping();
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress ||
        authorityInfo.ContractAddress == associationAddress ||
        authorityInfo.ContractAddress == referendumAddress,
        "Contract address must be a legitimate governance contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Test Cases:**

1. Test that `ChangeConfigurationController` succeeds with valid Parliament/Association/Referendum addresses
2. Test that `ChangeConfigurationController` fails with non-governance contract addresses  
3. Test that `ChangeConfigurationController` fails with user-deployed contract addresses
4. Add regression test deploying a malicious contract with fake `ValidateOrganizationExist`

### Proof of Concept

**Initial State:**
- ConfigurationController is initialized to Parliament's default organization [9](#0-8) 

**Attack Steps:**

1. **Deploy Malicious Contract:**
   - Attacker deploys contract `MaliciousGovernance` with:
     ```csharp
     public BoolValue ValidateOrganizationExist(Address input) {
         return new BoolValue { Value = true };
     }
     ```

2. **Create Governance Proposal:**
   - Attacker (or compromised member) creates Parliament proposal calling `ChangeConfigurationController` with:
     ```
     AuthorityInfo {
       ContractAddress = MaliciousGovernance,
       OwnerAddress = AttackerAddress
     }
     ```

3. **Proposal Approved and Released:**
   - Miners approve proposal (thinking it's a legitimate governance upgrade)
   - Proposal is released
   - `CheckOrganizationExist` calls `MaliciousGovernance.ValidateOrganizationExist(AttackerAddress)` → returns true
   - ConfigurationController updated successfully

4. **Exploit - Bypass Governance:**
   - Attacker directly calls `SetConfiguration` with any parameters
   - Permission check passes because `Context.Sender == AttackerAddress == ConfigurationController.OwnerAddress` [10](#0-9) 
   - No proposal, no approval, no multi-signature required

**Expected vs Actual:**
- **Expected:** Only legitimate governance contracts (Parliament/Association/Referendum) should be accepted
- **Actual:** Any contract implementing `ValidateOrganizationExist` is accepted, allowing governance bypass

**Success Condition:**
Attacker can repeatedly call `SetConfiguration` with arbitrary parameters without creating proposals or getting approvals, completely bypassing the organization-based governance model.

### Citations

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L72-77)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L8-19)
```csharp
    private AuthorityInfo GetDefaultConfigurationController()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L21-30)
```csharp
    private void AssertPerformedByConfigurationController()
    {
        if (State.ConfigurationController.Value == null)
        {
            var defaultConfigurationController = GetDefaultConfigurationController();
            State.ConfigurationController.Value = defaultConfigurationController;
        }

        Assert(Context.Sender == State.ConfigurationController.Value.OwnerAddress, "No permission.");
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L41-42)
```csharp
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to create organization.");
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationState.cs (L7-13)
```csharp
public partial class ConfigurationState : ContractState
{
    public SingletonState<AuthorityInfo> ConfigurationController { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public MappedState<string, BytesValue> Configurations { get; set; }
}
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L409-410)
```csharp
    public override DeployUserSmartContractOutput DeployUserSmartContract(UserContractDeploymentInput input)
    {
```
