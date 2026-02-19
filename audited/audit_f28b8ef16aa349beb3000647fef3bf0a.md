### Title
Insufficient Validation of Controller Contract Address Allows Malicious Governance Takeover

### Summary
The `ChangeSymbolsToPayTXSizeFeeController()` function validates organization existence but fails to verify that the `ContractAddress` in the `AuthorityInfo` parameter is one of the legitimate system governance contracts (Parliament, Association, or Referendum). An attacker can deploy a malicious contract that implements `ValidateOrganizationExist` to always return true, allowing Parliament to inadvertently approve setting an attacker-controlled address as the controller, granting unauthorized control over transaction fee mechanisms.

### Finding Description

The vulnerability exists in the validation logic of `ChangeSymbolsToPayTXSizeFeeController()`: [1](#0-0) 

The function calls `CheckOrganizationExist(input)` which performs cross-contract validation: [2](#0-1) 

**Root Cause:** `CheckOrganizationExist` makes a cross-contract call to `ValidateOrganizationExist` on whatever `ContractAddress` is provided in the `AuthorityInfo` parameter, without verifying that this address corresponds to one of the legitimate system governance contracts.

**Why Existing Protections Fail:**

The legitimate governance contracts implement `ValidateOrganizationExist` as: [3](#0-2) [4](#0-3) [5](#0-4) 

However, an attacker can deploy a malicious contract that implements the same interface but always returns true, bypassing the intended validation. The codebase has mechanisms to validate system contracts: [6](#0-5) 

But `CheckOrganizationExist` does not utilize these safeguards.

### Impact Explanation

**Direct Governance Impact:** An attacker who becomes the `SymbolToPayTxFeeController` gains the ability to call `SetSymbolsToPayTxSizeFee`: [7](#0-6) 

This controller can:
- Manipulate which tokens are accepted for transaction size fees
- Alter token weights used in fee calculations
- Potentially disrupt the fee mechanism by removing the primary token or setting invalid configurations
- Create economic advantages for specific tokens

**Who Is Affected:** All network participants who pay transaction fees, as the fee mechanism is a critical system-level component.

**Severity Justification:** Critical - while not directly stealing funds, this grants unauthorized control over a fundamental economic parameter of the blockchain, potentially enabling fee manipulation, network disruption, or unfair economic advantages.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Deploy a malicious contract implementing `ValidateOrganizationExist` 
2. Convince Parliament to create and approve a proposal using this malicious contract address

**Attack Complexity:** Medium - requires social engineering or deceiving Parliament members, but technically straightforward.

**Feasibility Conditions:** 
- The authorization check ensures only the current controller (Parliament) can execute the change: [8](#0-7) 

- However, Parliament members may assume the validation logic is sufficient and not manually verify that `ContractAddress` is a legitimate system governance contract
- The error message "new controller does not exist" suggests adequate validation, creating a false sense of security

**Detection/Operational Constraints:** Parliament could detect this if they:
- Manually verify the `ContractAddress` against known system governance contracts
- Check that `ContractAddress` matches addresses from `GetContractAddressByName`
- However, this requires operational vigilance beyond what the code enforces

**Probability:** Low to Medium - depends on Parliament's operational security practices, but the weak validation creates unnecessary risk.

### Recommendation

**Code-Level Mitigation:**

Add explicit validation in `CheckOrganizationExist` or `ChangeSymbolsToPayTXSizeFeeController` to ensure the `ContractAddress` is one of the legitimate system governance contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate ContractAddress is a legitimate governance contract
    var isParliament = authorityInfo.ContractAddress == State.ParliamentContract.Value;
    var isAssociation = authorityInfo.ContractAddress == State.AssociationContract.Value;
    var isReferendum = authorityInfo.ContractAddress == State.ReferendumContract.Value;
    
    Assert(isParliament || isAssociation || isReferendum, 
        "ContractAddress must be Parliament, Association, or Referendum contract");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

Alternatively, use `GetSystemContractNameToAddressMapping()` to validate:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    var systemContractAddresses = Context.GetSystemContractNameToAddressMapping().Values;
    Assert(systemContractAddresses.Contains(authorityInfo.ContractAddress),
        "ContractAddress must be a system governance contract");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Apply this fix to all similar controller change methods:**
- `ChangeSideChainRentalController`
- `ChangeCrossChainTokenContractRegistrationController`
- `ChangeUserFeeController`
- `ChangeDeveloperController`
- `ChangeTransferBlackListController`
- `ChangeMethodFeeController`

**Test Cases:**
1. Attempt to change controller with non-system contract address → should fail
2. Attempt to change controller with malicious contract implementing ValidateOrganizationExist → should fail
3. Successfully change controller with legitimate Parliament/Association/Referendum organization → should succeed
4. Verify all controller change methods enforce the same validation

### Proof of Concept

**Initial State:**
- `SymbolToPayTxFeeController` is set to default Parliament organization
- Attacker has deployed `MaliciousContract` at address `0xMALICIOUS`

**Attack Steps:**

1. **Attacker deploys malicious contract:**
```csharp
public class MaliciousContract
{
    public BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = true }; // Always returns true
    }
}
```

2. **Parliament creates proposal to change controller:**
```
ProposalInput {
    ContractMethodName: "ChangeSymbolsToPayTXSizeFeeController",
    ToAddress: TokenContractAddress,
    Params: AuthorityInfo {
        ContractAddress: 0xMALICIOUS,
        OwnerAddress: 0xATTACKER
    }
}
```

3. **Parliament members approve and release proposal** (not detecting that `ContractAddress` is not a system governance contract)

4. **Execution path:**
   - `AssertControllerForSymbolToPayTxSizeFee()` passes (sender is Parliament organization)
   - `CheckOrganizationExist(input)` calls `0xMALICIOUS.ValidateOrganizationExist(0xATTACKER)`
   - Malicious contract returns `true`
   - `State.SymbolToPayTxFeeController.Value` set to malicious AuthorityInfo

5. **Attack succeeds:** Attacker at `0xATTACKER` can now call `SetSymbolsToPayTxSizeFee` to manipulate fee mechanisms

**Expected vs Actual:**
- **Expected:** Validation should reject non-governance contract addresses
- **Actual:** Validation passes, attacker gains controller privileges

**Success Condition:** `GetSymbolsToPayTXSizeFeeController()` returns `AuthorityInfo` with attacker's malicious contract address, allowing attacker to execute privileged operations.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L45-51)
```csharp
    public override Empty ChangeSymbolsToPayTXSizeFeeController(AuthorityInfo input)
    {
        AssertControllerForSymbolToPayTxSizeFee();
        Assert(CheckOrganizationExist(input), "new controller does not exist");
        State.SymbolToPayTxFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L399-405)
```csharp
    private void AssertControllerForSymbolToPayTxSizeFee()
    {
        if (State.SymbolToPayTxFeeController.Value == null)
            State.SymbolToPayTxFeeController.Value = GetDefaultSymbolToPayTxFeeController();

        Assert(State.SymbolToPayTxFeeController.Value.OwnerAddress == Context.Sender, "no permission");
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

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L218-221)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L200-203)
```csharp
        var systemContractAddresses = Context.GetSystemContractNameToAddressMapping().Values;
        var isSystemContractAddress = systemContractAddresses.Contains(Context.Sender);
        Assert(isInWhiteList || isSystemContractAddress, "No Permission.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L616-619)
```csharp
    public override Empty SetSymbolsToPayTxSizeFee(SymbolListToPayTxSizeFee input)
    {
        AssertControllerForSymbolToPayTxSizeFee();
        if (input == null)
```
