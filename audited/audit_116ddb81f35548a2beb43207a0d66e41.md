### Title
Method Fee Controller Can Be Changed to Malicious Contract Address Bypassing Governance Validation

### Summary
The `ChangeMethodFeeController()` function validates organization existence by calling the provided `ContractAddress` without verifying it is a legitimate governance contract. An attacker controlling the current controller can set a malicious contract that always approves validation, establishing permanent direct control over method fees and bypassing all future governance oversight.

### Finding Description

The vulnerability exists in the `ChangeMethodFeeController()` implementation across multiple ACS1-implementing contracts, including TokenConverter: [1](#0-0) 

The function performs two checks:
1. Verifies caller is the current `MethodFeeController.OwnerAddress` 
2. Validates organization exists via `CheckOrganizationExist(input)`

The `CheckOrganizationExist()` implementation makes a cross-contract call to the **attacker-supplied** `ContractAddress`: [2](#0-1) 

**Root Cause**: The function trusts whatever contract address is provided in `input.ContractAddress` to validate the organization, without verifying this address belongs to an authorized governance contract (Parliament, Association, or Referendum system contracts).

An attacker can deploy a malicious contract implementing:
```csharp
public BoolValue ValidateOrganizationExist(Address input) {
    return new BoolValue { Value = true };  // Always returns true
}
```

When `ChangeMethodFeeController` is called with `AuthorityInfo { OwnerAddress: attackerAddress, ContractAddress: maliciousContract }`, the malicious contract returns `true` for any address, bypassing the intended validation that the organization must exist in a legitimate governance contract.

The same vulnerability pattern exists in all ACS1 implementations: [3](#0-2) [4](#0-3) 

### Impact Explanation

**Governance Bypass**: Once the MethodFeeController is changed to attacker-controlled values, all subsequent `SetMethodFee()` calls bypass governance: [5](#0-4) 

The attacker can directly call `SetMethodFee()` as the new `OwnerAddress` without creating proposals, obtaining approvals, or going through any governance process.

**Concrete Harm**:
- **Fee Manipulation**: Attacker can set method fees to 0, enabling free attacks and exploitation, or set them extremely high to DoS the contract
- **Permanent Control**: The malicious controller persists until another governance action reverses it (requiring compromise of the current attacker-controlled system)
- **System-Wide Impact**: This vulnerability affects all ACS1-implementing contracts (TokenConverter, MultiToken, Parliament, Association, Referendum, Consensus, CrossChain, Treasury, Profit, TokenHolder, Election, Vote, Configuration, Economic contracts)
- **Protocol Damage**: Loss of decentralized governance guarantees, undermining the entire authorization model

### Likelihood Explanation

**Preconditions**: 
- Attacker must control the current `MethodFeeController.OwnerAddress`
- This could occur through: legitimate governance majority, initialization misconfiguration, or key compromise

**Attack Complexity**: Once precondition is met, exploitation is trivial:
1. Deploy malicious contract (single transaction)
2. Call `ChangeMethodFeeController` (single transaction)
3. Exploit achieved

**Feasibility**: 
- The malicious contract implementation is straightforward
- No economic cost beyond gas fees
- No detection mechanisms exist in the code
- Attack leaves permanent backdoor

**Probability Reasoning**: While the precondition represents a significant barrier, the vulnerability provides **privilege escalation** - an attacker with temporary governance control can establish permanent direct control bypassing all future governance. This transforms temporary authorized access into a persistent backdoor.

The existing test suite validates only invalid `OwnerAddress` scenarios but never tests malicious `ContractAddress`: [6](#0-5) 

### Recommendation

Add validation to ensure `ContractAddress` is a whitelisted governance contract before accepting the authority change:

```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
    
    // NEW: Validate ContractAddress is a legitimate governance contract
    var systemContracts = Context.GetSystemContractNameToAddressMapping();
    Assert(
        input.ContractAddress == systemContracts[SmartContractConstants.ParliamentContractSystemName] ||
        input.ContractAddress == systemContracts[SmartContractConstants.AssociationContractSystemName] ||
        input.ContractAddress == systemContracts[SmartContractConstants.ReferendumContractSystemName],
        "Contract address must be a recognized governance contract.");
    
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");
    
    State.MethodFeeController.Value = input;
    return new Empty();
}
```

**Test Case**: Add test that attempts to use non-governance contract address:
```csharp
var maliciousContract = await DeployMaliciousContract();
var result = await ExecuteProposalForParliamentTransaction(
    TokenConverterContractAddress,
    nameof(ChangeMethodFeeController),
    new AuthorityInfo { OwnerAddress: someAddress, ContractAddress: maliciousContract });
result.Error.ShouldContain("Contract address must be a recognized governance contract");
```

### Proof of Concept

**Initial State**:
- MethodFeeController = { OwnerAddress: ParliamentDefaultOrg, ContractAddress: ParliamentContract }
- Attacker controls ParliamentDefaultOrg through legitimate voting majority

**Attack Steps**:

1. Attacker deploys MaliciousContract:
```csharp
public class MaliciousContract {
    public BoolValue ValidateOrganizationExist(Address input) {
        return new BoolValue { Value = true };
    }
}
```

2. Attacker creates and approves Parliament proposal to call:
```
ChangeMethodFeeController({
    OwnerAddress: AttackerExternalAddress,
    ContractAddress: MaliciousContract
})
```

3. Validation passes:
   - Line 25: Sender is ParliamentDefaultOrg ✓
   - Line 26-27: `MaliciousContract.ValidateOrganizationExist(AttackerExternalAddress)` returns `true` ✓

4. State updated: `MethodFeeController = { AttackerExternalAddress, MaliciousContract }`

5. Attacker now directly calls `SetMethodFee()` without governance:
   - Check at line 16: `Context.Sender == AttackerExternalAddress` ✓
   - No proposal, no approvals, no governance oversight

**Expected**: Only legitimate governance contracts should be accepted as `ContractAddress`

**Actual**: Any contract returning `true` from `ValidateOrganizationExist` is accepted, including attacker-controlled contracts

**Success Condition**: Attacker can arbitrarily set method fees by direct transaction, confirmed by querying `GetMethodFee()` after unauthorized `SetMethodFee()` call succeeds.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract_ACS1_TransactionFeeProvider.cs (L11-20)
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract_ACS1_TransactionFeeProvider.cs (L22-31)
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract_ACS1_TransactionFeeProvider.cs (L71-76)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L366-373)
```csharp
    public override Empty ChangeContractDeploymentController(AuthorityInfo input)
    {
        AssertSenderAddressWith(State.ContractDeploymentController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");
        State.ContractDeploymentController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L24-33)
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

**File:** test/AElf.Contracts.TokenConverter.Tests/ACS1_ImplementTest.cs (L91-100)
```csharp
    public async Task ChangeMethodFeeController_With_Invalid_Organization_Test()
    {
        var releaseResult = await ExecuteProposalForParliamentTransactionWithException(
            TokenConverterContractAddress, nameof(DefaultStub.ChangeMethodFeeController), new AuthorityInfo
            {
                OwnerAddress = DefaultSender,
                ContractAddress = ParliamentContractAddress
            });
        releaseResult.Error.ShouldContain("Invalid authority input");
    }
```
