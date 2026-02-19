### Title
Missing Authorization Contract Validation Allows Governance Bypass Through Malicious Controller

### Summary
The `CheckOrganizationExist()` function in `TokenHolderContract_ACS1_TransactionFeeProvider.cs` fails to validate that `authorityInfo.ContractAddress` is a legitimate authorization contract (Parliament, Association, or Referendum) before accepting it as the method fee controller. An attacker with temporary governance access can deploy a malicious contract and set it as the controller, gaining permanent unilateral control over method fees and bypassing all governance mechanisms.

### Finding Description
The vulnerability exists in the `CheckOrganizationExist()` function which is called by `ChangeMethodFeeController()`: [1](#0-0) 

The function performs a cross-contract call to `authorityInfo.ContractAddress` without first validating that this address is one of the three legitimate system authorization contracts. It only verifies that the `ValidateOrganizationExist` method returns true for the provided organization address.

The usage in `ChangeMethodFeeController()` shows the insufficient validation: [2](#0-1) 

This pattern is inconsistent with critical security controls elsewhere in the codebase. The CrossChain contract's `ChangeCrossChainIndexingController` explicitly validates that the contract address must be Parliament: [3](#0-2) 

This demonstrates that developers understood the need for contract address validation in sensitive controllers, but failed to implement it consistently across all ACS1 method fee controllers. The codebase provides mechanisms to validate system contract addresses through `GetSystemContractNameToAddressMapping()`, but these are not utilized in `CheckOrganizationExist()`.

The same vulnerable pattern appears in all ACS1-implementing contracts: [4](#0-3) [5](#0-4) 

### Impact Explanation
**Governance Bypass**: An attacker can permanently bypass all governance mechanisms by setting a malicious contract that always validates their address as an authorized organization. This breaks the fundamental security invariant that only Parliament, Association, or Referendum contracts should control governance.

**Permanent Unilateral Control**: Unlike temporary governance control through Parliament majority (which requires ongoing support and can be revoked), this vulnerability allows permanent unilateral control that cannot be easily removed through legitimate governance channels.

**Method Fee Manipulation**: The attacker gains complete control over `SetMethodFee()` as validated here: [6](#0-5) 

This enables:
- Setting fees to zero (eliminating method fee revenue)
- Setting extremely high fees (DoS of contract functionality)
- Arbitrary fee manipulation for economic advantage

**System-Wide Impact**: This vulnerability affects all system contracts implementing ACS1, including Genesis (contract deployment), Token, Treasury, Profit, Election, Consensus, CrossChain, and others, as they all use the same vulnerable validation pattern.

### Likelihood Explanation
**Prerequisites**: The attack requires:
1. Ability to deploy a malicious contract implementing `ValidateOrganizationExist` that returns true
2. Current control over the method fee controller (typically Parliament default organization)

**Attack Complexity**: Low once prerequisites are met. The attacker simply:
1. Deploys a contract with a permissive validation function
2. Proposes and passes a governance proposal to change the controller
3. Gains permanent unilateral control

**Privilege Escalation**: While precondition #2 requires significant access (Parliament control), this vulnerability represents a clear **privilege escalation**:
- **Before**: Temporary governance control requiring ongoing majority support, subject to transparency and voting delays
- **After**: Permanent unilateral control with no governance oversight or recourse

**Deployment Restrictions**: Contract deployment may be restricted by `ContractDeploymentAuthorityRequired` setting: [7](#0-6) 

However, an attacker with Parliament control could also control contract deployment governance, making this a realistic attack path.

**Detection Difficulty**: The malicious controller change would appear as a legitimate governance action, making it difficult to detect until the attacker begins exploiting unilateral control.

### Recommendation
**Immediate Fix**: Add validation in `CheckOrganizationExist()` to verify the contract address is one of the three legitimate authorization contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate contract address is Parliament, Association, or Referendum
    if (State.ParliamentContract.Value == null)
        State.ParliamentContract.Value = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    if (State.AssociationContract.Value == null)
        State.AssociationContract.Value = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    if (State.ReferendumContract.Value == null)
        State.ReferendumContract.Value = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == State.ParliamentContract.Value ||
        authorityInfo.ContractAddress == State.AssociationContract.Value ||
        authorityInfo.ContractAddress == State.ReferendumContract.Value,
        "Invalid authorization contract address.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Apply System-Wide**: This fix must be applied to ALL contracts implementing ACS1:
- BasicContractZero (Genesis)
- TokenContract (MultiToken)
- ParliamentContract
- AssociationContract
- ReferendumContract
- ConfigurationContract
- ConsensusContract
- TreasuryContract
- ElectionContract
- TokenHolderContract
- ProfitContract
- VoteContract
- NFTContract
- TokenConverterContract

**Add Invariant Tests**: Create test cases that attempt to set arbitrary contract addresses and verify they are rejected.

**Consider Alternative Validation**: Use `Context.GetSystemContractNameToAddressMapping()` for more flexible validation: [8](#0-7) 

### Proof of Concept

**Initial State**:
- Attacker has majority control of Parliament default organization
- Contract deployment is possible (either unrestricted or through governance)

**Attack Steps**:

1. **Deploy Malicious Contract**:
```csharp
public class MaliciousAuthContract : MaliciousAuthContractContainer.MaliciousAuthContractBase
{
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = true }; // Always validates
    }
}
```

2. **Create Governance Proposal**: Submit proposal to Parliament to call `TokenHolderContract.ChangeMethodFeeController` with:
```csharp
new AuthorityInfo
{
    ContractAddress = MaliciousAuthContractAddress,
    OwnerAddress = AttackerAddress
}
```

3. **Pass Proposal**: Approve and release proposal through Parliament

4. **Verify Bypass**: Call `TokenHolderContract.SetMethodFee` directly with AttackerAddress as sender (no governance required)

**Expected Result**: Transaction should fail due to invalid authorization contract address

**Actual Result**: Transaction succeeds; attacker gains permanent unilateral control over method fees, bypassing all governance mechanisms

**Success Condition**: Attacker can repeatedly call `SetMethodFee` directly without any governance approval, with changes persisting across blocks.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L11-20)
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L22-30)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L71-76)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L61-73)
```csharp
    public override Empty ChangeCrossChainIndexingController(AuthorityInfo input)
    {
        AssertCrossChainIndexingControllerAuthority(Context.Sender);
        SetContractStateRequired(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
        Assert(
            input.ContractAddress == State.ParliamentContract.Value &&
            ValidateParliamentOrganization(input.OwnerAddress), "Invalid authority input.");
        State.CrossChainIndexingController.Value = input;
        Context.Fire(new CrossChainIndexingControllerChanged
        {
            AuthorityInfo = input
        });
        return new Empty();
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L309-315)
```csharp
    public override Address DeploySmartContract(ContractDeploymentInput input)
    {
        RequireSenderAuthority(State.CodeCheckController.Value?.OwnerAddress);
        // AssertDeploymentProposerAuthority(Context.Origin);

        var inputHash = CalculateHashFromInput(input);
        TryClearContractProposingData(inputHash, out var contractProposingInput);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L96-105)
```csharp
    public override Address CreateOrganizationBySystemContract(CreateOrganizationBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to create organization.");
        var organizationAddress = CreateOrganization(input.OrganizationCreationInput);
        if (!string.IsNullOrEmpty(input.OrganizationAddressFeedbackMethod))
            Context.SendInline(Context.Sender, input.OrganizationAddressFeedbackMethod, organizationAddress);

        return organizationAddress;
    }
```
