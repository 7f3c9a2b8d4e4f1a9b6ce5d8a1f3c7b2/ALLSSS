### Title
Arbitrary Contract Trust in Authority Validation Allows Permanent Governance Bypass

### Summary
The `CheckOrganizationExist` function trusts arbitrary contract addresses provided in `AuthorityInfo` to implement `ValidateOrganizationExist` correctly, without validating that the contract is a legitimate governance contract (Parliament, Association, or Referendum). This allows a temporarily compromised governance to permanently bypass multi-sig governance requirements by installing a malicious validation contract that always returns true, converting the method fee controller from a multi-sig organization to a single attacker-controlled address.

### Finding Description

The vulnerability exists in the `CheckOrganizationExist` method across multiple system contracts: [1](#0-0) 

This same pattern is replicated in Parliament, Association, and Genesis contracts: [2](#0-1) [3](#0-2) [4](#0-3) 

The function is called during controller changes to validate the new authority: [5](#0-4) 

**Root Cause:** The `authorityInfo.ContractAddress` field is provided by the caller without validation. The system makes a cross-contract call to this arbitrary address, trusting it to correctly implement `ValidateOrganizationExist`. There is no whitelist check against legitimate governance contracts.

The legitimate governance contracts are defined as system contracts: [6](#0-5) 

However, `CheckOrganizationExist` does not validate that `ContractAddress` matches one of these system contracts, despite the system having the capability to do so via `GetSystemContractNameToAddressMapping()`.

**Why Existing Protections Fail:**
1. The sender authorization check only validates that the caller is the CURRENT controller owner, not that the NEW controller is legitimate
2. The `ValidateOrganizationExist` call can be to any contract address
3. No validation exists to ensure the governance contract is a recognized system contract (Parliament/Association/Referendum)
4. Test coverage only validates non-existent organizations, not malicious contract validation [7](#0-6) 

### Impact Explanation

**Direct Governance Impact:**
- Converts multi-sig governance controller into single-address controller
- Permanently removes governance requirements for method fee changes
- Single attacker gains unrestricted ability to manipulate method fees system-wide

**Concrete Harm:**
1. **Transaction Fee Revenue Loss**: Attacker can set fees to 0, draining protocol revenue
2. **Denial of Service**: Can set fees to extreme values (e.g., 10^18), making critical methods unusable
3. **User Discrimination**: Selective fee manipulation to favor/harm specific addresses or methods
4. **Governance Integrity**: Violates the fundamental invariant that method fee controllers are always legitimate governance organizations [8](#0-7) 

**Who Is Affected:** All system contracts using ACS1 method fee providers (Referendum, Parliament, Association, Genesis, MultiToken, Consensus, CrossChain, etc.)

**Severity Justification:** HIGH - While initial attack requires governance control, it permanently escalates temporary compromise into unrestricted control, fundamentally breaking the governance security model.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must control current method fee controller (typically Parliament's default organization, requiring miner consensus)
- Ability to deploy a malicious contract

**Attack Complexity:** LOW
1. Deploy trivial malicious contract with `ValidateOrganizationExist` returning `true`
2. Create governance proposal to call `ChangeMethodFeeController` with malicious `ContractAddress`
3. Approve through current governance (if compromised)
4. Gain permanent single-address control

**Feasibility Conditions:**
- Temporary governance compromise (e.g., miner collusion, key theft)
- OR insider attack by governance participants
- Attack is undetectable during proposal review (malicious contract address not obviously invalid)

**Economic Rationality:**
- Minimal cost (single contract deployment + proposal fees)
- Maximum benefit (permanent unrestricted control vs repeated proposals)
- High incentive for temporarily compromised governance to make breach permanent

**Key Distinction:** Even if governance is trusted initially, this vulnerability converts a SINGLE compromised governance action into PERMANENT bypass. Each subsequent fee change should require governance approval, but after this attack, none do.

### Recommendation

**Immediate Fix:** Add whitelist validation for governance contract addresses in `CheckOrganizationExist`:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate ContractAddress is a legitimate governance contract
    var isParliament = authorityInfo.ContractAddress == 
        Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var isAssociation = authorityInfo.ContractAddress == 
        Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var isReferendum = authorityInfo.ContractAddress == 
        Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(isParliament || isAssociation || isReferendum, 
        "ContractAddress must be a legitimate governance contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
}
```

**Apply to all affected contracts:**
- ReferendumContract_ACS1_TransactionFeeProvider.cs
- ParliamentContract_ACS1_TransactionFeeProvider.cs  
- AssociationContract_ACS1_TransactionFeeProvider.cs
- BasicContractZero_Helper.cs (for ChangeContractDeploymentController and ChangeCodeCheckController)
- All other *_ACS1_TransactionFeeProvider.cs files

**Test Cases to Add:**
1. Attempt `ChangeMethodFeeController` with non-system contract address → should fail
2. Attempt with user-deployed contract implementing `ValidateOrganizationExist` → should fail
3. Only Parliament/Association/Referendum addresses should succeed

### Proof of Concept

**Initial State:**
- Referendum contract deployed with default method fee controller = Parliament default organization
- Miners control Parliament default organization (legitimate governance)

**Attack Steps:**

1. **Deploy Malicious Contract:**
```csharp
// MaliciousValidator.cs
public override BoolValue ValidateOrganizationExist(Address input)
{
    return new BoolValue { Value = true }; // Always returns true
}
```

2. **Create Governance Proposal:**
    - Parliament miners create proposal calling `ReferendumContract.ChangeMethodFeeController`
    - Input: `AuthorityInfo { OwnerAddress = AttackerAddress, ContractAddress = MaliciousValidatorAddress }`
    - Approve through current governance (miners collude or are compromised)

3. **Execute Attack:**
    - Proposal is released
    - `ChangeMethodFeeController` calls `CheckOrganizationExist`
    - `CheckOrganizationExist` calls `MaliciousValidator.ValidateOrganizationExist(AttackerAddress)`
    - Returns `true` despite AttackerAddress not being a real organization
    - Validation passes: "Invalid authority input" check succeeds
    - `State.MethodFeeController.Value` updated to `{ OwnerAddress = AttackerAddress, ContractAddress = MaliciousValidatorAddress }`

**Post-Attack State:**
- Method fee controller is now single `AttackerAddress`
- Attacker can call `SetMethodFee` directly without any governance approval
- All future fee changes require only attacker's signature, bypassing multi-sig governance permanently

**Success Condition:** 
- `GetMethodFeeController()` returns `OwnerAddress = AttackerAddress` 
- `SetMethodFee` succeeds with sender = AttackerAddress (no proposal needed)
- Arbitrary fees can be set (0 for revenue loss, or extremely high for DoS)

### Citations

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L10-19)
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

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L70-74)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L70-74)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
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

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L918-931)
```csharp
    public async Task ChangeMethodFeeController_With_Invalid_Organization_Test()
    {
        var methodFeeController = await ReferendumContractStub.GetMethodFeeController.CallAsync(new Empty());
        var proposalId = await CreateFeeProposalAsync(ReferendumContractAddress,
            methodFeeController.OwnerAddress, nameof(ReferendumContractStub.ChangeMethodFeeController),
            new AuthorityInfo
            {
                OwnerAddress = TokenContractAddress,
                ContractAddress = ParliamentContractAddress
            });
        await ApproveWithMinersAsync(proposalId);
        var ret = await ParliamentContractStub.Release.SendWithExceptionAsync(proposalId);
        ret.TransactionResult.Error.ShouldContain("Invalid authority input");
    }
```
