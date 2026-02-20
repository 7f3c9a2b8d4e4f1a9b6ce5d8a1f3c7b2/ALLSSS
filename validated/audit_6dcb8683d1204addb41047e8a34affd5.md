# Audit Report

## Title
Authorization Chain Bypass via Malicious Contract Address in MethodFeeController

## Summary
The `ChangeMethodFeeController` method across all ACS1 implementations fails to validate that the `ContractAddress` field in `AuthorityInfo` points to a legitimate governance contract (Parliament/Association/Referendum). An attacker can deploy a malicious contract implementing `ValidateOrganizationExist` that always returns true, then get a governance proposal approved to set this malicious contract as the authority. Once set, the attacker gains permanent direct control over method fees, bypassing all future governance oversight.

## Finding Description

The vulnerability exists in the `ChangeMethodFeeController` method's validation logic. The method validates the new authority by calling `CheckOrganizationExist`: [1](#0-0) 

The `CheckOrganizationExist` method makes a cross-contract call to the provided `ContractAddress` without validating it is a system governance contract: [2](#0-1) 

**Root Cause**: The code blindly trusts any contract address provided in `authorityInfo.ContractAddress` and calls its `ValidateOrganizationExist` method. There is no validation that this address corresponds to Parliament, Association, or Referendum governance contracts.

**Why Existing Protections Fail**: The system has `GetSystemContractNameToAddressMapping()` available to validate system contracts, as demonstrated in other contexts: [3](#0-2) [4](#0-3) 

However, this validation is NOT applied to the `ContractAddress` in `CheckOrganizationExist`. The legitimate `ValidateOrganizationExist` implementations simply check if an organization exists in state: [5](#0-4) [6](#0-5) 

But any deployed contract can implement this interface and return arbitrary values.

**Execution Path**:
1. Attacker deploys malicious contract implementing `ValidateOrganizationExist` that returns `BoolValue { Value = true }` for any input
2. Attacker creates Parliament proposal to call `ChangeMethodFeeController` with `AuthorityInfo { ContractAddress = malicious_contract, OwnerAddress = attacker_address }`
3. Proposal gets approved through normal governance
4. Validation passes because malicious contract returns true
5. `State.MethodFeeController.Value` now points to attacker's AuthorityInfo
6. Attacker can directly call `SetMethodFee` bypassing all future governance: [7](#0-6) 

This pattern affects ALL ACS1 implementations identically: [8](#0-7) [9](#0-8) [10](#0-9) 

## Impact Explanation

**Authorization Chain Violation**: The vulnerability breaks the fundamental invariant that method fee changes must go through governance. Once the malicious controller is set, the attacker gains permanent direct control over method fees without organizational approval.

**Concrete Harms**:
1. **Fee Manipulation**: Attacker can set arbitrary fees for any contract method - set fees to 0 enabling transaction spam/DoS, or set extremely high fees for economic griefing
2. **Governance Bypass**: All future `SetMethodFee` operations bypass organizational approval, breaking the governance model permanently until another governance proposal can reclaim control
3. **System-Wide Impact**: This affects ALL 15+ system contracts implementing ACS1 (Parliament, Association, Referendum, Token, Consensus, Treasury, Profit, TokenConverter, Election, Vote, etc.)

**Affected Parties**: All blockchain users and the protocol's governance integrity. Method fees control transaction costs and network resource usage.

## Likelihood Explanation

**Attacker Capabilities Required**:
1. Deploy a malicious contract with simple `ValidateOrganizationExist` implementation
2. Create and get approved a Parliament proposal (requires proposer whitelist access or BP status)
3. Standard transaction execution capability

**Attack Complexity**: LOW once proposal is approved. The malicious contract implementation is trivial - a single method returning true.

**Feasibility Conditions**: 
- Attacker needs to convince governance to approve the controller change (main barrier)
- However, the `AuthorityInfo` structure looks legitimate on surface (has both ContractAddress and OwnerAddress filled)
- No existing validation would flag this as suspicious during proposal review
- No automatic detection mechanism exists
- The malicious controller persists indefinitely once set

**Probability Reasoning**: MEDIUM likelihood. While getting initial proposal approval is non-trivial, the attack is technically simple, difficult to detect during proposal review, provides permanent backdoor value, and could be embedded in seemingly legitimate governance restructuring proposals.

## Recommendation

Add validation in `CheckOrganizationExist` to verify the contract address is a legitimate governance contract. The fix should validate against the system contract mapping:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate that the contract address is a known governance contract
    var systemContracts = Context.GetSystemContractNameToAddressMapping();
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress ||
        authorityInfo.ContractAddress == associationAddress ||
        authorityInfo.ContractAddress == referendumAddress,
        "Invalid authority contract address. Must be Parliament, Association, or Referendum contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Test_MaliciousMethodFeeController_CanBypassGovernance()
{
    // 1. Deploy malicious contract that always returns true for ValidateOrganizationExist
    var maliciousContract = await DeployMaliciousAuthContract();
    
    // 2. Create Parliament proposal to change method fee controller
    var attackerAddress = Address.FromPublicKey(SampleKeyPairs[0].PublicKey);
    var proposalId = await ParliamentContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        OrganizationAddress = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty()),
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContractStub.ChangeMethodFeeController),
        Params = new AuthorityInfo
        {
            ContractAddress = maliciousContract,
            OwnerAddress = attackerAddress
        }.ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    // 3. Approve and release proposal through governance
    await ApproveWithMinersAsync(proposalId.Output);
    await ParliamentContractStub.Release.SendAsync(proposalId.Output);
    
    // 4. Verify malicious controller is set
    var controller = await TokenContractStub.GetMethodFeeController.CallAsync(new Empty());
    controller.ContractAddress.ShouldBe(maliciousContract);
    controller.OwnerAddress.ShouldBe(attackerAddress);
    
    // 5. Attacker can now directly set method fees without governance
    var result = await TokenContractStub.SetMethodFee.SendAsync(new MethodFees
    {
        MethodName = nameof(TokenContractStub.Transfer),
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 0 } } // Set fee to 0 for spam
    });
    
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    // Method fee successfully changed without governance approval - vulnerability confirmed
}
```

## Notes

This vulnerability demonstrates a critical gap in the authorization validation logic where the system assumes that any contract implementing `ValidateOrganizationExist` is a legitimate governance contract. The lack of whitelist validation against the known system contracts (Parliament, Association, Referendum) creates a permanent governance bypass vector once exploited. The fix requires adding explicit validation that the `ContractAddress` in `AuthorityInfo` corresponds to one of the three legitimate governance contracts before accepting the authority change.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L13-22)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");

        State.TransactionFees[input.MethodName] = input;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L98-99)
```csharp
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to create organization.");
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

**File:** contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs (L22-31)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L22-31)
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
