# Audit Report

## Title
Method Fee Controller Validation Bypass Through Malicious Contract Address

## Summary
The `CheckOrganizationExist` function in ACS1 implementations across multiple system contracts fails to validate that the `ContractAddress` in `AuthorityInfo` is a legitimate governance contract (Parliament/Association/Referendum). This allows an attacker with temporary method fee controller access to permanently bypass governance by registering a malicious contract that always validates any address as a valid organization.

## Finding Description

The vulnerability exists in the `CheckOrganizationExist` helper function used by all ACS1-implementing contracts when validating authority changes during `ChangeMethodFeeController` operations. [1](#0-0) 

This function makes a cross-contract call to the arbitrary address specified in `authorityInfo.ContractAddress` to invoke `ValidateOrganizationExist`, without verifying that this address corresponds to a legitimate governance contract. The same vulnerable pattern exists across all system contracts: [2](#0-1) [3](#0-2) [4](#0-3) 

**Root Cause**: The validation assumes all contracts implementing `ValidateOrganizationExist` will behave honestly. Legitimate governance contracts properly validate against their internal state: [5](#0-4) [6](#0-5) 

However, a malicious contract can bypass this by implementing `ValidateOrganizationExist` to unconditionally return `true`, allowing any address (including non-organization regular EOAs) to pass validation.

**Exploitation Mechanism**:

1. Attacker gains temporary control of MethodFeeController through governance (e.g., Parliament proposal requiring 2/3 miner approval)
2. Attacker deploys a malicious contract with: `ValidateOrganizationExist(Address) => return new BoolValue { Value = true }`
3. Attacker calls `ChangeMethodFeeController` with `AuthorityInfo { OwnerAddress: AttackerEOA, ContractAddress: MaliciousContract }`
4. `CheckOrganizationExist` calls the malicious contract, which returns `true`
5. Validation passes at: [7](#0-6) 

6. New controller is permanently set with attacker's EOA as `OwnerAddress`

Subsequently, when `SetMethodFee` is called: [8](#0-7) 

The attacker can call this method directly from their EOA without any governance approval, permanently bypassing the requirement for Parliament proposals, miner votes, and release mechanisms.

**Why This is Mis-Scoped Privilege (Not Threat Model Violation)**: While the attack requires initial governance access, the vulnerability is in the CODE'S failure to validate contract addresses. The system should enforce defense-in-depth by restricting `ContractAddress` to known governance contracts obtainable via `Context.GetContractAddressByName()` for Parliament, Association, and Referendum. The current implementation grants broader privileges (any contract) than intended (only governance contracts), making this a validation failure rather than an assumption about governance honesty.

## Impact Explanation

**Governance Invariant Violation**: The fundamental invariant "method fee changes require governance approval" is permanently broken. Normal method fee changes require creating a proposal, obtaining 2/3 miner approval, and executing through the governance organization. After this attack, the attacker controls method fees unilaterally.

**Operational Impact**:
- **DoS Attack**: Attacker can set arbitrarily high method fees (e.g., 1000000 ELF per transaction), making the Parliament contract economically unusable for all users
- **Spam Attack**: Attacker can set zero fees, enabling spam attacks that exhaust network resources
- **Scope**: Affects all users of the targeted contract system-wide
- **Persistence**: Unlike temporary governance compromise, this provides permanent control that survives even if the attacker loses their original governance access

**Cross-Contract Impact**: All ACS1-implementing system contracts share this pattern: [9](#0-8) 

This includes Parliament, Association, Referendum, Configuration, Economic, Election, MultiToken, Cross-Chain, Treasury, Profit, Vote, and TokenConverter contracts, making the attack surface extensive.

## Likelihood Explanation

**Barrier to Entry**: HIGH - Requires temporary control of the current MethodFeeController, typically obtained through:
- Parliament governance compromise (2/3 miner approval)
- Exploiting a separate governance vulnerability  
- Social engineering governance participants

**Attack Complexity**: MODERATE once initial access is achieved:
1. Deploy malicious contract (straightforward implementation)
2. Submit governance proposal to change controller (single transaction)
3. Execute after approval (single transaction)

**Why This Matters Despite High Barrier**: The vulnerability converts temporary governance access into permanent control. Even if governance participants realize the error and revoke the attacker's original access, the attacker retains unilateral method fee control indefinitely. This persistence multiplies the impact of any governance compromise.

**Detection Difficulty**: The malicious controller change appears as a legitimate governance decision in on-chain records. Only post-compromise monitoring of unusual method fee patterns would reveal the attack.

**Test Coverage Gap**: Existing tests validate against legitimate governance contracts but don't cover malicious contract scenarios: [10](#0-9) 

This test validates that invalid organization addresses are rejected when using legitimate governance contracts, but doesn't test the scenario where `ContractAddress` itself is malicious.

## Recommendation

Add validation in `CheckOrganizationExist` to verify that `authorityInfo.ContractAddress` is one of the known governance contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate that ContractAddress is a legitimate governance contract
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress || 
        authorityInfo.ContractAddress == associationAddress || 
        authorityInfo.ContractAddress == referendumAddress,
        "Invalid governance contract address.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
}
```

This defense-in-depth approach ensures that even if governance is temporarily compromised, only legitimate governance organizations can be set as method fee controllers. Apply this fix to all ACS1 implementations across the codebase.

## Proof of Concept

```csharp
[Fact]
public async Task MethodFeeController_MaliciousContract_Bypass()
{
    // Step 1: Deploy malicious contract that always validates
    var maliciousContractCode = CompileMaliciousContract(); // Returns true for any ValidateOrganizationExist call
    var maliciousAddress = await DeployContractAsync(maliciousContractCode);
    
    // Step 2: Get current controller (requires governance to execute)
    var currentController = await ParliamentContractStub.GetMethodFeeController.CallAsync(new Empty());
    
    // Step 3: Create proposal to change to malicious controller
    var attackerEOA = Address.FromPublicKey(SampleKeyPairs[4].PublicKey);
    var proposalId = await CreateProposalAsync(
        currentController.OwnerAddress,
        nameof(ParliamentContractStub.ChangeMethodFeeController),
        new AuthorityInfo
        {
            OwnerAddress = attackerEOA,  // Regular EOA, not an organization
            ContractAddress = maliciousAddress  // Malicious contract
        });
    
    // Step 4: Approve with 2/3 miners (simulating governance compromise)
    await ApproveWithMinersAsync(proposalId);
    
    // Step 5: Release proposal - validation passes!
    var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 6: Verify attacker now has direct control
    var newController = await ParliamentContractStub.GetMethodFeeController.CallAsync(new Empty());
    newController.OwnerAddress.ShouldBe(attackerEOA);
    newController.ContractAddress.ShouldBe(maliciousAddress);
    
    // Step 7: Attacker sets fees directly WITHOUT governance
    var attackerStub = GetParliamentContractTester(SampleKeyPairs[4]);
    var setFeeResult = await attackerStub.SetMethodFee.SendAsync(new MethodFees
    {
        MethodName = nameof(ParliamentContractStub.CreateProposal),
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 1000000_00000000 } }  // DoS fees
    });
    
    // Attack succeeds - no governance required!
    setFeeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

### Citations

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L1-92)
```csharp
using AElf.Sdk.CSharp;
using AElf.Standards.ACS1;
using AElf.Types;
using Google.Protobuf.WellKnownTypes;

namespace AElf.Contracts.Parliament;

public partial class ParliamentContract
{
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }

    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }

    #region Views

    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(ApproveMultiProposals))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };

        return State.TransactionFees[input.Value];
    }

    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        RequiredMethodFeeControllerSet();
        return State.MethodFeeController.Value;
    }

    #endregion

    #region private methods

    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }

    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.DefaultOrganizationAddress.Value,
            ContractAddress = Context.Self
        };

        State.MethodFeeController.Value = defaultAuthority;
    }

    private void AssertSenderAddressWith(Address address)
    {
        Assert(Context.Sender == address, "Unauthorized behavior.");
    }

    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
    }

    #endregion
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L116-121)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
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

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L1011-1034)
```csharp
    public async Task ChangeMethodFeeController_With_Invalid_Authority_Test()
    {
        // await InitializeParliamentContracts();
        var parliamentContractStub = GetParliamentContractTester(InitialMinersKeyPairs[0]);


        var methodFeeController = await parliamentContractStub.GetMethodFeeController.CallAsync(new Empty());
        var defaultOrganization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        methodFeeController.OwnerAddress.ShouldBe(defaultOrganization);

        const string proposalCreationMethodName = nameof(parliamentContractStub.ChangeMethodFeeController);
        var proposalId = await CreateFeeProposalAsync(ParliamentContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName, new AuthorityInfo
            {
                OwnerAddress = ParliamentContractAddress,
                ContractAddress = ParliamentContractAddress
            });
        await ApproveAsync(InitialMinersKeyPairs[0], proposalId);
        await ApproveAsync(InitialMinersKeyPairs[1], proposalId);
        await ApproveAsync(InitialMinersKeyPairs[2], proposalId);

        var releaseResult = await parliamentContractStub.Release.SendWithExceptionAsync(proposalId);
        releaseResult.TransactionResult.Error.ShouldContain("Invalid authority input");
    }
```
