# Audit Report

## Title
Insufficient Contract Type Validation in CheckOrganizationExist Allows Permanent Method Fee Controller Takeover

## Summary

The Genesis contract's `ChangeMethodFeeController` method accepts arbitrary contract addresses without validating they are legitimate organization contracts (Parliament/Association/Referendum). An attacker can deploy a malicious contract that always returns `true` for `ValidateOrganizationExist`, then pass a single Parliament proposal to install it as the method fee controller, gaining permanent unilateral control over Genesis contract method fees without further governance oversight.

## Finding Description

The vulnerability exists in the interaction between `ChangeMethodFeeController` and `CheckOrganizationExist`.

**Root Cause:**

The `CheckOrganizationExist` helper performs a cross-contract call to `ValidateOrganizationExist` on whatever contract address is provided in `AuthorityInfo.ContractAddress`, without any validation that this contract is a legitimate organization contract. [1](#0-0) 

The method simply calls the provided contract address and trusts its response, with no verification that the address corresponds to Parliament, Association, or Referendum contracts.

**Exploitation Path:**

1. **Deploy Malicious Contract:** On main/public chains, user contract deployment is permissionless when the native symbol matches the primary token symbol. [2](#0-1)  An attacker deploys a contract with a `ValidateOrganizationExist` method that always returns `true`, mimicking the legitimate implementation [3](#0-2)  but without actual state checks.

2. **Create Parliament Proposal:** Attacker creates a proposal to call `ChangeMethodFeeController` with `AuthorityInfo` containing their controlled address as `OwnerAddress` and the malicious contract address as `ContractAddress`.

3. **Proposal Execution:** When approved and released by Parliament, the sender becomes the Parliament organization address, passing the authorization check. [4](#0-3)  The malicious contract's `ValidateOrganizationExist` returns `true`, satisfying the validation requirement, and the controller is updated.

4. **Post-Exploit:** The attacker can directly call `SetMethodFee` [5](#0-4) , which only verifies that the sender matches the controller's `OwnerAddress`.

**Why Existing Protections Fail:**

The test suite validates organization existence but never validates contract address legitimacy. All tests use legitimate system contract addresses (Parliament or Association), missing this attack vector entirely. [6](#0-5) 

## Impact Explanation

**Governance Impact:**
The attacker achieves permanent privilege escalation from "must pass Parliament proposals for each fee change" to "can change fees unilaterally at will." This completely bypasses the intended governance oversight mechanism embedded in the ACS1 standard.

**Denial of Service:**
The attacker can set prohibitively high fees for critical Genesis contract methods including `DeploySmartContract`, `UpdateSmartContract`, `ProposeNewContract`, `ProposeUpdateContract`, `ReleaseApprovedContract`, and `ReleaseCodeCheckedContract`. This effectively halts the entire smart contract deployment and upgrade system for the chain, constituting a chain-level DoS attack.

**Economic Manipulation:**
- Setting zero fees bypasses intended economic controls
- Discriminatory fee structures can favor/harm specific users
- Fee extraction through manipulated pricing

**Severity Justification:**
HIGH severity due to: (1) Permanent governance bypass violating critical security invariants, (2) Chain-level DoS capability affecting all participants, (3) Economic manipulation potential, (4) Requires only ONE successful proposal for lasting damage.

## Likelihood Explanation

**Attacker Requirements:**
- Deploy a user contract (permissionless on main/public side chains where native symbol matches primary token)
- Pass ONE Parliament proposal (requires 2/3 miner approval)

**Attack Complexity:**
LOW - The malicious contract is trivial (single method returning `true`). The proposal parameters are complex enough to obscure intent from voters who would need to inspect the target contract code, recognize it's not a legitimate organization contract, and understand the privilege escalation implications.

**Feasibility:**
While passing a Parliament proposal requires 2/3 miner approval (a high bar), this is feasible during governance inattention, rushed voting periods, or coordinated attacks. The one-time nature (only need one successful proposal ever) significantly increases overall risk compared to attacks requiring repeated governance actions.

**Economic Rationality:**
The cost is minimal (contract deployment + political capital for one proposal), while the benefit is permanent control over fee structures with significant economic advantage and/or DoS capability.

## Recommendation

Add validation in `CheckOrganizationExist` to verify that `AuthorityInfo.ContractAddress` is one of the three legitimate organization contracts. This can be done by:

1. Retrieving the system contract addresses for Parliament, Association, and Referendum using `Context.GetContractAddressByName()`
2. Validating that the provided `ContractAddress` matches one of these three addresses
3. Only then proceeding with the `ValidateOrganizationExist` call

Additionally, similar validation should be added to `ChangeContractDeploymentController` and `ChangeCodeCheckController` methods which use the same vulnerable pattern.

## Proof of Concept

A malicious contract would implement:

```csharp
public override BoolValue ValidateOrganizationExist(Address input)
{
    return new BoolValue { Value = true };  // Always returns true
}
```

Once deployed, an attacker creates a Parliament proposal calling `ChangeMethodFeeController` with:
- `AuthorityInfo.OwnerAddress` = attacker's address
- `AuthorityInfo.ContractAddress` = malicious contract address

After the proposal is approved and released, the attacker can directly call `SetMethodFee` without any governance oversight, as the only check is that `Context.Sender == State.MethodFeeController.Value.OwnerAddress`, which now points to the attacker's address.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L180-185)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L344-357)
```csharp
    private void AssertUserDeployContract()
    {
        // Only the symbol of main chain or public side chain is native symbol.
        RequireTokenContractContractAddressSet();
        var primaryTokenSymbol = State.TokenContract.GetPrimaryTokenSymbol.Call(new Empty()).Value;
        if (Context.Variables.NativeSymbol == primaryTokenSymbol)
        {
            return;
        }

        RequireParliamentContractAddressSet();
        var whitelist = State.ParliamentContract.GetProposerWhiteList.Call(new Empty());
        Assert(whitelist.Proposers.Contains(Context.Sender), "No permission.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L9-19)
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L1207-1315)
```csharp
    [Fact]
    public async Task ChangeMethodFeeController_Test()
    {
        var createOrganizationResult = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateOrganization),
            new CreateOrganizationInput
            {
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = 1000,
                    MinimalVoteThreshold = 1000
                }
            });

        var organizationAddress = Address.Parser.ParseFrom(createOrganizationResult.ReturnValue);

        var methodFeeController = await GetMethodFeeController(Tester, BasicContractZeroAddress);
        const string proposalCreationMethodName =
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.ChangeMethodFeeController);
        var proposalId = await CreateProposalAsync(Tester, methodFeeController.ContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName,
            new AuthorityInfo
            {
                OwnerAddress = organizationAddress,
                ContractAddress = ParliamentAddress
            });
        await ApproveWithMinersAsync(Tester, ParliamentAddress, proposalId);
        var txResult2 = await ReleaseProposalAsync(Tester, ParliamentAddress, proposalId);
        txResult2.Status.ShouldBe(TransactionResultStatus.Mined);

        var newMethodFeeController = await GetMethodFeeController(Tester, BasicContractZeroAddress);
        Assert.True(newMethodFeeController.OwnerAddress == organizationAddress);
    }

    [Fact]
    public async Task ChangeMethodFeeController_WithoutAuth_Test()
    {
        var result = await Tester.ExecuteContractWithMiningAsync(BasicContractZeroAddress,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.ChangeMethodFeeController),
            new AuthorityInfo
            {
                OwnerAddress = Tester.GetCallOwnerAddress(),
                ContractAddress = ParliamentAddress
            });

        result.Status.ShouldBe(TransactionResultStatus.Failed);
        result.Error.Contains("Unauthorized behavior.").ShouldBeTrue();

        // Invalid organization address
        var methodFeeController = await GetMethodFeeController(Tester, BasicContractZeroAddress);
        const string proposalCreationMethodName =
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.ChangeMethodFeeController);
        var proposalId = await CreateProposalAsync(Tester, methodFeeController.ContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName,
            new AuthorityInfo
            {
                OwnerAddress = SampleAddress.AddressList[4],
                ContractAddress = ParliamentAddress
            });
        await ApproveWithMinersAsync(Tester, ParliamentAddress, proposalId);
        var txResult2 = await ReleaseProposalAsync(Tester, ParliamentAddress, proposalId);
        txResult2.Status.ShouldBe(TransactionResultStatus.Failed);
        txResult2.Error.Contains("Invalid authority input.").ShouldBeTrue();
    }

    [Fact]
    public async Task ChangeMethodFeeControllerByAssociation_Test()
    {
        var createOrganizationResult = await Tester.ExecuteContractWithMiningAsync(AssociationContractAddress,
            nameof(AssociationContractImplContainer.AssociationContractImplStub.CreateOrganization),
            new Association.CreateOrganizationInput
            {
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = 1,
                    MinimalVoteThreshold = 1
                },
                ProposerWhiteList = new ProposerWhiteList
                {
                    Proposers = { AnotherMinerAddress }
                },
                OrganizationMemberList = new OrganizationMemberList
                {
                    OrganizationMembers = { AnotherMinerAddress }
                }
            });

        var organizationAddress = Address.Parser.ParseFrom(createOrganizationResult.ReturnValue);

        var methodFeeController = await GetMethodFeeController(Tester, BasicContractZeroAddress);
        const string proposalCreationMethodName =
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.ChangeMethodFeeController);
        var proposalId = await CreateProposalAsync(Tester, methodFeeController.ContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName,
            new AuthorityInfo
            {
                OwnerAddress = organizationAddress,
                ContractAddress = AssociationContractAddress
            });
        await ApproveWithMinersAsync(Tester, ParliamentAddress, proposalId);
        var txResult2 = await ReleaseProposalAsync(Tester, ParliamentAddress, proposalId);
        txResult2.Status.ShouldBe(TransactionResultStatus.Mined);

        var methodFeeControllerAfterChange =
            await GetMethodFeeController(Tester, BasicContractZeroAddress);

        methodFeeControllerAfterChange.ContractAddress.ShouldBe(AssociationContractAddress);
        methodFeeControllerAfterChange.OwnerAddress.ShouldBe(organizationAddress);
    }
```
