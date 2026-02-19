### Title
Method Fee Controller Validation Bypass Through Malicious Contract Address

### Summary
The `CheckOrganizationExist` function in `ChangeMethodFeeController` only validates that the `OwnerAddress` exists in the contract specified by `ContractAddress`, without verifying that `ContractAddress` itself is a legitimate governance contract. An attacker who controls the current MethodFeeController can change it to use a malicious contract that always returns true for organization validation, paired with a regular address as `OwnerAddress`, enabling permanent method fee control without governance oversight.

### Finding Description

The vulnerability exists in the `CheckOrganizationExist` function which validates the new authority during method fee controller changes: [1](#0-0) 

This function makes a cross-contract call to `authorityInfo.ContractAddress` to invoke `ValidateOrganizationExist`, but performs no validation that `ContractAddress` is one of the legitimate governance contracts (Parliament, Association, or Referendum) or even a system contract.

The `ChangeMethodFeeController` method uses this validation: [2](#0-1) 

The `AuthorityInfo` structure is defined as: [3](#0-2) 

**Root Cause**: The validation assumes all contracts implementing `ValidateOrganizationExist` (part of ACS3 standard) will behave honestly. However, a malicious contract can implement this method to always return true, regardless of input. [4](#0-3) 

**Why Protection Fails**: Legitimate governance contracts like Parliament check their state: [5](#0-4) 

But a malicious contract can bypass this by always returning `true`, allowing any address (including non-organization regular addresses) to pass validation.

**Exploitation Path**:
1. Attacker gains control of MethodFeeController through legitimate governance (e.g., Parliament votes)
2. Attacker deploys MaliciousContract with `ValidateOrganizationExist` that always returns true
3. Attacker creates governance proposal to call `ChangeMethodFeeController` with `AuthorityInfo{OwnerAddress: AttackerControlledAddress, ContractAddress: MaliciousContract}`
4. Validation passes because MaliciousContract returns true for any address
5. New controller is set with a regular address (not an organization) as OwnerAddress

Now when `SetMethodFee` is called, it only checks: [6](#0-5) 

The attacker can call this directly from their personal address without governance approval.

### Impact Explanation

**Governance Invariant Violation**: The critical invariant "Authorization & Governance - method-fee provider authority" is permanently broken. Method fees should always require governance approval, but the attacker gains direct control.

**Operational Impact**: 
- Attacker can set arbitrary method fees for all Parliament contract methods
- High fees cause DoS by making the contract economically unusable
- Zero fees enable spam attacks and resource exhaustion
- Affects all users of the Parliament contract system-wide

**Persistence**: Unlike temporary governance compromise, this attack provides permanent control that persists even if the attacker loses the original governance organization. The attacker maintains unilateral method fee control indefinitely.

**Severity**: Medium-High. While initial governance compromise is required (high barrier), the attack enables permanent governance bypass, which is a critical violation of the authorization model. All ACS1-implementing contracts share this pattern and are similarly vulnerable. [7](#0-6) 

### Likelihood Explanation

**Attacker Capabilities**: Requires temporary control of the current MethodFeeController, typically through:
- Compromising Parliament governance (requires 2/3 miner approval)
- Exploiting a separate governance vulnerability
- Social engineering governance participants

**Attack Complexity**: Moderate once governance control is achieved:
1. Deploy malicious contract (simple implementation)
2. Create and pass governance proposal (requires existing control)
3. Execute the controller change (single transaction)

**Feasibility**: The attack is technically feasible and executable within AElf's contract execution model. The test suite demonstrates the expected validation behavior but doesn't cover malicious contract scenarios: [8](#0-7) 

This test only validates against legitimate contracts where `ValidateOrganizationExist` behaves correctly.

**Detection**: Difficult to detect proactively since the malicious contract change appears as a legitimate governance decision. Post-compromise detection would require monitoring for unusual method fee patterns.

**Economic Rationality**: High value for attackers who have temporarily compromised governance, as it allows them to maintain control permanently and potentially extract ongoing value or disrupt the protocol.

### Recommendation

**Immediate Fix**: Add validation to ensure `ContractAddress` is one of the legitimate system governance contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate ContractAddress is a legitimate governance contract
    RequireParliamentContractAddressSet();
    RequireAssociationContractAddressSet();
    RequireReferendumContractAddressSet();
    
    Assert(
        authorityInfo.ContractAddress == State.ParliamentContract.Value ||
        authorityInfo.ContractAddress == State.AssociationContract.Value ||
        authorityInfo.ContractAddress == State.ReferendumContract.Value,
        "Invalid governance contract address.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
}
```

**Additional Checks**:
1. Add helper methods to get and cache governance contract addresses
2. Verify organization addresses are valid virtual addresses (not regular EOAs)
3. Document the expected AuthorityInfo structure constraints

**Test Cases to Add**:
1. Test `ChangeMethodFeeController` with non-governance contract address (should fail)
2. Test with malicious contract returning true (should fail)
3. Test with regular address as OwnerAddress (should fail)
4. Test with valid Parliament/Association/Referendum organizations (should succeed)

**Apply Pattern Consistently**: This fix should be applied to all contracts implementing ACS1, as they share the same vulnerable pattern.

### Proof of Concept

**Initial State**:
- MethodFeeController = `{OwnerAddress: ParliamentDefaultOrg, ContractAddress: ParliamentContract}`
- Attacker has temporary control of ParliamentDefaultOrg through legitimate means

**Attack Steps**:

1. **Deploy MaliciousContract**:
```csharp
public class MaliciousContract : MaliciousContractContainer.MaliciousContractBase
{
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = true }; // Always returns true
    }
}
```

2. **Create Proposal** to change controller:
```csharp
var proposalId = await ParliamentContract.CreateProposal.SendAsync(new CreateProposalInput
{
    ToAddress = ParliamentContractAddress,
    ContractMethodName = nameof(ChangeMethodFeeController),
    Params = new AuthorityInfo
    {
        OwnerAddress = AttackerPersonalAddress,  // Regular address, not organization
        ContractAddress = MaliciousContractAddress
    }.ToByteString(),
    OrganizationAddress = ParliamentDefaultOrg,
    ExpiredTime = Timestamp.FromDateTime(DateTime.UtcNow.AddDays(1))
});
```

3. **Approve and Release** through compromised governance

4. **Verify Bypass**: New controller is set with AttackerPersonalAddress

5. **Exploit**: Attacker calls SetMethodFee directly:
```csharp
await ParliamentContract.SetMethodFee.SendAsync(new MethodFees
{
    MethodName = "CreateProposal",
    Fees = { new MethodFee { Symbol = "ELF", BasicFee = 1000000000000 } } // Extremely high fee
});
```

**Expected vs Actual**:
- **Expected**: Validation should reject MaliciousContractAddress as invalid governance contract
- **Actual**: Validation passes because MaliciousContract.ValidateOrganizationExist returns true

**Success Condition**: Attacker can set arbitrary method fees from their personal address without governance approval, demonstrated by successful execution of SetMethodFee with `Context.Sender == AttackerPersonalAddress`.

### Citations

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-19)
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

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L56-60)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }
```

**File:** protobuf/authority_info.proto (L5-10)
```text
message AuthorityInfo {
    // The contract address of the controller.
    aelf.Address contract_address = 1;
    // The address of the owner of the contract.
    aelf.Address owner_address = 2;
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

**File:** protobuf/acs1.proto (L19-38)
```text
service MethodFeeProviderContract {
    
    // Set the method fees for the specified method. Note that this will override all fees of the method.
    rpc SetMethodFee (MethodFees) returns (google.protobuf.Empty) {
    }

    // Change the method fee controller, the default is parliament and default organization.
    rpc ChangeMethodFeeController (AuthorityInfo) returns (google.protobuf.Empty) {
    }
    
    // Query method fee information by method name.
    rpc GetMethodFee (google.protobuf.StringValue) returns (MethodFees) {
        option (aelf.is_view) = true;
    }

    // Query the method fee controller.
    rpc GetMethodFeeController (google.protobuf.Empty) returns (AuthorityInfo) {
        option (aelf.is_view) = true;
    }
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
