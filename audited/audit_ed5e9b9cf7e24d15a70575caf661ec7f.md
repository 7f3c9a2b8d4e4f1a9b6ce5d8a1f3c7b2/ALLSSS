### Title
Unauthorized Contract Address Allows Governance Bypass via Malicious Authorization Contract in `ChangeMethodFeeController`

### Summary
The `CheckOrganizationExist()` function in `TokenContract_ACS1_MethodFeeProvider.cs` performs a cross-contract call to an arbitrary `authorityInfo.ContractAddress` without validating that it is a trusted authorization contract (Parliament, Association, or Referendum). [1](#0-0)  This allows a malicious governance proposal to change the MethodFeeController to point to a malicious contract, enabling permanent bypass of governance controls over method fees.

### Finding Description

**Root Cause:**
The `ChangeMethodFeeController` method accepts an `AuthorityInfo` parameter and validates it by calling `CheckOrganizationExist(input)`. [2](#0-1) 

The `CheckOrganizationExist` function makes a `Context.Call` to the `ContractAddress` provided in the `AuthorityInfo` without any validation that this address corresponds to a legitimate authorization contract. [1](#0-0) 

The `AuthorityInfo` structure contains two fields: `contract_address` (the authorization contract) and `owner_address` (the organization address). [3](#0-2) 

**Why Protections Fail:**
1. No validation exists to ensure `ContractAddress` is one of the trusted system contracts (Parliament, Association, or Referendum)
2. The only check is that the organization exists according to whatever contract is at `ContractAddress`
3. A malicious contract can trivially return `true` from its `ValidateOrganizationExist` method

**Execution Path:**
1. Attacker deploys a malicious contract implementing `ValidateOrganizationExist` that always returns `true`
2. A governance proposal is created to call `ChangeMethodFeeController` with the malicious contract address
3. Upon proposal execution, `CheckOrganizationExist` calls the malicious contract
4. The malicious contract returns `true`, bypassing validation
5. `State.MethodFeeController.Value` is updated to the attacker-controlled `AuthorityInfo`
6. Future `SetMethodFee` calls only check `OwnerAddress`, not `ContractAddress` [4](#0-3) 

### Impact Explanation

**Direct Governance Impact:**
- The attacker gains unilateral control over method fees for the MultiToken contract without requiring governance approval for future changes
- Method fees control the cost of executing all contract methods (transfer, approve, lock, etc.)
- This breaks the fundamental governance model where fee changes must go through Parliament/Association/Referendum proposals and voting

**Affected Parties:**
- All users of the MultiToken contract and dependent contracts
- The governance system loses authority over a critical protocol parameter
- The entire AElf ecosystem, as method fees affect transaction costs across all operations

**Severity Justification:**
This is a **CRITICAL** vulnerability because it enables a permanent governance bypass. Once exploited, the attacker can arbitrarily manipulate transaction costs without any governance oversight, potentially making the contract unusable or extracting value through discriminatory fee structures. The same pattern exists across all ACS1-implementing contracts. [5](#0-4) [6](#0-5) 

### Likelihood Explanation

**Attacker Capabilities:**
- Must be able to deploy a smart contract
- Must create a governance proposal (typically requires being a miner or on the proposer whitelist)
- Requires governance approval (majority vote in Parliament)

**Attack Complexity:**
The attack is straightforward:
1. Deploy malicious contract with one method returning `true`
2. Create proposal with malicious `AuthorityInfo`
3. Wait for approval and execution

**Feasibility Conditions:**
While this requires governance approval, it represents a "governance rug pull" vulnerability where one governance action permanently breaks future governance. This is a critical design flaw even if current governance is trusted, because:
- It violates the security invariant that governance should be persistent
- Temporary governance compromise creates permanent backdoor
- Similar to allowing a multisig to vote to become a single-sig

**Probability:**
MODERATE-TO-HIGH. While requiring governance approval increases the barrier, this type of "governance escape hatch" is considered a critical vulnerability in audits because proper governance systems should not allow themselves to be permanently disabled, even by majority vote.

### Recommendation

**Immediate Fix:**
Add validation in `CheckOrganizationExist` to ensure the `ContractAddress` is one of the trusted authorization contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate contract address is a trusted authorization contract
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress ||
        authorityInfo.ContractAddress == associationAddress ||
        authorityInfo.ContractAddress == referendumAddress,
        "Invalid authorization contract address.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Apply to All Contracts:**
This fix must be applied to all contracts implementing ACS1, including Parliament, Association, Referendum, Genesis, CrossChain, Economic, Election, Profit, TokenConverter, TokenHolder, Treasury, Vote, and Configuration contracts, as they all contain the same vulnerable pattern.

**Test Cases:**
Add test cases verifying:
1. `ChangeMethodFeeController` rejects non-system contract addresses
2. Only Parliament, Association, and Referendum contracts are accepted
3. User-deployed contracts cannot be used as authorization contracts

### Proof of Concept

**Initial State:**
- MethodFeeController is set to Parliament default organization
- Token contract is initialized

**Attack Steps:**
1. Deploy `MaliciousAuthContract` with method:
   ```csharp
   public BoolValue ValidateOrganizationExist(Address input) {
       return new BoolValue { Value = true };
   }
   ```

2. Create Parliament proposal to call `TokenContract.ChangeMethodFeeController`:
   ```csharp
   Input: AuthorityInfo {
       ContractAddress = MaliciousAuthContract,
       OwnerAddress = AttackerAddress
   }
   ```

3. Get proposal approved by miners and execute

4. Call `TokenContract.SetMethodFee` directly as AttackerAddress:
   ```csharp
   Input: MethodFees {
       MethodName = "Transfer",
       Fees = [{ Symbol = "ELF", BasicFee = 1000000000 }]
   }
   ```

**Expected Result:**
Step 3 should fail with "Invalid authorization contract address"

**Actual Result:**
Step 3 succeeds, Step 4 succeeds, and attacker now controls method fees without governance oversight

**Success Condition:**
After exploitation, `GetMethodFeeController()` returns the malicious `AuthorityInfo`, and `SetMethodFee` can be called directly by AttackerAddress without creating governance proposals.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L24-32)
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L116-121)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L56-60)
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
