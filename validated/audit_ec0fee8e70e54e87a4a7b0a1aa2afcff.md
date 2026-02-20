# Audit Report

## Title
IsUserContract Flag Manipulation via Incorrect Update Path Bypasses ACS Requirements

## Summary
User contract authors can permanently bypass required ACS (AElf Contract Standard) security validations by updating their contracts through the non-user contract update path. This exploits the lack of validation to ensure user contracts use the appropriate update method, allowing the `IsUserContract` flag to be flipped to false and permanently exempting the contract from user contract code validation.

## Finding Description

The AElf Genesis contract provides two distinct update paths for smart contracts:

1. **Standard contract update path**: `ProposeUpdateContract` → `UpdateSmartContract`
2. **User contract update path**: `UpdateUserSmartContract` → `PerformUpdateUserSmartContract`

The vulnerability exists because the private `UpdateSmartContract` helper method unconditionally overwrites the `IsUserContract` flag based on its caller-supplied parameter. [1](#0-0) 

The public update methods hardcode this parameter to false for standard updates [2](#0-1)  and true for user contract updates. [3](#0-2) 

The root cause is that `ProposeUpdateContract` only validates that the sender is the contract author or Genesis contract, [4](#0-3) [5](#0-4)  but does NOT check whether the contract's current `IsUserContract` status requires using the user contract update path instead.

When `ProposeUpdateContract` fires the `CodeCheckRequired` event through `ProposeContractCodeCheck`, it omits the `IsUserContract` field. [6](#0-5)  In protobuf, unset boolean fields default to false. [7](#0-6) 

The code check service uses this flag to determine whether to enforce user contract ACS requirements. When `isUserContract` is false, the service uses an empty `RequiredAcs` list, bypassing user contract validation. [8](#0-7) 

**Attack Execution Path:**
1. User contract author calls `ProposeUpdateContract` instead of `UpdateUserSmartContract`
2. Authorization check passes because contract author is allowed
3. Proposal goes through Parliament governance approval
4. `ProposeContractCodeCheck` fires `CodeCheckRequired` with `IsUserContract` unset (defaults to false)
5. Code check bypasses user contract ACS requirements
6. `UpdateSmartContract` executes, permanently setting `info.IsUserContract = false`
7. All future updates continue without user contract validation checks

## Impact Explanation

This vulnerability breaks the fundamental security model for user contracts in AElf. User contracts are intended to be subject to stricter ACS validation requirements to ensure code quality and security. By flipping the `IsUserContract` flag, a contract permanently escapes these constraints.

**Concrete harm:**
- User contracts can deploy code that violates required ACS standards (e.g., ACS12 User Contract Standard)
- Malicious or vulnerable code can be introduced without proper validation checks
- The bypass is permanent—the flag change persists across all subsequent updates
- Undermines trust in the user contract security model
- Affects all users and systems that interact with the compromised contract

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker capabilities required:**
- Must be the contract author (stored in `ContractInfo.Author`)
- Must obtain Parliament governance approval for the update proposal

**Why this is realistic:**
- Contract authors legitimately update their contracts for maintenance and feature additions
- The wrong update path can be triggered accidentally (developer confusion) or intentionally (malicious bypass)
- Governance reviewers may not understand the internal implementation difference between `ProposeUpdateContract` and `UpdateUserSmartContract`
- The flag manipulation is not visible in the proposal parameters—it requires understanding that the `CodeCheckReleaseMethod` determines which path is used
- No UI warnings or clear documentation distinguishes when each method should be used

**Detection constraints:**
The vulnerability is subtle because both update paths appear to be legitimate contract update methods. Governance would need deep knowledge of the Genesis contract implementation to detect that using `ProposeUpdateContract` will silently change the contract type.

## Recommendation

Add a validation check in `ProposeUpdateContract` to prevent user contracts from using the standard update path:

```csharp
public override Hash ProposeUpdateContract(ContractUpdateInput input)
{
    var proposedContractInputHash = CalculateHashFromInput(input);
    RegisterContractProposingData(proposedContractInputHash);

    var contractAddress = input.Address;
    var info = State.ContractInfos[contractAddress];
    Assert(info != null, "Contract not found.");
    
    // NEW: Enforce that user contracts must use UpdateUserSmartContract
    Assert(!info.IsUserContract, "User contracts must use UpdateUserSmartContract method.");
    
    AssertAuthorityByContractInfo(info, Context.Sender);
    // ... rest of method
}
```

Alternatively, preserve the `IsUserContract` flag during updates in the helper method:

```csharp
private void UpdateSmartContract(Address contractAddress, byte[] code, Address author, bool isUserContract)
{
    var info = State.ContractInfos[contractAddress];
    Assert(info != null, "Contract not found.");
    Assert(author == info.Author, "No permission.");
    
    // MODIFIED: Preserve original IsUserContract status
    var originalIsUserContract = info.IsUserContract;
    
    var oldCodeHash = info.CodeHash;
    var newCodeHash = HashHelper.ComputeFrom(code);
    Assert(oldCodeHash != newCodeHash, "Code is not changed.");
    AssertContractNotExists(newCodeHash);

    info.CodeHash = newCodeHash;
    info.IsUserContract = originalIsUserContract; // Don't allow flag change
    info.Version++;
    // ... rest of method
}
```

## Proof of Concept

The vulnerability can be demonstrated by creating a test that:

1. Deploys a user contract via `DeployUserSmartContract` (sets `IsUserContract = true`)
2. Calls `ProposeUpdateContract` with an update (instead of `UpdateUserSmartContract`)
3. Approves the proposal through governance
4. Verifies that `GetContractInfo` shows `IsUserContract = false` after the update
5. Confirms that subsequent updates bypass ACS validation

The test would validate that the contract info's `IsUserContract` flag has been permanently flipped from true to false, allowing all future updates to bypass user contract ACS requirements.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L110-110)
```csharp
        info.IsUserContract = isUserContract;
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L241-244)
```csharp
    private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
    {
        Assert(contractInfo.Author == Context.Self || address == contractInfo.Author, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L183-183)
```csharp
        AssertAuthorityByContractInfo(info, Context.Sender);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L266-272)
```csharp
        Context.Fire(new CodeCheckRequired
        {
            Code = ExtractCodeFromContractCodeCheckInput(input),
            ProposedContractInputHash = proposedContractInputHash,
            Category = input.Category,
            IsSystemContract = input.IsSystemContract
        });
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L334-334)
```csharp
        UpdateSmartContract(contractAddress, input.Code.ToByteArray(), info.Author, false);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L514-514)
```csharp
        UpdateSmartContract(input.Address, input.Code.ToByteArray(), proposingInput.Author, true);
```

**File:** protobuf/acs0.proto (L259-260)
```text
    // Indicates if the contract is the user contract.
    bool is_user_contract = 5;
```

**File:** src/AElf.Kernel.CodeCheck/Application/CodeCheckService.cs (L31-40)
```csharp
        var requiredAcs = new RequiredAcs
        {
            AcsList = new List<string>(),
            RequireAll = false
        };
        
        if (isUserContract)
        {
            requiredAcs = await _requiredAcsProvider.GetRequiredAcsInContractsAsync(blockHash, blockHeight);
        }
```
