### Title
Missing Interface Compatibility Validation Enables Silent Cross-Contract Call Failures on Parliament Contract Upgrade

### Summary
The contract upgrade mechanism validates only version number increments but does not enforce interface compatibility. If the Parliament contract is upgraded with breaking interface changes (e.g., method return type changes), dependent contracts calling Parliament methods will experience silent failures where protobuf deserialization succeeds with default/corrupted values rather than throwing explicit errors. This affects authorization and governance operations across 15+ system contracts.

### Finding Description

**Root Cause:**

The contract upgrade validation in [1](#0-0)  only checks that version numbers increase, with no validation of interface compatibility.

**Cross-Contract Call Mechanism:**

When Association contract calls Parliament, the execution flow is:
1. Association defines ParliamentContract reference in [2](#0-1) 
2. Calls GetDefaultOrganizationAddress in [3](#0-2) 
3. Method dispatch uses string-based lookup in [4](#0-3) 
4. Return value deserialization in [5](#0-4)  uses MergeFrom without type validation

**Why Protections Fail:**

The critical flaw is at line 224 of HostSmartContractBridgeContext: `obj.MergeFrom(trace.ReturnValue)` has no try-catch and no type signature validation. Protobuf's MergeFrom is designed for forward/backward compatibility and will:
- Silently ignore unknown fields
- Return default-initialized objects when field numbers don't match
- Rarely throw exceptions, preferring lenient parsing

If Parliament's GetDefaultOrganizationAddress is upgraded to return a different protobuf type, the calling code receives a default/empty Address instead of detecting the incompatibility.

**Systemic Scope:**

This affects all contracts referencing ParliamentContract (15+ system contracts including Genesis, MultiToken, Configuration, Economic, Referendum, TokenConverter, TokenHolder, Treasury, Vote, CrossChain, Election, Consensus, Profit, NFT) as shown in grep results across contract/**/*.cs files.

### Impact Explanation

**Authorization Bypass:**

In Association contract, the compromised Address is used for authorization checks in [6](#0-5) . If GetDefaultOrganizationAddress returns default/empty Address due to type mismatch, the authorization check `Context.Sender == State.MethodFeeController.Value.OwnerAddress` could incorrectly pass or fail.

**Governance Corruption:**

Multiple contracts use Parliament's GetDefaultOrganizationAddress to establish governance authority. Corrupted Address values would:
- Allow unauthorized method fee changes
- Break proposal approval mechanisms  
- Corrupt organization-based permissions across MultiToken, Treasury, Economic contracts
- Potentially enable unauthorized fund movements if combined with other authorization bypasses

**Protocol-Wide Impact:**

Since 15+ system contracts depend on Parliament interface, a single breaking upgrade creates cascading failures across governance, token economics, and cross-chain operations. The silent nature means contracts continue executing with wrong data rather than failing explicitly.

**Severity: High** - Compromises authorization invariants across critical system contracts, affects fund security through governance bypass, and failures are silent/undetectable.

### Likelihood Explanation

**Preconditions:**
1. Parliament contract upgrade approved by governance (2/3 miner approval required)
2. Upgrade contains breaking interface change (method signature/return type modified)
3. Dependent contracts not upgraded simultaneously

**Attack Complexity: Medium**

This is NOT a direct attack but a design flaw exploitable through:
- **Accidental scenario**: Developer upgrades Parliament with breaking change, testing misses cross-contract compatibility issues, governance approves without detecting the problem
- **Malicious scenario**: Compromised governance intentionally approves breaking upgrade to create authorization bypasses in dependent contracts

**Feasibility: Medium-High**

- Contract upgrades are governance-controlled but require only version number validation per [7](#0-6) 
- No technical barrier prevents breaking changes if governance approves
- Testing might not cover all 15+ dependent contracts' compatibility
- Once deployed, the failure mode is silent and hard to detect

**Detection Constraints:**

The vulnerability is particularly dangerous because:
- MergeFrom succeeds silently rather than throwing exceptions
- Default Address values may pass some validation checks
- No runtime type signature verification exists
- Impact only manifests in specific execution paths (authorization checks)

**Overall Likelihood: Medium** - Requires governance approval but no technical safeguards exist, and accidental occurrence is plausible during complex upgrades.

### Recommendation

**1. Add Interface Compatibility Validation:**

Modify [7](#0-6)  to validate method signatures match between versions:

- Extract method signatures from both old and new contract assemblies using reflection on ServerServiceDefinition
- Compare input/output protobuf message types for all existing methods
- Ensure new methods only add, never modify or remove existing signatures
- Fail upgrade if breaking changes detected

**2. Add Runtime Type Validation:**

Wrap MergeFrom in [8](#0-7)  with validation:

```
try {
    obj.MergeFrom(trace.ReturnValue);
    // Validate critical fields populated (not all defaults)
    if (IsDefaultInitialized(obj)) {
        throw new ContractCallException($"Deserialization resulted in default values - possible type mismatch for {methodName}");
    }
} catch (Exception ex) {
    throw new ContractCallException($"Failed to deserialize return value for {methodName}: {ex.Message}");
}
```

**3. Add Contract Reference Version Tracking:**

Store expected interface versions in contract state when initializing contract references, validate on each call that target contract version is compatible.

**4. Test Cases:**

Add regression tests that:
- Deploy contract with cross-contract references
- Upgrade referenced contract with breaking change
- Verify upgrade is rejected OR calling contract receives explicit error (not silent failure)

### Proof of Concept

**Initial State:**
1. Parliament contract deployed at version 1.0.0 with `GetDefaultOrganizationAddress() returns aelf.Address`
2. Association contract deployed referencing Parliament contract
3. Association.RequiredMethodFeeControllerSet() initializes MethodFeeController using Parliament.GetDefaultOrganizationAddress()

**Exploit Sequence:**

**Step 1:** Propose Parliament contract upgrade to version 1.1.0 where GetDefaultOrganizationAddress is modified to return a new protobuf type `OrganizationInfo { Address address; string name; }` instead of raw Address

**Step 2:** Governance approves upgrade (2/3 miner votes)

**Step 3:** Parliament contract updated - version check passes because 1.0.0 < 1.1.0 per [9](#0-8) 

**Step 4:** User calls Association.SetMethodFee() triggering RequiredMethodFeeControllerSet()

**Expected Result:** 
- Call to Parliament.GetDefaultOrganizationAddress should fail with explicit type mismatch error
- Transaction should revert

**Actual Result:**
- Parliament executes successfully, returns OrganizationInfo bytes
- Association's MergeFrom at [10](#0-9)  attempts to deserialize OrganizationInfo bytes as Address
- Protobuf MergeFrom succeeds but produces default/empty Address value
- State.MethodFeeController.Value.OwnerAddress set to empty/corrupted Address
- Subsequent authorization checks in [6](#0-5)  use wrong address
- Silent authorization bypass or incorrect rejection occurs

**Success Condition:** Association contract operates with corrupted MethodFeeController.Value.OwnerAddress without any error being thrown, demonstrating silent failure mode.

### Citations

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractService.cs (L53-61)
```csharp
    public async Task<ContractVersionCheckDto> CheckContractVersionAsync(string previousContractVersion,SmartContractRegistration registration)
    {
        var newContractVersion = await GetVersion(registration);
        var isSubsequentVersion = CheckVersion(previousContractVersion,newContractVersion);
        return new ContractVersionCheckDto
        {
            IsSubsequentVersion = isSubsequentVersion
        };
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractService.cs (L77-90)
```csharp
    private bool CheckVersion(string previousContractVersion,string newContractVersion)
    {
        if (newContractVersion.IsNullOrEmpty())
        {
            return false;
        }

        if (previousContractVersion.IsNullOrEmpty())
        {
            return true;
        }

        return  new Version(previousContractVersion) < new Version(newContractVersion);
    }
```

**File:** contract/AElf.Contracts.Association/AssociationReferenceState.cs (L6-10)
```csharp
public partial class AssociationState
{
    internal ParliamentContractContainer.ParliamentContractReferenceState ParliamentContract { get; set; }
    internal TokenContractContainer.TokenContractReferenceState TokenContract { get; set; }
}
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L15-15)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L56-60)
```csharp
        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L133-137)
```csharp
            if (!_callHandlers.TryGetValue(methodName, out var handler))
                throw new RuntimeException(
                    $"Failed to find handler for {methodName}. We have {_callHandlers.Count} handlers: " +
                    string.Join(", ", _callHandlers.Keys.OrderBy(k => k))
                );
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L221-225)
```csharp
        if (!trace.IsSuccessful()) throw new ContractCallException(trace.Error);

        var obj = new T();
        obj.MergeFrom(trace.ReturnValue);
        return obj;
```
