### Title
Insufficient Address Validation in ResetManager Allows Permanent Partial Lock of Scheme Management

### Summary
The `ResetManager()` function only validates that the new manager address is non-empty but does not verify it corresponds to a valid, reachable account. Setting the manager to an invalid or uncontrollable address (e.g., all zeros or random bytes) permanently locks sub-scheme management functions and prevents manager recovery, creating an irreversible partial denial-of-service condition.

### Finding Description
The `ResetManager()` function performs minimal validation on the new manager address: [1](#0-0) 

This check only ensures the address bytes array is not empty via `.Value.Any()`, but does not validate:
1. The address is exactly 32 bytes (AElf's required address length)
2. The address corresponds to a valid keypair that someone controls
3. The address is reachable or meaningful

In AElf, `Context.Sender` is derived from the transaction signature and represents the address of the account that signed the transaction: [2](#0-1) 

An address like `Address.FromBytes(new byte[32])` (all zeros) or random 32-byte values would pass the validation but no one can sign transactions from such addresses. Once set as manager, the following functions become permanently inaccessible:

**Manager-only functions that become locked:** [3](#0-2) [4](#0-3) [5](#0-4) 

The manager assignment happens without recovery mechanism: [6](#0-5) 

This is the ONLY place in the contract where the manager can be changed after scheme creation, with no governance override or recovery path.

### Impact Explanation
Setting the manager to an invalid address creates a **partial permanent lock** of scheme management:

**Permanently Locked Functions:**
- Sub-scheme management (`AddSubScheme`, `RemoveSubScheme`) - no alternative path
- Manager transfer (`ResetManager`) - cannot recover from this state

**Still Functional via TokenHolder Contract:** [7](#0-6) [8](#0-7) 

The scheme can still distribute profits and manage beneficiaries through the TokenHolder contract, but loses hierarchical sub-scheme functionality and manager transferability permanently.

**Severity: LOW** because:
- Core profit distribution functionality preserved via alternative path
- No direct fund loss or theft
- Sub-scheme feature is optional (schemes work without sub-schemes)
- Requires manager action, not exploitable by external attackers

### Likelihood Explanation
**Likelihood: LOW**

This requires the current scheme manager to actively call `ResetManager()` with an invalid address, which can occur due to:
- **User error**: Accidentally providing malformed address (e.g., copy-paste error, wrong format)
- **Software bug**: Application generating invalid address bytes
- **Malicious manager**: Intentionally locking the scheme

**Not exploitable by external attackers** because:
- Only the current manager can call `ResetManager()`
- Requires the trusted manager role to make the mistake
- No way for unauthorized parties to trigger this

**Detection:** Irreversible once executed - no recovery mechanism exists.

**Realistic scenario:** While uncommon, address input errors occur in blockchain applications. The lack of validation creates unnecessary risk for an irreversible operation.

### Recommendation
Add comprehensive address validation before accepting the new manager:

```csharp
public override Empty ResetManager(ResetManagerInput input)
{
    var scheme = State.SchemeInfos[input.SchemeId];
    Assert(scheme != null, "Scheme not found.");
    Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
    
    // Add comprehensive validation
    Assert(input.NewManager != null, "New manager cannot be null.");
    Assert(input.NewManager.Value.Length == AElfConstants.AddressHashLength, 
        "Invalid address length.");
    Assert(input.NewManager.Value.Any(b => b != 0), 
        "Cannot set manager to zero address.");
    
    // Optional: Validate it's not a contract address if that's a requirement
    // or add a confirmation mechanism for critical address changes
    
    // ... rest of function
}
```

**Additional mitigations:**
1. Add a two-step manager transfer with acceptance confirmation
2. Include governance override capability for scheme recovery
3. Add comprehensive test cases covering invalid address scenarios beyond just empty addresses

**Test cases to add:**
- Setting manager to all-zero address
- Setting manager to address with wrong length
- Setting manager to random uncontrolled address

### Proof of Concept

**Initial State:**
- Scheme exists with valid manager (Creator[0])
- Manager has full control over scheme

**Attack Steps:**
1. Current manager calls `ResetManager()` with invalid address:
```csharp
await creator.ResetManager.SendAsync(new ResetManagerInput
{
    SchemeId = schemeId,
    NewManager = Address.FromBytes(new byte[32]) // All zeros - no one controls this
});
```

2. Transaction succeeds (passes `.Value.Any()` check with 32 bytes)

3. Manager is now set to uncontrollable address

4. Attempt to call any manager-only function:
```csharp
await anyUser.AddSubScheme.SendAsync(...);
// FAILS: "Only manager can add sub-scheme"

await anyUser.ResetManager.SendAsync(...); 
// FAILS: "Only scheme manager can reset manager" - CANNOT RECOVER
```

**Expected Result:** Transaction should be rejected with "Invalid address" error

**Actual Result:** Transaction succeeds, scheme management is permanently partially locked

**Success Condition:** Sub-scheme functions and manager reset become permanently inaccessible, no recovery path exists

### Notes
This vulnerability has LIMITED impact because TokenHolder contract can still manage core profit distribution functionality. However, it represents a design flaw where insufficient input validation on an irreversible operation creates unnecessary risk. The LOW severity is justified by the requirement for manager action and preservation of core functionality.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L99-99)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only manager can add sub-scheme.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L139-139)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only manager can remove sub-scheme.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L172-174)
```csharp
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L729-730)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L740-741)
```csharp
        scheme.Manager = input.NewManager;
        State.SchemeInfos[input.SchemeId] = scheme;
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L76-87)
```csharp
            _transactionContext = value;
            CachedStateProvider.Cache = _transactionContext?.StateCache ?? new NullStateCache();
        }
    }

    public IStateProvider StateProvider => _lazyStateProvider.Value;

    public Address GetContractAddressByName(string hash)
    {
        var chainContext = new ChainContext
        {
            BlockHash = TransactionContext.PreviousBlockHash,
```
