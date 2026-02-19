### Title
Permanent Symbol Alias Mapping Prevents Legitimate Updates and Recovery from Key Compromise

### Summary
The `SetSymbolAlias()` function enforces permanent alias mappings with no update or removal mechanism. Once an alias is set, the owner/issuer cannot modify it even to correct errors or recover from key compromise, creating an operational DoS for legitimate alias management and a permanent attack surface.

### Finding Description

The vulnerability exists in the `SetSymbolAlias()` function where the assertion check permanently blocks any subsequent alias updates: [1](#0-0) 

Once an alias is stored in the global mapping, it becomes immutable: [2](#0-1) 

The code comment acknowledges this limitation as temporary ("For now"): [3](#0-2) 

The authorization check restricts alias setting to only the owner or issuer: [4](#0-3) 

**Root Cause:** The assertion `State.SymbolAliasMap[input.Alias] == null` fails for any already-set alias, with no functions to remove or update mappings (confirmed by codebase search showing no `RemoveSymbolAlias`, `UpdateSymbolAlias`, or similar functions exist).

**Why Protections Fail:** There are no protections - the design explicitly prevents any updates. This creates multiple failure scenarios:
1. Owner cannot correct accidental misconfigurations
2. Owner cannot update alias to point to different NFT items for business reasons  
3. If owner's key is temporarily compromised and attacker sets incorrect alias, owner cannot recover even after regaining control
4. No governance override mechanism exists

### Impact Explanation

**Operational Impact:**
- **Legitimate Operations Blocked:** NFT collection owners are permanently unable to update alias mappings once set, blocking legitimate business logic changes (e.g., pointing alias from "ABC-1" to "ABC-2")
- **No Error Correction:** Mistakes in alias configuration are permanent with no recovery path
- **Compromised Key Risk:** If an attacker gains temporary access to owner's private key, they can set malicious alias mappings that the owner can never fix, even after regaining control
- **Permanent Attack Surface:** Once set incorrectly (maliciously or accidentally), the incorrect mapping persists forever, affecting all future token operations that rely on alias resolution

**Affected Parties:** All NFT collection owners on MainChain who use the symbol alias feature are affected. Given the MainChain restriction: [5](#0-4) 

**Severity Justification:** Medium severity is appropriate because:
- Creates permanent operational DoS with no mitigation
- Amplifies impact of temporary key compromise into permanent damage
- Affects core token functionality (alias resolution used in transfers, approvals, etc.)
- No direct fund loss, but significant operational and security risk

### Likelihood Explanation

**High Likelihood Scenarios:**

1. **Accidental Misconfiguration:** Owners will naturally make mistakes when first using the feature, setting wrong NFT item in alias mapping. Once discovered, they cannot fix it.

2. **Business Logic Evolution:** Collection owners may legitimately want to change which NFT item their alias points to as their business evolves. This is completely blocked.

3. **Temporary Key Compromise:** If owner's key is compromised even briefly, attacker can permanently damage the alias configuration. Recovery is impossible.

**Attack Complexity:** Low - only requires single transaction from owner (or compromised owner key).

**Feasibility Conditions:** 
- Owner wants to update existing alias (common business need)
- Owner made configuration error (inevitable with any manual process)
- Owner's key temporarily compromised (realistic security incident)

**Detection:** The permanent lock occurs immediately upon first alias setting, with no warning to owner about immutability.

**Probability:** HIGH - the lack of update functionality will affect most users who utilize this feature over time.

### Recommendation

**Code-Level Mitigation:**

1. **Add Update Function:** Implement `UpdateSymbolAlias()` restricted to owner/issuer:
   - Verify caller is owner/issuer of NFT collection
   - Allow updating existing alias mappings
   - Emit event for transparency
   - Update both `SymbolAliasMap` and collection's `ExternalInfo`

2. **Add Time-Lock or Governance Override:** For security, consider either:
   - Time-locked updates (e.g., 24-hour delay for alias changes)
   - Parliament governance override for recovery scenarios

3. **Modify Assertion:** Replace the blocking assertion with a check that only prevents unauthorized updates:
   ```
   // Instead of: Assert(State.SymbolAliasMap[input.Alias] == null, ...)
   // Allow updates by current owner/issuer only
   ```

**Invariant Checks:**
- Only owner/issuer can update their aliases
- Alias must still match collection seed name validation
- Update events must be emitted for transparency

**Test Cases:**
- Owner successfully updates alias from "ABC-1" to "ABC-2"
- Non-owner cannot update someone else's alias
- Update maintains all validation rules (seed name matching)
- Recovery scenario after simulated key compromise

### Proof of Concept

**Initial State:**
- NFT Collection "ABC-0" exists with owner address Owner1
- NFT Items "ABC-1" and "ABC-2" exist in the collection

**Transaction Steps:**

1. Owner1 calls `SetSymbolAlias(Symbol: "ABC-1", Alias: "ABC")`
   - Transaction succeeds
   - `State.SymbolAliasMap["ABC"] = "ABC-1"`

2. Owner1 later wants to update and calls `SetSymbolAlias(Symbol: "ABC-2", Alias: "ABC")`
   - **Transaction FAILS at line 750**
   - Error: "Token alias ABC already exists"
   - Alias permanently stuck pointing to "ABC-1"

**Expected Result:** Owner should be able to update their own alias mapping

**Actual Result:** Owner is permanently blocked from any alias updates

**Success Condition:** The assertion at line 750 prevents all update attempts, confirming the operational DoS of legitimate alias management.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L744-745)
```csharp
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "Symbol alias setting only works on MainChain.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L749-749)
```csharp
        // For now, token alias can only be set once.
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L750-750)
```csharp
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L760-761)
```csharp
        Assert(collectionTokenInfo.Owner == Context.Sender || collectionTokenInfo.Issuer == Context.Sender,
            "No permission.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L768-768)
```csharp
        State.SymbolAliasMap[input.Alias] = input.Symbol;
```
