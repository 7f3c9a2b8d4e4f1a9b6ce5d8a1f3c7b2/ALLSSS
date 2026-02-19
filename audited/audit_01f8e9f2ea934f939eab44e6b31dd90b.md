### Title
Case-Sensitive NFT Type Short Name Allows Duplicate Registration Leading to Cross-Chain Synchronization Failures

### Summary
The `AddNFTType()` function uses case-sensitive comparison for NFT type short names, allowing variants like 'AR' and 'ar' to coexist as distinct entries. This inconsistency with the MultiToken contract's case-insensitive token validation creates cross-chain synchronization failures when NFT protocols created on the main chain cannot be properly registered on side chains due to missing case-variant type mappings.

### Finding Description
The NFT contract's `AddNFTType()` function performs case-sensitive validation when checking for duplicate short names. [1](#0-0) 

The state mappings `NFTTypeFullNameMap` and `NFTTypeShortNameMap` use standard string keys without case normalization. [2](#0-1) 

This allows Parliament to register both 'AR' and 'ar' as distinct NFT type short names mapping to different full names. When NFT symbols are generated, they combine the short name with a random number (e.g., "AR123456" or "ar789012"). [3](#0-2) 

However, the MultiToken contract uses case-insensitive validation for token existence checks by converting symbols to uppercase. [4](#0-3) [5](#0-4) 

During cross-chain synchronization, the `CrossChainCreate()` function extracts the first 2 characters of the symbol to look up the NFT type mapping. [6](#0-5) 

If the main chain has registered both 'AR' and 'ar', but a side chain only registered 'AR', any NFT protocol with symbol starting with "ar" will fail cross-chain synchronization with error "Full name of ar not found."

### Impact Explanation
**Operational Impact - Cross-Chain DoS:**
- NFT protocols created on the main chain cannot be synchronized to side chains if case-variant type mappings are inconsistent across chains
- Users attempting to transfer or interact with these NFTs on side chains will encounter failures
- Requires manual intervention by Parliament on each side chain to add missing case variants

**Protocol Inconsistency:**
- NFT contract maintains case-sensitive type registry while MultiToken enforces case-insensitive symbol uniqueness
- Creates confusion and potential integration issues for off-chain systems and indexers
- Violates principle of least surprise for governance participants

**Affected Parties:**
- NFT creators and holders whose protocols use case-variant type short names
- Side chain operators requiring synchronized NFT type registrations
- Cross-chain bridge functionality for NFT transfers

**Severity Justification: Medium**
- No direct fund loss or theft
- Causes operational disruption to cross-chain NFT functionality
- Requires governance action to trigger and resolve
- Affects protocol integrity and user experience

### Likelihood Explanation
**Attacker Capabilities:**
- Requires Parliament governance approval to add NFT types
- Parliament must approve both case variants (either intentionally or through oversight)
- No special technical capabilities needed beyond governance participation

**Attack Complexity:**
- Low complexity: Submit two AddNFTType proposals with case-variant short names
- Parliament approvers may not notice case difference during review
- Natural occurrence through legitimate proposals for similar NFT categories

**Feasibility Conditions:**
- Parliament must approve at least two AddNFTType proposals with short names differing only in case
- NFT protocols must be created using the case-variant types
- Cross-chain synchronization must be attempted

**Detection/Operational Constraints:**
- Case differences in 2-character codes are easy to miss in governance review
- No automated validation prevents case-variant registration
- Issue becomes apparent only during cross-chain operations

**Probability: Medium**
- Depends on governance oversight during proposal review
- More likely as NFT ecosystem grows and more custom types are added
- Could occur through legitimate use case misunderstanding rather than malicious intent

### Recommendation
**Code-Level Mitigation:**

1. Normalize short names to uppercase in `AddNFTType()`:
   - Convert `input.ShortName` to uppercase before all checks and storage
   - Convert lookup keys to uppercase in `GetSymbol()` and `CrossChainCreate()`

2. Add explicit case-insensitive duplicate check:
   ```
   Assert(State.NFTTypeFullNameMap[input.ShortName.ToUpper()] == null, 
          $"Short name {input.ShortName.ToUpper()} already exists.");
   ```

3. Update `InitialNFTTypeNameMap()` to ensure all predefined short names are uppercase. [7](#0-6) 

**Invariant Checks:**
- Assert all short names stored in state maps are uppercase
- Validate symbol prefix extraction matches registered types case-insensitively
- Ensure cross-chain type lookups use normalized keys

**Test Cases:**
1. Test AddNFTType with lowercase short name is converted to uppercase
2. Test AddNFTType rejects case-variant duplicates ('AR' when 'ar' exists)
3. Test CrossChainCreate successfully resolves types regardless of symbol case
4. Test GetSymbol generates symbols with normalized short name prefix

### Proof of Concept

**Initial State:**
- Parliament governance is operational
- NFT contract is deployed and initialized
- No custom NFT types have been added yet

**Attack Sequence:**

1. **Parliament adds first NFT type (uppercase):**
   - Call `AddNFTType({ShortName: "AR", FullName: "ArtType"})`
   - Result: Success, `NFTTypeFullNameMap["AR"] = "ArtType"`

2. **Parliament adds second NFT type (lowercase):**
   - Call `AddNFTType({ShortName: "ar", FullName: "ArtVariant"})`
   - Result: Success due to case-sensitive check, `NFTTypeFullNameMap["ar"] = "ArtVariant"`

3. **User creates NFT protocol on main chain:**
   - Call `Create({NftType: "ArtVariant", ...})`
   - Result: Symbol "ar123456" created on main chain

4. **Side chain initialization:**
   - Side chain only adds: `AddNFTType({ShortName: "AR", FullName: "ArtType"})`
   - Note: "ar" variant not added to side chain

5. **Cross-chain synchronization attempted:**
   - Call `CrossChainCreate({Symbol: "ar123456"})`
   - Extracts short name: "ar"
   - Looks up: `State.NFTTypeFullNameMap["ar"]` → null
   - Result: **Transaction fails** with "Full name of ar not found"

**Expected vs Actual Result:**
- **Expected:** NFT protocols sync successfully across chains regardless of short name case
- **Actual:** Cross-chain synchronization fails for case-variant NFT types
- **Success Condition:** Transaction reverts with assertion error, blocking NFT cross-chain functionality

**Notes**

The vulnerability stems from architectural inconsistency: the NFT contract treats short names as case-sensitive identifiers while the underlying MultiToken contract enforces case-insensitive token symbol uniqueness. This creates a semantic gap that manifests during cross-chain operations where exact case matching is required for type lookups. The fix requires normalizing all short name operations to uppercase to align with MultiToken's case-insensitive approach and ensure consistent behavior across all chains in the AElf ecosystem.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L89-93)
```csharp
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L136-137)
```csharp
        Assert(input.ShortName.Length == 2, "Incorrect short name.");
        Assert(State.NFTTypeFullNameMap[input.ShortName] == null, $"Short name {input.ShortName} already exists.");
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L35-36)
```csharp
    public MappedState<string, string> NFTTypeShortNameMap { get; set; }
    public MappedState<string, string> NFTTypeFullNameMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L28-36)
```csharp
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }

        return $"{shortName}{randomNumber}";
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L44-53)
```csharp
        nftTypes.Value.Add("XX", NFTType.Any.ToString());
        nftTypes.Value.Add("AR", NFTType.Art.ToString());
        nftTypes.Value.Add("MU", NFTType.Music.ToString());
        nftTypes.Value.Add("DN", NFTType.DomainNames.ToString());
        nftTypes.Value.Add("VW", NFTType.VirtualWorlds.ToString());
        nftTypes.Value.Add("TC", NFTType.TradingCards.ToString());
        nftTypes.Value.Add("CO", NFTType.Collectables.ToString());
        nftTypes.Value.Add("SP", NFTType.Sports.ToString());
        nftTypes.Value.Add("UT", NFTType.Utility.ToString());
        nftTypes.Value.Add("BA", NFTType.Badges.ToString());
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L233-233)
```csharp
        State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()] = true;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L302-302)
```csharp
        Assert(!State.InsensitiveTokenExisting[symbol.ToUpper()], "Token already exists.");
```
