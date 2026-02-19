### Title
Insufficient Address Validation Allows Permanent NFT Protocol Lockout via Zero Creator Address

### Summary
The `CrossChainCreate()` function fails to validate that the Creator address obtained from cross-chain token info is non-zero before adding it to the MinterList. If a token with a zero or empty issuer address is registered in the MultiToken contract, the NFT protocol becomes permanently unusable as no one can mint tokens or modify the minter list.

### Finding Description

The vulnerability exists in the `CrossChainCreate()` function where the Creator address is obtained from the MultiToken contract's token info and added to the MinterList without validation: [1](#0-0) [2](#0-1) 

The root cause is insufficient address validation in the MultiToken contract's `RegisterTokenInfo` method, which only checks if the issuer is not null but doesn't validate that the address value is non-empty: [3](#0-2) 

The codebase has a proper address validation pattern that should be used: [4](#0-3) 

Once a zero/empty Creator is added to the MinterList, the protocol becomes permanently locked because:

1. Minting requires the caller to be in the MinterList, but `Context.Sender` can never be a zero address: [5](#0-4) 

2. Adding new minters requires the caller to be the Creator: [6](#0-5) 

3. Removing minters also requires the caller to be the Creator: [7](#0-6) 

### Impact Explanation

**Severity: HIGH** - Permanent Denial of Service

If an NFT protocol is created via `CrossChainCreate()` with a zero or empty Creator address:

- **Complete protocol lockout**: No user can mint NFTs because the only address in the MinterList is the zero address, which cannot be used as `Context.Sender`
- **Irreversible damage**: The minter list cannot be modified because both `AddMinters` and `RemoveMinters` require the caller to be the Creator (zero address)
- **Total value loss**: Any planned NFT collections under this protocol cannot be created or traded, resulting in complete loss of the protocol's intended functionality
- **Permanent state**: There is no recovery mechanism - the protocol remains permanently unusable

This violates the critical invariant for Token Supply & Fees: "NFT uniqueness and ownership checks" by preventing any NFT from being minted in the first place.

### Likelihood Explanation

**Likelihood: MEDIUM**

While the normal token creation flow includes proper issuer assignment, the vulnerability is exploitable if:

1. **Weak upstream validation**: The MultiToken contract's `RegisterTokenInfo` only validates `!= null`, not `!Value.IsNullOrEmpty()`, creating a gap in the validation chain
2. **Cross-chain complexity**: During cross-chain token synchronization via `CrossChainCreateToken`, if the issuer data is corrupted or manipulated, it could pass the insufficient validation
3. **Defense-in-depth failure**: The NFT contract trusts external data without validation, violating defense-in-depth principles
4. **Future risk**: Smart contract upgrades or bugs in the token contract could inadvertently allow zero issuers

The attack requires:
- Ability to trigger cross-chain token creation with invalid issuer data
- Understanding of the validation gaps in both contracts
- No special privileges beyond normal cross-chain operations

### Recommendation

**Immediate fix in NFT contract** - Add defensive validation in `CrossChainCreate()`:

```csharp
// After line 100
Assert(nftProtocolInfo.Creator != null && !nftProtocolInfo.Creator.Value.IsNullOrEmpty(), 
       "Invalid creator address.");
```

**Root cause fix in MultiToken contract** - Update `RegisterTokenInfo()` to properly validate addresses:

```csharp
// Replace line 230
Assert(tokenInfo.Issuer != null && !tokenInfo.Issuer.Value.IsNullOrEmpty(), 
       "Invalid issuer address.");
Assert(tokenInfo.Owner != null && !tokenInfo.Owner.Value.IsNullOrEmpty(), 
       "Invalid owner address.");
```

**Test cases to add:**
1. Attempt to call `CrossChainCreate()` with token info containing null/zero issuer - should revert
2. Verify that `RegisterTokenInfo` rejects tokens with empty address values
3. Integration test for cross-chain NFT creation with various invalid address scenarios

### Proof of Concept

**Prerequisites:**
1. Token registered in MultiToken contract with issuer that passes `!= null` but has `Value.IsNullOrEmpty() == true`
2. Cross-chain setup between parent and side chains

**Attack Sequence:**

1. **Setup**: Attacker exploits the weak validation in `RegisterTokenInfo` to register a token with a zero issuer address on the parent chain (via bug or data corruption)

2. **Cross-chain sync**: Call `CrossChainCreateToken()` on the side chain to sync this token
   - Input: Cross-chain proof containing the malformed token info
   - Result: Token registered with zero issuer

3. **NFT protocol creation**: Call `CrossChainCreate()` on NFT contract
   - Input: `symbol` of the malformed token
   - Line 80-83: Gets token info with zero issuer
   - Line 100: `Creator = tokenInfo.Issuer` (zero address)
   - Line 112: Zero address added to MinterList
   - Result: NFT protocol created but unusable

4. **Verify lockout**: Attempt to mint an NFT
   - Call `Mint()` with valid parameters
   - Line 399 check fails: `Context.Sender` (normal user) not in MinterList (contains only zero address)
   - Result: Transaction reverts with "No permission to mint."

5. **Verify permanent state**: Attempt to recover by adding a valid minter
   - Call `AddMinters()` as any user
   - Line 338 check fails: `Context.Sender != protocolInfo.Creator` (zero address)
   - Result: Transaction reverts with "No permission."

**Expected Result**: NFT protocol functions normally with valid Creator
**Actual Result**: NFT protocol is permanently locked, no operations possible

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L100-100)
```csharp
            Creator = tokenInfo.Issuer,
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L110-113)
```csharp
        State.MinterListMap[input.Symbol] = new MinterList
        {
            Value = { nftProtocolInfo.Creator }
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L230-230)
```csharp
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L337-338)
```csharp
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L357-358)
```csharp
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
