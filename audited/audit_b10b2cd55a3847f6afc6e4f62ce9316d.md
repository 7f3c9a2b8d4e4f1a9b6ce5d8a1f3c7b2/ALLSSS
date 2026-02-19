### Title
NFT Protocol Creation Accepts Empty Address Values Leading to Permanent Protocol Bricking

### Summary
The NFT contract's `Create` method fails to validate that `input.Creator` has a non-empty `Address.Value` field before using it as the token issuer. Combined with insufficient validation in the MultiToken contract's `RegisterTokenInfo` method, this allows creation of NFT protocols with invalid issuer addresses (empty byte values), permanently bricking the protocol as no one can mint NFTs or manage the minter list.

### Finding Description

The vulnerability exists in the NFT creation flow across two contracts:

**NFT Contract - Insufficient Creator Validation:**
At line 22, the code uses a null-coalescing operator to set the creator [1](#0-0) . This only checks if `input.Creator` is null, but does not validate whether the Address object has an empty `Value` field (ByteString). If a caller passes `new Address()` or `new Address { Value = ByteString.Empty }`, this is a non-null Address object that bypasses the null check, resulting in `creator` being set to an invalid empty-value address.

This invalid creator is then passed to the MultiToken contract as the `Issuer` [2](#0-1) .

**MultiToken Contract - Incomplete RegisterTokenInfo Validation:**
The `RegisterTokenInfo` method only validates that the issuer is not null [3](#0-2) , but does not check if the `Address.Value` field is empty. This is inconsistent with the proper validation pattern used elsewhere in the same contract, such as in `ModifyTokenIssuerAndOwner` which correctly validates both conditions [4](#0-3) .

**Protocol Becomes Permanently Unusable:**
Once created with an empty-value issuer, the protocol cannot be used:

1. **Minting Fails**: The `GetMinterList` helper adds the empty-value issuer to the minter list [5](#0-4) , but the minting permission check fails because `Context.Sender` (a valid address) will never equal the empty-value address [6](#0-5) .

2. **Minter Management Fails**: The `AddMinters` and `RemoveMinters` methods require the caller to equal the protocol creator [7](#0-6) , which will always fail for any real sender when the creator has an empty value.

### Impact Explanation

**Severity: High/Critical**

This vulnerability enables permanent denial-of-service attacks against NFT protocol functionality:

1. **Complete Protocol Bricking**: Any NFT protocol created with an empty-value creator becomes permanently unusable - no NFTs can ever be minted, and the minter list cannot be modified.

2. **Economic Damage**: 
   - Attackers can intentionally brick protocols, wasting the creation fees/costs paid by legitimate users
   - If the attacker front-runs a legitimate NFT protocol creation, the intended creator loses their fees and must create under a different symbol

3. **Griefing Attack Vector**: Malicious actors can systematically brick popular NFT symbol names or types, causing operational disruption and user frustration.

4. **No Recovery Mechanism**: Unlike some protocol configuration issues that can be fixed through governance, there is no mechanism to recover from this state. The protocol creator address is immutably set in the `NFTProtocolInfo` structure [8](#0-7) .

### Likelihood Explanation

**Probability: High**

This vulnerability is highly exploitable:

1. **Reachable Entry Point**: The `Create` method is a public function callable by any user who can pay the creation fee.

2. **Low Attack Complexity**: Exploitation requires only sending a `CreateInput` message with `Creator = new Address()` (an Address object with empty Value). This is trivial to construct in any AElf transaction.

3. **No Special Permissions Required**: Any user can call the Create method - the only barrier is passing the seed NFT check or being in the create whitelist [9](#0-8) , which is necessary for any protocol creation.

4. **Low Attack Cost**: The cost is merely the NFT creation fee/seed NFT, making griefing attacks economically viable.

5. **Undetectable Until Too Late**: The protocol appears to be created successfully - the vulnerability only manifests when users attempt to mint or manage minters, at which point the damage is already done.

### Recommendation

**Primary Fix - Add Proper Address Validation:**

Modify the `RegisterTokenInfo` method in `TokenContract_Helper.cs` to validate both null and empty Address values, consistent with the pattern used in `ModifyTokenIssuerAndOwner`:

```csharp
Assert(tokenInfo.Issuer != null && !tokenInfo.Issuer.Value.IsNullOrEmpty(), "Invalid issuer address.");
Assert(tokenInfo.Owner != null && !tokenInfo.Owner.Value.IsNullOrEmpty(), "Invalid owner address.");
```

**Secondary Fix - Add Validation in NFT Contract:**

Add explicit validation in the NFT contract's `Create` method after line 22 to ensure the creator address is valid:

```csharp
var creator = input.Creator ?? Context.Sender;
Assert(!creator.Value.IsNullOrEmpty(), "Invalid creator address.");
```

**Test Cases to Add:**

1. Test attempting to create NFT protocol with `Creator = new Address()` - should fail with "Invalid issuer address"
2. Test attempting to create NFT protocol with `Creator = new Address { Value = ByteString.Empty }` - should fail
3. Verify that legitimate creation with valid addresses still works
4. Add regression tests to ensure address validation is applied consistently across all token creation paths

### Proof of Concept

**Initial State:**
- Attacker has access to call NFT Create method (either via seed NFT or being in whitelist)
- Target NFT protocol symbol is available for creation

**Attack Steps:**

1. Attacker constructs a `CreateInput` message with an empty-value Address:
   ```
   CreateInput {
       NftType = "Art",
       ProtocolName = "BrickedProtocol", 
       TotalSupply = 1000000,
       Creator = new Address(),  // Empty Value field
       IsBurnable = true,
       BaseUri = "ipfs://example/",
       // ... other fields
   }
   ```

2. Attacker calls `NFTContract.Create()` with this input

3. **Expected Result**: Transaction should fail with "Invalid issuer address"

4. **Actual Result**: 
   - Transaction succeeds
   - NFT protocol is created with symbol (e.g., "AR-0")
   - Protocol's `Creator` field is set to the empty-value Address
   - Protocol is stored in `State.NftProtocolMap`

5. **Verification of Bricked State:**
   - Any attempt to call `Mint()` on this protocol fails with "No permission to mint" because the minter list contains the empty-value address which never matches any real `Context.Sender`
   - Any attempt to call `AddMinters()` fails with "No permission" because `Context.Sender == protocolInfo.Creator` is always false
   - The protocol is permanently unusable with no recovery mechanism

**Success Condition:** The protocol is created successfully but cannot be used for any operations, confirming the permanent bricking vulnerability.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L22-22)
```csharp
        var creator = input.Creator ?? Context.Sender;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L23-34)
```csharp
        var tokenCreateInput = new MultiToken.CreateInput
        {
            Symbol = symbol,
            Decimals = 0, // Fixed
            Issuer = creator,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId,
            TokenName = input.ProtocolName,
            TotalSupply = input.TotalSupply,
            ExternalInfo = tokenExternalInfo
        };
        State.TokenContract.Create.Send(tokenCreateInput);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L40-53)
```csharp
        var protocolInfo = new NFTProtocolInfo
        {
            Symbol = symbol,
            BaseUri = input.BaseUri,
            TotalSupply = tokenCreateInput.TotalSupply,
            Creator = tokenCreateInput.Issuer,
            Metadata = new Metadata { Value = { tokenExternalInfo.Value } },
            ProtocolName = tokenCreateInput.TokenName,
            IsTokenIdReuse = input.IsTokenIdReuse,
            IssueChainId = tokenCreateInput.IssueChainId,
            IsBurnable = tokenCreateInput.IsBurnable,
            NftType = input.NftType
        };
        State.NftProtocolMap[symbol] = protocolInfo;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L230-230)
```csharp
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-65)
```csharp
            if (!IsAddressInCreateWhiteList(Context.Sender) &&
                input.Symbol != TokenContractConstants.SeedCollectionSymbol)
            {
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L646-647)
```csharp
        Assert(input.Issuer != null && !input.Issuer.Value.IsNullOrEmpty(), "Invalid input issuer.");
        Assert(input.Owner != null && !input.Owner.Value.IsNullOrEmpty(), "Invalid input owner.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L338-338)
```csharp
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L375-381)
```csharp
    private MinterList GetMinterList(TokenInfo tokenInfo)
    {
        var minterList = State.MinterListMap[tokenInfo.Symbol] ?? new MinterList();
        if (!minterList.Value.Contains(tokenInfo.Issuer)) minterList.Value.Add(tokenInfo.Issuer);

        return minterList;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L399-399)
```csharp
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
