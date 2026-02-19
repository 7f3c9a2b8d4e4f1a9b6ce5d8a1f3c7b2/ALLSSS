### Title
Cross-Chain NFT Minter Privilege Loss Due to Incomplete State Synchronization

### Summary
The NFT contract's `Create()` method accepts a custom minter list, but the `CrossChainCreate()` method only initializes the creator as the sole minter on the destination chain. This causes non-creator minters to lose their minting privileges when an NFT protocol is synchronized across chains, breaking cross-chain operational consistency and requiring manual intervention to restore access.

### Finding Description

**Exact Code Locations:**

In `Create()`, custom minter lists are accepted and stored: [1](#0-0) 

In `CrossChainCreate()`, only the creator is initialized as a minter: [2](#0-1) 

The minting operation checks this minter list and requires the sender to be included: [3](#0-2) 

**Root Cause:**

The minter list is stored in `State.MinterListMap[symbol]` in the NFT contract's state, but this information is NOT encoded in the token's external info or any cross-chain transferable data structure. When `CrossChainCreate()` executes, it retrieves token information from the MultiToken contract which only contains the issuer address, not the custom minter list. The `GetMinterList()` helper function ensures the issuer is always in the minter list: [4](#0-3) 

However, `CrossChainCreate()` explicitly creates a NEW `MinterList` with only the creator, overwriting any potential to preserve additional minters.

**Why Protections Fail:**

The `CrossChainCreate()` method has no mechanism to retrieve or preserve the original minter list from the source chain. It only checks that the protocol doesn't already exist and that token info exists: [5](#0-4) 

There is no authorization check preventing anyone from calling `CrossChainCreate()`, and no validation that the minter list matches the source chain.

### Impact Explanation

**Direct Privilege Loss:**
- Addresses granted minting privileges on the MainChain via the custom `minter_list` parameter lose their ability to mint NFTs on SideChains
- Only the creator retains minting capability on the destination chain

**Operational Impact:**
- Multi-minter NFT protocols cannot operate consistently across chains without manual intervention
- The creator must call `AddMinters()` on each destination chain to restore privileges: [6](#0-5) 

**Who is Affected:**
- NFT protocol creators who delegate minting to multiple addresses
- Authorized minters who expect cross-chain minting capabilities
- DApps and services relying on consistent minter permissions across chains

**Severity Justification:**
HIGH severity because:
1. Direct and immediate privilege loss occurs
2. Breaks fundamental cross-chain state consistency guarantees
3. Affects core NFT minting functionality
4. Requires manual remediation for each affected protocol on each chain
5. Could cause operational disruption if minters attempt to mint without realizing their privileges were lost

### Likelihood Explanation

**Attack Complexity:**
LOW - This occurs through normal cross-chain synchronization operations, not requiring any exploit or special attacker capabilities.

**Execution Path:**
1. User creates NFT protocol on MainChain with custom minter list `[Creator, Minter1, Minter2]`
2. Token is synchronized to SideChain via MultiToken's `CrossChainCreateToken` mechanism
3. `CrossChainCreate()` is called on the SideChain NFT contract (can be called by anyone)
4. Minter list is initialized as `[Creator]` only
5. `Minter1` and `Minter2` cannot mint on SideChain despite MainChain privileges

**Feasibility Conditions:**
- Standard cross-chain flow with no special preconditions required
- `CrossChainCreate()` is publicly callable with no authorization checks
- Occurs deterministically whenever a multi-minter NFT protocol is synced

**Probability:**
CERTAIN - This will occur 100% of the time when an NFT protocol with multiple minters is synchronized from MainChain to a SideChain.

### Recommendation

**Code-Level Mitigation:**

1. **Encode minter list in token external info during Create():**
   Serialize the minter list into the token's external info so it can be retrieved during cross-chain synchronization.

2. **Retrieve and restore minter list in CrossChainCreate():**
   Modify `CrossChainCreate()` to parse the minter list from token external info and initialize `State.MinterListMap[input.Symbol]` with the complete list.

3. **Add invariant checks:**
   - Assert that token external info contains minter list metadata
   - Validate minter list deserialization succeeds
   - Log warning events if minter list cannot be retrieved

4. **Test cases to prevent regression:**
   - Create NFT with multiple minters on MainChain
   - Sync to SideChain via CrossChainCreate
   - Verify all minters can mint on SideChain
   - Verify GetMinterList returns identical lists on both chains

**Example Fix Pattern:**
```
// In GetTokenExternalInfo:
tokenExternalInfo.Value["__minter_list__"] = SerializeMinterList(input.MinterList);

// In CrossChainCreate:
var minterListData = tokenInfo.ExternalInfo.Value["__minter_list__"];
var minterList = DeserializeMinterList(minterListData);
State.MinterListMap[input.Symbol] = minterList;
```

### Proof of Concept

**Required Initial State:**
- MainChain and SideChain deployed with NFT and MultiToken contracts
- Cross-chain indexing configured between chains

**Transaction Sequence:**

1. **On MainChain - Create NFT with multiple minters:**
   ```
   NFTContract.Create({
     nft_type: "ART",
     protocol_name: "TestNFT",
     total_supply: 1000,
     creator: CreatorAddress,
     minter_list: [CreatorAddress, Minter1Address, Minter2Address],
     ...
   })
   ```
   
2. **Verify minters on MainChain:**
   ```
   GetMinterList("TESTNFT-0") 
   => Returns: [CreatorAddress, Minter1Address, Minter2Address]
   ```

3. **Sync token to SideChain:**
   ```
   MultiToken.CrossChainCreateToken(...) // Standard cross-chain flow
   ```

4. **On SideChain - Initialize NFT protocol:**
   ```
   NFTContract.CrossChainCreate({symbol: "TESTNFT-0"})
   ```

5. **Verify minters on SideChain:**
   ```
   GetMinterList("TESTNFT-0")
   => Returns: [CreatorAddress]  // Minter1 and Minter2 are missing!
   ```

6. **Attempt to mint as Minter1 on SideChain:**
   ```
   Context.Sender = Minter1Address
   NFTContract.Mint({symbol: "TESTNFT-0", ...})
   => FAILS with "No permission to mint."
   ```

**Expected vs Actual Result:**
- **Expected:** All minters from MainChain can mint on SideChain
- **Actual:** Only the creator can mint on SideChain; other minters are rejected

**Success Condition:**
The vulnerability is confirmed when `GetMinterList` returns different results on MainChain vs SideChain after cross-chain synchronization, and non-creator minters cannot mint on the destination chain.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L36-38)
```csharp
        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L79-85)
```csharp
        Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
        var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
        {
            Symbol = input.Symbol
        });
        if (string.IsNullOrEmpty(tokenInfo.Symbol))
            throw new AssertionException($"Token info {input.Symbol} not exists.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L110-113)
```csharp
        State.MinterListMap[input.Symbol] = new MinterList
        {
            Value = { nftProtocolInfo.Creator }
        };
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L335-353)
```csharp
    public override Empty AddMinters(AddMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
        var minterList = State.MinterListMap[protocolInfo.Symbol] ?? new MinterList();

        foreach (var minter in input.MinterList.Value)
            if (!minterList.Value.Contains(minter))
                minterList.Value.Add(minter);

        State.MinterListMap[input.Symbol] = minterList;

        Context.Fire(new MinterListAdded
        {
            Symbol = input.Symbol,
            MinterList = input.MinterList
        });
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-400)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Incorrect chain.");
```
