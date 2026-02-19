### Title
Inconsistent Null Handling in GetNFTProtocolInfo and Related Functions Causes NullReferenceException

### Summary
The `GetNFTProtocolInfo()` view method returns null directly when querying non-existent NFT protocols, violating the established codebase pattern of returning empty protobuf instances. This inconsistent null handling extends to multiple state-changing functions (`AddMinters`, `RemoveMinters`, `Burn`, `GetNFTInfoByTokenHash`) that access `State.NftProtocolMap` properties without null checks, causing NullReferenceException when protocols don't exist.

### Finding Description

**Primary Issue Location:** [1](#0-0) 

The `GetNFTProtocolInfo()` method directly returns `State.NftProtocolMap[input.Value]` without null-coalescing or null-assertion. When a protocol symbol doesn't exist in the state map, it returns null to callers.

**Established Pattern Violation:**
The codebase consistently uses null-coalescing operators in view methods: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

Even within the same file, `GetNFTInfoByTokenHash` properly handles null: [6](#0-5) 

However, it then accesses `State.NftProtocolMap[nftInfo.Symbol]` properties without null checking (lines 24-28), which will throw NullReferenceException if the protocol doesn't exist.

**Critical Functions Affected by Missing Null Checks:**

1. **AddMinters** - Accesses `protocolInfo.Creator` without null check: [7](#0-6) 

2. **RemoveMinters** - Accesses `protocolInfo.Creator` without null check: [8](#0-7) 

3. **Burn** - Accesses `protocolInfo.IsBurnable` without null check: [9](#0-8) 

**Correct Pattern Examples in Same Contract:**

The contract demonstrates awareness of this issue in some functions: [10](#0-9) [11](#0-10) 

**Root Cause:** [12](#0-11) 

`CrossChainCreate` explicitly checks for null (line 79), confirming that `State.NftProtocolMap` can return null for non-existent entries. However, there is no method to delete protocols, meaning null states occur during:
- Cross-chain synchronization delays before `CrossChainCreate` completes
- User input errors (typos in symbol names)
- Queries for protocols that were never created

### Impact Explanation

**Operational Disruption:**
1. **View Method Inconsistency**: `GetNFTProtocolInfo` returns null, causing client-side deserialization errors or unexpected null handling requirements, while all other view methods in the codebase return empty protobuf instances.

2. **NullReferenceException in Critical Functions**:
   - `AddMinters` throws exception when attempting to verify creator permission on non-existent protocol
   - `RemoveMinters` throws exception when attempting to verify creator permission on non-existent protocol  
   - `Burn` throws exception when checking `IsBurnable` property on non-existent protocol
   - `GetNFTInfoByTokenHash` throws exception when populating NFT info with protocol metadata

3. **Cross-Chain Synchronization Vulnerability**: Between mainchain protocol creation and sidechain `CrossChainCreate` completion, any calls to these functions will fail with NullReferenceException instead of proper validation errors.

**Affected Parties:**
- DApp developers integrating with NFT contract who expect consistent null handling
- Users calling NFT functions during cross-chain synchronization windows
- Smart contracts that call these methods and don't handle NullReferenceException

**Severity Justification:**
Medium severity due to operational impact causing DoS of multiple NFT contract functions, high likelihood of triggering through normal usage patterns (typos, cross-chain delays), and inconsistency with established codebase security patterns.

### Likelihood Explanation

**Reachability:** All affected functions are public methods callable by any user without special permissions (except creator-only checks that fail due to the null issue).

**Triggering Scenarios:**
1. User mistypes protocol symbol when calling `GetNFTProtocolInfo`, `AddMinters`, `RemoveMinters`, or `Burn`
2. Cross-chain scenario where sidechain queries protocol before `CrossChainCreate` synchronization completes
3. Integration errors where wrong symbol passed from external contracts
4. `GetNFTInfoByTokenHash` called with valid token hash but protocol state corrupted/missing

**Execution Practicality:** 
- View methods have zero transaction cost
- State-changing methods fail before any meaningful state changes occur
- No complex preconditions required beyond invalid symbol input

**Detection:** 
- Throws generic NullReferenceException rather than informative validation error
- Stack traces reveal internal contract structure
- Inconsistent with proper error messages in `ApproveProtocol` ("Protocol {symbol} not exists") and `PerformMint` ("Invalid NFT Token symbol")

**Probability:** High - normal user errors or timing issues in cross-chain synchronization guarantee frequent triggering.

### Recommendation

**1. Fix GetNFTProtocolInfo to Follow Codebase Pattern:**
```csharp
public override NFTProtocolInfo GetNFTProtocolInfo(StringValue input)
{
    return State.NftProtocolMap[input.Value] ?? new NFTProtocolInfo();
}
```

**2. Add Null Assertions to State-Changing Functions:**
```csharp
// In AddMinters:
var protocolInfo = State.NftProtocolMap[input.Symbol];
Assert(protocolInfo != null, $"Protocol {input.Symbol} not exists.");

// In RemoveMinters:
var protocolInfo = State.NftProtocolMap[input.Symbol];
Assert(protocolInfo != null, $"Protocol {input.Symbol} not exists.");

// In Burn:
var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
Assert(nftProtocolInfo != null, $"Protocol {input.Symbol} not exists.");
```

**3. Fix GetNFTInfoByTokenHash Null Access:**
```csharp
var nftProtocolInfo = State.NftProtocolMap[nftInfo.Symbol];
if (nftProtocolInfo != null)
{
    nftInfo.ProtocolName = nftProtocolInfo.ProtocolName;
    nftInfo.Creator = nftProtocolInfo.Creator;
    nftInfo.BaseUri = nftProtocolInfo.BaseUri;
    nftInfo.NftType = nftProtocolInfo.NftType;
}
```

**4. Add Regression Tests:**
- Test `GetNFTProtocolInfo` with non-existent symbol returns empty object
- Test `AddMinters`, `RemoveMinters`, `Burn` with non-existent symbol throw clear assertion errors
- Test cross-chain scenario where protocol not yet synchronized
- Test `GetMinterList` which has same issue [13](#0-12) 

### Proof of Concept

**Initial State:**
- NFT contract deployed on sidechain
- No protocols have been created via `CrossChainCreate` yet

**Attack Sequence:**

1. **Trigger GetNFTProtocolInfo null return:**
   ```
   Call: GetNFTProtocolInfo("NONEXISTENT-SYMBOL")
   Expected: Empty NFTProtocolInfo with default values
   Actual: Returns null, causing client deserialization issues
   ```

2. **Trigger NullReferenceException in AddMinters:**
   ```
   Call: AddMinters({Symbol: "NONEXISTENT-SYMBOL", MinterList: [address1]})
   Expected: Assert error "Protocol NONEXISTENT-SYMBOL not exists"
   Actual: NullReferenceException when accessing protocolInfo.Creator at line 338
   ```

3. **Trigger NullReferenceException in Burn:**
   ```
   Call: Burn({Symbol: "NONEXISTENT-SYMBOL", TokenId: 1, Amount: 1})
   Expected: Assert error "Protocol NONEXISTENT-SYMBOL not exists"  
   Actual: NullReferenceException when accessing protocolInfo.IsBurnable at line 87
   ```

4. **Cross-Chain Race Condition:**
   ```
   T0: Mainchain creates NFT protocol "VW-SEED-123456"
   T1: User on sidechain calls GetNFTProtocolInfo("VW-SEED-123456")
   T2: Returns null because CrossChainCreate hasn't synced yet
   T3: CrossChainCreate completes
   T4: Same call now returns valid data
   
   Result: Timing-dependent behavior, inconsistent experience
   ```

**Success Condition:** Any of the above scenarios successfully triggers null return or NullReferenceException, demonstrating the vulnerability.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L9-12)
```csharp
    public override NFTProtocolInfo GetNFTProtocolInfo(StringValue input)
    {
        return State.NftProtocolMap[input.Value];
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L20-30)
```csharp
    public override NFTInfo GetNFTInfoByTokenHash(Hash input)
    {
        var nftInfo = State.NftInfoMap[input];
        if (nftInfo == null) return new NFTInfo();
        var nftProtocolInfo = State.NftProtocolMap[nftInfo.Symbol];
        nftInfo.ProtocolName = nftProtocolInfo.ProtocolName;
        nftInfo.Creator = nftProtocolInfo.Creator;
        nftInfo.BaseUri = nftProtocolInfo.BaseUri;
        nftInfo.NftType = nftProtocolInfo.NftType;
        return nftInfo;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L77-80)
```csharp
    public override MinterList GetMinterList(StringValue input)
    {
        return State.MinterListMap[input.Value];
    }
```

**File:** test/AElf.Contracts.TestContract.BasicSecurity/BasicContract_View.cs (L130-154)
```csharp
    public override ProtobufMessage QueryMappedState(ProtobufInput input)
    {
        var message = State.MappedState[input.ProtobufValue.Int64Value];
        return message ?? new ProtobufMessage();
    }

    public override ProtobufMessage QueryMappedState1(ProtobufInput input)
    {
        var result = State.Complex3Info[input.ProtobufValue.Int64Value][input.ProtobufValue.StringValue];
        return result ?? new ProtobufMessage();
    }

    public override ProtobufMessage QueryMappedState2(ProtobufInput input)
    {
        var message = State.Complex4Info[input.ProtobufValue.Int64Value][input.ProtobufValue.StringValue][
            input.ProtobufValue.StringValue];

        return message ?? new ProtobufMessage();
    }

    public override TradeMessage QueryMappedState3(Complex3Input input)
    {
        var tradeMessage = State.Complex5Info[input.From][input.PairA][input.To][input.PairB];
        return tradeMessage ?? new TradeMessage();
    }
```

**File:** test/AElf.Contracts.TestContract.B/ContractB.cs (L87-90)
```csharp
    public override StringValue CallBB(Address input)
    {
        return State.BState[input] ?? new StringValue();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L13-17)
```csharp
    public override IndexedSideChainBlockData GetIndexedSideChainBlockDataByHeight(Int64Value input)
    {
        var indexedSideChainBlockData = State.IndexedSideChainBlockData[input.Value];
        return indexedSideChainBlockData ?? new IndexedSideChainBlockData();
    }
```

**File:** test/AElf.Contracts.TestContract.Events/EventsContract_View.cs (L73-77)
```csharp
    public override OrderInfo QueryOrderById(Hash input)
    {
        var order = State.AllOrders[input];
        return order ?? new OrderInfo();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L82-110)
```csharp
    public override Empty Burn(BurnInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(nftProtocolInfo.IsBurnable,
            $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
        State.BalanceMap[tokenHash][Context.Sender] = State.BalanceMap[tokenHash][Context.Sender].Sub(input.Amount);
        nftProtocolInfo.Supply = nftProtocolInfo.Supply.Sub(input.Amount);
        nftInfo.Quantity = nftInfo.Quantity.Sub(input.Amount);

        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;
        if (nftInfo.Quantity == 0 && !nftProtocolInfo.IsTokenIdReuse) nftInfo.IsBurned = true;

        State.NftInfoMap[tokenHash] = nftInfo;

        Context.Fire(new Burned
        {
            Burner = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            TokenId = input.TokenId
        });
        return new Empty();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L238-250)
```csharp
    public override Empty ApproveProtocol(ApproveProtocolInput input)
    {
        Assert(State.NftProtocolMap[input.Symbol] != null, $"Protocol {input.Symbol} not exists.");
        var operatorList = State.OperatorMap[input.Symbol][Context.Sender] ?? new AddressList();
        switch (input.Approved)
        {
            case true when !operatorList.Value.Contains(input.Operator):
                operatorList.Value.Add(input.Operator);
                break;
            case false when operatorList.Value.Contains(input.Operator):
                operatorList.Value.Remove(input.Operator);
                break;
        }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L355-365)
```csharp
    public override Empty RemoveMinters(RemoveMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
        var minterList = State.MinterListMap[protocolInfo.Symbol];

        foreach (var minter in input.MinterList.Value)
            if (minterList.Value.Contains(minter))
                minterList.Value.Remove(minter);

        State.MinterListMap[input.Symbol] = minterList;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L383-415)
```csharp
    private NFTMinted PerformMint(MintInput input, bool isTokenIdMustBeUnique = false)
    {
        var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
        {
            Symbol = input.Symbol
        });
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        if (protocolInfo == null) throw new AssertionException($"Invalid NFT Token symbol: {input.Symbol}");

        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
        var nftInfo = State.NftInfoMap[tokenHash];
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");

        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Incorrect chain.");

        var quantity = input.Quantity > 0 ? input.Quantity : 1;
        protocolInfo.Supply = protocolInfo.Supply.Add(quantity);
        protocolInfo.Issued = protocolInfo.Issued.Add(quantity);
        Assert(protocolInfo.Issued <= protocolInfo.TotalSupply, "Total supply exceeded.");
        State.NftProtocolMap[input.Symbol] = protocolInfo;

        // Inherit from protocol info.
        var nftMetadata = protocolInfo.Metadata.Clone();
        if (input.Metadata != null)
            foreach (var pair in input.Metadata.Value)
                if (!nftMetadata.Value.ContainsKey(pair.Key))
                    nftMetadata.Value[pair.Key] = pair.Value;

        if (nftInfo == null)
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-129)
```csharp
    public override Empty CrossChainCreate(CrossChainCreateInput input)
    {
        MakeSureTokenContractAddressSet();
        InitialNFTTypeNameMap();
        Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
        var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
        {
            Symbol = input.Symbol
        });
        if (string.IsNullOrEmpty(tokenInfo.Symbol))
            throw new AssertionException($"Token info {input.Symbol} not exists.");

        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");

        var nftProtocolInfo = new NFTProtocolInfo
        {
            Symbol = input.Symbol,
            TotalSupply = tokenInfo.TotalSupply,
            BaseUri = baseUri,
            Creator = tokenInfo.Issuer,
            IsBurnable = tokenInfo.IsBurnable,
            IssueChainId = tokenInfo.IssueChainId,
            IsTokenIdReuse = isTokenIdReuse,
            Metadata = new Metadata { Value = { tokenInfo.ExternalInfo.Value } },
            ProtocolName = tokenInfo.TokenName,
            NftType = nftTypeFullName
        };
        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;

        State.MinterListMap[input.Symbol] = new MinterList
        {
            Value = { nftProtocolInfo.Creator }
        };

        Context.Fire(new NFTProtocolCreated
        {
            Symbol = input.Symbol,
            Creator = nftProtocolInfo.Creator,
            IsBurnable = nftProtocolInfo.IsBurnable,
            IssueChainId = nftProtocolInfo.IssueChainId,
            ProtocolName = nftProtocolInfo.ProtocolName,
            TotalSupply = nftProtocolInfo.TotalSupply,
            Metadata = nftProtocolInfo.Metadata,
            BaseUri = nftProtocolInfo.BaseUri,
            IsTokenIdReuse = isTokenIdReuse,
            NftType = nftProtocolInfo.NftType
        });
        return new Empty();
    }
```
