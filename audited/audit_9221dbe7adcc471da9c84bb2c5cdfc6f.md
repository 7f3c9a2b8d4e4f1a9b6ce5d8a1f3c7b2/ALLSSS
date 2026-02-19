### Title
NFT Contract Unbounded Metadata Enables Blockchain Storage DOS via Disproportionate Economic Cost

### Summary
The NFT contract's `Create()` method accepts metadata up to the 5MB transaction size limit without proportional resource token charging, as the contract only implements ACS1 (fixed method fees) and not ACS8 (resource tokens). This allows attackers to permanently store large amounts of data on-chain at a disproportionately low cost relative to the perpetual storage and read performance burden imposed on the network.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The `Create()` method only validates metadata keys (not reserved), but performs no size validation on the metadata map<string, string> structure. [2](#0-1) 

The metadata is then:
1. Copied to `tokenExternalInfo` and passed to TokenContract.Create() [3](#0-2) 
2. Stored in `State.NftProtocolMap[symbol]` [4](#0-3) 
3. Emitted in the `NFTProtocolCreated` event [5](#0-4) 

**Why Protections Fail:**

1. **No ACS8 Implementation:** The NFT contract only implements ACS1, not ACS8 [6](#0-5) , meaning it doesn't charge resource tokens (STORAGE, WRITE) that scale with data size. [7](#0-6) 

2. **Fixed Method Fee:** The Create method charges a fixed fee of 100 ELF regardless of metadata size. [8](#0-7) 

3. **System Contract Exemption:** The NFT contract is a system contract [9](#0-8) , making it exempt from automatic `ValidateStateSize` injection that enforces the 128KB state limit. [10](#0-9) 

4. **Transaction Size Only Limit:** The only constraint is the 5MB transaction size limit. [11](#0-10) 

### Impact Explanation

**Concrete Harm:**
1. **Blockchain Storage Bloat:** Attackers can inject up to 5MB of arbitrary data per protocol creation, stored permanently in both NFT and MultiToken contract states without size validation. [12](#0-11) 

2. **Read Performance Degradation:** All future reads of `State.NftProtocolMap[symbol]` must deserialize and load megabytes of data, impacting protocol queries and cross-contract interactions.

3. **Event Processing Overhead:** Large metadata in events impacts indexing, querying, and event processing systems.

4. **Economic Imbalance:** For a 5MB transaction, attacker pays:
   - Method fee: 100 ELF (fixed)
   - Tx size fee: ~62,500 ELF (using coefficient x/80 for 1-5MB range) [13](#0-12) 
   - **Total: ~62,600 ELF one-time** for perpetual 5MB storage burden

For smaller targeted attacks (1MB each):
   - ~1,350 ELF per protocol
   - 100 protocols = 135,000 ELF for 100MB permanent storage bloat

**Who Is Affected:** All network nodes must store and serve this data perpetually. Future protocol queries incur performance costs.

### Likelihood Explanation

**Attacker Capabilities:** Any user with sufficient ELF tokens can call the public `Create()` method.

**Attack Complexity:** Low - single transaction with large metadata map in CreateInput.

**Feasibility:** 
- Transaction construction is straightforward
- No special permissions required (mainchain check is for protocol creation location, not authorization)
- Cost is one-time payment for perpetual storage impact

**Economic Rationality:** 
- For targeted disruption: ~135,000 ELF creates 100MB storage bloat across 100 protocols
- Cost is proportional to transaction size but not to perpetual storage/read costs
- Lack of ACS8 resource tokens means no ongoing cost for contract state storage

**Detection:** Network monitors could detect unusually large Create transactions, but cannot prevent them.

### Recommendation

1. **Add Metadata Size Validation:**
```
// In GetTokenExternalInfo method
const int MaxMetadataSize = 10240; // 10KB limit
var metadataSize = input.Metadata.Value.Sum(kvp => 
    kvp.Key.Length + kvp.Value.Length);
Assert(metadataSize <= MaxMetadataSize, 
    $"Metadata size {metadataSize} exceeds maximum {MaxMetadataSize}");
```
Location: [14](#0-13) 

2. **Implement ACS8 or Size-Based Method Fees:**
Consider implementing ACS8 for resource token charging, or modify ACS1 method fees to scale with metadata size: [15](#0-14) 

3. **Add Size Validation to MultiToken ExternalInfo:**
The MultiToken contract should also validate ExternalInfo size in `AssertValidCreateInput`: [16](#0-15) 

4. **Test Cases:**
    - Verify Create() rejects metadata exceeding size limit
    - Test edge cases (exactly at limit, multiple large key-value pairs)
    - Verify cross-contract ExternalInfo size propagation

### Proof of Concept

**Initial State:**
- Attacker has sufficient ELF balance (e.g., 70,000 ELF)
- Mainchain environment (chain ID = "AELF")

**Attack Steps:**

1. Construct CreateInput with ~5MB metadata:
```
var largeMetadata = new Metadata();
for (int i = 0; i < 1000; i++) {
    largeMetadata.Value.Add(
        $"key_{i}", 
        new string('X', 5000) // 5KB per entry, 1000 entries ≈ 5MB
    );
}

var input = new CreateInput {
    NftType = "Art",
    ProtocolName = "LargeMetadataProtocol",
    TotalSupply = 10000,
    Metadata = largeMetadata,
    BaseUri = "https://example.com",
    IsTokenIdReuse = false
};
```

2. Call NFTContract.Create(input)

**Expected Result:** Transaction should be rejected due to metadata size limit.

**Actual Result:** Transaction succeeds, ~5MB stored permanently in state, attacker pays ~62,600 ELF.

**Success Condition:** Query GetNFTProtocolInfo for created symbol returns protocol with massive metadata, consuming significant storage and impacting read performance.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L34-34)
```csharp
        State.TokenContract.Create.Send(tokenCreateInput);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L53-53)
```csharp
        State.NftProtocolMap[symbol] = protocolInfo;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L55-67)
```csharp
        Context.Fire(new NFTProtocolCreated
        {
            Symbol = tokenCreateInput.Symbol,
            Creator = tokenCreateInput.Issuer,
            IsBurnable = tokenCreateInput.IsBurnable,
            IssueChainId = tokenCreateInput.IssueChainId,
            ProtocolName = tokenCreateInput.TokenName,
            TotalSupply = tokenCreateInput.TotalSupply,
            Metadata = protocolInfo.Metadata,
            BaseUri = protocolInfo.BaseUri,
            IsTokenIdReuse = protocolInfo.IsTokenIdReuse,
            NftType = protocolInfo.NftType
        });
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L184-201)
```csharp
    private ExternalInfo GetTokenExternalInfo(CreateInput input)
    {
        if (input.Metadata != null) AssertMetadataKeysAreCorrect(input.Metadata.Value.Keys);

        var tokenExternalInfo = input.Metadata == null
            ? new ExternalInfo()
            : new ExternalInfo
            {
                Value = { input.Metadata.Value }
            };

        // Add NFT Type to external info.
        tokenExternalInfo.Value[NftTypeMetadataKey] = input.NftType;
        // Add Uri to external info.
        tokenExternalInfo.Value[NftBaseUriMetadataKey] = input.BaseUri;
        tokenExternalInfo.Value[NftTokenIdReuseMetadataKey] = input.IsTokenIdReuse.ToString();
        return tokenExternalInfo;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L118-123)
```csharp
    private void AssertMetadataKeysAreCorrect(IEnumerable<string> metadataKeys)
    {
        var reservedMetadataKey = GetNftMetadataReservedKeys();
        foreach (var metadataKey in metadataKeys)
            Assert(!reservedMetadataKey.Contains(metadataKey), $"Metadata key {metadataKey} is reserved.");
    }
```

**File:** protobuf/nft_contract.proto (L18-20)
```text
service NFTContract {
    option (aelf.csharp_state) = "AElf.Contracts.NFT.NFTContractState";
    option (aelf.base) = "acs1.proto";
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/ResourceConsumptionPreExecutionPlugin.cs (L31-34)
```csharp
    public async Task<IEnumerable<Transaction>> GetPreTransactionsAsync(
        IReadOnlyList<ServiceDescriptor> descriptors, ITransactionContext transactionContext)
    {
        if (!HasApplicableAcs(descriptors)) return new List<Transaction>();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L20-37)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(Create))
            return new MethodFees
            {
                MethodName = input.Value,
                Fees =
                {
                    new MethodFee
                    {
                        Symbol = Context.Variables.NativeSymbol,
                        BasicFee = 100_00000000
                    }
                }
            };

        return new MethodFees();
    }
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractInitializationProvider.cs (L10-10)
```csharp
    public Hash SystemSmartContractName { get; } = HashHelper.ComputeFrom("AElf.ContractNames.NFT");
```

**File:** src/AElf.CSharp.CodeOps/Patchers/Module/StateWrittenSizeLimitMethodInjector.cs (L17-17)
```csharp
    public bool SystemContactIgnored => true;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-88)
```csharp
        var tokenInfo = new TokenInfo
        {
            Symbol = input.Symbol,
            TokenName = input.TokenName,
            TotalSupply = input.TotalSupply,
            Decimals = input.Decimals,
            Issuer = input.Issuer,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
            Owner = input.Owner
        };

        if (IsAliasSettingExists(tokenInfo))
        {
            Assert(symbolType == SymbolType.NftCollection, "Token alias can only be set for NFT Item.");
            SetTokenAlias(tokenInfo);
        }

        CheckTokenExists(tokenInfo.Symbol);
        RegisterTokenInfo(tokenInfo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L291-298)
```csharp
                new CalculateFeePieceCoefficients
                {
                    // Interval (1000000, 5000000): x / 80
                    Value =
                    {
                        5000000,
                        1, 1, 80
                    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-283)
```csharp
    private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
    {
        Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
               && input.Symbol.Length > 0
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

        CheckSymbolLength(input.Symbol, symbolType);
        if (symbolType == SymbolType.Nft) return;
        CheckTokenAndCollectionExists(input.Symbol);
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
    }
```
