# Audit Report

## Title
Hash Collision in NFT Token Identification Causes Cross-Protocol Balance and State Corruption

## Summary
The NFT contract's `CalculateTokenHash` function concatenates symbol and tokenId without a delimiter, creating hash collisions between different protocols when symbol lengths transition from N to N+1 digits. This causes critical state corruption across balance maps, metadata storage, allowances, and assembly data, affecting all NFT holders during protocol count growth phases.

## Finding Description

The vulnerability originates from the `CalculateTokenHash` implementation that performs direct string concatenation: [1](#0-0) 

NFT protocol symbols follow the format `{2-letter-prefix}{N-digit-number}`, where the number length starts at 9 digits and dynamically increases: [2](#0-1) [3](#0-2) 

The length transition logic increments the digit count as protocol creation grows: [4](#0-3) 

**Collision Mechanism:**
When transitioning from 9-digit to 10-digit symbols:
- Protocol A: "AR123456789" (9 digits) + tokenId "123" → concatenation: "AR123456789123"
- Protocol B: "AR1234567891" (10 digits) + tokenId "23" → concatenation: "AR123456789123"
- **Result: Identical tokenHash despite different protocols and tokenIds**

All state maps are indexed by this colliding tokenHash: [5](#0-4) 

Critical operations use the vulnerable hash calculation:
- GetBalance retrieves balances: [6](#0-5) 
- Transfer/Burn operations: [7](#0-6) 
- Approve operations: [8](#0-7) 

The minting process allows arbitrary tokenId specification and stores data at the colliding hash: [9](#0-8) 

The uniqueness validation at line 395-396 fails to prevent cross-protocol collisions because it checks `NftInfoMap[tokenHash]` where tokenHash itself is the collision point. When `IsTokenIdReuse=false` (protobuf default), the second mint fails with a misleading error. When `IsTokenIdReuse=true`, the code at lines 433-437 incorrectly treats the collision as a legitimate re-mint, corrupting the original NFT's quantity and minter list.

## Impact Explanation

**Critical State Corruption Across Multiple Dimensions:**

1. **Balance Mixing**: The `BalanceMap[tokenHash][owner]` structure aggregates balances from unrelated protocols. Users querying balance for ("AR123456789", tokenId=123) receive incorrect totals that include balances from ("AR1234567891", tokenId=23).

2. **NFT Metadata Corruption**: The `NftInfoMap[tokenHash]` either blocks the second protocol's mint (causing DoS) or when `IsTokenIdReuse=true`, incorrectly increments the first protocol's NFT quantity and adds the second protocol's minter to the minter list, fundamentally corrupting the NFT's identity and provenance.

3. **Allowance Confusion**: The `AllowanceMap[tokenHash][owner][spender]` shares approval state between completely unrelated NFTs from different protocols, potentially enabling unauthorized transfers where a user approves Protocol A's NFT but inadvertently grants access to Protocol B's colliding NFT.

4. **Assembly Data Corruption**: The `AssembledNftsMap` and `AssembledFtsMap` store component relationships at incorrect keys, causing disassembly operations to fail or return wrong components.

**Fund and Supply Impact**: Protocol supply accounting becomes inaccurate. Users experience incorrect balance queries that could lead to economic decisions based on false data. NFT metadata corruption affects provenance tracking and authenticity verification. The DoS effect prevents legitimate minting of specific tokenIds in new protocols.

**Affected Parties**: All users holding NFTs from protocols created during or after symbol length transitions (9→10, 10→11 digits, etc.), and any dApps querying NFT balances across multiple protocols for portfolio tracking or marketplace operations.

## Likelihood Explanation

**Attacker Capabilities:**
- Protocol creation requires only mainchain access with 100 ELF fee (no governance approval) [10](#0-9) 
- Minters can specify arbitrary tokenIds when minting [11](#0-10) 

**Attack Execution:**
1. Monitor protocol count approaching digit length transitions (e.g., 500M protocols for 9→10 transition)
2. Create one or more protocols during the transition window
3. Calculate which tokenIds will collide with existing protocols' NFTs
4. Mint NFTs with calculated tokenIds to trigger collisions

**Feasibility: HIGH**
- Occurs naturally as ecosystem grows beyond 10^9, 10^10, etc. protocol counts
- Multiple collision opportunities exist at each length transition
- Attack cost is minimal (100 ELF per protocol creation)
- Collisions are deterministic once symbol numbers are known
- Detection is difficult as operations appear legitimate

The mathematical inevitability of collisions during length transitions, combined with permissionless protocol creation and arbitrary tokenId specification, makes this a high-likelihood vulnerability as the protocol scales.

## Recommendation

**Fix: Add delimiter in hash calculation**

Replace the vulnerable concatenation in `CalculateTokenHash`:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}:{tokenId}");  // Add delimiter
}
```

The delimiter (`:`) ensures that different (symbol, tokenId) combinations always produce different pre-hash strings, eliminating collision opportunities regardless of symbol length transitions.

**Alternative: Use structured hashing**

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(symbol),
        HashHelper.ComputeFrom(tokenId)
    );
}
```

This approach hashes components separately before combining them, providing cryptographic separation.

## Proof of Concept

```csharp
[Fact]
public void HashCollision_CrossProtocol_Test()
{
    // Setup: Create protocol with 9-digit number
    var protocol1Symbol = "AR123456789"; // 2 letters + 9 digits
    var tokenId1 = 123L;
    
    // Setup: Create protocol with 10-digit number (simulating length transition)
    var protocol2Symbol = "AR1234567891"; // 2 letters + 10 digits
    var tokenId2 = 23L;
    
    // Calculate hashes using current vulnerable implementation
    var hash1 = CalculateTokenHash(protocol1Symbol, tokenId1);
    var hash2 = CalculateTokenHash(protocol2Symbol, tokenId2);
    
    // Verify collision
    hash1.ShouldBe(hash2); // PASSES - demonstrates vulnerability
    
    // Demonstrate impact: mint NFT from protocol1, then protocol2 mints with colliding tokenId
    // Result: BalanceMap[hash1] and BalanceMap[hash2] point to same storage location
    // causing balance mixing and metadata corruption
}

private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}{tokenId}");
}
```

## Notes

The vulnerability is rooted in a fundamental design flaw in the hashing scheme that becomes exploitable as the protocol scales. The lack of delimiter between variable-length components creates mathematical collision opportunities that cannot be prevented by access controls or validation logic. The issue affects core NFT functionality including balance queries, transfers, approvals, and assembly operations. Immediate remediation is critical before protocol count approaches the first length transition threshold (approximately 10^9 protocols for the 9→10 digit transition).

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L21-35)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L295-308)
```csharp
    public override Empty Approve(ApproveInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = input.Amount;
        Context.Fire(new Approved
        {
            Owner = Context.Sender,
            Spender = input.Spender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            TokenId = input.TokenId
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L383-463)
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
        {
            nftInfo = new NFTInfo
            {
                Symbol = input.Symbol,
                Uri = input.Uri ?? string.Empty,
                TokenId = tokenId,
                Metadata = nftMetadata,
                Minters = { Context.Sender },
                Quantity = quantity,
                Alias = input.Alias

                // No need.
                //BaseUri = protocolInfo.BaseUri,
                //Creator = protocolInfo.Creator,
                //ProtocolName = protocolInfo.ProtocolName
            };
        }
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
        }

        State.NftInfoMap[tokenHash] = nftInfo;
        var owner = input.Owner ?? Context.Sender;
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);

        var nftMinted = new NFTMinted
        {
            Symbol = input.Symbol,
            ProtocolName = protocolInfo.ProtocolName,
            TokenId = tokenId,
            Metadata = nftMetadata,
            Owner = owner,
            Minter = Context.Sender,
            Quantity = quantity,
            Alias = input.Alias,
            BaseUri = protocolInfo.BaseUri,
            Uri = input.Uri ?? string.Empty,
            Creator = protocolInfo.Creator,
            NftType = protocolInfo.NftType,
            TotalQuantity = nftInfo.Quantity,
            TokenHash = tokenHash
        };
        Context.Fire(nftMinted);

        return nftMinted;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-36)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }

        return $"{shortName}{randomNumber}";
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L87-116)
```csharp
    private int GetCurrentNumberLength()
    {
        if (State.CurrentSymbolNumberLength.Value == 0) State.CurrentSymbolNumberLength.Value = NumberMinLength;

        var flag = State.NftProtocolNumberFlag.Value;

        if (flag == 0)
        {
            // Initial protocol number flag.
            var protocolNumber = 1;
            for (var i = 1; i < State.CurrentSymbolNumberLength.Value; i++) protocolNumber = protocolNumber.Mul(10);

            State.NftProtocolNumberFlag.Value = protocolNumber;
            flag = protocolNumber;
        }

        var upperNumberFlag = flag.Mul(2);
        if (upperNumberFlag.ToString().Length > State.CurrentSymbolNumberLength.Value)
        {
            var newSymbolNumberLength = State.CurrentSymbolNumberLength.Value.Add(1);
            State.CurrentSymbolNumberLength.Value = newSymbolNumberLength;
            var protocolNumber = 1;
            for (var i = 1; i < newSymbolNumberLength; i++) protocolNumber = protocolNumber.Mul(10);

            State.NftProtocolNumberFlag.Value = protocolNumber;
            return newSymbolNumberLength;
        }

        return State.CurrentSymbolNumberLength.Value;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L17-33)
```csharp
    public MappedState<Hash, NFTInfo> NftInfoMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Balance
    /// </summary>
    public MappedState<Hash, Address, long> BalanceMap { get; set; }

    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }

    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L32-42)
```csharp
    public override GetBalanceOutput GetBalance(GetBalanceInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var balance = State.BalanceMap[tokenHash][input.Owner];
        return new GetBalanceOutput
        {
            Owner = input.Owner,
            Balance = balance,
            TokenHash = tokenHash
        };
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-20)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
```
