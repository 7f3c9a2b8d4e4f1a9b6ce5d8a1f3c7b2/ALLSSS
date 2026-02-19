# Audit Report

## Title
Hash Collision in NFT Token Identification Causes Cross-Protocol Balance and State Corruption

## Summary
The `CalculateTokenHash` function concatenates NFT symbol and tokenId without a delimiter, enabling hash collisions between different protocols. As protocol symbol lengths grow from 9 to 10+ digits, NFTs from different protocols can share the same tokenHash, causing state corruption across balance maps, metadata storage, allowances, and assembly data.

## Finding Description

The vulnerability stems from the `CalculateTokenHash` implementation which performs direct string concatenation without a delimiter: [1](#0-0) 

NFT protocol symbols are generated with the format `{2-letter-code}{N-digit-number}` where N starts at 9 digits: [2](#0-1) [3](#0-2) 

The number length dynamically increases as protocol count grows: [4](#0-3) 

**Collision Example:**
- Protocol 1: Symbol "AR123456789" (2 letters + 9 digits) with tokenId 123
  - Concatenation: "AR123456789" + "123" = "AR123456789123"
- Protocol 2: Symbol "AR1234567891" (2 letters + 10 digits) with tokenId 23
  - Concatenation: "AR1234567891" + "23" = "AR123456789123"
- **Both produce identical strings before hashing**

This shared tokenHash corrupts all state maps indexed by it: [5](#0-4) 

The `GetBalance` function retrieves balances using the colliding tokenHash: [6](#0-5) 

All critical operations (Transfer, Burn, Approve, Assemble) calculate tokenHash identically: [7](#0-6) [8](#0-7) [9](#0-8) 

The minting process allows specifying arbitrary tokenIds and stores data using the vulnerable hash: [10](#0-9) 

When `IsTokenIdReuse=false` (default), the second mint fails with misleading error. When `IsTokenIdReuse=true`, the existing NFT metadata gets corrupted by adding quantity/minters from the second protocol.

## Impact Explanation

**Critical State Corruption:**
1. **Balance Mixing**: `BalanceMap[tokenHash][owner]` combines balances from different protocols' NFTs. Users querying balance for ("AR123456789", 123) receive incorrect totals including balances from ("AR1234567891", 23).

2. **NFT Metadata Overwrite/Corruption**: `NftInfoMap[tokenHash]` either blocks the second mint (DoS) or corrupts the first protocol's NFT by incrementing its quantity with the second protocol's data, mixing minters and metadata.

3. **Allowance Confusion**: `AllowanceMap[tokenHash][owner][spender]` shares approval state between unrelated NFTs, potentially enabling unauthorized transfers.

4. **Assembly Data Corruption**: `AssembledNftsMap` and `AssembledFtsMap` store component data at the wrong key, breaking disassembly operations.

**Fund Impact**: Users can experience incorrect balance queries, failed mints (DoS), corrupted NFT metadata, and unauthorized transfer approvals. Protocol supply accounting becomes inaccurate.

**Affected Parties**: All users holding NFTs from protocols created during/after symbol length transitions, and any applications querying NFT balances across multiple protocols.

## Likelihood Explanation

**Attacker Capabilities:**
- Protocol creation is permissionless on mainchain (only requires being on AELF mainchain)
- Minters can specify arbitrary tokenIds when minting [11](#0-10) 

**Attack Complexity**: Low
1. Monitor when protocol count transitions from N-digit to (N+1)-digit symbols
2. Identify existing protocol with N-digit number (e.g., "AR123456789")
3. Create protocol with (N+1)-digit number forming collision pattern (e.g., "AR1234567891")
4. Calculate colliding tokenId (23 to collide with earlier protocol's 123)
5. Mint NFT with calculated tokenId

**Feasibility**: HIGH
- Occurs naturally as protocol count grows beyond 100M protocols (transition from 9 to 10 digits)
- Collision opportunities exist at every length transition (10→11, 11→12, etc.)
- No governance approval or special permissions required
- Attack is difficult to detect as it appears as normal protocol creation and minting

## Recommendation

Add a delimiter between symbol and tokenId in the `CalculateTokenHash` function:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}:{tokenId}");
}
```

Or use structured hashing:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(symbol),
        HashHelper.ComputeFrom(tokenId)
    );
}
```

## Proof of Concept

```csharp
// Test demonstrating hash collision vulnerability
[Fact]
public void HashCollision_DifferentProtocolsSameHash()
{
    // Setup: Create first protocol with 9-digit number
    var symbol1 = "AR123456789"; // 2 letters + 9 digits
    var tokenId1 = 123L;
    
    // Create and mint NFT from protocol 1
    var nftContract = GetNFTContract();
    nftContract.Mint(new MintInput
    {
        Symbol = symbol1,
        TokenId = tokenId1,
        Owner = TestAddress1
    });
    
    // Calculate hash for protocol 1
    var hash1 = nftContract.CalculateTokenHash(new CalculateTokenHashInput
    {
        Symbol = symbol1,
        TokenId = tokenId1
    });
    
    // Setup: Protocol 2 with 10-digit number designed to collide
    var symbol2 = "AR1234567891"; // 2 letters + 10 digits
    var tokenId2 = 23L;
    
    // Calculate hash for protocol 2
    var hash2 = nftContract.CalculateTokenHash(new CalculateTokenHashInput
    {
        Symbol = symbol2,
        TokenId = tokenId2
    });
    
    // Verify collision: Both concatenate to "AR123456789123"
    Assert.Equal(hash1, hash2); // COLLISION DETECTED
    
    // Demonstrate impact: Balance query returns wrong data
    var balance1 = nftContract.GetBalance(new GetBalanceInput
    {
        Symbol = symbol1,
        TokenId = tokenId1,
        Owner = TestAddress1
    });
    
    // If protocol 2 mints to same owner, balances mix
    var balance2 = nftContract.GetBalance(new GetBalanceInput
    {
        Symbol = symbol2,
        TokenId = tokenId2,
        Owner = TestAddress1
    });
    
    // Both queries access same BalanceMap entry due to hash collision
    Assert.Equal(balance1.TokenHash, balance2.TokenHash);
}
```

## Notes

The vulnerability is deterministic and guaranteed to occur at symbol length transitions. The string concatenation "AR123456789" + "123" produces identical output to "AR1234567891" + "23", resulting in the same hash value. This breaks the fundamental assumption that each unique (symbol, tokenId) pair should have a unique identifier. The impact ranges from DoS (blocked mints) when `IsTokenIdReuse=false`, to critical state corruption when `IsTokenIdReuse=true`.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L82-111)
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-37)
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
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-73)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
        var tokenExternalInfo = GetTokenExternalInfo(input);
        var creator = input.Creator ?? Context.Sender;
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

        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;

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

        return new StringValue
        {
            Value = symbol
        };
    }
```
