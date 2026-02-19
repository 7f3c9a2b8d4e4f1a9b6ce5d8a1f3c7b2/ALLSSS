# Audit Report

## Title
Hash Input Collision Vulnerability in NFT Token Hash Calculation

## Summary
The `CalculateTokenHash()` function concatenates symbol and tokenId without a delimiter before hashing, allowing different (symbol, tokenId) pairs to produce identical tokenHash values. This enables cross-protocol NFT collisions, leading to denial of service during minting and state corruption when `IsTokenIdReuse` is enabled.

## Finding Description

The root cause lies in the `CalculateTokenHash` implementation, which creates hash inputs by directly concatenating symbol and tokenId strings without any delimiter: [1](#0-0) 

NFT protocol symbols follow the format `{2-char-prefix}{N-digit-number}` where the 2-character prefix represents the NFT type (e.g., "AR" for Art, "MU" for Music): [2](#0-1) 

The number length starts at 9 digits minimum and dynamically increases as more protocols are created: [3](#0-2) [4](#0-3) 

**Collision Mechanism**: Without a delimiter, different (symbol, tokenId) pairs can produce identical concatenated strings:
- Protocol A (9-digit era): symbol="AR123456789", tokenId=12 → hash input="AR12345678912"
- Protocol B (10-digit era): symbol="AR1234567891", tokenId=2 → hash input="AR12345678912"

Both produce the same tokenHash, causing them to share the same state mappings.

**Failed Protections**: The uniqueness check in `PerformMint` only prevents collisions when `IsTokenIdReuse=false`: [5](#0-4) 

This check cannot distinguish between:
1. Same tokenId within same protocol (intended to block)
2. Colliding tokenHash from different protocols (unintended, also blocks)

When `IsTokenIdReuse=true`, the check is bypassed and the code updates existing nftInfo without validating symbol ownership: [6](#0-5) 

The shared state mappings include: [7](#0-6) 

## Impact Explanation

**Scenario 1 - Denial of Service** (IsTokenIdReuse=false):
When a collision occurs, the second protocol's mint attempt fails with "Token id already exists" error, even though it's a different protocol. This permanently blocks that (symbol, tokenId) combination from being minted in the second protocol, causing operational disruption for legitimate NFT projects.

**Scenario 2 - Cross-Protocol State Corruption** (IsTokenIdReuse=true):
- The second protocol's mint updates the first protocol's NFT info, adding their address to the minters list
- Balance mappings (`State.BalanceMap[tokenHash]`) become shared and corrupted across unrelated protocols
- NFT quantity counts are incorrectly aggregated
- Allowances (`State.AllowanceMap[tokenHash]`) become confused between unrelated NFTs
- This violates the fundamental NFT uniqueness invariant where each (protocol, tokenId) should have isolated state

**Affected Parties**: All NFT protocols and their users. High-value NFT projects can be targeted for DoS, while protocols with `IsTokenIdReuse=true` face state corruption risks.

## Likelihood Explanation

**Attacker Capabilities**: Any user can call the `Create` method to create NFT protocols: [8](#0-7) 

**Attack Complexity**: Moderate. While symbol generation uses consensus-derived random numbers, attackers can:
1. Monitor existing NFTs and their (symbol, tokenId) combinations via view methods
2. Create multiple protocols until obtaining a symbol that collides with a target
3. Choose specific tokenIds during minting to force collisions (tokenId is caller-controlled when provided): [9](#0-8) 

**Feasibility**: As the protocol matures and symbol lengths transition from N digits to N+1 digits, collision opportunities increase naturally. The symbol space (10 NFT types × variable-length numbers) is large but finite, and strategic monitoring makes exploitation practical.

**Economic Rationality**: The cost includes protocol creation fees, but the benefit includes DoS attacks on competitor NFT projects or state manipulation when `IsTokenIdReuse=true`, making it economically viable for malicious actors.

## Recommendation

Add a delimiter or use structured hashing to prevent ambiguous input construction:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    // Option 1: Use delimiter
    return HashHelper.ComputeFrom($"{symbol}|{tokenId}");
    
    // Option 2: Hash components separately (preferred)
    return HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(symbol),
        HashHelper.ComputeFrom(tokenId)
    );
}
```

The second option (hashing components separately) is preferred as it eliminates ambiguity entirely by treating symbol and tokenId as distinct hash inputs.

## Proof of Concept

The vulnerability can be demonstrated by:

1. **Setup**: Create Protocol A early when symbol length is 9 digits, receiving symbol "AR123456789"
2. **First Mint**: Protocol A mints NFT with tokenId=12, creating tokenHash from "AR12345678912"
3. **Wait**: Protocol count increases, triggering length transition to 10 digits
4. **Collision**: Create Protocol B, receiving symbol "AR1234567891" 
5. **Exploit**: Protocol B attempts to mint NFT with tokenId=2, generating same hash input "AR12345678912"

**Result**: 
- If `IsTokenIdReuse=false`: Protocol B's mint fails with "Token id already exists" (DoS)
- If `IsTokenIdReuse=true`: Protocol B's mint corrupts Protocol A's NFT state (State Corruption)

The vulnerability is provable by calculating `CalculateTokenHash("AR123456789", 12)` and `CalculateTokenHash("AR1234567891", 2)` and verifying they produce identical hashes. This can be tested via the public view method: [10](#0-9)

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L392-393)
```csharp
        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L395-396)
```csharp
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L433-437)
```csharp
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L17-30)
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

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L82-85)
```csharp
    public override Hash CalculateTokenHash(CalculateTokenHashInput input)
    {
        return CalculateTokenHash(input.Symbol, input.TokenId);
    }
```
