### Title
Hash Collision Vulnerability Due to Missing Delimiter in Token Hash Calculation and Lack of Input Sanitization

### Summary
The NFT contract's view and action functions do not sanitize or validate string inputs, and the `CalculateTokenHash` function concatenates symbol and tokenId without a delimiter. This allows different (symbol, tokenId) pairs to produce identical hashes, causing state corruption and enabling unauthorized access to NFT balances and data when protocols use token ID reuse.

### Finding Description

**Root Cause Location:** [1](#0-0) 

The `CalculateTokenHash` function performs simple string concatenation without any delimiter:
- Formula used: `HashHelper.ComputeFrom($"{symbol}{tokenId}")`
- No validation of symbol format before hashing
- No delimiter separating symbol from tokenId

**Affected View Functions (No Input Sanitization):** [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

None of these functions validate or sanitize the symbol string inputs before using them.

**Collision Protection Gap:** [8](#0-7) 

When `IsTokenIdReuse = true`, the uniqueness check is skipped, allowing colliding hashes to overwrite existing NFT data.

**Symbol Generation Context:** [9](#0-8) 

Symbols are generated as 2-character prefix + random numeric suffix (e.g., "AB1234", "AR100"), which creates collision opportunities.

### Impact Explanation

**Concrete Hash Collision Examples:**
- Symbol "AB100" + TokenId 123 → Hash("AB100123")
- Symbol "AB1001" + TokenId 23 → Hash("AB100123") ← SAME HASH

**State Corruption:**
When two different NFTs produce the same tokenHash:
1. `State.NftInfoMap[tokenHash]` - Second mint overwrites first NFT's metadata
2. `State.BalanceMap[tokenHash]` - Both NFTs share the same balance storage locations
3. `State.AllowanceMap[tokenHash]` - Both NFTs share the same allowance mappings

**Affected Operations:** [10](#0-9) [11](#0-10) [12](#0-11) 

All operations using `CalculateTokenHash` become vulnerable to cross-protocol state confusion.

**Harm:**
- NFT metadata corruption
- Unauthorized access to balances/allowances across different protocols
- Potential NFT theft through shared state exploitation
- DOS of legitimate NFT operations

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Create multiple NFT protocols (requires mainchain access or cross-chain setup) [13](#0-12) 

2. Calculate colliding symbol+tokenId combinations offline
3. Mint NFTs with specific tokenIds to trigger collisions

**Feasibility:**
- Symbol generation uses randomness but attacker can create multiple protocols to obtain various numeric suffixes [14](#0-13) 

- TokenId is controllable by minter when provided in MintInput [15](#0-14) 

- More protocols created system-wide increases collision probability naturally

**Economic Rationality:**
- Cost: Creating protocols + minting operations
- Benefit: Access to valuable NFTs or DOS capability
- Practical for targeted attacks on high-value NFTs

**Detection:**
- Difficult to detect without monitoring hash collisions across all protocols
- No event or check warns of collision occurrence

### Recommendation

**1. Add Delimiter in Hash Calculation:**
Modify the `CalculateTokenHash` function to include a delimiter:
```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}-{tokenId}");
}
```

**2. Add Symbol Validation in View Functions:**
Before calculating hashes, validate symbol format matches expected pattern (alphanumeric with optional dash-number suffix):
```csharp
private void ValidateSymbol(string symbol)
{
    Assert(!string.IsNullOrEmpty(symbol) && symbol.Length <= 30, "Invalid symbol length");
    Assert(Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$"), "Invalid symbol format");
}
```

**3. Enhanced Collision Detection:**
Add explicit collision check regardless of IsTokenIdReuse setting:
```csharp
var existingNftInfo = State.NftInfoMap[tokenHash];
if (existingNftInfo != null && existingNftInfo.Symbol != input.Symbol)
{
    throw new AssertionException("Token hash collision detected across different protocols");
}
```

**4. Test Cases:**
- Test hash calculation with various symbol+tokenId combinations
- Test for collisions between different symbol lengths
- Test validation rejection of malformed symbols

### Proof of Concept

**Initial State:**
- System has no NFT protocols created

**Attack Steps:**

1. **Attacker creates Protocol A:**
   - Call `Create` with `IsTokenIdReuse = true`
   - Receives auto-generated symbol (e.g., "AB100")
   - Call `Mint` with `symbol = "AB100"`, `tokenId = 123`
   - Creates tokenHash = Hash("AB100123")
   - NFTInfo stored at State.NftInfoMap[Hash("AB100123")]
   - Balance: State.BalanceMap[Hash("AB100123")][attacker] = 1

2. **Attacker creates Protocol B (or waits for victim):**
   - Call `Create` repeatedly until obtaining symbol "AB1001"
   - Call `Mint` with `symbol = "AB1001"`, `tokenId = 23`
   - Calculates tokenHash = Hash("AB100123") ← SAME HASH as step 1
   - Since IsTokenIdReuse = true, check at line 395-396 is skipped
   - NFTInfo OVERWRITES previous: State.NftInfoMap[Hash("AB100123")] = new NFTInfo
   - Balance shares storage: State.BalanceMap[Hash("AB100123")][attacker] accessible by both

**Expected Result:**
- Each NFT should have unique tokenHash
- Separate storage for each NFT's info and balances

**Actual Result:**
- Both NFTs share tokenHash = Hash("AB100123")
- Protocol B's mint overwrites Protocol A's NFTInfo
- Both protocols access shared balance/allowance storage
- Cross-protocol state corruption enabled

**Success Condition:**
Transfer operation using Protocol A's symbol+tokenId can affect balances stored under Protocol B's tokenHash, demonstrating shared state vulnerability.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L393-396)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
        var nftInfo = State.NftInfoMap[tokenHash];
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L9-12)
```csharp
    public override NFTProtocolInfo GetNFTProtocolInfo(StringValue input)
    {
        return State.NftProtocolMap[input.Value];
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L14-18)
```csharp
    public override NFTInfo GetNFTInfo(GetNFTInfoInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        return GetNFTInfoByTokenHash(tokenHash);
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L54-64)
```csharp
    public override GetAllowanceOutput GetAllowance(GetAllowanceInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        return new GetAllowanceOutput
        {
            Owner = input.Owner,
            Spender = input.Spender,
            TokenHash = tokenHash,
            Allowance = State.AllowanceMap[tokenHash][input.Owner][input.Spender]
        };
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L77-80)
```csharp
    public override MinterList GetMinterList(StringValue input)
    {
        return State.MinterListMap[input.Value];
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L92-95)
```csharp
    public override AddressList GetOperatorList(GetOperatorListInput input)
    {
        return State.OperatorMap[input.Symbol][input.Owner];
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L65-85)
```csharp
    private long GenerateSymbolNumber()
    {
        var length = GetCurrentNumberLength();
        var from = 1L;
        for (var i = 1; i < length; i++) from = from.Mul(10);

        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
        long randomNumber;
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);

        return randomNumber;
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

**File:** protobuf/nft_contract.proto (L209-217)
```text
message MintInput {
    string symbol = 1;
    aelf.Address owner = 2;
    string uri = 3;
    string alias = 4;
    Metadata metadata = 5;
    int64 quantity = 6;
    int64 token_id = 7;
}
```
