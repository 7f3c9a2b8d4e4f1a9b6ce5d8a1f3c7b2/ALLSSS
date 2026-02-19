### Title
Hash Collision Vulnerability in NFT Token Hash Calculation Enables Cross-NFT Ownership and Balance Manipulation

### Summary
The `CalculateTokenHash()` function concatenates symbol and tokenId as strings without a delimiter, enabling different (symbol, tokenId) pairs to produce identical token hashes. While SHA256 itself is cryptographically secure, the flawed input construction allows attackers to create colliding NFT protocols via `CrossChainCreate`, causing multiple distinct NFTs to share the same storage mappings for ownership, balances, and allowances.

### Finding Description

The vulnerability exists in the token hash calculation implementation: [1](#0-0) 

The function directly concatenates symbol and tokenId using string interpolation without any delimiter. This flows through the HashHelper utility: [2](#0-1) 

Which ultimately uses SHA256: [3](#0-2) 

While SHA256 is cryptographically secure against collision and pre-image attacks, the vulnerability lies in the **input construction**, not the hash algorithm. Different (symbol, tokenId) pairs can produce identical concatenated strings:

- symbol="AR1", tokenId=23 → "AR123"
- symbol="AR12", tokenId=3 → "AR123"

Both produce the same hash despite being different NFT identifiers.

The calculated tokenHash is used throughout critical storage mappings: [4](#0-3) [5](#0-4) [6](#0-5) 

The attack vector is through `CrossChainCreate`, which accepts arbitrary symbols with minimal validation: [7](#0-6) 

The function only validates that (1) the protocol doesn't exist, (2) the token exists in MultiToken, and (3) the symbol starts with a valid 2-character NFT type code. It does NOT prevent symbols that could collide when concatenated with tokenIds.

Token symbols are validated to be alphanumeric and under length limits: [8](#0-7) [9](#0-8) 

This allows creating tokens "AR1", "AR12", "AR123" etc. (all under 10 characters) which, when combined with appropriate tokenIds, produce colliding hashes.

### Impact Explanation

**Direct Fund Impact - Critical:**

When two NFTs share the same tokenHash due to collision, they map to identical storage locations:
- `State.NftInfoMap[tokenHash]` - NFT metadata and ownership info
- `State.BalanceMap[tokenHash][owner]` - Balance tracking per address  
- `State.AllowanceMap[tokenHash][owner][spender]` - Approval allowances

This causes:

1. **Asset Theft**: Transferring NFT-A updates the balance of both NFT-A and colliding NFT-B. An attacker can drain balances of legitimate NFT holders by transferring their colliding NFT: [10](#0-9) 

2. **Ownership Confusion**: Both NFTs share the same NFTInfo record, causing complete confusion about which NFT actually owns which metadata, quantity, and minter list: [11](#0-10) 

3. **Allowance Abuse**: Approvals granted for NFT-A automatically apply to NFT-B, enabling unauthorized transfers: [12](#0-11) 

The vulnerability violates the critical invariant: "NFT uniqueness and ownership checks" - each NFT should have unique storage independent of any other NFT.

**Affected Parties:**
- All holders of NFTs from colliding protocols
- NFT creators whose protocols are targeted for collision attacks
- Any marketplace or dApp relying on NFT ownership accuracy

**Quantified Damage:**
Complete loss of all NFT value in colliding protocols. If protocol "AR1" has 1000 NFTs worth $100k total, and attacker creates colliding protocol "AR12" and manipulates balances, all $100k value is at risk.

### Likelihood Explanation

**Reachable Entry Point:** 
The attack requires creating tokens via MultiToken contract and NFT protocols via CrossChainCreate - both are public methods accessible to any user.

**Feasible Preconditions:**
1. Attacker needs to create two regular tokens with colliding symbol patterns (e.g., "AR1" and "AR12")
2. Both tokens must include required NFT metadata fields (NftBaseUriMetadataKey, NftTokenIdReuseMetadataKey)
3. Call CrossChainCreate for both symbols to register as NFT protocols
4. Mint NFTs with carefully chosen tokenIds to create hash collisions

**Execution Practicality:**
All steps are executable under AElf contract semantics:
- Token creation is permissioned but available to addresses in the create whitelist or via SEED NFT mechanism: [13](#0-12) 

- CrossChainCreate has no explicit permission checks beyond requiring the token to exist
- Minting requires being in the minter list, but the protocol creator is automatically added: [14](#0-13) 

**Attack Complexity:** 
Medium - requires understanding the hash concatenation flaw and creating tokens with specific symbol patterns, but all necessary operations are standard contract interactions.

**Economic Rationality:**
The cost of creating two tokens and NFT protocols is minimal compared to potential gains from stealing valuable NFTs or causing market manipulation. High-value NFT collections make this economically attractive.

**Detection Constraints:**
The collision is not immediately obvious. NFTs appear separate until balance/ownership operations reveal shared storage. Monitoring for suspiciously similar symbols is possible but not currently implemented.

**Likelihood Assessment:** MEDIUM-HIGH - The attack is technically feasible and economically rational, limited primarily by the need to create tokens (which requires whitelist access or SEED NFT).

### Recommendation

**Immediate Fix:**
Modify the hash calculation to include a delimiter that cannot appear in symbol strings:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}|{tokenId}");
}
```

Or use a more robust approach with separate hashing:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    var symbolHash = HashHelper.ComputeFrom(symbol);
    var tokenIdHash = HashHelper.ComputeFrom(tokenId);
    return HashHelper.ConcatAndCompute(symbolHash, tokenIdHash);
}
```

The concatenation approach in ConcatAndCompute is already implemented: [15](#0-14) 

**Additional Invariant Checks:**
Add validation in CrossChainCreate to prevent symbols that could collide:
1. Enforce minimum symbol length (e.g., must be at least 8 characters for non-generated symbols)
2. Maintain a registry of symbol prefixes and validate new symbols don't create collision potential
3. Add explicit check: verify that `CalculateTokenHash(symbol, 0)` doesn't match any existing tokenHash

**Test Cases:**
1. Test that different (symbol, tokenId) pairs always produce different hashes
2. Test that symbols "ABC1", "ABC12", "ABC123" with various tokenIds cannot collide
3. Regression test to verify the fix prevents all concatenation-based collisions

### Proof of Concept

**Initial State:**
- MultiToken contract deployed and operational
- NFT contract deployed with NFT types initialized including "AR" (Art) type

**Attack Sequence:**

1. **Create First Token:**
   - Attacker calls `MultiToken.Create` with symbol="AR1", including required NFT external info metadata (NftBaseUriMetadataKey, NftTokenIdReuseMetadataKey, NftTypeMetadataKey="Art")
   - Token "AR1" is registered in TokenInfos state

2. **Create Second Token:**
   - Attacker calls `MultiToken.Create` with symbol="AR12", including same NFT metadata
   - Token "AR12" is registered in TokenInfos state

3. **Register NFT Protocols:**
   - Attacker calls `NFTContract.CrossChainCreate` with symbol="AR1"
   - NFT Protocol "AR1" is created, attacker added to minter list
   - Attacker calls `NFTContract.CrossChainCreate` with symbol="AR12"
   - NFT Protocol "AR12" is created, attacker added to minter list

4. **Mint Colliding NFTs:**
   - Attacker calls `NFTContract.Mint` for protocol "AR1" with tokenId=23
     - Calculates hash: `HashHelper.ComputeFrom("AR123")` → Hash_X
     - Creates NFTInfo at `State.NftInfoMap[Hash_X]`
     - Sets balance at `State.BalanceMap[Hash_X][attacker]` = 1
   
   - Attacker calls `NFTContract.Mint` for protocol "AR12" with tokenId=3
     - Calculates hash: `HashHelper.ComputeFrom("AR123")` → Hash_X (SAME!)
     - Updates SAME NFTInfo at `State.NftInfoMap[Hash_X]`
     - Updates SAME balance at `State.BalanceMap[Hash_X][attacker]` = 2

5. **Exploit Collision:**
   - Attacker transfers "AR1" NFT (tokenId 23) to victim
   - Balance at `State.BalanceMap[Hash_X]` is modified
   - Victim now has confused ownership of both logically distinct NFTs
   - Attacker can manipulate balances by operating on either NFT

**Expected Result:**
Two distinct NFTs with separate storage: NFT("AR1", 23) has hash Hash_A, NFT("AR12", 3) has hash Hash_B where Hash_A ≠ Hash_B

**Actual Result:**
Both NFTs share identical hash Hash_X, causing shared storage for all balance, ownership, and allowance operations - complete violation of NFT uniqueness invariant

**Success Condition:**
Demonstrate that `GetBalance` for address using NFT("AR1", 23) returns the same value as for NFT("AR12", 3), proving they map to identical storage due to hash collision.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L57-80)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var operatorList = State.OperatorMap[input.Symbol][input.From];
        var isOperator = operatorList?.Value.Contains(Context.Sender) ?? false;
        if (!isOperator)
        {
            var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
            Assert(allowance >= input.Amount, "Not approved.");
            State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
        }

        DoTransfer(tokenHash, input.From, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = input.From,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
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

**File:** src/AElf.Types/Helper/HashHelper.cs (L25-28)
```csharp
        public static Hash ComputeFrom(string str)
        {
            return ComputeFrom(Encoding.UTF8.GetBytes(str));
        }
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L74-78)
```csharp
        public static Hash ConcatAndCompute(Hash hash1, Hash hash2)
        {
            var bytes = ByteArrayHelper.ConcatArrays(hash1.ToByteArray(), hash2.ToByteArray());
            return ComputeFrom(bytes);
        }
```

**File:** src/AElf.Types/Extensions/ByteExtensions.cs (L64-70)
```csharp
        public static byte[] ComputeHash(this byte[] bytes)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(bytes);
            }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-93)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L110-113)
```csharp
        State.MinterListMap[input.Symbol] = new MinterList
        {
            Value = { nftProtocolInfo.Creator }
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L18-21)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L7-7)
```csharp
    public const int SymbolMaxLength = 10;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-66)
```csharp
    private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
    {
        AssertValidCreateInput(input, symbolType);
        if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
        {
            // can not call create on side chain
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
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
        }
```
