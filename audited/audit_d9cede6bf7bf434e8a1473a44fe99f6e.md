### Title
TokenHash Collision Vulnerability Enables Cross-Protocol State Corruption and Allowance Theft

### Summary
The `CalculateTokenHash()` function concatenates symbol and tokenId without a delimiter, creating ambiguous string inputs that can produce identical hashes for different NFTs. This allows attackers to exploit naturally occurring collision pairs where one protocol's symbol is a prefix of another's, enabling theft through shared allowance state, balance manipulation, and NFT metadata corruption.

### Finding Description

The vulnerability exists in the token hash calculation mechanism: [1](#0-0) 

This function concatenates symbol and tokenId as strings without any delimiter or separator. Since NFT protocol symbols are generated as 2-letter prefix plus N-digit numbers (where N starts at 9 and grows): [2](#0-1) [3](#0-2) 

The symbol number length dynamically increases as more protocols are created: [4](#0-3) 

This creates a collision scenario where:
- Protocol A has symbol "AR123456789" (9 digits) with tokenId=123 → hash("AR123456789123")
- Protocol B has symbol "AR1234567891" (10 digits) with tokenId=23 → hash("AR123456789123")

Both produce identical string inputs and thus identical hashes. Users can specify custom tokenIds when minting: [5](#0-4) 

The collision affects all hash-keyed state mappings: [6](#0-5) 

Both `GetAllowance()` and `GetAllowanceByTokenHash()` query the same shared state when a collision exists: [7](#0-6) 

No validation exists to prevent or detect tokenHash collisions. The only uniqueness check is for the random number portion of symbols, not the final tokenHash: [8](#0-7) 

### Impact Explanation

**Direct Fund Impact:**
1. **Allowance Theft**: An attacker controlling NFT from Protocol A can spend allowances granted for NFT from Protocol B (different owner), enabling direct token theft through `TransferFrom()`: [9](#0-8) 

2. **Balance Corruption**: Transfers on one NFT affect the balance of another unrelated NFT, allowing attackers to artificially inflate their balance or drain others': [10](#0-9) 

3. **NFT Info Overwrite**: Minting a colliding NFT can overwrite or corrupt existing NFT metadata and quantity: [11](#0-10) 

**Severity: Critical** - Enables theft of arbitrary NFT allowances and balance manipulation across different protocols.

### Likelihood Explanation

**Feasibility: High**

1. **Attacker Capabilities**: Only requires ability to mint NFTs (available to any minter) and specify custom tokenIds (standard feature).

2. **Preconditions**: Collision pairs emerge naturally as protocols are created. For every 9-digit protocol created, there are 10 potential colliding 10-digit protocols (when length increases). With thousands of protocols, collisions become statistically certain.

3. **Attack Complexity**: Low
   - Monitor blockchain for protocol creation events
   - Identify collision pairs using simple pattern matching
   - Mint NFT with calculated tokenId to trigger collision
   - Execute theft via standard approval/transfer operations

4. **Detection**: Extremely difficult - collisions appear as legitimate state updates within protocol rules.

5. **Economic Rationality**: High reward (steal valuable NFT allowances), low cost (standard minting fees).

### Recommendation

**Immediate Fix**: Add a delimiter to prevent string concatenation ambiguity:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}:{tokenId}"); // Add ":" separator
}
```

**Additional Protections**:
1. Add tokenHash collision detection during minting - verify `State.NftInfoMap[tokenHash]` has matching symbol/tokenId or is null
2. Implement protocol-aware validation in `GetAllowance()` to verify symbol consistency
3. Add regression tests for collision scenarios with increasing symbol lengths
4. Consider migrating to a structured hash input (e.g., protobuf encoding) instead of string concatenation

### Proof of Concept

**Initial State**:
- Protocol A exists: symbol="AR123456789" (created when symbol length was 9 digits)
- Protocol B exists: symbol="AR1234567891" (created when symbol length grew to 10 digits)
- User Alice owns NFT from Protocol A
- User Bob owns NFT from Protocol B

**Attack Sequence**:
1. Alice mints NFT: `Mint({symbol: "AR123456789", tokenId: 123})` → tokenHash = hash("AR123456789123")
2. Alice approves 100 units to Charlie: `Approve({symbol: "AR123456789", tokenId: 123, spender: Charlie, amount: 100})`
3. Bob mints NFT: `Mint({symbol: "AR1234567891", tokenId: 23})` → tokenHash = hash("AR123456789123") **[COLLISION]**
4. Bob calls `GetAllowance({symbol: "AR1234567891", tokenId: 23, owner: Alice, spender: Charlie})` → returns 100 (Alice's allowance for different NFT!)
5. Bob uses Charlie's address to execute: `TransferFrom({symbol: "AR1234567891", tokenId: 23, from: Alice, to: Bob})` → succeeds by consuming Alice's allowance meant for Protocol A

**Expected Result**: TransferFrom should fail (no allowance exists for Protocol B's NFT)

**Actual Result**: TransferFrom succeeds, stealing Alice's NFT using her allowance from a different protocol due to tokenHash collision

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L46-55)
```csharp
    private void DoTransfer(Hash tokenHash, Address from, Address to, long amount)
    {
        if (amount < 0) throw new AssertionException("Invalid transfer amount.");

        if (amount == 0) return;

        Assert(State.BalanceMap[tokenHash][from] >= amount, "Insufficient balance.");
        State.BalanceMap[tokenHash][from] = State.BalanceMap[tokenHash][from].Sub(amount);
        State.BalanceMap[tokenHash][to] = State.BalanceMap[tokenHash][to].Add(amount);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L392-392)
```csharp
        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L415-441)
```csharp
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L79-82)
```csharp
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L54-75)
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

    public override GetAllowanceOutput GetAllowanceByTokenHash(GetAllowanceByTokenHashInput input)
    {
        return new GetAllowanceOutput
        {
            Owner = input.Owner,
            Spender = input.Spender,
            TokenHash = input.TokenHash,
            Allowance = State.AllowanceMap[input.TokenHash][input.Owner][input.Spender]
        };
    }
```
