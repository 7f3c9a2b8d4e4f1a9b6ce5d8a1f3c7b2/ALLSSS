# Audit Report

## Title
NFT Collection Creation Bypass Allows Non-Zero Decimals Through Direct TokenContract Call

## Summary
The AElf protocol enforces that NFT collections must have `Decimals = 0` to maintain indivisibility, but this invariant can be bypassed by calling `TokenContract.Create` directly with NFT collection symbols (ending with "-0") and non-zero decimals, allowing creation of divisible "NFT collections" that violate the fundamental NFT indivisibility guarantee.

## Finding Description

The NFT contract properly enforces NFT indivisibility by hardcoding `Decimals = 0` when creating NFT protocols. [1](#0-0) 

However, the `TokenContract.Create` method is publicly callable and routes token creation based on symbol patterns through `GetSymbolType`. [2](#0-1)  The symbol type classification is purely pattern-based - symbols ending with "-0" are automatically classified as `NftCollection`. [3](#0-2) 

When an NFT collection symbol is detected, `CreateNFTCollection` delegates directly to `CreateToken` without enforcing `Decimals = 0`. [4](#0-3)  The `CreateToken` method validates decimals only through `AssertValidCreateInput`, which permits any value between 0 and `MaxDecimals` (18). [5](#0-4) [6](#0-5) 

Only SEED NFTs have explicit `Decimals == 0` validation in the NFT creation flow. [7](#0-6)  Regular NFT collections created via direct `TokenContract.Create` calls bypass the NFT contract entirely and inherit no decimals enforcement beyond the [0, 18] range check.

Once created, the TokenInfo is stored with the specified decimals value [8](#0-7) , and subsequent Issue and Transfer operations treat the token according to its stored decimals without additional NFT-specific validation.

The only requirement for calling `TokenContract.Create` (for non-whitelisted users) is ownership of a valid SEED NFT for the symbol, which is validated and then burned during token creation. [9](#0-8) 

## Impact Explanation

**Protocol Invariant Violation**: NFT collections are fundamentally defined as indivisible tokens with `Decimals = 0`. Creating NFT collections (symbols ending with "-0") with non-zero decimals breaks this core protocol invariant, allowing fractional NFT collection amounts. For example, an NFT collection with `Decimals = 8` could be issued/transferred in amounts like 50000000 (representing 0.5 units).

**Ecosystem Confusion**: The AElf ecosystem (dApps, wallets, NFT marketplaces) relies on symbol patterns to identify token types. Symbols ending in "-0" are recognized as NFT collections. When these symbols represent divisible tokens, it creates:
- Incorrect display and accounting in NFT galleries and marketplaces
- Failed assumptions in smart contracts that interact with NFT collections expecting indivisible units
- User deception when purchasing what appears to be an NFT collection based on symbol pattern but is actually divisible

**Operational Impact**: The malformed NFT collections can be fully operated as divisible tokens through standard MultiToken operations (Issue, Transfer, Approve, etc.), completely undermining the NFT semantic guarantees the protocol intends to provide.

## Likelihood Explanation

**Reachable Entry Point**: `TokenContract.Create` is a public method callable by any user on the network without special privileges.

**Feasible Preconditions**: 
- The attacker must obtain a SEED NFT for their desired symbol (e.g., "ABC"), which can be acquired through the normal SEED NFT creation and issuance mechanisms
- No governance approvals, whitelisting, or special contract permissions are required beyond standard SEED NFT ownership

**Execution Steps**:
1. Acquire SEED NFT for symbol "ABC" through normal SEED NFT mechanisms
2. Call `TokenContract.Create` with `Symbol = "ABC-0"`, `Decimals = 8` (or any value 1-18), and other valid parameters
3. The system validates the SEED NFT ownership and burns it
4. Token is created with non-zero decimals as an NFT collection
5. The attacker can now issue and transfer fractional amounts of this "NFT collection"

**Economic Rationality**: SEED NFT acquisition costs are reasonable within the protocol's token economics, and the ability to create confusing NFT-like tokens could enable deceptive schemes in secondary markets or cause integration issues with NFT-dependent protocols.

## Recommendation

Add explicit validation in `AssertValidCreateInput` to enforce `Decimals == 0` for NFT collections:

```csharp
private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
{
    Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
           && input.Symbol.Length > 0
           && input.Decimals >= 0
           && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

    // Add NFT collection decimals validation
    if (symbolType == SymbolType.NftCollection)
    {
        Assert(input.Decimals == 0, "NFT collections must have Decimals = 0.");
    }

    CheckSymbolLength(input.Symbol, symbolType);
    if (symbolType == SymbolType.Nft) return;
    CheckTokenAndCollectionExists(input.Symbol);
    if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CreateNFTCollection_WithNonZeroDecimals_ShouldFail()
{
    // Arrange: Create and issue SEED NFT for symbol "TEST"
    var seedSymbol = await CreateSeedNftAsync("TEST", 1);
    
    // Act: Try to create NFT collection with non-zero decimals
    var result = await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "TEST-0", // NFT collection format
        TokenName = "Test Collection",
        TotalSupply = 10000,
        Decimals = 8, // Non-zero decimals - should fail but doesn't
        Issuer = DefaultAddress,
        IsBurnable = true,
        Owner = DefaultAddress
    });
    
    // Assert: Transaction succeeds when it should fail
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Token was created with non-zero decimals
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
    {
        Symbol = "TEST-0"
    });
    
    tokenInfo.Decimals.ShouldBe(8); // VULNERABILITY: NFT collection has Decimals = 8 instead of 0
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L26-26)
```csharp
            Decimals = 0, // Fixed
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L33-46)
```csharp
    public override Empty Create(CreateInput input)
    {
        var inputSymbolType = GetSymbolType(input.Symbol);
        if (input.Owner == null)
        {
            input.Owner = input.Issuer;
        }
        return inputSymbolType switch
        {
            SymbolType.NftCollection => CreateNFTCollection(input),
            SymbolType.Nft => CreateNFTInfo(input),
            _ => CreateToken(input)
        };
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-79)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L10-13)
```csharp
    private Empty CreateNFTCollection(CreateInput input)
    {
        return CreateToken(input, SymbolType.NftCollection);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L38-39)
```csharp
        {
            Assert(input.Decimals == 0 && input.TotalSupply == 1, "SEED must be unique.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L6-6)
```csharp
    public const int MaxDecimals = 18;
```
