# Audit Report

## Title
NFT Contract Burn Function Allows Unauthorized Token Minting via Negative Amount Input

## Summary
The NFT contract's `Burn()` function lacks input validation for negative amounts, allowing minters to exploit signed integer arithmetic in SafeMath operations to mint unlimited tokens. This bypasses all supply limits and represents a critical privilege escalation vulnerability.

## Finding Description

The vulnerability exists in the `Burn()` function where no validation ensures `input.Amount` is positive [1](#0-0) . 

When a negative amount is passed:

1. The balance check at lines 90-92 passes because any positive balance is greater than or equal to a negative number (e.g., `100 >= -1000` evaluates to true)
2. The SafeMath `.Sub()` operations become additions: `balance.Sub(-1000)` = `balance - (-1000)` = `balance + 1000`

This occurs because SafeMath's `.Sub()` method only performs overflow checking but does not validate the sign of inputs [2](#0-1) .

The protobuf definition allows this by using `int64` for the amount field [3](#0-2) .

**Contrast with MultiToken Contract:**
The MultiToken contract's `Burn()` implementation properly validates amounts by calling `AssertValidToken()` [4](#0-3) , which invokes `AssertValidSymbolAndAmount()` that explicitly checks `Assert(amount > 0, "Invalid amount.")` [5](#0-4) .

This validation is completely absent from the NFT contract's `Burn()` function, even though the same codebase shows awareness of this pattern in the `DoTransfer()` method which validates against negative amounts [6](#0-5) .

## Impact Explanation

**Critical Supply Invariant Violation:**
The legitimate `Mint()` function enforces that issued tokens cannot exceed total supply [7](#0-6) . By burning negative amounts, attackers bypass this check entirely, causing:

1. **Token inflation:** Balance, Supply, and Quantity all increase instead of decreasing
2. **Supply cap breach:** Supply can exceed TotalSupply 
3. **Economic manipulation:** Dilutes existing token holders' ownership
4. **Privilege escalation:** Minters with limited quotas gain unlimited minting capability

**Affected parties:**
- NFT protocol creators who set supply limits
- Existing NFT holders (value dilution)
- Markets and pricing mechanisms relying on supply data

## Likelihood Explanation

**Entry Point:** Public `Burn()` method is directly accessible.

**Required Privileges:** Attacker must be in the minter list for the target NFT protocol. While this is a privileged role, it represents privilege escalation since minters should be constrained by the supply limits enforced in the legitimate `Mint()` path.

**Attack Complexity:** Trivial - single transaction calling `Burn()` with a negative amount value.

**Execution:** Fully executable under AElf C# contract semantics. The `.Sub()` method will successfully execute `value - (negative_number)`, resulting in addition without any runtime exceptions.

**Detection:** The `Burned` event will fire with the negative amount, but this is post-exploitation and does not prevent the attack.

## Recommendation

Add input validation at the start of the `Burn()` function to match the MultiToken contract pattern:

```csharp
public override Empty Burn(BurnInput input)
{
    Assert(input.Amount > 0, "Invalid amount.");
    
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    // ... rest of implementation
}
```

Alternatively, create a helper method similar to `AssertValidSymbolAndAmount()` in the MultiToken contract and call it before any balance operations.

## Proof of Concept

```csharp
[Fact]
public async Task BurnWithNegativeAmount_ShouldInflateSupply()
{
    // Setup: Create NFT protocol with supply limit
    var symbol = await CreateTest(); // Creates protocol with TotalSupply=1_000_000_000
    await AddMinterAsync(symbol);
    
    // Mint one NFT to establish initial state
    var tokenHash = await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Quantity = 100,
        Owner = MinterAddress
    });
    
    // Get initial state
    var protocolInfoBefore = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    var balanceBefore = await NFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = symbol,
        TokenId = 1
    });
    
    protocolInfoBefore.Supply.ShouldBe(100);
    balanceBefore.Balance.ShouldBe(100);
    
    // EXPLOIT: Call Burn with negative amount
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000  // Negative amount
    });
    
    // Verify: Supply and balance INCREASED instead of decreased
    var protocolInfoAfter = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    var balanceAfter = await NFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = symbol,
        TokenId = 1
    });
    
    protocolInfoAfter.Supply.ShouldBe(1100);  // Increased by 1000!
    balanceAfter.Balance.ShouldBe(1100);      // Increased by 1000!
    
    // Supply now exceeds any reasonable limit, bypassing mint checks
}
```

## Notes

This vulnerability demonstrates inconsistent input validation patterns within the same codebase. The `DoTransfer()` method in the same file properly validates negative amounts, and the MultiToken contract implements comprehensive amount validation, but these patterns were not applied to the NFT contract's `Burn()` function. This represents a critical oversight that allows privileged actors to escalate their permissions beyond intended design constraints.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L402-406)
```csharp
        var quantity = input.Quantity > 0 ? input.Quantity : 1;
        protocolInfo.Supply = protocolInfo.Supply.Add(quantity);
        protocolInfo.Issued = protocolInfo.Issued.Add(quantity);
        Assert(protocolInfo.Issued <= protocolInfo.TotalSupply, "Total supply exceeded.");
        State.NftProtocolMap[input.Symbol] = protocolInfo;
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

**File:** protobuf/nft_contract.proto (L182-186)
```text
message BurnInput {
    string symbol = 1;
    int64 token_id = 2;
    int64 amount = 3;
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
