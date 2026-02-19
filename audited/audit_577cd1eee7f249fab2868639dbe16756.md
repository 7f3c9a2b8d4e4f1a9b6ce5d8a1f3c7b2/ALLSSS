### Title
NFT Burn Function Allows Negative Amounts to Inflate Balances and Bypass Supply Limits

### Summary
The NFT contract's `Burn` function accepts negative amounts without validation, allowing authorized minters to increase their token balances, inflate supply counters, and bypass total supply restrictions by calling burn with negative values. This directly contradicts the intended burn semantics and breaks critical token supply invariants.

### Finding Description

The vulnerability exists in the `Burn` method [1](#0-0)  where `input.Amount` is a signed `int64` field [2](#0-1)  that can accept negative values.

The method's balance check only verifies that the current balance is greater than or equal to the input amount [3](#0-2) , which passes when amount is negative (e.g., `0 >= -100` evaluates to true).

Subsequently, three critical state updates use the `Sub` extension method [4](#0-3) , which performs simple arithmetic subtraction [5](#0-4) . When subtracting a negative value, this actually *increases* the balance: `balance - (-100) = balance + 100`.

The vulnerability occurs because unlike the `DoTransfer` method which explicitly validates against negative amounts [6](#0-5) , the `Burn` method lacks this critical validation step.

### Impact Explanation

An authorized minter can exploit this to:
1. **Inflate token balances arbitrarily**: By calling Burn with negative amounts, minters increase their own balance rather than decreasing it
2. **Bypass total supply limits**: The `nftProtocolInfo.Supply` counter is also inflated, allowing creation of tokens beyond the protocol's `TotalSupply` limit
3. **Break NFT quantity tracking**: The `nftInfo.Quantity` field is similarly inflated, corrupting the total quantity metrics

This represents a **HIGH severity** direct fund impact as it allows unlimited token creation by a minter role, completely breaking the token supply invariant that must hold at all times. While the attacker must be a minter (a semi-trusted role), minters are not expected to have the ability to mint unlimited tokens bypassing supply caps - this violates the fundamental token economics of the NFT protocol.

### Likelihood Explanation

**Attacker Prerequisites:**
- Must be in the minter list for the NFT protocol (authorized role)
- The NFT protocol must have `IsBurnable` set to true

**Attack Complexity:** 
Very low - requires only a single transaction calling `Burn` with a negative `Amount` value (e.g., -1000000).

**Execution Practicality:**
Fully practical under AElf contract semantics. The protobuf message accepts signed int64 [7](#0-6) , and there are no input validation checks preventing negative values from reaching the arithmetic operations.

**Economic Rationality:**
Transaction costs are minimal compared to the ability to mint unlimited tokens. A minter could create tokens worth significant value at negligible cost.

**Detection:** 
The `Burned` event would show a negative amount [8](#0-7) , making the exploit potentially detectable, but by then balances and supply have already been corrupted.

Given the simplicity and the fact that minters are common in NFT systems, this has **HIGH likelihood** despite requiring a privileged role.

### Recommendation

Add explicit negative amount validation at the beginning of the `Burn` method, mirroring the protection in `DoTransfer`:

```csharp
public override Empty Burn(BurnInput input)
{
    // Add this validation
    if (input.Amount < 0) 
        throw new AssertionException("Invalid burn amount.");
    
    if (input.Amount == 0) 
        return new Empty();
    
    // ... rest of existing code
}
```

**Additional hardening:**
1. Add similar validation to all methods accepting amount parameters (`Approve`, `UnApprove`, etc.)
2. Add test cases specifically testing negative amounts for all token operations
3. Consider using unsigned types (ulong) for amount fields in protobuf definitions where negative values never make semantic sense

### Proof of Concept

**Initial State:**
- NFT protocol "TEST" exists with `TotalSupply = 1000`, `Supply = 100`, `IsBurnable = true`
- Attacker address is in the minter list for "TEST"
- Token "TEST-1" exists with `Quantity = 100`
- Attacker's balance for "TEST-1" is 10 tokens

**Attack Transaction:**
```
Burn({
    Symbol: "TEST",
    TokenId: 1,
    Amount: -90  // Negative amount
})
```

**Expected Result (correct behavior):**
Transaction should fail with "Invalid burn amount" error.

**Actual Result (vulnerable behavior):**
- Transaction succeeds
- Attacker's balance: 10 - (-90) = **100 tokens** (increased by 90)
- Protocol Supply: 100 - (-90) = **190** (exceeds intended limits)
- Token Quantity: 100 - (-90) = **190** (inflated)
- Burned event emitted with Amount = -90

**Success Condition:**
Attacker successfully increased balance from 10 to 100 tokens using a "burn" operation with negative amount, bypassing all supply constraints.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L48-48)
```csharp
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
