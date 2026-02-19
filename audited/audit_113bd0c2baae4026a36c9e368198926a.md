### Title
Negative Amount Bypass in NFT Burn Function Allows Arbitrary Balance Inflation

### Summary
The `Burn` function in the NFT contract lacks validation for negative input amounts, allowing malicious minters to arbitrarily inflate their NFT balances, protocol supply, and token quantities. By passing a negative amount value, the subtraction operation becomes addition, enabling unlimited NFT creation beyond protocol constraints.

### Finding Description

The vulnerability exists in the `Burn` function where balance subtraction occurs without validating that the input amount is non-negative. [1](#0-0) 

The root cause is that while the `DoTransfer` helper function properly validates against negative amounts: [2](#0-1) 

The `Burn` function performs direct balance manipulation without calling `DoTransfer` or implementing equivalent validation. The input amount field is defined as a signed `int64` type: [3](#0-2) 

When a negative amount is passed (e.g., `-1000`), the security check `State.BalanceMap[tokenHash][Context.Sender] >= input.Amount` passes because any positive balance is greater than a negative number. Subsequently, the `SafeMath.Sub()` operation with a negative operand results in addition: [4](#0-3) 

For example: `balance.Sub(-1000)` computes as `balance - (-1000) = balance + 1000`, inflating the balance instead of decreasing it. This same logic applies to the protocol supply and token quantity updates on subsequent lines.

### Impact Explanation

**Direct Fund Impact - Critical:**
- Minters can inflate their NFT balance to arbitrary amounts (e.g., from 50 to 1,050 NFTs with a single call)
- Protocol supply can exceed `total_supply` limits, breaking the fundamental NFT scarcity invariant
- Token quantity becomes inconsistent with actual minted amounts
- Enables unlimited NFT creation beyond intended protocol constraints

**Affected Parties:**
- NFT protocol holders suffer dilution of their holdings
- NFT marketplace integrity is compromised
- Protocol economics break down entirely

**Severity Justification:**
This violates the critical "Token Supply & Fees" invariant requiring correct mint/burn limits and NFT uniqueness checks. It allows arbitrary asset creation, equivalent to unlimited money printing.

### Likelihood Explanation

**Reachable Entry Point:** The `Burn` function is a public RPC method accessible to any caller: [5](#0-4) 

**Feasible Preconditions:**
- Attacker must be in the minter list for the NFT protocol
- This is realistic as legitimate minters exist for every NFT protocol
- No other special permissions or contract states required

**Execution Practicality:**
- Single transaction with negative amount parameter
- No complex state setup or timing requirements
- Immediate and guaranteed success if attacker is a minter

**Economic Rationality:**
- Extremely rational - effectively free NFT creation with zero cost
- Profit potential unlimited based on NFT market value
- No gas cost constraints since operation succeeds immediately

**Detection Constraints:**
- Transaction appears as normal burn in events (negative amounts logged)
- Balance increases instead of decreases would be observable but may not trigger immediate alerts

### Recommendation

Add explicit negative amount validation at the beginning of the `Burn` function, identical to the protection in `DoTransfer`:

```csharp
public override Empty Burn(BurnInput input)
{
    if (input.Amount < 0) throw new AssertionException("Invalid burn amount.");
    
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    // ... rest of function
}
```

**Additional safeguards:**
1. Add similar validation to `UnApprove` function which has the same vulnerability: [6](#0-5) 

2. Add regression test cases verifying that negative amounts are rejected:
   - Test `Burn` with negative amount expects "Invalid burn amount" error
   - Test `UnApprove` with negative amount expects validation error
   - Verify balances/allowances remain unchanged after failed attempts

3. Consider using unsigned integer types (`uint64`) for amount fields in protobuf definitions to prevent negative values at the type level

### Proof of Concept

**Initial State:**
- NFT protocol "TESTNFT" exists with `total_supply = 1000`, `supply = 50`
- Attacker (minter) owns 50 NFTs with token hash H
- `State.BalanceMap[H][attacker] = 50`
- `State.NftProtocolMap["TESTNFT"].Supply = 50`

**Attack Steps:**
1. Attacker calls `Burn({ Symbol: "TESTNFT", TokenId: 1, Amount: -1000 })`
2. Line 91 check: `50 >= -1000 && attacker_is_minter` → TRUE ✓
3. Line 94: `State.BalanceMap[H][attacker] = 50.Sub(-1000) = 1050`
4. Line 95: `Supply = 50.Sub(-1000) = 1050`
5. Line 96: `Quantity = 50.Sub(-1000) = 1050`

**Expected Result:** Burn should reject negative amounts with error
**Actual Result:** Balance inflated from 50 to 1,050, supply inflated from 50 to 1,050

**Success Condition:** Attacker's balance increases by 1,000 NFTs in a single "burn" transaction, protocol supply exceeds total_supply limit (1,050 > 1,000)

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L310-328)
```csharp
    public override Empty UnApprove(UnApproveInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var oldAllowance = State.AllowanceMap[tokenHash][Context.Sender][input.Spender];
        var currentAllowance = oldAllowance.Sub(input.Amount);
        if (currentAllowance <= 0) currentAllowance = 0;

        State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = currentAllowance;

        Context.Fire(new UnApproved
        {
            Owner = Context.Sender,
            Spender = input.Spender,
            Symbol = input.Symbol,
            CurrentAllowance = currentAllowance,
            TokenId = input.TokenId
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
