### Title
Missing Address Validation in NFT Transfer Allows Token Burning Without Supply Accounting Update

### Summary
The NFT contract's `Transfer` function lacks recipient address validation, allowing tokens to be sent to invalid or inaccessible addresses (including zero addresses). Unlike the proper `Burn` function which updates `NFTProtocolInfo.Supply` and `NFTInfo.Quantity`, transfers to invalid addresses only update the balance map, breaking the critical accounting invariant where actual circulating supply must equal recorded supply metrics.

### Finding Description

The `Transfer` function accepts any address without validation: [1](#0-0) 

The internal `DoTransfer` helper performs no address validation on the `to` parameter, only checking amount and balance: [2](#0-1) 

In contrast, the MultiToken contract implements `AssertValidInputAddress` validation: [3](#0-2) 

This validation is used in MultiToken's transfer operations: [4](#0-3) 

The critical issue is that proper burning via the `Burn` function updates supply metrics: [5](#0-4) 

Specifically, lines 95-96 decrement both `nftProtocolInfo.Supply` and `nftInfo.Quantity`. The `Transfer` function performs no such updates.

In AElf, addresses must be exactly 32 bytes: [6](#0-5) 

A zero address (32 bytes of zeros) is structurally valid but uncontrolled. The protocol tracks supply in NFTProtocolInfo: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact**: Tokens transferred to invalid addresses are permanently lost from circulation but remain counted in supply metrics, creating phantom supply. For a protocol with 1,000,000 total supply, if 100,000 tokens are sent to invalid addresses, the recorded supply remains 1,000,000 while actual circulating supply is only 900,000.

**Broken Invariant**: The critical accounting invariant `Σ(BalanceMap[tokenHash][address]) = NFTProtocolInfo.Supply` is violated, corrupting protocol-level supply tracking used for governance, economics, and user-facing data.

**Bypassed Restrictions**:
1. Non-burnable protocols (where `IsBurnable = false`) can have tokens effectively burned via transfer
2. Users without minter permissions can burn tokens by transferring to invalid addresses, bypassing the burn permission check
3. Supply manipulation without emitting proper `Burned` events, hiding actual token destruction

**Affected Parties**: All protocol participants relying on accurate supply data, including governance voters, marketplace participants, and protocol analytics.

### Likelihood Explanation

**Reachable Entry Point**: `Transfer` is a public function callable by any NFT holder without special permissions.

**Feasible Preconditions**: 
- Attacker only needs to own NFTs to transfer
- No special privileges required
- Can construct valid 32-byte addresses with arbitrary values

**Execution Practicality**: 
- Creating an invalid address is trivial (e.g., `Address.FromBytes(new byte[32])` creates a zero address)
- Single transaction execution
- No complex state setup required

**Attack Scenarios**:
1. **Intentional burn bypass**: User wants to reduce supply but lacks minter permission or protocol is non-burnable
2. **Supply manipulation**: Malicious actor corrupts supply metrics to affect price discovery or governance
3. **User error**: Accidental transfer to mistyped address permanently locks tokens without proper accounting
4. **Contract integration bugs**: External contracts sending to invalid addresses due to logic errors

**Economic Rationality**: Low cost (only gas fees), potential high impact if exploited systematically or if large holders accidentally send to wrong addresses.

### Recommendation

1. **Add address validation in Transfer function**:
```csharp
public override Empty Transfer(TransferInput input)
{
    AssertValidInputAddress(input.To); // Add this check
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
    // ... rest of function
}
```

2. **Implement address validation helper in NFT contract** similar to MultiToken:
```csharp
private void AssertValidInputAddress(Address input)
{
    Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid recipient address.");
}
```

3. **Also validate in TransferFrom function** to maintain consistency.

4. **Add test cases**:
   - Test transfer to null address (should fail)
   - Test transfer to empty address (should fail)  
   - Test transfer to zero address (should fail)
   - Verify supply metrics remain accurate after valid transfers

5. **Consider additional checks**:
   - Prevent transfers to contract's own address unless explicitly allowed
   - Maintain a blacklist of invalid addresses if needed

### Proof of Concept

**Initial State**:
- NFT protocol created with TotalSupply = 1000, Supply = 100
- User A owns 50 tokens of tokenId 1
- Protocol has `IsBurnable = false` and User A is not a minter

**Attack Sequence**:

1. User A creates zero address:
   ```csharp
   var zeroAddress = Address.FromBytes(new byte[32]);
   ```

2. User A calls Transfer:
   ```csharp
   NFTContract.Transfer({
       To: zeroAddress,
       Symbol: "PROTOCOL-1",
       TokenId: 1,
       Amount: 50
   })
   ```

3. **Expected Result** (with proper validation):
   - Transaction fails with "Invalid recipient address"
   - User A still owns 50 tokens
   - Supply remains 100

4. **Actual Result** (current implementation):
   - Transaction succeeds
   - User A balance: 0
   - Zero address balance: 50 (inaccessible)
   - NFTProtocolInfo.Supply: **Still 100** (incorrect!)
   - NFTInfo.Quantity: **Still 100** (incorrect!)
   - No Burned event emitted
   - Tokens effectively destroyed without updating supply metrics
   - **Invariant broken**: Sum of accessible balances (50) ≠ recorded Supply (100)

**Success Condition**: Tokens are transferred to an invalid address, balance is debited from sender, credited to invalid address, but supply metrics (`NFTProtocolInfo.Supply` and `NFTInfo.Quantity`) remain unchanged, breaking accounting invariants.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L21-35)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
```

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L69-95)
```csharp
    private void DoTransferFrom(Address from, Address to, Address spender, string symbol, long amount, string memo)
    {
        AssertValidInputAddress(from);
        AssertValidInputAddress(to);
        
        // First check allowance.
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }

        DoTransfer(from, to, symbol, amount, memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput()
            { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
    }
```

**File:** src/AElf.Types/Types/Address.cs (L49-58)
```csharp
        public static Address FromBytes(byte[] bytes)
        {
            if (bytes.Length != AElfConstants.AddressHashLength)
                throw new ArgumentException("Invalid bytes.", nameof(bytes));

            return new Address
            {
                Value = ByteString.CopyFrom(bytes)
            };
        }
```

**File:** protobuf/nft_contract.proto (L261-285)
```text
message NFTProtocolInfo {
    // The symbol of the token.
    string symbol = 1;
    // The minted number of the token.
    int64 supply = 2;
    // The total number of the token.
    int64 total_supply = 3;
    // The address that creat the token.
    aelf.Address creator = 4;
    // Base Uri.
    string base_uri = 5;
    // A flag indicating if this token is burnable.
    bool is_burnable = 6;
    // The chain to mint this token.
    int32 issue_chain_id = 7;
    // The metadata of the token.
    Metadata metadata = 8;
    // NFT Type.
    string nft_type = 9;
    // Protocol name, aka token name in MultiToken Contract.
    string protocol_name = 10;
    // Is token id can be reused.
    bool is_token_id_reuse = 11;
    int64 issued = 12;
}
```
