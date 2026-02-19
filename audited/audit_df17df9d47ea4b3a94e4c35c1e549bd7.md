### Title
NFT Contract Memo Validation Bypass Enables Storage Bloat DoS Attack

### Summary
The NFT contract's `Transfer` and `TransferFrom` methods accept unbounded memo strings without validation, while the MultiToken and Economic contracts enforce a 64-byte limit. Attackers can exploit this inconsistency to include arbitrarily large memos in NFT transfer transactions, causing blockchain storage bloat through event data accumulation and degrading indexing/query performance.

### Finding Description

The AElf codebase defines a `MemoMaxLength` constant of 64 bytes in both the MultiToken and Economic contracts to prevent storage bloat: [1](#0-0) [2](#0-1) 

The MultiToken contract consistently validates memo length using UTF-8 byte count before any transfer operation: [3](#0-2) 

This validation is invoked in the `DoTransfer` method that all transfer paths use: [4](#0-3) 

Similarly, the Economic contract validates memos before issuing tokens: [5](#0-4) 

**However, the NFT contract completely bypasses this protection.** The NFT contract's `Transfer` method accepts a memo parameter but directly fires the event without any validation: [6](#0-5) 

The `TransferFrom` method has the same vulnerability: [7](#0-6) 

The memo field is defined in the NFT protobuf without any size constraint: [8](#0-7) [9](#0-8) 

The NFT contract has no `MemoMaxLength` constant or validation helper defined: [10](#0-9) 

### Impact Explanation

**Storage Bloat DoS:** Events fired via `Context.Fire` are stored permanently in `TransactionResult.Logs` on the blockchain. An attacker can repeatedly call NFT `Transfer` or `TransferFrom` with multi-megabyte memos, causing:

1. **Blockchain Storage Exhaustion**: Each transfer transaction embeds the full memo in the `Transferred` event. At 1 MB per memo across thousands of transactions, this rapidly consumes storage.

2. **Block Size Inflation**: Large event payloads increase block size, potentially affecting block propagation time and network bandwidth.

3. **Indexing Performance Degradation**: Event indexers and bloom filter processors must handle bloated event data, slowing down historical queries and real-time event monitoring.

4. **Operational Costs**: Node operators face increased storage costs without corresponding fee increases if transaction fees are not proportional to memo size.

**Severity Justification**: This is a Medium severity issue because it requires repeated transactions (economic cost barrier) but can systematically degrade protocol operations and storage efficiency. Unlike MultiToken transfers which are protected, NFT transfers provide an unprotected attack vector.

### Likelihood Explanation

**Reachable Entry Point**: The `Transfer` and `TransferFrom` methods are public and callable by any NFT owner without special permissions.

**Feasible Preconditions**: 
- Attacker must own or mint NFTs (achievable through normal protocol usage)
- No special authorization required beyond token ownership
- Can be automated across multiple addresses/NFTs

**Execution Practicality**: 
- Attack is straightforward: call `Transfer(to, symbol, tokenId, LARGE_MEMO, amount)`
- No complex state manipulation or timing requirements
- Can be repeated continuously within transaction fee budget

**Economic Rationality**: If transaction fees are not proportional to memo size in event data, the attack cost may be significantly lower than the storage/operational damage inflicted. The attacker pays per-transaction fees but causes per-byte storage costs.

**Detection**: Large memos in NFT transfer events would be visible in blockchain explorers and indexers, but may not trigger automated alerts if memo size monitoring is not implemented.

### Recommendation

**Immediate Fix**: Add memo validation to the NFT contract consistent with MultiToken/Economic contracts:

1. Add `MemoMaxLength` constant to `NFTContractConstants.cs`:
```csharp
public const int MemoMaxLength = 64;
```

2. Create an `AssertValidMemo` helper method in `NFTContract_Helpers.cs`:
```csharp
private void AssertValidMemo(string memo)
{
    Assert(memo == null || Encoding.UTF8.GetByteCount(memo) <= NFTContractConstants.MemoMaxLength,
        "Invalid memo size.");
}
```

3. Add validation calls in `Transfer` and `TransferFrom` methods before firing events:
```csharp
AssertValidMemo(input.Memo);
```

**Invariant to Enforce**: All contracts accepting memo parameters must validate `Encoding.UTF8.GetByteCount(memo) <= 64` before storing in events or state.

**Regression Test**: Add test case verifying that NFT transfers with 65+ byte memos are rejected with "Invalid memo size" error, matching MultiToken contract behavior.

### Proof of Concept

**Initial State**:
1. Deploy NFT protocol with `Create` method
2. Mint an NFT token to attacker's address
3. Blockchain storage at baseline S₀

**Attack Sequence**:
1. Attacker constructs memo string of 1,048,576 bytes (1 MB)
2. Attacker calls `NFTContract.Transfer`:
   - `to`: victim address (can be self)
   - `symbol`: NFT protocol symbol
   - `token_id`: owned NFT token ID
   - `memo`: 1 MB string
   - `amount`: 1

3. Transaction succeeds without validation error
4. `Transferred` event is fired with full 1 MB memo
5. Event is stored in `TransactionResult.Logs`

**Expected vs Actual**:
- **Expected**: Transaction should revert with "Invalid memo size" error (as MultiToken does)
- **Actual**: Transaction succeeds, storing 1 MB memo in blockchain events

**Success Condition**: Blockchain storage increases by ~1 MB per transaction. After 1,000 such transactions, storage bloats by ~1 GB purely from memo data in NFT transfer events, while equivalent MultiToken transfers would be rejected.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L28-28)
```csharp
    public const char AllSymbolIdentifier = '*';
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L28-28)
```csharp
    public const int MemoMaxLength = 64;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L88-92)
```csharp
    private void AssertValidMemo(string memo)
    {
        Assert(memo == null || Encoding.UTF8.GetByteCount(memo) <= TokenContractConstants.MemoMaxLength,
            "Invalid memo size.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L99-114)
```csharp
    private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
    {
        Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
        Assert(from != to, "Can't do transfer to sender itself.");
        AssertValidMemo(memo);
        ModifyBalance(from, symbol, -amount);
        ModifyBalance(to, symbol, amount);
        Context.Fire(new Transferred
        {
            From = from,
            To = to,
            Symbol = symbol,
            Amount = amount,
            Memo = memo ?? string.Empty
        });
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L262-265)
```csharp
    private void AssertValidMemo(string memo)
    {
        Assert(Encoding.UTF8.GetByteCount(memo) <= EconomicContractConstants.MemoMaxLength, "Invalid memo size.");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L21-34)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L57-79)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var operatorList = State.OperatorMap[input.Symbol][input.From];
        var isOperator = operatorList?.Value.Contains(Context.Sender) ?? false;
        if (!isOperator)
        {
            var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
            Assert(allowance >= input.Amount, "Not approved.");
            State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
        }

        DoTransfer(tokenHash, input.From, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = input.From,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
```

**File:** protobuf/nft_contract.proto (L136-142)
```text
message TransferInput {
    aelf.Address to = 1;
    string symbol = 2;
    int64 token_id = 3;
    string memo = 4;
    int64 amount = 5;
}
```

**File:** protobuf/nft_contract.proto (L144-151)
```text
message TransferFromInput {
    aelf.Address from = 1;
    aelf.Address to = 2;
    string symbol = 3;
    int64 token_id = 4;
    string memo = 5;
    int64 amount = 6;
}
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L1-12)
```csharp
namespace AElf.Contracts.NFT;

public partial class NFTContract
{
    private const int NumberMinLength = 9;

    private const string NftTypeMetadataKey = "aelf_nft_type";
    private const string NftBaseUriMetadataKey = "aelf_nft_base_uri";
    private const string NftTokenIdReuseMetadataKey = "aelf_nft_token_id_reuse";
    private const string AssembledNftsKey = "aelf_assembled_nfts";
    private const string AssembledFtsKey = "aelf_assembled_fts";
}
```
