# Audit Report

## Title
NFT Contract Memo Validation Bypass Enables Storage Bloat DoS Attack

## Summary
The NFT contract's `Transfer` and `TransferFrom` methods accept unbounded memo strings without validation, while the MultiToken and Economic contracts enforce a 64-byte limit. This inconsistency allows attackers to exploit NFT transfers to cause disproportionate blockchain storage bloat through event data accumulation.

## Finding Description

The AElf codebase establishes a clear security control pattern for memo field validation across system contracts. Both the MultiToken and Economic contracts define a `MemoMaxLength` constant of 64 bytes to prevent storage bloat: [1](#0-0) [2](#0-1) 

The MultiToken contract enforces this limit through the `AssertValidMemo` method, which validates memo length using UTF-8 byte count: [3](#0-2) 

This validation is consistently invoked in the `DoTransfer` method before firing transfer events: [4](#0-3) 

The Economic contract implements identical memo validation: [5](#0-4) 

**However, the NFT contract completely omits this protection.** The `Transfer` method directly fires the `Transferred` event with the unvalidated memo from user input: [6](#0-5) 

The `TransferFrom` method exhibits the same vulnerability: [7](#0-6) 

The protobuf definitions for `TransferInput` and `TransferFromInput` declare memo fields without size constraints: [8](#0-7) [9](#0-8) 

The NFT contract constants file contains no `MemoMaxLength` definition or validation helpers: [10](#0-9) 

## Impact Explanation

This vulnerability enables a **storage amplification attack**. Events fired via `Context.Fire` are permanently stored in blockchain `TransactionResult.Logs`. While transaction fees are calculated based on input size (which includes the memo), the event output **also stores the memo**, effectively doubling the storage footprint without corresponding fee increases.

**Attack mechanics:**
1. Attacker mints or acquires NFTs through normal protocol operations
2. Repeatedly calls `Transfer` or `TransferFrom` with memos approaching the 5MB transaction size limit [11](#0-10) 
3. Each transaction stores the memo twice: once in input, once in event logs
4. Transaction fees only account for input size, not the duplicated event storage

**Concrete impacts:**
- **Storage Exhaustion**: At ~5MB per memo across thousands of transactions, rapid blockchain storage consumption
- **Indexing Degradation**: Event indexers must process and store bloated event data, slowing queries and real-time monitoring
- **Node Operational Costs**: Storage costs increase disproportionately to fee revenue

The severity is **Medium** because while it requires economic investment (transaction fees), the 2:1 storage-to-cost multiplier enables systematic degradation. This is not immediately critical but can measurably degrade protocol operations over time.

## Likelihood Explanation

**Entry points are readily accessible:**
- `Transfer` and `TransferFrom` are public methods callable by any NFT owner
- No special permissions required beyond token ownership
- Easily automatable across multiple addresses/NFTs

**Preconditions are trivial:**
- Attacker simply needs to own NFTs (achievable through minting or purchase)
- No timing constraints or complex state manipulation required

**Economic feasibility:**
- Transaction fees scale with input size, providing some cost barrier
- However, the event duplication creates a 2:1 storage cost ratio
- Over many transactions, this multiplier makes the attack economically viable
- No automated monitoring likely exists for abnormal memo sizes in NFT transfers

**Detection challenges:**
- Large memos would be visible in explorers
- But may not trigger alerts if memo size monitoring isn't implemented for NFT contracts specifically

## Recommendation

Implement consistent memo validation across all token contracts. Add the following to `NFTContract_UseChain.cs`:

1. Add memo validation constant to `NFTContractConstants.cs`:
```csharp
public const int MemoMaxLength = 64;
```

2. Add validation helper method:
```csharp
private void AssertValidMemo(string memo)
{
    Assert(memo == null || Encoding.UTF8.GetByteCount(memo) <= NFTContractConstants.MemoMaxLength,
        "Invalid memo size.");
}
```

3. Invoke validation in both `Transfer` and `TransferFrom` methods before firing events:
```csharp
AssertValidMemo(input.Memo);
```

This aligns the NFT contract with the security controls already present in MultiToken and Economic contracts, closing the storage bloat attack vector.

## Proof of Concept

```csharp
// Test demonstrating unbounded memo acceptance in NFT Transfer
[Fact]
public async Task NFT_Transfer_Accepts_Unbounded_Memo()
{
    // Setup: Create NFT protocol and mint token
    var symbol = await CreateNFTProtocol();
    var tokenId = await MintNFT(symbol);
    
    // Attack: Transfer with 1MB memo (would be rejected by MultiToken)
    var largeMemo = new string('A', 1024 * 1024); // 1MB
    
    var transferInput = new TransferInput
    {
        To = UserAddress,
        Symbol = symbol,
        TokenId = tokenId,
        Amount = 1,
        Memo = largeMemo
    };
    
    // Execute transfer - should succeed (demonstrating vulnerability)
    var result = await NFTContractStub.Transfer.SendAsync(transferInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify event contains full memo
    var transferredEvent = result.TransactionResult.Logs
        .First(l => l.Name == nameof(Transferred))
        .NonIndexed;
    var eventData = Transferred.Parser.ParseFrom(transferredEvent);
    eventData.Memo.ShouldBe(largeMemo);
    
    // Compare: Same operation would fail in MultiToken with memo > 64 bytes
}
```

## Notes

This vulnerability represents a **security control inconsistency** rather than a critical protocol break. The fact that MultiToken and Economic contracts explicitly protect against this pattern validates the threat model - the developers recognized memo size as a potential attack vector but failed to apply the same protection to the NFT contract. The 5MB transaction size limit provides an upper bound per transaction, but does not prevent the storage amplification attack across multiple transactions.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L8-8)
```csharp
    public const int MemoMaxLength = 64;
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L57-80)
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
    }
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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```
