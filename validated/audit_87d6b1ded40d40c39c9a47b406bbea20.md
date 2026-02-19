# Audit Report

## Title
State Corruption in TokenHolder Scheme Updates via Cross-Scheme Operations

## Summary
The `UpdateTokenHolderProfitScheme` function incorrectly writes scheme data to `Context.Sender`'s address instead of the intended `manager` address, causing state corruption when users interact with schemes managed by others. When a scheme manager interacts with an uninitialized scheme (SchemeId == null), their own scheme data gets overwritten with the target scheme's data, rendering withdrawals inoperable for users registered to their scheme.

## Finding Description
The root cause exists in the `UpdateTokenHolderProfitScheme` function where scheme data is persisted to the wrong address mapping key. [1](#0-0) 

This function receives the `manager` parameter indicating whose scheme should be updated, but writes to `State.TokenHolderProfitSchemes[Context.Sender]` instead of `State.TokenHolderProfitSchemes[manager]`. The scheme data structure is defined as a mapping keyed by manager addresses: [2](#0-1) 

The vulnerable function is invoked through `GetValidScheme`, which is called from multiple public entry points: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

**Attack Execution Path:**
1. Alice creates SchemeA with Symbol="USDT", MinimumLockMinutes=60
2. Bob creates SchemeB with Symbol="ELF", MinimumLockMinutes=120  
3. Users register to Bob's scheme, locking "ELF" tokens
4. Bob calls `ClaimProfits` with `SchemeManager = Alice`
5. `GetValidScheme(Alice)` loads Alice's scheme from `State.TokenHolderProfitSchemes[Alice]`
6. Since Alice's scheme has `SchemeId == null` (uninitialized), the conditional at line 289 passes and `UpdateTokenHolderProfitScheme` executes: [7](#0-6) 

7. Line 298 writes Alice's scheme data (Symbol="USDT", MinimumLockMinutes=60) to `State.TokenHolderProfitSchemes[Bob]`, corrupting Bob's scheme
8. Users registered to Bob's scheme now reference corrupted data with wrong token symbol and lock duration

Test evidence confirms schemes have `SchemeId == null` immediately after creation: [8](#0-7) 

The scheme structure includes critical fields that control withdrawal validation: [9](#0-8) 

## Impact Explanation
When Bob's scheme is corrupted, the `Symbol` and `MinimumLockMinutes` fields are replaced with Alice's values. This breaks withdrawals for all users registered to Bob's scheme: [10](#0-9) 

The `Withdraw` function retrieves the locked token amount using the corrupted scheme's symbol. Since users locked "ELF" but the corrupted scheme now specifies "USDT", the unlock operation will fail or return zero amount. [11](#0-10) 

Additionally, the lock time validation uses the corrupted `MinimumLockMinutes`, potentially causing incorrect timing checks.

**Affected Parties:**
- Users who locked tokens in Bob's scheme lose access to their funds (effective DoS)
- Bob's scheme becomes permanently unusable
- Any scheme manager who interacts with uninitialized schemes risks corruption

**Severity:** High - causes operational DoS and effective permanent fund lockup for scheme participants.

## Likelihood Explanation
**Attacker Capabilities:** No special privileges required. Any user can:
1. Create their own scheme (become a manager) via the public `CreateScheme` method
2. Interact with another scheme via `ClaimProfits`, `RegisterForProfits`, `ContributeProfits`, or `Withdraw`

**Attack Complexity:** Low
- Normal transaction sequence using public methods
- No timing requirements beyond the target scheme being uninitialized  
- No economic cost beyond standard transaction fees
- Multiple entry points available (`ClaimProfits`, `RegisterForProfits`, `ContributeProfits`, `Withdraw`)

**Feasibility Conditions:**
- Target scheme must have `SchemeId == null` (window exists after `CreateScheme` call until first operation that triggers `GetValidScheme`)
- Attacker must be a scheme manager (trivially achievable by calling `CreateScheme`)

**Probability:** Medium - While schemes typically get initialized quickly in production, the vulnerability window definitively exists and the operation sequence is natural (managers legitimately participating in multiple schemes). The attack can be triggered through normal cross-scheme interactions.

## Recommendation
Change line 298 to write scheme data to the correct address key:

```csharp
State.TokenHolderProfitSchemes[manager] = scheme;
```

This ensures scheme updates are persisted to the intended manager's address rather than the transaction sender's address.

## Proof of Concept
```csharp
[Fact]
public async Task SchemeCorruption_CrossSchemeOperation_Test()
{
    // Alice creates SchemeA with Symbol="ELF"
    var aliceStub = GetTester<TokenHolderContractImplContainer.TokenHolderContractImplStub>(
        TokenHolderContractAddress, UserKeyPairs[0]);
    var aliceAddress = UserAddresses[0];
    
    await aliceStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 60
    });
    
    // Bob creates SchemeB with Symbol="WRITE" 
    var bobStub = GetTester<TokenHolderContractImplContainer.TokenHolderContractImplStub>(
        TokenHolderContractAddress, UserKeyPairs[1]);
    var bobAddress = UserAddresses[1];
    
    await bobStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "WRITE", // Different token
        MinimumLockMinutes = 120 // Different lock time
    });
    
    // Verify Bob's scheme has correct symbol
    var bobSchemeBefore = await bobStub.GetScheme.CallAsync(bobAddress);
    bobSchemeBefore.Symbol.ShouldBe("WRITE");
    bobSchemeBefore.MinimumLockMinutes.ShouldBe(120);
    
    // Bob calls ClaimProfits on Alice's scheme
    await bobStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeManager = aliceAddress
    });
    
    // Bob's scheme is now corrupted with Alice's data
    var bobSchemeAfter = await bobStub.GetScheme.CallAsync(bobAddress);
    bobSchemeAfter.Symbol.ShouldBe("ELF"); // CORRUPTED: Changed from "WRITE" to "ELF"
    bobSchemeAfter.MinimumLockMinutes.ShouldBe(60); // CORRUPTED: Changed from 120 to 60
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L102-102)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L213-213)
```csharp
        var scheme = GetValidScheme(input);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L220-225)
```csharp
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L230-236)
```csharp
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L249-249)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L289-289)
```csharp
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L298-298)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs (L10-10)
```csharp
    public MappedState<Address, TokenHolderProfitScheme> TokenHolderProfitSchemes { get; set; }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L45-45)
```csharp
            tokenHolderProfitScheme.SchemeId.ShouldBeNull();
```

**File:** protobuf/token_holder_contract.proto (L116-127)
```text
message TokenHolderProfitScheme {
    // The token symbol.
    string symbol = 1;
    // The scheme id.
    aelf.Hash scheme_id = 2;
    // The current dividend period.
    int64 period = 3;
    // Minimum lock time for holding token.
    int64 minimum_lock_minutes = 4;
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 5;
}
```
