# Audit Report

## Title
Scheme Overwriting Causes Permanent Token Lock Due to Symbol Mismatch

## Summary
The TokenHolder contract's `CreateScheme` method allows overwriting an existing scheme without validation, causing users who locked tokens under the original scheme to permanently lose access to their funds. When users attempt to withdraw, the contract queries locked amounts using the new scheme's symbol instead of the original symbol, resulting in transaction revert and making tokens irrecoverable.

## Finding Description

The vulnerability occurs due to a critical mismatch between the token symbol used during lock and unlock operations.

**Root Cause - Scheme Overwriting:**
The `CreateScheme` method directly overwrites the scheme data without any validation to prevent duplicate calls or check for existing user registrations. [1](#0-0) 

**Lock Operation - Original Symbol:**
When users call `RegisterForProfits`, tokens are locked using the current scheme's symbol. The lock ID is generated deterministically based only on manager and user addresses. [2](#0-1) 

**Withdraw Operation - New Symbol:**
When users call `Withdraw` after the scheme has been overwritten, the contract retrieves the current (new) scheme and uses its symbol to query locked amounts. [3](#0-2) 

**Symbol Mismatch in GetLockedAmount:**
The `GetLockedAmount` method queries the balance of a specific symbol at the virtual address. Since tokens were locked with the original symbol but the query uses the new symbol, it returns zero. [4](#0-3) 

**Transaction Revert:**
The withdraw operation attempts to unlock zero tokens, which fails validation that requires `amount > 0`. [5](#0-4)  This causes the entire transaction to revert, leaving the lock state intact. [6](#0-5) 

**No Recovery Path:**
Users cannot retry `Withdraw` (same revert occurs) and cannot call `RegisterForProfits` again due to the "Already registered" check. [7](#0-6)  No administrative unlock mechanism exists in the TokenHolder contract.

## Impact Explanation

This is **HIGH severity** due to:

1. **Complete Fund Loss**: Users lose 100% of their locked tokens with no possibility of recovery
2. **Multiple Users Affected**: All users who registered before the scheme overwrite are simultaneously impacted
3. **No Administrative Recovery**: Neither users nor managers have any mechanism to rescue the locked funds
4. **Protocol Invariant Break**: Violates the fundamental contract guarantee that users can withdraw locked tokens after the minimum lock period expires

The locked tokens remain at the virtual address indefinitely, completely inaccessible to all parties. This represents direct, permanent loss of user funds.

## Likelihood Explanation

This vulnerability is **HIGHLY LIKELY** to occur because:

1. **Public Entry Point**: `CreateScheme` is a public method accessible to any address [8](#0-7) 

2. **Simple Trigger**: Requires only two calls to `CreateScheme` by the same manager address - no complex state manipulation needed

3. **Accidental Scenario**: A manager might innocently call `CreateScheme` twice thinking they're "updating" scheme parameters (changing symbol or lock duration), without realizing this will brick all existing user deposits

4. **Malicious Scenario**: A malicious manager can intentionally lock user funds to prevent withdrawals

5. **No Warnings**: The contract provides no warnings or checks that would alert the manager about existing user registrations before overwriting

## Recommendation

Add validation to prevent scheme overwriting when users have already registered:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add check to prevent overwriting existing scheme
    var existingScheme = State.TokenHolderProfitSchemes[Context.Sender];
    Assert(existingScheme == null || existingScheme.Symbol == null, 
        "Scheme already exists. Cannot overwrite existing scheme.");
    
    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
    {
        Manager = Context.Sender,
        IsReleaseAllBalanceEveryTimeByDefault = true,
        CanRemoveBeneficiaryDirectly = true
    });

    State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
    {
        Symbol = input.Symbol,
        MinimumLockMinutes = input.MinimumLockMinutes,
        AutoDistributeThreshold = { input.AutoDistributeThreshold }
    };

    return new Empty();
}
```

Alternatively, add an `UpdateScheme` method that validates the symbol remains unchanged or require all users to withdraw before allowing scheme updates.

## Proof of Concept

```csharp
[Fact]
public async Task SchemeOverwriteCausesPermanentTokenLock()
{
    // Manager creates initial scheme with ELF symbol
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });

    // Issue tokens to user
    var userStub = GetTokenHolderContractTester(UserKeyPairs[0]);
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ELF",
        Amount = 1000,
        To = UserAddresses[0]
    });

    // User registers and locks 1000 ELF tokens
    await userStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = Starter,
        Amount = 1000
    });

    // Manager accidentally calls CreateScheme again with different symbol
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "USDT",
        MinimumLockMinutes = 200
    });

    // User tries to withdraw after lock period
    // This will REVERT with "Invalid amount" error because:
    // - GetLockedAmount queries for "USDT" balance at virtual address
    // - But tokens were locked as "ELF"
    // - Returns 0, causing AssertValidSymbolAndAmount to fail
    var withdrawResult = await userStub.Withdraw.SendWithExceptionAsync(Starter);
    withdrawResult.TransactionResult.Error.ShouldContain("Invalid amount");

    // Tokens are permanently locked - no recovery possible
}
```

**Notes**

This vulnerability represents a critical design flaw in the TokenHolder contract where scheme metadata can be changed without consideration for existing user locks. The deterministic lock ID generation based only on manager and user addresses creates a permanent binding between users and schemes, but the scheme data itself is mutable. This mismatch between immutable lock references and mutable scheme data creates the permanent lock condition. The issue is exacerbated by the lack of any administrative recovery mechanisms or emergency withdrawal functions.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-14)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L151-151)
```csharp
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L157-166)
```csharp
        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L213-225)
```csharp
        var scheme = GetValidScheme(input);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = State.LockIds[input][Context.Sender];
        Assert(lockId != null, "Sender didn't register for profits.");
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L230-238)
```csharp
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });

        State.LockIds[input].Remove(Context.Sender);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L101-116)
```csharp
    public override GetLockedAmountOutput GetLockedAmount(GetLockedAmountInput input)
    {
        Assert(input.LockId != null, "Lock id cannot be null.");
        var virtualAddress = GetVirtualAddressForLocking(new GetVirtualAddressForLockingInput
        {
            Address = input.Address,
            LockId = input.LockId
        });
        return new GetLockedAmountOutput
        {
            Symbol = input.Symbol,
            Address = input.Address,
            LockId = input.LockId,
            Amount = GetBalance(virtualAddress, input.Symbol)
        };
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
