# Audit Report

## Title
TokenHolder Scheme Symbol Overwrite Causes Permanent Fund Lock

## Summary
The `CreateScheme` method in TokenHolderContract allows a scheme manager to overwrite an existing scheme without validation, enabling symbol changes that permanently lock user funds. When the scheme symbol is changed after users lock tokens, the `Withdraw` function queries locked balances using the new symbol instead of the original, returning zero and leaving tokens permanently inaccessible.

## Finding Description

The vulnerability exists because `CreateScheme` directly overwrites the stored scheme without checking if one already exists. [1](#0-0) 

When users lock tokens via `RegisterForProfits`, the tokens are locked using the current scheme's symbol at the time of registration. [2](#0-1) 

The critical architectural issue is that the MultiToken contract computes the virtual address for locking WITHOUT including the symbol in the hash computation. [3](#0-2)  The same symbol-independent hash is used during unlock operations. [4](#0-3) 

The virtual address computation for querying locked amounts also excludes the symbol. [5](#0-4) 

During withdrawal, `GetLockedAmount` queries the balance at the virtual address using the CURRENT scheme symbol, not the original symbol used during locking. [6](#0-5)  The `Withdraw` function then retrieves the current scheme and uses its symbol for the unlock operation. [7](#0-6) 

**Attack Sequence:**
1. Manager creates scheme with Symbol = "ELF"
2. Users lock 1,000 ELF tokens via `RegisterForProfits`
3. Manager calls `CreateScheme` again with Symbol = "USDT" (overwrites scheme)
4. User calls `Withdraw`:
   - Retrieves scheme with Symbol = "USDT"
   - Queries locked amount for "USDT" at virtual address
   - Returns 0 (virtual address only contains "ELF" tokens)
   - Unlocks 0 tokens
5. Original 1,000 ELF tokens remain permanently locked

The scheme symbol must remain constant throughout the scheme's lifetime, but no validation enforces this invariant.

## Impact Explanation

This vulnerability results in **permanent, irreversible fund loss** for all users who registered before the scheme overwrite:

- **Direct Loss**: All locked tokens become permanently inaccessible because the withdrawal logic queries for the wrong token symbol at the virtual address
- **Scale**: Affects every beneficiary who called `RegisterForProfits` under the original scheme
- **Irreversibility**: The virtual address holding original tokens cannot be accessed because the contract state no longer stores the original symbol - there is no recovery mechanism
- **Broken Invariant**: Violates the fundamental lock/unlock correctness guarantee - users cannot withdraw what they deposited

**Severity: CRITICAL** - Results in permanent fund loss with no recovery mechanism.

## Likelihood Explanation

**Trigger Conditions:**
- Single call to `CreateScheme` by the scheme manager with a different symbol
- No special permissions required beyond being the scheme manager (any address can create schemes for itself via the public `CreateScheme` method)
- Low complexity - no multi-step attack or timing requirements

**Realistic Scenarios:**
1. **Operational Error**: Manager accidentally calls `CreateScheme` twice during initial setup, using different token symbols
2. **Contract Upgrade**: Management transition or scheme reinitialization attempts lead to unintended overwrite
3. **Malicious Manager**: Compromised or rogue manager intentionally locks user funds

**Detection Difficulty:**
- No events emitted on scheme overwrite
- Silent failure mode - withdrawals succeed but unlock zero tokens
- Users discover the issue only when attempting withdrawal

**Probability: MEDIUM-HIGH** - While scheme managers are typically project owners, the lack of validation creates substantial operational risk through human error, even without malicious intent. Scheme managers are NOT listed as trusted roles in the threat model.

## Recommendation

Add validation in `CreateScheme` to prevent overwriting existing schemes:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation to prevent overwrite
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
        "Scheme already exists for this manager.");
    
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

Alternatively, if scheme updates are intended, implement a dedicated `UpdateScheme` method that validates no users have active locks before allowing symbol changes.

## Proof of Concept

```csharp
[Fact]
public async Task SchemeSymbolOverwrite_CausesPermanentFundLock_Test()
{
    var lockAmount = 1000L;
    var nativeTokenSymbol = "ELF";
    
    // Step 1: Manager creates scheme with Symbol="ELF"
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = nativeTokenSymbol,
        MinimumLockMinutes = 0
    });
    
    // Step 2: User locks 1000 ELF tokens
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = lockAmount,
        SchemeManager = Starter
    });
    
    var balanceAfterLock = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = nativeTokenSymbol,
        Owner = Starter
    })).Balance;
    
    // Step 3: Manager overwrites scheme with Symbol="USDT" (vulnerability!)
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "USDT",  // Different symbol!
        MinimumLockMinutes = 0
    });
    
    // Verify scheme was overwritten
    var overwrittenScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    overwrittenScheme.Symbol.ShouldBe("USDT");  // Now shows USDT instead of ELF
    
    // Step 4: User attempts to withdraw - FAILS to unlock tokens
    await TokenHolderContractStub.Withdraw.SendAsync(Starter);
    
    // Step 5: Verify funds are permanently locked
    var balanceAfterWithdraw = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = nativeTokenSymbol,
        Owner = Starter
    })).Balance;
    
    // VULNERABILITY CONFIRMED: Balance unchanged - tokens remain locked!
    balanceAfterWithdraw.ShouldBe(balanceAfterLock);  // Tokens NOT returned
    // Expected: balanceAfterWithdraw == balanceAfterLock + lockAmount
    // Actual: balanceAfterWithdraw == balanceAfterLock (funds permanently locked)
}
```

## Notes

This vulnerability demonstrates a critical state inconsistency between the TokenHolderContract's scheme metadata and the actual locked token state in the MultiToken contract. The root cause is the combination of:

1. Unchecked scheme overwriting in `CreateScheme`
2. Symbol-independent virtual address computation in MultiToken's lock/unlock mechanism
3. Symbol-dependent balance queries during withdrawal

The virtual address acts as a "container" that can hold multiple token types, but the withdrawal logic assumes it queries the correct symbol. When the scheme symbol changes, the query targets a different token type at the same virtual address, returning zero balance and leaving the original tokens inaccessible.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-165)
```csharp
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L213-236)
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

        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");

        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L208-210)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L234-235)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L101-115)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L118-123)
```csharp
    public override Address GetVirtualAddressForLocking(GetVirtualAddressForLockingInput input)
    {
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        return virtualAddress;
```
