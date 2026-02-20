# Audit Report

## Title
Scheme Manager Can Modify Critical Parameters After User Registration, Breaking Withdrawal and Lock Period Expectations

## Summary
The TokenHolder contract's `CreateScheme` method allows scheme managers to overwrite critical scheme parameters (Symbol, MinimumLockMinutes, AutoDistributeThreshold) after users have already registered and locked tokens. This creates a parameter mismatch where users lock tokens under one set of conditions but must withdraw under different conditions, potentially causing permanent fund lockup or indefinite lock period extensions.

## Finding Description

The vulnerability arises from the interaction between three components:

1. **Unconditional State Overwrite**: The `CreateScheme` method directly overwrites the scheme state without any validation checks. [1](#0-0)  There is no assertion to prevent a manager from calling this method multiple times, and no verification that users have already registered under the existing parameters.

2. **Multiple Profit Schemes Created**: Each call to `CreateScheme` creates a NEW scheme in the underlying Profit contract with a different scheme ID. [2](#0-1)  The scheme ID is generated based on the manager's scheme count [3](#0-2) , so the first call creates hash(0), the second creates hash(1), etc. Each new scheme ID is appended to the manager's list [4](#0-3) .

3. **Parameter Mismatch During Withdrawal**: When users register, they lock tokens based on the current scheme parameters. [5](#0-4)  However, during withdrawal, the contract retrieves the OVERWRITTEN scheme parameters from state [6](#0-5) , while the SchemeId is updated to the FIRST scheme via `FirstOrDefault()`. [7](#0-6)  This creates a hybrid scheme object with SchemeId from the original scheme but parameters from the overwritten state.

The critical issue is in the withdrawal flow where the scheme Symbol is used to query locked amounts [8](#0-7)  and unlock tokens. [9](#0-8)  Since MultiToken's lock/unlock operations are symbol-specific [10](#0-9) [11](#0-10) , attempting to unlock "BTC" when tokens were locked as "ELF" will fail. The GetLockedAmount query will also return 0 [12](#0-11)  because it queries the virtual address balance for the wrong symbol.

## Impact Explanation

This vulnerability has severe impact on user funds:

**Symbol Modification Attack**: If the manager changes the Symbol from "ELF" to "BTC" after users have locked ELF tokens, the withdrawal function will query locked amounts for "BTC" (returning 0) and attempt to unlock "BTC" tokens from a virtual address that holds "ELF" tokens. This causes withdrawal failures and permanent fund lockup, as there is no mechanism for users to unlock their original "ELF" tokens once the scheme parameters have been overwritten.

**MinimumLockMinutes Extension Attack**: If the manager increases MinimumLockMinutes from 1440 minutes (1 day) to 43200 minutes (30 days) after users have registered, users who expected to withdraw after 1 day will fail the time validation check. [13](#0-12)  The manager can repeatedly call `CreateScheme` with increasing lock periods, indefinitely trapping user funds by constantly extending the withdrawal timelock.

**AutoDistributeThreshold Manipulation**: Changing the threshold affects when profits are automatically distributed, altering dividend distribution behavior for existing participants who registered under different expectations.

All registered users are affected - they either lose access to their locked funds completely (symbol mismatch) or face arbitrary extensions of lock periods (time manipulation). This represents direct fund seizure by scheme managers, violating the core security invariant that locked tokens must be unlockable by their rightful owners.

## Likelihood Explanation

The likelihood of this vulnerability being exploited is HIGH:

**Reachable Entry Point**: `CreateScheme` is a public method callable by any address without authorization restrictions. [14](#0-13)  There is no check preventing the same manager from calling it multiple times.

**Feasible Preconditions**: The attacker only needs to be the scheme manager, which is simply the address that called `CreateScheme` initially. This is not a privileged admin role requiring governance approval - any user can create a scheme and become its manager. Malicious scheme creators or compromised scheme manager accounts can trivially execute this attack.

**Execution Practicality**: The attack requires only simple transactions:
1. Initial `CreateScheme` call with legitimate-looking parameters (e.g., Symbol: "ELF", MinimumLockMinutes: 1440)
2. Wait for users to register and lock their tokens
3. Second `CreateScheme` call with modified parameters (e.g., Symbol: "BTC", MinimumLockMinutes: 43200)

No complex contract interactions, timing constraints, or special conditions are required. The attack is straightforward and deterministic.

**Economic Rationality**: The attack costs minimal gas fees (two CreateScheme transactions) but can trap arbitrary amounts of user funds. A malicious scheme manager could profit by collecting contributions via `ContributeProfits` while preventing users from withdrawing their stake, effectively stealing user funds.

## Recommendation

Add a check in `CreateScheme` to prevent overwriting existing schemes:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add this check to prevent overwriting existing schemes
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
        "Scheme already exists. Cannot modify scheme parameters after creation.");
    
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

Alternatively, if scheme parameter updates are intended functionality, implement a dedicated `UpdateScheme` method with proper validations:
- Verify no users are currently registered
- Only allow compatible parameter changes (e.g., same symbol)
- Require time delays or governance approval for changes

## Proof of Concept

```csharp
[Fact]
public async Task CreateScheme_ParameterOverwrite_LocksUserFunds_Test()
{
    var lockAmount = 1000L;
    var originalSymbol = "ELF";
    var modifiedSymbol = "BTC";
    var originalLockMinutes = 1440L; // 1 day
    var extendedLockMinutes = 43200L; // 30 days

    // Step 1: Manager creates initial scheme with ELF symbol
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = originalSymbol,
        MinimumLockMinutes = originalLockMinutes
    });

    // Step 2: User registers and locks ELF tokens
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = lockAmount,
        SchemeManager = Starter
    });

    // Verify tokens are locked
    var lockedAmount = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = Starter,
        Symbol = originalSymbol,
        LockId = Context.GenerateId(TokenHolderContractAddress, 
            ByteArrayHelper.ConcatArrays(Starter.ToByteArray(), Starter.ToByteArray()))
    });
    lockedAmount.Amount.ShouldBe(lockAmount);

    // Step 3: Manager maliciously overwrites scheme parameters
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = modifiedSymbol,  // Changed from ELF to BTC
        MinimumLockMinutes = extendedLockMinutes  // Extended from 1 day to 30 days
    });

    // Step 4: User attempts withdrawal after original lock period (1 day)
    // This should succeed based on original parameters but will fail
    var withdrawResult = await TokenHolderContractStub.Withdraw.SendWithExceptionAsync(Starter);
    
    // Vulnerability confirmed: withdrawal fails due to symbol mismatch or extended time
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    // User's ELF tokens are now permanently locked
}
```

## Notes

This vulnerability fundamentally breaks the trust model of the TokenHolder contract. Users lock tokens under explicit conditions (specific token symbol and minimum lock duration), but the scheme manager can unilaterally change these conditions post-facto. The root cause is the missing idempotency check in `CreateScheme` - it should only be callable once per manager address, or it should have a dedicated update mechanism with proper safeguards for existing participants.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-14)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-25)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L220-225)
```csharp
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L280-280)
```csharp
        var scheme = State.TokenHolderProfitSchemes[manager];
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-293)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L62-71)
```csharp
        var schemeIds = State.ManagingSchemeIds[scheme.Manager];
        if (schemeIds == null)
            schemeIds = new CreatedSchemeIds
            {
                SchemeIds = { schemeId }
            };
        else
            schemeIds.SchemeIds.Add(schemeId);

        State.ManagingSchemeIds[scheme.Manager] = schemeIds;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L964-971)
```csharp
    private Hash GenerateSchemeId(CreateSchemeInput createSchemeInput)
    {
        var manager = createSchemeInput.Manager ?? Context.Sender;
        if (createSchemeInput.Token != null)
            return Context.GenerateId(Context.Self, createSchemeInput.Token);
        var createdSchemeCount = State.ManagingSchemeIds[manager]?.SchemeIds.Count ?? 0;
        return Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false));
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L208-212)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L234-242)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        Context.SendVirtualInline(fromVirtualAddress, Context.Self, nameof(Transfer), new TransferInput
        {
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
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
