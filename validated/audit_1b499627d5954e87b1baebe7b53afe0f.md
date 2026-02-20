# Audit Report

## Title
Period Desynchronization Between TokenHolder and Profit Contracts Causes DOS in RegisterForProfits

## Summary
The TokenHolder contract maintains a local `Period` counter that becomes desynchronized from ProfitContract's `CurrentPeriod` when managers call `ProfitContract.DistributeProfits` directly. This causes `RegisterForProfits` with auto-distribute to revert with "Invalid period" errors, creating a DOS condition for new user registrations.

## Finding Description

The vulnerability stems from improper period synchronization between TokenHolder and Profit contracts.

**Root Cause:**

TokenHolder's `RegisterForProfits` method retrieves the scheme without period synchronization: [1](#0-0) 

This calls `GetValidScheme` with the default `updateSchemePeriod = false` parameter: [2](#0-1) 

When `updateSchemePeriod` is false and `SchemeId` is already set, `UpdateTokenHolderProfitScheme` returns early without syncing the period from ProfitContract: [3](#0-2) 

Meanwhile, ProfitContract explicitly allows scheme managers to call `DistributeProfits` directly: [4](#0-3) 

When called directly, ProfitContract increments its `CurrentPeriod`: [5](#0-4) 

**Attack Flow:**

1. Manager creates TokenHolder scheme with auto-distribute threshold
2. Manager calls `ProfitContract.DistributeProfits` directly, advancing ProfitContract's period
3. User calls `TokenHolder.RegisterForProfits` when auto-distribute threshold is met
4. Auto-distribute logic uses the stale period from TokenHolder: [6](#0-5) 
5. ProfitContract validates the period and fails: [7](#0-6) 
6. Transaction reverts with "Invalid period" error

**Additional Bug:**

The synchronization logic also contains a storage bug where it saves to `Context.Sender` instead of the `manager` parameter: [8](#0-7) 

This can save period updates to incorrect addresses, further compounding synchronization issues.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes complete DOS of the `RegisterForProfits` function when auto-distribute thresholds are configured:

- **Core Functionality Broken**: Users cannot stake tokens and register for profit schemes, which is the primary purpose of TokenHolder contract
- **Permanent DOS**: Once desynchronized, every `RegisterForProfits` call with auto-distribute will fail until manually recovered
- **Economic Impact**: New participants cannot join profit schemes, breaking the token holder dividend mechanism
- **User Experience**: Failed transactions with cryptic "Invalid period" errors cause confusion

While the manager can recover by calling `TokenHolder.DistributeProfits` (which uses `updateSchemePeriod = true`), this requires manual intervention and may not be known to managers.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability has high probability of occurrence:

- **Accidental Trigger**: Can happen unintentionally if managers use both TokenHolder and ProfitContract interfaces
- **No Cost**: Only requires normal transaction fees to trigger
- **Public Methods**: Both entry points are publicly accessible with documented APIs
- **Common Configuration**: Auto-distribute thresholds are a standard feature
- **Repeatable**: Manager can continuously trigger desync by calling ProfitContract directly
- **No Detection**: Desynchronization is invisible until users attempt registration

The attack requires no special privileges beyond being a scheme manager (legitimate role), and can occur through normal contract usage patterns.

## Recommendation

**Fix 1: Always synchronize period in RegisterForProfits**

Modify `RegisterForProfits` to use `updateSchemePeriod = true`: [1](#0-0) 

Change to: `var scheme = GetValidScheme(input.SchemeManager, true);`

**Fix 2: Correct the storage bug**

In `UpdateTokenHolderProfitScheme`, change line 298 to save to the correct address: [8](#0-7) 

Change to: `State.TokenHolderProfitSchemes[manager] = scheme;`

**Fix 3: Prevent direct ProfitContract calls (optional)**

Consider restricting `ProfitContract.DistributeProfits` to only accept calls from TokenHolderContract for TokenHolder-managed schemes, or document the requirement that managers must only use TokenHolder interface.

## Proof of Concept

```csharp
[Fact]
public async Task PeriodDesynchronizationDOS_Test()
{
    // Setup: Manager creates scheme with auto-distribute threshold
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 0,
        AutoDistributeThreshold = { { "ELF", 1000 } }
    });
    
    // Initialize scheme by contributing profits
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 100
    });
    
    var tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(tokenHolderScheme.SchemeId);
    
    // Attack: Manager calls ProfitContract.DistributeProfits directly
    // This advances ProfitContract's period but not TokenHolder's period
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = tokenHolderScheme.SchemeId,
        Period = profitScheme.CurrentPeriod,
        AmountsMap = { { "ELF", 0 } }
    });
    
    // Contribute more profits to meet auto-distribute threshold
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 1000
    });
    
    // DOS: User tries to RegisterForProfits with auto-distribute
    // This will FAIL with "Invalid period" error
    var userStub = GetTokenHolderContractTester(UserKeyPairs[0]);
    var result = await userStub.RegisterForProfits.SendWithExceptionAsync(new RegisterForProfitsInput
    {
        SchemeManager = Starter,
        Amount = 100
    });
    
    result.TransactionResult.Error.ShouldContain("Invalid period");
}
```

## Notes

This vulnerability demonstrates a critical synchronization issue between two tightly-coupled contracts. The TokenHolder contract assumes it is the sole interface for distribution operations, but ProfitContract's authorization logic allows managers to bypass this assumption. The combination of the early-return optimization and the dual-interface design creates an exploitable DOS condition.

The storage bug at line 298 compounds this issue by potentially saving synchronization updates to the wrong address, making recovery even more difficult in certain call patterns.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L196-196)
```csharp
                        Period = scheme.Period
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-284)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
    {
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L289-289)
```csharp
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L298-298)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L479-480)
```csharp
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```
