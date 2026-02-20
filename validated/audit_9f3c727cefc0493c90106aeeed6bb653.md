# Audit Report

## Title
Period Desynchronization Causes RegisterForProfits DoS and Auto-Distribution Failure

## Summary
The TokenHolder contract maintains a cached period value that becomes desynchronized from the Profit contract's CurrentPeriod when distributions are initiated externally by the scheme manager. This desynchronization causes RegisterForProfits transactions to revert during auto-distribution attempts, preventing users from locking tokens and registering as beneficiaries.

## Finding Description

The vulnerability stems from period synchronization issues between the TokenHolder and Profit contracts. When a user creates a TokenHolder profit scheme, they become the scheme manager [1](#0-0) . The scheme manager is authorized to call `Profit.DistributeProfits` directly [2](#0-1) .

When `RegisterForProfits` is called, it retrieves the scheme without updating the period [3](#0-2) . The `GetValidScheme` method with `updateSchemePeriod=false` returns early without synchronizing the period from the Profit contract [4](#0-3) .

During auto-distribution within `RegisterForProfits`, the cached stale period is used to create the distribution input [5](#0-4) . When this distribution request reaches the Profit contract, it performs strict period validation [6](#0-5) .

**Desynchronization Scenario:**
1. Scheme manager calls `Profit.DistributeProfits` directly (bypassing TokenHolder)
2. Profit contract increments `CurrentPeriod` [7](#0-6) 
3. TokenHolder's cached period remains stale (not updated)
4. User calls `RegisterForProfits` triggering auto-distribution [8](#0-7) 
5. Period mismatch causes assertion failure and transaction revert

The TokenHolder contract only updates its cached period when `DistributeProfits` is called with `updateSchemePeriod=true` [9](#0-8) , but this synchronization is bypassed when the manager calls Profit contract directly.

## Impact Explanation

**High Severity - Denial of Service:**
- Complete DoS of `RegisterForProfits` function when auto-distribution is triggered
- Users cannot lock their tokens to participate in profit schemes
- Users cannot become beneficiaries and receive profit distributions
- The auto-distribution mechanism, a core contract feature, becomes unreliable
- Affects all users attempting to register during the desynchronization period
- Requires manual intervention by scheme manager to restore synchronization by calling `TokenHolder.DistributeProfits`

While profits are not lost (they remain in the VirtualAddress and can be distributed later), and double distribution is prevented by the period validation, the operational impact is severe as it breaks a critical user-facing function. Users lose the ability to participate in profit schemes until the period is manually resynchronized.

## Likelihood Explanation

**High Likelihood:**
The vulnerability occurs through normal, authorized operations without requiring any malicious behavior:

1. **Scheme Manager Authority:** Any user who creates a TokenHolder scheme becomes the scheme manager and gains authorization to call `Profit.DistributeProfits` directly [2](#0-1) 
2. **Expected Behavior:** Direct calls to the Profit contract by the manager are authorized and legitimate
3. **No Special Privileges:** No elevated permissions or complex setup required beyond normal scheme creation
4. **Natural Occurrence:** Will happen whenever a scheme manager performs manual distribution outside TokenHolder's control
5. **Immediate Impact:** The issue manifests immediately as failed transactions when users attempt to register

The vulnerability has a high probability of occurrence in any actively managed profit scheme where the manager performs manual distributions.

## Recommendation

The fix should ensure period synchronization occurs in `RegisterForProfits` before auto-distribution is triggered. Modify the `GetValidScheme` call to always update the scheme period:

```csharp
// In RegisterForProfits method, change line 152 from:
var scheme = GetValidScheme(input.SchemeManager);

// To:
var scheme = GetValidScheme(input.SchemeManager, true);
```

This ensures that the cached period is synchronized with the Profit contract's CurrentPeriod before any auto-distribution logic executes, preventing the period mismatch assertion failure.

Alternatively, the auto-distribution logic could be modified to fetch the current period directly from the Profit contract before creating the distribution input, rather than relying on the cached value.

## Proof of Concept

```csharp
[Fact]
public async Task RegisterForProfits_Period_Desynchronization_DoS_Test()
{
    var amount = 1000L;
    var nativeTokenSymbol = "ELF";
    
    // Step 1: Create TokenHolder scheme - Starter becomes manager
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = nativeTokenSymbol,
        AutoDistributeThreshold = { { nativeTokenSymbol, amount } }
    });
    
    // Step 2: Contribute profits to trigger auto-distribution later
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = amount,
        Symbol = nativeTokenSymbol
    });
    
    // Step 3: Manager calls Profit.DistributeProfits directly (bypassing TokenHolder)
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var schemeId = schemeIds.SchemeIds.First();
    
    // This direct call causes desynchronization
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1,
        AmountsMap = { { nativeTokenSymbol, 0 } }
    });
    
    // At this point:
    // - Profit contract's CurrentPeriod = 2
    // - TokenHolder's cached Period = 1
    
    // Step 4: User tries to RegisterForProfits with auto-distribution
    var registerResult = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            Amount = amount,
            SchemeManager = Starter
        });
    
    // This fails with "Invalid period" error due to period mismatch
    registerResult.TransactionResult.Error.ShouldContain("Invalid period");
}
```

## Notes

The vulnerability is specific to scenarios where:
1. Auto-distribution thresholds are configured in the TokenHolder scheme
2. The scheme manager performs distributions directly via the Profit contract
3. Users attempt to register during the period desynchronization window

The root cause is the early return in `UpdateTokenHolderProfitScheme` when `updateSchemePeriod=false` [10](#0-9) , which prevents synchronization with the authoritative CurrentPeriod value from the Profit contract [11](#0-10) .

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-25)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-146)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager, true);
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
        var distributeProfitsInput = new Profit.DistributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Period = scheme.Period
        };
        if (input.AmountsMap != null && input.AmountsMap.Any()) distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

        State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
        scheme.Period = scheme.Period.Add(1);
        State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        return new Empty();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L179-206)
```csharp
        if (scheme.AutoDistributeThreshold != null && scheme.AutoDistributeThreshold.Any())
        {
            var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
            var virtualAddress = originScheme.VirtualAddress;
            Profit.DistributeProfitsInput distributedInput = null;
            foreach (var threshold in scheme.AutoDistributeThreshold)
            {
                var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = virtualAddress,
                    Symbol = threshold.Key
                }).Balance;
                if (balance < threshold.Value) continue;
                if (distributedInput == null)
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
                distributedInput.AmountsMap[threshold.Key] = 0;
                break;
            }

            if (distributedInput == null) return new Empty();
            State.ProfitContract.DistributeProfits.Send(distributedInput);
            scheme.Period = scheme.Period.Add(1);
            State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L286-289)
```csharp
    private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
        bool updateSchemePeriod)
    {
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L297-297)
```csharp
        var newDetail = fixingDetail.Clone();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L478-480)
```csharp
        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```
