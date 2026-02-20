# Audit Report

## Title
Scheme Manager Can DOS Profit Claiming Through Unlimited Empty Period Creation

## Summary
A malicious scheme manager can repeatedly call `DistributeProfits` with empty `AmountsMap`, causing periods to increment indefinitely without distributing any profits. This forces beneficiaries to iterate through potentially millions of empty periods when claiming profits, making profit claiming economically infeasible due to excessive gas costs and transaction requirements.

## Finding Description

The vulnerability exists in the TokenHolder and Profit contracts' period management logic where a scheme manager can abuse the `DistributeProfits` function to create unlimited empty periods that beneficiaries must later traverse during claiming.

**Root Cause**: The TokenHolder contract's `DistributeProfits` function conditionally adds the `AmountsMap` only when it is non-null and non-empty, but unconditionally increments the period counter. [1](#0-0) 

The authorization check allows the scheme manager to call this function. [2](#0-1) 

In the Profit contract, the only protection checks if the period is negative or if `totalShares` is zero. When a scheme has beneficiaries (totalShares > 0), the function proceeds and unconditionally increments `CurrentPeriod` even with empty profits. [3](#0-2) 

When beneficiaries claim profits, the `ProfitAllPeriods` function must iterate from `LastProfitPeriod` to `maxProfitPeriod`. While empty periods are skipped with `continue`, the loop still executes state reads and iterations for each period, consuming gas. [4](#0-3) 

Each claim transaction is limited to processing a maximum number of periods defined by `DefaultMaximumProfitReceivingPeriodCountOfOneTime`. [5](#0-4) 

This limit is enforced through the calculation in `GetMaximumPeriodCountForProfitableDetail`, which divides the maximum period count by the number of profitable details being processed. [6](#0-5) 

## Impact Explanation

**High Severity** - This vulnerability enables an economic denial-of-service attack affecting all beneficiaries of a TokenHolder profit scheme:

1. **Economic DOS**: If an attacker creates 1,000,000 empty periods, users need approximately 10,000 claim transactions (at ~100 periods per transaction). At typical gas costs, this could cost hundreds of dollars per user, making small profit amounts permanently unclaimed as the claiming cost exceeds the profit value.

2. **Availability DOS**: Legitimate users cannot practically claim their profits due to the excessive number of transactions required. Each transaction consumes gas for state reads and loop iterations even though empty periods are skipped.

3. **No Recovery Mechanism**: There is no on-chain mechanism to delete or bulk-skip empty periods once created. The damage is permanent once the attack is executed.

4. **Widespread Impact**: All beneficiaries in the affected scheme become victims simultaneously.

5. **Protocol Reputation**: Such an attack would severely damage the protocol's reputation as users discover their earned profits are inaccessible.

## Likelihood Explanation

**High Likelihood** - The attack is trivially executable:

1. **Minimal Privilege**: The attacker only needs to be a scheme manager, a legitimate role obtained by calling `CreateScheme`. This is not a privilege escalation - it's abuse of existing authority. [7](#0-6) 

2. **Trivial Execution**: The attack requires only repeated calls to `DistributeProfits` with an empty `AmountsMap`.

3. **No Preconditions**: The scheme must have at least one beneficiary (totalShares > 0), which is the normal operational case.

4. **No Rate Limiting**: There are no time locks, cooldown periods, or maximum period count validations to prevent rapid empty period creation.

5. **Immediate Detection, Irreversible Damage**: While the attack is visible on-chain (period increments without profit distribution events), the damage is already done once periods are created with no mechanism to reverse them.

## Recommendation

Implement the following protections in the `DistributeProfits` function:

1. **Validation Check**: Add a check to prevent distribution when `AmountsMap` is empty or null and there are no balances to auto-distribute. In `TokenHolderContract.DistributeProfits`, add:
   ```csharp
   Assert(input.AmountsMap != null && input.AmountsMap.Any(), "Cannot distribute empty profits.");
   ```

2. **Alternative**: In `ProfitContract.DistributeProfits`, prevent period increment when `profitsMap` is empty after all processing:
   ```csharp
   Assert(profitsMap.Any() && profitsMap.Values.Any(v => v > 0), "Cannot distribute zero profits.");
   ```

3. **Period Cleanup**: Implement an administrative function to bulk-skip or reset empty periods for recovery from existing attacks.

4. **Rate Limiting**: Consider adding a minimum time delay between distributions to prevent rapid empty period creation.

## Proof of Concept

```csharp
[Fact]
public async Task SchemeManager_DOS_Through_Empty_Period_Creation()
{
    // Setup: Create scheme and add beneficiary
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF"
    });
    
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 1000
    });
    
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = UserAddresses.First(),
        Shares = 100
    });
    
    var tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var initialPeriod = tokenHolderProfitScheme.Period;
    
    // Attack: Scheme manager creates 1000 empty periods
    for (int i = 0; i < 1000; i++)
    {
        await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
        {
            SchemeManager = Starter,
            AmountsMap = { } // Empty map
        });
    }
    
    // Verify: Period incremented 1000 times without profit distribution
    tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    tokenHolderProfitScheme.Period.ShouldBe(initialPeriod + 1000);
    
    // Verify: Beneficiary must now iterate through 1000 empty periods to claim
    var originScheme = await ProfitContractStub.GetScheme.CallAsync(tokenHolderProfitScheme.SchemeId);
    originScheme.CurrentPeriod.ShouldBe(initialPeriod + 1000 + 1); // +1 from initial state
    
    // Attempting to claim will require multiple transactions due to period limit
    // With DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100,
    // user needs ~10 transactions to claim through 1000 empty periods
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-35)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
    {
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L134-135)
```csharp
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L141-145)
```csharp
        if (input.AmountsMap != null && input.AmountsMap.Any()) distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

        State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
        scheme.Period = scheme.Period.Add(1);
        State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-494)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);

        Context.LogDebug(() => $"Receiving virtual address: {profitsReceivingVirtualAddress}");

        UpdateDistributedProfits(profitsMap, profitsReceivingVirtualAddress, totalShares);

        PerformDistributeProfits(profitsMap, scheme, totalShares, profitsReceivingVirtualAddress);

        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L822-833)
```csharp
    private int GetMaximumPeriodCountForProfitableDetail(int profitableDetailCount)
    {
        // Get the maximum profit receiving period count
        var maxPeriodCount = GetMaximumProfitReceivingPeriodCount();
        // Check if the maximum period count is greater than the profitable detail count
        // and if the profitable detail count is greater than 0
        return maxPeriodCount > profitableDetailCount && profitableDetailCount > 0
            // Divide the maximum period count by the profitable detail count
            ? maxPeriodCount.Div(profitableDetailCount)
            // If the conditions are not met, return 1 as the maximum period count
            : 1;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-871)
```csharp
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
            {
                var periodToPrint = period;
                var detailToPrint = profitDetail;
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L9-9)
```csharp
    public const int DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100;
```
