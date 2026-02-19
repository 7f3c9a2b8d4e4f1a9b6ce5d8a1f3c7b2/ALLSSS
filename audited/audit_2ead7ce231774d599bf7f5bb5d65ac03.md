# Audit Report

## Title
Scheme Manager Can DOS Profit Claiming Through Unlimited Empty Period Creation

## Summary
A malicious scheme manager can repeatedly call `DistributeProfits` with an empty `AmountsMap`, causing period counters to increment indefinitely without distributing any actual profits. This forces beneficiaries to iterate through potentially millions of empty periods when claiming their legitimate profits, making the claiming process economically infeasible due to excessive gas costs and transaction requirements, effectively creating a permanent denial-of-service condition.

## Finding Description

The vulnerability exists in the TokenHolder contract's `DistributeProfits` function, which unconditionally increments the period counter regardless of whether any profits were actually distributed. [1](#0-0) 

The critical flaw is on line 144, where `scheme.Period` is incremented unconditionally after calling the Profit contract. The only check is the conditional addition of `AmountsMap` on line 141, which simply doesn't add anything if the input is null or empty - but the period still increments.

The authorization check on lines 134-135 confirms that the scheme manager is explicitly authorized to call this function, making this an abuse of legitimate authority rather than a privilege escalation. [2](#0-1) 

In the underlying Profit contract, the `DistributeProfits` function has a similar issue: [3](#0-2) 

The only protection is the check on line 485: if the period is negative OR totalShares is zero or less, profits are burned instead. However, in the normal case where a scheme has beneficiaries (totalShares > 0), this check passes and the CurrentPeriod is unconditionally incremented on line 494, even when no actual profits were distributed.

When beneficiaries attempt to claim profits, they must iterate through all periods from their `LastProfitPeriod` to the scheme's `CurrentPeriod - 1`: [4](#0-3) 

While empty periods are skipped (lines 868-871), they still consume gas during iteration. The maximum number of periods that can be processed per claim transaction is limited by a constant: [5](#0-4) 

This means approximately 100 periods maximum can be processed per claim (divided by the number of profitable details, which is capped at 10). If a malicious manager creates 1,000,000 empty periods, beneficiaries would need to make approximately 10,000 separate `ClaimProfits` transactions to traverse all empty periods and reach their actual profits.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables a complete economic denial-of-service attack on the profit claiming mechanism:

1. **All scheme beneficiaries are affected**: Every participant who has registered for profits in the scheme becomes a victim
2. **Profits become economically unclaimed**: The gas cost of making 10,000+ transactions would far exceed the value of small profit amounts, making them permanently inaccessible
3. **No recovery mechanism**: There is no way to skip empty periods or reset the period counter - the damage is permanent once periods are created
4. **Minimal attack cost**: The attacker only pays normal transaction fees for calling `DistributeProfits`, while victims must pay orders of magnitude more to claim
5. **Protocol reputation damage**: Users losing access to legitimate profits severely damages trust in the entire economic system

## Likelihood Explanation

**Likelihood: HIGH**

The attack has extremely high feasibility:

1. **Attacker capability**: The scheme manager role is obtained legitimately during scheme creation. Anyone can create a scheme and become its manager. This is not a privilege escalation vulnerability - it's abuse of intended functionality. [6](#0-5) 

2. **Attack complexity**: Trivially low - the attacker simply calls `DistributeProfits` repeatedly with an empty `AmountsMap`. No complex conditions or timing requirements exist.

3. **Preconditions**: The only requirement is that the scheme has at least one beneficiary (totalShares > 0), which is the normal operational state for any active profit scheme.

4. **Detection**: While the attack is visible on-chain (period increments without corresponding profit distribution events), detection doesn't prevent the damage - once empty periods are created, they cannot be removed.

5. **No protections**: There are no rate limits, cooldown periods, or validation checks to prevent empty period creation.

## Recommendation

Add validation to prevent period incrementation when no actual profits are being distributed:

**In TokenHolderContract.cs, line 141-147:**
```csharp
if (input.AmountsMap != null && input.AmountsMap.Any()) 
{
    distributeProfitsInput.AmountsMap.Add(input.AmountsMap);
    State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
    scheme.Period = scheme.Period.Add(1);
    State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
}
else
{
    // Reject empty distributions or only allow if scheme has auto-distribute threshold exceeded
    Assert(false, "Cannot distribute without specifying amounts.");
}
```

**In ProfitContract.cs, add validation before line 432:**
```csharp
if (input.AmountsMap.Any())
    Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");
else if (!scheme.IsReleaseAllBalanceEveryTimeByDefault || !scheme.ReceivedTokenSymbols.Any())
    Assert(false, "Cannot distribute without amounts when scheme is not auto-releasing.");
```

Alternatively, implement a period cleanup mechanism that allows beneficiaries or managers to skip ranges of empty periods during claims.

## Proof of Concept

```csharp
// Test demonstrating the DOS attack
[Fact]
public async Task MaliciousManager_CanCreateEmptyPeriods_DOS()
{
    // Setup: Create scheme with beneficiaries
    var manager = Accounts[0].Address;
    var beneficiary = Accounts[1].Address;
    
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = beneficiary,
        Shares = 100
    });
    
    var initialScheme = await TokenHolderContractStub.GetScheme.CallAsync(manager);
    var initialPeriod = initialScheme.Period;
    
    // Attack: Create 1000 empty periods by calling DistributeProfits with empty AmountsMap
    for (int i = 0; i < 1000; i++)
    {
        await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
        {
            SchemeManager = manager,
            AmountsMap = { } // Empty map
        });
    }
    
    var attackedScheme = await TokenHolderContractStub.GetScheme.CallAsync(manager);
    
    // Verify: Period incremented 1000 times without distributing profits
    attackedScheme.Period.ShouldBe(initialPeriod + 1000);
    
    // Impact: Beneficiary now needs multiple ClaimProfits calls to traverse empty periods
    // With 100 periods max per claim, would need 10 transactions minimum
    // At 1M empty periods, would need 10,000+ transactions
}
```

## Notes

This vulnerability represents a fundamental design flaw where period progression is not tied to actual economic activity. The scheme manager's legitimate authority is weaponized to create empty state that permanently degrades system usability for all participants. The attack is particularly insidious because it appears as normal operation (authorized manager calling a legitimate function), but results in catastrophic denial of service for all beneficiaries.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-22)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-147)
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
    }
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
