# Audit Report

## Title
Scheme Manager Can Permanently Destroy All Accumulated Profits by Removing Beneficiaries Before Distribution

## Summary
A malicious TokenHolder scheme manager can remove all beneficiaries immediately before calling `DistributeProfits`, reducing the scheme's `TotalShares` to zero. When distribution occurs with zero total shares, the Profit contract automatically burns all accumulated profits instead of distributing them, permanently destroying funds that legitimate beneficiaries were entitled to claim.

## Finding Description

TokenHolder schemes are created with `CanRemoveBeneficiaryDirectly = true` hardcoded into the scheme creation logic, allowing the scheme manager unrestricted removal of beneficiaries at any time. [1](#0-0) 

The `RemoveBeneficiary` function in TokenHolderContract can only be called by the scheme manager (verified through `GetValidScheme(Context.Sender)`), and forwards the removal request to the underlying Profit contract. [2](#0-1) 

In the Profit contract, the `RemoveBeneficiary` function calls `RemoveProfitDetails` and subtracts the removed shares from the scheme's `TotalShares`. [3](#0-2) 

The `RemoveProfitDetails` function removes ALL beneficiary details when `CanRemoveBeneficiaryDirectly` is true, with no restrictions. [4](#0-3) 

**Critical Flaw:** When `DistributeProfits` is called and `totalShares <= 0`, the contract invokes `BurnProfits` instead of distributing to beneficiaries. [5](#0-4) 

The `BurnProfits` function permanently destroys the tokens by calling the Token contract's `Burn` method. [6](#0-5) 

The scheme manager can also call `DistributeProfits` in the TokenHolder contract, giving them complete control over both removal and distribution operations. [7](#0-6) 

**Attack Sequence:**
1. Manager creates a TokenHolder scheme
2. Legitimate beneficiaries register and lock tokens
3. Profits accumulate in the scheme's virtual address
4. Manager calls `RemoveBeneficiary` for each beneficiary, reducing `TotalShares` to 0
5. Manager calls `DistributeProfits`
6. Because `TotalShares = 0`, `BurnProfits` is invoked
7. All accumulated profits are permanently burned
8. Beneficiaries lose their entitled distributions with no recovery mechanism

The test suite confirms this behavior, showing that when `TotalShares = 0`, distributed amounts are negative (indicating burn). [8](#0-7) 

## Impact Explanation

**HIGH Severity** - This vulnerability results in:

1. **Complete Permanent Fund Loss**: All accumulated profits in the scheme are irreversibly destroyed through token burning, with no recovery mechanism.

2. **Supply Deflation**: The total token supply permanently decreases as tokens are burned rather than distributed.

3. **Beneficiary Harm**: Legitimate users who staked tokens and were entitled to profit distributions lose their entire share without recourse.

4. **Protocol Integrity Violation**: The core dividend distribution mechanism can be weaponized to destroy rather than distribute funds, breaking the fundamental trust model of profit-sharing schemes.

The impact is maximized because:
- The attack affects ALL accumulated profits in one action
- No governance or time-delay protections exist
- The scheme manager controls both critical functions
- The burning is permanent and irreversible

## Likelihood Explanation

**MEDIUM-HIGH Likelihood** - The attack is realistic because:

1. **Attacker Profile**: The scheme manager is a user-created role (typically DApp operators), not a trusted protocol role like Parliament or consensus contracts. Any entity can create a scheme and become its manager.

2. **Low Attack Complexity**: Only two function calls are required:
   - `RemoveBeneficiary` for each beneficiary (can be sequential or batched)
   - `DistributeProfits`
   
   Both are directly accessible to the scheme manager with no additional approvals.

3. **No Protective Mechanisms**:
   - No minimum `TotalShares` requirement before distribution
   - No timelock or delay between removal and distribution
   - No governance approval for mass beneficiary removal
   - No economic disincentive or penalty

4. **Realistic Threat Scenarios**:
   - Malicious DApp operator executing an exit scam
   - Compromised manager keys
   - Insider attack to harm competitors or users
   - Disgruntled or departing operators

5. **Detection Difficulty**: The removal transactions appear legitimate and authorized. The attack would only be detected after profits are already burned.

The search for timelock/delay protections confirmed none exist in the TokenHolder contract implementation.

## Recommendation

Implement multiple protective layers:

1. **Add Minimum TotalShares Check**: Prevent distribution when `TotalShares = 0` by reverting instead of burning:
   ```csharp
   if (totalShares <= 0)
   {
       Assert(false, "Cannot distribute with zero total shares");
   }
   ```

2. **Implement Timelock**: Add a configurable delay between beneficiary removal and profit distribution:
   ```csharp
   State.LastBeneficiaryChangeTime[schemeId] = Context.CurrentBlockTime;
   // In DistributeProfits:
   Assert(Context.CurrentBlockTime >= State.LastBeneficiaryChangeTime[schemeId].AddMinutes(MinimumDelayMinutes), 
          "Must wait after beneficiary changes");
   ```

3. **Add Governance for Mass Removal**: Require multi-sig or governance approval when removing beneficiaries exceeding a threshold percentage of total shares.

4. **Remove CanRemoveBeneficiaryDirectly**: Or make it an optional parameter during scheme creation, defaulting to `false` for safety.

5. **Add Emergency Pause**: Implement a circuit breaker that beneficiaries can trigger if they detect suspicious removal activity.

## Proof of Concept

```csharp
[Fact]
public async Task VulnerabilityTest_ManagerCanBurnAllProfitsByRemovingBeneficiaries()
{
    // Setup: Create TokenHolder scheme
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "APP"
    });
    
    // Add beneficiaries and contribute profits
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 10000 // Large profit amount
    });
    
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    
    // Verify profits are in the scheme
    var initialBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = profitScheme.VirtualAddress,
        Symbol = "ELF"
    })).Balance;
    initialBalance.ShouldBe(10000);
    
    // Register multiple beneficiaries
    var user1 = await TokenHolderContractStub.RegisterForProfits.SendAsync(...);
    var user2 = await TokenHolderContractStub.RegisterForProfits.SendAsync(...);
    
    // ATTACK: Manager removes all beneficiaries
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(user1Address);
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(user2Address);
    
    // Verify TotalShares is now 0
    profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    profitScheme.TotalShares.ShouldBe(0);
    
    // ATTACK: Manager distributes profits with zero shares
    var totalSupplyBefore = (await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "ELF" })).Supply;
    
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = Starter
    });
    
    // VERIFY: Profits were burned (supply decreased)
    var totalSupplyAfter = (await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "ELF" })).Supply;
    totalSupplyAfter.ShouldBeLessThan(totalSupplyBefore);
    
    // VERIFY: Beneficiaries received nothing
    var user1Profits = await TokenHolderContractStub.GetProfitsMap.CallAsync(new ClaimProfitsInput
    {
        SchemeManager = Starter,
        Beneficiary = user1Address
    });
    user1Profits.Value["ELF"].ShouldBe(0);
}
```

**Notes:**

This vulnerability is particularly dangerous because:
1. The scheme manager role is user-created (not a trusted protocol role)
2. TokenHolder schemes are widely used for DApp staking and reward distribution
3. The attack leaves no recovery path - burned tokens cannot be restored
4. Users have no way to prevent or detect the attack before execution
5. The same pattern could affect any TokenHolder scheme in production

The core issue is the combination of `CanRemoveBeneficiaryDirectly = true` (hardcoded), manager control over both removal and distribution, and the burn-on-zero-shares logic with no protective timelock or governance oversight.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-24)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-84)
```csharp
    public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);

        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-262)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();

        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");

        var removedDetails = RemoveProfitDetails(scheme, input.Beneficiary, input.ProfitDetailId);

        foreach (var (removedMinPeriod, removedShares) in removedDetails.Where(d => d.Key != 0))
        {
            if (scheme.DelayDistributePeriodCount > 0)
            {
                for (var removedPeriod = removedMinPeriod;
                     removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
                     removedPeriod++)
                {
                    if (scheme.CachedDelayTotalShares.ContainsKey(removedPeriod))
                    {
                        scheme.CachedDelayTotalShares[removedPeriod] =
                            scheme.CachedDelayTotalShares[removedPeriod].Sub(removedShares);
                    }
                }
            }
        }

        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());

        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-486)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L546-551)
```csharp
                State.TokenContract.Burn.Send(new BurnInput
                {
                    Amount = amount,
                    Symbol = symbol
                });
                distributedProfitsInfo.AmountsMap.Add(symbol, -amount);
```

**File:** test/AElf.Contracts.Profit.Tests/BVT/SchemeTests.cs (L205-207)
```csharp
            distributedInformation.TotalShares.ShouldBe(0);
            distributedInformation.AmountsMap[ProfitContractTestConstants.NativeTokenSymbol]
                .ShouldBe(-contributeAmountEachTime);
```
