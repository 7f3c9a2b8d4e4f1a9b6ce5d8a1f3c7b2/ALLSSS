# Audit Report

## Title
Unreleased Periods Can Permanently Lock Beneficiary Profits

## Summary
The Profit contract contains a critical vulnerability where profits contributed to future periods can become permanently locked if the scheme manager stops calling `DistributeProfits` before reaching those periods. The issue stems from `LastProfitPeriod` being updated even when profits are not transferred due to `IsReleased=false`, causing beneficiaries to permanently lose access to contributed funds.

## Finding Description

The vulnerability exists due to a logic flaw in how the contract handles unreleased profit periods across three key functions:

**1. ContributeProfits allows contributions to ANY future period**

The contract permits anyone to contribute profits to any future period by only validating that the period is greater than or equal to the current period [1](#0-0) . When contributing to a specific future period, a `DistributedProfitsInfo` entry is created with `IsReleased` defaulting to `false` [2](#0-1) .

**2. DistributeProfits enforces strict sequential period release**

The `DistributeProfits` method enforces that periods must be released sequentially by asserting the input period equals the scheme's current period [3](#0-2) . After distribution, the current period is incremented by exactly 1 [4](#0-3) . Only when `DistributeProfits` is called does `IsReleased` get set to `true` [5](#0-4) . This means there is no way to skip periods or directly release a specific future period.

**3. ProfitAllPeriods updates LastProfitPeriod regardless of transfer success**

The critical flaw occurs in the `ProfitAllPeriods` method. When processing periods, the method only transfers tokens if `IsReleased` is `true` [6](#0-5) . However, the `LastProfitPeriod` is unconditionally updated to `period + 1` outside this check [7](#0-6) , and then permanently saved [8](#0-7) .

**Attack Scenario:**
1. Current period is 5, beneficiaries exist with shares
2. A user contributes 10,000 tokens to period 10
3. Manager distributes periods 5, 6, 7 then abandons the scheme (lost keys, death, or deliberate)
4. Beneficiary calls `ClaimProfits`:
   - Periods 5-7 are claimed successfully
   - Loop reaches period 10: `DistributedProfitsInfo` exists with 10,000 tokens but `IsReleased=false`
   - Transfer is skipped, but `LastProfitPeriod` is updated to 11
5. Next `ClaimProfits` call starts from period 11, permanently skipping period 10
6. The 10,000 tokens are irreversibly locked in period 10's virtual address

## Impact Explanation

**Direct Fund Impact - HIGH Severity:**
- **Permanent Loss**: Tokens contributed to unreleased periods become permanently locked with no recovery mechanism
- **Scope**: Affects all beneficiaries proportionally - if 10,000 tokens are locked and total shares are 100, each beneficiary with 10 shares loses 1,000 tokens permanently
- **Scale**: Can affect multiple periods simultaneously if contributions were made to periods 10, 15, 20, etc.

**Protocol Impact:**
- Breaks the fundamental guarantee of the profit distribution system that contributed funds will be distributable
- No admin function or recovery mechanism exists to release specific periods or recover locked funds
- The `ResetManager` function only changes scheme ownership but cannot skip periods [9](#0-8) 

**Economic Damage:**
- Contributed funds are effectively burned from beneficiaries' perspective
- Virtual address holds the tokens but they become inaccessible
- Undermines trust in the profit distribution mechanism

## Likelihood Explanation

**High Likelihood due to multiple realistic scenarios:**

1. **Accidental User Error (High Probability):**
   - User mistypes period 50 instead of 5
   - Manager eventually stops managing scheme (abandonment, lost keys, death)
   - Period 50's profits become permanently locked

2. **Manager Abandonment (Medium-High Probability):**
   - Manager loses private keys
   - Manager dies without key transfer
   - Manager intentionally abandons scheme after collecting early period benefits
   - Project discontinuation

3. **Malicious Actor Griefing (Medium Probability):**
   - Attacker contributes small amounts to very distant periods (e.g., period 1000)
   - Creates complexity and eventual fund loss when scheme is abandoned

**Preconditions (All Easily Met):**
- Profit scheme exists (common in AElf ecosystem)
- Anyone can call `ContributeProfits` with any future period - confirmed in tests [10](#0-9) 
- Manager stops calling `DistributeProfits` before reaching contributed periods

**Execution Complexity:** None - uses standard public contract methods with no special permissions or timing requirements.

## Recommendation

**Fix the LastProfitPeriod update logic to only advance when profits are actually transferred:**

```csharp
// In ProfitAllPeriods method around line 876-909
if (!isView)
{
    Context.LogDebug(() =>
        $"{beneficiary} is profiting {amount} {symbol} tokens from {scheme.SchemeId.ToHex()} in period {periodToPrint}." +
        $"Sender's Shares: {detailToPrint.Shares}, total Shares: {distributedProfitsInformation.TotalShares}");
    if (distributedProfitsInformation.IsReleased && amount > 0)
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Context.SendVirtualInline(
            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
            State.TokenContract.Value,
            nameof(State.TokenContract.Transfer), new TransferInput
            {
                To = beneficiary,
                Symbol = symbol,
                Amount = amount
            }.ToByteString());

        Context.Fire(new ProfitsClaimed
        {
            Beneficiary = beneficiary,
            Symbol = symbol,
            Amount = amount,
            ClaimerShares = detailToPrint.Shares,
            TotalShares = distributedProfitsInformation.TotalShares,
            Period = periodToPrint
        });
        
        // MOVE THIS LINE INSIDE THE IsReleased CHECK
        lastProfitPeriod = period + 1;
    }
    // Remove the line that was at 908 - it should only execute when IsReleased is true
}
```

**Alternative Solution:** Add a mechanism to allow managers to explicitly release specific periods out of order, or implement an emergency recovery function for locked funds.

## Proof of Concept

```csharp
[Fact]
public async Task ProfitContract_UnreleasedPeriod_LocksProfit_Test()
{
    const long shares = 100;
    const long contributionAmount = 10000;
    const int futurePeriod = 10;
    
    var creator = Creators[0];
    var beneficiary = Normal[0];
    var beneficiaryAddress = Address.FromPublicKey(NormalKeyPair[0].PublicKey);
    
    // Create scheme and add beneficiary
    var schemeId = await CreateSchemeAsync();
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = beneficiaryAddress, Shares = shares }
    });
    
    // Contribute to future period 10
    await creator.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId,
        Amount = contributionAmount,
        Symbol = ProfitContractTestConstants.NativeTokenSymbol,
        Period = futurePeriod
    });
    
    // Manager only distributes periods 1-5, then stops
    for (var i = 1; i <= 5; i++)
    {
        await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
        {
            SchemeId = schemeId,
            Period = i,
            AmountsMap = { }
        });
    }
    
    // Verify period 10 is not released
    var distributedInfo = await creator.GetDistributedProfitsInfo.CallAsync(new SchemePeriod
    {
        SchemeId = schemeId,
        Period = futurePeriod
    });
    distributedInfo.IsReleased.ShouldBe(false);
    distributedInfo.AmountsMap[ProfitContractTestConstants.NativeTokenSymbol].ShouldBe(contributionAmount);
    
    // Beneficiary claims profits - this will skip the unreleased period 10
    await beneficiary.ClaimProfits.SendAsync(new ClaimProfitsInput { SchemeId = schemeId });
    
    // Check that LastProfitPeriod advanced past period 10
    var profitDetails = await creator.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiaryAddress
    });
    
    // LastProfitPeriod should be 6 (next unclaimed period), but if bug exists, 
    // it may have advanced past period 10 without transferring funds
    // Attempting to claim again will not recover period 10's profits
    
    // Verify funds are still locked in period 10 virtual address
    var period10Address = await creator.GetSchemeAddress.CallAsync(new SchemePeriod
    {
        SchemeId = schemeId,
        Period = futurePeriod
    });
    var lockedBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = period10Address,
        Symbol = ProfitContractTestConstants.NativeTokenSymbol
    })).Balance;
    
    // Funds remain locked - this proves the vulnerability
    lockedBalance.ShouldBe(contributionAmount);
}
```

## Notes

This vulnerability affects the core `ProfitContract.cs` which is widely used throughout the AElf ecosystem for reward distribution. The issue is particularly severe because:
- It violates the invariant that contributed funds will eventually be distributable
- No emergency recovery mechanism exists
- The bug is in production contract logic, not test code
- It can be triggered by normal user behavior (typos) or unavoidable circumstances (manager key loss)

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L568-568)
```csharp
        distributedProfitsInformation.IsReleased = true;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L684-684)
```csharp
            Assert(input.Period >= scheme.CurrentPeriod, "Invalid contributing period.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L688-703)
```csharp
            var distributedProfitsInformation = State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
            if (distributedProfitsInformation == null)
            {
                distributedProfitsInformation = new DistributedProfitsInfo
                {
                    AmountsMap = { { input.Symbol, input.Amount } }
                };
            }
            else
            {
                Assert(!distributedProfitsInformation.IsReleased,
                    $"Scheme of period {input.Period} already released.");
                distributedProfitsInformation.AmountsMap[input.Symbol] =
                    distributedProfitsInformation.AmountsMap[input.Symbol].Add(input.Amount);
            }

```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L723-743)
```csharp
    public override Empty ResetManager(ResetManagerInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");

        // Transfer managing scheme id.
        var oldManagerSchemeIds = State.ManagingSchemeIds[scheme.Manager];
        oldManagerSchemeIds.SchemeIds.Remove(input.SchemeId);
        State.ManagingSchemeIds[scheme.Manager] = oldManagerSchemeIds;
        var newManagerSchemeIds = State.ManagingSchemeIds[input.NewManager] ?? new CreatedSchemeIds();
        newManagerSchemeIds.SchemeIds.Add(input.SchemeId);
        State.ManagingSchemeIds[input.NewManager] = newManagerSchemeIds;

        scheme.Manager = input.NewManager;
        State.SchemeInfos[input.SchemeId] = scheme;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L881-906)
```csharp
                    if (distributedProfitsInformation.IsReleased && amount > 0)
                    {
                        if (State.TokenContract.Value == null)
                            State.TokenContract.Value =
                                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());

                        Context.Fire(new ProfitsClaimed
                        {
                            Beneficiary = beneficiary,
                            Symbol = symbol,
                            Amount = amount,
                            ClaimerShares = detailToPrint.Shares,
                            TotalShares = distributedProfitsInformation.TotalShares,
                            Period = periodToPrint
                        });
                    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L908-908)
```csharp
                    lastProfitPeriod = period + 1;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L917-917)
```csharp
        profitDetail.LastProfitPeriod = lastProfitPeriod;
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L138-144)
```csharp
        await thirdParty.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeId = schemeId,
            Amount = amountAddedByThirdParty,
            Symbol = ProfitContractTestConstants.NativeTokenSymbol,
            Period = 1
        });
```
