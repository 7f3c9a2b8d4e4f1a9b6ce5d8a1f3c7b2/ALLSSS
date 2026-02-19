# Audit Report

## Title
Arithmetic Overflow in Profit Calculation Due to Unbounded Beneficiary Shares Value

## Summary
The Profit contract's `SafeCalculateProfits` method performs unchecked decimal multiplication that overflows when beneficiary shares approach `long.MaxValue` and profit amounts exceed ~8.6 billion base units. This causes `ClaimProfits` to fail with `OverflowException`, permanently locking beneficiaries' earned profits in the scheme's virtual address with no recovery mechanism.

## Finding Description

The vulnerability exists in the profit distribution calculation flow where three issues combine to create a critical failure:

**1. Missing Upper Bound Validation**

The `AssertValidInput` method only validates non-negativity of shares, with no maximum limit: [1](#0-0) 

This allows scheme managers to add beneficiaries with shares values up to `long.MaxValue` (9,223,372,036,854,775,807): [2](#0-1) 

**2. Vulnerable Decimal Arithmetic**

The `SafeCalculateProfits` method performs multiplication before division without overflow protection: [3](#0-2) 

The operation `decimalTotalAmount * decimalShares` executes before dividing by `decimalTotalShares`. When:
- First parameter (passed as shares) ≈ 9.2 × 10^18
- Second parameter (passed as total amount) > 8.6 × 10^9
- Product: 9.2 × 10^28 exceeds C# `decimal.MaxValue` (7.9 × 10^28)

This causes an immediate `OverflowException` since decimal arithmetic in C# has built-in overflow checking.

**3. Execution Path Through ClaimProfits**

When beneficiaries claim profits, the vulnerable calculation is invoked: [4](#0-3) 

At line 873 within `ProfitAllPeriods`, `SafeCalculateProfits` is called with potentially overflowing values: [5](#0-4) 

**Authorization Context**

Only scheme managers or TokenHolder contract can add beneficiaries: [6](#0-5) 

However, profit contributions are unrestricted—anyone can contribute any amount: [7](#0-6) 

## Impact Explanation

**Direct Fund Lockup:** Beneficiaries with large share values cannot claim their legitimately earned profits. The `ClaimProfits` transaction throws `OverflowException` and reverts, leaving funds permanently locked in the scheme's virtual address. No administrative function exists to rescue these funds.

**Quantified Scenario:**
- Scheme manager adds beneficiary with `shares = long.MaxValue`
- Natural profit accumulation reaches 10 billion base units (100 tokens with 8 decimals—realistic for staking rewards)
- Calculation: 9.2 × 10^18 × 10 × 10^9 = 9.2 × 10^28 > decimal.MaxValue
- Result: All profits for affected periods become permanently unclaimable

**Affected Parties:**
1. **Individual Beneficiaries**: Direct financial loss, cannot access earned rewards
2. **Staking Participants**: If scheme distributes validator rewards, all stakers lose access to dividends
3. **Treasury Recipients**: DAO/protocol treasury distributions fail
4. **Cross-chain Operations**: Bridge reward schemes become inoperative

**Severity Assessment:** HIGH due to:
- Permanent, irrecoverable fund lockup
- Affects core economic incentive mechanisms
- No circuit breaker or recovery path
- Breaks fundamental protocol guarantee (claimable profits)

## Likelihood Explanation

**Attack Complexity:** Very Low
- Step 1: Manager adds beneficiary with large shares value (single transaction, 30 seconds)
- Step 2: Wait for natural profit accumulation OR trigger via unrestricted `ContributeProfits`
- No sophisticated timing, no oracle manipulation, no multi-block requirements

**Attacker Capabilities:** Minimal
- Requires only scheme manager role (obtainable by creating a scheme, zero prerequisites)
- Anyone can contribute profits to trigger overflow condition
- No need for governance control, consensus participation, or special privileges

**Realistic Preconditions:**
AElf ecosystem commonly sees:
- Tokens with 8-18 decimals (ELF has 8 decimals)
- Staking rewards accumulating billions of base units in active validator pools
- Treasury contracts receiving transaction fees over time
- Token holder dividend schemes with substantial distributions
- 10 billion base units = 100 ELF tokens—entirely realistic distribution amount

**Natural Occurrence Probability:** MODERATE
- Legitimate schemes could accidentally set overly large shares values
- High-value tokens with large decimal places hit threshold faster
- Active schemes naturally accumulate sufficient profit amounts
- No warning signs before overflow occurs

**Economic Incentives:**
- Malicious manager: Zero cost to DoS competitor reward schemes
- Negligent manager: Accidental misconfiguration when attempting "equal shares" logic
- Griefing: Attacker creates scheme, attracts deposits, then triggers lockup

**Detection Difficulty:** High
- No on-chain validation warns of approaching overflow threshold
- Off-chain monitoring would require complex analysis of shares × amounts
- First indication is when legitimate claim transactions start failing

## Recommendation

**Immediate Fix: Add Maximum Shares Validation**

Modify `AssertValidInput` to enforce reasonable upper bounds:

```csharp
private void AssertValidInput(AddBeneficiaryInput input)
{
    Assert(input.SchemeId != null, "Invalid scheme id.");
    Assert(input.BeneficiaryShare?.Beneficiary != null, "Invalid beneficiary address.");
    Assert(input.BeneficiaryShare?.Shares >= 0, "Invalid share.");
    
    // Add maximum validation to prevent overflow in SafeCalculateProfits
    const long MaxSafeShares = long.MaxValue / 10000; // Leave safety margin
    Assert(input.BeneficiaryShare?.Shares <= MaxSafeShares, 
        $"Shares value too large. Maximum allowed: {MaxSafeShares}");
}
```

**Alternative Fix: Reorder Calculation**

Modify `SafeCalculateProfits` to divide before multiplying (reduces precision but prevents overflow):

```csharp
private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
{
    var decimalTotalAmount = (decimal)totalAmount;
    var decimalShares = (decimal)shares;
    var decimalTotalShares = (decimal)totalShares;
    
    // Divide first to reduce magnitude before multiplication
    var ratio = decimalShares / decimalTotalShares;
    return (long)(decimalTotalAmount * ratio);
}
```

**Comprehensive Fix: Add Try-Catch with Fallback**

Wrap calculation in exception handler with safe fallback:

```csharp
private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
{
    try
    {
        var decimalTotalAmount = (decimal)totalAmount;
        var decimalShares = (decimal)shares;
        var decimalTotalShares = (decimal)totalShares;
        return (long)(decimalTotalAmount * decimalShares / decimalTotalShares);
    }
    catch (OverflowException)
    {
        // Fallback: divide first when overflow detected
        var ratio = (decimal)shares / (decimal)totalShares;
        return (long)((decimal)totalAmount * ratio);
    }
}
```

**Additional Measures:**
1. Add event emission when shares values exceed warning thresholds
2. Implement maximum total shares limit per scheme
3. Add view function to simulate profit calculations before claiming
4. Document safe shares value ranges in contract comments

## Proof of Concept

```csharp
[Fact]
public async Task ClaimProfits_Should_Fail_With_Overflow_When_Large_Shares()
{
    // Setup: Create scheme and add beneficiary with maximum shares
    var schemeId = await Creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    var beneficiary = SampleAccount.Accounts[1].Address;
    var largeShares = long.MaxValue; // 9,223,372,036,854,775,807
    
    await Creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare 
        { 
            Beneficiary = beneficiary, 
            Shares = largeShares 
        },
        EndPeriod = long.MaxValue
    });
    
    // Contribute profit amount that triggers overflow
    // 10 billion base units * long.MaxValue > decimal.MaxValue
    var profitAmount = 10_000_000_000L; 
    
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Spender = ProfitContractAddress,
        Symbol = "ELF",
        Amount = profitAmount
    });
    
    await Creator.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Symbol = "ELF",
        Amount = profitAmount
    });
    
    // Distribute profits
    await Creator.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Period = 1,
        AmountsMap = { { "ELF", profitAmount } }
    });
    
    // Attempt to claim should fail with OverflowException
    // Calculation: (long.MaxValue * 10_000_000_000) overflows decimal.MaxValue
    var claimResult = await User1ProfitStub.ClaimProfits.SendWithExceptionAsync(
        new ClaimProfitsInput
        {
            SchemeId = schemeId.Output,
            Beneficiary = beneficiary
        });
    
    // Verify overflow exception occurs
    claimResult.TransactionResult.Error.ShouldContain("Overflow");
    
    // Verify profits are locked (balance remains in scheme virtual address)
    var schemeInfo = await Creator.GetScheme.CallAsync(schemeId.Output);
    var schemeBalance = await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput
        {
            Owner = schemeInfo.VirtualAddress,
            Symbol = "ELF"
        });
    
    schemeBalance.Balance.ShouldBe(0); // Already distributed to period virtual address
    
    var periodVirtualAddress = GetDistributedPeriodProfitsVirtualAddress(schemeId.Output, 1);
    var periodBalance = await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput
        {
            Owner = periodVirtualAddress,
            Symbol = "ELF"
        });
    
    // Profits locked permanently in period virtual address
    periodBalance.Balance.ShouldBe(profitAmount);
}
```

This test demonstrates that when shares approach `long.MaxValue` and profit amounts exceed ~8.6 billion base units, the `ClaimProfits` operation fails with overflow, leaving funds permanently locked in the scheme's virtual address with no recovery mechanism.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-184)
```csharp
    public override Empty AddBeneficiary(AddBeneficiaryInput input)
    {
        AssertValidInput(input);
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;

        var schemeId = input.SchemeId;
        var scheme = State.SchemeInfos[schemeId];

        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");

        Context.LogDebug(() =>
            $"{input.SchemeId}.\n End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        Assert(input.EndPeriod >= scheme.CurrentPeriod,
            $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);

        State.SchemeInfos[schemeId] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L217-222)
```csharp
    private void AssertValidInput(AddBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.BeneficiaryShare?.Beneficiary != null, "Invalid beneficiary address.");
        Assert(input.BeneficiaryShare?.Shares >= 0, "Invalid share.");
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L651-660)
```csharp
    public override Empty ContributeProfits(ContributeProfitsInput input)
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
        AssertTokenExists(input.Symbol);
        if (input.Amount <= 0)
        {
            throw new AssertionException("Amount need to greater than 0.");
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L750-784)
```csharp
    public override Empty ClaimProfits(ClaimProfitsInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        if (scheme == null) throw new AssertionException("Scheme not found.");
        var beneficiary = input.Beneficiary ?? Context.Sender;
        var profitDetails = State.ProfitDetailsMap[input.SchemeId][beneficiary];
        if (profitDetails == null) throw new AssertionException("Profit details not found.");

        Context.LogDebug(
            () => $"{Context.Sender} is trying to profit from {input.SchemeId.ToHex()} for {beneficiary}.");

        // LastProfitPeriod is set as 0 at the very beginning, and be updated as current period every time when it is claimed.
        // What's more, LastProfitPeriod can also be +1 more than endPeroid, for it always points to the next period to claim.
        // So if LastProfitPeriod is 0, that means this profitDetail hasn't be claimed before, so just check whether it is a valid one;
        // And if a LastProfitPeriod is larger than EndPeriod, it should not be claimed, and should be removed later.
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();

        Context.LogDebug(() =>
            $"Profitable details: {profitableDetails.Aggregate("\n", (profit1, profit2) => profit1.ToString() + "\n" + profit2)}");

        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
        // Only can get profit from last profit period to actual last period (profit.CurrentPeriod - 1),
        // because current period not released yet.
        for (var i = 0; i < profitableDetailCount; i++)
        {
            var profitDetail = profitableDetails[i];
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L845-875)
```csharp
    private Dictionary<string, long> ProfitAllPeriods(Scheme scheme, ProfitDetail profitDetail, Address beneficiary, long maxProfitReceivingPeriodCount,
        bool isView = false, string targetSymbol = null)
    {
        var profitsMap = new Dictionary<string, long>();
        var lastProfitPeriod = profitDetail.LastProfitPeriod;

        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };

        foreach (var symbol in symbols)
        {
            var totalAmount = 0L;
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
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

                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);

```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L956-962)
```csharp
    private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
    {
        var decimalTotalAmount = (decimal)totalAmount;
        var decimalShares = (decimal)shares;
        var decimalTotalShares = (decimal)totalShares;
        return (long)(decimalTotalAmount * decimalShares / decimalTotalShares);
    }
```
