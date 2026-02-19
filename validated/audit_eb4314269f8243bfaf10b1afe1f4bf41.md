# Audit Report

## Title
Beneficiaries with EndPeriod=long.MaxValue Cannot Be Removed from Schemes with CanRemoveBeneficiaryDirectly=false

## Summary
The Profit contract contains a critical logic flaw where beneficiaries added with default `EndPeriod` (automatically set to `long.MaxValue`) cannot be effectively removed from schemes that have `CanRemoveBeneficiaryDirectly = false` (the default setting). When a manager calls `RemoveBeneficiary` without providing a `profitDetailId`, the removal silently fails, allowing the "removed" beneficiary to continue claiming profits indefinitely and permanently diluting legitimate beneficiaries' shares.

## Finding Description

The vulnerability originates from the interaction between the `AddBeneficiary` default behavior and the `RemoveProfitDetails` filter logic.

When a beneficiary is added without specifying `EndPeriod`, it defaults to `long.MaxValue`: [1](#0-0) 

When a scheme is created without explicitly setting `CanRemoveBeneficiaryDirectly`, it defaults to `false` as per proto3 boolean default semantics: [2](#0-1) 

The critical flaw exists in the `RemoveProfitDetails` helper method, which filters which details can be removed: [3](#0-2) 

When `CanRemoveBeneficiaryDirectly = false`, only details where `d.EndPeriod < scheme.CurrentPeriod` are eligible for removal. Since `long.MaxValue` is always greater than or equal to any `CurrentPeriod`, beneficiaries with `EndPeriod = long.MaxValue` are NEVER included in `detailsCanBeRemoved`.

This causes cascading failures in the removal process:
- The `IsWeightRemoved` flag is NOT set (line 345 never executes for these details)
- Shares are NOT added to `removedDetails` (line 358 never executes)
- The beneficiary's profit details remain unchanged in `ProfitDetailsMap`

Consequently, when `RemoveBeneficiary` completes, the `TotalShares` reduction is based on the empty `removedDetails`: [4](#0-3) 

Since `removedDetails.Values.Sum()` returns 0, nothing is subtracted from `TotalShares`, and the beneficiary remains fully active in the scheme.

The "removed" beneficiary can continue claiming profits because the claim logic only checks if `EndPeriod >= LastProfitPeriod`: [5](#0-4) 

With `EndPeriod = long.MaxValue`, this condition is always satisfied.

A workaround exists where managers can provide a `profitDetailId` to bypass the filter: [6](#0-5) 

However, this workaround is non-obvious, undocumented, and requires knowledge of internal profit detail IDs.

## Impact Explanation

This vulnerability has **CRITICAL** impact on profit distribution integrity:

1. **Unauthorized Continuous Profit Drainage:** After the manager's attempted removal, the beneficiary continues claiming their proportional share of all future profit distributions indefinitely. For example, if a beneficiary has 100 shares out of 1000 total, they will continue receiving 10% of all future distributions forever.

2. **Permanent Share Dilution:** The "removed" beneficiary's shares remain in the scheme's `TotalShares`, permanently diluting the profit share of all legitimate beneficiaries. This directly reduces the amount received by intended beneficiaries.

3. **Manager Authorization Bypass:** The scheme manager's explicit intent to remove a beneficiary is silently ignored by the contract, violating the core authorization model where only managers control beneficiary membership.

4. **Undetected Exploitation:** Since `RemoveBeneficiary` returns successfully without throwing an error, managers have no indication that the removal failed. This makes the issue extremely difficult to detect without manually querying contract state.

**Who is affected:** All schemes created with default settings (`CanRemoveBeneficiaryDirectly = false`) where beneficiaries are added without explicitly specifying `EndPeriod`. This includes potential third-party dApp profit schemes and any future system contract upgrades using the Profit contract.

## Likelihood Explanation

The likelihood of this vulnerability being triggered is **MEDIUM-HIGH**:

**Reachable Entry Point:** The vulnerability is triggered through normal manager operations:
1. Creating a scheme with default settings (common)
2. Adding beneficiaries without specifying `EndPeriod` (common pattern)
3. Later attempting to remove the beneficiary (legitimate management action)

**Feasible Preconditions:**
- Default scheme configuration (`CanRemoveBeneficiaryDirectly = false`) - this is the proto3 default
- Common beneficiary addition pattern where `EndPeriod` is not specified

**Execution Practicality:** The vulnerability requires no malicious action - it's triggered by normal management operations:
1. Manager creates scheme with default settings
2. Manager adds beneficiary without `EndPeriod` (defaults to `long.MaxValue`)
3. Manager later calls `RemoveBeneficiary` without `profitDetailId`
4. Removal silently fails, beneficiary continues claiming profits

**Detection Constraints:** The vulnerability is silent - `RemoveBeneficiary` completes successfully without error, making it undetectable without querying `ProfitDetailsMap` and `TotalShares` after removal.

**Real-World Risk:** While current system contracts (Treasury, Election) avoid this by explicitly specifying `EndPeriod` values, the contract itself doesn't enforce this protection. Third-party dApps using the Profit contract with default settings would be vulnerable.

## Recommendation

**Immediate Fix Options:**

1. **Option 1 - Allow Removal of long.MaxValue Details:**
   Modify the filter logic in `RemoveProfitDetails` to allow removal of details with `EndPeriod = long.MaxValue` when `CanRemoveBeneficiaryDirectly = false`:
   ```csharp
   var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
       ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
       : profitDetails.Details
           .Where(d => (d.EndPeriod < scheme.CurrentPeriod || d.EndPeriod == long.MaxValue) 
                       && !d.IsWeightRemoved).ToList();
   ```

2. **Option 2 - Add Error When Removal Fails:**
   Throw an explicit error when `removedDetails` is empty but profit details exist for the beneficiary:
   ```csharp
   if (removedDetails.Values.Sum() == 0 && profitDetails != null && profitDetails.Details.Any())
   {
       throw new AssertionException("Cannot remove beneficiary. Provide profitDetailId or set scheme's CanRemoveBeneficiaryDirectly to true.");
   }
   ```

3. **Option 3 - Change Default Behavior:**
   Set `CanRemoveBeneficiaryDirectly = true` as the default when creating schemes, or require explicit specification of this field.

**Recommended Approach:** Implement Option 1 AND Option 2 together for both safety and usability. This allows legitimate removal while providing clear error messages when something goes wrong.

## Proof of Concept

```csharp
[Fact]
public async Task ProfitContract_RemoveBeneficiary_LongMaxValue_SilentFailure_Test()
{
    const int shares = 100;
    const int amount = 1000;

    var creator = Creators[0];
    var beneficiary = Normal[0];
    var receiverAddress = Address.FromPublicKey(NormalKeyPair[0].PublicKey);

    // Create scheme with default settings (CanRemoveBeneficiaryDirectly = false by default)
    var schemeId = await creator.CreateScheme.SendAsync(new CreateSchemeInput()).Result.Output;

    // Add beneficiary WITHOUT specifying EndPeriod (defaults to long.MaxValue)
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = receiverAddress, Shares = shares },
        SchemeId = schemeId
        // EndPeriod NOT specified - defaults to long.MaxValue
    });

    // Distribute profits
    await creator.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId,
        Amount = amount,
        Symbol = ProfitContractTestConstants.NativeTokenSymbol
    });

    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        AmountsMap = { { ProfitContractTestConstants.NativeTokenSymbol, amount } },
        Period = 1
    });

    // Verify beneficiary exists before removal
    var schemeBeforeRemoval = await creator.GetScheme.CallAsync(schemeId);
    schemeBeforeRemoval.TotalShares.ShouldBe(shares);

    // Manager attempts to remove beneficiary (WITHOUT profitDetailId)
    await creator.RemoveBeneficiary.SendAsync(new RemoveBeneficiaryInput
    {
        Beneficiary = receiverAddress,
        SchemeId = schemeId
        // No profitDetailId provided
    });

    // VULNERABILITY: TotalShares should be 0, but remains at original value
    var schemeAfterRemoval = await creator.GetScheme.CallAsync(schemeId);
    schemeAfterRemoval.TotalShares.ShouldBe(shares); // Still has shares!

    // VULNERABILITY: Beneficiary can still claim profits
    var balanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = receiverAddress,
        Symbol = ProfitContractTestConstants.NativeTokenSymbol
    })).Balance;

    await beneficiary.ClaimProfits.SendAsync(new ClaimProfitsInput { SchemeId = schemeId });

    var balanceAfter = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = receiverAddress,
        Symbol = ProfitContractTestConstants.NativeTokenSymbol
    })).Balance;

    // VULNERABILITY: "Removed" beneficiary successfully claimed profits
    (balanceAfter - balanceBefore).ShouldBe(amount); // Received full distribution!
}
```

## Notes

- The vulnerability is in production code and affects the core Profit contract functionality
- The issue is triggered by default configuration without any malicious intent
- Current system contracts (Treasury, Election) avoid this by always explicitly specifying `EndPeriod` values, but third-party integrators are at risk
- The workaround (providing `profitDetailId`) is undocumented and non-obvious
- This violates the principle of least surprise - managers expect `RemoveBeneficiary` to actually remove beneficiaries
- The silent failure makes this particularly dangerous as it provides no indication that the removal failed

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L161-163)
```csharp
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L260-260)
```csharp
        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L333-338)
```csharp
        // remove the profitDetail with the profitDetailId, and de-duplicate it before involving.
        if (profitDetailId != null && profitDetails.Details.Any(d => d.Id == profitDetailId) &&
            detailsCanBeRemoved.All(d => d.Id != profitDetailId))
        {
            detailsCanBeRemoved.Add(profitDetails.Details.Single(d => d.Id == profitDetailId));
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-766)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
```

**File:** protobuf/profit_contract.proto (L130-130)
```text
    bool can_remove_beneficiary_directly = 5;
```
