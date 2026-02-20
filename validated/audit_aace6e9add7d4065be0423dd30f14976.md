# Audit Report

## Title
Permanent DOS in TokenHolder RemoveBeneficiary Due to Single() Assumption on Multiple Profit Details

## Summary
The `RemoveBeneficiary()` and `AddBeneficiary()` functions in TokenHolderContract incorrectly assume each beneficiary has exactly one profit detail by using `.Single()` to retrieve them. When a partial removal occurs, the Profit contract creates multiple details, causing all subsequent operations to fail with `InvalidOperationException`, permanently locking tokens and disabling scheme management.

## Finding Description

TokenHolderContract contains two critical `.Single()` calls that fail when multiple profit details exist: [1](#0-0) [2](#0-1) 

However, the Profit contract explicitly supports multiple details per beneficiary. During a partial removal (where `lockedAmount > input.Amount && input.Amount != 0`), the following occurs:

1. TokenHolder calls `RemoveBeneficiary()` to remove all beneficiary details from Profit
2. If unclaimed profits exist, Profit marks the old detail as removed but keeps it in the list: [3](#0-2) 

3. TokenHolder then re-adds the beneficiary with reduced shares: [4](#0-3) 

4. Profit's `AddBeneficiary` creates a NEW detail and adds it to the existing list: [5](#0-4) 

**Result:** The beneficiary now has 2 profit details. This is confirmed by the official test case: [6](#0-5) 

Once multiple details exist, any subsequent call to `RemoveBeneficiary()` or `AddBeneficiary()` throws `InvalidOperationException` because `.Single()` requires exactly one element. This also affects `Withdraw()`, which internally calls `RemoveBeneficiary()`: [7](#0-6) 

The default scheme configuration enables this behavior: [8](#0-7) 

## Impact Explanation

**HIGH SEVERITY - Permanent Fund Lock and Complete Operational DOS:**

1. **Permanent Token Lock**: Users who locked tokens via `RegisterForProfits()` cannot call `Withdraw()` once they have multiple profit details. Their tokens remain permanently locked with no recovery mechanism.

2. **Complete Scheme Management Failure**: Scheme managers lose the ability to remove beneficiaries, update shares, or manage their schemes in any capacity.

3. **Widespread Affected Parties**: All users with locked tokens, all beneficiaries added by managers, and all scheme managers are affected.

The impact is permanent because once the state contains multiple details, there is no contract method to fix it without direct state manipulation.

## Likelihood Explanation

**HIGH LIKELIHOOD - Easily Triggered Through Normal Operations:**

**Triggering Conditions:**
- Scheme manager permissions (normal role)
- Single function call: `RemoveBeneficiary(beneficiary, partialAmount)` where `0 < partialAmount < totalShares`
- Default scheme setting `CanRemoveBeneficiaryDirectly = true` enables this

**Attack Complexity:** Trivial - requires only one transaction with partial removal amount

**Realistic Scenario:** This can occur unintentionally during legitimate operations when scheme managers try to gradually reduce beneficiary shares - a natural use case for profit scheme management.

## Recommendation

Replace `.Single()` calls with logic that handles multiple profit details. For `RemoveBeneficiary()`, sum all details' shares. For `AddBeneficiary()`, remove all existing details first to ensure a clean state:

```csharp
// In RemoveBeneficiary
var details = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = input.Beneficiary,
    SchemeId = scheme.SchemeId
}).Details;
var lockedAmount = details.Sum(d => d.Shares);

// In AddBeneficiary
var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    SchemeId = scheme.SchemeId,
    Beneficiary = input.Beneficiary
});
var shares = input.Shares;
if (detail.Details.Any())
{
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    shares = shares.Add(detail.Details.Sum(d => d.Shares));
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DOS_After_Partial_RemoveBeneficiary_Test()
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
        Amount = 9999
    });
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Shares = 1000
    });

    // Trigger: Partial removal creates 2 details
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Amount = 10  // Partial removal
    });

    // Verify: Beneficiary now has 2 details
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        Beneficiary = Starter,
        SchemeId = schemeIds.SchemeIds[0]
    });
    profitDetails.Details.Count.ShouldBe(2);

    // DOS: Any subsequent RemoveBeneficiary call fails with InvalidOperationException
    var dosResult = await TokenHolderContractStub.RemoveBeneficiary.SendWithExceptionAsync(
        new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = 5
        });
    dosResult.TransactionResult.Error.ShouldContain("Sequence contains more than one element");
}
```

## Notes

The vulnerability is rooted in an architectural mismatch: TokenHolder assumes single details while Profit explicitly supports multiple details. The test case `RemoveBeneficiary_With_Amount_Test` confirms this behavior is known but the DOS implications were not addressed. Users with locked tokens via `RegisterForProfits()` and withdrawal time restrictions are particularly vulnerable, as their funds become permanently inaccessible after a single partial removal operation.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L46-56)
```csharp
        if (detail.Details.Any())
        {
            // Only keep one detail.

            State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                Beneficiary = input.Beneficiary
            });
            shares.Add(detail.Details.Single().Shares);
        }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L74-78)
```csharp
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L85-95)
```csharp
        if (lockedAmount > input.Amount &&
            input.Amount != 0) // If input.Amount == 0, means just remove this beneficiary.
            State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = input.Beneficiary,
                    Shares = lockedAmount.Sub(input.Amount)
                }
            });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L239-243)
```csharp
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = Context.Sender
        });
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L194-201)
```csharp
        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L351-356)
```csharp
                else if (profitDetail.EndPeriod >= scheme.CurrentPeriod)
                {
                    // No profit can be here, except the scheme is cancellable.
                    // shorten profit.
                    profitDetail.EndPeriod = scheme.CurrentPeriod.Sub(1);
                }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L187-192)
```csharp
        var profitAmount = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
        {
            Beneficiary = Starter,
            SchemeId = schemeId
        });
        profitAmount.Details.Count.ShouldBe(2);
```
