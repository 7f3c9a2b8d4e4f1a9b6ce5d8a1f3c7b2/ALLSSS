# Audit Report

## Title
Unsafe `.Single()` Call in TokenHolder RemoveBeneficiary Causing Denial of Service

## Summary
The `RemoveBeneficiary` function in TokenHolderContract unconditionally calls `.Single()` on the beneficiary's profit details list without checking if the list is empty or contains multiple elements. This causes the function to revert when a beneficiary has either claimed all expired profits (leaving an empty details list) or has multiple profit detail entries, effectively blocking the manager's ability to remove beneficiaries.

## Finding Description

The vulnerability exists in `TokenHolderContract.RemoveBeneficiary` where it retrieves beneficiary profit details and unconditionally calls `.Single()` on the Details collection. [1](#0-0) 

The LINQ `.Single()` method throws an `InvalidOperationException` in two scenarios:
1. When the sequence contains no elements ("Sequence contains no elements")
2. When the sequence contains more than one element ("Sequence contains more than one element")

**Scenario 1: Empty Details List**

The `ClaimProfits` function in ProfitContract identifies expired profit details for removal: [2](#0-1) 

These expired details are then removed from the available details list and the state is updated: [3](#0-2) 

When all details are expired and removed, the `availableDetails` list becomes empty, and the state is updated with an empty Details collection. Subsequently, when `RemoveBeneficiary` calls `GetProfitDetails`: [4](#0-3) 

The returned `ProfitDetails` will have an empty `Details` list, causing `.Single()` to throw an exception.

**Scenario 2: Multiple Details**

The test case demonstrates that multiple profit details can legitimately exist after partial removal operations: [5](#0-4) 

After a partial `RemoveBeneficiary` operation (where `Amount < Shares`), the beneficiary has 2 profit details. If `RemoveBeneficiary` is called again without specifying an amount (meaning complete removal), the `.Single()` call will fail with "Sequence contains more than one element".

**Execution Path:**
1. Beneficiary has profit details where `LastProfitPeriod > EndPeriod` (naturally occurs after claiming all periods)
2. Beneficiary calls `ClaimProfits` (either defensively or as normal operation)
3. All expired details are removed, resulting in empty Details list
4. Manager attempts to call `RemoveBeneficiary`
5. The function calls `.Single()` on the empty Details list
6. Transaction reverts with exception
7. Manager cannot remove the beneficiary

**Root Cause:** The TokenHolder contract was created with `CanRemoveBeneficiaryDirectly = true`: [6](#0-5) 

However, the implementation assumes exactly one profit detail will always exist, which is violated in normal operation when details expire or after partial removals.

## Impact Explanation

**Operational Denial of Service:**
- Scheme managers lose the ability to remove beneficiaries through the TokenHolder contract
- Critical administrative function for scheme lifecycle management is blocked
- Beneficiaries remain in the ProfitDetailsMap state indefinitely (though with no effective shares)
- Schemes cannot clean up inactive participants, leading to state bloat
- Gas is wasted on failed RemoveBeneficiary attempts

**Affected Parties:**
- Scheme managers requiring beneficiary removal for administrative purposes
- TokenHolder schemes needing proper lifecycle management
- The protocol's operational efficiency and state hygiene

**Severity Assessment:**
This represents a **Medium severity** operational DoS. While it doesn't directly compromise funds or enable theft, it permanently blocks a fundamental administrative capability. The beneficiary with empty details has zero effective shares, so no profit distribution is affected, but the inability to maintain clean scheme state is a significant operational failure.

## Likelihood Explanation

**Attack Requirements:**
- Attacker must be a registered beneficiary (legitimate role)
- Must have expired profit details (naturally occurs in normal operation)
- Only needs to call the public `ClaimProfits` function
- No special privileges or complex setup required

**Execution Complexity:**
- **Low complexity**: Single function call to `ClaimProfits`
- Can be executed defensively without monitoring mempool
- ClaimProfits is a legitimate operation beneficiaries perform regularly
- Works even without front-running - simply claiming profits before removal attempt

**Precondition Feasibility:**
- Expired details (`LastProfitPeriod > EndPeriod`) occur naturally when all periods are claimed
- Common in long-running schemes where beneficiaries participate for multiple periods
- The scenario is not exceptional but part of normal operational flow

**Economic Rationality:**
- Cost: Only gas for one ClaimProfits transaction
- Benefit: Prevents removal from scheme (even with zero effective shares)
- No economic penalty for executing ClaimProfits
- May be rational if beneficiary anticipates future scheme participation

**Probability Assessment:**
The combination of low execution complexity, naturally occurring preconditions, and legitimate-looking operations makes this vulnerability **highly likely** to manifest in production, either accidentally or deliberately.

## Recommendation

Replace the unsafe `.Single()` call with defensive code that handles both empty and multiple-element scenarios:

```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
    {
        Beneficiary = input.Beneficiary,
        SchemeId = scheme.SchemeId
    });
    
    // Handle empty details - beneficiary already fully removed
    if (profitDetails?.Details == null || !profitDetails.Details.Any())
    {
        return new Empty();
    }
    
    // For multiple details, sum all shares or remove all
    var lockedAmount = profitDetails.Details.Sum(d => d.Shares);
    
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    
    if (lockedAmount > input.Amount && input.Amount != 0)
    {
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = input.Beneficiary,
                Shares = lockedAmount.Sub(input.Amount)
            }
        });
    }
    
    return new Empty();
}
```

Similarly, fix the `AddBeneficiary` method which also uses `.Single()` unsafely: [7](#0-6) 

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_After_ClaimProfits_DoS_Test()
{
    // Setup: Create scheme and add beneficiary with shares
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
    
    // Distribute profits to create a period
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = Starter,
        AmountsMap = { { "ELF", 0L } }
    });
    
    // User claims all profits, which removes expired details
    var userTokenHolderStub = GetTester<TokenHolderContractImplContainer.TokenHolderContractImplStub>(
        TokenHolderContractAddress, UserKeyPairs.First());
    await userTokenHolderStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeManager = Starter
    });
    
    // Verify details are now empty after claiming
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = Starter });
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(
        new GetProfitDetailsInput
        {
            SchemeId = schemeIds.SchemeIds[0],
            Beneficiary = UserAddresses.First()
        });
    
    // This will show empty details after claiming all periods
    profitDetails.Details.Count.ShouldBe(0);
    
    // Now manager tries to remove beneficiary - this will fail with "Sequence contains no elements"
    var result = await TokenHolderContractStub.RemoveBeneficiary.SendWithExceptionAsync(
        new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = UserAddresses.First()
        });
    
    // Verify the DoS - transaction fails with Single() exception
    result.TransactionResult.Error.ShouldContain("Sequence contains no elements");
}
```

This test demonstrates that after a beneficiary claims all their profits and the expired details are cleaned up, the manager cannot remove the beneficiary due to the unsafe `.Single()` call on an empty Details list.

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-789)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L801-806)
```csharp
        foreach (var profitDetail in profitDetailsToRemove)
        {
            availableDetails.Remove(profitDetail);
        }

        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L46-49)
```csharp
    public override ProfitDetails GetProfitDetails(GetProfitDetailsInput input)
    {
        return State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];
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
