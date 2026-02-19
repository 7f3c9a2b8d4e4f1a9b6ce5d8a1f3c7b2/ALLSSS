# Audit Report

## Title
Race Condition in TokenHolder RemoveBeneficiary Causing DoS via ClaimProfits Front-Running

## Summary
The `RemoveBeneficiary` function in TokenHolderContract unconditionally calls `.Single()` on the beneficiary's profit details list without checking if the list is empty or contains multiple elements. A beneficiary can front-run the manager's RemoveBeneficiary transaction by calling ClaimProfits, which removes expired profit details and may leave an empty list, causing RemoveBeneficiary to revert with an `InvalidOperationException` and permanently blocking the administrative removal action.

## Finding Description

The vulnerability exists in the TokenHolderContract's `RemoveBeneficiary` function where it retrieves and processes beneficiary details [1](#0-0) . The critical flaw is the unconditional use of the LINQ `.Single()` method, which throws an `InvalidOperationException` when the Details collection is empty ("Sequence contains no elements") or contains more than one element ("Sequence contains more than one element").

The race condition occurs because the ProfitContract's `ClaimProfits` function actively removes expired profit details from state. When ClaimProfits identifies expired details (where `LastProfitPeriod > EndPeriod`) [2](#0-1) , it removes them from the available details list [3](#0-2)  and updates the state with the remaining details, which can be an empty list [4](#0-3) .

**Attack Execution Path:**
1. A beneficiary exists with profit details where all periods have been claimed (`LastProfitPeriod > EndPeriod`)
2. Scheme manager submits `RemoveBeneficiary` transaction to the mempool
3. Beneficiary monitors the mempool and front-runs with a `ClaimProfits` transaction with higher gas
4. `ClaimProfits` executes first, removing all expired details and setting the Details list to empty
5. `RemoveBeneficiary` then executes and calls `GetProfitDetails` [5](#0-4)  which returns the empty Details list
6. The `.Single()` call throws `InvalidOperationException: Sequence contains no elements`
7. The RemoveBeneficiary transaction reverts

Notably, the same codebase shows awareness of this pattern - the `AddBeneficiary` function properly checks `if (detail.Details.Any())` before calling `.Single()` [6](#0-5) , but this defensive check is missing in `RemoveBeneficiary`.

Additionally, test evidence confirms that multiple details can legitimately exist in the system [7](#0-6) , which would also cause `.Single()` to throw an exception.

## Impact Explanation

**Operational Denial of Service:**
- The scheme manager loses the ability to remove beneficiaries through the TokenHolder contract's administrative functions
- Schemes cannot perform proper beneficiary lifecycle management or clean up inactive entries
- The beneficiary remains in the `ProfitDetailsMap` state (though with empty details and no effective voting shares)
- Multiple failed transaction attempts waste gas for legitimate administrative operations
- Accumulation of stale beneficiary entries degrades scheme state hygiene

**Affected Parties:**
- Scheme managers requiring legitimate beneficiary removal for administrative reasons
- TokenHolder schemes that depend on proper beneficiary lifecycle management
- Protocol governance needing clean scheme state maintenance

**Severity Assessment - Medium:**
This vulnerability creates a reliable DoS vector for an important administrative function. While it does not result in direct fund theft or loss (the beneficiary with empty details has no effective shares), it prevents proper scheme management and administrative control. The impact is operational rather than financial - the protocol's financial integrity remains intact, but administrative functionality is compromised.

## Likelihood Explanation

**Attack Feasibility:**
- **Attacker Capabilities:** Requires only mempool monitoring (standard for any blockchain) and ability to submit transactions with higher gas priority
- **Required Privileges:** Must be a registered beneficiary with expired profit details (`LastProfitPeriod > EndPeriod`)
- **Attack Complexity:** Low - requires only calling the public `ClaimProfits` function, a standard front-running technique

**Precondition Naturalness:**
- Profit details naturally expire in normal protocol operation when all periods are claimed
- Common scenario in long-running schemes where beneficiaries have participated across multiple periods
- `ClaimProfits` is a legitimate operation that beneficiaries regularly perform, making the attack indistinguishable from normal behavior

**Economic Rationality:**
- Attack cost is minimal: only the gas cost for one `ClaimProfits` transaction
- No economic penalty or downside for the attacker
- May be executed defensively when a beneficiary anticipates or detects an imminent removal attempt

**Detection and Prevention:**
- Difficult to detect: `ClaimProfits` is legitimate user behavior
- No transaction ordering guarantees exist to prevent front-running
- Cannot be mitigated without modifying the contract logic

**Probability Assessment - High:**
The combination of low attack cost, simple execution via public methods, naturally occurring preconditions, and the legitimate appearance of attack transactions makes this vulnerability highly exploitable in production environments.

## Recommendation

Add defensive checks before calling `.Single()` in the `RemoveBeneficiary` function. The fix should handle both empty Details lists and multiple Details entries:

```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
    {
        Beneficiary = input.Beneficiary,
        SchemeId = scheme.SchemeId
    });
    
    // Add defensive check for empty or multiple details
    if (profitDetails == null || !profitDetails.Details.Any())
    {
        // Beneficiary already has no details, removal is effectively complete
        return new Empty();
    }
    
    var detail = profitDetails.Details.First(); // Use First() instead of Single()
    var lockedAmount = detail.Shares;
    
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    
    if (lockedAmount > input.Amount && input.Amount != 0)
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = input.Beneficiary,
                Shares = lockedAmount.Sub(input.Amount)
            }
        });

    return new Empty();
}
```

This approach mirrors the pattern already used in `AddBeneficiary` and gracefully handles edge cases.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_RaceCondition_ClaimProfitsCanCauseDoS()
{
    // Setup: Create scheme and add beneficiary
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    var beneficiary = UserAddresses[0];
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = beneficiary,
        Shares = 100
    });
    
    // Distribute profits and advance to make details expired
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = Starter,
        AmountsMap = { { "ELF", 1000L } }
    });
    
    // Beneficiary claims all profits, causing LastProfitPeriod > EndPeriod
    var beneficiaryStub = GetTokenHolderContractStub(beneficiary);
    await beneficiaryStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeManager = Starter,
        Beneficiary = beneficiary
    });
    
    // Verify details list is now empty after ClaimProfits cleanup
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = (await TokenHolderContractStub.GetScheme.CallAsync(Starter)).SchemeId,
        Beneficiary = beneficiary
    });
    Assert.Empty(profitDetails.Details); // Details list is empty
    
    // Manager attempts to remove beneficiary - this will throw InvalidOperationException
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = beneficiary,
            Amount = 0
        });
    });
    
    // Verify the exception is due to .Single() on empty sequence
    Assert.Contains("Sequence contains no elements", exception.Message);
}
```

This test demonstrates that after `ClaimProfits` removes expired details, the `RemoveBeneficiary` function fails with an exception, confirming the DoS vulnerability.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L46-55)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L801-803)
```csharp
        foreach (var profitDetail in profitDetailsToRemove)
        {
            availableDetails.Remove(profitDetail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L806-806)
```csharp
        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L46-49)
```csharp
    public override ProfitDetails GetProfitDetails(GetProfitDetailsInput input)
    {
        return State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];
    }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L192-192)
```csharp
        profitAmount.Details.Count.ShouldBe(2);
```
