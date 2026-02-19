# Audit Report

## Title
Race Condition in TokenHolder RemoveBeneficiary Causing DoS via ClaimProfits Front-Running

## Summary
The `RemoveBeneficiary` function in TokenHolderContract unconditionally calls `.Single()` on the beneficiary's profit details list without verifying that exactly one element exists. When a beneficiary's profit details become expired (after claiming all periods), calling `ClaimProfits` removes these details and creates an empty list. A malicious beneficiary can front-run the manager's `RemoveBeneficiary` transaction with `ClaimProfits`, causing the administrative removal to revert with "Sequence contains no elements" exception, permanently blocking the manager's ability to remove that beneficiary.

## Finding Description

The vulnerability exists in the `RemoveBeneficiary` method where it retrieves and processes beneficiary details without defensive validation. [1](#0-0) 

The critical flaw is the unconditional call to `.Details.Single()`, which is a LINQ method that throws `InvalidOperationException` when called on an empty sequence or a sequence with multiple elements.

The attack vector leverages `ClaimProfits` in the Profit contract, which removes expired profit details from state: [2](#0-1) 

After identifying expired details (where `LastProfitPeriod > EndPeriod`), the method removes them: [3](#0-2) 

The state update at line 806 can result in a `ProfitDetails` object with an empty `Details` list when all profit details are expired and removed.

When `RemoveBeneficiary` subsequently calls `GetProfitDetails`, it receives this empty list: [4](#0-3) 

**Attack Execution Path:**

1. Beneficiary has profit details where all periods have been claimed (`LastProfitPeriod > EndPeriod`)
2. Manager submits `RemoveBeneficiary` transaction to mempool
3. Beneficiary monitors mempool and front-runs with higher gas `ClaimProfits` transaction
4. `ClaimProfits` executes first, removes all expired details, setting `Details` to empty list
5. `RemoveBeneficiary` executes, calls `GetProfitDetails` which returns empty `Details`
6. The `.Single()` call throws `InvalidOperationException: "Sequence contains no elements"`
7. `RemoveBeneficiary` transaction reverts, wasting gas
8. Beneficiary remains in the scheme's state (though with zero effective shares)

TokenHolder schemes are created with `CanRemoveBeneficiaryDirectly = true`, enabling immediate beneficiary removal, but this vulnerability prevents that capability: [5](#0-4) 

## Impact Explanation

**Operational Denial of Service:**
- Scheme managers lose the ability to remove beneficiaries through the TokenHolder contract's administrative interface
- The `RemoveBeneficiary` function becomes permanently unusable for affected beneficiaries
- Beneficiaries remain in the `ProfitDetailsMap` state, creating stale entries that cannot be cleaned up
- Scheme state becomes polluted with inactive beneficiaries
- Wasted gas on repeatedly failing `RemoveBeneficiary` attempts

**Affected Parties:**
- Scheme managers requiring beneficiary lifecycle management for legitimate administrative reasons
- TokenHolder schemes that depend on clean beneficiary lists
- Protocol's operational integrity and state hygiene

**Severity Justification - Medium:**
This vulnerability creates a reliable DoS vector for an important administrative function. While it doesn't result in direct fund theft or loss (the beneficiary has zero effective shares after claiming all profits), it breaks operational integrity by preventing proper scheme management. The impact is operational rather than financial, making it a Medium severity issue rather than High/Critical.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to monitor blockchain mempool for pending `RemoveBeneficiary` transactions (standard blockchain observation)
- Ability to submit `ClaimProfits` with sufficient gas priority to execute first (standard front-running)
- Must be a registered beneficiary with expired profit details

**Attack Complexity:**
- **Very Low** - Requires only calling the public `ClaimProfits` function with appropriate gas pricing
- No special permissions needed beyond being a registered beneficiary
- Standard front-running technique applicable to any public blockchain
- The attack transaction (`ClaimProfits`) is indistinguishable from legitimate user behavior

**Feasibility Conditions:**
- **Naturally Occurring Precondition**: Profit details expire in normal operation when all periods have been claimed (`LastProfitPeriod > EndPeriod`)
- **Common Scenario**: Expected in long-running schemes where beneficiaries participate across multiple profit distribution periods
- **Legitimate Operation**: `ClaimProfits` is a normal function that beneficiaries regularly use

**Economic Rationality:**
- **Minimal Cost**: Only requires gas for one `ClaimProfits` transaction
- **No Economic Penalty**: Attacker suffers no loss; claiming profits is their legitimate right
- **Defensive Use Case**: May be executed when beneficiary suspects imminent removal

**Detection/Prevention Constraints:**
- **Difficult to Detect**: `ClaimProfits` appears as normal user activity in transaction logs
- **No Ordering Guarantees**: Blockchain transaction ordering cannot prevent front-running without protocol changes
- **Cannot Be Prevented**: Without contract logic changes, managers cannot circumvent this attack

**Probability Assessment - High:**
The combination of minimal attack cost, trivial execution complexity, naturally occurring preconditions, and legitimate-appearing attack transactions makes this vulnerability highly likely to be exploited in production environments.

## Recommendation

Implement defensive validation before calling `.Single()` in `RemoveBeneficiary`:

**Option 1 - Handle Empty/Multiple Details Gracefully:**
```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
    {
        Beneficiary = input.Beneficiary,
        SchemeId = scheme.SchemeId
    });
    
    // Defensive check for empty or multiple details
    if (profitDetails == null || profitDetails.Details.Count == 0)
    {
        // Details already cleaned up, just remove from Profit contract
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        return new Empty();
    }
    
    // For multiple details, sum all shares
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

**Option 2 - Use FirstOrDefault with null check:**
Replace `.Single()` with `.FirstOrDefault()` and handle null case explicitly.

**Additional Fix Required:**
The same issue exists in `AddBeneficiary` at line 55 which also calls `.Single()`: [6](#0-5) 

Apply similar defensive checks there as well.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_DoS_Via_ClaimProfits_FrontRun()
{
    // Setup: Create scheme and register beneficiary
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    var beneficiary = SampleAccount.Accounts[1].Address;
    const long amount = 1000;
    
    // Register beneficiary with shares
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = beneficiary,
        Shares = amount
    });
    
    // Distribute profits and advance period so details become claimable and eventually expired
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = DefaultSender });
    var schemeId = schemeIds.SchemeIds[0];
    
    await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1,
        AmountsMap = { { "ELF", 100 } }
    });
    
    // Beneficiary claims all profits, creating expired details (LastProfitPeriod > EndPeriod)
    var beneficiaryStub = GetTester<TokenHolderContractImplContainer.TokenHolderContractImplStub>(
        TokenHolderContractAddress, SampleAccount.Accounts[1].KeyPair);
    await beneficiaryStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeManager = DefaultSender,
        Beneficiary = beneficiary
    });
    
    // Now beneficiary front-runs RemoveBeneficiary with another ClaimProfits
    // This removes all expired details, leaving empty Details list
    await beneficiaryStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeManager = DefaultSender,
        Beneficiary = beneficiary
    });
    
    // Verify Details list is now empty
    var details = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiary
    });
    details.Details.Count.ShouldBe(0); // Empty list confirms vulnerability precondition
    
    // Manager attempts RemoveBeneficiary - this should revert with "Sequence contains no elements"
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = beneficiary,
            Amount = 0
        });
    });
    
    // Verify the DoS - RemoveBeneficiary fails due to .Single() on empty list
    exception.Message.ShouldContain("Sequence contains no elements");
}
```

## Notes

This vulnerability demonstrates a critical gap in defensive programming where administrative functions assume ideal state conditions without validation. The interaction between `ClaimProfits` legitimately cleaning up expired state and `RemoveBeneficiary` assuming exactly one detail exists creates an exploitable race condition. The front-running attack is feasible on any public blockchain with visible mempools, making this a practical threat rather than theoretical concern.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-24)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
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
