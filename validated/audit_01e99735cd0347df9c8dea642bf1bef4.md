# Audit Report

## Title
Missing Input Validation in RemoveBeneficiary Allows Unintended Complete Removal of Beneficiaries

## Summary
The `RemoveBeneficiary` function in the TokenHolder contract lacks input validation to enforce that the removal amount must be strictly less than the beneficiary's current shares when performing partial removal. This allows beneficiaries to be completely removed when `input.Amount >= lockedAmount`, violating the documented API contract.

## Finding Description

The vulnerability exists in the `RemoveBeneficiary` function where the conditional logic only re-adds a beneficiary if `lockedAmount > input.Amount && input.Amount != 0`. [1](#0-0) 

The function retrieves the beneficiary's current shares [2](#0-1) , then completely removes them from the Profit contract [3](#0-2) , and only conditionally re-adds them with reduced shares if the condition holds.

However, the official documentation explicitly states that the amount parameter should be "A positive integer, smaller than the current shares." [4](#0-3) 

**Root Cause:** No validation check exists to assert `input.Amount < lockedAmount` when `input.Amount > 0`.

**Why Protections Fail:**
- The function performs removal first, then conditionally re-adds
- When `lockedAmount == input.Amount`: The condition `100 > 100` evaluates to FALSE, beneficiary is NOT re-added
- When `lockedAmount < input.Amount`: The condition `50 > 100` evaluates to FALSE, beneficiary is NOT re-added
- Both scenarios result in complete removal without error feedback

**Execution Path:**
1. Scheme manager calls `RemoveBeneficiary` with `input.Amount == lockedAmount` (e.g., both 100)
2. Function retrieves current shares: `lockedAmount = 100`
3. Beneficiary completely removed from Profit contract
4. Condition evaluates: `100 > 100 && 100 != 0` = FALSE
5. Beneficiary NOT re-added
6. Function returns successfully, beneficiary completely removed

## Impact Explanation

**Operational Impact:**
- Scheme managers attempting to reduce shares by an amount equal to or greater than current shares will unintentionally remove beneficiaries completely
- The operation succeeds silently without error, providing no feedback about the invalid state
- Beneficiaries lose their position in the profit scheme and all rights to future profit distributions
- Manual intervention required to re-add beneficiaries via `AddBeneficiary`

**Affected Parties:**
- **Beneficiaries**: Unexpectedly lose profit scheme participation when managers make calculation errors
- **Scheme Managers**: No validation feedback when attempting operations that violate API constraints
- **System Integrity**: Documented API contract is violated, undermining trust in specified behavior

**Severity: Medium**
- Does not directly steal funds or cause permanent loss
- Breaks documented API invariant causing operational inconsistency
- Affects profit distribution rights
- Requires manual correction but no funds are permanently lost
- Can occur through honest operational mistakes

## Likelihood Explanation

**Attacker Capabilities:**
- Requires being a scheme manager (authorized role obtained by creating a scheme)
- No sophisticated attack needed - single function call with specific amount
- More likely to occur as operational error than malicious attack
- Common scenarios: typos in amount field, incorrect calculations, off-by-one errors

**Feasibility:**
- **Complexity**: Very low - single function call
- **Preconditions**: Only requires being scheme manager
- **Execution**: Fully executable under normal AElf contract semantics
- The existing test suite validates partial removal (amount < shares) [5](#0-4)  but does not test the edge cases (amount == shares or amount > shares)

**Probability: High**
- Likely to occur through operational errors in production environments
- Frequent beneficiary adjustments increase exposure
- Lack of validation feedback increases probability of repeated errors

## Recommendation

Add input validation to enforce the documented API contract. The fix should assert that when `amount > 0`, it must be strictly less than `lockedAmount`:

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
    
    // ADD THIS VALIDATION
    Assert(input.Amount == 0 || input.Amount < lockedAmount, 
        "Invalid amount: must be 0 for complete removal or strictly less than current shares.");
    
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    if (lockedAmount > input.Amount &&
        input.Amount != 0)
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

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_With_Equal_Amount_Should_Fail()
{
    // Setup: Create scheme and add beneficiary with 1000 shares
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
    
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var schemeId = schemeIds.SchemeIds[0];
    
    // Attempt to remove with amount equal to current shares (should fail but doesn't)
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Amount = 1000  // Equal to current shares
    });
    
    // Verify: Beneficiary is completely removed (vulnerability demonstrated)
    var afterRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    afterRemoveScheme.TotalShares.ShouldBe(0);  // Beneficiary completely removed
    
    // Attempting to get profit details should fail (beneficiary no longer exists)
    var profitDetailsResult = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        Beneficiary = Starter,
        SchemeId = schemeId
    });
    profitDetailsResult.Details.Count.ShouldBe(0);  // No details - beneficiary removed
}
```

## Notes

The vulnerability is confirmed through:
1. **Code Analysis**: The conditional logic at line 85 does not enforce the documented constraint [6](#0-5) 
2. **Documentation Review**: The API contract explicitly requires amount to be "smaller than the current shares" [4](#0-3) 
3. **Proto Documentation**: Additional documentation states "amount > 0: update the weight of the beneficiary, amount = 0: remove the beneficiary" [7](#0-6) 

This is a valid Medium severity issue that breaks the documented API contract and can cause operational problems through unintended complete removal of beneficiaries.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L74-79)
```csharp
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L80-84)
```csharp
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
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

**File:** docs/resources/smart-contract-apis/token-holder.md (L50-50)
```markdown
- **amount**: 0 to remove the beneficiary. A positive integer, smaller than the current shares. 
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L156-196)
```csharp
    public async Task RemoveBeneficiary_With_Amount_Test()
    {
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
        var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
        {
            Manager = Starter
        });
        var schemeId = schemeIds.SchemeIds[0];
        var beforeRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
        var amount = 10;
        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = amount
        });
        var afterRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeIds.SchemeIds[0]);
        afterRemoveScheme.TotalShares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
        var profitAmount = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
        {
            Beneficiary = Starter,
            SchemeId = schemeId
        });
        profitAmount.Details.Count.ShouldBe(2);
        profitAmount.Details[0].Shares.ShouldBe(beforeRemoveScheme.TotalShares);
        profitAmount.Details[0].EndPeriod.ShouldBe(0);
        profitAmount.Details[1].Shares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
    }
```

**File:** protobuf/token_holder_contract.proto (L28-29)
```text
    // Note: amount > 0: update the weight of the beneficiary, amount = 0: remove the beneficiary.
    rpc RemoveBeneficiary (RemoveTokenHolderBeneficiaryInput) returns (google.protobuf.Empty) {
```
