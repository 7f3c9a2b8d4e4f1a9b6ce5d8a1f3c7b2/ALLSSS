### Title
Missing Input Validation in RemoveBeneficiary Allows Unintended Complete Removal of Beneficiaries

### Summary
The `RemoveBeneficiary` function lacks input validation to ensure the removal amount is strictly less than the beneficiary's current shares when performing partial removal. This allows beneficiaries to be completely removed from the profit scheme when `lockedAmount == input.Amount` or `lockedAmount < input.Amount`, violating the documented API contract and potentially causing unintended loss of beneficiary status.

### Finding Description

The vulnerability exists in the `RemoveBeneficiary` function where the conditional check on line 85 only re-adds a beneficiary if `lockedAmount > input.Amount && input.Amount != 0`. [1](#0-0) 

The function first removes the beneficiary completely from the Profit contract (lines 80-84), then conditionally re-adds them with reduced shares only if the above condition holds. However, the official documentation explicitly states that the amount parameter should be "A positive integer, smaller than the current shares." [2](#0-1) 

**Root Cause:** Missing input validation check that would assert `input.Amount < lockedAmount` when `input.Amount > 0`.

**Why Protections Fail:**
- No validation exists to enforce the documented constraint
- The function blindly removes the beneficiary first, then only re-adds if shares remain
- Two invalid scenarios pass through unchecked:
  1. `lockedAmount == input.Amount`: Removes beneficiary entirely instead of rejecting the operation
  2. `lockedAmount < input.Amount`: Also removes beneficiary entirely, allowing removal of more shares than exist

**Execution Path:**
1. Scheme manager calls `RemoveBeneficiary` with `input.Amount == lockedAmount` (e.g., both are 100)
2. Function retrieves beneficiary's current shares (line 79) [3](#0-2) 
3. Beneficiary is completely removed from Profit contract (lines 80-84) [4](#0-3) 
4. Condition `lockedAmount > input.Amount` evaluates to `100 > 100` = FALSE
5. Beneficiary is NOT re-added, resulting in complete removal
6. Function returns successfully without error

### Impact Explanation

**Operational Impact - Loss of Beneficiary Status:**
- Scheme managers who intend to reduce a beneficiary's shares to exactly zero (expecting an error or explicit removal) will inadvertently remove the beneficiary completely
- When `input.Amount > lockedAmount`, the operation succeeds silently instead of failing, providing no feedback about the invalid operation
- Beneficiaries lose their position in the profit scheme and all associated rights to future profit distributions

**Affected Parties:**
- **Beneficiaries:** Lose profit scheme participation unexpectedly when managers make errors in amount calculation
- **Scheme Managers:** No validation feedback when attempting invalid operations, leading to operational errors
- **System Integrity:** API contract violation undermines trust in documented behavior

**Severity Justification (Medium):**
- Does not directly steal funds but affects profit distribution rights
- Breaks documented API invariant, causing operational inconsistency
- Requires scheme manager action (not arbitrary attacker) but can happen through honest mistakes
- No permanent fund loss, but beneficiaries must be manually re-added with `AddBeneficiary`

### Likelihood Explanation

**Attacker Capabilities:**
- Requires being a scheme manager (authorized role)
- No sophisticated attack required - simply calling the function with equal or greater amount
- Can occur accidentally during normal operations (e.g., typo in amount, calculation error)

**Attack Complexity:**
- Very low - single function call
- No special preconditions beyond being scheme manager
- No timing or race condition requirements

**Feasibility Conditions:**
- Highly feasible - any scheme manager can trigger this
- More likely to occur as operational error than malicious attack
- Can happen repeatedly if managers don't realize the validation gap

**Execution Practicality:**
- Fully executable under normal AElf contract semantics
- Test case demonstrates this behavior is possible (lines 156-196 show partial removal works, but doesn't test the equal case) [5](#0-4) 

**Probability:** High - likely to occur through operational errors in production environments where managers perform frequent beneficiary adjustments.

### Recommendation

**Code-level Mitigation:**
Add input validation immediately after retrieving the locked amount (after line 79):

```csharp
Assert(input.Amount == 0 || input.Amount < lockedAmount, 
    "Amount must be 0 to remove beneficiary completely, or a positive value smaller than current shares.");
```

This ensures:
1. `input.Amount = 0`: Explicit removal (current behavior maintained)
2. `input.Amount > 0 && input.Amount < lockedAmount`: Valid partial removal
3. `input.Amount >= lockedAmount`: Rejected with clear error message

**Additional Safeguards:**
1. Update the inline comment on line 86 to reflect the validation requirement
2. Add explicit test cases for the edge cases:
   - Test case where `input.Amount == lockedAmount` (should fail)
   - Test case where `input.Amount > lockedAmount` (should fail)
   - Test case confirming error messages are clear

**Invariant to Enforce:**
```
When input.Amount > 0: input.Amount < current_beneficiary_shares
When input.Amount == 0: complete removal is intended
```

### Proof of Concept

**Initial State:**
- Scheme created with manager = Alice
- Beneficiary Bob added with 1000 shares
- Profit scheme active and operational

**Exploitation Steps:**

**Scenario 1: Equal Amount (lockedAmount == input.Amount)**
1. Alice (scheme manager) calls `RemoveBeneficiary`:
   - `input.Beneficiary = Bob`
   - `input.Amount = 1000` (exactly equal to Bob's current shares)

2. Expected Result (per documentation): Transaction should fail with error "Amount must be smaller than current shares"

3. Actual Result: Transaction succeeds, Bob is completely removed from the scheme with 0 shares remaining

4. Verification: Query `GetProfitDetails` for Bob returns empty or 0 shares

**Scenario 2: Excessive Amount (lockedAmount < input.Amount)**
1. Alice calls `RemoveBeneficiary`:
   - `input.Beneficiary = Bob` (has 1000 shares)
   - `input.Amount = 1500` (more than Bob's current shares)

2. Expected Result: Transaction should fail with error "Amount exceeds current shares"

3. Actual Result: Transaction succeeds, Bob is completely removed (same as Scenario 1)

4. Verification: No error thrown, beneficiary silently removed despite invalid amount

**Success Condition:** 
In both scenarios, the transaction completes successfully without validation errors, violating the documented constraint that amount must be "smaller than the current shares" for partial removal operations. The beneficiary is removed entirely when the documentation indicates this should only happen with `amount = 0`.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L85-86)
```csharp
        if (lockedAmount > input.Amount &&
            input.Amount != 0) // If input.Amount == 0, means just remove this beneficiary.
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
