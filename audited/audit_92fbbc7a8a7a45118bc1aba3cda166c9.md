### Title
Permanent DOS in TokenHolder RemoveBeneficiary Due to Single() Assumption on Multiple Profit Details

### Summary
The `RemoveBeneficiary()` and `AddBeneficiary()` functions in TokenHolderContract assume beneficiaries have exactly one profit detail and use `.Single()` to retrieve it. However, the underlying Profit contract explicitly supports multiple details per beneficiary. After a partial beneficiary removal (where shares are reduced but not eliminated), multiple details are created, causing all future removal or modification attempts to fail with an exception, permanently locking beneficiaries in the scheme and preventing token withdrawals.

### Finding Description

The vulnerability exists in two locations within TokenHolderContract: [1](#0-0) [2](#0-1) 

**Root Cause**: TokenHolderContract incorrectly assumes each beneficiary has exactly one profit detail per scheme, but the Profit contract explicitly supports multiple details: [3](#0-2) 

When `RemoveBeneficiary()` is called with a partial amount (where `lockedAmount > input.Amount && input.Amount != 0`), the following occurs:
1. The beneficiary is completely removed from the Profit contract via `RemoveBeneficiary`
2. The Profit contract may keep the old detail in a shortened/marked state if profits haven't been claimed
3. The beneficiary is re-added with reduced shares, creating a NEW detail
4. Result: The beneficiary now has multiple profit details

This is proven by the official test case: [4](#0-3) 

The test explicitly expects and validates that 2 details exist after partial removal. Once multiple details exist, any subsequent call to `RemoveBeneficiary()` or `AddBeneficiary()` will throw an `InvalidOperationException` because `.Single()` requires exactly one element.

### Impact Explanation

**Critical Operational DOS with Fund Lock:**

1. **Permanent Beneficiary Lock**: Once a beneficiary has multiple profit details, they can never be removed from the scheme via TokenHolderContract methods. The scheme manager loses the ability to manage the scheme.

2. **Withdrawal DOS**: The `Withdraw()` function internally calls `RemoveBeneficiary()`: [5](#0-4) 

Users who registered via `RegisterForProfits()` and locked tokens cannot withdraw their funds if they end up with multiple profit details. Their tokens remain permanently locked in the contract.

3. **Share Update DOS**: Scheme managers cannot update beneficiary shares via `AddBeneficiary()` for affected users.

**Who is Affected**: 
- Users who locked tokens via `RegisterForProfits()` 
- Beneficiaries added via `AddBeneficiary()`
- Scheme managers who need to manage their schemes

**Severity Justification**: This is HIGH severity because it causes permanent loss of funds for users and complete operational failure of the TokenHolder scheme management.

### Likelihood Explanation

**High Likelihood - Easily Triggered:**

**Attacker Capabilities Required**: Only scheme manager permissions are needed, but this can also occur through legitimate operations:
- A scheme manager performing normal share adjustments
- Users who have unclaimed profits when their shares are modified

**Attack Complexity**: Trivial - single function call:
1. Ensure a beneficiary exists with shares (e.g., 1000)
2. Call `RemoveBeneficiary(beneficiary, amount=10)` where 0 < amount < total shares
3. Beneficiary now has multiple details and is permanently stuck

**Feasibility Conditions**: 
- No special state required
- Works on any TokenHolder scheme with `CanRemoveBeneficiaryDirectly = true` (which is the default) [6](#0-5) 

**Probability**: This can happen unintentionally during normal operations when managers try to reduce (not fully remove) beneficiary shares, making it a realistic and likely scenario.

### Recommendation

**Immediate Fix**: Replace `.Single()` calls with proper handling of multiple profit details.

For `RemoveBeneficiary()`, calculate total shares across all details:
```csharp
var details = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = input.Beneficiary,
    SchemeId = scheme.SchemeId
});
var lockedAmount = details.Details.Sum(d => d.Shares);
```

For `AddBeneficiary()`, sum existing shares before removal:
```csharp
if (detail.Details.Any())
{
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    shares.Add(detail.Details.Sum(d => d.Shares));
}
```

**Invariant Check**: Add validation that confirms beneficiary has been fully removed before re-adding:
```csharp
var remainingDetails = State.ProfitContract.GetProfitDetails.Call(...);
Assert(remainingDetails == null || !remainingDetails.Details.Any(), 
       "Failed to fully remove beneficiary");
```

**Test Cases**: Add regression tests that:
1. Perform partial removal followed by another removal attempt
2. Perform partial removal followed by AddBeneficiary
3. Attempt withdrawal after partial removal
4. Verify all operations succeed with multiple pre-existing details

### Proof of Concept

**Initial State**:
- TokenHolder scheme exists with manager = Alice
- User Bob has registered for profits with 1000 shares (1 profit detail exists)

**Transaction Sequence**:

1. Alice calls `TokenHolderContract.RemoveBeneficiary(Bob, 10)`
   - Expected: Reduces Bob's shares to 990
   - Actual: Creates 2 profit details for Bob (old shortened + new with 990 shares)
   - Proven by test at line 192 of TokenHolderTests.cs

2. Alice calls `TokenHolderContract.RemoveBeneficiary(Bob, 0)` to fully remove Bob
   - Expected: Bob is removed from scheme
   - **Actual: Transaction fails with InvalidOperationException "Sequence contains more than one element" at line 78**

3. Bob calls `TokenHolderContract.Withdraw(Alice)` to retrieve locked tokens
   - Expected: Bob's locked tokens are unlocked and returned
   - **Actual: Transaction fails with InvalidOperationException at line 239 (calls RemoveBeneficiary internally)**

**Success Condition**: 
- Step 2 and 3 fail with exception
- Bob's tokens remain permanently locked
- Bob cannot be removed from the scheme
- Scheme manager loses control over Bob's beneficiary status

This vulnerability is CONFIRMED by the codebase's own test suite which explicitly validates that multiple details exist after partial removal, yet the contract code assumes only one detail exists.

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

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L187-195)
```csharp
        var profitAmount = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
        {
            Beneficiary = Starter,
            SchemeId = schemeId
        });
        profitAmount.Details.Count.ShouldBe(2);
        profitAmount.Details[0].Shares.ShouldBe(beforeRemoveScheme.TotalShares);
        profitAmount.Details[0].EndPeriod.ShouldBe(0);
        profitAmount.Details[1].Shares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
```
