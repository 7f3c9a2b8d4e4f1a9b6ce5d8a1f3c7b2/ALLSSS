### Title
Race Condition in TokenHolder RemoveBeneficiary Causing DoS via ClaimProfits Front-Running

### Summary
The `RemoveBeneficiary` function in TokenHolderContract unconditionally calls `.Single()` on the beneficiary's profit details list, which throws an exception when the list is empty. A beneficiary with expired profit details can front-run the manager's RemoveBeneficiary transaction by calling ClaimProfits first, which removes all expired details and leaves an empty list, causing RemoveBeneficiary to revert and blocking the administrative removal action.

### Finding Description

The vulnerability exists in `RemoveBeneficiary` where the function retrieves beneficiary details: [1](#0-0) 

The critical issue is at line 74-78 where `.Details.Single()` is called. This LINQ method throws `InvalidOperationException` with message "Sequence contains no elements" when the Details list is empty.

The race condition occurs because `ClaimProfits` in the Profit contract can remove all profit details: [2](#0-1) 

At lines 787-789, expired details (where `LastProfitPeriod > EndPeriod`) are identified for removal. Lines 801-803 remove these from the available details list, and line 806 updates the state with only remaining details, which can be an empty list.

**Execution Path:**
1. Beneficiary has profit details where all periods have been claimed and `LastProfitPeriod > EndPeriod`
2. Manager submits `RemoveBeneficiary` transaction to mempool
3. Beneficiary monitors mempool and front-runs with `ClaimProfits` transaction
4. `ClaimProfits` removes all expired details, setting Details to empty list
5. `RemoveBeneficiary` calls `GetProfitDetails` which returns empty Details [3](#0-2) 

6. The `.Single()` call fails with "Sequence contains no elements" exception
7. RemoveBeneficiary transaction reverts

**Root Cause:** No defensive check for empty or multiple details before calling `.Single()`. The function assumes exactly one detail always exists, which is violated after ClaimProfits cleanup or when multiple details exist (as shown in test expectations). [4](#0-3) 

The test at line 192 shows that multiple details (`Count.ShouldBe(2)`) can legitimately exist, which would also cause `.Single()` to fail.

### Impact Explanation

**Operational Impact - Denial of Service:**
- The scheme manager cannot remove beneficiaries through the TokenHolder contract
- Administrative functions for scheme management are blocked
- The beneficiary remains in the ProfitDetailsMap state (though with empty details and no effective shares)
- Schemes cannot clean up inactive beneficiaries, potentially accumulating stale entries
- Gas is wasted on failed RemoveBeneficiary transactions

**Affected Parties:**
- Scheme managers who need to remove beneficiaries for legitimate administrative reasons
- TokenHolder schemes that require beneficiary lifecycle management
- The protocol's ability to maintain clean scheme state

**Severity Justification - Medium:**
While this doesn't result in direct fund theft, it creates a reliable DoS vector for an important administrative function. The impact is operational rather than financial, preventing proper scheme management but not causing loss of funds. The beneficiary with empty details has no effective shares anyway, so the protocol's financial integrity remains intact.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to monitor the mempool for pending RemoveBeneficiary transactions
- Ability to submit ClaimProfits transactions with sufficient gas to execute first
- Must be a beneficiary with expired profit details (LastProfitPeriod > EndPeriod)

**Attack Complexity:**
- Low complexity - requires only calling the public `ClaimProfits` function
- No special permissions needed beyond being a registered beneficiary
- Standard front-running technique applicable to any blockchain

**Feasibility Conditions:**
- Precondition naturally occurs: profit details expire in normal operation when all periods are claimed
- Common scenario in long-running schemes where beneficiaries have participated for multiple periods
- ClaimProfits is a legitimate operation that beneficiaries regularly perform

**Economic Rationality:**
- Attack cost is minimal: just gas for one ClaimProfits transaction
- No economic penalty for the attacker
- May be executed defensively when beneficiary suspects removal is imminent

**Detection/Prevention Constraints:**
- Difficult to detect: ClaimProfits is a normal user action
- No transaction ordering guarantees prevent front-running
- Cannot be prevented without changing the contract logic

**Probability Assessment - High:**
The combination of low attack cost, simple execution, naturally occurring preconditions, and legitimate-looking attack transactions makes this vulnerability highly exploitable in practice.

### Recommendation

Replace the unsafe `.Single()` call with defensive code that handles empty or multiple details:

```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
    {
        Beneficiary = input.Beneficiary,
        SchemeId = scheme.SchemeId
    });
    
    // Handle empty details gracefully
    if (profitDetails == null || profitDetails.Details.Count == 0)
    {
        // Already removed or no details exist, consider it successful
        return new Empty();
    }
    
    // Sum all shares if multiple details exist
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

**Invariant Checks to Add:**
- Verify that RemoveBeneficiary succeeds even when Details list is empty
- Verify that RemoveBeneficiary handles multiple details correctly by summing shares

**Test Cases to Prevent Regression:**
1. Test RemoveBeneficiary after ClaimProfits removes all expired details
2. Test RemoveBeneficiary when beneficiary has multiple profit details
3. Test RemoveBeneficiary race condition simulation with concurrent ClaimProfits
4. Test RemoveBeneficiary with input.Amount when multiple details exist

### Proof of Concept

**Required Initial State:**
1. TokenHolder scheme created with SchemeManager address
2. Beneficiary registered with shares via `AddBeneficiary` 
3. Profits distributed and claimed such that beneficiary's details have `LastProfitPeriod > EndPeriod`
4. ProfitDetailsMap contains beneficiary with one or more expired ProfitDetail entries

**Attack Sequence:**

**Step 1 - Setup:** Beneficiary has expired profit details
```
State: ProfitDetailsMap[schemeId][beneficiary].Details[0]:
  - StartPeriod: 1
  - EndPeriod: 10
  - LastProfitPeriod: 11  (> EndPeriod, so marked for removal)
  - Shares: 1000
```

**Step 2 - Manager Action:** Manager submits RemoveBeneficiary transaction
```
Transaction: TokenHolderContract.RemoveBeneficiary(beneficiary, amount=0)
Status: Pending in mempool
```

**Step 3 - Front-Running:** Beneficiary detects pending transaction and submits ClaimProfits with higher gas
```
Transaction: TokenHolderContract.ClaimProfits(schemeManager, beneficiary)
Gas: Higher than RemoveBeneficiary
Status: Executes first
```

**Step 4 - ClaimProfits Execution:** Expired details are removed
```
Result: ProfitDetailsMap[schemeId][beneficiary].Details = [] (empty list)
```

**Step 5 - RemoveBeneficiary Execution:** Transaction fails
```
Line 74-78: GetProfitDetails returns ProfitDetails with empty Details list
Line 78: .Details.Single() throws InvalidOperationException
Error: "Sequence contains no elements"
Transaction Status: Reverted
```

**Expected vs Actual Result:**
- **Expected:** RemoveBeneficiary succeeds, beneficiary removed from scheme
- **Actual:** RemoveBeneficiary reverts with exception, beneficiary entry remains (with empty details)

**Success Condition for Attack:**
The RemoveBeneficiary transaction reverts, preventing the manager from removing the beneficiary, while the attacker successfully claims any remaining profits and causes the details list to be emptied.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-98)
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
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
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

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-806)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;

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

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L187-196)
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
    }
```
