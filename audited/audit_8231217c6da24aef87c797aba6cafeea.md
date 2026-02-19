### Title
Missing Empty Address Validation in AddBeneficiary Allows Permanent Profit Loss

### Summary
The `AddBeneficiary` method in the Profit contract fails to validate that beneficiary addresses have non-empty Value fields, only checking for null references. This allows scheme managers or the TokenHolder contract to add beneficiaries with empty addresses (`new Address()`), causing allocated profits to be permanently locked in an inaccessible address when distributed and claimed.

### Finding Description

The vulnerability exists in the `AssertValidInput` validation method used by `AddBeneficiary`: [1](#0-0) 

The validation only checks if the beneficiary Address object is not null (`!= null`), but does not verify that the Address has a non-empty Value field. In AElf's protobuf-based Address type, it is possible to create an Address instance with an empty ByteString Value using `new Address()`.

This contrasts with proper validation patterns used elsewhere in the codebase:

**Correct validation in ResetManager:** [2](#0-1) 

**Correct validation in MultiToken contract:** [3](#0-2) 

**Execution Path:**
1. Scheme manager or TokenHolder contract calls `AddBeneficiary` with an Address containing empty Value [4](#0-3) 

2. Validation passes because the Address object reference is not null [5](#0-4) 

3. Empty address is stored in ProfitDetailsMap with allocated shares [6](#0-5) 

4. When `DistributeProfits` is called, profits are allocated proportionally including to the empty address [7](#0-6) 

5. When `ClaimProfits` is called for the empty address, tokens are transferred via the MultiToken contract [8](#0-7) 

6. The MultiToken `Transfer` method does not validate the recipient address, allowing the transfer to succeed [9](#0-8) 

7. The `DoTransfer` internal method modifies balances without recipient address validation [10](#0-9) 

8. Tokens become permanently locked in `State.Balances[emptyAddress][symbol]` as no one possesses the private key for an empty address.

### Impact Explanation

**Direct Fund Impact:** Tokens allocated to empty address beneficiaries are permanently lost. The empty address has no corresponding private key, making the tokens irrecoverable.

**Quantified Damage:** 
- Loss proportional to shares allocated to the empty address relative to total scheme shares
- Example: If empty address receives 100 shares out of 1000 total shares, 10% of all distributed profits are permanently lost

**Affected Parties:**
- All legitimate beneficiaries suffer reduced profit shares due to dilution by the empty address allocation
- The scheme itself loses assets that could have been redistributed

**Severity Justification:** HIGH
- Irreversible loss of funds with no recovery mechanism
- Violates the critical invariant of profit distribution accuracy in the Economics & Treasury component
- Can affect multiple distribution periods until detected and beneficiary is removed

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be the scheme manager (creator/owner of the profit scheme), OR
- Must be the TokenHolder system contract [11](#0-10) 

**Attack Complexity:** LOW
- Single transaction to `AddBeneficiary` with `new Address()` as beneficiary
- No complex preconditions or timing requirements

**Feasibility Conditions:**
- Most likely scenario: Programming error in calling contract or scheme management interface
- Malicious scenario: Compromised or malicious scheme manager
- No on-chain protection exists to prevent this

**Detection Constraints:**
- Difficult to detect until profits are distributed and claimed
- Empty address entries may not be immediately visible in standard queries

**Probability Assessment:** MEDIUM-HIGH
- While requires privileged access, the lack of validation makes accidental occurrence through bugs highly probable
- Similar operations (ResetManager, Token operations) have proper validation, highlighting this as an oversight

### Recommendation

**Code-Level Mitigation:**

Add empty address validation to `AssertValidInput` method:

```csharp
private void AssertValidInput(AddBeneficiaryInput input)
{
    Assert(input.SchemeId != null, "Invalid scheme id.");
    Assert(input.BeneficiaryShare?.Beneficiary != null, "Invalid beneficiary address.");
    Assert(!input.BeneficiaryShare.Beneficiary.Value.IsNullOrEmpty(), "Invalid beneficiary address.");
    Assert(input.BeneficiaryShare?.Shares >= 0, "Invalid share.");
}
```

**Invariant Check:**
Ensure all address inputs in profit distribution methods validate both null reference AND empty Value field, consistent with the pattern used in `ResetManager` and MultiToken operations.

**Test Cases to Add:**
1. Test `AddBeneficiary` with `new Address()` - should revert with "Invalid beneficiary address"
2. Test `AddBeneficiaries` batch operation with mix of valid and empty addresses - should revert
3. Test `FixProfitDetail` with empty beneficiary address - should revert
4. Regression test confirming empty addresses are rejected across all beneficiary management methods

Reference the existing test pattern: [12](#0-11) 

### Proof of Concept

**Required Initial State:**
- A profit scheme created with manager = MANAGER_ADDRESS
- Some tokens available for distribution (e.g., 1000 ELF)

**Transaction Steps:**

1. **Add empty address beneficiary:**
```
MANAGER_ADDRESS → ProfitContract.AddBeneficiary({
    SchemeId: SCHEME_ID,
    BeneficiaryShare: {
        Beneficiary: new Address(),  // Empty address
        Shares: 100
    },
    EndPeriod: long.MaxValue
})
```
**Expected:** Transaction should fail with "Invalid beneficiary address"
**Actual:** Transaction succeeds, empty address added with 100 shares

2. **Add legitimate beneficiary:**
```
MANAGER_ADDRESS → ProfitContract.AddBeneficiary({
    SchemeId: SCHEME_ID,
    BeneficiaryShare: {
        Beneficiary: USER_ADDRESS,
        Shares: 900
    },
    EndPeriod: long.MaxValue
})
```
Total scheme shares now = 1000 (100 empty + 900 legitimate)

3. **Distribute profits:**
```
MANAGER_ADDRESS → ProfitContract.DistributeProfits({
    SchemeId: SCHEME_ID,
    AmountsMap: { "ELF": 1000 },
    Period: 1
})
```
Empty address allocated: 100 ELF (10%)
USER_ADDRESS allocated: 900 ELF (90%)

4. **Claim profits for empty address:**
```
ANY_ADDRESS → ProfitContract.ClaimProfits({
    SchemeId: SCHEME_ID,
    Beneficiary: new Address()
})
```

**Expected vs Actual Result:**
- **Expected:** Claim should fail or empty address should never have been accepted
- **Actual:** 100 ELF transferred to empty address and permanently locked in `State.Balances[new Address()]["ELF"]`

**Success Condition:** 
Query `State.Balances[emptyAddress]["ELF"]` returns 100, but no private key exists to access these tokens, confirming permanent fund loss.

### Notes

The vulnerability is confirmed through comparison with existing test cases that demonstrate empty addresses being properly rejected by validation in `ResetManager`. The absence of similar validation in `AddBeneficiary` represents an inconsistent security pattern across the Profit contract's address handling methods.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-165)
```csharp
    public override Empty AddBeneficiary(AddBeneficiaryInput input)
    {
        AssertValidInput(input);
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;

        var schemeId = input.SchemeId;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L194-209)
```csharp
        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);

        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);

        State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary] = currentProfitDetails;
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L417-429)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        if (input.AmountsMap.Any())
            Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");

```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L730-730)
```csharp
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L887-895)
```csharp
                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L99-114)
```csharp
    private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
    {
        Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
        Assert(from != to, "Can't do transfer to sender itself.");
        AssertValidMemo(memo);
        ModifyBalance(from, symbol, -amount);
        ModifyBalance(to, symbol, amount);
        Context.Fire(new Transferred
        {
            From = from,
            To = to,
            Symbol = symbol,
            Amount = amount,
            Memo = memo ?? string.Empty
        });
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L180-193)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransfer(Context.Sender, input.To, tokenInfo.Symbol, input.Amount, input.Memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = tokenInfo.Symbol,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L1526-1531)
```csharp
        resetRet = await creator.ResetManager.SendWithExceptionAsync(new ResetManagerInput
        {
            NewManager = new Address(),
            SchemeId = schemeId
        });
        resetRet.TransactionResult.Error.ShouldContain("Invalid new sponsor.");
```
