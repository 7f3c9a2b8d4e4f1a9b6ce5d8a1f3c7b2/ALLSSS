# Audit Report

## Title
Double Share Allocation Vulnerability: AddBeneficiary and RegisterForProfits Interaction Allows Uncollateralized Profit Claims

## Summary
A critical vulnerability in the TokenHolder contract allows users to receive duplicate profit share allocations by being added via `AddBeneficiary` and subsequently calling `RegisterForProfits`. This results in uncollateralized profit claims, where users receive distributions based on inflated share counts without corresponding token locks, while permanently breaking manager control over beneficiary updates through exception-throwing code paths.

## Finding Description

The vulnerability arises from an incomplete validation check in `RegisterForProfits` that only verifies lock ID existence without checking existing beneficiary status. [1](#0-0) 

The underlying Profit contract's `AddBeneficiary` implementation compounds this issue by appending new `ProfitDetail` entries to a list rather than enforcing uniqueness per beneficiary. [2](#0-1) 

**Exploitation Sequence:**

1. **Manager Pre-allocation**: Manager calls TokenHolder's `AddBeneficiary` for userX with 100 shares. This invokes the Profit contract's `AddBeneficiary`, creating one `ProfitDetail` entry with 100 shares and incrementing `TotalShares` by 100. No lock ID is created in the TokenHolder contract state.

2. **User Self-Registration**: UserX calls `RegisterForProfits` with 50 tokens. The assertion at line 151 passes because `State.LockIds[input.SchemeManager][Context.Sender]` is null. [1](#0-0) 

3. **Token Lock and Duplicate Addition**: The method locks 50 tokens and then invokes Profit contract's `AddBeneficiary` with 50 shares. [3](#0-2) 

4. **List Append Without Deduplication**: In the Profit contract, since `currentProfitDetails` already exists from step 1, the code appends a second `ProfitDetail` rather than replacing or validating uniqueness. [4](#0-3) 

**Result**: UserX now has two distinct `ProfitDetail` entries totaling 150 shares, but only 50 tokens are locked as collateral.

**Manager Function Breakage:**

When the manager attempts to update this beneficiary via `AddBeneficiary`, the code retrieves profit details and expects exactly one entry using `.Single()`. [5](#0-4)  With multiple details present, this throws an `InvalidOperationException`, permanently blocking manager updates.

Similarly, `RemoveBeneficiary` also uses `.Single()` on the details collection, creating the same exception path. [6](#0-5) 

**Profit Distribution Impact:**

During profit claims, the `ClaimProfits` method in the Profit contract retrieves all profit details for the beneficiary and processes each one independently. [7](#0-6)  This means userX receives profits calculated against 150 total shares despite only locking 50 tokens.

**Withdrawal Consequence:**

The TokenHolder contract creates schemes with `CanRemoveBeneficiaryDirectly = true`. [8](#0-7)  When this flag is set and a user withdraws, the Profit contract's `RemoveProfitDetails` removes all details for that beneficiary. [9](#0-8)  This causes the user to lose both profit streams simultaneously.

## Impact Explanation

**Direct Financial Impact:**
- **Uncollateralized Profit Extraction**: Users receive profit distributions based on shares (100) that require no token collateral. In a scheme distributing 1000 ELF across 1000 total shares, an exploiting user with 50 locked tokens but 150 allocated shares receives 150 ELF instead of 50 ELF—extracting 100 ELF without corresponding locked value.

- **Dilution of Legitimate Participants**: Every exploiting user inflates `TotalShares` without proportional token locks, reducing the profit percentage for all honest participants who maintain proper token-to-share ratios.

**Operational Impact:**
- **Permanent Manager DoS**: Once triggered, manager functions `AddBeneficiary` and `RemoveBeneficiary` become permanently inoperable for affected beneficiaries due to `.Single()` exception paths. This completely breaks administrative control over the profit scheme.

- **State Integrity Violation**: The fundamental invariant that profit shares correspond to locked tokens is broken, corrupting the economic model of the TokenHolder system.

## Likelihood Explanation

**Accessibility:**
Both `AddBeneficiary` (manager-only) and `RegisterForProfits` (user-callable) are standard public methods with no complex preconditions beyond role-based access control.

**Triggering Scenarios:**

*Accidental Occurrence*: In normal operational workflows, managers may pre-allocate beneficiaries for administrative purposes. If any pre-allocated user later decides to independently register for profits (unaware of their existing status), the vulnerability triggers automatically.

*Intentional Exploitation*: A malicious user who discovers they've been added as a beneficiary can deliberately call `RegisterForProfits` with minimal tokens to double their share allocation while minimizing locked collateral.

**Detection Difficulty:**
The vulnerable state (multiple profit details per beneficiary) is not easily observable until:
- A manager attempts an update and receives an exception
- Profit calculations reveal unexpected share inflation
- Post-mortem analysis of beneficiary withdrawal events

Given the commonality of pre-allocation patterns in profit-sharing systems and the lack of preventive validation, this vulnerability has HIGH likelihood of occurrence in production deployments.

## Recommendation

Add a beneficiary existence check in `RegisterForProfits` before proceeding with token lock and registration:

```csharp
public override Empty RegisterForProfits(RegisterForProfitsInput input)
{
    Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
    
    var scheme = GetValidScheme(input.SchemeManager);
    
    // NEW: Check if user is already a beneficiary in the Profit contract
    var existingDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = Context.Sender
    });
    Assert(existingDetails == null || !existingDetails.Details.Any(), 
        "User is already a beneficiary. Cannot register again.");
    
    // ... rest of existing logic
}
```

Additionally, consider implementing deduplication logic in the Profit contract's `AddBeneficiary` to enforce at most one active `ProfitDetail` per beneficiary per scheme, or modifying TokenHolder's `AddBeneficiary` and `RemoveBeneficiary` to handle multiple details gracefully rather than using `.Single()`.

## Proof of Concept

```csharp
[Fact]
public async Task DoubleShareAllocation_ExploitTest()
{
    // Setup: Create scheme
    var manager = Accounts[0];
    var exploitUser = Accounts[1];
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    // Step 1: Manager adds user with 100 shares (no lock required)
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = exploitUser.Address,
        Shares = 100
    });
    
    // Verify: User has 100 shares, no lock
    var detailsBefore = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeId,
        Beneficiary = exploitUser.Address
    });
    Assert.Single(detailsBefore.Details); // One detail with 100 shares
    Assert.Equal(100, detailsBefore.Details[0].Shares);
    
    // Step 2: User registers with only 50 tokens
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager.Address,
        Amount = 50
    });
    
    // Verify: User now has TWO profit details (100 + 50 = 150 shares)
    var detailsAfter = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeId,
        Beneficiary = exploitUser.Address
    });
    Assert.Equal(2, detailsAfter.Details.Count); // VULNERABILITY: Two details exist
    Assert.Equal(150, detailsAfter.Details.Sum(d => d.Shares)); // Total 150 shares
    
    // Verify: Manager functions are now broken (will throw on .Single())
    var updateException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
        {
            Beneficiary = exploitUser.Address,
            Shares = 200
        });
    });
    Assert.Contains("Sequence contains more than one element", updateException.Message);
    
    // Verify: User receives profits based on 150 shares despite only 50 tokens locked
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = manager.Address,
        Amount = 1500, // 1500 ELF to distribute
        Symbol = "ELF"
    });
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = manager.Address
    });
    
    var profitAmount = await ProfitContractStub.GetProfitAmount.CallAsync(new GetProfitAmountInput
    {
        SchemeId = schemeId,
        Beneficiary = exploitUser.Address,
        Symbol = "ELF"
    });
    
    // With 150 shares out of TotalShares, user receives disproportionate profits
    // Expected (50 locked / total locked) but receives (150 shares / total shares)
    Assert.True(profitAmount.Value > 50); // Receives more than their locked collateral justifies
}
```

**Notes**

This vulnerability represents a fundamental breakdown in the TokenHolder contract's economic model, where profit shares are intended to correspond 1:1 with locked token amounts. The interaction between manager-initiated beneficiary addition and user-initiated profit registration creates an exploitable state where shares can be inflated without corresponding collateral. The `.Single()` usage in manager functions indicates the original design assumed exactly one profit detail per beneficiary, but the Profit contract's implementation allows multiple details through its append-only logic. This architectural mismatch creates both the economic exploit and the administrative DoS vector.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L24-24)
```csharp
            CanRemoveBeneficiaryDirectly = true
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L55-55)
```csharp
            shares.Add(detail.Details.Single().Shares);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L78-78)
```csharp
        }).Details.Single();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L151-151)
```csharp
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L168-176)
```csharp
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = input.Amount
            }
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L766-785)
```csharp
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();

        Context.LogDebug(() =>
            $"Profitable details: {profitableDetails.Aggregate("\n", (profit1, profit2) => profit1.ToString() + "\n" + profit2)}");

        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
        // Only can get profit from last profit period to actual last period (profit.CurrentPeriod - 1),
        // because current period not released yet.
        for (var i = 0; i < profitableDetailCount; i++)
        {
            var profitDetail = profitableDetails[i];
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
        }
```
