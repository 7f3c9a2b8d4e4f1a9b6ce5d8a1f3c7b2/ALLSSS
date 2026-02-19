# Audit Report

## Title
Non-Existent Token Distribution Causes Permanent Profit Loss in DistributeProfits

## Summary
The `DistributeProfits` function fails to validate token existence, only checking that symbols are non-empty strings. When a manager distributes profits using a non-existent token symbol with amount 0, the period is marked as released without transferring legitimate tokens from the general ledger, causing permanent fund loss as those tokens become unclaimable.

## Finding Description

The vulnerability stems from insufficient token validation in `DistributeProfits`. While `ContributeProfits` properly validates token existence using `AssertTokenExists`, [1](#0-0)  `DistributeProfits` only validates that token symbols are non-empty strings. [2](#0-1) 

When `GetBalance` is called on a non-existent token, it returns 0 instead of throwing an error. [3](#0-2)  This allows the distribution flow to proceed with invalid tokens.

**Attack Execution Path:**

1. Users contribute legitimate tokens (e.g., 1000 ELF) to the scheme's general ledger via `ContributeProfits` with Period=0
2. Manager calls `DistributeProfits` with a non-existent token symbol (e.g., "FAKE") and amount=0
3. At line 437-442, when amount is 0, the code queries the balance of "FAKE" from the general ledger, which returns 0 [4](#0-3) 
4. The `profitsMap` is populated with only {"FAKE": 0}, excluding legitimate ELF tokens
5. Since `AmountsMap.Any()` is true, the code skips the section that would include all tokens from `ReceivedTokenSymbols` [5](#0-4) 
6. `UpdateDistributedProfits` marks the period as released and updates `AmountsMap` with only the fake token [6](#0-5) 
7. `PerformDistributeProfits` transfers only "FAKE" tokens (0 amount = no-op) [7](#0-6) 
8. The period's `CurrentPeriod` is incremented, finalizing the release [8](#0-7) 

The ELF tokens remain in the general ledger but are not transferred to the period's virtual address. When beneficiaries attempt to claim, `ClaimProfits` checks if the symbol exists in `AmountsMap` and skips distribution for missing symbols. [9](#0-8) 

Furthermore, future contributions to the released period are blocked by the `IsReleased` check in `ContributeProfits`. [10](#0-9) 

## Impact Explanation

**Direct Fund Impact:**
- Legitimate tokens (e.g., 1000 ELF) remain permanently locked in the scheme's general ledger
- These tokens are excluded from the period's `AmountsMap`, making them unclaimable by beneficiaries
- No recovery mechanism exists to extract tokens from a released period or redistribute them
- All scheme beneficiaries lose their expected profit share for that period

**Affected Parties:**
- Scheme beneficiaries who expect to claim profits
- Users who contributed tokens to the scheme
- The protocol's profit distribution integrity

**Severity Justification:**
This is a high-severity issue due to permanent fund loss. While it requires manager action to trigger, the scheme manager is not a trusted role per the framework definition (which lists only genesis method-fee provider, organization controllers, and consensus system contracts as trusted). The vulnerability can occur through honest mistakes (typos, copy-paste errors) or malicious intent.

## Likelihood Explanation

**Attacker Capabilities:**
- Requires scheme manager role to call `DistributeProfits`
- Manager privilege is obtainable and not restricted to trusted actors

**Attack Complexity:**
Low - requires only a single function call with an incorrect token symbol parameter.

**Realistic Scenarios:**
1. **Accidental:** Manager makes a typo in token symbol (e.g., "EFL" instead of "ELF")
2. **Accidental:** Copy-paste error from documentation or previous transactions
3. **Accidental:** Integration bug in frontend/tooling passes wrong symbol
4. **Malicious:** Compromised or malicious manager intentionally griefs beneficiaries

**Detection Constraints:**
- No validation exists to detect invalid symbols before distribution
- Once executed, the damage is irreversible
- No monitoring or warning system for token existence

**Probability Assessment:**
Medium to high likelihood given the ease of triggering through common mistakes and the lack of protective validation.

## Recommendation

Add token existence validation to `DistributeProfits` consistent with `ContributeProfits`:

```csharp
public override Empty DistributeProfits(DistributeProfitsInput input)
{
    if (input.AmountsMap.Any())
    {
        Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");
        // ADD THIS VALIDATION:
        foreach (var symbol in input.AmountsMap.Keys)
        {
            AssertTokenExists(symbol);
        }
    }
    
    // ... rest of the method
}
```

This ensures that only valid, existing tokens can be included in profit distribution, preventing permanent fund lock scenarios.

## Proof of Concept

```csharp
[Fact]
public async Task DistributeProfits_NonExistentToken_CausesPermanentLoss()
{
    // Setup: Create scheme and contribute ELF to general ledger
    var schemeId = await CreateSchemeAsync();
    await ContributeProfits(schemeId, amount: 1000); // Goes to general ledger (Period=0)
    
    // Add beneficiary
    await Creators[0].AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare 
        { 
            Beneficiary = Address.FromPublicKey(NormalKeyPair[0].PublicKey), 
            Shares = 100 
        }
    });
    
    // Attack: Distribute with non-existent token
    await Creators[0].DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        AmountsMap = { { "FAKE", 0 } }, // Non-existent token
        Period = 1
    });
    
    // Verify: Period is released
    var scheme = await Creators[0].GetScheme.CallAsync(schemeId);
    scheme.CurrentPeriod.ShouldBe(2); // Period incremented
    
    // Verify: ELF still in general ledger, not distributed
    var generalLedgerBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = scheme.VirtualAddress,
        Symbol = "ELF"
    })).Balance;
    generalLedgerBalance.ShouldBe(1000); // Still locked in general ledger
    
    // Verify: Beneficiary cannot claim ELF (not in AmountsMap for period 1)
    await Normal[0].ClaimProfits.SendAsync(new ClaimProfitsInput { SchemeId = schemeId });
    var beneficiaryBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = Address.FromPublicKey(NormalKeyPair[0].PublicKey),
        Symbol = "ELF"
    })).Balance;
    beneficiaryBalance.ShouldBe(0); // No ELF received - permanent loss
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L419-420)
```csharp
        if (input.AmountsMap.Any())
            Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L437-444)
```csharp
                var actualAmount = amount.Value == 0
                    ? State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = amount.Key
                    }).Balance
                    : amount.Value;
                profitsMap.Add(amount.Key, actualAmount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L447-460)
```csharp
        else
        {
            if (scheme.IsReleaseAllBalanceEveryTimeByDefault && scheme.ReceivedTokenSymbols.Any())
                // Prepare to distribute all from general ledger.
                foreach (var symbol in scheme.ReceivedTokenSymbols)
                {
                    var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = symbol
                    }).Balance;
                    profitsMap.Add(symbol, balance);
                }
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L560-583)
```csharp
    private void UpdateDistributedProfits(Dictionary<string, long> profitsMap,
        Address profitsReceivingVirtualAddress, long totalShares)
    {
        var distributedProfitsInformation =
            State.DistributedProfitsMap[profitsReceivingVirtualAddress] ??
            new DistributedProfitsInfo();

        distributedProfitsInformation.TotalShares = totalShares;
        distributedProfitsInformation.IsReleased = true;

        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            var balanceOfVirtualAddressForCurrentPeriod = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = profitsReceivingVirtualAddress,
                Symbol = symbol
            }).Balance;
            distributedProfitsInformation.AmountsMap[symbol] = amount.Add(balanceOfVirtualAddressForCurrentPeriod);
        }

        State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInformation;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L585-604)
```csharp
    private void PerformDistributeProfits(Dictionary<string, long> profitsMap, Scheme scheme, long totalShares,
        Address profitsReceivingVirtualAddress)
    {
        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            var remainAmount = DistributeProfitsForSubSchemes(symbol, amount, scheme, totalShares);
            Context.LogDebug(() => $"Distributing {remainAmount} {symbol} tokens.");
            // Transfer remain amount to individuals' receiving profits address.
            if (remainAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = profitsReceivingVirtualAddress,
                        Amount = remainAmount,
                        Symbol = symbol
                    }.ToByteString());
        }
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L656-656)
```csharp
        AssertTokenExists(input.Symbol);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L698-699)
```csharp
                Assert(!distributedProfitsInformation.IsReleased,
                    $"Scheme of period {input.Period} already released.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L866-871)
```csharp
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L166-172)
```csharp
    private long GetBalance(Address address, string symbol)
    {
        AssertValidInputAddress(address);
        var actualSymbol = GetActualTokenSymbol(symbol);
        Assert(!string.IsNullOrWhiteSpace(actualSymbol), "Invalid symbol.");
        return State.Balances[address][actualSymbol];
    }
```
