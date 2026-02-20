# Audit Report

## Title
Rounding Errors in Profit Distribution Cause Inaccessible Dust Accumulation in Period Virtual Addresses

## Summary
The `SafeCalculateProfits` function uses truncating integer division that systematically rounds down profit shares, causing remainder tokens (dust) to accumulate in period-specific virtual addresses. These period addresses are only accessible via `SendVirtualInline` during beneficiary claims, with no mechanism for scheme managers to recover unclaimed remainders after all beneficiaries have claimed their truncated shares.

## Finding Description

The Profit contract's distribution mechanism creates permanent token locks through integer division truncation:

**Root Cause - Truncating Division:**

The `SafeCalculateProfits` function converts values to decimal for calculation but casts back to `long`, which truncates fractional amounts, always rounding down: [1](#0-0) 

**Distribution Flow:**

When `DistributeProfits` executes, it stores the total distributed amount in `AmountsMap` for the period: [2](#0-1) 

Sub-schemes receive truncated amounts calculated via `SafeCalculateProfits`: [3](#0-2) 

The remainder after sub-scheme distribution is transferred to the period virtual address: [4](#0-3) 

**Claiming Flow:**

Individual beneficiaries claim using the same truncating calculation based on the original `AmountsMap` amount: [5](#0-4) 

Each beneficiary receives a rounded-down amount. After all claims, dust remains in the period address.

**Why Dust is Inaccessible:**

Period virtual addresses are generated deterministically via XOR of scheme ID and period hash: [6](#0-5) 

The ONLY code path that transfers from period addresses is through `SendVirtualInline` during `ClaimProfits`: [7](#0-6) 

No public method exists for managers to withdraw remaining balances. The `BurnProfits` method only operates on the scheme's main virtual address (using `scheme.SchemeId`), not period-specific addresses: [8](#0-7) 

The protocol definition confirms no withdrawal mechanism exists for period addresses - all public methods listed provide no way to recover dust from period-specific virtual addresses: [9](#0-8) 

## Impact Explanation

**Quantified Loss:**
- Per-period dust: 0 to (totalShares - 1) tokens per symbol
- Example: 100 tokens distributed among 99 total shares (33+33+33) results in 3×33=99 claimed, leaving 1 token permanently locked
- Over 1,000 periods: thousands of tokens become inaccessible
- Affects ALL profit schemes: consensus mining rewards, treasury distributions, token holder dividends

**Severity Rationale (Medium):**
This represents genuine economic loss through fund locks rather than theft. While individual per-period amounts are small relative to total shares, the cumulative effect across hundreds of periods and multiple active schemes protocol-wide results in measurable value loss. The funds are not exploited by attackers but are permanently removed from circulation, reducing protocol economic efficiency.

## Likelihood Explanation

**Deterministic Occurrence:**
This is not an attack but a mathematical certainty. Whenever `totalAmount % totalShares ≠ 0`, truncation guarantees dust creation. For typical token distributions (e.g., distributing 1,000,000 tokens among 987,654 shares), the calculation produces fractional results that get truncated.

**Operational Reality:**
- Triggered by normal `DistributeProfits` calls from authorized managers
- No special preconditions required
- Affects every distribution period with non-divisible amounts
- Beneficiaries claim normally via `ClaimProfits`
- Schemes run continuously for hundreds or thousands of periods

The probability is effectively 100% for real-world profit distributions.

## Recommendation

Implement one of these solutions:

**Option 1: Manager Sweep Function**
Add a public method allowing scheme managers to withdraw unclaimed balances from period addresses after a sufficient grace period (e.g., after the period is older than `ProfitReceivingDuePeriodCount`). This allows recovery of dust without affecting legitimate claims.

**Option 2: Accumulate to Next Period**
Instead of losing dust, carry forward remainder amounts to the next period's distribution by storing them in state and adding them to the next `DistributeProfits` call.

**Option 3: Round-Robin Distribution**
Distribute dust tokens using round-robin: assign the first `remainder` beneficiaries one extra token each until the remainder is exhausted. This ensures all tokens are distributed fairly.

## Proof of Concept

```csharp
// Test case demonstrating dust accumulation
[Fact]
public async Task Test_DustAccumulationInPeriodAddress()
{
    // Setup: Create scheme with 3 beneficiaries having 33 shares each (99 total)
    var schemeId = await CreateTestScheme();
    await AddBeneficiary(schemeId, beneficiary1, 33);
    await AddBeneficiary(schemeId, beneficiary2, 33);
    await AddBeneficiary(schemeId, beneficiary3, 33);
    
    // Distribute 100 tokens in period 1
    await DistributeProfits(schemeId, period: 1, amount: 100, symbol: "ELF");
    
    // Each beneficiary claims
    await ClaimProfits(schemeId, beneficiary1); // Gets 33 tokens
    await ClaimProfits(schemeId, beneficiary2); // Gets 33 tokens  
    await ClaimProfits(schemeId, beneficiary3); // Gets 33 tokens
    
    // Verify: Period address has 1 token dust remaining
    var periodAddress = GetDistributedPeriodProfitsVirtualAddress(schemeId, 1);
    var balance = await TokenContract.GetBalance(periodAddress, "ELF");
    
    Assert.Equal(1, balance); // Dust is locked
    
    // Verify: No method exists to recover this dust
    // Manager cannot withdraw it, beneficiaries already claimed maximum
}
```

## Notes

This vulnerability is a **design flaw** rather than an exploitable attack vector. The funds become permanently inaccessible through normal operation, not malicious action. The cumulative economic impact across all profit schemes and periods can be significant despite individual per-period amounts being small. The lack of any recovery mechanism makes this a genuine fund lock issue requiring a protocol-level fix.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L534-545)
```csharp
                    Owner = scheme.VirtualAddress,
                    Symbol = symbol
                });
                if (balanceOfToken.Balance < amount)
                    continue;
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = Context.Self,
                        Amount = amount,
                        Symbol = symbol
                    }.ToByteString());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L574-582)
```csharp
            var balanceOfVirtualAddressForCurrentPeriod = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = profitsReceivingVirtualAddress,
                Symbol = symbol
            }).Balance;
            distributedProfitsInformation.AmountsMap[symbol] = amount.Add(balanceOfVirtualAddressForCurrentPeriod);
        }

        State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInformation;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L595-603)
```csharp
            if (remainAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = profitsReceivingVirtualAddress,
                        Amount = remainAmount,
                        Symbol = symbol
                    }.ToByteString());
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L621-631)
```csharp
            var distributeAmount = SafeCalculateProfits(subSchemeShares.Shares, totalAmount, totalShares);
            if (distributeAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = subItemVirtualAddress,
                        Amount = distributeAmount,
                        Symbol = symbol
                    }.ToByteString());

            remainAmount = remainAmount.Sub(distributeAmount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L873-875)
```csharp
                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);

```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L887-896)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L956-962)
```csharp
    private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
    {
        var decimalTotalAmount = (decimal)totalAmount;
        var decimalShares = (decimal)shares;
        var decimalTotalShares = (decimal)totalShares;
        return (long)(decimalTotalAmount * decimalShares / decimalTotalShares);
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L57-60)
```csharp
    private Hash GeneratePeriodVirtualAddressFromHash(Hash schemeId, long period)
    {
        return HashHelper.XorAndCompute(schemeId, HashHelper.ComputeFrom(period));
    }
```

**File:** protobuf/profit_contract.proto (L15-68)
```text
service ProfitContract {
    option (aelf.csharp_state) = "AElf.Contracts.Profit.ProfitContractState";

    // Create a scheme for profit distribution, and return the created scheme id.
    rpc CreateScheme (CreateSchemeInput) returns (aelf.Hash) {
    }
    
    // Add beneficiary to scheme.
    rpc AddBeneficiary (AddBeneficiaryInput) returns (google.protobuf.Empty) {
    }

    // Remove beneficiary from scheme.
    rpc RemoveBeneficiary (RemoveBeneficiaryInput) returns (google.protobuf.Empty) {
    }
    
    // Batch add beneficiary to scheme.
    rpc AddBeneficiaries (AddBeneficiariesInput) returns (google.protobuf.Empty) {
    }

    // Batch remove beneficiary from scheme.
    rpc RemoveBeneficiaries (RemoveBeneficiariesInput) returns (google.protobuf.Empty) {
    }

    rpc FixProfitDetail (FixProfitDetailInput) returns (google.protobuf.Empty) {
    }

    // Contribute profit to a scheme.
    rpc ContributeProfits (ContributeProfitsInput) returns (google.protobuf.Empty) {
    }
    
    // The beneficiary draws tokens from the scheme.
    rpc ClaimProfits (ClaimProfitsInput) returns (google.protobuf.Empty) {
    }

    // Distribute profits to schemes, including its sub scheme according to period and  token symbol, 
    // should be called by the manager. 
    rpc DistributeProfits (DistributeProfitsInput) returns (google.protobuf.Empty) {
    }
    
    // Add sub scheme to a scheme. 
    // This will effectively add the specified sub-scheme as a beneficiary of the parent scheme.
    rpc AddSubScheme (AddSubSchemeInput) returns (google.protobuf.Empty) {
    }
    
    // Remove sub scheme from a scheme.
    rpc RemoveSubScheme (RemoveSubSchemeInput) returns (google.protobuf.Empty) {
    }
    
    // Reset the manager of a scheme.
    rpc ResetManager (ResetManagerInput) returns (google.protobuf.Empty) {
    }
    
    rpc SetMaximumProfitReceivingPeriodCount(google.protobuf.Int32Value) returns (google.protobuf.Empty) {
    }
```
