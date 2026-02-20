# Audit Report

## Title
Systematic Token Loss Due to Precision Loss in SafeCalculateProfits Function

## Summary
The Profit contract's `SafeCalculateProfits` function performs floor division when casting decimal calculations to `long`, causing systematic rounding errors. When profits are distributed to beneficiaries across multiple periods, the sum of individual allocations is consistently less than the total amount, resulting in dust tokens permanently locked in period virtual addresses with no recovery mechanism.

## Finding Description

**Root Cause:**

The `SafeCalculateProfits` function performs decimal arithmetic but casts the result to `long`, causing an implicit floor operation [1](#0-0) 

This function is called in two critical distribution paths:

1. **Sub-scheme distribution**: When distributing to sub-schemes via `DistributeProfitsForSubSchemes`, each allocation uses floor division [2](#0-1) , and the remainder is tracked and sent to period virtual addresses [3](#0-2) 

2. **Individual beneficiary claims**: When beneficiaries claim from period virtual addresses via `ProfitAllPeriods`, the same floor division applies [4](#0-3) , transferring the floor-divided amount [5](#0-4) 

**Why Protections Fail:**

Period virtual addresses are computed deterministically using XOR of scheme ID and period hash [6](#0-5) 

Examining all public methods in the Profit contract [7](#0-6) , there is NO administrative function to withdraw leftover balances from period-specific virtual addresses. The only operations are:
- `ContributeProfits`: Adds to virtual addresses
- `DistributeProfits`: Distributes from general ledger to period virtual addresses  
- `ClaimProfits`: Beneficiaries claim their floor-divided shares

No recovery mechanism exists for dust remaining after all beneficiaries have claimed.

## Impact Explanation

**Concrete Impact:**
- **Permanent Token Loss**: For every profit distribution period where `totalAmount` is not perfectly divisible by `totalShares`, dust tokens (1 to n-1 tokens per period, where n = number of beneficiaries) remain permanently locked in period virtual addresses
- **Systematic Accumulation**: This occurs in EVERY distribution period across ALL profit schemes where division is not exact
- **Irreversible**: Period virtual addresses are deterministically computed with no admin override or recovery function

**Quantified Example:**
- Distribution: 1000 tokens among 3 equal beneficiaries (1 share each, totalShares = 3)
- Beneficiary 1 claims: floor(1000 × 1 / 3) = 333 tokens
- Beneficiary 2 claims: floor(1000 × 1 / 3) = 333 tokens  
- Beneficiary 3 claims: floor(1000 × 1 / 3) = 333 tokens
- Total claimed: 999 tokens
- **Dust locked permanently: 1 token**

Over thousands of distribution periods across multiple schemes (Election, Treasury, TokenHolder contracts all use Profit schemes), this accumulates to significant token loss.

## Likelihood Explanation

**Execution Practicality:**
- **Trigger**: Normal `DistributeProfits` and `ClaimProfits` operations automatically trigger this
- **No Attack Required**: Natural consequence of the floor division logic in normal protocol operations
- **Guaranteed Occurrence**: Happens whenever `totalAmount % totalShares ≠ 0`

**Feasibility:**
- **Preconditions**: Standard profit distribution with multiple beneficiaries (extremely common scenario in Election rewards, Treasury distributions, etc.)
- **Frequency**: Every distribution period in every profit scheme where amounts don't divide evenly
- **Detection Difficulty**: Small per-period losses (1-N tokens) make the issue non-obvious until accumulated over time

**Probability: CRITICAL** - This occurs with virtually every profit distribution in normal protocol operations.

## Recommendation

Replace the floor division with a proportional distribution that allocates the remainder to ensure all tokens are distributed:

```csharp
private static Dictionary<int, long> DistributeWithRemainder(long totalAmount, List<long> shares, long totalShares)
{
    var distribution = new Dictionary<int, long>();
    var remainingAmount = totalAmount;
    
    // Calculate base amounts using floor division
    for (int i = 0; i < shares.Count; i++)
    {
        var amount = (long)((decimal)totalAmount * shares[i] / totalShares);
        distribution[i] = amount;
        remainingAmount -= amount;
    }
    
    // Distribute remainder to beneficiaries with largest fractional parts
    // or simply add to the last beneficiary
    if (remainingAmount > 0)
    {
        var lastIndex = shares.Count - 1;
        distribution[lastIndex] += remainingAmount;
    }
    
    return distribution;
}
```

Alternatively, implement an administrative function to recover dust from expired period virtual addresses after a grace period.

## Proof of Concept

```csharp
[Fact]
public async Task PrecisionLoss_DustAccumulation_Test()
{
    // Create a profit scheme
    var schemeId = await CreateSchemeAsync();
    
    // Add 3 beneficiaries with equal shares
    var beneficiary1 = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);
    var beneficiary2 = Address.FromPublicKey(CreatorKeyPair[1].PublicKey);
    var beneficiary3 = Address.FromPublicKey(CreatorKeyPair[2].PublicKey);
    
    await Creators[0].AddBeneficiaries.SendAsync(new AddBeneficiariesInput
    {
        SchemeId = schemeId,
        BeneficiaryShares = {
            new BeneficiaryShare { Beneficiary = beneficiary1, Shares = 1 },
            new BeneficiaryShare { Beneficiary = beneficiary2, Shares = 1 },
            new BeneficiaryShare { Beneficiary = beneficiary3, Shares = 1 }
        },
        EndPeriod = 100
    });
    
    // Contribute 1000 tokens to period 1
    const long amount = 1000;
    await Creators[0].ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId,
        Amount = amount,
        Period = 1,
        Symbol = "ELF"
    });
    
    // Distribute profits
    await Creators[0].DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1,
        AmountsMap = { {"ELF", amount} }
    });
    
    // Get period virtual address
    var periodAddress = await Creators[0].GetSchemeAddress.CallAsync(new SchemePeriod
    {
        SchemeId = schemeId,
        Period = 1
    });
    
    var initialBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = periodAddress,
        Symbol = "ELF"
    })).Balance;
    
    // All beneficiaries claim
    await Creators[0].ClaimProfits.SendAsync(new ClaimProfitsInput { SchemeId = schemeId, Beneficiary = beneficiary1 });
    await Creators[1].ClaimProfits.SendAsync(new ClaimProfitsInput { SchemeId = schemeId, Beneficiary = beneficiary2 });
    await Creators[2].ClaimProfits.SendAsync(new ClaimProfitsInput { SchemeId = schemeId, Beneficiary = beneficiary3 });
    
    // Check remaining balance in period virtual address (should be > 0 due to rounding)
    var finalBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = periodAddress,
        Symbol = "ELF"
    })).Balance;
    
    // Assert that dust remains locked
    finalBalance.ShouldBeGreaterThan(0);
    finalBalance.ShouldBe(1); // Expected 1 token dust for 1000/3 division
}
```

## Notes

This vulnerability affects all contracts using the Profit scheme system, including Election, Treasury, and TokenHolder contracts. The accumulated dust over time represents a permanent loss to the protocol and its users. The issue is particularly severe because it occurs automatically during normal operations without any malicious actor involvement.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L595-602)
```csharp
            if (remainAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = profitsReceivingVirtualAddress,
                        Amount = remainAmount,
                        Symbol = symbol
                    }.ToByteString());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L621-621)
```csharp
            var distributeAmount = SafeCalculateProfits(subSchemeShares.Shares, totalAmount, totalShares);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L873-874)
```csharp
                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);
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

**File:** protobuf/profit_contract.proto (L15-118)
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

    // Get all schemes managed by the specified manager.
    rpc GetManagingSchemeIds (GetManagingSchemeIdsInput) returns (CreatedSchemeIds) {
        option (aelf.is_view) = true;
    }
    
    // Get scheme according to scheme id.
    rpc GetScheme (aelf.Hash) returns (Scheme) {
        option (aelf.is_view) = true;
    }
    
    // Get the virtual address of the number of period of the scheme.
    rpc GetSchemeAddress (SchemePeriod) returns (aelf.Address) {
        option (aelf.is_view) = true;
    }
    
    // Query the distributed profit information for the specified period.
    rpc GetDistributedProfitsInfo (SchemePeriod) returns (DistributedProfitsInfo) {
        option (aelf.is_view) = true;
    }
    
    // Query the beneficiary's profit information on the scheme.
    rpc GetProfitDetails (GetProfitDetailsInput) returns (ProfitDetails) {
        option (aelf.is_view) = true;
    }
    
    // Query the amount of profit according to token symbol. (up to 10 periods).
    rpc GetProfitAmount (GetProfitAmountInput) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
    
    // Query the amount of profit according to token symbol.
    rpc GetAllProfitAmount (GetAllProfitAmountInput) returns (GetAllProfitAmountOutput) {
        option (aelf.is_view) = true;
    }

    // Query all profit (up to 10 periods).
    rpc GetProfitsMap (ClaimProfitsInput) returns (ReceivedProfitsMap) {
        option (aelf.is_view) = true;
    }
    
    // Query all profit.
    rpc GetAllProfitsMap (GetAllProfitsMapInput) returns (GetAllProfitsMapOutput) {
        option (aelf.is_view) = true;
    }
    
    rpc GetMaximumProfitReceivingPeriodCount(google.protobuf.Empty) returns (google.protobuf.Int32Value) {
        option (aelf.is_view) = true;
    }
}
```
