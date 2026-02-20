# Audit Report

## Title
Unbounded DelayDistributePeriodCount Enables Storage Exhaustion and Computational DoS via CachedDelayTotalShares Accumulation

## Summary
The `CreateScheme` method in the Profit contract lacks validation for `DelayDistributePeriodCount`, allowing any user to set arbitrarily large values up to int32.MaxValue (2,147,483,647). This causes unbounded growth of `CachedDelayTotalShares` map entries during profit distribution, leading to permanent storage exhaustion and computational denial-of-service in `RemoveBeneficiary` and `ClaimProfits` operations.

## Finding Description

The vulnerability stems from missing bounds validation on the `DelayDistributePeriodCount` parameter in `CreateScheme`. While `ProfitReceivingDuePeriodCount` is properly validated against a maximum of 1024, [1](#0-0)  no such validation exists for `DelayDistributePeriodCount`. The field is directly assigned from user input without any bounds checking. [2](#0-1) 

The protobuf definition confirms `delay_distribute_period_count` is an int32 field with no validation constraints. [3](#0-2)  No maximum constant is defined in the contract constants file. [4](#0-3) 

**Attack Vector 1 - Unbounded Storage Accumulation:**
During `DistributeProfits`, each call adds an entry to `CachedDelayTotalShares` at key `(period + DelayDistributePeriodCount)`. [5](#0-4)  These entries are only removed when that future period is reached. With `DelayDistributePeriodCount` set to 2,147,483,647, cache entries accumulate indefinitely as the removal condition will never be satisfied.

**Attack Vector 2 - RemoveBeneficiary Computational DoS:**
The `RemoveBeneficiary` function contains a loop that iterates from `removedMinPeriod` to `removedMinPeriod + DelayDistributePeriodCount`. [6](#0-5)  With `DelayDistributePeriodCount` equal to int32.MaxValue, this attempts approximately 2.1 billion iterations, causing guaranteed transaction failure and permanent inability to remove beneficiaries.

**Attack Vector 3 - ClaimProfits Computational DoS:**
The `ClaimProfits` function iterates over all keys in `CachedDelayTotalShares` to update shares. [7](#0-6)  As the cache grows linearly with each distribution period, this iteration becomes increasingly expensive, eventually making profit claims prohibitively costly or impossible.

## Impact Explanation

**Operational Impact - Computational DoS:**
- `RemoveBeneficiary` becomes completely unusable when `DelayDistributePeriodCount` is set to large values. The loop attempting billions of iterations will exceed all reasonable gas limits and fail deterministically, permanently preventing scheme managers from removing beneficiaries.
- `ClaimProfits` operations experience linearly increasing costs as cached entries accumulate. After N distribution periods with a large delay value, beneficiaries must iterate over N accumulated cache entries to claim profits.
- Any scheme with a maliciously large `DelayDistributePeriodCount` becomes permanently broken for beneficiary management since there is no mechanism to modify this value post-creation.

**Storage Exhaustion:**
- Each `DistributeProfits` call adds one permanent map entry to blockchain state
- After 1,000,000 periods, this accumulates significant storage per malicious scheme
- Multiple malicious schemes can be created by different attackers
- Blockchain state bloat increases node operation costs system-wide and is irreversible

**Severity: HIGH** because:
1. Complete denial-of-service for critical profit distribution functions
2. Storage exhaustion permanently affects blockchain state integrity
3. Attack is permanent once scheme is created (immutable `DelayDistributePeriodCount`)
4. Impacts both individual scheme operations and system-wide resources

## Likelihood Explanation

**Reachable Entry Point:**
`CreateScheme` is a public method [8](#0-7)  callable by any user without authorization restrictions. The method performs no caller validation beyond checking contract state references.

**Attacker Capabilities:**
- No special permissions required to create schemes
- Attacker becomes the scheme manager upon creation, enabling all subsequent operations
- Can set `DelayDistributePeriodCount` to any int32 value including int32.MaxValue
- Can call `DistributeProfits` repeatedly to accumulate cache entries
- Single transaction is sufficient to create the malicious scheme

**Attack Complexity:**
- Single transaction with modified parameter value
- No complex state setup or race conditions required
- Deterministic outcome (guaranteed DoS on affected operations)
- No timing dependencies or external oracle requirements

**Economic Rationality:**
- Initial cost: Single transaction fee (~$0.01-$1 depending on network conditions)
- Damage potential: Permanent DoS and storage exhaustion affecting all users of the scheme
- Cost-to-impact ratio: Extremely favorable for attacker
- No economic disincentive as attacker doesn't bear computational costs of victim transactions

**Probability: HIGH** - The attack has zero barriers to execution, is economically rational, and no existing protections prevent exploitation. Legitimate test cases demonstrate expected values of 0-3 for delay periods, [9](#0-8)  not millions, confirming the design intent was for small bounded values.

## Recommendation

Add validation for `DelayDistributePeriodCount` similar to the existing validation for `ProfitReceivingDuePeriodCount`:

```csharp
// In ProfitContractConstants.cs, add:
public const int MaximumDelayDistributePeriodCount = 1024;

// In CreateScheme method, add validation after line 54:
if (input.DelayDistributePeriodCount < 0 || 
    input.DelayDistributePeriodCount > ProfitContractConstants.MaximumDelayDistributePeriodCount)
{
    throw new AssertionException("Invalid delay distribute period count.");
}
```

This ensures `DelayDistributePeriodCount` remains within reasonable operational bounds while maintaining the delayed distribution functionality.

## Proof of Concept

```csharp
[Fact]
public async Task ProfitContract_UnboundedDelayDistributePeriodCount_DoS_Test()
{
    var creator = Creators[0];
    var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);
    
    // Create malicious scheme with unbounded delay period
    await creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        ProfitReceivingDuePeriodCount = 100,
        DelayDistributePeriodCount = int.MaxValue, // 2,147,483,647
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    var schemeIds = (await creator.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = creatorAddress })).SchemeIds;
    var schemeId = schemeIds.First();
    
    // Add a beneficiary
    var beneficiary = Address.FromPublicKey(NormalKeyPair[0].PublicKey);
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = beneficiary,
            Shares = 100
        },
        EndPeriod = 10
    });
    
    // Attempt to remove beneficiary - this will fail with DoS
    // The loop will attempt 2.1 billion iterations and exceed gas limits
    var removeResult = await creator.RemoveBeneficiary.SendWithExceptionAsync(
        new RemoveBeneficiaryInput
        {
            SchemeId = schemeId,
            Beneficiary = beneficiary
        });
    
    // Assert that transaction fails due to excessive computation
    removeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

**Notes:**
This vulnerability represents a critical flaw in the Profit contract's input validation. The absence of bounds checking on `DelayDistributePeriodCount` violates the principle of defensive programming and creates multiple attack vectors. The permanent nature of the DoS (no way to modify scheme parameters post-creation) makes this particularly severe. The vulnerability affects core protocol functionality and can be exploited by any user without special privileges.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L44-44)
```csharp
    public override Hash CreateScheme(CreateSchemeInput input)
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L48-54)
```csharp
        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
        else
            Assert(
                input.ProfitReceivingDuePeriodCount > 0 &&
                input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
                "Invalid profit receiving due period count.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L245-258)
```csharp
            if (scheme.DelayDistributePeriodCount > 0)
            {
                for (var removedPeriod = removedMinPeriod;
                     removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
                     removedPeriod++)
                {
                    if (scheme.CachedDelayTotalShares.ContainsKey(removedPeriod))
                    {
                        scheme.CachedDelayTotalShares[removedPeriod] =
                            scheme.CachedDelayTotalShares[removedPeriod].Sub(removedShares);
                    }
                }
            }
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L464-476)
```csharp
        if (scheme.DelayDistributePeriodCount > 0)
        {
            scheme.CachedDelayTotalShares.Add(input.Period.Add(scheme.DelayDistributePeriodCount), totalShares);
            if (scheme.CachedDelayTotalShares.ContainsKey(input.Period))
            {
                totalShares = scheme.CachedDelayTotalShares[input.Period];
                scheme.CachedDelayTotalShares.Remove(input.Period);
            }
            else
            {
                totalShares = 0;
            }
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L793-797)
```csharp
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L949-949)
```csharp
            DelayDistributePeriodCount = input.DelayDistributePeriodCount,
```

**File:** protobuf/profit_contract.proto (L126-126)
```text
    int32 delay_distribute_period_count = 3;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L1-10)
```csharp
namespace AElf.Contracts.Profit;

public class ProfitContractConstants
{
    public const int ProfitReceivingLimitForEachTime = 10;
    public const int DefaultProfitReceivingDuePeriodCount = 10;
    public const int MaximumProfitReceivingDuePeriodCount = 1024;
    public const int TokenAmountLimit = 5;
    public const int DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100;
}
```

**File:** test/AElf.Contracts.Profit.Tests/BVT/SchemeTests.cs (L66-76)
```csharp
        const int delayDistributePeriodCount = 3;
        const int contributeAmountEachTime = 100_000;
        var creator = Creators[0];
        var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);

        await creator.CreateScheme.SendAsync(new CreateSchemeInput
        {
            IsReleaseAllBalanceEveryTimeByDefault = true,
            ProfitReceivingDuePeriodCount = 100,
            DelayDistributePeriodCount = delayDistributePeriodCount
        });
```
