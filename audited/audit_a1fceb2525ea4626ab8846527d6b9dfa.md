### Title
Permanent Fund Lock via Unbounded Far-Future Period Contributions in Profit Contract

### Summary
The `ContributeProfits` function lacks an upper bound on the `Period` parameter, allowing any user to contribute funds to arbitrarily distant future periods (e.g., period 9,223,372,036,854,775,807). Since period distribution must proceed sequentially and no recovery mechanism exists, these funds become permanently locked in period-specific virtual addresses that can never practically be reached.

### Finding Description

The vulnerability exists in the `ContributeProfits` function where period validation only enforces a lower bound: [1](#0-0) 

This assertion only checks that `input.Period >= scheme.CurrentPeriod` with no upper limit. The function has no authorization check, allowing any user to call it: [2](#0-1) 

When a period value is specified, funds are transferred to a period-specific virtual address: [3](#0-2) 

The critical issue is that the `DistributeProfits` function enforces strict sequential period progression: [4](#0-3) 

This requires `input.Period == CurrentPeriod` exactly, and `CurrentPeriod` only increments by 1 per distribution: [5](#0-4) 

Virtual addresses are deterministically generated and have no private keys, making funds accessible only through contract logic: [6](#0-5) 

No recovery mechanism exists to withdraw from unreleased future periods, and no maximum period constant is defined: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**
- Funds contributed to far-future periods (e.g., period 1,000,000 when CurrentPeriod = 1) are permanently locked
- To release period 1,000,000 requires exactly 999,999 sequential `DistributeProfits` calls
- This is computationally and economically infeasible (years of continuous operation at 1 call/block)
- Virtual addresses can only be accessed via contract logic, not by direct transfer

**Affected Parties:**
- Contributors who mistakenly or maliciously specify large period values lose funds permanently
- Profit scheme integrity is compromised as unreachable periods create "dead" balances
- Any user can grief any scheme by contributing dust amounts to far-future periods

**Severity Justification:**
- Medium-to-High severity due to permanent, irreversible fund loss
- No reliance on privileged roles - any user with token approval can trigger
- Cannot be mitigated after the fact without contract upgrade

### Likelihood Explanation

**Attacker Capabilities:**
- Requires only: (1) tokens of the scheme's accepted symbol, (2) approval to ProfitContract
- No privileged role or special authorization needed

**Attack Complexity:**
- Single transaction with `ContributeProfits` call
- Parameters: valid SchemeId, large Period value (e.g., `long.MaxValue - 1`), any Amount > 0
- Transaction cost: standard gas fees only

**Feasibility Conditions:**
- Any active profit scheme is vulnerable
- Attacker doesn't need to control or compromise the scheme manager
- The assertion at line 684 explicitly permits any period >= CurrentPeriod

**Economic Rationality:**
- Cost: Minimal (approval transaction + contribution transaction + token amount)
- Impact: Permanent lock of contributed funds (own funds for griefing, or accidental user error)
- A malicious actor could contribute small amounts to extremely distant periods to permanently "poison" a scheme

**Probability:**
- High for accidental lock: Users may misunderstand period semantics or have UI bugs
- Medium for intentional griefing: Low cost, high disruption potential
- Demonstrated in tests that period 3 is contributed when CurrentPeriod = 1, showing far-future contributions are expected behavior without bounds [8](#0-7) 

### Recommendation

**Immediate Fix:**
Add an upper bound check in `ContributeProfits` to limit how far into the future contributions can be made:

```csharp
// After line 684, add:
const long MaxFuturePeriods = 1000; // or appropriate business limit
Assert(input.Period <= scheme.CurrentPeriod.Add(MaxFuturePeriods), 
    $"Period {input.Period} exceeds maximum allowed future period {scheme.CurrentPeriod.Add(MaxFuturePeriods)}");
```

**Additional Mitigations:**
1. Add a constant `MaximumContributionPeriodOffset` to ProfitContractConstants
2. Implement an emergency withdrawal function for scheme managers to reclaim funds from unreleased periods
3. Consider allowing period "skipping" with consensus (e.g., governance vote) to jump CurrentPeriod forward
4. Add comprehensive validation tests for boundary period values

**Test Cases to Add:**
- Test contributing to period > CurrentPeriod + reasonable_offset (should fail)
- Test contributing to long.MaxValue (should fail)
- Test contributing to MaxInt64 (should fail)
- Verify existing tests don't exceed new bounds

### Proof of Concept

**Initial State:**
1. Profit scheme exists with SchemeId = `scheme_id`, CurrentPeriod = 1
2. Attacker has 1000 ELF tokens and approves ProfitContract

**Attack Steps:**

Transaction 1 - Token Approval:
```
TokenContract.Approve(
    Spender: ProfitContractAddress,
    Symbol: "ELF",
    Amount: 1000
)
```

Transaction 2 - Lock Funds in Far Future:
```
ProfitContract.ContributeProfits(
    SchemeId: scheme_id,
    Symbol: "ELF",
    Amount: 1000,
    Period: 9223372036854775806  // long.MaxValue - 1
)
```

**Expected vs Actual:**
- Expected: Transaction should fail with "Period exceeds maximum allowed" or similar
- Actual: Transaction succeeds, 1000 ELF transferred to virtual address for period 9223372036854775806

**Verification:**
```
GetSchemeAddress(scheme_id, period: 9223372036854775806)
-> Returns virtual address with 1000 ELF balance
```

**Funds Recovery Attempt:**
To release period 9223372036854775806, manager must call `DistributeProfits` exactly 9,223,372,036,854,775,805 times sequentially (period 1, 2, 3, ..., 9223372036854775806). At 5 seconds per block and 1 call per block, this requires approximately 1.46 trillion years.

**Success Condition:**
Funds are permanently locked with no practical recovery path, confirming the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L478-480)
```csharp
        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L651-721)
```csharp
    public override Empty ContributeProfits(ContributeProfitsInput input)
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
        AssertTokenExists(input.Symbol);
        if (input.Amount <= 0)
        {
            throw new AssertionException("Amount need to greater than 0.");
        }

        var scheme = State.SchemeInfos[input.SchemeId];
        if (scheme == null)
        {
            throw new AssertionException("Scheme not found.");
        }
        // ReSharper disable once PossibleNullReferenceException
        var virtualAddress = scheme.VirtualAddress;

        if (input.Period == 0)
        {

            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = Context.Sender,
                To = virtualAddress,
                Symbol = input.Symbol,
                Amount = input.Amount,
                Memo = $"Add {input.Amount} dividends."
            });
        }
        else
        {
            Assert(input.Period >= scheme.CurrentPeriod, "Invalid contributing period.");
            var distributedPeriodProfitsVirtualAddress =
                GetDistributedPeriodProfitsVirtualAddress(input.SchemeId, input.Period);

            var distributedProfitsInformation = State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
            if (distributedProfitsInformation == null)
            {
                distributedProfitsInformation = new DistributedProfitsInfo
                {
                    AmountsMap = { { input.Symbol, input.Amount } }
                };
            }
            else
            {
                Assert(!distributedProfitsInformation.IsReleased,
                    $"Scheme of period {input.Period} already released.");
                distributedProfitsInformation.AmountsMap[input.Symbol] =
                    distributedProfitsInformation.AmountsMap[input.Symbol].Add(input.Amount);
            }

            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = Context.Sender,
                To = distributedPeriodProfitsVirtualAddress,
                Symbol = input.Symbol,
                Amount = input.Amount
            });

            State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress] = distributedProfitsInformation;
        }

        // If someone directly use virtual address to do the contribution, won't sense the token symbol he was using.
        if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol)) scheme.ReceivedTokenSymbols.Add(input.Symbol);

        State.SchemeInfos[scheme.SchemeId] = scheme;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L51-60)
```csharp
    private Address GetDistributedPeriodProfitsVirtualAddress(Hash schemeId, long period)
    {
        return Context.ConvertVirtualAddressToContractAddress(
            GeneratePeriodVirtualAddressFromHash(schemeId, period));
    }

    private Hash GeneratePeriodVirtualAddressFromHash(Hash schemeId, long period)
    {
        return HashHelper.XorAndCompute(schemeId, HashHelper.ComputeFrom(period));
    }
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

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L71-78)
```csharp
        const int period = 3;
        await creator.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeId = schemeId,
            Amount = amount,
            Period = period,
            Symbol = ProfitContractTestConstants.NativeTokenSymbol,
        });
```
