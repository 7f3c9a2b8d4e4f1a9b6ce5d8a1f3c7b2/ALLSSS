### Title
Integer Overflow in Vote Weight Calculation Causing Voting System DoS

### Summary
The `SetVoteWeightProportion()` function only validates that `TimeProportion` and `AmountProportion` are greater than zero, but does not validate upper bounds. Setting `AmountProportion` to `Int32.MaxValue` (2,147,483,647) and `TimeProportion` to 1 causes integer overflow in `GetVotesWeight()` during vote weight calculation, resulting in complete denial-of-service of the voting functionality for all users attempting to vote with realistic token amounts. [1](#0-0) 

### Finding Description

The vulnerability exists in the vote weight calculation mechanism. The `SetVoteWeightProportion()` function enforces only a minimum validation (values > 0) but no maximum bounds. [1](#0-0) 

The `VoteWeightProportion` message defines both fields as `int32`, allowing values up to `Int32.MaxValue` (2,147,483,647). [2](#0-1) 

When users vote via the `Vote()` function, it calls `GetVotesWeight()` to calculate voting power. [3](#0-2) 

The `GetVotesWeight()` function performs the calculation `votesAmount.Mul(AmountProportion).Div(TimeProportion)` at two critical locations. [4](#0-3) [5](#0-4) 

The `.Mul()` operation uses checked arithmetic that throws `OverflowException` on overflow. [6](#0-5) 

**Overflow Calculation:**
- If `AmountProportion = Int32.MaxValue = 2,147,483,647` and `TimeProportion = 1`
- Overflow occurs when: `votesAmount * 2,147,483,647 > Int64.MaxValue`
- Threshold: `votesAmount > 4,294,967,298` base units (≈42.95 tokens with 8 decimals)
- Typical voting amount from tests: 100,000 tokens = 10,000,000,000,000 base units [7](#0-6) 

With typical amounts, the calculation `10,000,000,000,000 * 2,147,483,647 = 21,474,836,470,000,000,000,000` exceeds `Int64.MaxValue` by over 2,000,000x, causing immediate overflow.

### Impact Explanation

**Operational Impact - Complete DoS of Voting System:**

1. **All voting transactions fail**: Any user attempting to vote with more than ~43 tokens will experience transaction failure due to `OverflowException`
2. **Election mechanism broken**: The election contract cannot fulfill its core purpose of allowing users to vote for candidates
3. **Consensus impact**: Since elections determine validator/miner selection, the consensus mechanism's democratic selection process is completely blocked
4. **No recovery path**: Once set, these proportions remain active until governance can pass another proposal to fix them, during which time no voting is possible

**Affected parties:**
- All token holders who wish to participate in governance
- Candidates who rely on votes for election
- The entire network's consensus selection mechanism

**Severity Justification:** HIGH - This causes complete denial of the election system's core functionality with no workaround available to users. The typical voting amounts (100,000+ tokens) far exceed the overflow threshold, making this affect virtually all legitimate voting attempts.

### Likelihood Explanation

**Governance Configuration Scenario:**

**Attacker Capabilities:**
- Requires ability to propose and execute Parliament governance proposals
- This is the default `VoteWeightInterestController` [8](#0-7) 

**Attack Complexity:** LOW
1. Propose `SetVoteWeightProportion` with `TimeProportion=1, AmountProportion=2147483647`
2. These values pass validation (both > 0)
3. Governance approves (may not realize mathematical implications)
4. All subsequent votes with realistic amounts fail

**Feasibility Conditions:**
- Values pass existing validation checks
- Could occur accidentally through poorly-reviewed governance proposal
- No malicious intent required - represents insufficient input validation
- Governance may not perform overflow analysis when reviewing proposals

**Detection Constraints:**
- The misconfiguration is visible on-chain in state
- Impact only becomes apparent when users attempt to vote
- First vote attempt with amount > 42.95 tokens will fail, alerting the system

**Probability Reasoning:** MEDIUM-HIGH
While requiring governance action, the values pass validation and could be proposed/approved without recognizing the overflow implications. This represents a configuration error rather than requiring system compromise.

### Recommendation

**Add maximum bounds validation in `SetVoteWeightProportion()`:**

Add checks to prevent overflow in vote weight calculations. The maximum safe value for `AmountProportion` can be calculated as:
```
MaxSafeAmountProportion = Int64.MaxValue / MaxExpectedVoteAmount
```

For example, if maximum expected vote amount is 1,000,000 tokens (1,000,000 * 10^8 = 10^14 base units):
```
MaxSafeAmountProportion = 9,223,372,036,854,775,807 / 100,000,000,000,000 ≈ 92,233,720
```

**Mitigation Code:**
In `SetVoteWeightProportion()`, add after line 213:

```csharp
Assert(input.TimeProportion > 0 && input.AmountProportion > 0, "invalid input");
// Add maximum bounds to prevent overflow in vote weight calculation
const long maxReasonableVoteAmount = 100_000_000_000_000; // 1M tokens with 8 decimals
const long maxSafeAmountProportion = long.MaxValue / maxReasonableVoteAmount;
Assert(input.AmountProportion <= maxSafeAmountProportion, 
    $"AmountProportion too large, maximum allowed: {maxSafeAmountProportion}");
Assert(input.TimeProportion <= maxSafeAmountProportion,
    $"TimeProportion must not exceed: {maxSafeAmountProportion}");
```

**Test Cases to Add:**
1. Test `SetVoteWeightProportion` rejects `AmountProportion = Int32.MaxValue`
2. Test `SetVoteWeightProportion` accepts reasonable values (e.g., 1-1000)
3. Test `Vote()` succeeds with maximum allowed proportion values and large vote amounts
4. Test `Vote()` with various proportion configurations does not overflow

### Proof of Concept

**Initial State:**
- Election contract deployed and initialized
- Default `VoteWeightProportion` is `TimeProportion=2, AmountProportion=1` [9](#0-8) 

**Attack Steps:**

1. **Governance sets malicious proportions:**
   - Parliament proposes `SetVoteWeightProportion(TimeProportion=1, AmountProportion=2147483647)`
   - Proposal passes (values satisfy `> 0` check)
   - Configuration updated

2. **User attempts to vote:**
   - User calls `Vote()` with amount = 100,000 tokens (10,000,000,000,000 base units)
   - Function reaches line 443: `AddBeneficiaryToVoter(GetVotesWeight(input.Amount, lockSeconds), ...)`
   - `GetVotesWeight()` calculates at line 585: `votesAmount.Mul(2147483647).Div(1)`
   - Multiplication: `10,000,000,000,000 * 2,147,483,647` attempts to produce `21,474,836,470,000,000,000,000`
   - This exceeds `Int64.MaxValue = 9,223,372,036,854,775,807`
   - `SafeMath.Mul()` throws `OverflowException`
   - Transaction reverts

**Expected Result:** Vote transaction succeeds and user's vote is recorded

**Actual Result:** Transaction fails with `OverflowException` - "Arithmetic operation resulted in an overflow"

**Success Condition for Attack:** All users are unable to vote with realistic amounts (>42.95 tokens), completely disabling the election system's functionality.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L210-216)
```csharp
    public override Empty SetVoteWeightProportion(VoteWeightProportion input)
    {
        AssertPerformedByVoteWeightInterestController();
        Assert(input.TimeProportion > 0 && input.AmountProportion > 0, "invalid input");
        State.VoteWeightProportion.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L261-268)
```csharp
    private VoteWeightProportion GetDefaultVoteWeightProportion()
    {
        return new VoteWeightProportion
        {
            TimeProportion = 2,
            AmountProportion = 1
        };
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L393-400)
```csharp
    private AuthorityInfo GetDefaultVoteWeightInterestController()
    {
        return new AuthorityInfo
        {
            ContractAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName),
            OwnerAddress = GetParliamentDefaultAddress()
        };
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L443-443)
```csharp
        AddBeneficiaryToVoter(GetVotesWeight(input.Amount, lockSeconds), lockSeconds, voteId);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L584-585)
```csharp
            return ((long)(Pow(initBase, (uint)lockDays) * votesAmount)).Add(votesAmount
                .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L590-591)
```csharp
        return ((long)(Pow(maxInterestBase, (uint)lockDays) * votesAmount)).Add(votesAmount
            .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
```

**File:** protobuf/election_contract.proto (L478-483)
```text
message VoteWeightProportion {
    // The weight of lock time.
    int32 time_proportion = 1;
    // The weight of the votes cast.
    int32 amount_proportion = 2;
}
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L79-85)
```csharp
    public static long Mul(this long a, long b)
    {
        checked
        {
            return a * b;
        }
    }
```

**File:** test/AElf.Contracts.Election.Tests/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
