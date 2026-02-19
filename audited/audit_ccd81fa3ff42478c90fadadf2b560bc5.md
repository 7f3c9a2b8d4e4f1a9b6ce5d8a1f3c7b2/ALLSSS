### Title
Integer Division Order Causes Miner Count Underestimation During Auto-Increase Periods

### Summary
The `GetAutoIncreasedMinersCount()` and `GetMinersCount()` functions calculate the time-based miner count increase using integer arithmetic in the order `(seconds / interval) * 2`, which loses precision compared to the mathematically equivalent `(seconds * 2) / interval`. This systematic calculation error causes the miner count to be underestimated by 1 during the first half of each `MinerIncreaseInterval` period, temporarily reducing consensus decentralization.

### Finding Description

The vulnerability exists in two locations that use identical calculation logic:

**Location 1:** [1](#0-0) 

**Location 2:** [2](#0-1) 

**Root Cause:**
The calculation computes `(elapsed_seconds / MinerIncreaseInterval) * 2` where all values are integers. The `Div` and `Mul` extension methods perform standard C# integer division and multiplication [3](#0-2) , which means integer division truncates the fractional part before multiplication occurs.

**Why Protections Fail:**
No validation exists to detect this precision loss. The calculation appears correct syntactically but produces incorrect results due to operation ordering.

**Concrete Example:**
With the default `MinerIncreaseInterval` of 31536000 seconds (1 year) [4](#0-3) :

- At 6 months elapsed (15,768,000 seconds):
  - Current: `(15768000 / 31536000) * 2 = 0 * 2 = 0` additional miners
  - Correct: `(15768000 * 2) / 31536000 = 1` additional miner
  - **Difference: 1 miner lost**

- At 18 months elapsed (47,304,000 seconds):
  - Current: `(47304000 / 31536000) * 2 = 1 * 2 = 2` additional miners
  - Correct: `(47304000 * 2) / 31536000 = 3` additional miners
  - **Difference: 1 miner lost**

**Execution Path:**
1. `GetAutoIncreasedMinersCount()` is called by the public view method `GetMaximumMinersCount()` [5](#0-4) 
2. `GetMinersCount(Round input)` is called during consensus operations to update the Election contract's miner count [6](#0-5)  and [7](#0-6) 
3. The underestimated count propagates to the Election contract which uses it to determine how many top candidates become miners

### Impact Explanation

**Harm:**
During the first half of each `MinerIncreaseInterval` period, the system operates with 1 fewer miner than intended by design. Starting from the base count of 17 miners [8](#0-7) , the auto-increase mechanism adds 2 miners per interval but the calculation error delays this increase.

**Quantified Impact:**
- **Decentralization reduction:** Approximately 5.5% fewer miners during affected periods (e.g., 17 instead of 18, or 19 instead of 20)
- **Duration:** Affects roughly 50% of all time periods (the first half of each interval)
- **Consensus participation:** One eligible candidate is excluded from block production and rewards during these periods

**Who is Affected:**
- The blockchain network experiences slightly reduced decentralization
- One candidate who should be elected misses out on mining opportunities and rewards
- Users experience marginally less distributed consensus

**Severity Justification (LOW):**
- Maximum impact is 1 miner difference at any time
- Does not break consensus mechanism or cause system failure
- Does not result in fund theft or unauthorized access
- Self-corrects at the halfway point of each interval
- Temporary reduction in decentralization rather than security compromise

### Likelihood Explanation

**Occurrence Probability:**
This is not an exploitable vulnerability but a deterministic calculation error that occurs automatically.

**Conditions:**
- Happens systematically during the first 50% of every `MinerIncreaseInterval` period
- No special preconditions required
- Affects all chains using this consensus implementation
- Cannot be prevented or triggered by any party

**Complexity:**
- Zero complexity - purely mathematical error
- Always active when elapsed time falls within affected ranges
- Observable through public view methods

**Detection:**
The error is difficult to detect operationally because:
- The miner count appears to increase correctly, just with delayed timing
- The difference of 1 miner is small relative to total count
- No error conditions or failed transactions occur

### Recommendation

**Code-Level Mitigation:**
Change the calculation order to multiply before dividing. Replace:

```csharp
(int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
    .Div(State.MinerIncreaseInterval.Value).Mul(2)
```

With:

```csharp
(int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
    .Mul(2).Div(State.MinerIncreaseInterval.Value)
```

**Apply this fix in both locations:**
1. `GetAutoIncreasedMinersCount()` [9](#0-8) 
2. `GetMinersCount()` [10](#0-9) 

**Overflow Safety:**
The multiplication of `seconds * 2` is safe because:
- Maximum realistic elapsed time is hundreds of years
- C# `long` max value is 9,223,372,036,854,775,807
- Even 1000 years (31,536,000,000 seconds) * 2 = 63,072,000,000, well below limits
- The `Mul` operation uses checked arithmetic to detect overflows [11](#0-10) 

**Test Cases:**
Add unit tests verifying:
1. Miner count at various fractional intervals (0.25, 0.5, 0.75, 1.0, 1.5, etc.)
2. Expected count matches formula: `SupposedMinersCount + ((elapsed_seconds * 2) / interval)`
3. Compare old vs new calculation results across time ranges
4. Verify the test expectation [12](#0-11)  produces correct results with the fix

### Proof of Concept

**Initial State:**
- Blockchain start timestamp: T₀
- MinerIncreaseInterval: 31,536,000 seconds (1 year)
- SupposedMinersCount: 17

**Test Sequence:**

1. **At T₀ + 6 months (15,768,000 seconds):**
   - Call `GetMaximumMinersCount()`
   - Current result: 17 + 0 = 17 miners
   - Expected result: 17 + 1 = 18 miners
   - **Discrepancy: 1 miner**

2. **At T₀ + 9 months (23,652,000 seconds):**
   - Call `GetMaximumMinersCount()`
   - Current result: 17 + 0 = 17 miners
   - Expected result: 17 + 1 = 18 miners
   - **Discrepancy: 1 miner**

3. **At T₀ + 12 months (31,536,000 seconds):**
   - Call `GetMaximumMinersCount()`
   - Current result: 17 + 2 = 19 miners
   - Expected result: 17 + 2 = 19 miners
   - **Correct at interval boundary**

4. **At T₀ + 18 months (47,304,000 seconds):**
   - Call `GetMaximumMinersCount()`
   - Current result: 17 + 2 = 19 miners
   - Expected result: 17 + 3 = 20 miners
   - **Discrepancy: 1 miner**

**Success Condition:**
After applying the fix (multiply before divide), all test cases above should produce the expected results, eliminating the 1-miner undercount during fractional intervals.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L72-78)
```csharp
    public override Int32Value GetMaximumMinersCount(Empty input)
    {
        return new Int32Value
        {
            Value = Math.Min(GetAutoIncreasedMinersCount(), State.MaximumMinersCount.Value)
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L14-14)
```csharp
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-61)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L128-135)
```csharp
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/MinersCountTest.cs (L118-118)
```csharp
            Assert.Equal(AEDPoSContractTestConstants.SupposedMinersCount.Add(termCount.Mul(2)), minerCount);
```
