### Title
Write Fee Discontinuity Exploitation via Transaction Splitting

### Summary
The `GetWriteFeeInitialCoefficient()` function defines piecewise fee calculation formulas with sharp discontinuities at boundaries x=10 and x=100, where marginal fee rates double and increase by 7x respectively. Users can exploit these discontinuities by splitting operations across multiple transactions to stay within lower-cost intervals, resulting in 25-86% fee savings compared to single-transaction execution.

### Finding Description

The write fee calculation is defined in [1](#0-0) 

Three intervals with different formulas create exploitable discontinuities:
- Interval [0, 10]: f₁(x) = x/8 + 1/10000 (marginal rate: 0.125 per write)
- Interval (10, 100]: f₂(x) = x/4 (marginal rate: 0.25 per write - **2x increase**)
- Interval (100, ∞): f₃(x) = x/4 + x²*25/16 (marginal rate starts at ~1.8125 for first write - **7.25x increase**)

The fee calculation processes write counts piecewise as shown in [2](#0-1) , where each interval's formula is applied to the portion of writes falling within that range.

The write count comes from transaction state writes: [3](#0-2) 

Users control write counts through batch operations like [4](#0-3) , which loops through operations and generates approximately one write per operation.

**No protections exist** against transaction splitting to exploit these discontinuities. The fee calculation is deterministic with no minimum fees, flat fees, or anti-splitting mechanisms.

### Impact Explanation

**Direct Fund Impact:**
- For 20 writes: Single transaction costs 375,010,000 WRITE tokens; split into 2×10 costs 250,020,000 - **savings of 124,990,000 (33%)**
- For 110 writes: Single transaction costs 18,250,010,000 WRITE tokens; split into 100+10 costs 2,500,020,000 - **savings of 15,749,990,000 (86%)**

Even accounting for additional Tx fees [5](#0-4)  with formula [6](#0-5) , the net savings remain substantial (approximately 25% for 20 writes, 85% for 110 writes).

This reduces protocol fee revenue, creating unfair advantages for sophisticated users who understand the fee structure, and violates the principle of proportional fee charging based on resource consumption.

### Likelihood Explanation

**Reachable Entry Point:** Any user creating transactions with state writes can trigger this fee calculation path.

**Feasible Preconditions:** User must have operations that can be split into multiple transactions. Common examples include:
- Batch approvals via `BatchApprove` (can approve 20 spenders in one tx or 10 spenders in two tx)
- Multiple token transfers
- Batch state updates

**Execution Practicality:** Highly practical - users simply structure their batch operations to stay below boundaries. For `BatchApprove`, instead of calling with 20 approvals, call twice with 10 approvals each.

**Economic Rationality:** Extremely attractive - savings of 25-86% far exceed the minimal additional Tx fee overhead (~62,510,000 per extra transaction for typical sizes). The exploit becomes more profitable as write counts increase toward boundaries.

**Detection Constraints:** Difficult to detect as legitimate usage - splitting transactions is normal behavior and indistinguishable from genuine operational needs.

### Recommendation

**Immediate Fix:** Redesign fee formulas to ensure continuity at boundaries. Replace piecewise linear/polynomial functions with smooth curves, or use progressive rate structures where only incremental writes pay higher rates (like progressive taxation):

```
For totalWrites = 20:
- Writes 1-10 pay rate₁ each
- Writes 11-20 pay rate₂ each
Total = (10 × rate₁) + (10 × rate₂)
```

This ensures splitting provides no advantage since each write's cost is independent of transaction boundaries.

**Additional Safeguards:**
1. Add minimum flat fee per transaction to discourage excessive splitting
2. Implement exponential penalty for users making many small transactions in short timeframes
3. Add continuity validation in [7](#0-6)  to verify formula values match at boundaries during coefficient updates

**Test Cases:**
- Verify identical total fees for N writes whether executed as 1 transaction or M transactions
- Test boundary conditions: 10, 11, 100, 101 writes in various split configurations
- Ensure marginal cost per write remains monotonically increasing

### Proof of Concept

**Initial State:** User wants to approve 20 spenders for token transfers

**Attack Sequence:**

1. **Legitimate Approach (Higher Cost):**
   - Call `BatchApprove` with 20 approvals
   - Results in ~20 state writes
   - Write fee calculation: f₁(10) + f₂(10) = (10/8 + 1/10000) + (10/4) = 375,010,000 WRITE tokens
   - Tx fee (assuming 1000 bytes): ~125,010,000
   - **Total: 500,020,000 tokens**

2. **Exploit Approach (Lower Cost):**
   - Call `BatchApprove` with 10 approvals (Transaction 1)
   - Call `BatchApprove` with 10 approvals (Transaction 2)
   - Each results in ~10 state writes
   - Write fee per transaction: f₁(10) = 125,010,000 WRITE tokens
   - Total write fees: 250,020,000
   - Tx fee per transaction (assuming 500 bytes each): ~62,510,000
   - Total Tx fees: 125,020,000
   - **Total: 375,040,000 tokens**

**Result:** Attacker saves 124,980,000 tokens (25% reduction) by exploiting the discontinuity at x=10.

**Success Condition:** The split-transaction approach costs less than the single-transaction approach, proving the discontinuity is exploitable for economic gain.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L74-88)
```csharp
    private void AssertCoefficientsValid(CalculateFeePieceCoefficients coefficients)
    {
        // Assert the count should be (3n + 1), n >= 1.
        var count = coefficients.Value.Count;
        Assert(count > 0 && (count - 1) % 3 == 0, "Coefficients count should be (3n + 1), n >= 1.");

        // Assert every unit. one [(B / C) * x ^ A] means one unit.
        for (var i = 1; i < count; i += 3)
        {
            var power = coefficients.Value[i];
            var divisor = coefficients.Value[i + 1];
            var dividend = coefficients.Value[i + 2];
            Assert(power >= 0 && divisor >= 0 && dividend > 0, "Invalid coefficient.");
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L203-241)
```csharp
    private CalculateFeeCoefficients GetWriteFeeInitialCoefficient()
    {
        return new CalculateFeeCoefficients
        {
            FeeTokenType = (int)FeeTypeEnum.Write,
            PieceCoefficientsList =
            {
                new CalculateFeePieceCoefficients
                {
                    // Interval [0, 10]: x / 8 + 1 / 10000
                    Value =
                    {
                        10,
                        1, 1, 8,
                        0, 1, 10000
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (10, 100]: x / 4
                    Value =
                    {
                        100,
                        1, 1, 4
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (100, +∞): x / 4 + x^2 * 25 / 16
                    Value =
                    {
                        int.MaxValue,
                        1, 1, 4,
                        2, 25, 16
                    }
                }
            }
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L283-289)
```csharp
                    // Interval [0, 1000000]: x / 800 + 1 / 10000
                    Value =
                    {
                        1000000,
                        1, 1, 800,
                        0, 1, 10000
                    }
```

**File:** src/AElf.Kernel.FeeCalculation/Infrastructure/CalculateFunction.cs (L34-58)
```csharp
    public long CalculateFee(int totalCount)
    {
        if (CalculateFeeCoefficients.PieceCoefficientsList.Count != _currentCalculateFunctions.Count)
            throw new ArgumentOutOfRangeException(nameof(_currentCalculateFunctions),
                "Coefficients count not match.");

        var remainCount = totalCount;
        var result = 0L;
        var pieceStart = 0;
        for (var i = 0; i < _currentCalculateFunctions.Count; i++)
        {
            var function = _currentCalculateFunctions[i];
            var pieceCoefficient = CalculateFeeCoefficients.PieceCoefficientsList[i].Value;
            var pieceUpperBound = pieceCoefficient[0];
            var interval = pieceUpperBound - pieceStart;
            pieceStart = pieceUpperBound;
            var count = Math.Min(interval, remainCount);
            result += function(count);
            if (pieceUpperBound > totalCount) break;

            remainCount -= interval;
        }

        return result;
    }
```

**File:** src/AElf.Kernel.FeeCalculation/Infrastructure/WriteFeeProvider.cs (L15-18)
```csharp
    protected override int GetCalculateCount(ITransactionContext transactionContext)
    {
        return transactionContext.Trace.StateSet.Writes.Count;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L283-298)
```csharp
    public override Empty BatchApprove(BatchApproveInput input)
    {
        Assert(input != null && input.Value != null && input.Value.Count > 0, "Invalid input .");
        Assert(input.Value.Count <= GetMaxBatchApproveCount(), "Exceeds the max batch approve count.");
        foreach (var approve in input.Value)
        {
            AssertValidInputAddress(approve.Spender);
            var actualSymbol = GetActualTokenSymbol(approve.Symbol);
            AssertValidApproveTokenAndAmount(actualSymbol, approve.Amount);
        }
        var approveInputList = input.Value.GroupBy(approve => approve.Symbol + approve.Spender, approve => approve)
            .Select(approve => approve.Last()).ToList();
        foreach (var approve in approveInputList)
            Approve(approve.Spender, approve.Symbol, approve.Amount);
        return new Empty();
    }
```

**File:** src/AElf.Kernel.FeeCalculation/Infrastructure/TxFeeProvider.cs (L13-16)
```csharp
    protected override int GetCalculateCount(ITransactionContext transactionContext)
    {
        return transactionContext.Transaction.Size();
    }
```
