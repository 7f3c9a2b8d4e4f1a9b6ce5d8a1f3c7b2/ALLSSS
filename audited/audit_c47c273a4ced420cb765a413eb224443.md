# Audit Report

## Title
Missing Validation of Upper Bound Constraints in Fee Coefficient Updates Leads to Fee Undercharging

## Summary
The `AssertPieceUpperBoundsIsInOrder()` validation function fails to ensure the final piece upper bound equals `int.MaxValue`, allowing governance to accidentally or intentionally misconfigure fee coefficients. This causes the fee calculation logic to systematically undercharge users whose resource consumption exceeds the final configured upper bound, resulting in direct economic loss to the protocol treasury.

## Finding Description

The vulnerability exists in the coefficient validation logic that is called during fee coefficient updates. The `AssertPieceUpperBoundsIsInOrder()` function only validates that piece upper bounds are unique and in ascending order, but critically fails to ensure the final bound represents infinity. [1](#0-0) 

When fee coefficients are updated through governance, the validation occurs after modification but before state persistence: [2](#0-1) 

The actual fee calculation logic processes resource consumption in piecewise intervals. The critical flaw occurs in the loop logic - when `totalCount` exceeds the last piece's upper bound, the loop processes all configured pieces and then exits naturally without processing the remaining count: [3](#0-2) 

The break condition at line 52 only triggers if `pieceUpperBound > totalCount`. If the last bound is less than `totalCount`, the loop completes all iterations, but `remainCount` still has a positive value that is never charged.

**Concrete Example**:
- Initial READ fee bounds: `[10, 100, int.MaxValue]` (correct configuration)
- Governance updates piece 3 to bound `1000` instead of `int.MaxValue`
- New bounds: `[10, 100, 1000]`
- User transaction consumes 2000 READ operations:
  - Piece 1 (0-10): charges 10 units
  - Piece 2 (10-100): charges 90 units  
  - Piece 3 (100-1000): charges 900 units
  - Loop exits, remaining 1000 units are **never charged**

This misconfiguration bypasses the intended fee structure where all resource consumption should be charged according to the piecewise polynomial formulas.

**Proof from Existing Tests**:
The vulnerability's existence is inadvertently demonstrated in the existing test suite: [4](#0-3) 

This test shows that with bounds `[10, 100, 1000]` and input `1001`, the output is `909010` - exactly the same as input `1000`. The excess 1 unit beyond the last bound is not charged, proving the systematic undercharging behavior.

## Impact Explanation

**Direct Economic Loss**: The protocol treasury suffers systematic revenue loss from users with high resource consumption. For READ fees using the formula `25/16 * x^2 + x/4` on the final piece, undercharging 1000 excess units results in approximately 1,562,750 fee units of lost revenue per affected transaction.

**Affected Components**:
- All resource token fees (READ, STORAGE, WRITE, TRAFFIC)
- Primary token (ELF) transaction size fees
- All five fee types defined in `FeeTypeEnum`

**Severity Justification**: HIGH - This directly undermines the protocol's economic security model. Resource-intensive operations would be systematically undercharged, creating several risks:
1. Protocol revenue loss accumulating over time
2. Economic incentive misalignment - heavy resource usage becomes artificially cheap
3. Potential enablement of DoS attacks at negligible cost once consumption exceeds the misconfigured bound
4. Difficulty in detection - the undercharging may go unnoticed until significant damage accumulates

The initial coefficient configurations are correct, using `int.MaxValue` as the final bound: [5](#0-4) 

However, the insufficient validation allows these to be degraded through updates.

## Likelihood Explanation

**Required Authority**: The attack requires control of governance organizations that serve as fee controllers: [6](#0-5) 

**Feasibility Assessment**: MEDIUM-HIGH
- Requires governance authority (DeveloperFeeController for resource fees, UserFeeController for TX fees) but not genesis key compromise
- Could occur through **accidental misconfiguration** during legitimate coefficient updates - governance may not realize the final bound must equal `int.MaxValue`
- No cryptographic primitives need to be broken
- No consensus manipulation required
- Attack is a straightforward parameter update via standard governance proposal flow

**Detection Difficulty**: The undercharging may be difficult to detect because:
- Fee calculations appear to work normally for consumption within bounds
- Only high-resource transactions exhibit the flaw
- No error messages or events indicate the missing charges
- Impact accumulates gradually rather than causing immediate system failure

## Recommendation

Add explicit validation in `AssertPieceUpperBoundsIsInOrder()` to ensure the final piece upper bound equals `int.MaxValue`:

```csharp
private void AssertPieceUpperBoundsIsInOrder(
    IReadOnlyCollection<CalculateFeePieceCoefficients> calculateFeePieceCoefficientsList)
{
    // Existing validations...
    Assert(!calculateFeePieceCoefficientsList.GroupBy(i => i.Value[0]).Any(g => g.Count() > 1),
        "Piece upper bounds contains same elements.");

    var pieceUpperBounds = calculateFeePieceCoefficientsList.Select(l => l.Value[0]).ToList();
    var orderedEnumerable = pieceUpperBounds.OrderBy(i => i).ToList();
    for (var i = 0; i < calculateFeePieceCoefficientsList.Count; i++)
        Assert(pieceUpperBounds[i] == orderedEnumerable[i], "Piece upper bounds not in order.");
    
    // NEW VALIDATIONS:
    // Ensure all bounds are positive
    Assert(pieceUpperBounds.All(bound => bound > 0), 
        "All piece upper bounds must be positive.");
    
    // Ensure the final bound represents infinity
    Assert(pieceUpperBounds.Last() == int.MaxValue, 
        "The final piece upper bound must equal int.MaxValue to represent infinity.");
}
```

This ensures the piecewise fee calculation logic will always process all resource consumption, as the final bound will always exceed any realistic `totalCount` value.

## Proof of Concept

The existing test suite inadvertently proves this vulnerability. The test at line 32 of `CalculateFunctionTest.cs` demonstrates that when bounds are `[10, 100, 1000]` and input is `1001`, the output is `909010` - identical to the output for input `1000`. This proves the excess consumption beyond the last bound is not charged.

To explicitly demonstrate the vulnerability, a test could:

1. Initialize fee coefficients with correct bounds including `int.MaxValue`
2. Update coefficients via governance to replace `int.MaxValue` with a finite value (e.g., `1000`)
3. Calculate fees for resource consumption exceeding the new final bound (e.g., `2000`)
4. Verify the calculated fee equals the fee for consumption exactly at the bound (e.g., `1000`)
5. Demonstrate the expected fee for `2000` units should be significantly higher than what was charged

The test would confirm that the insufficient validation in `AssertPieceUpperBoundsIsInOrder()` allows this misconfiguration, and the `CalculateFee()` logic systematically undercharges as described.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L34-72)
```csharp
    private void UpdateCoefficients(UpdateCoefficientsInput input)
    {
        var feeType = input.Coefficients.FeeTokenType;
        var currentAllCoefficients = State.AllCalculateFeeCoefficients.Value;

        // Get coefficients for specific fee type.
        var currentCoefficients = currentAllCoefficients.Value.SingleOrDefault(x =>
            x.FeeTokenType == feeType);
        Assert(currentCoefficients != null, "Specific fee type not existed before.");

        var inputPieceCoefficientsList = input.Coefficients.PieceCoefficientsList;
        // ReSharper disable once PossibleNullReferenceException
        var currentPieceCoefficientList = currentCoefficients.PieceCoefficientsList;

        var inputPieceCount = input.PieceNumbers.Count;
        Assert(inputPieceCount == inputPieceCoefficientsList.Count,
            "Piece numbers not match.");

        foreach (var coefficients in inputPieceCoefficientsList)
            AssertCoefficientsValid(coefficients);

        for (var i = 0; i < inputPieceCount; i++)
        {
            Assert(currentPieceCoefficientList.Count >= input.PieceNumbers[i],
                "Piece number exceeded.");
            var pieceIndex = input.PieceNumbers[i].Sub(1);
            var pieceCoefficients = inputPieceCoefficientsList[i];
            currentPieceCoefficientList[pieceIndex] = pieceCoefficients;
        }

        AssertPieceUpperBoundsIsInOrder(currentPieceCoefficientList);

        State.AllCalculateFeeCoefficients.Value = currentAllCoefficients;

        Context.Fire(new CalculateFeeAlgorithmUpdated
        {
            AllTypeFeeCoefficients = currentAllCoefficients
        });
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L90-101)
```csharp
    private void AssertPieceUpperBoundsIsInOrder(
        IReadOnlyCollection<CalculateFeePieceCoefficients> calculateFeePieceCoefficientsList)
    {
        // No same piece upper bound.
        Assert(!calculateFeePieceCoefficientsList.GroupBy(i => i.Value[0]).Any(g => g.Count() > 1),
            "Piece upper bounds contains same elements.");

        var pieceUpperBounds = calculateFeePieceCoefficientsList.Select(l => l.Value[0]).ToList();
        var orderedEnumerable = pieceUpperBounds.OrderBy(i => i).ToList();
        for (var i = 0; i < calculateFeePieceCoefficientsList.Count; i++)
            Assert(pieceUpperBounds[i] == orderedEnumerable[i], "Piece upper bounds not in order.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L132-170)
```csharp
    private CalculateFeeCoefficients GetReadFeeInitialCoefficient()
    {
        return new CalculateFeeCoefficients
        {
            FeeTokenType = (int)FeeTypeEnum.Read,
            PieceCoefficientsList =
            {
                new CalculateFeePieceCoefficients
                {
                    // Interval [0, 10]: x/8 + 1 / 100000
                    Value =
                    {
                        10,
                        1, 1, 8,
                        0, 1, 100000
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (10, 100]: x/4 
                    Value =
                    {
                        100,
                        1, 1, 4
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (100, +∞): 25 / 16 * x^2 + x / 4
                    Value =
                    {
                        int.MaxValue,
                        2, 25, 16,
                        1, 1, 4
                    }
                }
            }
        };
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

**File:** test/AElf.Kernel.FeeCalculation.Tests/Infrastructure/CalculateFunctionTest.cs (L32-32)
```csharp
    [InlineData(10, 100, 1000, 1001, 909010)] //10 + （100 - 10）* 100 +（1000 -100）* 1000
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L383-397)
```csharp
    private void AssertDeveloperFeeController()
    {
        Assert(State.DeveloperFeeController.Value != null,
            "controller does not initialize, call InitializeAuthorizedController first");

        Assert(Context.Sender == State.DeveloperFeeController.Value.RootController.OwnerAddress, "no permission");
    }

    private void AssertUserFeeController()
    {
        Assert(State.UserFeeController.Value != null,
            "controller does not initialize, call InitializeAuthorizedController first");
        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == State.UserFeeController.Value.RootController.OwnerAddress, "no permission");
    }
```
