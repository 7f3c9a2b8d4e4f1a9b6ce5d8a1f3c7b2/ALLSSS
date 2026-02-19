I'll investigate this potential division by zero vulnerability in the AEDPoS consensus contract.
> Searching codebase... [1](#0-0) [2](#0-1)

### Citations

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L50-56)
```csharp
        Should.Throw<DivideByZeroException>(() => { number1.Div(0); });
        Should.Throw<DivideByZeroException>(() => { number2.Div(0); });

        number1.Div(2).ShouldBe(3UL);
        number2.Div(-2).ShouldBe(-3L);
        Should.Throw<DivideByZeroException>(() => { 5.Div(0); });
        Should.Throw<DivideByZeroException>(() => { (-5).Div(0); });
```
