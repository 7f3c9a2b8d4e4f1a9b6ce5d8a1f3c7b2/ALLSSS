# Audit Report

## Title
Integer Division Rounding Allows Zero Transaction Fee Bypass

## Summary
The transaction size fee calculation in the MultiToken contract uses integer division without rounding protection, allowing users to bypass fees entirely when paying with alternative tokens that have unfavorable weight ratios. When the converted fee amount rounds down to zero, transactions succeed without charging any fee despite users having sufficient balance, breaking the network's economic model for spam prevention and fee collection.

## Finding Description

The vulnerability exists in the `ChargeSizeFee` method's fee conversion logic. When a user pays transaction size fees using an alternative token instead of the primary token, the fee amount is converted using the token's weight ratio [1](#0-0) .

This conversion uses the `Div()` method, which is implemented as standard integer division that truncates toward zero [2](#0-1) . For small transaction fees or tokens with unfavorable weight ratios (e.g., `AddedTokenWeight=1`, `BaseTokenWeight=10`), the result rounds down to zero. For example: `5 * 1 / 10 = 0`.

Once `txSizeFeeAmount` becomes zero, the billing logic still succeeds because the sufficiency check only verifies that available funds are greater than or equal to the (now zero) fee amount [3](#0-2) .

In `GenerateBill`, when the fee amount is zero and the user has any balance, both `chargeAmount` and `chargeAllowanceAmount` are calculated as zero [4](#0-3) .

Finally, when `ModifyBalance` processes the bill, it skips any amounts that are less than or equal to zero [5](#0-4) , resulting in no actual balance deduction despite the transaction being marked as successfully charged.

The root cause is that `SetSymbolsToPayTxSizeFee` only validates that token weights are positive, not that their ratios prevent rounding issues [6](#0-5) . No minimum fee check exists after the conversion.

## Impact Explanation

This vulnerability breaks the fundamental transaction fee mechanism, which is a critical protocol invariant for:

1. **Spam Prevention**: Transaction size fees prevent network spam by making large-scale attacks economically infeasible. Zero-fee transactions eliminate this protection completely.

2. **Network Revenue**: Fee collection funds network operations and validator rewards. Lost fee revenue impacts the economic sustainability of the network.

3. **Economic Model Integrity**: The fee distribution mechanisms (Treasury, Profit pools) receive no funds from affected transactions, breaking expected economic flows.

**Quantified Impact**: 
- Transactions with size fees < 10 units using a 1:10 token ratio result in zero fees
- Transactions with size fees < 100 units using a 1:100 ratio result in zero fees  
- Users retain 100% of intended fee amounts
- Affects all transactions where `originalFee * AddedTokenWeight < BaseTokenWeight`

## Likelihood Explanation

**Attacker Capabilities**: Any user can exploit this vulnerability by simply selecting an alternative payment token when submitting transactions. No special privileges or technical expertise required.

**Preconditions**:
1. Governance must configure alternative tokens via `SetSymbolsToPayTxSizeFee` (likely already done in production deployments as evidenced by test cases)
2. Token weight ratios must cause rounding (e.g., `AddedTokenWeight=1`, `BaseTokenWeight≥10`)
3. Transaction size fees must be small relative to the weight ratio

**Attack Complexity**: Trivial - the user just selects the favorable token when submitting a transaction. The vulnerable conversion happens automatically in the system.

**Probability**: Medium-High. Alternative tokens are commonly configured to allow fee payment flexibility [7](#0-6) . Once configured, any user can exploit this immediately. The attack requires no additional setup beyond normal transaction submission.

## Recommendation

Implement rounding protection in the fee conversion logic. One approach is to enforce a minimum fee of 1 unit after conversion:

```csharp
txSizeFeeAmount = txSizeFeeAmount.Mul(availableSymbol.AddedTokenWeight)
    .Div(availableSymbol.BaseTokenWeight);
if (txSizeFeeAmount == 0 && input.TransactionSizeFee > 0)
{
    txSizeFeeAmount = 1; // Minimum fee of 1 unit
}
```

Alternatively, validate weight ratios in `SetSymbolsToPayTxSizeFee` to prevent configurations that could cause zero-fee transactions:

```csharp
// Ensure ratio doesn't cause rounding issues for typical fee ranges
var minExpectedFee = 10; // Minimum expected transaction size fee
var convertedMinFee = minExpectedFee.Mul(tokenWeightInfo.AddedTokenWeight)
    .Div(tokenWeightInfo.BaseTokenWeight);
Assert(convertedMinFee > 0, 
    $"Token weight ratio would cause zero fees for small transactions");
```

## Proof of Concept

```csharp
[Fact]
public async Task ZeroFee_IntegerDivision_Bypass_Test()
{
    // Setup: Configure alternative token with unfavorable ratio
    var alternativeToken = "ALT";
    await CreateTokenAsync(DefaultSender, alternativeToken);
    await IssueTokenToDefaultSenderAsync(alternativeToken, 1000);
    
    var sizeFeeSymbolList = new SymbolListToPayTxSizeFee
    {
        SymbolsToPayTxSizeFee =
        {
            new SymbolToPayTxSizeFee
            {
                TokenSymbol = NativeTokenSymbol,
                AddedTokenWeight = 1,
                BaseTokenWeight = 1
            },
            new SymbolToPayTxSizeFee
            {
                TokenSymbol = alternativeToken,
                AddedTokenWeight = 1,
                BaseTokenWeight = 10  // Unfavorable ratio: 1 ALT = 10 ELF
            }
        }
    };
    await TokenContractImplStub.SetSymbolsToPayTxSizeFee.SendAsync(sizeFeeSymbolList);
    
    // Get balance before
    var balanceBefore = await GetBalanceAsync(DefaultSender, alternativeToken);
    balanceBefore.ShouldBe(1000);
    
    // Execute transaction with size fee = 5 (less than BaseTokenWeight=10)
    // Expected converted fee: 5 * 1 / 10 = 0
    var chargeInput = new ChargeTransactionFeesInput
    {
        MethodName = "TestMethod",
        ContractAddress = TokenContractAddress,
        TransactionSizeFee = 5,  // Small fee that rounds to zero
    };
    chargeInput.SymbolsToPayTxSizeFee.AddRange(sizeFeeSymbolList.SymbolsToPayTxSizeFee);
    
    var result = await TokenContractStub.ChargeTransactionFees.SendAsync(chargeInput);
    
    // Vulnerability: Transaction succeeds with no fee charged
    result.Output.Success.ShouldBe(true);
    
    var balanceAfter = await GetBalanceAsync(DefaultSender, alternativeToken);
    
    // Bug: Balance unchanged - zero fee charged despite having sufficient balance
    balanceAfter.ShouldBe(1000);  // No deduction occurred
    // Expected behavior: Should charge at least 1 ALT (or reject if ratio problematic)
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L247-247)
```csharp
            if (amount <= 0) continue;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L403-404)
```csharp
                txSizeFeeAmount = txSizeFeeAmount.Mul(availableSymbol.AddedTokenWeight)
                    .Div(availableSymbol.BaseTokenWeight);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L417-417)
```csharp
        var chargeResult = availableBalance.Add(availableAllowance) >= txSizeFeeAmount;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L519-564)
```csharp
    private void GenerateBill(long txSizeFeeAmount, string symbolToPayTxFee, string symbolChargedForBaseFee,
        long availableBalance, long availableAllowance, ref TransactionFeeBill bill,
        ref TransactionFreeFeeAllowanceBill allowanceBill)
    {
        var chargeAmount = 0L;
        var chargeAllowanceAmount = 0L;
        if (availableBalance.Add(availableAllowance) > txSizeFeeAmount)
        {
            // Allowance > size fee, all allowance
            if (availableAllowance > txSizeFeeAmount)
            {
                chargeAllowanceAmount = txSizeFeeAmount;
            }
            else
            {
                // Allowance is not enough
                chargeAllowanceAmount = availableAllowance;
                chargeAmount = txSizeFeeAmount.Sub(chargeAllowanceAmount);
            }
        }
        else
        {
            chargeAllowanceAmount = availableAllowance;
            chargeAmount = availableBalance;
        }

        if (symbolChargedForBaseFee == symbolToPayTxFee)
        {
            bill.FeesMap[symbolToPayTxFee] =
                bill.FeesMap[symbolToPayTxFee].Add(chargeAmount);
            allowanceBill.FreeFeeAllowancesMap[symbolToPayTxFee] =
                allowanceBill.FreeFeeAllowancesMap[symbolToPayTxFee].Add(chargeAllowanceAmount);
        }
        else
        {
            if (chargeAmount > 0)
            {
                bill.FeesMap.Add(symbolToPayTxFee, chargeAmount);
            }

            if (chargeAllowanceAmount > 0)
            {
                allowanceBill.FreeFeeAllowancesMap.Add(symbolToPayTxFee, chargeAllowanceAmount);
            }
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L634-635)
```csharp
            Assert(tokenWeightInfo.AddedTokenWeight > 0 && tokenWeightInfo.BaseTokenWeight > 0,
                $"symbol:{tokenWeightInfo.TokenSymbol} weight should be greater than 0");
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/ACS2_TokenResourceTests.cs (L103-114)
```csharp
        newSymbolList.SymbolsToPayTxSizeFee.Add(new SymbolToPayTxSizeFee
        {
            TokenSymbol = "ELF",
            AddedTokenWeight = 1,
            BaseTokenWeight = 1
        });
        newSymbolList.SymbolsToPayTxSizeFee.Add(new SymbolToPayTxSizeFee
        {
            TokenSymbol = "CPU",
            AddedTokenWeight = 2,
            BaseTokenWeight = 1
        });
```
