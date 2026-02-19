# Audit Report

## Title
Transaction Fee Threshold Gaming Through Batch Splitting Enables Quadratic Fee Avoidance

## Summary
The TRAFFIC fee calculation mechanism applies piecewise polynomial pricing independently to each transaction based on its size. The system uses a threshold at 1,000,000 bytes where fees transition from linear to quadratic scaling. Users can exploit this design by splitting large transactions into multiple smaller transactions that stay under the threshold, avoiding quadratic fee scaling and significantly reducing total fees paid.

## Finding Description

The vulnerability exists in the architectural design of the TRAFFIC fee calculation system. The fee structure uses a piecewise polynomial function with two distinct pricing tiers defined in `GetTrafficFeeInitialCoefficient()`: a linear tier for transactions up to 1,000,000 bytes and a quadratic tier for larger transactions. [1](#0-0) 

The critical flaw is that fee calculation is performed independently for each transaction. The `TrafficFeeProvider` retrieves only the current transaction's size as input for fee calculation. [2](#0-1) 

The `CalculateFee` method then applies the piecewise polynomial function to this single transaction's size, with no consideration of cumulative traffic consumption from the same user or contract. [3](#0-2) 

While block-level accumulation exists through `ResourceTokenChargedLogEventProcessor`, this accumulation occurs AFTER fees are calculated and is used solely for billing and donation purposes, not for determining which pricing tier applies to subsequent transactions. [4](#0-3) 

**Attack Scenario:**
An attacker with a 2,000,000 byte operation splits it into two 1,000,000 byte transactions. Each transaction is evaluated independently against the linear pricing tier (x/64 + 1/10000), avoiding the quadratic tier (x/64 + x²/20000) that would apply to the combined operation. This is a fundamental property of piecewise polynomials: f(2x) ≠ 2·f(x) when different polynomial degrees apply to different ranges.

## Impact Explanation

**Economic Impact:**
- Direct protocol revenue loss: Users avoid paying the intended quadratic fees for large operations
- Fee avoidance scales with transaction size: larger operations see greater percentage savings
- Sophisticated users gain systematic economic advantage over users who submit naturally large transactions

**Protocol Damage:**
- Undermines congestion control mechanism: The quadratic pricing is specifically designed to discourage large transactions and manage network resources. When easily bypassed, this mechanism becomes ineffective.
- Incentivizes transaction spam: Instead of consolidating operations into efficient large transactions, users are economically incentivized to split into many small transactions, potentially degrading network efficiency.
- Breaks progressive fee model: The intended economic design of progressive scaling to manage network load is circumvented.

**Severity: HIGH** - This represents a fundamental break in the protocol's economic mechanism with direct financial impact and no feasible detection or prevention in the current design.

## Likelihood Explanation

**Attacker Capabilities:** Any user can submit multiple transactions. No special permissions, privileged access, or technical sophistication required beyond basic transaction submission.

**Technical Feasibility:** 
- Many smart contract operations can be meaningfully split: batch token transfers can become individual transfers, multiple contract calls can be separated, large data operations can be chunked.
- While some operations are atomic and cannot be split, a significant class of operations is splittable.
- Standard transaction submission mechanisms already support submitting multiple transactions.

**Detection Impossibility:**
- No protocol-level mechanism exists to distinguish "malicious splitting" from legitimate separate operations
- No state is maintained to correlate potentially related transactions
- Users submitting separate legitimate transactions vs. intentionally split transactions are indistinguishable

**Economic Incentive:** The potential fee savings are substantial enough to justify minimal effort in splitting transactions, especially for high-value or high-frequency operations.

**Likelihood: HIGH** - The combination of trivial execution, clear economic benefit, and zero detection creates strong likelihood of exploitation.

## Recommendation

Implement cumulative traffic consumption tracking with one of these approaches:

**Option 1: Block-level accumulation for fee calculation**
Track cumulative transaction sizes per address within a block, applying the piecewise polynomial to the cumulative total rather than individual transactions.

**Option 2: Time-windowed accumulation**
Maintain a rolling window (e.g., last N blocks) of transaction sizes per address, calculating fees based on cumulative consumption within the window.

**Option 3: Fee model redesign**
Replace the piecewise polynomial with a continuous function (e.g., exponential) that doesn't create exploitable threshold boundaries, or use per-byte linear pricing throughout.

**Implementation consideration:** Any accumulation mechanism must balance the security benefit against the state storage and computational overhead of tracking per-address consumption.

## Proof of Concept

```csharp
// Test demonstrating fee avoidance through transaction splitting
public async Task Test_FeeAvoidance_ThroughSplitting()
{
    // Setup: Fund contract with TRAFFIC tokens
    await AdvanceResourceToken(new List<string>(), 10_000_00000000);
    
    // Scenario 1: Submit one large 2MB transaction
    var largeTransaction = new TrafficConsumingMethodInput
    {
        Blob = ByteString.CopyFrom(new byte[2000000]) // 2MB
    };
    
    var balanceBefore1 = await GetTrafficBalance(TestContractAddress);
    await TestContractStub.TrafficConsumingMethod.SendAsync(largeTransaction);
    await MineBlock(); // Trigger resource fee charging
    var balanceAfter1 = await GetTrafficBalance(TestContractAddress);
    var costLarge = balanceBefore1 - balanceAfter1;
    
    // Scenario 2: Submit two 1MB transactions (split)
    var smallTransaction1 = new TrafficConsumingMethodInput
    {
        Blob = ByteString.CopyFrom(new byte[1000000]) // 1MB
    };
    var smallTransaction2 = new TrafficConsumingMethodInput
    {
        Blob = ByteString.CopyFrom(new byte[1000000]) // 1MB
    };
    
    var balanceBefore2 = await GetTrafficBalance(TestContractAddress);
    await TestContractStub.TrafficConsumingMethod.SendAsync(smallTransaction1);
    await TestContractStub.TrafficConsumingMethod.SendAsync(smallTransaction2);
    await MineBlock(); // Trigger resource fee charging
    var balanceAfter2 = await GetTrafficBalance(TestContractAddress);
    var costSplit = balanceBefore2 - balanceAfter2;
    
    // Verify: Split transactions cost significantly less
    costLarge.ShouldBeGreaterThan(costSplit);
    var savings = costLarge - costSplit;
    var savingsPercentage = (savings * 100) / costLarge;
    savingsPercentage.ShouldBeGreaterThan(50); // >50% savings from splitting
}
```

## Notes

This vulnerability represents a fundamental flaw in the fee mechanism design rather than an implementation bug. The piecewise polynomial coefficient structure itself, combined with per-transaction evaluation, creates the exploitable threshold effect. While the specific fee amounts may vary based on precision calculations, the core principle remains: splitting transactions to stay within lower pricing tiers provides systematic economic advantage, undermining the protocol's intended congestion control mechanism.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L243-272)
```csharp
    private CalculateFeeCoefficients GetTrafficFeeInitialCoefficient()
    {
        return new CalculateFeeCoefficients
        {
            FeeTokenType = (int)FeeTypeEnum.Traffic,
            PieceCoefficientsList =
            {
                new CalculateFeePieceCoefficients
                {
                    // Interval [0, 1000000]: x / 64 + 1 / 10000
                    Value =
                    {
                        1000000,
                        1, 1, 64,
                        0, 1, 10000
                    }
                },
                new CalculateFeePieceCoefficients
                {
                    // Interval (1000000, +∞): x / 64 + x^2 / 20000
                    Value =
                    {
                        int.MaxValue,
                        1, 1, 64,
                        2, 1, 20000
                    }
                }
            }
        };
    }
```

**File:** src/AElf.Kernel.FeeCalculation/Infrastructure/TrafficFeeProvider.cs (L15-18)
```csharp
    protected override int GetCalculateCount(ITransactionContext transactionContext)
    {
        return transactionContext.Transaction.Size();
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

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/ResourceTokenChargedLogEventProcessor.cs (L48-96)
```csharp
    public override async Task ProcessAsync(Block block, Dictionary<TransactionResult, List<LogEvent>> logEventsMap)
    {
        var blockHash = block.GetHash();
        var blockHeight = block.Height;
        var totalResourceTokensMaps = new TotalResourceTokensMaps
        {
            BlockHash = blockHash,
            BlockHeight = blockHeight
        };

        foreach (var logEvent in logEventsMap.Values.SelectMany(logEvents => logEvents))
        {
            var eventData = new ResourceTokenCharged();
            eventData.MergeFrom(logEvent);
            if (eventData.Symbol == null || eventData.Amount == 0)
                continue;

            if (totalResourceTokensMaps.Value.Any(b => b.ContractAddress == eventData.ContractAddress))
            {
                var oldBill =
                    totalResourceTokensMaps.Value.First(b => b.ContractAddress == eventData.ContractAddress);
                if (oldBill.TokensMap.Value.ContainsKey(eventData.Symbol))
                    oldBill.TokensMap.Value[eventData.Symbol] += eventData.Amount;
                else
                    oldBill.TokensMap.Value.Add(eventData.Symbol, eventData.Amount);
            }
            else
            {
                var contractTotalResourceTokens = new ContractTotalResourceTokens
                {
                    ContractAddress = eventData.ContractAddress,
                    TokensMap = new TotalResourceTokensMap
                    {
                        Value =
                        {
                            { eventData.Symbol, eventData.Amount }
                        }
                    }
                };
                totalResourceTokensMaps.Value.Add(contractTotalResourceTokens);
            }
        }

        await _totalTotalResourceTokensMapsProvider.SetTotalResourceTokensMapsAsync(new BlockIndex
        {
            BlockHash = blockHash,
            BlockHeight = blockHeight
        }, totalResourceTokensMaps);
    }
```
