### Title
Fee-Free CheckThreshold Method Enables Resource Exhaustion DOS Attack via Unbounded State Reads

### Summary
The `CheckThreshold` method in the MultiToken contract is marked as fee-free but lacks input validation on the size of the `symbol_to_threshold` map, allowing attackers to craft transactions that trigger thousands of expensive state reads at zero cost. This creates a denial-of-service vector targeting the transaction validation layer, where nodes must pre-execute these resource-intensive transactions before rejection, enabling sustained resource exhaustion across the network.

### Finding Description [1](#0-0) 

The `CheckThreshold` method is explicitly marked as `IsSizeFeeFree = true`, exempting it from both method fees and transaction size fees. This fee-free designation was intended for legitimate pre-execution validation use by the `MethodCallingThresholdPreExecutionPlugin`. [2](#0-1) 

The implementation iterates through every entry in the `input.SymbolToThreshold` map, calling `GetBalance` (a state read operation) for each symbol. When `IsCheckAllowance` is true, additional state reads occur for allowance checks. Critically, there is **no validation** on the map size - an attacker can include thousands of symbols limited only by the 5MB transaction size constraint. [3](#0-2) 

The protobuf definition shows `symbol_to_threshold` as an unbounded map with no size constraints, enabling arbitrarily large inputs. [4](#0-3) 

During transaction pool validation, `TransactionExecutionValidationProvider` pre-executes all transactions to validate they will succeed. Even though a malicious `CheckThreshold` transaction would ultimately fail the assertion and be rejected, the pre-execution itself consumes significant validator resources by performing all the state reads. This creates the DOS vector: attackers spam the mempool with such transactions, forcing every validator node to repeatedly execute expensive state reads during validation.

**Why Existing Protections Are Insufficient**: [5](#0-4) 

The 5MB transaction size limit caps the number of symbols but doesn't prevent the attack - an attacker can still fit thousands of symbol entries within this limit, each triggering expensive state operations. Block transaction limits (512 default) only throttle throughput but don't prevent resource exhaustion at the validation layer where the DOS occurs.

### Impact Explanation

**Operational DOS of Transaction Validation Infrastructure**:
- Attackers can force validator nodes to perform thousands of `GetBalance` state reads per transaction at zero cost
- Multiple concurrent attackers spamming such transactions can exhaust validation resources network-wide
- Legitimate transactions experience delayed validation and inclusion as nodes process malicious payloads
- Network throughput degrades as validators spend computational resources on validation rather than consensus

**Quantified Impact**:
- A single transaction with ~10,000 symbols (achievable under 5MB limit) triggers 10,000+ state reads
- At zero cost, an attacker can submit hundreds of such transactions to the mempool
- With transaction execution validation enabled (default), every node pre-executes these before rejection
- Sustained attack could significantly degrade network transaction processing capacity

**Affected Parties**:
- All validator nodes (forced to execute expensive validation)
- Network users (delayed transaction confirmation times)
- DApp operators (degraded service quality)

**Severity Justification: Medium** - Does not compromise funds, consensus integrity, or governance, but enables operational disruption of transaction processing at zero attacker cost.

### Likelihood Explanation

**Attacker Capabilities**: Minimal
- No special permissions or tokens required
- Only needs ability to submit transactions to the network
- Zero financial cost due to fee-free status
- Standard transaction construction tools sufficient

**Attack Complexity**: Low
- Straightforward to craft large `CheckThresholdInput` with many symbols
- No timing, state manipulation, or complex preconditions required
- Can be automated for sustained attacks

**Feasibility Conditions**: Highly Feasible
- `CheckThreshold` is a public method callable by anyone
- No rate limiting or caller restrictions
- Fee-free status removes economic disincentive
- Transaction size limit (5MB) is generous enough for significant impact

**Detection Constraints**: Visible but Difficult to Prevent
- Attacks would be visible in mempool and logs
- However, distinguishing malicious from legitimate threshold checks is challenging
- Miners can manually filter but lack protocol-level enforcement
- No automated DOS protection for fee-free methods

**Probability Assessment**: High - The combination of zero cost, no input validation, and expensive operations per symbol makes exploitation both practical and economically rational for adversaries seeking to disrupt the network.

### Recommendation

**1. Add Input Size Validation**

In `TokenContract_Actions.cs`, add explicit validation at the start of `CheckThreshold`:

```csharp
public override Empty CheckThreshold(CheckThresholdInput input)
{
    AssertValidInputAddress(input.Sender);
    
    // NEW: Validate maximum symbols to prevent DOS
    const int MaxSymbolsPerCheck = 10; // Adjust based on legitimate use cases
    Assert(input.SymbolToThreshold.Count <= MaxSymbolsPerCheck, 
        $"Symbol threshold map exceeds maximum allowed size of {MaxSymbolsPerCheck}");
    
    // ... rest of implementation
}
```

**2. Consider Resource Token Charging**

Even for fee-free methods, charge resource tokens proportional to the number of state reads to create economic disincentive for large inputs.

**3. Add Monitoring and Rate Limiting**

Implement mempool-level detection for suspicious patterns of `CheckThreshold` transactions with large inputs and apply rate limiting per sender address.

**4. Test Cases**

Add regression tests:
- Test that `CheckThreshold` rejects inputs exceeding the maximum symbol count
- Test performance with maximum allowed symbols vs. rejected oversized inputs
- Test that legitimate `MethodCallingThresholdPreExecutionPlugin` usage stays within limits

### Proof of Concept

**Initial State**:
- Token contract deployed and operational
- Attacker address with no special permissions or token balances

**Attack Steps**:

1. **Craft Malicious Transaction**:
```
CheckThresholdInput:
  sender: <attacker_address>
  symbol_to_threshold: {
    "SYM0001": 1,
    "SYM0002": 1,
    "SYM0003": 1,
    ... (10,000 entries)
  }
  is_check_allowance: true
```

2. **Submit to Network**:
    - Transaction size < 5MB (passes size validation)
    - No transaction fees charged (IsSizeFeeFree = true)
    - Enters mempool successfully

3. **Validation Phase**:
    - Each validator node's `TransactionExecutionValidationProvider` pre-executes the transaction
    - 10,000 `GetBalance` state reads execute
    - 10,000 allowance state reads execute
    - Transaction fails final assertion and is rejected
    - But validation resources already consumed

4. **Repeat Attack**:
    - Submit 100+ such transactions concurrently
    - Each validator must validate all transactions
    - Total: 1,000,000+ state reads per validator for zero attacker cost

**Expected vs Actual Result**:
- **Expected**: Fee-free methods should have input validation to prevent abuse
- **Actual**: No validation exists; unbounded input triggers expensive operations at zero cost

**Success Condition**: Validator nodes exhibit degraded transaction processing performance, increased validation latency, and resource exhaustion when handling legitimate transactions during the attack period.

### Notes

This vulnerability exploits the tension between making validation methods fee-free (necessary for the pre-execution plugin architecture) and preventing abuse of computationally expensive operations. The `CheckThreshold` method is legitimately used by `MethodCallingThresholdPreExecutionPlugin` to validate calling thresholds, but the lack of input constraints allows it to be weaponized for DOS attacks. The fix must balance preventing abuse while maintaining the method's intended functionality for threshold validation in the pre-execution context.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L39-49)
```csharp
        if (new List<string>
            {
                nameof(ClaimTransactionFees), nameof(DonateResourceToken), nameof(ChargeTransactionFees),
                nameof(CheckThreshold), nameof(CheckResourceToken), nameof(ChargeResourceToken),
                nameof(CrossChainReceiveToken)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L339-369)
```csharp
    public override Empty CheckThreshold(CheckThresholdInput input)
    {
        AssertValidInputAddress(input.Sender);
        var meetThreshold = false;
        var meetBalanceSymbolList = new List<string>();
        foreach (var symbolToThreshold in input.SymbolToThreshold)
        {
            if (GetBalance(input.Sender, symbolToThreshold.Key) < symbolToThreshold.Value)
                continue;
            meetBalanceSymbolList.Add(symbolToThreshold.Key);
        }

        if (meetBalanceSymbolList.Count > 0)
        {
            if (input.IsCheckAllowance)
                foreach (var symbol in meetBalanceSymbolList)
                {
                    if (State.Allowances[input.Sender][Context.Sender][symbol] <
                        input.SymbolToThreshold[symbol]) continue;
                    meetThreshold = true;
                    break;
                }
            else
                meetThreshold = true;
        }

        if (input.SymbolToThreshold.Count == 0) meetThreshold = true;

        Assert(meetThreshold, "Cannot meet the calling threshold.");
        return new Empty();
    }
```

**File:** protobuf/token_contract.proto (L413-420)
```text
message CheckThresholdInput {
    // The sender of the transaction.
    aelf.Address sender = 1;
    // The threshold to set, Symbol->Threshold.
    map<string, int64> symbol_to_threshold = 2;
    // Whether to check the allowance.
    bool is_check_allowance = 3;
}
```

**File:** src/AElf.Kernel.TransactionPool/Infrastructure/TransactionExecutionValidationProvider.cs (L31-66)
```csharp
    public async Task<bool> ValidateTransactionAsync(Transaction transaction, IChainContext chainContext)
    {
        if (!_transactionOptions.EnableTransactionExecutionValidation)
            return true;

        var executionReturnSets = await _plainTransactionExecutingService.ExecuteAsync(new TransactionExecutingDto
        {
            Transactions = new[] { transaction },
            BlockHeader = new BlockHeader
            {
                PreviousBlockHash = chainContext.BlockHash,
                Height = chainContext.BlockHeight + 1,
                Time = TimestampHelper.GetUtcNow()
            }
        }, CancellationToken.None);

        var executionValidationResult =
            executionReturnSets.FirstOrDefault()?.Status == TransactionResultStatus.Mined;
        if (!executionValidationResult)
        {
            var transactionId = transaction.GetHash();
            // TODO: Consider to remove TransactionExecutionValidationFailedEvent.
            await LocalEventBus.PublishAsync(new TransactionExecutionValidationFailedEvent
            {
                TransactionId = transactionId
            });
            await LocalEventBus.PublishAsync(new TransactionValidationStatusChangedEvent
            {
                TransactionId = transactionId,
                TransactionResultStatus = TransactionResultStatus.NodeValidationFailed,
                Error = executionReturnSets.FirstOrDefault()?.TransactionResult?.Error ?? string.Empty
            });
        }

        return executionValidationResult;
    }
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L6-11)
```csharp
}

```
