# Audit Report

## Title
Fee-Free CheckThreshold Method Enables Resource Exhaustion DoS Attack via Unbounded State Reads

## Summary
The `CheckThreshold` method in the MultiToken contract performs unbounded iteration over an input map without size validation while being marked as fee-free, allowing attackers to force validator nodes to execute hundreds of thousands of state read operations at zero cost during transaction pre-execution validation, creating a resource exhaustion denial-of-service vector against network transaction processing.

## Finding Description

The `CheckThreshold` method is a public method that validates token balance thresholds [1](#0-0) . This method is explicitly marked as `IsSizeFeeFree = true`, exempting it from all transaction fees [2](#0-1) .

The vulnerability exists in the unbounded iteration through `input.SymbolToThreshold` where each entry triggers a `GetBalance` call [3](#0-2) . The `GetBalance` method performs a state read operation accessing `State.Balances[address][symbol]` [4](#0-3) . 

When `IsCheckAllowance` is enabled, additional state reads occur for each qualifying symbol, accessing `State.Allowances` mappings [5](#0-4) .

The protobuf definition specifies `symbol_to_threshold` as an unbounded `map<string, int64>` with no size constraints [6](#0-5) . The transaction size limit of 5MB allows inclusion of tens of thousands of map entries [7](#0-6) .

Transaction pre-execution validation is enabled by default to prevent transaction flood attacks [8](#0-7) . The `TransactionExecutionValidationProvider` pre-executes all transactions before acceptance, performing full contract execution including all state reads [9](#0-8) .

**Attack Execution:**
1. Attacker crafts `CheckThreshold` transaction with 50,000+ symbol entries in `symbol_to_threshold` map
2. Transaction submitted to network (within 5MB limit)
3. Each validator node pre-executes transaction during validation
4. Pre-execution performs 50,000+ `GetBalance` state reads
5. If `IsCheckAllowance=true`, performs additional 50,000+ allowance state reads
6. Transaction fails threshold assertion and is rejected
7. Validator resources already consumed on state reads
8. Attacker repeats attack with zero cost
9. Legitimate transactions experience validation delays

## Impact Explanation

This vulnerability enables operational denial-of-service against transaction processing infrastructure with the following impacts:

**Validator Resource Exhaustion**: Each malicious transaction forces validators to perform tens of thousands of database read operations during pre-execution, consuming CPU cycles and I/O bandwidth that would otherwise process legitimate transactions.

**Network Throughput Degradation**: As validators spend resources validating malicious transactions, the effective transaction processing capacity decreases, creating backlogs and delaying legitimate user transactions across all contract operations (token transfers, governance proposals, consensus participation).

**Zero Economic Barrier**: The fee-free status completely removes economic disincentives. An attacker can sustain this attack indefinitely without cost, while legitimate users must pay fees for their delayed transactions.

**Cascading Service Degradation**: Since transaction validation is a prerequisite for ALL blockchain operations, this attack effectively creates a DoS condition for governance voting, consensus participation, token operations, and all other contract interactions.

The severity is justified because this enables sustained operational disruption of critical network infrastructure with zero attacker cost and high impact on service availability for all users.

## Likelihood Explanation

**High Likelihood** due to:

**Minimal Attack Prerequisites**: Any actor capable of submitting transactions can execute this attack. No tokens, special permissions, or governance participation required. Only network access is needed.

**Trivial Implementation Complexity**: Constructing a `CheckThresholdInput` with many symbol entries is straightforward using standard protobuf serialization. No sophisticated exploit techniques required.

**Zero Financial Cost**: The `IsSizeFeeFree = true` marking means no method fees or transaction size fees apply. Attacker incurs zero cost per attack transaction, making sustained attacks economically viable.

**No Rate Limiting or Validation**: The method performs only basic address validation [10](#0-9) . No checks exist on map size, symbol count, or request frequency.

**Default Configuration Enables Attack**: Transaction execution validation is enabled by default on common nodes [11](#0-10) , ensuring the pre-execution vector is active network-wide.

**Existing Test Coverage Shows Normal Usage**: Tests demonstrate typical usage with only 1-2 symbols [12](#0-11) , indicating no consideration for large-scale inputs during development.

## Recommendation

Implement input validation to limit the maximum number of symbols in `CheckThreshold` requests:

```csharp
public override Empty CheckThreshold(CheckThresholdInput input)
{
    AssertValidInputAddress(input.Sender);
    const int MaxSymbolCount = 10; // Reasonable limit for threshold checking
    Assert(input.SymbolToThreshold.Count <= MaxSymbolCount, 
        $"Symbol count exceeds maximum limit of {MaxSymbolCount}");
    
    // ... rest of implementation
}
```

Additionally, consider:
1. Adding rate limiting for fee-free methods based on sender address
2. Implementing a per-transaction computation budget that fails early when exceeded
3. Reviewing other fee-free methods for similar unbounded iteration patterns
4. Adding monitoring for abnormal transaction validation patterns

## Proof of Concept

```csharp
[Fact]
public async Task CheckThreshold_ResourceExhaustion_DoS_Test()
{
    // Attacker creates transaction with excessive symbols
    var maliciousInput = new CheckThresholdInput
    {
        Sender = DefaultAddress,
        IsCheckAllowance = true
    };
    
    // Add 10,000 symbols to trigger resource exhaustion
    // In real attack, could use 50,000+ within 5MB limit
    for (int i = 0; i < 10000; i++)
    {
        maliciousInput.SymbolToThreshold.Add($"SYM{i}", 1);
    }
    
    // Transaction will fail but forces 10,000 state reads during pre-execution
    // With no fees charged, attacker can repeat indefinitely
    var result = await TokenContractStub.CheckThreshold.SendWithExceptionAsync(maliciousInput);
    
    // Transaction fails as expected but resources already consumed
    result.TransactionResult.Error.ShouldContain("Cannot meet the calling threshold");
    
    // Attack demonstrated: validator performed 10,000+ state reads at zero cost to attacker
}
```

## Notes

This vulnerability is particularly severe because it weaponizes the transaction validation mechanism intended to protect against spam. The pre-execution validation, designed to prevent invalid transactions from flooding the network, becomes the attack vector itself when combined with fee-free methods that lack input validation.

The state read operations during pre-execution are genuine database accesses that consume real validator resources, making this a concrete resource exhaustion attack rather than a theoretical concern. The combination of zero cost, public accessibility, and unbounded resource consumption creates optimal conditions for sustained denial-of-service attacks against network transaction processing infrastructure.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L166-172)
```csharp
    private long GetBalance(Address address, string symbol)
    {
        AssertValidInputAddress(address);
        var actualSymbol = GetActualTokenSymbol(symbol);
        Assert(!string.IsNullOrWhiteSpace(actualSymbol), "Invalid symbol.");
        return State.Balances[address][actualSymbol];
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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L1-6)
```csharp
namespace AElf.Kernel.TransactionPool;

public class TransactionPoolConsts
{
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
}
```

**File:** src/AElf.Kernel.TransactionPool/TransactionOptions.cs (L15-19)
```csharp
    /// <summary>
    ///     Bp Node can disable this flag to make best performance.
    ///     But common node needs to enable it to prevent transaction flood attack
    /// </summary>
    public bool EnableTransactionExecutionValidation { get; set; } = true;
```

**File:** src/AElf.Kernel.TransactionPool/Infrastructure/TransactionExecutionValidationProvider.cs (L31-48)
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
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenApplicationTests.cs (L1688-1688)
```csharp
                    SymbolToThreshold = { { tokenA, tokenACheckAmount }, { tokenB, tokenBCheckAmount } }
```
