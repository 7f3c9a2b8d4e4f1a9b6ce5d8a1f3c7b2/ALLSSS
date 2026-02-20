# Audit Report

## Title
Missing Validation Allows Transaction Fee Free Allowance Overflow Causing DoS

## Summary
The transaction fee free allowances system lacks validation on allowance amounts during configuration, allowing parliament to set multiple symbol allowances that overflow when summed. Users holding multiple configured tokens above threshold experience transaction failures due to `OverflowException` during the pre-plugin fee charging process, resulting in a denial-of-service condition.

## Finding Description

The vulnerability exists in the transaction fee free allowances configuration and calculation logic:

**Configuration Without Validation:**
The `ConfigTransactionFeeFreeAllowances` method only validates that threshold and refresh seconds are non-negative, but performs no validation on the actual allowance amounts or their cumulative sum across multiple symbol configurations. [1](#0-0) 

**Overflow-Prone Summation:**
The `GetFreeFeeAllowanceAmount` method iterates through all configured symbols for which a user meets the threshold and sums their allowances using the `.Add()` extension method. [2](#0-1) 

**Checked Arithmetic Throws Exception:**
The `.Add()` extension method uses C#'s `checked` keyword, which throws an `OverflowException` when the sum exceeds `long.MaxValue` (9,223,372,036,854,775,807). [3](#0-2) 

**Critical Path Integration:**
The allowance calculation occurs during transaction fee charging as a pre-execution plugin. The `ChargeTransactionFees` method is invoked via `MethodFeeChargedPreExecutionPluginBase` [4](#0-3)  which calls `CalculateTransactionFeeFreeAllowances` to build the allowances map. [5](#0-4) 

**Data Structure and Calculation:**
The `CalculateTransactionFeeFreeAllowances` method iterates through all configured symbols and adds entries to the result map for each symbol where the user's balance meets the threshold. [6](#0-5)  This map is then passed to fee charging logic where `GetFreeFeeAllowanceAmount` is invoked during token selection. [7](#0-6) 

**Execution Flow:**
1. Parliament configures Symbol_A with threshold=1000 and allowances={ELF: 5,000,000,000,000,000,000}
2. Parliament configures Symbol_B with threshold=1000 and allowances={ELF: 5,000,000,000,000,000,000}
3. User holds both Symbol_A >= 1000 and Symbol_B >= 1000
4. User submits any transaction
5. Pre-plugin generates `ChargeTransactionFees` transaction
6. `CalculateTransactionFeeFreeAllowances` builds map with both Symbol_A and Symbol_B entries
7. `GetFreeFeeAllowanceAmount(map, "ELF")` iterates and sums: 5e18 + 5e18 = 10e18
8. Sum exceeds `long.MaxValue` → `OverflowException` thrown
9. Pre-plugin transaction fails → User's main transaction fails

## Impact Explanation

**Operational DoS:**
When parliament configures multiple symbols with allowance amounts that sum beyond `long.MaxValue` for any fee token, all users holding those tokens above their respective thresholds become unable to execute any transactions. The overflow exception propagates up through the call stack and causes the pre-plugin fee charging transaction to fail, which blocks the user's actual transaction from executing.

**Affected Users:**
Any user who legitimately holds multiple tokens for which parliament has configured free allowances above the respective thresholds. This could affect a significant portion of the user base if commonly held tokens are misconfigured.

**System Impact:**
The blockchain's transaction processing capability is degraded for affected users until parliament reconfigures the allowances with corrected values through a governance proposal. During this remediation period, impacted users cannot perform any transactions.

**Severity Assessment:**
Medium severity - This causes significant operational disruption without direct fund loss. The impact is substantial (complete transaction DoS for affected users) but requires a configuration error by parliament rather than malicious exploitation. The issue is recoverable through governance action but requires time and coordination.

## Likelihood Explanation

**Configuration Error Likelihood:**
Parliament configures transaction fee free allowances through governance proposals. Without validation warnings, bounds checking, or cumulative sum validation, administrators could unknowingly set values that trigger the overflow condition. For example:
- Symbol1: ELF allowance = 5,000,000,000,000,000,000 (representing 50 million ELF tokens)
- Symbol2: ELF allowance = 5,000,000,000,000,000,000 (representing 50 million ELF tokens)
- Sum = 10,000,000,000,000,000,000 > `long.MaxValue` (9,223,372,036,854,775,807)

**Realistic Scenario:**
This vulnerability represents an operational error rather than a malicious attack. The likelihood is **medium** because:
1. No validation exists on individual allowance amounts
2. No validation exists on the cumulative sum across multiple symbol configurations
3. No UI warnings would alert administrators to potential overflow risks
4. Token amounts typically use large values due to decimal precision (e.g., 1 ELF = 100,000,000 base units)
5. Generous free allowance policies for multiple popular tokens could easily exceed the limit

**Automatic Trigger:**
Once the misconfiguration exists, the vulnerability triggers automatically during normal user operations (submitting any transaction) without requiring specific attacker actions beyond holding the configured tokens.

## Recommendation

Add validation in `ConfigTransactionFeeFreeAllowances` to:
1. Validate individual allowance amounts are within reasonable bounds (e.g., < long.MaxValue / 2)
2. Check cumulative sum across all existing configurations for each fee token symbol
3. Reject configurations that would cause overflow when summed

Example fix:
```csharp
// After line 1242, add cumulative validation
foreach (var allowance in allowances.TransactionFeeFreeAllowances!.Value!)
{
    Assert(allowance.Amount >= 0 && allowance.Amount < long.MaxValue / 100, 
        "Allowance amount exceeds safe limit");
    
    // Check cumulative sum across all symbols
    long totalAllowance = allowance.Amount;
    foreach (var existingSymbol in State.TransactionFeeFreeAllowancesSymbolList.Value.Symbols)
    {
        if (existingSymbol == allowances.Symbol) continue;
        var existingConfig = State.TransactionFeeFreeAllowancesConfigMap[existingSymbol];
        if (existingConfig?.FreeAllowances?.Map?.ContainsKey(allowance.Symbol) == true)
        {
            totalAllowance = totalAllowance.Add(existingConfig.FreeAllowances.Map[allowance.Symbol].Amount);
        }
    }
    Assert(totalAllowance <= long.MaxValue, 
        $"Total allowance for {allowance.Symbol} would overflow when summed across all symbols");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ConfigTransactionFeeFreeAllowances_Overflow_DoS_Test()
{
    await SetPrimaryTokenSymbolAsync();
    
    // Create two additional tokens
    await CreateTokenAsync(DefaultSender, "SYMBOL_A");
    await CreateTokenAsync(DefaultSender, "SYMBOL_B");
    
    // Issue tokens to user to meet thresholds
    await IssueTokenToDefaultSenderAsync("SYMBOL_A", 2000);
    await IssueTokenToDefaultSenderAsync("SYMBOL_B", 2000);
    
    // Configure Symbol_A with large ELF allowance
    await TokenContractImplStub.ConfigTransactionFeeFreeAllowances.SendAsync(
        new ConfigTransactionFeeFreeAllowancesInput
        {
            Value =
            {
                new ConfigTransactionFeeFreeAllowance
                {
                    Symbol = "SYMBOL_A",
                    TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                    {
                        Value =
                        {
                            new TransactionFeeFreeAllowance
                            {
                                Symbol = NativeTokenSymbol, // ELF
                                Amount = 5_000_000_000_000_000_000L // 5e18
                            }
                        }
                    },
                    RefreshSeconds = 100,
                    Threshold = 1000
                }
            }
        });
    
    // Configure Symbol_B with large ELF allowance
    await TokenContractImplStub.ConfigTransactionFeeFreeAllowances.SendAsync(
        new ConfigTransactionFeeFreeAllowancesInput
        {
            Value =
            {
                new ConfigTransactionFeeFreeAllowance
                {
                    Symbol = "SYMBOL_B",
                    TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                    {
                        Value =
                        {
                            new TransactionFeeFreeAllowance
                            {
                                Symbol = NativeTokenSymbol, // ELF
                                Amount = 5_000_000_000_000_000_000L // 5e18
                            }
                        }
                    },
                    RefreshSeconds = 100,
                    Threshold = 1000
                }
            }
        });
    
    // User tries to perform a simple transfer - should throw OverflowException
    var transferException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await TokenContractStub.Transfer.SendAsync(new TransferInput
        {
            To = SampleAddress,
            Symbol = NativeTokenSymbol,
            Amount = 1,
            Memo = "test"
        });
    });
    
    // Verify it's an overflow exception in the fee charging logic
    transferException.Message.ShouldContain("Overflow");
}
```

## Notes

The vulnerability is confirmed through code analysis showing:
1. Missing validation on allowance amounts and cumulative sums
2. Checked arithmetic in the summation path that throws on overflow
3. Execution in a critical pre-plugin path that blocks all user transactions
4. Realistic configuration values that could trigger the overflow

This represents a genuine DoS vector caused by missing input validation rather than malicious intent.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L268-276)
```csharp
    private bool ChargeTransactionFeesToBill(ChargeTransactionFeesInput input, Address fromAddress,
        ref TransactionFeeBill bill,
        ref TransactionFreeFeeAllowanceBill allowanceBill, Dictionary<string, long> fee, bool isSizeFeeFree = false,
        TransactionFeeDelegations delegations = null)
    {
        var successToChargeBaseFee = true;

        SetOrRefreshTransactionFeeFreeAllowances(fromAddress);
        var freeAllowancesMap = CalculateTransactionFeeFreeAllowances(fromAddress);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L720-745)
```csharp
        }

        chargeResult = TryToChargeUserBaseFee(symbolToAmountMap, fromAddress, transactionFeeFreeAllowancesMap,
            out amount, out symbol, out existingBalance, out existingAllowance);

        if (symbol != null)
        {
            existingBalance = GetBalance(fromAddress, symbol);
            existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
            amount = symbolToAmountMap[symbol];
        }

        //For user, if charge failed and delegation is null, priority charge primary token
        if (!chargeResult)
        {
            var primaryTokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
            if (symbolToAmountMap.ContainsKey(primaryTokenSymbol))
            {
                symbol = primaryTokenSymbol;
                existingBalance = GetBalance(fromAddress, symbol);
                existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
            }
        }

        return chargeResult;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1234-1242)
```csharp
        foreach (var allowances in input.Value!)
        {
            ValidateToken(allowances.Symbol);
            Assert(
                allowances.TransactionFeeFreeAllowances?.Value != null &&
                allowances.TransactionFeeFreeAllowances.Value.Count > 0,
                "Invalid input allowances");
            Assert(allowances.Threshold >= 0, "Invalid input threshold");
            Assert(allowances.RefreshSeconds >= 0, "Invalid input refresh seconds");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1313-1356)
```csharp
    private TransactionFeeFreeAllowancesMap CalculateTransactionFeeFreeAllowances(Address input)
    {
        var freeAllowanceMap = State.TransactionFeeFreeAllowances[input];

        var freeAllowancesConfig = State.TransactionFeeFreeAllowancesSymbolList.Value;
        if (freeAllowancesConfig == null)
        {
            return new TransactionFeeFreeAllowancesMap();
        }

        var transactionFeeFreeAllowancesMap = new TransactionFeeFreeAllowancesMap();

        foreach (var symbol in freeAllowancesConfig.Symbols)
        {
            var balance = State.Balances[input][symbol];
            if (balance < State.TransactionFeeFreeAllowancesConfigMap[symbol].Threshold) continue;

            var lastRefreshTime = State.TransactionFeeFreeAllowancesLastRefreshTimes[input][symbol];

            var freeAllowances = freeAllowanceMap[symbol];

            if (freeAllowances == null)
            {
                transactionFeeFreeAllowancesMap.Map.Add(symbol,
                    State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone());
                continue;
            }

            if (lastRefreshTime == null)
            {
                transactionFeeFreeAllowancesMap.Map.Add(symbol, freeAllowances);
            }
            else
            {
                transactionFeeFreeAllowancesMap.Map[symbol] =
                    (Context.CurrentBlockTime - lastRefreshTime).Seconds >
                    State.TransactionFeeFreeAllowancesConfigMap[symbol].RefreshSeconds
                        ? State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone()
                        : freeAllowances;
            }
        }

        return transactionFeeFreeAllowancesMap;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L179-194)
```csharp
    private long GetFreeFeeAllowanceAmount(TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap, string symbol)
    {
        var allowance = 0L;
        var map = transactionFeeFreeAllowancesMap.Map;

        if (map == null) return allowance;

        foreach (var freeAllowances in map.Values)
        {
            freeAllowances.Map.TryGetValue(symbol, out var freeAllowance);

            allowance = allowance.Add(freeAllowance?.Amount ?? 0L);
        }

        return allowance;
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L100-106)
```csharp
    public static long Add(this long a, long b)
    {
        checked
        {
            return a + b;
        }
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L16-109)
```csharp
internal class MethodFeeChargedPreExecutionPluginBase : SmartContractExecutionPluginBase, IPreExecutionPlugin,
    ISingletonDependency
{
    private readonly IContractReaderFactory<TokenContractImplContainer.TokenContractImplStub>
        _contractReaderFactory;

    private readonly ISmartContractAddressService _smartContractAddressService;
    private readonly ITransactionSizeFeeSymbolsProvider _transactionSizeFeeSymbolsProvider;
    private readonly IPrimaryTokenFeeService _txFeeService;

    public MethodFeeChargedPreExecutionPluginBase(ISmartContractAddressService smartContractAddressService,
        IPrimaryTokenFeeService txFeeService,
        ITransactionSizeFeeSymbolsProvider transactionSizeFeeSymbolsProvider,
        IContractReaderFactory<TokenContractImplContainer.TokenContractImplStub> contractReaderFactory,
        string acsSymbol) : base(acsSymbol)
    {
        _smartContractAddressService = smartContractAddressService;
        _txFeeService = txFeeService;
        _transactionSizeFeeSymbolsProvider = transactionSizeFeeSymbolsProvider;
        _contractReaderFactory = contractReaderFactory;
    }

    public ILogger<MethodFeeChargedPreExecutionPluginBase> Logger { get; set; }

    protected virtual bool IsApplicableToTransaction(IReadOnlyList<ServiceDescriptor> descriptors, Transaction transaction,
        Address tokenContractAddress)
    {
        return false;
    }

    protected virtual bool IsExemptedTransaction(Transaction transaction, Address tokenContractAddress,
        TokenContractImplContainer.TokenContractImplStub tokenStub)
    {
        return false;
    }

    protected virtual Transaction GetTransaction(TokenContractImplContainer.TokenContractImplStub tokenStub,
        ChargeTransactionFeesInput chargeTransactionFeesInput)
    {
        return new Transaction();
    }

    public async Task<IEnumerable<Transaction>> GetPreTransactionsAsync(IReadOnlyList<ServiceDescriptor> descriptors,
        ITransactionContext transactionContext)
    {
        try
        {
            var chainContext = new ChainContext
            {
                BlockHash = transactionContext.PreviousBlockHash,
                BlockHeight = transactionContext.BlockHeight - 1
            };

            var tokenContractAddress = await _smartContractAddressService.GetAddressByContractNameAsync(
                chainContext,
                TokenSmartContractAddressNameProvider.StringName);

            if (transactionContext.BlockHeight < AElfConstants.GenesisBlockHeight + 1 ||
                tokenContractAddress == null)
                return new List<Transaction>();

            if (!IsApplicableToTransaction(descriptors, transactionContext.Transaction, tokenContractAddress))
                return new List<Transaction>();

            var tokenStub = _contractReaderFactory.Create(new ContractReaderContext
            {
                Sender = transactionContext.Transaction.From,
                ContractAddress = tokenContractAddress,
                RefBlockNumber = transactionContext.Transaction.RefBlockNumber
            });

            if (IsExemptedTransaction(transactionContext.Transaction, tokenContractAddress, tokenStub))
                return new List<Transaction>();

            var txCost = await _txFeeService.CalculateFeeAsync(transactionContext, chainContext);
            var chargeTransactionFeesInput = new ChargeTransactionFeesInput
            {
                MethodName = transactionContext.Transaction.MethodName,
                ContractAddress = transactionContext.Transaction.To,
                TransactionSizeFee = txCost
            };

            var transactionSizeFeeSymbols =
                await _transactionSizeFeeSymbolsProvider.GetTransactionSizeFeeSymbolsAsync(chainContext);
            if (transactionSizeFeeSymbols != null)
                foreach (var transactionSizeFeeSymbol in transactionSizeFeeSymbols.TransactionSizeFeeSymbolList)
                    chargeTransactionFeesInput.SymbolsToPayTxSizeFee.Add(new SymbolToPayTxSizeFee
                    {
                        TokenSymbol = transactionSizeFeeSymbol.TokenSymbol,
                        BaseTokenWeight = transactionSizeFeeSymbol.BaseTokenWeight,
                        AddedTokenWeight = transactionSizeFeeSymbol.AddedTokenWeight
                    });

            var chargeFeeTransaction = GetTransaction(tokenStub, chargeTransactionFeesInput);
```
