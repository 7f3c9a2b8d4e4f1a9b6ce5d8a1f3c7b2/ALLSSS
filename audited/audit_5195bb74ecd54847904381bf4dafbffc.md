### Title
Unbounded Symbol List in Transaction Size Fee Configuration Enables Chain-Wide DOS

### Summary
The `SetSymbolsToPayTxSizeFee` method lacks bounds validation on the number of symbols that can be configured for transaction size fee payment. If governance sets thousands of symbols, every transaction on the chain will iterate through all configured symbols during fee charging, performing multiple state reads and calculations per symbol, causing transactions to fail due to excessive computation and effectively DOSing the entire chain.

### Finding Description

The vulnerability exists in the `SetSymbolsToPayTxSizeFee` method which configures which token symbols can be used to pay transaction size fees. [1](#0-0) 

This method validates each symbol individually (checking weights, duplicates, and token validity) but **never validates the total count** of symbols in the list. The `SymbolListToPayTxSizeFee` structure is defined as a repeated field with no maximum limit: [2](#0-1) 

The configured symbol list is then retrieved and passed to every transaction through the fee charging plugin: [3](#0-2) 

During transaction fee charging, `ChargeSizeFee` calls `GetAvailableSymbolToPayTxFee` which iterates through **ALL** configured symbols: [4](#0-3) 

The iteration logic performs expensive operations for each symbol: [5](#0-4) 

Each iteration involves multiple state reads through `GetBalanceCalculatedBaseOnPrimaryToken` and `GetAllowanceCalculatedBaseOnPrimaryToken`: [6](#0-5) 

### Impact Explanation

If the symbol list is configured with thousands of entries (e.g., 1000+ symbols), every transaction on the chain would:
- Iterate through all 1000+ symbols in `GetAvailableSymbolToPayTxFee`
- Perform ~2000-3000 state reads (balance + allowance checks per symbol)
- Execute ~1000+ arithmetic operations (weight calculations)

This would cause:
- **Chain-wide DOS**: All transactions would fail or consume excessive gas, making the chain unusable
- **Complete service disruption**: No user transactions could be processed successfully
- **Persistent impact**: The misconfiguration would persist until governance corrects it through another proposal

The severity is HIGH because it affects **every transaction** and **every user** on the chain, completely halting normal operations.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must have governance (parliament controller) authority to call `SetSymbolsToPayTxSizeFee`

**Attack Complexity:**
- Very low - simply call `SetSymbolsToPayTxSizeFee` with a large symbol list

**Feasibility Conditions:**
The vulnerability can be triggered through:
1. **Malicious governance**: Compromised governance intentionally sets excessive symbols
2. **Accidental misconfiguration**: Well-intentioned governance sets too many symbols without realizing the performance impact
3. **Governance capture**: Attacker gains temporary governance control

While governance control is required, the lack of bounds checking violates defense-in-depth principles. Governance is **supposed** to be able to configure fee payment symbols - the system should enforce reasonable limits to prevent both accidents and malicious abuse.

**Detection:**
The misconfiguration would be immediately apparent as all transactions start failing, but by then the damage is done and requires another governance action to fix.

### Recommendation

**1. Add Maximum Symbol Count Validation:**

In `SetSymbolsToPayTxSizeFee`, add a bounds check after the authorization check:

```csharp
public override Empty SetSymbolsToPayTxSizeFee(SymbolListToPayTxSizeFee input)
{
    AssertControllerForSymbolToPayTxSizeFee();
    if (input == null)
        throw new AssertionException("invalid input");
    
    // ADD THIS CHECK
    const int MaxSymbolCount = 10; // Or appropriate limit based on gas analysis
    Assert(input.SymbolsToPayTxSizeFee.Count <= MaxSymbolCount,
        $"Symbol count {input.SymbolsToPayTxSizeFee.Count} exceeds maximum allowed {MaxSymbolCount}");
    
    // ... rest of validation
}
```

**2. Add Constant Definition:** [7](#0-6) 

Add a constant like `SYMBOL_LIST_MAX_COUNT` alongside existing constants.

**3. Add Test Cases:**
- Test with boundary values (max count, max count + 1)
- Test performance with realistic symbol counts
- Test that exceeding limit reverts with proper error message

**4. Gas Analysis:**
Perform empirical testing to determine the optimal maximum based on transaction gas limits and performance requirements.

### Proof of Concept

**Initial State:**
- Chain is operational with normal governance control
- Primary token (ELF) and a few alternative tokens exist

**Attack Sequence:**

1. **Governance prepares malicious/excessive symbol list:**
   - Create or identify 1000+ valid, burnable tokens
   - Construct `SymbolListToPayTxSizeFee` with all symbols and weight ratios

2. **Governance calls `SetSymbolsToPayTxSizeFee`:**
   - Transaction succeeds (no bounds check prevents it)
   - State `SymbolListToPayTxSizeFee.Value` now contains 1000+ symbols

3. **Any user attempts a transaction:**
   - Pre-execution plugin retrieves 1000+ symbols
   - `ChargeTransactionFees` is called with full symbol list
   - `GetAvailableSymbolToPayTxFee` iterates through all 1000+ symbols
   - Transaction fails or times out due to excessive computation

**Expected Result:** Transaction should be rejected or governance should be unable to set excessive symbols

**Actual Result:** Transaction succeeds in step 2, then all subsequent transactions fail in step 3, causing chain-wide DOS

**Success Condition:** After step 2, monitor transaction success rate drops to 0% or near-0% as all transactions hit gas/computation limits during fee charging.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L392-398)
```csharp
        // SymbolsToPayTxSizeFee is set of all available token can be charged, and with the ratio of primary token and another.
        if (input.SymbolsToPayTxSizeFee.Any())
        {
            var allSymbolToTxFee = input.SymbolsToPayTxSizeFee.ToList();
            var availableSymbol = GetAvailableSymbolToPayTxFee(allSymbolToTxFee, fromAddress, txSizeFeeAmount,
                transactionFeeFreeAllowancesMap, symbolChargedForBaseFee, amountChargedForBaseFee,
                amountChargedForBaseAllowance, delegations);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L462-517)
```csharp
    private SymbolToPayTxSizeFee GetAvailableSymbolToPayTxFee(List<SymbolToPayTxSizeFee> allSymbolToTxFee,
        Address fromAddress, long txSizeFeeAmount, TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap,
        string symbolChargedForBaseFee, long amountChargedForBaseFee, long amountChargedForBaseAllowance,
        TransactionFeeDelegations delegations = null)
    {
        SymbolToPayTxSizeFee availableSymbol = null;
        SymbolToPayTxSizeFee availableSymbolWithAnything = null;
        SymbolToPayTxSizeFee availableSymbolWithEnoughBalance = null;
        SymbolToPayTxSizeFee availableSymbolWithEnoughBalancePlusAllowance = null;

        // get 1st Allowance > size fee, else, get 1st Balance + Allowance > 0, else get 1st > 0
        foreach (var symbolToPlayTxSizeFee in allSymbolToTxFee)
        {
            if (delegations != null)
            {
                var delegationEnough = IsDelegationEnoughBaseOnPrimaryToken(symbolToPlayTxSizeFee,
                    symbolChargedForBaseFee, amountChargedForBaseFee.Add(amountChargedForBaseAllowance),
                    txSizeFeeAmount, delegations);
                if (!delegationEnough) break;
            }

            var allowance = GetAllowanceCalculatedBaseOnPrimaryToken(symbolToPlayTxSizeFee,
                transactionFeeFreeAllowancesMap, symbolChargedForBaseFee, amountChargedForBaseAllowance);
            var balance = GetBalanceCalculatedBaseOnPrimaryToken(fromAddress, symbolToPlayTxSizeFee,
                symbolChargedForBaseFee, amountChargedForBaseFee);
            
            var balancePlusAllowance = balance.Add(allowance);

            if (allowance >= txSizeFeeAmount)
            {
                availableSymbol = symbolToPlayTxSizeFee;
                break;
            }

            if (delegations == null && balancePlusAllowance > 0)
            {
                availableSymbolWithAnything ??= symbolToPlayTxSizeFee;
            }

            if (balancePlusAllowance < txSizeFeeAmount) continue;

            if (allowance > 0)
            {
                availableSymbolWithEnoughBalancePlusAllowance ??= symbolToPlayTxSizeFee;
            }
            else
            {
                availableSymbolWithEnoughBalance ??= symbolToPlayTxSizeFee;
            }
        }

        availableSymbol ??= availableSymbolWithEnoughBalancePlusAllowance ??
                            availableSymbolWithEnoughBalance ?? availableSymbolWithAnything;

        return availableSymbol;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L616-649)
```csharp
    public override Empty SetSymbolsToPayTxSizeFee(SymbolListToPayTxSizeFee input)
    {
        AssertControllerForSymbolToPayTxSizeFee();
        if (input == null)
            throw new AssertionException("invalid input");
        var isPrimaryTokenExist = false;
        var symbolList = new List<string>();
        var primaryTokenSymbol = GetPrimaryTokenSymbol(new Empty());
        Assert(!string.IsNullOrEmpty(primaryTokenSymbol.Value), "primary token does not exist");
        foreach (var tokenWeightInfo in input.SymbolsToPayTxSizeFee)
        {
            if (tokenWeightInfo.TokenSymbol == primaryTokenSymbol.Value)
            {
                isPrimaryTokenExist = true;
                Assert(tokenWeightInfo.AddedTokenWeight == 1 && tokenWeightInfo.BaseTokenWeight == 1,
                    $"symbol:{tokenWeightInfo.TokenSymbol} weight should be 1");
            }

            Assert(tokenWeightInfo.AddedTokenWeight > 0 && tokenWeightInfo.BaseTokenWeight > 0,
                $"symbol:{tokenWeightInfo.TokenSymbol} weight should be greater than 0");
            Assert(!symbolList.Contains(tokenWeightInfo.TokenSymbol),
                $"symbol:{tokenWeightInfo.TokenSymbol} repeat");
            AssertSymbolToPayTxFeeIsValid(tokenWeightInfo.TokenSymbol, out var addedTokenTotalSupply);
            symbolList.Add(tokenWeightInfo.TokenSymbol);
        }

        Assert(isPrimaryTokenExist, $"primary token:{primaryTokenSymbol.Value} not included");
        State.SymbolListToPayTxSizeFee.Value = input;
        Context.Fire(new ExtraTokenListModified
        {
            SymbolListToPayTxSizeFee = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1358-1389)
```csharp
    private long GetBalanceCalculatedBaseOnPrimaryToken(Address fromAddress, SymbolToPayTxSizeFee tokenInfo,
        string baseSymbol,
        long cost)
    {
        var availableBalance = GetBalance(fromAddress, tokenInfo.TokenSymbol);
        if (tokenInfo.TokenSymbol == baseSymbol)
            availableBalance = availableBalance.Sub(cost);
        return availableBalance.Mul(tokenInfo.BaseTokenWeight)
            .Div(tokenInfo.AddedTokenWeight);
    }

    private long GetBalancePlusAllowanceCalculatedBaseOnPrimaryToken(Address fromAddress,
        SymbolToPayTxSizeFee tokenInfo, string baseSymbol,
        long cost, TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap, long allowanceCost)
    {
        return GetBalanceCalculatedBaseOnPrimaryToken(fromAddress, tokenInfo, baseSymbol, cost).Add(
            GetAllowanceCalculatedBaseOnPrimaryToken(tokenInfo, transactionFeeFreeAllowancesMap, baseSymbol,
                allowanceCost));
    }

    private long GetAllowanceCalculatedBaseOnPrimaryToken(SymbolToPayTxSizeFee tokenInfo,
        TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap, string baseSymbol,
        long allowanceCost)
    {
        var availableAllowance =
            GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap,
                tokenInfo.TokenSymbol); //GetBalance(Context.Sender, tokenInfo.TokenSymbol);
        if (tokenInfo.TokenSymbol == baseSymbol)
            availableAllowance = availableAllowance.Sub(allowanceCost);
        return availableAllowance.Mul(tokenInfo.BaseTokenWeight)
            .Div(tokenInfo.AddedTokenWeight);
    }
```

**File:** protobuf/token_contract.proto (L507-510)
```text
message SymbolListToPayTxSizeFee{
    // Transaction fee token information.
    repeated SymbolToPayTxSizeFee symbols_to_pay_tx_size_fee = 1;
}
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L98-107)
```csharp
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L1-30)
```csharp
namespace AElf.Contracts.MultiToken;

public static class TokenContractConstants
{
    public const int TokenNameLength = 80;
    public const int MaxDecimals = 18;
    public const int SymbolMaxLength = 10;
    public const int MemoMaxLength = 64;

    public const string PayTxFeeSymbolListName = "SymbolListToPayTxFee";
    public const string PayRentalSymbolListName = "SymbolListToPayRental";

    public const string TransferCallbackExternalInfoKey = "aelf_transfer_callback";
    public const string LockCallbackExternalInfoKey = "aelf_lock_callback";
    public const string UnlockCallbackExternalInfoKey = "aelf_unlock_callback";
    public const string LogEventExternalInfoKey = "aelf_log_event";
    public const string TokenAliasExternalInfoKey = "aelf_token_alias";
    public const int DELEGATEE_MAX_COUNT = 24;
    public const char NFTSymbolSeparator = '-';
    public const int NFTSymbolMaxLength = 30;
    public const string UserContractMethodFeeKey = "UserContractMethodFee";
    public const string CollectionSymbolSuffix = "0";
    public const string SeedCollectionSymbol = "SEED-0";
    public const string SeedOwnedSymbolExternalInfoKey = "__seed_owned_symbol";
    public const string SeedExpireTimeExternalInfoKey = "__seed_exp_time";
    public const string NftCreateChainIdExternalInfoKey = "__nft_create_chain_id";
    public const int DefaultMaxBatchApproveCount = 100;
    public const char AllSymbolIdentifier = '*';

}
```
