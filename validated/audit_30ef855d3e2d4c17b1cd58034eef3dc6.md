# Audit Report

## Title
Resource Token Debt Accumulates Indefinitely Without Repayment Mechanism, Causing Contract DoS and Accounting Integrity Violation

## Summary
The `PayResourceTokens()` function in the MultiToken contract accumulates resource token debt in `OwningResourceToken` state when contracts have insufficient balance, but provides no mechanism to repay or clear this debt. This creates an immediate and permanent DoS for affected contracts and violates accounting integrity, with potential long-term overflow causing system transaction failures.

## Finding Description

The vulnerability exists in the resource token debt tracking mechanism within the MultiToken contract. When `PayResourceTokens()` is executed and a contract has insufficient balance to pay resource fees, the shortfall is recorded as debt in the `OwningResourceToken` state variable. [1](#0-0) 

However, this debt is **never cleared or reduced**, even when contracts later acquire sufficient balance. A comprehensive grep search confirms that `OwningResourceToken` is only modified in three locations across the entire codebase - one read-only access in `CheckResourceToken` and two write operations in `PayResourceTokens` that exclusively perform addition. The debt accumulation logic only adds to existing debt without any subtraction path.

The `CheckResourceToken()` function validates that a contract's balance exceeds its accumulated debt before allowing transaction execution, but does not reduce or clear the debt. [2](#0-1)  This function is invoked as a **pre-execution plugin** for all ACS8 contracts, [3](#0-2)  meaning any transaction to a contract with accumulated debt will fail the pre-execution check if `balance <= debt`.

This contrasts sharply with the `PayRental()` function, which implements proper debt repayment logic for side chain rental fees. [4](#0-3)  Specifically, `PayRental()` explicitly clears the `OwningRental` debt when sufficient balance exists, [5](#0-4)  demonstrating the expected pattern that `PayResourceTokens()` fails to implement.

The `.Add()` operation used for debt accumulation employs checked arithmetic that throws `OverflowException` when overflow occurs. [6](#0-5) 

The `DonateResourceToken()` method is executed as a system transaction at the end of each block by the consensus miner, [7](#0-6)  and it calls `PayResourceTokens()` to process all accumulated resource token fees. [8](#0-7) 

## Impact Explanation

**Critical Immediate Impact - Permanent Contract DoS**: Once any contract accumulates debt in `OwningResourceToken` (which occurs whenever it consumes resource tokens without sufficient balance), the `CheckResourceToken` pre-execution plugin will cause **ALL subsequent transactions to that contract to fail** if `balance <= accumulated_debt`. Since there is no mechanism to clear this debt (only to add to it), the contract becomes permanently unusable unless someone transfers sufficient tokens to exceed the debt threshold. This is a high-severity availability impact affecting any contract that temporarily lacks resource token balance.

**Accounting Integrity Violation**: The debt tracking system becomes meaningless once debt accumulates, as it never clears even when contracts later acquire sufficient balance. This prevents accurate resource accounting across the chain and violates the fundamental invariant that settled debts should be marked as paid.

**Long-term Impact - System Transaction DoS**: When accumulated debt across all contracts and symbols eventually exceeds `long.MaxValue`, the checked arithmetic `.Add()` operation will throw an `OverflowException`. Since this occurs in `DonateResourceToken` - a system transaction generated automatically for each block - the failure could disrupt block production and consensus operations.

**Affected Parties**:
- Any contract implementing ACS8 (resource consumption standard) that consumes resource tokens without maintaining sufficient balance becomes permanently DoS'd
- The entire chain when overflow causes system transaction failures
- Users unable to interact with affected contracts
- Node operators attempting to produce blocks after overflow

## Likelihood Explanation

**Attacker Capabilities**: Any contract that consumes resource tokens (CPU, RAM, DISK, NET) can trigger debt accumulation by operating without sufficient balance. No special privileges are required - this is a passive consequence of normal resource consumption patterns.

**Attack Complexity**: **Low** - Debt accumulates automatically through normal contract operations when balance is insufficient. A contract need only consume resources without maintaining adequate token balance.

**Immediate Likelihood**: **High** - Contracts may temporarily lack sufficient resource token balance due to normal operational conditions (e.g., tokens locked elsewhere, sudden usage spikes, or deployment without adequate funding). The permanent DoS impact occurs immediately upon first debt accumulation.

**Long-term Overflow Likelihood**: **Low-to-Medium** - While reaching `long.MaxValue` overflow may require years of accumulation (the report estimates ~11.6 years at 1,000 tokens per block for a single symbol), multiple contracts and symbols accumulating debt simultaneously could accelerate this timeline. However, the **critical immediate DoS impact** makes this vulnerability severe regardless of overflow timing.

## Recommendation

Implement debt repayment logic in `PayResourceTokens()` following the same pattern used in `PayRental()`. When processing resource token payments, check if the contract's current balance can cover both the current charge and any accumulated debt. If so, clear the debt before deducting the current payment.

Suggested fix pattern (based on the `PayRental()` implementation):

```csharp
// In PayResourceTokens(), after line 969:
var existingBalance = GetBalance(bill.ContractAddress, symbol);
var existingDebt = State.OwningResourceToken[bill.ContractAddress][symbol];

// Try to clear existing debt first if balance permits
if (existingDebt > 0 && existingBalance > existingDebt)
{
    amount = amount.Add(existingDebt); // Include debt in total payment
    existingBalance = existingBalance.Sub(existingDebt);
    State.OwningResourceToken[bill.ContractAddress][symbol] = 0; // Clear debt
}

if (amount > existingBalance)
{
    // Only accumulate NEW debt, not total amount
    var newDebt = amount.Sub(existingBalance);
    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(newDebt);
    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
    // ... rest of existing logic
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploying a contract that implements ACS8 and consumes resource tokens
2. Allowing the contract to consume resources without sufficient balance (triggers debt accumulation in `PayResourceTokens`)
3. Attempting to execute any subsequent transaction on the contract - it will fail at the `CheckResourceToken` pre-execution check
4. Even after transferring tokens to the contract to cover new operations, transactions continue failing because the old debt remains in `OwningResourceToken` and the check requires `balance > owningBalance`

The grep search confirms `OwningResourceToken[` is only accessed at three locations, with only additive modifications and no subtraction/clearing operations, proving the debt can only grow.

---

## Notes

The original report focuses heavily on the eventual overflow scenario occurring after years of accumulation. However, the **most critical and immediate impact is the permanent DoS of contracts** once they accumulate any debt. The `CheckResourceToken` pre-execution plugin enforcement means affected contracts become unusable immediately, not after years of overflow accumulation.

The existence of the correctly-implemented `PayRental()` function demonstrates that the developers understood the proper debt repayment pattern, making this a clear bug rather than an intentional design choice. The `OwningResourceToken` state variable definition [9](#0-8)  indicates it was intended to track "owning" (debt) amounts, but the implementation lacks the critical debt clearing logic.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L602-614)
```csharp
    public override Empty CheckResourceToken(Empty input)
    {
        AssertTransactionGeneratedByPlugin();
        foreach (var symbol in Context.Variables.GetStringArray(TokenContractConstants.PayTxFeeSymbolListName))
        {
            var balance = GetBalance(Context.Sender, symbol);
            var owningBalance = State.OwningResourceToken[Context.Sender][symbol];
            Assert(balance > owningBalance,
                $"Contract balance of {symbol} token is not enough. Owning {owningBalance}.");
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-952)
```csharp
    public override Empty DonateResourceToken(TotalResourceTokensMaps input)
    {
        AssertSenderIsCurrentMiner();
        var donateResourceTokenExecuteHeight = State.DonateResourceTokenExecuteHeight.Value;
        if (donateResourceTokenExecuteHeight == 0)
        {
            donateResourceTokenExecuteHeight = Context.CurrentHeight;
        }

        Assert(donateResourceTokenExecuteHeight == Context.CurrentHeight,
            $"This method already executed in height {State.DonateResourceTokenExecuteHeight.Value}");
        State.DonateResourceTokenExecuteHeight.Value = donateResourceTokenExecuteHeight.Add(1);
        Context.LogDebug(() => $"Start donate resource token. {input}");
        State.LatestTotalResourceTokensMapsHash.Value = HashHelper.ComputeFrom(input);
        Context.LogDebug(() =>
            $"Now LatestTotalResourceTokensMapsHash is {State.LatestTotalResourceTokensMapsHash.Value}");

        var isMainChain = true;
        if (State.DividendPoolContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            if (treasuryContractAddress == null)
            {
                isMainChain = false;
            }
            else
            {
                State.DividendPoolContract.Value = treasuryContractAddress;
            }
        }

        PayResourceTokens(input, isMainChain);

        if (!isMainChain)
        {
            PayRental();
        }

        return new Empty();
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L968-982)
```csharp
                // Check balance in case of insufficient balance.
                var existingBalance = GetBalance(bill.ContractAddress, symbol);
                if (amount > existingBalance)
                {
                    var owned = amount.Sub(existingBalance);
                    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
                    Context.Fire(new ResourceTokenOwned
                    {
                        Symbol = symbol,
                        Amount = currentOwning,
                        ContractAddress = bill.ContractAddress
                    });
                    amount = existingBalance;
                }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1019-1097)
```csharp
    private void PayRental()
    {
        var creator = State.SideChainCreator.Value;
        if (creator == null) return;
        if (State.LastPayRentTime.Value == null)
        {
            // Initial LastPayRentTime first calling DonateResourceToken.
            State.LastPayRentTime.Value = Context.CurrentBlockTime;
            return;
        }

        // We need minutes.
        var duration = (Context.CurrentBlockTime - State.LastPayRentTime.Value).Seconds.Div(60);
        if (duration == 0)
        {
            return;
        }

        // Update LastPayRentTime if it is ready to charge rental.
        State.LastPayRentTime.Value += new Duration { Seconds = duration.Mul(60) };

        foreach (var symbol in Context.Variables.GetStringArray(TokenContractConstants.PayRentalSymbolListName))
        {
            var donates = 0L;

            var availableBalance = GetBalance(creator, symbol);

            // Try to update owning rental.
            var owningRental = State.OwningRental[symbol];
            if (owningRental > 0)
            {
                // If Creator own this symbol and current balance can cover the debt, pay the debt at first.
                if (availableBalance > owningRental)
                {
                    donates = owningRental;
                    // Need to update available balance,
                    // cause existing balance not necessary equals to available balance.
                    availableBalance = availableBalance.Sub(owningRental);
                    State.OwningRental[symbol] = 0;
                }
            }

            var rental = duration.Mul(State.ResourceAmount[symbol]).Mul(State.Rental[symbol]);
            if (availableBalance >= rental) // Success
            {
                donates = donates.Add(rental);
                ModifyBalance(creator, symbol, -donates);
            }
            else // Fail
            {
                // Donate all existing balance. Directly reset the donates.
                donates = GetBalance(creator, symbol);
                State.Balances[creator][symbol] = 0;

                // Update owning rental to record a new debt.
                var own = rental.Sub(availableBalance);
                State.OwningRental[symbol] = State.OwningRental[symbol].Add(own);

                Context.Fire(new RentalAccountBalanceInsufficient
                {
                    Symbol = symbol,
                    Amount = own
                });
            }

            // Side Chain donates.
            var consensusContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
            ModifyBalance(consensusContractAddress, symbol, donates);

            Context.Fire(new RentalCharged()
            {
                Symbol = symbol,
                Amount = donates,
                Payer = creator,
                Receiver = consensusContractAddress
            });
        }
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/ResourceConsumptionPreExecutionPlugin.cs (L31-68)
```csharp
    public async Task<IEnumerable<Transaction>> GetPreTransactionsAsync(
        IReadOnlyList<ServiceDescriptor> descriptors, ITransactionContext transactionContext)
    {
        if (!HasApplicableAcs(descriptors)) return new List<Transaction>();

        var chainContext = new ChainContext
        {
            BlockHash = transactionContext.PreviousBlockHash,
            BlockHeight = transactionContext.BlockHeight - 1
        };

        // Generate token contract stub.
        var tokenContractAddress =
            await _smartContractAddressService.GetAddressByContractNameAsync(chainContext,
                TokenSmartContractAddressNameProvider.StringName);
        if (tokenContractAddress == null) return new List<Transaction>();

        var tokenStub = _contractReaderFactory.Create(new ContractReaderContext
        {
            ContractAddress = tokenContractAddress,
            Sender = transactionContext.Transaction.To
        });

        if (transactionContext.Transaction.To == tokenContractAddress &&
            transactionContext.Transaction.MethodName == nameof(tokenStub.ChargeResourceToken))
            return new List<Transaction>();

        if (transactionContext.Transaction.MethodName ==
            nameof(ResourceConsumptionContractContainer.ResourceConsumptionContractStub.BuyResourceToken))
            return new List<Transaction>();

        var checkResourceTokenTransaction = tokenStub.CheckResourceToken.GetTransaction(new Empty());

        return new List<Transaction>
        {
            checkResourceTokenTransaction
        };
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

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/DonateResourceTransactionGenerator.cs (L28-75)
```csharp
    public async Task<List<Transaction>> GenerateTransactionsAsync(Address from, long preBlockHeight,
        Hash preBlockHash)
    {
        var generatedTransactions = new List<Transaction>();

        var chainContext = new ChainContext
        {
            BlockHash = preBlockHash,
            BlockHeight = preBlockHeight
        };

        var tokenContractAddress =
            await _smartContractAddressService.GetAddressByContractNameAsync(chainContext,
                TokenSmartContractAddressNameProvider.StringName);

        if (tokenContractAddress == null) return generatedTransactions;

        var totalResourceTokensMaps = await _totalResourceTokensMapsProvider.GetTotalResourceTokensMapsAsync(
            chainContext);

        ByteString input;
        if (totalResourceTokensMaps != null && totalResourceTokensMaps.BlockHeight == preBlockHeight &&
            totalResourceTokensMaps.BlockHash == preBlockHash)
            // If totalResourceTokensMaps match current block.
            input = totalResourceTokensMaps.ToByteString();
        else
            input = new TotalResourceTokensMaps
            {
                BlockHash = preBlockHash,
                BlockHeight = preBlockHeight
            }.ToByteString();

        generatedTransactions.AddRange(new List<Transaction>
        {
            new()
            {
                From = from,
                MethodName = nameof(TokenContractImplContainer.TokenContractImplStub.DonateResourceToken),
                To = tokenContractAddress,
                RefBlockNumber = preBlockHeight,
                RefBlockPrefix = BlockHelper.GetRefBlockPrefix(preBlockHash),
                Params = input
            }
        });

        Logger.LogTrace("Tx DonateResourceToken generated.");
        return generatedTransactions;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L29-32)
```csharp
    /// <summary>
    ///     Contract Address -> (Owning) Resource Token Symbol -> Amount.
    /// </summary>
    public MappedState<Address, string, long> OwningResourceToken { get; set; }
```
