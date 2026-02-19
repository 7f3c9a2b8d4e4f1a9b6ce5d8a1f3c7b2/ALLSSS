### Title
Missing Balance Validation Before Virtual Transfers in Profit Claiming Creates DoS Vulnerability

### Summary
The `ProfitAllPeriods()` function performs multiple virtual token transfers across different periods without pre-validating balance availability. When any single inline transfer fails due to insufficient funds, the entire `ClaimProfits` transaction fails and reverts all state changes, permanently blocking users from claiming legitimate profits from any period, even those with adequate balances.

### Finding Description

**Exact Location**: [1](#0-0) 

**Root Cause**: In the `ProfitAllPeriods()` function, the code loops through multiple periods and queues virtual transfers using `SendVirtualInline()` without checking if each period's virtual address has sufficient balance. [2](#0-1) 

The `SendVirtualInline()` method is void and only queues transactions - it provides no immediate feedback on whether transfers will succeed. [3](#0-2) 

**Execution Flow**: Inline transactions are executed sequentially after the main contract execution. [4](#0-3)  If any inline transaction fails, execution halts immediately and remaining inline transactions are skipped. [5](#0-4) 

Token transfers fail when insufficient balance exists. [6](#0-5) 

The failure surfaces up through the trace hierarchy, causing the entire parent transaction to fail. [7](#0-6) 

**Why Protection Fails**: The `ClaimProfits` function provides no mechanism to claim specific periods or skip problematic ones. [8](#0-7)  Users must claim all outstanding periods at once through the single input structure. [9](#0-8) 

**Inconsistent Pattern**: Other parts of the codebase DO check balance before calling `SendVirtualInline()` using the pattern of querying balance first and using `continue` to skip insufficient funds. [10](#0-9)  This pattern is NOT applied in `ProfitAllPeriods()`.

### Impact Explanation

**Direct Fund Impact**: Users become permanently unable to withdraw their legitimately earned profits. Even if 99 periods have sufficient balance and 1 period has insufficient balance, the user cannot claim ANY profits.

**Affected Parties**: All beneficiaries of profit schemes who have accumulated profits across multiple periods where at least one period's virtual address has insufficient balance.

**Harm Quantification**: Complete loss of access to earned funds. Users' `lastProfitPeriod` cannot be updated, creating a deadlock where profits remain inaccessible indefinitely.

**Severity Justification**: HIGH - This constitutes a direct Denial of Service of the fund withdrawal mechanism, one of the critical invariants listed: "Profit/Treasury/TokenHolder share calculations, donation/release logic, dividend distribution and settlement accuracy."

### Likelihood Explanation

**Entry Point**: Public method `ClaimProfits()` callable by any beneficiary. [11](#0-10) 

**Realistic Preconditions**: Insufficient balance in a period's virtual address can occur through:
1. Rounding errors accumulating over multiple distributions
2. Race conditions where multiple beneficiaries claim simultaneously and drain a period
3. Sub-scheme distributions exceeding parent scheme balance [12](#0-11) 
4. Bugs in profit distribution calculations
5. Scheme manager actions affecting virtual address balances

**Complexity**: LOW - No special privileges required, occurs naturally from edge cases in normal operation.

**Detection**: Users discover the issue only when claiming fails. No preventive monitoring exists.

**Probability**: MEDIUM-HIGH - Given complex multi-period, multi-beneficiary, multi-symbol profit schemes with sub-schemes, balance mismatches are reasonably probable over time.

### Recommendation

**Code-Level Mitigation**: Implement balance checking before each `SendVirtualInline()` call in `ProfitAllPeriods()`:

1. Query the virtual address balance for each period before attempting transfer
2. Skip periods with insufficient balance using `continue` (similar to the pattern at lines 532-538)
3. Emit a warning event for skipped periods to enable off-chain monitoring
4. Allow `lastProfitPeriod` to advance past failed periods so users can claim subsequent periods

**Invariant Checks**: Add assertion that verifies virtual address balance >= transfer amount before queuing inline transfers.

**Enhanced Feature**: Consider adding an optional period range parameter to `ClaimProfitsInput` to allow users to claim specific periods, providing granular control and workaround capability.

**Test Cases**: 
- Test claiming with one period having insufficient balance among multiple periods
- Verify that subsequent periods can still be claimed after skipping failed period
- Test concurrent claiming scenarios that could lead to race conditions

### Proof of Concept

**Initial State**:
1. Profit scheme exists with 3 periods (Period 1, 2, 3) that have been distributed
2. Beneficiary has shares in all 3 periods
3. Period 1 virtual address: 100 tokens
4. Period 2 virtual address: 0 tokens (insufficient)
5. Period 3 virtual address: 100 tokens
6. Beneficiary's calculated profit per period: 50 tokens

**Transaction Steps**:
1. Beneficiary calls `ClaimProfits(scheme_id, beneficiary_address)`
2. Function calculates profits for all 3 periods
3. Queues inline transfer for Period 1: 50 tokens (will succeed)
4. Queues inline transfer for Period 2: 50 tokens (will fail - insufficient balance)
5. Queues inline transfer for Period 3: 50 tokens (will not execute)

**Expected Result**: User receives 150 tokens (50 from each period), or at minimum 100 tokens (Periods 1 and 3)

**Actual Result**: 
- Inline transfer for Period 2 fails with "Insufficient balance" error
- Entire transaction reverts
- User receives 0 tokens
- `lastProfitPeriod` remains unchanged
- User cannot claim profits from Period 1 or Period 3 despite sufficient balances
- User is permanently blocked from accessing any profits until Period 2's virtual address is manually funded

**Success Condition for Attack/Bug**: Period 2's virtual address balance < required transfer amount, which can occur through normal operational edge cases without malicious intent.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L532-545)
```csharp
                var balanceOfToken = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = symbol
                });
                if (balanceOfToken.Balance < amount)
                    continue;
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = Context.Self,
                        Amount = amount,
                        Symbol = symbol
                    }.ToByteString());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L606-635)
```csharp
    private long DistributeProfitsForSubSchemes(string symbol, long totalAmount, Scheme scheme, long totalShares)
    {
        Context.LogDebug(() => $"Sub schemes count: {scheme.SubSchemes.Count}");
        var remainAmount = totalAmount;
        foreach (var subSchemeShares in scheme.SubSchemes)
        {
            Context.LogDebug(() => $"Releasing {subSchemeShares.SchemeId}");

            // General ledger of this sub profit scheme.
            var subItemVirtualAddress = Context.ConvertVirtualAddressToContractAddress(subSchemeShares.SchemeId);

            if (State.TokenContract.Value == null)
                State.TokenContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

            var distributeAmount = SafeCalculateProfits(subSchemeShares.Shares, totalAmount, totalShares);
            if (distributeAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = subItemVirtualAddress,
                        Amount = distributeAmount,
                        Symbol = symbol
                    }.ToByteString());

            remainAmount = remainAmount.Sub(distributeAmount);

            // Update current_period of detail of sub profit scheme.
            var subItemDetail = State.ProfitDetailsMap[scheme.SchemeId][subItemVirtualAddress];
            foreach (var detail in subItemDetail.Details) detail.LastProfitPeriod = scheme.CurrentPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L750-808)
```csharp
    public override Empty ClaimProfits(ClaimProfitsInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        if (scheme == null) throw new AssertionException("Scheme not found.");
        var beneficiary = input.Beneficiary ?? Context.Sender;
        var profitDetails = State.ProfitDetailsMap[input.SchemeId][beneficiary];
        if (profitDetails == null) throw new AssertionException("Profit details not found.");

        Context.LogDebug(
            () => $"{Context.Sender} is trying to profit from {input.SchemeId.ToHex()} for {beneficiary}.");

        // LastProfitPeriod is set as 0 at the very beginning, and be updated as current period every time when it is claimed.
        // What's more, LastProfitPeriod can also be +1 more than endPeroid, for it always points to the next period to claim.
        // So if LastProfitPeriod is 0, that means this profitDetail hasn't be claimed before, so just check whether it is a valid one;
        // And if a LastProfitPeriod is larger than EndPeriod, it should not be claimed, and should be removed later.
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();

        Context.LogDebug(() =>
            $"Profitable details: {profitableDetails.Aggregate("\n", (profit1, profit2) => profit1.ToString() + "\n" + profit2)}");

        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
        // Only can get profit from last profit period to actual last period (profit.CurrentPeriod - 1),
        // because current period not released yet.
        for (var i = 0; i < profitableDetailCount; i++)
        {
            var profitDetail = profitableDetails[i];
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
        }

        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;

        foreach (var profitDetail in profitDetailsToRemove)
        {
            availableDetails.Remove(profitDetail);
        }

        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };

        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-912)
```csharp
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
            {
                var periodToPrint = period;
                var detailToPrint = profitDetail;
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;

                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);

                if (!isView)
                {
                    Context.LogDebug(() =>
                        $"{beneficiary} is profiting {amount} {symbol} tokens from {scheme.SchemeId.ToHex()} in period {periodToPrint}." +
                        $"Sender's Shares: {detailToPrint.Shares}, total Shares: {distributedProfitsInformation.TotalShares}");
                    if (distributedProfitsInformation.IsReleased && amount > 0)
                    {
                        if (State.TokenContract.Value == null)
                            State.TokenContract.Value =
                                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());

                        Context.Fire(new ProfitsClaimed
                        {
                            Beneficiary = beneficiary,
                            Symbol = symbol,
                            Amount = amount,
                            ClaimerShares = detailToPrint.Shares,
                            TotalShares = distributedProfitsInformation.TotalShares,
                            Period = periodToPrint
                        });
                    }

                    lastProfitPeriod = period + 1;
                }

                totalAmount = totalAmount.Add(amount);
            }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L239-249)
```csharp
    public void SendVirtualInline(Hash fromVirtualAddress, Address toAddress, string methodName,
        ByteString args)
    {
        TransactionContext.Trace.InlineTransactions.Add(new Transaction
        {
            From = ConvertVirtualAddressToContractAddress(fromVirtualAddress, Self),
            To = toAddress,
            MethodName = methodName,
            Params = args
        });
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L216-246)
```csharp
    private async Task ExecuteInlineTransactions(int depth, Timestamp currentBlockTime,
        ITransactionContext txContext, TieredStateCache internalStateCache,
        IChainContext internalChainContext,
        Hash originTransactionId,
        CancellationToken cancellationToken)
    {
        var trace = txContext.Trace;
        internalStateCache.Update(txContext.Trace.GetStateSets());
        foreach (var inlineTx in txContext.Trace.InlineTransactions)
        {
            var singleTxExecutingDto = new SingleTransactionExecutingDto
            {
                Depth = depth + 1,
                ChainContext = internalChainContext,
                Transaction = inlineTx,
                CurrentBlockTime = currentBlockTime,
                Origin = txContext.Origin,
                OriginTransactionId = originTransactionId
            };

            var inlineTrace = await ExecuteOneAsync(singleTxExecutingDto, cancellationToken);

            if (inlineTrace == null)
                break;
            trace.InlineTraces.Add(inlineTrace);
            if (!inlineTrace.IsSuccessful())
                // Already failed, no need to execute remaining inline transactions
                break;

            internalStateCache.Update(inlineTrace.GetStateSets());
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```

**File:** src/AElf.Kernel.Core/Extensions/TransactionTraceExtensions.cs (L35-45)
```csharp
    public static void SurfaceUpError(this TransactionTrace txTrace)
    {
        foreach (var inline in txTrace.InlineTraces)
        {
            inline.SurfaceUpError();
            if (inline.ExecutionStatus < txTrace.ExecutionStatus)
            {
                txTrace.ExecutionStatus = inline.ExecutionStatus;
                txTrace.Error = $"{inline.Error}";
            }
        }
```

**File:** protobuf/profit_contract.proto (L217-222)
```text
message ClaimProfitsInput {
    // The scheme id.
    aelf.Hash scheme_id = 1;
    // The address of beneficiary.
    aelf.Address beneficiary = 2;
}
```
