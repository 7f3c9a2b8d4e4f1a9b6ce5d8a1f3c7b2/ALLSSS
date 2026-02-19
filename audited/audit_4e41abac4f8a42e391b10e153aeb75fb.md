### Title
State Read Reentrancy via Token Transfer Callbacks Causes State Corruption in Profit Distribution

### Summary
The Profit contract reads state into memory, performs external token transfers via `SendVirtualInline` that can trigger reentrancy through token transfer callbacks, then writes the stale in-memory state back to storage. This violates the checks-effects-interactions pattern and allows attackers to cause state corruption, double-claim profits, and break share accounting invariants.

### Finding Description

**Root Cause**: The contract reads state into local variables, makes external calls that enable reentrancy, then writes the stale local state back, overwriting any state changes made during the reentrant calls.

**Primary Vulnerable Functions**:

1. **ClaimProfits** - Reads scheme and profitDetails into memory, calls `ProfitAllPeriods` which transfers tokens via `SendVirtualInline`, then writes back stale state. [1](#0-0) 

2. **DistributeProfits** - Reads scheme into memory, calls `PerformDistributeProfits` which transfers tokens via `SendVirtualInline`, then writes back stale state including `CurrentPeriod`. [2](#0-1) 

**Reentrancy Vector**: Token transfers execute callbacks if the token has `TransferCallbackExternalInfoKey` configured in its ExternalInfo. The `DealWithExternalInfoDuringTransfer` method calls `Context.SendInline` to invoke the callback contract synchronously. [3](#0-2) 

**Why Protections Fail**: 
- No reentrancy guards exist in the Profit contract
- The contract uses the read-external call-write pattern instead of read-write-external call
- Inline transactions execute synchronously, enabling immediate reentrancy

**Execution Path Example**:
1. User calls `ClaimProfits(schemeId)` 
2. Line 752: scheme read into memory → `var scheme = State.SchemeInfos[input.SchemeId]`
3. Line 784: `ProfitAllPeriods` is called
4. Line 887-895: `SendVirtualInline` transfers tokens to beneficiary [4](#0-3) 
5. Token transfer triggers callback via `DealWithExternalInfoDuringTransfer`
6. Callback contract calls `AddBeneficiary` which updates `State.SchemeInfos[schemeId].TotalShares`
7. Original `ClaimProfits` continues with stale scheme object
8. Line 792: `scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove)` uses stale value
9. Line 799: Stale scheme written back, overwriting the TotalShares change from step 6

### Impact Explanation

**Direct Fund Impact**:
- **Double Claiming**: Beneficiaries can claim the same profits multiple times by triggering reentrancy during the transfer in `ProfitAllPeriods`, allowing them to claim again before `LastProfitPeriod` is properly updated and written to state
- **Reward Misallocation**: `TotalShares` becomes incorrect when modifications during reentrancy are overwritten, causing future profit distributions to use wrong denominators in `SafeCalculateProfits`, leading to incorrect per-share amounts
- **State Inconsistency**: `CurrentPeriod`, `ReceivedTokenSymbols`, `SubSchemes`, and `ProfitDetailsMap` can all become corrupted when stale values overwrite live state

**Economics & Treasury Invariant Violations**:
- Share calculations broken: The invariant "Profit/Treasury/TokenHolder share calculations, donation/release logic, dividend distribution and settlement accuracy" is violated
- TotalShares can become less than the sum of individual beneficiary shares, or fail to decrease when beneficiaries are removed
- CachedDelayTotalShares can desynchronize from actual TotalShares

**Quantified Damage**:
- A beneficiary with X% shares could claim X% of profits multiple times per period
- If TotalShares is artificially reduced via reentrancy overwrites, remaining beneficiaries receive inflated shares
- Scheme corruption could affect all beneficiaries in a scheme (potentially thousands of users for system-wide schemes like consensus rewards)

**Affected Parties**:
- All beneficiaries of profit schemes using tokens with transfer callbacks
- Scheme managers whose schemes become corrupted
- Protocol integrity if system contracts like Treasury/TokenHolder are affected

### Likelihood Explanation

**Attacker Capabilities Required**:
- Deploy a token with `TransferCallbackExternalInfoKey` in ExternalInfo pointing to a malicious callback contract
- Become a beneficiary in a profit scheme (achievable for public schemes) OR contribute the malicious token to a scheme
- Trigger `ClaimProfits` or wait for `DistributeProfits` to be called by the scheme manager

**Attack Complexity**: MEDIUM
- Token transfer callback feature exists in TokenContract by design [5](#0-4) 
- No special privileges required beyond being a beneficiary
- Inline transactions execute synchronously in AElf, enabling immediate reentrancy
- No reentrancy guards detected in Profit contract (grep found zero matches)

**Feasibility Conditions**:
- ✅ Reachable from public entry point `ClaimProfits` (anyone can call for themselves)
- ✅ Token creation with callbacks is standard TokenContract feature
- ✅ SendVirtualInline enables synchronous execution, proven by execution model
- ✅ Multiple state write-backs occur after external calls in both `ClaimProfits` and `DistributeProfits`

**Detection/Operational Constraints**:
- Difficult to detect: state corruption may appear as accounting errors rather than obvious attacks
- No transaction size limits prevent the attack
- Can be executed across multiple blocks to avoid detection
- Callback execution is a standard token feature, not inherently suspicious

**Probability Assessment**: HIGH for schemes using tokens with transfer callbacks, MEDIUM overall given that:
- Feature exists and is documented
- No reentrancy protections in place
- Multiple attack vectors (ClaimProfits, DistributeProfits, DistributeProfitsForSubSchemes)
- Economic incentive is clear (claim profits multiple times or manipulate shares)

### Recommendation

**Immediate Fix**: Implement the checks-effects-interactions pattern by writing all state changes BEFORE making external calls.

**Specific Code Changes**:

1. **For ClaimProfits**: Move state writes before `ProfitAllPeriods`:
   - Update `State.SchemeInfos[scheme.SchemeId]` BEFORE calling `ProfitAllPeriods`
   - Update `State.ProfitDetailsMap[input.SchemeId][beneficiary]` BEFORE making transfers
   - Modify `ProfitAllPeriods` to accept and return updated state rather than updating during execution

2. **For DistributeProfits**: Move scheme update before external calls:
   - Update `scheme.CurrentPeriod` and write to `State.SchemeInfos[input.SchemeId]` BEFORE calling `UpdateDistributedProfits` or `PerformDistributeProfits`

3. **Add Reentrancy Guard**: Implement a simple boolean flag:
   ```
   State.MappedState<Hash, bool> IsDistributing
   
   // At start of ClaimProfits/DistributeProfits:
   Assert(!State.IsDistributing[schemeId], "Reentrancy detected");
   State.IsDistributing[schemeId] = true;
   
   // At end (including all return paths):
   State.IsDistributing[schemeId] = false;
   ```

4. **Alternative**: Separate token transfers into a post-processing phase that only occurs after all state updates are complete.

**Invariant Checks to Add**:
- Assert `TotalShares == sum of all beneficiary shares` after any modification
- Assert `scheme.CurrentPeriod` only increases monotonically
- Add events for state changes to enable external monitoring

**Test Cases**:
- Test `ClaimProfits` with a token that has a callback calling `ClaimProfits` again
- Test `DistributeProfits` with a callback calling `AddBeneficiary` 
- Test that `TotalShares` remains consistent across reentrant calls
- Verify state writes occur before external calls in all distribution paths

### Proof of Concept

**Required Initial State**:
1. Deploy malicious token `MAL` with `TransferCallbackExternalInfoKey` pointing to `AttackerCallback` contract
2. Create profit scheme `SCHEME1` with attacker as beneficiary with 100 shares, TotalShares=200
3. Contribute 1000 MAL tokens to SCHEME1
4. Call `DistributeProfits` to release period 1

**Attack Steps**:

**Transaction 1** - Attacker calls `ClaimProfits(schemeId=SCHEME1, beneficiary=attacker)`:
- `ClaimProfits` reads: `scheme.TotalShares = 200`, `scheme.CurrentPeriod = 2`
- `ClaimProfits` enters loop, calls `ProfitAllPeriods`
- `ProfitAllPeriods` line 887: `SendVirtualInline` transfers 500 MAL to attacker
- MAL transfer triggers `DealWithExternalInfoDuringTransfer` callback
- `AttackerCallback` invoked with transfer details

**Transaction 1.1** - `AttackerCallback` executes synchronously:
- Calls `AddBeneficiary(schemeId=SCHEME1, beneficiary=attacker2, shares=100)`
- `AddBeneficiary` updates: `State.SchemeInfos[SCHEME1].TotalShares = 300`
- Returns to original `ClaimProfits`

**Transaction 1 (continued)**:
- `ClaimProfits` continues with stale `scheme.TotalShares = 200`
- Line 792: calculates `sharesToRemove` (may be 0 or incorrect)
- Line 799: `State.SchemeInfos[SCHEME1] = scheme` writes back `TotalShares = 200`
- **Result**: TotalShares reverted from 300 to 200, losing the `attacker2` shares

**Expected vs Actual**:
- **Expected**: TotalShares = 300 (original 200 + attacker2's 100)
- **Actual**: TotalShares = 200 (overwritten with stale value)
- **Success Condition**: Read `State.SchemeInfos[SCHEME1].TotalShares` after Transaction 1 completes, verify it equals 200 instead of expected 300

**Alternative PoC** - Double Claiming:
- Callback calls `ClaimProfits` again for same beneficiary
- Second call succeeds because first hasn't updated `LastProfitPeriod` in state yet
- Attacker receives 2x profits for same period

### Notes

The vulnerability exists because AElf's inline transaction model executes synchronously (depth-first), and the TokenContract's transfer callback feature (`DealWithExternalInfoDuringTransfer`) enables arbitrary external contract calls during transfers. The Profit contract lacks reentrancy guards and follows the vulnerable pattern of read-external call-write instead of read-write-external call. This is a critical violation of the stated invariant: "Profit/Treasury/TokenHolder share calculations, donation/release logic, dividend distribution and settlement accuracy."

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L417-499)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        if (input.AmountsMap.Any())
            Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");

        ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

        var profitsMap = new Dictionary<string, long>();
        if (input.AmountsMap.Any())
        {
            foreach (var amount in input.AmountsMap)
            {
                var actualAmount = amount.Value == 0
                    ? State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = amount.Key
                    }).Balance
                    : amount.Value;
                profitsMap.Add(amount.Key, actualAmount);
            }
        }
        else
        {
            if (scheme.IsReleaseAllBalanceEveryTimeByDefault && scheme.ReceivedTokenSymbols.Any())
                // Prepare to distribute all from general ledger.
                foreach (var symbol in scheme.ReceivedTokenSymbols)
                {
                    var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = symbol
                    }).Balance;
                    profitsMap.Add(symbol, balance);
                }
        }

        var totalShares = scheme.TotalShares;

        if (scheme.DelayDistributePeriodCount > 0)
        {
            scheme.CachedDelayTotalShares.Add(input.Period.Add(scheme.DelayDistributePeriodCount), totalShares);
            if (scheme.CachedDelayTotalShares.ContainsKey(input.Period))
            {
                totalShares = scheme.CachedDelayTotalShares[input.Period];
                scheme.CachedDelayTotalShares.Remove(input.Period);
            }
            else
            {
                totalShares = 0;
            }
        }

        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");

        var profitsReceivingVirtualAddress =
            GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, releasingPeriod);

        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);

        Context.LogDebug(() => $"Receiving virtual address: {profitsReceivingVirtualAddress}");

        UpdateDistributedProfits(profitsMap, profitsReceivingVirtualAddress, totalShares);

        PerformDistributeProfits(profitsMap, scheme, totalShares, profitsReceivingVirtualAddress);

        scheme.CurrentPeriod = input.Period.Add(1);

        State.SchemeInfos[input.SchemeId] = scheme;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L750-809)
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
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L887-896)
```csharp
                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());

```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L337-350)
```csharp
    private void DealWithExternalInfoDuringTransfer(TransferFromInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo.ExternalInfo == null) return;
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.TransferCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.TransferCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
        }

        FireExternalLogEvent(tokenInfo, input);
    }
```
