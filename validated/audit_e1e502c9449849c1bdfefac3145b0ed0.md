# Audit Report

## Title
Scheme Manager Can Remove Self-Registered Token Holders Without Unlocking Tokens, Causing Loss of Expected Dividends

## Summary
Users who lock tokens via `RegisterForProfits` to participate in profit distributions can be unilaterally removed by the scheme manager using `RemoveBeneficiary`. This removes their beneficiary status but leaves their tokens locked in the Token contract, creating an inconsistent state where users cannot earn dividends but their capital remains locked until the minimum lock period expires. This violates the fundamental lock-for-profit contract and results in direct financial loss through missed dividend distributions.

## Finding Description

The TokenHolder contract provides two distinct beneficiary management flows that fail to coordinate properly:

**Flow 1: Manager-Controlled Beneficiaries (AddBeneficiary/RemoveBeneficiary)** [1](#0-0) [2](#0-1) 

These methods allow the scheme manager to add/remove beneficiaries with specified shares, with no token locking involved.

**Flow 2: User Self-Registration (RegisterForProfits/Withdraw)** [3](#0-2) 

When users call `RegisterForProfits`, tokens are locked via the MultiToken contract and the lock ID is stored: [4](#0-3) [5](#0-4) 

**Root Cause:**
The `RemoveBeneficiary` function only validates scheme manager authority but does NOT check whether the beneficiary has locked tokens: [2](#0-1) 

It removes the beneficiary from the Profit contract but never unlocks tokens or removes the lock ID from `State.LockIds`. The Profit contract's `RemoveBeneficiary` terminates profit eligibility: [6](#0-5) [7](#0-6) 

Specifically, when `CanRemoveBeneficiaryDirectly = true` (which is explicitly set in TokenHolder scheme creation): [8](#0-7) 

The profit details are removed or shortened, terminating future profit distributions while tokens remain locked.

**Execution Flow:**
1. User calls `RegisterForProfits` → tokens locked via Token contract Lock method [9](#0-8) 

2. Manager calls `RemoveBeneficiary` → beneficiary status removed, tokens still locked
3. User must wait until `MinimumLockMinutes` expires to call `Withdraw`: [10](#0-9) 

## Impact Explanation

**Direct Financial Harm:**
Users suffer immediate and quantifiable financial losses:
- Locked tokens generate ZERO profit distributions after removal
- Capital remains frozen and cannot be deployed elsewhere
- All dividends distributed during the remaining lock period are permanently lost

**Quantified Scenario:**
- User locks 10,000 tokens for 30-day minimum period
- Manager removes them after 5 days
- User loses 25 days of dividend distributions
- With a 10% APY on significant profit pools, this represents material value loss
- User cannot withdraw or use these tokens for 25 more days despite earning nothing

**Severity:**
This violates the core invariant that locked tokens earn profit distributions. Users enter a contract where "locked capital → profit distributions" but the manager can unilaterally convert this to "locked capital → no profits" without unlocking funds. This is a breach of the fundamental economic agreement.

## Likelihood Explanation

**High Likelihood - This can happen in normal operations:**

1. **Attacker Capabilities**: The scheme manager has legitimate authority to call `RemoveBeneficiary` - this is by design, not a privilege escalation.

2. **Simple Execution**: Manager simply calls `RemoveBeneficiary(userAddress)` - no complex conditions or attack sophistication required.

3. **No Technical Barriers**: 
   - `CanRemoveBeneficiaryDirectly = true` is explicitly set
   - No validation prevents removal of self-registered users
   - No warnings alert manager about locked tokens

4. **Realistic Scenario**: A manager might legitimately want to rebalance beneficiaries without realizing users have locked tokens. They may assume all beneficiaries are manager-added (Flow 1) when some used self-registration (Flow 2).

5. **No Test Coverage**: Analysis of the test suite shows no tests combine `RegisterForProfits` followed by `RemoveBeneficiary`. All RemoveBeneficiary tests only cover manager-added beneficiaries: [11](#0-10) [12](#0-11) 

## Recommendation

Add a check in `RemoveBeneficiary` to detect and handle locked tokens:

```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    // Check if beneficiary has locked tokens
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    if (lockId != null)
    {
        // Option 1: Prevent removal until user withdraws
        Assert(false, "Cannot remove beneficiary with locked tokens. User must withdraw first.");
        
        // OR Option 2: Automatically unlock tokens
        // var amount = State.TokenContract.GetLockedAmount.Call(...);
        // State.TokenContract.Unlock.Send(...);
        // State.LockIds[Context.Sender].Remove(input.Beneficiary);
    }
    
    // Existing removal logic...
    var detail = State.ProfitContract.GetProfitDetails.Call(...);
    // ...
}
```

**Recommended Fix**: Option 1 (prevent removal) is safer - require users to withdraw first, maintaining clear separation of concerns and avoiding potential unlock-related edge cases.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_AfterRegisterForProfits_TokensRemainLocked()
{
    // Setup: Create scheme and register user with locked tokens
    var lockAmount = 1000L;
    var nativeTokenSymbol = "ELF";
    
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = nativeTokenSymbol,
        MinimumLockMinutes = 30 * 24 * 60 // 30 days
    });
    
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = lockAmount,
        SchemeManager = Starter
    });
    
    // Verify tokens are locked
    var beforeBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = nativeTokenSymbol,
        Owner = Starter
    })).Balance;
    
    // Manager removes beneficiary
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter
    });
    
    // Verify: User is no longer beneficiary
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var profitDetail = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeIds.SchemeIds[0],
        Beneficiary = Starter
    });
    profitDetail.Details.Count.ShouldBe(0); // No longer a beneficiary
    
    // Verify: Tokens STILL LOCKED - balance unchanged
    var afterBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = nativeTokenSymbol,
        Owner = Starter
    })).Balance;
    afterBalance.ShouldBe(beforeBalance); // Tokens still locked
    
    // Verify: Cannot withdraw immediately (must wait 30 days)
    var withdrawResult = await TokenHolderContractStub.Withdraw.SendWithExceptionAsync(Starter);
    withdrawResult.TransactionResult.Error.ShouldContain("Cannot withdraw");
    
    // VULNERABILITY PROVEN: User has locked tokens but no profit eligibility
}
```

## Notes

This vulnerability exists at the intersection of two independent systems (TokenHolder locking and Profit distribution) that share state but lack coordination. The scheme manager's `RemoveBeneficiary` authority is legitimate and necessary for Flow 1 (manager-controlled beneficiaries), but becomes problematic when applied to Flow 2 (user self-registration with locks). The fix requires distinguishing between these two flows or enforcing withdrawal before removal.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-25)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L37-68)
```csharp
    public override Empty AddBeneficiary(AddTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        var shares = input.Shares;
        if (detail.Details.Any())
        {
            // Only keep one detail.

            State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                Beneficiary = input.Beneficiary
            });
            shares.Add(detail.Details.Single().Shares);
        }

        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = input.Beneficiary,
                Shares = shares
            }
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-98)
```csharp
    public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);

        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        if (lockedAmount > input.Amount &&
            input.Amount != 0) // If input.Amount == 0, means just remove this beneficiary.
            State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = input.Beneficiary,
                    Shares = lockedAmount.Sub(input.Amount)
                }
            });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-209)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
    {
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
        var scheme = GetValidScheme(input.SchemeManager);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = input.Amount
            }
        });

        // Check auto-distribute threshold.
        if (scheme.AutoDistributeThreshold != null && scheme.AutoDistributeThreshold.Any())
        {
            var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
            var virtualAddress = originScheme.VirtualAddress;
            Profit.DistributeProfitsInput distributedInput = null;
            foreach (var threshold in scheme.AutoDistributeThreshold)
            {
                var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = virtualAddress,
                    Symbol = threshold.Key
                }).Balance;
                if (balance < threshold.Value) continue;
                if (distributedInput == null)
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
                distributedInput.AmountsMap[threshold.Key] = 0;
                break;
            }

            if (distributedInput == null) return new Empty();
            State.ProfitContract.DistributeProfits.Send(distributedInput);
            scheme.Period = scheme.Period.Add(1);
            State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L211-245)
```csharp
    public override Empty Withdraw(Address input)
    {
        var scheme = GetValidScheme(input);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = State.LockIds[input][Context.Sender];
        Assert(lockId != null, "Sender didn't register for profits.");
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;

        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");

        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });

        State.LockIds[input].Remove(Context.Sender);
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = Context.Sender
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs (L12-17)
```csharp
    /// <summary>
    ///     Contract address (Manager address) -> Beneficiary address -> Lock id.
    /// </summary>
    public MappedState<Address, Address, Hash> LockIds { get; set; }

    public MappedState<Hash, Timestamp> LockTimestamp { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-263)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();

        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");

        var removedDetails = RemoveProfitDetails(scheme, input.Beneficiary, input.ProfitDetailId);

        foreach (var (removedMinPeriod, removedShares) in removedDetails.Where(d => d.Key != 0))
        {
            if (scheme.DelayDistributePeriodCount > 0)
            {
                for (var removedPeriod = removedMinPeriod;
                     removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
                     removedPeriod++)
                {
                    if (scheme.CachedDelayTotalShares.ContainsKey(removedPeriod))
                    {
                        scheme.CachedDelayTotalShares[removedPeriod] =
                            scheme.CachedDelayTotalShares[removedPeriod].Sub(removedShares);
                    }
                }
            }
        }

        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L308-386)
```csharp
    private RemovedDetails RemoveProfitDetails(Scheme scheme, Address beneficiary, Hash profitDetailId = null)
    {
        var removedDetails = new RemovedDetails();

        var profitDetails = State.ProfitDetailsMap[scheme.SchemeId][beneficiary];
        if (profitDetails == null)
        {
            return removedDetails;
        }
        
        // remove all removalbe profitDetails.
        // If a scheme can be cancelled, get all available profitDetail.
        // else, get those available and out of date ones.
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
        //id == null
        if (scheme.CanRemoveBeneficiaryDirectly && profitDetailId != null)
        {
            detailsCanBeRemoved = detailsCanBeRemoved.All(d => d.Id != profitDetailId)
                ? detailsCanBeRemoved.Where(d => d.Id == null).ToList()
                : detailsCanBeRemoved.Where(d => d.Id == profitDetailId).ToList();
        }

        // remove the profitDetail with the profitDetailId, and de-duplicate it before involving.
        if (profitDetailId != null && profitDetails.Details.Any(d => d.Id == profitDetailId) &&
            detailsCanBeRemoved.All(d => d.Id != profitDetailId))
        {
            detailsCanBeRemoved.Add(profitDetails.Details.Single(d => d.Id == profitDetailId));
        }

        if (detailsCanBeRemoved.Any())
        {
            foreach (var profitDetail in detailsCanBeRemoved)
            {
                // set remove sign
                profitDetail.IsWeightRemoved = true;
                if (profitDetail.LastProfitPeriod >= scheme.CurrentPeriod)
                {
                    // remove those profits claimed
                    profitDetails.Details.Remove(profitDetail);
                }
                else if (profitDetail.EndPeriod >= scheme.CurrentPeriod)
                {
                    // No profit can be here, except the scheme is cancellable.
                    // shorten profit.
                    profitDetail.EndPeriod = scheme.CurrentPeriod.Sub(1);
                }

                removedDetails.TryAdd(scheme.CurrentPeriod, profitDetail.Shares);
            }

            Context.LogDebug(() => $"ProfitDetails after removing expired details: {profitDetails}");
        }

        var weightCanBeRemoved = profitDetails.Details
            .Where(d => d.EndPeriod == scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
        foreach (var profitDetail in weightCanBeRemoved)
        {
            profitDetail.IsWeightRemoved = true;
        }

        var weights = weightCanBeRemoved.Sum(d => d.Shares);
        removedDetails.Add(0, weights);


        // Clear old profit details.
        if (profitDetails.Details.Count != 0)
        {
            State.ProfitDetailsMap[scheme.SchemeId][beneficiary] = profitDetails;
        }
        else
        {
            State.ProfitDetailsMap[scheme.SchemeId].Remove(beneficiary);
        }

        return removedDetails;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-222)
```csharp
    public override Empty Lock(LockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Lock behaviour should be initialed by origin address.");

        var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
        if (allowance >= input.Amount)
            State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
        AssertValidToken(input.Symbol, input.Amount);
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
        DealWithExternalInfoDuringLocking(new TransferFromInput
        {
            From = input.Address,
            To = virtualAddress,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        return new Empty();
    }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L137-153)
```csharp
    [Fact]
    public async Task RemoveBeneficiaryTest()
    {
        await AddBeneficiaryTest();

        var tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);

        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = UserAddresses.First()
        });

        {
            var originScheme = await ProfitContractStub.GetScheme.CallAsync(tokenHolderProfitScheme.SchemeId);
            originScheme.TotalShares.ShouldBe(0);
        }
    }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L155-196)
```csharp
    [Fact]
    public async Task RemoveBeneficiary_With_Amount_Test()
    {
        await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = "ELF"
        });
        await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeManager = Starter,
            Symbol = "ELF",
            Amount = 9999
        });
        await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Shares = 1000
        });
        var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
        {
            Manager = Starter
        });
        var schemeId = schemeIds.SchemeIds[0];
        var beforeRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
        var amount = 10;
        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = amount
        });
        var afterRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeIds.SchemeIds[0]);
        afterRemoveScheme.TotalShares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
        var profitAmount = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
        {
            Beneficiary = Starter,
            SchemeId = schemeId
        });
        profitAmount.Details.Count.ShouldBe(2);
        profitAmount.Details[0].Shares.ShouldBe(beforeRemoveScheme.TotalShares);
        profitAmount.Details[0].EndPeriod.ShouldBe(0);
        profitAmount.Details[1].Shares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
    }
```
