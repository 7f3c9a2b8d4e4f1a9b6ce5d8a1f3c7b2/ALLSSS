### Title
Re-Registration DOS Prevents Stake Increases Without Full Withdrawal

### Summary
The `RegisterForProfits` function enforces a one-time registration limit per user per scheme through a null check on `LockIds`, preventing users from increasing their locked token stake without first withdrawing completely. This forces users to wait for the minimum lock period, lose beneficiary status temporarily, and potentially miss profit distributions during the transition, creating an operational DOS for stake increases.

### Finding Description

The vulnerability exists in the `RegisterForProfits` function where line 151 enforces a strict registration check: [1](#0-0) 

This assertion prevents any user who has previously registered from calling `RegisterForProfits` again to lock additional tokens. The lockId is stored upon first registration: [2](#0-1) 

The only way to clear this lockId is through the `Withdraw` function, which removes the registration entirely: [3](#0-2) 

However, withdrawal requires the minimum lock period to have elapsed: [4](#0-3) 

The `AddBeneficiary` function can update shares but is restricted to the scheme manager and does not lock tokens: [5](#0-4) 

This behavior is confirmed by the test case that explicitly validates the re-registration failure: [6](#0-5) 

### Impact Explanation

**Affected Users**: All users who have registered for profits and wish to increase their locked stake.

**Concrete Harm**:
1. **Forced Complete Withdrawal**: Users must fully withdraw their stake to increase it, losing all current position
2. **Time Delay**: Users must wait for `MinimumLockMinutes` to pass before withdrawal is permitted
3. **Missed Profit Distributions**: During the withdrawal and re-registration window, users have no beneficiary status and miss any profit distributions
4. **Reset Lock Period**: Upon re-registration, the minimum lock period resets, creating a new waiting period
5. **Operational DOS**: The legitimate action of increasing stake is completely blocked without destructive workaround

**Severity Justification - Medium**: While no funds are directly stolen or lost, the operational impact is significant. Users experience:
- Loss of profit accrual during transitions
- Time-locked inability to adjust positions
- Forced all-or-nothing stake management
- Degraded user experience for a fundamental DeFi operation (stake increase)

### Likelihood Explanation

**Attacker Capabilities**: None required - this affects legitimate users attempting normal operations.

**Attack Complexity**: Trivial - any user who has called `RegisterForProfits` once will encounter this limitation when attempting to increase stake.

**Feasibility Conditions**:
1. User has previously called `RegisterForProfits` for a scheme
2. User wants to lock additional tokens to increase their stake
3. User calls `RegisterForProfits` again with a larger amount

**Expected Frequency**: High - increasing stake is a common DeFi pattern. Users regularly want to compound earnings or add capital to existing positions.

**Probability**: Certain - 100% of users attempting to increase stake without first withdrawing will be blocked by the assertion at line 151.

### Recommendation

**Immediate Fix**: Implement an `IncreaseStake` function or modify `RegisterForProfits` to support increasing locked amounts for existing registrations:

```csharp
public override Empty RegisterForProfits(RegisterForProfitsInput input)
{
    var existingLockId = State.LockIds[input.SchemeManager][Context.Sender];
    var scheme = GetValidScheme(input.SchemeManager);
    
    if (existingLockId == null)
    {
        // New registration - existing code path
        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput { ... });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
        // Add beneficiary with input.Amount shares
    }
    else
    {
        // Increase stake - lock additional tokens and update shares
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = existingLockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        // Update beneficiary shares by adding input.Amount to existing shares
    }
    
    // Auto-distribute logic remains the same
    return new Empty();
}
```

**Invariant Checks**:
1. Verify total locked amount matches beneficiary shares after stake increases
2. Ensure lock timestamp is only set on initial registration, not on increases
3. Validate that partial withdrawals (if implemented) maintain proper share-to-lock ratios

**Test Cases**:
1. Test increasing stake multiple times for the same user/scheme
2. Test that lock amounts accumulate correctly with multiple increases
3. Test that beneficiary shares reflect total locked amount after increases
4. Test that profit distributions work correctly after stake increases
5. Test edge cases: increasing by zero, increasing after partial distributions

### Proof of Concept

**Initial State**:
- User has 1000 ELF tokens
- Scheme exists with 10-minute minimum lock period
- User has not yet registered

**Transaction Sequence**:

1. User calls `RegisterForProfits` with 100 ELF
   - **Result**: Success - 100 ELF locked, user becomes beneficiary with 100 shares

2. User acquires 200 more ELF and wants to increase stake to 300 ELF total

3. User calls `RegisterForProfits` with 200 ELF
   - **Expected**: Additional 200 ELF locked, shares increase to 300
   - **Actual**: Transaction fails with "Already registered." error from line 151 assertion

4. User attempts workaround: calls `Withdraw`
   - **Result**: Fails with "Cannot withdraw." if < 10 minutes have passed

5. After 10+ minutes, user calls `Withdraw`
   - **Result**: All 100 ELF unlocked, beneficiary status removed, misses any pending profits

6. User calls `RegisterForProfits` with 300 ELF
   - **Result**: Success, but lock period resets and user lost profit accrual during steps 4-6

**Success Condition**: The user should be able to increase their stake from 100 to 300 ELF in step 3 without needing to withdraw, maintaining continuous beneficiary status and profit eligibility throughout.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L37-67)
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L151-151)
```csharp
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L166-166)
```csharp
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L238-238)
```csharp
        State.LockIds[input].Remove(Context.Sender);
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L306-325)
```csharp
    public async Task RegisterForProfits_Repeatedly_Test()
    {
        await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = "ELF",
            AutoDistributeThreshold = { { "ELF", 1000 } }
        });
        await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
        {
            Amount = 10,
            SchemeManager = Starter
        });
        var repeatRegisterRet = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
            new RegisterForProfitsInput
            {
                Amount = 10,
                SchemeManager = Starter
            });
        repeatRegisterRet.TransactionResult.Error.ShouldContain("Already registered.");
    }
```
