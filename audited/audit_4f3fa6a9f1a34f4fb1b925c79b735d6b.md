### Title
TokenHolder Scheme Configuration Overwrite Allows Violation of Lock Agreements

### Summary
The `CreateScheme` function in TokenHolderContract lacks protection against being called multiple times by the same scheme manager. This allows a malicious scheme manager to arbitrarily change the `Symbol` or `MinimumLockMinutes` parameters after users have already locked their tokens, breaking the lock agreement users entered into and potentially causing permanent fund loss or allowing unintended early withdrawals.

### Finding Description

The `CreateScheme` function has no check to prevent a scheme manager from calling it multiple times. [1](#0-0) 

Each invocation unconditionally overwrites the `State.TokenHolderProfitSchemes[Context.Sender]` mapping with new values for `Symbol`, `MinimumLockMinutes`, and `AutoDistributeThreshold`. [2](#0-1) 

While each call to `CreateScheme` creates a new profit scheme in the underlying Profit contract, [3](#0-2)  the `GetValidScheme` function always retrieves the first scheme ID via `FirstOrDefault()`. [4](#0-3) 

The critical issue is that when users register for profits, they lock tokens using the current `scheme.Symbol` value. [5](#0-4)  The lock timestamp is recorded with the expectation that `MinimumLockMinutes` will remain constant. [6](#0-5) 

However, when users attempt to withdraw, the `Withdraw` function uses the **current** `scheme.Symbol` and `scheme.MinimumLockMinutes` values from the overwritten state. [7](#0-6) 

**Root Cause:** Missing validation to prevent duplicate scheme creation by the same manager, combined with state overwriting instead of updating.

**Why Existing Protections Fail:** 
- No assertion checking if a scheme already exists for `Context.Sender`
- The Profit contract's `CreateScheme` prevents duplicate scheme IDs (different on each call due to counter-based ID generation), [8](#0-7)  but doesn't prevent the same manager from creating multiple schemes [9](#0-8) 
- Test suite shows protection against repeated `RegisterForProfits` calls but no equivalent test for repeated `CreateScheme` calls [10](#0-9) 

### Impact Explanation

**Attack Scenario 1 - Symbol Change (Permanent DoS):**
- Users lock ELF tokens under a scheme with `Symbol="ELF"`
- Scheme manager calls `CreateScheme` again with `Symbol="USDT"`
- When users attempt withdrawal, `GetLockedAmount` queries for USDT locks instead of ELF [11](#0-10) 
- The query returns 0 amount (tokens were locked as ELF, not USDT)
- Users cannot unlock their ELF tokens - **permanent fund loss**

**Attack Scenario 2 - MinimumLockMinutes Reduction (Early Withdrawal):**
- Scheme manager creates scheme with `MinimumLockMinutes=10000` (≈7 days)
- Users lock tokens expecting a 10000-minute minimum lock period
- Scheme manager calls `CreateScheme` with `MinimumLockMinutes=1`
- Users (or the scheme manager as a beneficiary) can withdraw after 1 minute instead of 10000 minutes [12](#0-11) 
- Violates profit distribution timeframe expectations

**Attack Scenario 3 - MinimumLockMinutes Increase (Extended Lock):**
- Users lock tokens with `MinimumLockMinutes=100`
- Scheme manager calls `CreateScheme` with `MinimumLockMinutes=1000000`
- Users cannot withdraw for 1000000 minutes (≈694 days) instead of expected 100 minutes
- Funds locked far beyond user consent

**Who is Affected:**
- All users who registered for profits under the original scheme parameters
- Potentially thousands of token holders if scheme is popular
- Trust in TokenHolder contract mechanism is undermined

**Severity Justification:** HIGH
- Direct fund impact: Complete loss of access to locked funds or unintended early access
- Breaks critical invariant: "lock/unlock correctness" from the audit requirements
- Violates user expectations and lock agreements explicitly
- No recovery mechanism exists for affected users

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be the scheme manager (original creator of the scheme via `CreateScheme`)
- No additional authorization or governance approval required
- Can be executed by any address that previously called `CreateScheme`

**Attack Complexity:**
- Extremely simple: Single transaction calling `CreateScheme` with modified parameters
- No complex state manipulation or multi-step process required
- No timing constraints or dependencies

**Feasibility Conditions:**
- Scheme manager role is not a privileged trusted role - any address can create schemes
- Nothing prevents the scheme creator from being malicious from the start
- Economic cost is minimal (just transaction fees)

**Detection Constraints:**
- State change is visible on-chain but users may not monitor for scheme parameter changes
- No event emission specifically for scheme parameter updates
- Users would only detect the issue when attempting withdrawal

**Economic Rationality:**
- Malicious scheme manager could benefit by:
  - Reducing `MinimumLockMinutes` to withdraw their own registered profits early
  - Changing `Symbol` to DoS competitors' locked funds
  - Creating griefing attacks at minimal cost
- Legitimate scenario where accident could occur: Scheme manager trying to "update" configuration

**Probability Assessment:** HIGH
- Public function with no access controls beyond being the original creator
- Simple to execute, whether maliciously or accidentally
- No disincentive mechanism to prevent this behavior

### Recommendation

**Code-Level Mitigation:**

1. Add an existence check in `CreateScheme` to prevent duplicate creation:
```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
           "Scheme already exists for this address.");
    // ... rest of function
}
```

2. Alternatively, create a separate `UpdateScheme` function with appropriate constraints:
   - Only allow updates if no users have registered yet
   - Emit events when parameters change
   - Add governance controls for parameter updates after users register

3. Store scheme parameters in the Profit contract scheme itself rather than in TokenHolder state, making them immutable after creation.

**Invariant Checks to Add:**

1. Assert in `Withdraw` that scheme configuration hasn't changed since user's `RegisterForProfits` call
2. Add validation that `Symbol` matches the originally locked token symbol
3. Track original `MinimumLockMinutes` per lock ID to prevent retroactive changes

**Test Cases to Prevent Regression:**

1. Test calling `CreateScheme` twice from same address - should fail with "already exists" error
2. Test that changing scheme parameters after users register causes appropriate failure/protection
3. Test withdrawal with mismatched Symbol parameter - should fail safely
4. Test that `MinimumLockMinutes` used in withdrawal matches value at registration time

### Proof of Concept

**Initial State:**
- Alice (scheme manager address: 0xAAA) has never created a TokenHolder scheme
- Bob (user address: 0xBBB) has 10000 ELF tokens

**Attack Steps:**

1. **Alice creates initial scheme:**
   ```
   CreateScheme({
     Symbol: "ELF",
     MinimumLockMinutes: 10000
   })
   ```
   - Transaction succeeds
   - State.TokenHolderProfitSchemes[0xAAA] = {Symbol: "ELF", MinimumLockMinutes: 10000}

2. **Bob registers and locks tokens:**
   ```
   RegisterForProfits({
     SchemeManager: 0xAAA,
     Amount: 10000
   })
   ```
   - 10000 ELF tokens locked with lockId = hash(0xAAA, 0xBBB)
   - State.LockTimestamp[lockId] = CurrentBlockTime (e.g., T0)
   - Bob expects to wait 10000 minutes before withdrawal

3. **Alice calls CreateScheme again (attack):**
   ```
   CreateScheme({
     Symbol: "USDT",
     MinimumLockMinutes: 1
   })
   ```
   - Transaction succeeds (no validation prevents this)
   - State.TokenHolderProfitSchemes[0xAAA] = {Symbol: "USDT", MinimumLockMinutes: 1}
   - Bob's locked ELF tokens now orphaned

4. **Bob attempts withdrawal after 10000+ minutes:**
   ```
   Withdraw(0xAAA)
   ```
   - GetValidScheme retrieves {Symbol: "USDT", MinimumLockMinutes: 1}
   - GetLockedAmount queries for USDT with Bob's lockId
   - Returns 0 (tokens locked as ELF, not USDT)
   - **Transaction fails or Bob cannot withdraw his 10000 ELF**

**Expected Result:** Bob should be able to withdraw his 10000 ELF tokens after 10000 minutes

**Actual Result:** Bob cannot withdraw his tokens because Symbol mismatch causes GetLockedAmount to return 0

**Success Condition:** Attack succeeds if State.TokenHolderProfitSchemes can be overwritten and affects existing locks, which is confirmed by the code paths shown above.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-35)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
    {
        if (State.ProfitContract.Value == null)
            State.ProfitContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });

        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-165)
```csharp
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L167-167)
```csharp
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L220-228)
```csharp
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;

        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-293)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-59)
```csharp
        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L62-71)
```csharp
        var schemeIds = State.ManagingSchemeIds[scheme.Manager];
        if (schemeIds == null)
            schemeIds = new CreatedSchemeIds
            {
                SchemeIds = { schemeId }
            };
        else
            schemeIds.SchemeIds.Add(schemeId);

        State.ManagingSchemeIds[scheme.Manager] = schemeIds;
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L306-324)
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
```
