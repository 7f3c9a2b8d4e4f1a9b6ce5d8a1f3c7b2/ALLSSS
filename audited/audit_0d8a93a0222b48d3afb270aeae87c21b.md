### Title
Null Reference Exception in GetManagingSchemeIds Causes TokenHolder Contract DoS

### Summary
The `GetManagingSchemeIds` view method returns null when a manager has no associated schemes, but downstream callers in TokenHolderContract and TreasuryContract access the `.SchemeIds` property without null validation. This causes NullReferenceException and blocks critical operations including token withdrawals and profit claims, effectively locking user funds in the TokenHolder contract.

### Finding Description

The vulnerability originates in the `GetManagingSchemeIds` method which directly returns the state mapping value without null protection: [1](#0-0) 

When `State.ManagingSchemeIds[input.Manager]` returns null for a non-existent manager, downstream callers experience NullReferenceException when accessing `.SchemeIds`.

**Critical Failure Point 1 - TokenHolderContract:**

The `UpdateTokenHolderProfitScheme` method calls `GetManagingSchemeIds` and immediately accesses `.SchemeIds.FirstOrDefault()` without null checking: [2](#0-1) 

This method is invoked by `GetValidScheme`, which is called by all major TokenHolder operations: [3](#0-2) 

The assertion on line 281 only checks if `State.TokenHolderProfitSchemes[manager]` exists, but does not validate that the manager still has schemes in the Profit contract.

**Critical Failure Point 2 - TreasuryContract:**

The `InitialMiningRewardProfitItem` method accesses `.SchemeIds` directly on the result: [4](#0-3) 

**Root Cause - State Desynchronization:**

The `ResetManager` function in ProfitContract allows transferring scheme management to a different address: [5](#0-4) 

This removes the scheme ID from the old manager's `ManagingSchemeIds` (line 734) but TokenHolderContract maintains its own state keyed by the original creator, causing desynchronization.

### Impact Explanation

**Operational DoS Impact:**

When a user transfers their TokenHolder scheme management via `ResetManager`, all subsequent TokenHolder operations fail with NullReferenceException:
- `AddBeneficiary` (line 39)
- `RemoveBeneficiary` (line 72) 
- `ContributeProfits` (line 102)
- `DistributeProfits` (line 133)
- `RegisterForProfits` (line 152)
- `Withdraw` (line 213) - **blocks fund withdrawal**
- `ClaimProfits` (line 249) - **blocks profit claims**

**Direct Fund Impact:**

Users cannot withdraw their locked tokens or claim accumulated profits. The tokens remain locked in the contract but become inaccessible through normal operations. This effectively locks user funds indefinitely until manual intervention or contract upgrade.

**Affected Users:**

Any user who has created a TokenHolder scheme and subsequently called `ResetManager` on the underlying Profit scheme, either intentionally or by mistake. Given that users control their schemes, this is a realistic scenario.

### Likelihood Explanation

**Attack Complexity: Low**

The exploitation requires only a single transaction from the scheme owner:
1. User creates TokenHolder scheme via `CreateScheme`
2. User calls `ProfitContract.ResetManager` to transfer management
3. Any subsequent TokenHolder operation by the user triggers the exception

**Feasible Preconditions:**

- The user must be the manager of their own scheme (always true after creation)
- The `ResetManager` function is publicly accessible to scheme managers
- No validation prevents users from resetting their TokenHolder scheme managers [6](#0-5) 

**Execution Practicality:**

This is immediately executable. A user could unknowingly call `ResetManager` thinking it's necessary for scheme management, or could be socially engineered into doing so. The TokenHolder contract provides no warnings or protections against this action.

**Economic Rationality:**

No economic cost to trigger (just transaction fees). An attacker could target their own account to demonstrate the vulnerability or could trick users into self-DoS.

### Recommendation

**Fix 1: Add Null Protection in GetManagingSchemeIds**

Modify the view method to return an empty `CreatedSchemeIds` instead of null:

```csharp
public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
{
    return State.ManagingSchemeIds[input.Manager] ?? new CreatedSchemeIds();
}
```

This follows the defensive pattern used in other view methods: [7](#0-6) 

**Fix 2: Add Validation in TokenHolderContract**

Add null checking before accessing `.SchemeIds`:

```csharp
var managingSchemeIds = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
{
    Manager = manager
});
Assert(managingSchemeIds != null && managingSchemeIds.SchemeIds.Any(), 
    "No schemes found for manager. Scheme may have been transferred.");
var originSchemeId = managingSchemeIds.SchemeIds.FirstOrDefault();
```

**Fix 3: Prevent TokenHolder Scheme Management Transfer**

Add validation in the ResetManager method to prevent resetting managers of TokenHolder-managed schemes, or update TokenHolder state when schemes are transferred.

**Test Cases:**

1. Test `GetManagingSchemeIds` with non-existent manager returns empty list
2. Test TokenHolder operations after calling `ResetManager` on underlying scheme
3. Test Treasury initialization with missing schemes

### Proof of Concept

**Initial State:**
- User A has sufficient ELF tokens for locking
- TokenHolder and Profit contracts are deployed

**Exploitation Steps:**

1. **User A creates TokenHolder scheme:**
   ```
   TokenHolderContract.CreateScheme({
       Symbol: "ELF",
       MinimumLockMinutes: 100,
       AutoDistributeThreshold: {}
   })
   ```
   - Creates scheme in ProfitContract with manager = A
   - Stores TokenHolderProfitScheme[A] in TokenHolder state

2. **User A locks tokens and registers:**
   ```
   TokenHolderContract.RegisterForProfits({
       SchemeManager: A,
       Amount: 1000
   })
   ```
   - Successfully locks 1000 ELF tokens
   - User A is now a beneficiary

3. **User A resets scheme manager (intentionally or by mistake):**
   ```
   ProfitContract.ResetManager({
       SchemeId: <scheme_id>,
       NewManager: <other_address>
   })
   ```
   - Removes scheme from ManagingSchemeIds[A]
   - Adds scheme to ManagingSchemeIds[other_address]

4. **User A attempts to withdraw tokens:**
   ```
   TokenHolderContract.Withdraw(A)
   ```

**Expected Result:** 
User A should be able to withdraw their locked tokens

**Actual Result:**
Transaction fails with NullReferenceException at line 293 of TokenHolderContract when accessing `.SchemeIds.FirstOrDefault()` on null result from `GetManagingSchemeIds(A)`. User A's 1000 ELF tokens remain locked and inaccessible.

**Success Condition:**
The NullReferenceException proves the vulnerability exists. User funds are locked in the contract with no recovery mechanism through normal contract operations.

### Citations

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L103-110)
```csharp
    private GetAllProfitsMapOutput GetAllProfitsMap(Hash schemeId, Address beneficiary, string symbol = null)
    {
        var scheme = State.SchemeInfos[schemeId];
        Assert(scheme != null, "Scheme not found.");
        beneficiary = beneficiary ?? Context.Sender;
        var profitDetails = State.ProfitDetailsMap[schemeId][beneficiary];

        if (profitDetails == null) return new GetAllProfitsMapOutput();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-284)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
    {
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-294)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L83-88)
```csharp
        var managingSchemeIds = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = Context.Self
        }).SchemeIds;

        Assert(managingSchemeIds.Count == 7, "Incorrect schemes count.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L729-730)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L732-738)
```csharp
        // Transfer managing scheme id.
        var oldManagerSchemeIds = State.ManagingSchemeIds[scheme.Manager];
        oldManagerSchemeIds.SchemeIds.Remove(input.SchemeId);
        State.ManagingSchemeIds[scheme.Manager] = oldManagerSchemeIds;
        var newManagerSchemeIds = State.ManagingSchemeIds[input.NewManager] ?? new CreatedSchemeIds();
        newManagerSchemeIds.SchemeIds.Add(input.SchemeId);
        State.ManagingSchemeIds[input.NewManager] = newManagerSchemeIds;
```
