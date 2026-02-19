### Title
State Corruption and Authorization Bypass in TokenHolder Profit Scheme Management

### Summary
The `UpdateTokenHolderProfitScheme` function incorrectly writes scheme data to `State.TokenHolderProfitSchemes[Context.Sender]` instead of `State.TokenHolderProfitSchemes[manager]`, causing severe state corruption when the caller differs from the scheme manager. This enables attackers to corrupt their own scheme with another manager's scheme data, then exploit the corrupted scheme_id to perform unauthorized beneficiary modifications on the victim's profit scheme through the TokenHolder contract's elevated privileges.

### Finding Description

The root cause is at line 298 in `UpdateTokenHolderProfitScheme` where the function parameter `manager` is used to query scheme information but `Context.Sender` is used to write the updated state: [1](#0-0) 

The function is called from `GetValidScheme` with a `manager` parameter that can differ from `Context.Sender`: [2](#0-1) 

Critical call sites where `manager != Context.Sender`:

1. **ContributeProfits** - No authorization check, accepts arbitrary scheme_manager: [3](#0-2) 

2. **DistributeProfits** - Calls GetValidScheme before authorization check: [4](#0-3) 

3. **RegisterForProfits** - User can specify any scheme_manager: [5](#0-4) 

4. **Withdraw** - Input is scheme manager address: [6](#0-5) 

5. **ClaimProfits** - User specifies scheme_manager: [7](#0-6) 

After state corruption, when the attacker calls `AddBeneficiary` or `RemoveBeneficiary` using their corrupted scheme (which now contains the victim's scheme_id), the TokenHolder contract makes calls to the Profit contract with the victim's scheme_id. The Profit contract authorization checks pass because the TokenHolder contract itself is an authorized caller: [8](#0-7) 

### Impact Explanation

**Critical Authorization Bypass:**
- Attacker corrupts their TokenHolderProfitScheme entry by calling `ContributeProfits` with victim's address as scheme_manager
- Attacker's scheme now contains victim's scheme_id, symbol, period, and other configuration
- Attacker calls `AddBeneficiary` or `RemoveBeneficiary`, which uses `Context.Sender` to retrieve scheme: [9](#0-8) 

- TokenHolder contract then manipulates beneficiaries on victim's profit scheme via elevated privileges: [10](#0-9) 

**Fund Theft Vectors:**
1. Attacker adds themselves as beneficiary to victim's profit scheme with arbitrary shares
2. Attacker removes legitimate beneficiaries from victim's scheme, stealing their profit allocation
3. Profit distributions intended for legitimate holders get redirected to attacker

**State Corruption Impact:**
- Victim's TokenHolderProfitScheme never gets updated when it should (manager's scheme unchanged)
- Attacker's scheme is corrupted with wrong symbol, minimum_lock_minutes, auto_distribute_threshold
- Users who registered under corrupted scheme cannot withdraw correctly due to wrong symbol: [11](#0-10) 

**Affected Parties:**
- All TokenHolder profit scheme managers whose scheme_manager address is used by attackers
- Legitimate beneficiaries who lose profit share allocations
- Users who locked tokens under schemes that later get corrupted

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is directly exploitable through the public `ContributeProfits` method which has no authorization checks preventing arbitrary scheme_manager specification.

**Attacker Capabilities Required:**
- Any user can create their own TokenHolder scheme via `CreateScheme`
- Any user can call `ContributeProfits` with any scheme_manager address
- No special permissions or tokens required for initial corruption
- Standard token approvals needed to complete ContributeProfits (but corruption happens regardless)

**Attack Complexity:**
Low - Two simple transactions:
1. Call `ContributeProfits(victim_address, amount, symbol)` to corrupt attacker's scheme
2. Call `AddBeneficiary(attacker_address, large_shares)` to gain unauthorized beneficiary status

**Feasibility Conditions:**
- Victim must have created a TokenHolder profit scheme (common for dividend distribution)
- No special blockchain state required
- Works on any AElf chain with TokenHolder contract deployed

**Detection Constraints:**
- State corruption is silent - no events emitted
- Unauthorized beneficiary additions appear as legitimate TokenHolder contract calls to Profit contract
- Difficult to distinguish from legitimate operations in transaction logs

**Economic Rationality:**
- Attack cost: minimal (gas fees only)
- Potential gain: share of all future profit distributions to victim's scheme
- Risk/reward extremely favorable for attacker

### Recommendation

**Immediate Fix:**
Change line 298 to write to the correct state key:

```csharp
State.TokenHolderProfitSchemes[manager] = scheme;
```

**Additional Protections:**
1. Add authorization check in `ContributeProfits` to verify caller relationship to scheme_manager
2. Add validation in `GetValidScheme` to ensure retrieved scheme integrity (symbol, manager matches expected values)
3. Emit events when TokenHolderProfitScheme state is modified for audit trail

**Test Cases to Add:**
1. Verify `ContributeProfits` with scheme_manager != Context.Sender doesn't corrupt caller's scheme
2. Verify state updates always write to the manager parameter, not Context.Sender
3. Verify attacker cannot manipulate beneficiaries of schemes they don't manage
4. Verify each scheme's symbol, period, scheme_id remain consistent across operations

### Proof of Concept

**Initial State:**
- Alice creates TokenHolder scheme (symbol: "ELF", manager: Alice, scheme_id: SchemeA)
- Bob creates TokenHolder scheme (symbol: "USDT", manager: Bob, scheme_id: SchemeB)
- Both schemes registered in State.TokenHolderProfitSchemes

**Attack Sequence:**

**Step 1 - State Corruption:**
```
Transaction: Bob calls ContributeProfits
Input: {
  scheme_manager: Alice's address,
  amount: 100,
  symbol: "ELF"
}
```

Execution trace:
- Line 102: GetValidScheme(Alice) retrieves Alice's scheme
- Line 282: UpdateTokenHolderProfitScheme(ref scheme, Alice, false)
- Line 290-295: Queries Alice's profit scheme_id from Profit contract
- Line 298: **BUG** - Writes to State.TokenHolderProfitSchemes[Bob] instead of [Alice]

Result: Bob's scheme now contains {symbol: "ELF", scheme_id: SchemeA, period: Alice's period}

**Step 2 - Authorization Bypass:**
```
Transaction: Bob calls AddBeneficiary
Input: {
  beneficiary: Bob's address,
  shares: 1000000
}
```

Execution trace:
- Line 39: GetValidScheme(Context.Sender=Bob) retrieves Bob's corrupted scheme
- Bob's scheme has scheme_id: SchemeA (Alice's scheme!)
- Line 58-66: TokenHolder contract calls Profit.AddBeneficiary(SchemeA, Bob, 1000000)
- Profit contract authorization passes (TokenHolder contract is authorized caller)
- Bob is now beneficiary on Alice's profit scheme

**Expected vs Actual:**
- Expected: Bob can only modify his own scheme (SchemeB)
- Actual: Bob successfully added himself as beneficiary to Alice's scheme (SchemeA)

**Success Condition:**
Query Profit contract for beneficiaries of SchemeA - Bob appears with 1000000 shares despite not being authorized by Alice.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L37-39)
```csharp
    public override Empty AddBeneficiary(AddTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L58-66)
```csharp
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = input.Beneficiary,
                Shares = shares
            }
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L100-102)
```csharp
    public override Empty ContributeProfits(ContributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-135)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager, true);
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-152)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
    {
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L211-213)
```csharp
    public override Empty Withdraw(Address input)
    {
        var scheme = GetValidScheme(input);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L224-235)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L247-250)
```csharp
    public override Empty ClaimProfits(ClaimProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager);
        var beneficiary = input.Beneficiary ?? Context.Sender;
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L286-299)
```csharp
    private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
        bool updateSchemePeriod)
    {
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        var originScheme = State.ProfitContract.GetScheme.Call(originSchemeId);
        scheme.SchemeId = originScheme.SchemeId;
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```
