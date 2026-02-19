### Title
Scheme Hijacking via Incorrect Storage Key in UpdateTokenHolderProfitScheme

### Summary
The `UpdateTokenHolderProfitScheme` function saves scheme data to `State.TokenHolderProfitSchemes[Context.Sender]` instead of using the `manager` parameter, causing schemes to be stored under the wrong address key. This allows attackers to overwrite their own scheme with another manager's scheme data via unauthorized calls to functions like `ContributeProfits`, effectively hijacking scheme management and corrupting the profit distribution system.

### Finding Description

The root cause is at line 298 of `UpdateTokenHolderProfitScheme`: [1](#0-0) 

The function receives a `manager` parameter but incorrectly uses `Context.Sender` as the storage key, while the scheme data being saved contains information queried for the `manager` address: [2](#0-1) 

This function is called from `GetValidScheme`, which is invoked by multiple public methods where `manager` can differ from `Context.Sender`: [3](#0-2) 

The most critical entry point is `ContributeProfits`, which has **no authorization check** and allows any caller to specify any `scheme_manager`: [4](#0-3) 

The vulnerability is triggered because `CreateScheme` does not initialize the `SchemeId` field, leaving it null: [5](#0-4) 

When `UpdateTokenHolderProfitScheme` is called with a scheme that has `SchemeId == null`, it proceeds to query the Profit contract for the manager's scheme information and then incorrectly saves it under `Context.Sender`'s key: [6](#0-5) 

### Impact Explanation

**Direct State Corruption:** The attacker's scheme at `State.TokenHolderProfitSchemes[attacker_address]` gets overwritten with the victim's scheme data, including the victim's `SchemeId`, `Symbol`, `Period`, `MinimumLockMinutes`, and `AutoDistributeThreshold`.

**Scheme Hijacking:** Both the attacker's address and victim's address now map to schemes with the same `SchemeId` from the Profit contract. When users interact with the attacker's scheme (via `RegisterForProfits`, `ClaimProfits`, etc.), they unknowingly interact with the victim's actual profit scheme in the underlying Profit contract.

**Fund Mismanagement:** Users who lock tokens under the attacker's scheme become beneficiaries in the victim's profit scheme, breaking the isolation between different scheme managers and causing incorrect profit distributions.

**Wide Attack Surface:** The vulnerability affects multiple functions including `ContributeProfits`, `RegisterForProfits`, `Withdraw`, and `ClaimProfits` - all of which can be exploited by any caller without special permissions.

### Likelihood Explanation

**Highly Exploitable:** The attack requires only a single transaction calling `ContributeProfits` with the victim's address as `scheme_manager`. No special permissions or complex setup is needed.

**No Authorization Barriers:** `ContributeProfits` and other affected functions lack authorization checks that would prevent arbitrary callers from triggering this vulnerability: [7](#0-6) 

**Always Exploitable After CreateScheme:** Any scheme created via `CreateScheme` is vulnerable until its first state update, making this a persistent and widespread issue.

**Zero Attack Cost:** The attacker only needs to create their own scheme and call a public function - there are no economic barriers or complex preconditions.

**Practical Attack Scenario:** Attacker creates scheme A, victim creates scheme B, attacker calls `ContributeProfits(scheme_manager: victim_address, amount: 1, symbol: "ELF")` to corrupt their own scheme with victim's data.

### Recommendation

**Immediate Fix:** Change line 298 to use the `manager` parameter instead of `Context.Sender`:
```csharp
State.TokenHolderProfitSchemes[manager] = scheme;
```

**Additional Safeguards:**
1. Initialize `SchemeId` immediately in `CreateScheme` by retrieving it from the Profit contract's return value or querying it after creation
2. Add authorization checks to `ContributeProfits` to verify the caller has permission to contribute to the specified scheme
3. Add invariant validation to ensure scheme data consistency across updates

**Test Cases:**
1. Verify that calling `ContributeProfits` with `scheme_manager != Context.Sender` does not corrupt the caller's scheme
2. Verify that scheme data at address A remains unchanged when operations reference address A but are called by address B
3. Verify that `SchemeId` is properly initialized immediately after `CreateScheme`

### Proof of Concept

**Initial State:**
- Victim calls `CreateScheme(symbol: "ELF", minimum_lock_minutes: 100)` 
  - Creates scheme at `State.TokenHolderProfitSchemes[victim_address]` with `SchemeId = null`
- Attacker calls `CreateScheme(symbol: "USDT", minimum_lock_minutes: 50)`
  - Creates scheme at `State.TokenHolderProfitSchemes[attacker_address]` with `SchemeId = null`

**Attack Transaction:**
- Attacker calls `ContributeProfits(scheme_manager: victim_address, amount: 1, symbol: "ELF")`

**Execution Flow:**
1. `ContributeProfits` calls `GetValidScheme(victim_address)` at line 102
2. `GetValidScheme` loads victim's scheme and calls `UpdateTokenHolderProfitScheme(ref scheme, victim_address, false)`
3. Since `scheme.SchemeId == null`, the function queries Profit contract for victim's `SchemeId`
4. **BUG:** Line 298 saves to `State.TokenHolderProfitSchemes[Context.Sender]` = `State.TokenHolderProfitSchemes[attacker_address]`

**Result:**
- `State.TokenHolderProfitSchemes[attacker_address].Symbol` = "ELF" (was "USDT")
- `State.TokenHolderProfitSchemes[attacker_address].MinimumLockMinutes` = 100 (was 50)
- `State.TokenHolderProfitSchemes[attacker_address].SchemeId` = victim's SchemeId
- Both attacker and victim now reference the same underlying Profit scheme

**Success Condition:**
Query `GetScheme(attacker_address)` returns scheme data matching victim's configuration with victim's `SchemeId`, confirming the hijacking.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L100-129)
```csharp
    public override Empty ContributeProfits(ContributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = Context.Sender,
            To = Context.Self,
            Symbol = input.Symbol,
            Amount = input.Amount
        });

        State.TokenContract.Approve.Send(new ApproveInput
        {
            Spender = State.ProfitContract.Value,
            Symbol = input.Symbol,
            Amount = input.Amount
        });

        State.ProfitContract.ContributeProfits.Send(new Profit.ContributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Symbol = input.Symbol,
            Amount = input.Amount
        });
        return new Empty();
    }
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
