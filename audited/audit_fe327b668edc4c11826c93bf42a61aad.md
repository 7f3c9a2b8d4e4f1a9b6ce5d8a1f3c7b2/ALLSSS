# Audit Report

## Title
State Corruption in UpdateTokenHolderProfitScheme Enables Unauthorized Scheme Manipulation and Fund Theft

## Summary
The `UpdateTokenHolderProfitScheme` helper function in TokenHolderContract contains a critical state corruption bug where it incorrectly writes scheme data to `Context.Sender`'s storage slot instead of the intended `manager` parameter's slot. This allows any attacker to hijack a victim's scheme ID through public functions like `ContributeProfits`, then exploit TokenHolderContract's privileged relationship with ProfitContract to add malicious beneficiaries and steal accumulated profits.

## Finding Description

**Root Cause:**

The `UpdateTokenHolderProfitScheme` function retrieves scheme information for a given manager address, queries the ProfitContract to populate the SchemeId, but then incorrectly saves the updated scheme to `Context.Sender`'s storage slot instead of the `manager`'s slot. [1](#0-0) 

**Correct Pattern Demonstrated Elsewhere:**

Both `DistributeProfits` and `RegisterForProfits` correctly use the manager parameter (`input.SchemeManager`) when persisting scheme updates: [2](#0-1) [3](#0-2) 

**Vulnerable Execution Path:**

1. When an attacker calls `ContributeProfits` with `input.SchemeManager` pointing to a victim's address, the function retrieves the victim's scheme: [4](#0-3) 

2. `GetValidScheme` loads the victim's scheme from their storage slot and calls `UpdateTokenHolderProfitScheme`: [5](#0-4) 

3. The update logic queries ProfitContract using the victim's address as manager to retrieve the correct SchemeId, updates the scheme object with this information, but then saves it to the attacker's (`Context.Sender`) storage slot instead of the victim's slot (line 298 in the first citation).

**Why Authorization Protections Fail:**

The ProfitContract's `AddBeneficiary` method trusts TokenHolderContract as a privileged caller: [6](#0-5) 

Once the attacker has the victim's SchemeId stored in their own storage slot, they can call `AddBeneficiary`, which retrieves the scheme from the attacker's storage (containing the victim's SchemeId) and successfully adds the attacker as a beneficiary: [7](#0-6) 

The ProfitContract allows this modification because the call originates from TokenHolderContract (a trusted system contract), despite the attacker having no legitimate authorization over the victim's scheme.

## Impact Explanation

**Direct Fund Theft:**
- Attackers can add themselves as beneficiaries with arbitrarily large shares to any victim's TokenHolder profit scheme
- Attackers can claim all accumulated profits meant for legitimate stakeholders
- Impact scales linearly with the total profits accumulated in victim schemes (potentially thousands to millions of tokens)

**Share Dilution:**
- Legitimate beneficiaries receive proportionally reduced profits based on the attacker's injected shares
- Scheme managers permanently lose control over their beneficiary authorization

**State Corruption:**
- Victim's scheme metadata in their storage slot never gets updated (SchemeId remains null/outdated)
- Repeated exploitation creates inconsistent scheme copies across multiple attacker storage slots
- Creates operational DoS scenarios when the victim attempts legitimate scheme operations

**Affected Parties:**
- DApp operators who create TokenHolder profit schemes for user rewards
- Token stakers and legitimate beneficiaries expecting profit distributions
- Any scheme with accumulated profits becomes an immediate target for exploitation

## Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to call public contract functions (standard blockchain user capability)
- Knowledge of target scheme manager address (publicly observable from CreateScheme transaction logs)
- Minimal token holdings for the initial ContributeProfits call (can be as low as 1 token unit)

**Attack Complexity:**
- Simple 2-transaction attack sequence:
  1. Call `ContributeProfits(schemeManager: VictimAddress, amount: 1, symbol: "ELF")`
  2. Call `AddBeneficiary(beneficiary: AttackerAddress, shares: 1000000000)`
- No timing constraints, race conditions, or complex state manipulation required
- Deterministic outcome with 100% success rate

**Feasibility Conditions:**
- Victim must have created a TokenHolder scheme (common pattern for DApp reward distribution shown in test suite) [8](#0-7) 

- Attack succeeds when the victim's scheme SchemeId is null (first use after creation) or when the attacker acts before legitimate scheme initialization
- No privileged access or governance approval required

**Economic Incentives:**
- Attack cost: 1 token + transaction gas fees (negligible)
- Attack reward: Proportional share of all accumulated profits in the victim's scheme (unlimited upside)
- Risk-adjusted ROI: Extremely favorable for attackers, creating strong incentive for exploitation

**Detection Constraints:**
- No on-chain indicators distinguish malicious ContributeProfits from legitimate contributions
- State corruption occurs silently; victims only discover the issue when attempting scheme operations or auditing beneficiary lists

## Recommendation

Change line 298 in `UpdateTokenHolderProfitScheme` to use the `manager` parameter instead of `Context.Sender`:

**Current (vulnerable) code:**
```csharp
State.TokenHolderProfitSchemes[Context.Sender] = scheme;
```

**Fixed code:**
```csharp
State.TokenHolderProfitSchemes[manager] = scheme;
```

This ensures that scheme updates are always saved to the correct manager's storage slot, preventing unauthorized scheme hijacking. The fix aligns with the correct pattern already used in `DistributeProfits` and `RegisterForProfits`.

## Proof of Concept

```csharp
[Fact]
public async Task StateCorruption_AttackerStealsVictimSchemeId()
{
    // Setup: Victim creates their scheme
    var victimStub = GetTokenHolderContractStub(UserKeyPairs[0]);
    await victimStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "APP",
        MinimumLockMinutes = 100
    });
    
    var victimAddress = UserAddresses[0];
    
    // Verify victim's scheme has null SchemeId initially
    var victimScheme = await victimStub.GetScheme.CallAsync(victimAddress);
    victimScheme.SchemeId.ShouldBeNull();
    
    // Attack Step 1: Attacker calls ContributeProfits targeting victim's scheme
    var attackerStub = GetTokenHolderContractStub(UserKeyPairs[1]);
    await attackerStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = victimAddress,  // Target victim's scheme
        Amount = 1,
        Symbol = "ELF"
    });
    
    // Verify bug: Attacker now has victim's SchemeId in their storage
    var attackerAddress = UserAddresses[1];
    var attackerScheme = await attackerStub.GetScheme.CallAsync(attackerAddress);
    attackerScheme.SchemeId.ShouldNotBeNull();  // Attacker hijacked victim's SchemeId
    
    // Verify victim's scheme still has null SchemeId (state corruption)
    victimScheme = await victimStub.GetScheme.CallAsync(victimAddress);
    victimScheme.SchemeId.ShouldBeNull();  // Victim's state never updated
    
    // Attack Step 2: Attacker adds themselves as beneficiary using stolen SchemeId
    await attackerStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = attackerAddress,
        Shares = 1000000
    });
    
    // Verify exploitation: Attacker is now beneficiary of victim's scheme
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(
        new GetProfitDetailsInput
        {
            SchemeId = attackerScheme.SchemeId,
            Beneficiary = attackerAddress
        });
    
    profitDetails.Details.Count.ShouldBeGreaterThan(0);  // Attacker successfully added
    profitDetails.Details.First().Shares.ShouldBe(1000000);  // With malicious shares
    
    // Impact: Attacker can now claim profits from victim's scheme
}
```

**Notes:**
This vulnerability breaks the fundamental security guarantee that only the scheme manager can control beneficiary authorization. The state corruption occurs because the function parameter `manager` is ignored in favor of the transaction's `Context.Sender`, creating a dangerous mismatch between authorization logic (based on `manager`) and state persistence (based on `Context.Sender`). The privileged trust relationship between TokenHolderContract and ProfitContract amplifies this bug into a critical fund theft vulnerability.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L100-102)
```csharp
    public override Empty ContributeProfits(ContributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L145-145)
```csharp
        State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L205-205)
```csharp
            State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
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

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L34-59)
```csharp
    public async Task CreateTokenHolderProfitSchemeTest()
    {
        await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = "APP"
        });

        {
            var tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
            tokenHolderProfitScheme.Period.ShouldBe(0);
            tokenHolderProfitScheme.Symbol.ShouldBe("APP");
            tokenHolderProfitScheme.SchemeId.ShouldBeNull();
        }

        await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeManager = Starter,
            Symbol = "ELF",
            Amount = 1
        });

        {
            var tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
            tokenHolderProfitScheme.SchemeId.ShouldNotBeNull();
        }
    }
```
