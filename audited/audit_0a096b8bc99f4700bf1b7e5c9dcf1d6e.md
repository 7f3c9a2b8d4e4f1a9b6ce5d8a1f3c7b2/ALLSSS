### Title
TokenHolder Scheme Manager Can Steal Profits by Removing Beneficiaries Before Distribution

### Summary
The `CreateScheme` function in TokenHolderContract sets `CanRemoveBeneficiaryDirectly=true`, allowing the scheme manager to arbitrarily remove beneficiaries at any time. By removing legitimate beneficiaries before distributing profits, a malicious manager can manipulate the share calculation to drain all profits, effectively stealing funds from users who locked tokens in good faith.

### Finding Description

The vulnerability exists across three interacting contracts:

**Root Cause:** [1](#0-0) 

When creating a TokenHolder profit scheme, `CanRemoveBeneficiaryDirectly` is hardcoded to `true`, giving the scheme manager unrestricted removal power.

**Manager Control:** [2](#0-1) 

The `RemoveBeneficiary` function retrieves the scheme where `Context.Sender` is the manager, allowing only the scheme creator to remove beneficiaries.

**Share Manipulation Without Token Lock:** [3](#0-2) 

The manager can call `AddBeneficiary` to assign themselves arbitrary shares without locking any tokens, unlike legitimate users who must lock tokens via `RegisterForProfits`.

**Removal Mechanism:** [4](#0-3) 

When `CanRemoveBeneficiaryDirectly` is true, `RemoveProfitDetails` allows removing any non-removed beneficiary. For active beneficiaries, it sets `EndPeriod = CurrentPeriod - 1`, preventing them from claiming future profits.

**Claim Prevention:** [5](#0-4) 

In `ClaimProfits`, beneficiaries with `EndPeriod < StartPeriod` are filtered out from `availableDetails`, making their profit details unclaimable.

**Share Reduction Impact:** [6](#0-5) 

When beneficiaries are removed, `TotalShares` is reduced, causing remaining beneficiaries to receive disproportionately large shares during distribution.

### Impact Explanation

**Direct Fund Theft:**
- A malicious manager can steal 100% of contributed profits with zero or minimal upfront investment
- Legitimate users who lock tokens (e.g., 1000 ELF) receive nothing despite fulfilling all requirements
- The attack works on any TokenHolder scheme, affecting all users who register for profits

**Attack Profitability:**
- Cost: 0 ELF (manager adds themselves via `AddBeneficiary` without locking)
- Gain: All contributed profits (e.g., 1000 ELF from legitimate contributions)
- Net profit: 1000 ELF with zero risk

**Affected Parties:**
- All users who lock tokens in any TokenHolder profit scheme
- Protocol reputation and user trust severely damaged
- Any dApp or service relying on TokenHolder for staking/rewards

**Severity Justification:**
This is **HIGH severity** because it enables direct theft of user funds with no countermeasures, no upfront cost, and affects the core profit distribution mechanism used throughout the AElf ecosystem.

### Likelihood Explanation

**Reachable Entry Points:**
All required functions are public and accessible:
- `CreateScheme`: Anyone can create a scheme (becomes manager)
- `AddBeneficiary`: Manager can add themselves with arbitrary shares
- `RemoveBeneficiary`: Manager can remove any beneficiary
- `DistributeProfits`: Manager can trigger distribution

**Feasibility:** [7](#0-6) 

No authorization checks prevent malicious actors from creating schemes and becoming managers. The scheme creation is permissionless.

**Attack Complexity:**
The attack requires only basic transaction sequencing:
1. Call `CreateScheme` (1 tx)
2. Call `AddBeneficiary` for self with 1 share (1 tx)
3. Wait for victims to register and profits to be contributed
4. Call `RemoveBeneficiary` for each victim (N txs)
5. Call `DistributeProfits` (1 tx)
6. Call `ClaimProfits` (1 tx)

**Economic Rationality:**
- Zero upfront capital required (no token locking for manager)
- Gas costs are negligible compared to stolen profits
- No time locks or penalties prevent immediate execution
- Attack is undetectable until after victim funds are lost

**Detection Constraints:**
Victims cannot detect the vulnerability before locking tokens. By the time profits are contributed, it's too late to withdraw without waiting for the `MinimumLockMinutes` period, which the manager controls.

### Recommendation

**Immediate Mitigation:**
Modify `CreateScheme` to set `CanRemoveBeneficiaryDirectly = false`: [1](#0-0) 

Change line 24 from `CanRemoveBeneficiaryDirectly = true` to `CanRemoveBeneficiaryDirectly = false`. This restricts removal to only expired beneficiaries (where `EndPeriod < CurrentPeriod`).

**Additional Safeguards:**

1. **Enforce Token Locking for Manager:**
Modify `AddBeneficiary` to prevent the manager from adding themselves without locking tokens via `RegisterForProfits`: [3](#0-2) 

Add a check: `Assert(input.Beneficiary != Context.Sender || State.LockIds[Context.Sender][input.Beneficiary] != null, "Manager must lock tokens via RegisterForProfits");`

2. **Add Withdrawal Protection:**
Implement a grace period after beneficiary removal before distribution, allowing removed users to withdraw their locked tokens.

3. **Invariant Checks:**
Add assertions in `DistributeProfits` to verify that `TotalShares` hasn't decreased suspiciously between profit contribution and distribution.

**Test Cases:**
- Test that managers cannot remove beneficiaries before their `EndPeriod`
- Test that managers cannot add themselves as beneficiaries without locking tokens
- Test that profit calculations remain fair after legitimate beneficiary expiration
- Test that removed beneficiaries can withdraw their locked tokens immediately

### Proof of Concept

**Initial State:**
- Attacker has an address with sufficient gas for transactions
- Token contract has sufficient ELF supply for victim locking

**Attack Sequence:**

1. **Attacker creates malicious scheme:**
   - Call `CreateScheme({symbol: "ELF", minimum_lock_minutes: 0})`
   - Attacker becomes manager with `CanRemoveBeneficiaryDirectly = true`

2. **Attacker adds self as beneficiary (no tokens locked):**
   - Call `AddBeneficiary({beneficiary: AttackerAddress, shares: 1})`
   - Scheme now has `TotalShares = 1`

3. **Victim registers for profits (locks 1000 ELF):**
   - Victim calls `RegisterForProfits({scheme_manager: AttackerAddress, amount: 1000})`
   - 1000 ELF locked from victim's account
   - Scheme now has `TotalShares = 1001`

4. **External user contributes 1000 ELF profits:**
   - Call `ContributeProfits({scheme_manager: AttackerAddress, symbol: "ELF", amount: 1000})`
   - 1000 ELF transferred to scheme's virtual address

5. **Attacker removes victim (before distribution):**
   - Call `RemoveBeneficiary({beneficiary: VictimAddress, amount: 0})`
   - Victim's `EndPeriod` set to `CurrentPeriod - 1 = 0`
   - Scheme now has `TotalShares = 1`

6. **Attacker distributes profits:**
   - Call `DistributeProfits({scheme_manager: AttackerAddress, amounts_map: {"ELF": 0}})`
   - Profit calculation: `1000 * (1 / 1) = 1000 ELF` to attacker
   - Victim gets 0 ELF (EndPeriod = 0 < StartPeriod = 1, filtered out)

7. **Attacker claims profits:**
   - Call `ClaimProfits({scheme_manager: AttackerAddress})`
   - Attacker receives 1000 ELF

**Expected vs Actual Result:**
- **Expected:** Victim receives ~999 ELF (999/1001 of profits), Attacker receives ~1 ELF (1/1001 of profits)
- **Actual:** Attacker receives 1000 ELF, Victim receives 0 ELF despite locking 1000 ELF

**Success Condition:**
The attack succeeds when the attacker's token balance increases by the full profit amount (1000 ELF) while victims with locked tokens receive nothing.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-84)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L260-260)
```csharp
        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-356)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-767)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();
```
