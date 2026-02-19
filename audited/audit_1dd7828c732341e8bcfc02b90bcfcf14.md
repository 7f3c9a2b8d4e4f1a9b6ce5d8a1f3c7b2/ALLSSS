### Title
Authorization Bypass in TokenHolder ContributeProfits Enables Front-Running of Beneficiary Removal

### Summary
The `ContributeProfits()` function in TokenHolderContract allows any user to contribute tokens to any profit scheme without authorization checks, enabling malicious beneficiaries to force premature distributions via auto-distribution thresholds. This allows beneficiaries facing removal to front-run the removal transaction, locking in their share of accumulated profits that the scheme manager intended to distribute after their removal.

### Finding Description

The vulnerability exists in the `ContributeProfits()` function where line 102 retrieves a scheme using `input.SchemeManager` without verifying that `Context.Sender` has authorization to contribute to that scheme. [1](#0-0) 

The function performs token transfers from `Context.Sender` (lines 107-113) and contributes them to the scheme's virtual address (lines 122-127), but the only validation is that the scheme exists via `GetValidScheme()`. [2](#0-1) 

When schemes are created, they can specify `AutoDistributeThreshold` values. The `RegisterForProfits()` function checks if the virtual address balance exceeds these thresholds and triggers automatic distribution. [3](#0-2) 

TokenHolder schemes are created with `CanRemoveBeneficiaryDirectly = true`, allowing immediate beneficiary removal. [4](#0-3) 

However, when a beneficiary is removed after distribution, the Profit contract sets their `EndPeriod` to `CurrentPeriod - 1`, allowing them to claim profits from the just-distributed period. [5](#0-4) 

### Impact Explanation

**Direct Fund Impact**: A malicious beneficiary facing removal can steal their share of accumulated profits that should have gone to other beneficiaries after their removal.

**Concrete Example**:
1. Scheme has 10,000 ELF accumulated, ready for distribution
2. Bob is a beneficiary with 30% shares
3. Scheme manager plans to remove Bob, then distribute to remaining 70% of beneficiaries
4. Bob detects the removal intent and contributes 100 ELF to reach auto-distribute threshold
5. Bob calls `RegisterForProfits()` (or waits for someone else to), triggering distribution
6. Bob receives 30% × 10,100 ELF = 3,030 ELF
7. Manager's subsequent `RemoveBeneficiary` call is ineffective - Bob already locked in his share
8. **Net result**: Bob steals 3,000 ELF that should have been distributed to other beneficiaries, at a cost of only 100 ELF

**Who is Affected**:
- Legitimate beneficiaries lose their rightful share of profits
- Scheme managers lose control over distribution timing and beneficiary management
- Any TokenHolder scheme with auto-distribution thresholds is vulnerable

**Severity Justification**: HIGH - Direct theft of funds through authorization bypass with economically rational attack path.

### Likelihood Explanation

**Reachable Entry Point**: `ContributeProfits()` is a public function callable by any address.

**Feasible Preconditions**: 
- Attacker must be a current beneficiary of a scheme (or collude with one)
- Attacker needs tokens to contribute (amount depends on threshold and current balance)
- Scheme must have auto-distribution threshold configured
- Accumulated profits in the scheme must exceed the attacker's contribution cost

**Execution Practicality**: Extremely simple - single function call followed by `RegisterForProfits()` call.

**Economic Rationality**: Highly rational when:
- Beneficiary detects imminent removal (through governance proposals, on-chain signals, or off-chain communication)
- Their share percentage × accumulated profits > contribution cost
- Example: 20% share of 50,000 ELF (10,000 ELF gain) costs ~1,000 ELF contribution = 9,000 ELF profit

**Detection Constraints**: The contribution transaction appears legitimate and cannot be prevented once broadcast. The manager cannot front-run the attacker's transaction to remove them first due to blockchain ordering guarantees.

**Probability Assessment**: MEDIUM-HIGH - While requiring specific conditions (beneficiary removal scenario), this is a realistic and common governance action. The attack is cheap, easy to execute, and highly profitable when conditions are met.

### Recommendation

**Code-Level Mitigation**:

1. Add authorization check in `ContributeProfits()` to verify sender is scheme manager:
```
Assert(Context.Sender == input.SchemeManager, "Only scheme manager can contribute profits.");
```

2. Alternatively, if public contributions are intended, add a scheme configuration flag `AllowPublicContributions` that managers can opt into, and disable auto-distribution for schemes allowing public contributions.

3. Add manager-only control over auto-distribution by moving the auto-distribution check from `RegisterForProfits()` to a dedicated `TriggerAutoDistribution()` function that requires manager authorization.

**Invariant Checks to Add**:
- Verify `Context.Sender == scheme.Manager` OR `scheme.AllowPublicContributions == true` before accepting contributions
- Emit events for all contributions showing contributor, manager, and amount for monitoring
- Add time-lock or delay between contribution and distribution eligibility

**Test Cases**:
1. Test that non-managers cannot contribute to schemes with public contributions disabled
2. Test that beneficiaries cannot trigger auto-distribution through contributions
3. Test that removed beneficiaries cannot claim from periods after their removal
4. Test legitimate use cases still work (e.g., AEDPoS Donate function using its own scheme)

### Proof of Concept

**Initial State**:
- Alice creates TokenHolder scheme with address ALICE_ADDR
- Alice sets AutoDistributeThreshold["ELF"] = 5,000
- Bob registers as beneficiary with 30% shares (3,000 locked ELF)
- Carol registers as beneficiary with 70% shares (7,000 locked ELF)  
- Scheme accumulates 10,000 ELF in profits over time
- Alice decides to remove Bob before next distribution

**Attack Sequence**:

1. Bob detects removal intent (sees proposal, manager communication, etc.)

2. Bob calls `TokenHolderContract.ContributeProfits()`:
   - Input: `scheme_manager = ALICE_ADDR, amount = 100, symbol = "ELF"`
   - Result: Virtual address balance = 10,100 ELF (exceeds 5,000 threshold)

3. Bob (or anyone) calls `TokenHolderContract.RegisterForProfits()`:
   - Input: `scheme_manager = ALICE_ADDR, amount = 1000`
   - Result: Auto-distribution triggers (line 203), period increments, 10,100 ELF distributed

4. Alice calls `TokenHolderContract.RemoveBeneficiary()`:
   - Input: `beneficiary = BOB_ADDR`
   - Result: Bob's EndPeriod set to CurrentPeriod - 1 (still includes distributed period)

5. Bob calls `TokenHolderContract.ClaimProfits()`:
   - Input: `scheme_manager = ALICE_ADDR`
   - Result: Bob receives 30% × 10,100 = 3,030 ELF

**Expected Result**: Bob should receive 0 ELF (removed before distribution)

**Actual Result**: Bob receives 3,030 ELF (30% of accumulated + contributed amounts)

**Success Condition**: Bob nets 2,930 ELF profit (3,030 claimed - 100 contributed), stealing funds from Carol who should have received the full 10,000 ELF after Bob's removal.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L178-206)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L351-356)
```csharp
                else if (profitDetail.EndPeriod >= scheme.CurrentPeriod)
                {
                    // No profit can be here, except the scheme is cancellable.
                    // shorten profit.
                    profitDetail.EndPeriod = scheme.CurrentPeriod.Sub(1);
                }
```
