### Title
TokenHolder Scheme Manager Can Arbitrarily Dilute User Shares After Token Lock

### Summary
When a malicious contract creates a TokenHolder profit scheme, it becomes the scheme manager with unrestricted control over beneficiary shares. After honest users lock their tokens via `RegisterForProfits`, the malicious manager can add itself or other addresses as beneficiaries with massive shares, diluting all existing participants' profit proportions. Users cannot withdraw their locked tokens until `MinimumLockMinutes` expires, during which the manager can manipulate share distribution to steal nearly all distributed profits.

### Finding Description

The vulnerability exists in the TokenHolder contract's scheme creation and beneficiary management flow:

**Root Cause - Unrestricted Manager Control:**
When `CreateScheme` is called, `Context.Sender` becomes the scheme manager with no validation preventing a contract address from assuming this role. [1](#0-0) 

The manager gains unrestricted control through `AddBeneficiary`, which only validates that `Context.Sender` is the scheme manager but places no limits on the shares that can be added: [2](#0-1) 

**Execution Path:**

1. A malicious contract `M` calls `CreateScheme()` and becomes the manager
2. Honest users call `RegisterForProfits(SchemeManager: M, Amount: X)`, which:
   - Locks their tokens via the Token contract [3](#0-2) 
   - Adds them as beneficiaries with shares equal to locked amount [4](#0-3) 

3. Users cannot withdraw until `MinimumLockMinutes` expires: [5](#0-4) 

4. Malicious contract `M` calls `AddBeneficiary(M, massive_shares)` to dilute all existing beneficiaries
5. When profits distribute, each beneficiary receives `(their_shares / total_shares) * profit`, giving the attacker the majority

**Why Protections Fail:**

The ProfitContract's authorization check only validates the manager identity, not the legitimacy of share additions: [6](#0-5) 

The scheme is created with `CanRemoveBeneficiaryDirectly = true`, allowing the manager to remove legitimate beneficiaries at will: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact - Reward Misallocation:**
- Users lock tokens expecting proportional profit distribution based on their locked amount
- Malicious manager can add arbitrary shares to dilute user proportions to near-zero
- Example: User locks 1,000 tokens (1,000 shares). Manager adds itself with 1,000,000 shares. User receives only 0.1% of profits instead of expected 100%
- All profits contributed to the scheme are redirected to the attacker while legitimate users' tokens remain locked

**Affected Parties:**
- Any users who call `RegisterForProfits` on a scheme managed by a malicious contract
- The TokenHolder contract's reputation and usability for legitimate DApp profit distribution

**Severity Justification:**
This is a **HIGH severity** vulnerability because:
1. Users suffer direct financial loss (stolen profit share)
2. User funds are locked and cannot be recovered until time lock expires
3. No on-chain mechanism exists to detect or prevent this attack
4. Affects fundamental profit distribution invariants

### Likelihood Explanation

**Attacker Capabilities:**
- Deploy a malicious smart contract that calls `CreateScheme`
- The contract can freely call `AddBeneficiary` and `RemoveBeneficiary` as the scheme manager
- No special privileges or governance control required

**Attack Complexity:**
- **LOW** - Requires only:
  1. Deploy a contract with `CreateScheme` call
  2. Wait for users to call `RegisterForProfits` targeting the malicious scheme
  3. Call `AddBeneficiary` to add attacker addresses with massive shares
  4. Call `ContributeProfits` or wait for organic contributions
  5. Call `DistributeProfits` to realize stolen profits

**Feasibility Conditions:**
- Users must be incentivized to register for the malicious scheme (e.g., through social engineering, fake DApp frontend, or promise of high yields)
- Once even a single user registers and locks tokens, the attack becomes profitable
- The scheme creation and beneficiary manipulation can occur in rapid succession

**Detection/Operational Constraints:**
- No on-chain events warn users of share dilution
- Users can query `GetScheme` to see total shares, but this requires active monitoring
- By the time users detect the attack, their tokens are already locked
- No emergency withdrawal mechanism exists

**Probability:** **HIGH** - The attack is straightforward to execute, economically rational (low cost, high reward), and difficult for users to detect before suffering losses.

### Recommendation

**Immediate Mitigations:**

1. **Restrict AddBeneficiary in TokenHolder context** - Modify `AddBeneficiary` to only be callable during scheme creation or remove it entirely from TokenHolder, allowing beneficiaries to be added only through `RegisterForProfits`: [2](#0-1) 

2. **Enforce share-to-locked-token correspondence** - Add validation that beneficiary shares cannot exceed their locked token amount:
   ```csharp
   Assert(input.Shares <= GetLockedAmount(input.Beneficiary, scheme.Symbol), 
          "Shares cannot exceed locked tokens");
   ```

3. **Add share increase limit** - Implement a maximum total share increase per period to prevent sudden dilution attacks.

4. **Add emergency withdrawal** - Allow users to withdraw with a penalty if total shares increase by more than a threshold percentage since their registration.

**Invariant Checks to Add:**
- `sum(all_beneficiary_shares) == sum(all_locked_tokens)` for each scheme
- `manager_shares <= manager_locked_tokens`
- Emit events when shares are modified to enable off-chain monitoring

**Test Cases:**
1. Test that non-manager cannot call `AddBeneficiary`
2. Test that manager cannot add shares exceeding locked amounts
3. Test emergency withdrawal when share dilution detected
4. Test that scheme with contract manager enforces stricter controls

### Proof of Concept

**Initial State:**
- Malicious contract `M` deployed at address `0xMALICIOUS`
- Honest user `U` has 10,000 ELF tokens
- TokenHolder and Profit contracts deployed

**Attack Steps:**

1. **Malicious contract calls CreateScheme:**
   ```
   M.CreateScheme({
     Symbol: "ELF",
     MinimumLockMinutes: 1440  // 1 day lock
   })
   ```
   Result: `M` becomes manager of new scheme [8](#0-7) 

2. **User locks tokens and registers:**
   ```
   U.RegisterForProfits({
     SchemeManager: M,
     Amount: 10000
   })
   ```
   Result: U's 10,000 ELF locked, U added as beneficiary with 10,000 shares [9](#0-8) 

3. **Malicious manager dilutes shares:**
   ```
   M.AddBeneficiary({
     Beneficiary: M,
     Shares: 10000000  // 10 million shares
   })
   ```
   Result: Total shares = 10,010,000, U's proportion = 0.0999% [10](#0-9) 

4. **Profits are contributed and distributed:**
   ```
   ContributeProfits(SchemeManager: M, Amount: 100000, Symbol: "ELF")
   DistributeProfits(SchemeManager: M)
   ```
   Result:
   - U receives: (10000 / 10010000) * 100000 = 99.9 ELF
   - M receives: (10000000 / 10010000) * 100000 = 99900.1 ELF

**Expected vs Actual Result:**
- **Expected:** U receives 100,000 ELF (100% of profits as sole participant)
- **Actual:** U receives 99.9 ELF (0.0999% of profits), M steals 99,900.1 ELF (99.9%)
- **Success Condition:** Attacker receives >99% of profits while victim's tokens remain locked for 1440 minutes

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-176)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
    {
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
        var scheme = GetValidScheme(input.SchemeManager);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = input.Amount
            }
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```
