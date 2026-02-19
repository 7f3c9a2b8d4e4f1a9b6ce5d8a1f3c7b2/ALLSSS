### Title
Allowance Bypass in Lock() Function Enables Unlimited Token Locking by Whitelisted Contracts

### Summary
The `Lock()` function contains a critical allowance bypass vulnerability where whitelisted contracts (Election and Vote) can lock unlimited tokens from users who have granted approvals, far exceeding the approved amounts. The allowance check at lines 204-206 only conditionally decrements the allowance but never enforces it, allowing repeated calls to drain user balances.

### Finding Description

The vulnerability exists in the `Lock()` function's allowance validation logic. [1](#0-0) 

The code reads the allowance and conditionally decrements it if `allowance >= input.Amount`, but when `allowance < input.Amount`, execution continues without any assertion or error. The transfer proceeds regardless at line 212. [2](#0-1) 

This contrasts sharply with the correct pattern implemented in `DoTransferFrom()`, which properly enforces allowance limits by asserting when insufficient: [3](#0-2) 

The authorization check at lines 201-202 allows whitelisted contracts (Election and Vote contracts, identified at lines 378-403) to call `Lock()`: [4](#0-3) [5](#0-4) 

The `DoTransfer()` function only validates balance, not allowance: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Fund Impact**: Users lose control over their tokens. When a user approves a whitelisted contract (Election or Vote) for amount X, they expect only X tokens can be locked. However, the contract can lock their entire balance by repeatedly calling `Lock()`.

**Affected Parties**: All users who have granted token approvals to Election or Vote contracts are at risk. This breaks the fundamental trust model of the allowance mechanism.

**Severity Justification**: HIGH severity because:
- Complete bypass of allowance protection mechanism
- Affects core token security invariant: "allowance/approval enforcement"
- Direct, quantifiable fund loss (all approved tokens can be drained)
- Exploitation only requires whitelisted contract to make multiple `Lock()` calls

### Likelihood Explanation

**Attacker Capabilities**: The attacker must either:
1. Compromise or find a vulnerability in the Election or Vote contract that allows arbitrary `Lock()` calls
2. Be a malicious operator of these trusted system contracts

**Attack Complexity**: Low - once the precondition is met, the attack is straightforward repeated calls to `Lock()`.

**Feasibility**: 
- Entry point is publicly accessible through whitelisted contracts
- No special permissions beyond whitelist status required
- Attack leaves clear on-chain evidence but may complete before detection

**Detection/Operational Constraints**: The vulnerability is exploitable immediately after any user approves tokens to whitelisted contracts (common operation for staking/voting).

**Probability**: While exploitation requires either compromising a system contract or malicious behavior by trusted contracts, the impact is severe enough that the risk must be mitigated. Historical precedent shows system contracts can contain vulnerabilities.

### Recommendation

**Code-level Mitigation**: Modify the allowance check to enforce limits similar to `DoTransferFrom()`:

```csharp
var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];

// Allow users to lock their own tokens without allowance check
if (Context.Origin != input.Address)
{
    if (allowance < input.Amount)
    {
        Assert(false, 
            $"Insufficient allowance. Token: {input.Symbol}; {allowance}/{input.Amount}.\n" +
            $"From:{input.Address}\tSpender:{Context.Sender}");
    }
    State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
}
```

**Invariant Checks**: 
1. Assert allowance sufficiency before any token movement when caller is not the token owner
2. Always decrement allowance after successful lock if allowance was checked

**Test Cases**:
1. Test that whitelisted contract cannot lock more than approved amount
2. Test that multiple `Lock()` calls properly consume cumulative allowances
3. Test that users can still lock their own tokens without approval
4. Test allowance exhaustion scenarios with exact amounts

### Proof of Concept

**Initial State**:
- Alice has 1000 ELF tokens in her balance
- Alice approves Election contract for 100 ELF tokens
- `State.Allowances[Alice][ElectionContract][ELF] = 100`

**Step 1**: Election contract calls `Lock(Address=Alice, Symbol=ELF, Amount=100, LockId=X)`
- Line 201-202: Passes (Election is whitelisted)
- Line 204: `allowance = 100`
- Line 205-206: `100 >= 100` is true, allowance decremented to 0
- Line 212: `DoTransfer` succeeds (Alice has 1000 balance)
- **Result**: 100 ELF locked, allowance now 0

**Step 2**: Election contract calls `Lock(Address=Alice, Symbol=ELF, Amount=900, LockId=Y)`
- Line 201-202: Passes (Election is whitelisted)
- Line 204: `allowance = 0`
- Line 205-206: `0 >= 900` is FALSE, condition skipped, no assertion
- Line 212: `DoTransfer` succeeds (Alice has 900 balance remaining)
- **Result**: Additional 900 ELF locked

**Expected vs Actual**:
- **Expected**: Second lock should fail with "Insufficient allowance" error
- **Actual**: Second lock succeeds, total 1000 ELF locked despite only 100 approved

**Success Condition**: Attacker successfully locked 10x the approved amount without any error or revert.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L201-202)
```csharp
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Lock behaviour should be initialed by origin address.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L204-206)
```csharp
        var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
        if (allowance >= input.Amount)
            State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L212-212)
```csharp
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L76-89)
```csharp
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L99-114)
```csharp
    private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
    {
        Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
        Assert(from != to, "Can't do transfer to sender itself.");
        AssertValidMemo(memo);
        ModifyBalance(from, symbol, -amount);
        ModifyBalance(to, symbol, amount);
        Context.Fire(new Transferred
        {
            From = from,
            To = to,
            Symbol = symbol,
            Amount = amount,
            Memo = memo ?? string.Empty
        });
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L378-403)
```csharp
    private bool IsInLockWhiteList(Address address)
    {
        return address == GetElectionContractAddress() || address == GetVoteContractAddress();
    }

    private Address GetElectionContractAddress()
    {
        if (State.ElectionContractAddress.Value == null)
        {
            State.ElectionContractAddress.Value =
                Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        }
        
        return State.ElectionContractAddress.Value;
    }
    
    private Address GetVoteContractAddress()
    {
        if (State.VoteContractAddress.Value == null)
        {
            State.VoteContractAddress.Value =
                Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName);
        }
        
        return State.VoteContractAddress.Value;
    }
```
