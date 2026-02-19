### Title
NFT Approval Change Vulnerable to Front-Running Attack

### Summary
The NFT contract's `Approve` method directly overwrites allowance values without any protection against front-running attacks. When an NFT owner attempts to change an approval from one non-zero value to another, a malicious spender can front-run the transaction to extract both the old and new allowance amounts, resulting in unauthorized token transfers exceeding the owner's intent.

### Finding Description

The vulnerability exists in the `Approve` method which directly sets the allowance to a new value without any safeguards: [1](#0-0) 

The `AllowanceMap` state variable stores approvals as a three-level mapping: [2](#0-1) 

When an approval change transaction is submitted, it sits in the mempool before being included in a block. During this time, the spender can observe the pending transaction and submit a `TransferFrom` call with higher priority to execute first: [3](#0-2) 

The contract provides an `UnApprove` method for decreasing allowances, but this does not solve the front-running issue as it can also be front-run: [4](#0-3) 

**Why existing protections fail:**
- No requirement to set allowance to 0 before changing to a new value
- No check that the current allowance matches an expected value
- No increaseAllowance/decreaseAllowance pattern (confirmed absent from entire codebase)
- The operator mechanism is separate and doesn't prevent this attack on allowance-based approvals

### Impact Explanation

**Direct Fund Impact:** An NFT owner who changes an approval from amount X to amount Y can lose up to X tokens beyond their intent. For example, if an owner reduces approval from 100 tokens to 50 tokens, the attacker can extract 150 tokens total (100 before the change + 50 after).

**Who is affected:** Any NFT owner who:
1. Has granted an approval to a spender
2. Attempts to modify that approval to a different non-zero value
3. Has the spender monitoring the mempool for such changes

**Quantified damage:** Maximum loss = (old_allowance + new_allowance) - intended_allowance per approval change. In a collection with valuable NFTs, this could result in significant unauthorized transfers.

**Severity justification:** Medium-High. While the attack requires the victim to have an existing approval with the attacker, changing approvals is a common operation. The attack is deterministic and requires minimal sophistication (mempool monitoring). The impact is direct theft of NFT tokens.

### Likelihood Explanation

**Attacker capabilities required:**
- Must have been previously approved by the victim
- Ability to monitor mempool for pending transactions
- Ability to submit transactions with higher priority/gas

**Attack complexity:** Low. Mempool monitoring and transaction front-running are well-established attack techniques with readily available tools.

**Feasibility conditions:**
- No special permissions required beyond existing approval
- Works on any public blockchain with visible mempool
- Transaction ordering can be influenced by gas prices or validator selection

**Detection constraints:** While the attack can be detected by monitoring on-chain events, detection occurs after the exploit has succeeded. The victim cannot prevent the attack once both transactions are in the mempool.

**Probability:** High in active blockchain environments where mempool monitoring is common. The attack is economically rational when the value of NFTs exceeds transaction costs.

### Recommendation

**Primary fix - Implement safe approval pattern:**

Add two new methods to replace direct `Approve` usage:

```csharp
public override Empty IncreaseAllowance(IncreaseAllowanceInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    var currentAllowance = State.AllowanceMap[tokenHash][Context.Sender][input.Spender];
    State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = currentAllowance.Add(input.Amount);
    // Fire event
    return new Empty();
}

public override Empty DecreaseAllowance(DecreaseAllowanceInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    var currentAllowance = State.AllowanceMap[tokenHash][Context.Sender][input.Spender];
    Assert(currentAllowance >= input.Amount, "Insufficient allowance to decrease.");
    State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = currentAllowance.Sub(input.Amount);
    // Fire event
    return new Empty();
}
```

**Alternative fix - Add protection to existing Approve:**

Modify `Approve` to require setting to 0 first:

```csharp
public override Empty Approve(ApproveInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    var currentAllowance = State.AllowanceMap[tokenHash][Context.Sender][input.Spender];
    
    // Require intermediate step to 0 if changing between non-zero values
    Assert(currentAllowance == 0 || input.Amount == 0 || currentAllowance == input.Amount,
        "To change approval, first set to 0 then set new value.");
    
    State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = input.Amount;
    // Fire event and return
}
```

**Test cases to add:**
1. Test that changing approval from 100→50 requires two transactions (100→0, then 0→50)
2. Test increaseAllowance/decreaseAllowance work correctly with front-running attempts
3. Test that TransferFrom cannot exploit approval changes

### Proof of Concept

**Initial state:**
- Alice owns 200 units of NFT token (Symbol: "TEST", TokenId: 1)
- Alice has approved Bob for 100 units
- Current allowance: `AllowanceMap[tokenHash][Alice][Bob] = 100`

**Attack sequence:**

1. **Block N:** Alice decides to reduce Bob's approval to 50 units
   - Alice submits: `Approve(spender: Bob, symbol: "TEST", tokenId: 1, amount: 50)`
   - Transaction enters mempool, not yet executed

2. **Mempool monitoring:** Bob's monitoring software detects Alice's pending approval change

3. **Front-running:** Bob immediately submits with higher gas/priority:
   - Bob submits: `TransferFrom(from: Alice, to: Bob, symbol: "TEST", tokenId: 1, amount: 100)`

4. **Block N+1 execution order:**
   - **First:** Bob's TransferFrom executes
     - Allowance check passes: `100 >= 100` ✓
     - Allowance updated: `100 - 100 = 0`
     - Bob receives 100 tokens
   - **Second:** Alice's Approve executes
     - Allowance set: `0 → 50`

5. **Block N+2:** Bob can now call TransferFrom again:
   - Bob submits: `TransferFrom(from: Alice, to: Bob, symbol: "TEST", tokenId: 1, amount: 50)`
   - Allowance check passes: `50 >= 50` ✓
   - Bob receives another 50 tokens

**Expected result:** Bob should have received only 50 tokens (the new approval amount)

**Actual result:** Bob received 150 tokens (100 + 50)

**Success condition:** Bob's balance increased by 150 tokens instead of the intended 50 tokens, demonstrating the front-running vulnerability in the approval change mechanism.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L57-80)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var operatorList = State.OperatorMap[input.Symbol][input.From];
        var isOperator = operatorList?.Value.Contains(Context.Sender) ?? false;
        if (!isOperator)
        {
            var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
            Assert(allowance >= input.Amount, "Not approved.");
            State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
        }

        DoTransfer(tokenHash, input.From, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = input.From,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L295-308)
```csharp
    public override Empty Approve(ApproveInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = input.Amount;
        Context.Fire(new Approved
        {
            Owner = Context.Sender,
            Spender = input.Spender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            TokenId = input.TokenId
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L310-328)
```csharp
    public override Empty UnApprove(UnApproveInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var oldAllowance = State.AllowanceMap[tokenHash][Context.Sender][input.Spender];
        var currentAllowance = oldAllowance.Sub(input.Amount);
        if (currentAllowance <= 0) currentAllowance = 0;

        State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = currentAllowance;

        Context.Fire(new UnApproved
        {
            Owner = Context.Sender,
            Spender = input.Spender,
            Symbol = input.Symbol,
            CurrentAllowance = currentAllowance,
            TokenId = input.TokenId
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L26-30)
```csharp
    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }
```
