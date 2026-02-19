### Title
Dual Authorization Allows Double-Spend of NFT Allowances via Operator Bypass

### Summary
The NFT contract's `TransferFrom` method allows an address to be simultaneously authorized as both a protocol-level operator and a token-specific spender with allowance. When an operator transfers tokens, the allowance is not consumed because the operator check bypasses the allowance logic entirely. This enables an attacker who has been granted both authorizations to transfer more tokens than the owner explicitly approved via the `Approve` method.

### Finding Description

The vulnerability exists in the authorization logic of the `TransferFrom` method: [1](#0-0) 

The contract maintains two separate authorization mechanisms:

1. **OperatorMap**: Protocol-level authorization granting unlimited transfer rights for all tokens in a protocol [2](#0-1) 

2. **AllowanceMap**: Token-specific authorization for limited amounts [3](#0-2) 

**Root Cause**: In `TransferFrom`, the code first checks if the sender is an operator. If true, it completely skips the allowance check and deduction (lines 62-67). This means:
- When an operator transfers tokens, `AllowanceMap` remains unchanged
- The same address can later use their unused allowance even after using operator privileges
- No mutual exclusion or consumption logic exists between the two authorization types

The owner can grant both authorizations through separate methods:
- `ApproveProtocol`: Adds an address to OperatorMap [4](#0-3) 

- `Approve`: Sets an allowance in AllowanceMap [5](#0-4) 

The contract has no mechanism to prevent both authorizations from being active simultaneously, nor does it invalidate one when the other is used.

### Impact Explanation

**Direct Fund Impact**: An attacker can steal NFTs beyond the explicitly approved amount.

**Concrete Scenario**:
- Owner has 2 units of NFT "ABC-1" and wants to authorize transfer of only 1 unit
- Owner calls `Approve(spender=Attacker, amount=1)` → explicitly authorizes 1 unit
- Owner also calls `ApproveProtocol(operator=Attacker, approved=true)` → grants operator status (possibly by mistake or misunderstanding the implications)
- Attacker calls `TransferFrom` as operator → transfers 1 unit, allowance NOT consumed (still 1)
- Owner calls `ApproveProtocol(operator=Attacker, approved=false)` → revokes operator status, believing Attacker can only transfer the 1 unit allowance remaining
- Attacker calls `TransferFrom` using allowance → transfers 1 more unit
- **Result**: Attacker transferred 2 units total when owner only explicitly approved 1 unit via `Approve`

**Who is Affected**: NFT owners who grant both operator status and explicit allowances to the same address, either through:
- User error/confusion about authorization types
- Changing authorization model (e.g., restricting an operator to limited allowance)
- Multi-step authorization workflows

**Severity Justification**: HIGH - Violates the principle of explicit authorization and can lead to unauthorized asset transfers. While requiring owner to grant both authorizations, this can realistically occur due to UI confusion or authorization management mistakes.

### Likelihood Explanation

**Attacker Capabilities**: 
- Must be granted both operator status AND explicit allowance by the same owner
- No special privileges required beyond these authorizations
- Can be any address (EOA or contract)

**Attack Complexity**: LOW
- Simple sequence of `TransferFrom` calls
- No complex timing, reentrancy, or state manipulation required
- Straightforward exploitation once preconditions are met

**Feasibility Conditions**:
- Owner must call both `ApproveProtocol` and `Approve` for the same address
- Can occur through legitimate user error or misunderstanding of authorization models
- Wallet UIs may not clearly distinguish between operator and allowance authorization
- Users migrating from operator-based to allowance-based authorization may leave both active

**Detection/Operational Constraints**:
- Contract provides separate view functions for operator status and allowances, making simultaneous authorization visible
- No on-chain monitoring or alerts for dual authorization state
- Exploitation appears as legitimate authorized transfers

**Probability Reasoning**: MEDIUM-HIGH
- Requires specific precondition (dual authorization) but this is a realistic user error
- Authorization model confusion is common in NFT ecosystems
- Once conditions are met, exploitation is deterministic and undetectable

### Recommendation

**Immediate Fix**: Modify `TransferFrom` to consume allowance even when caller is an operator, treating them as mutually exclusive authorization paths:

```csharp
public override Empty TransferFrom(TransferFromInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    var operatorList = State.OperatorMap[input.Symbol][input.From];
    var isOperator = operatorList?.Value.Contains(Context.Sender) ?? false;
    
    // If caller has explicit allowance, use and consume it regardless of operator status
    var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
    if (allowance > 0)
    {
        Assert(allowance >= input.Amount, "Not approved.");
        State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
    }
    else if (!isOperator)
    {
        // Only fail if caller is neither approved spender nor operator
        Assert(false, "Not approved.");
    }
    
    DoTransfer(tokenHash, input.From, input.To, input.Amount);
    // ... rest of method
}
```

**Alternative Fix**: Clear allowance when granting operator status and vice versa:

```csharp
public override Empty ApproveProtocol(ApproveProtocolInput input)
{
    Assert(State.NftProtocolMap[input.Symbol] != null, $"Protocol {input.Symbol} not exists.");
    var operatorList = State.OperatorMap[input.Symbol][Context.Sender] ?? new AddressList();
    
    if (input.Approved && !operatorList.Value.Contains(input.Operator))
    {
        operatorList.Value.Add(input.Operator);
        // Clear all specific token allowances for this operator when granting operator status
        // (Implementation would require iterating or adding a reverse mapping)
    }
    // ... rest of method
}
```

**Invariant to Add**:
- At any given time, an address should have EITHER operator status OR specific allowance, not both
- If both are set, one authorization path should be consumed/checked before the other

**Test Cases**:
1. Test that operator transfers consume allowance if one exists
2. Test that granting operator status clears existing allowances (if using alternative fix)
3. Test that granting allowance when operator status exists results in allowance taking precedence
4. Comprehensive integration test covering the exploit scenario described above

### Proof of Concept

**Initial State**:
- Alice (owner) has 2 units of NFT "SYMBOL-1"
- Bob (attacker) has no tokens or authorizations

**Transaction Sequence**:

1. **Alice approves Bob for 1 unit**:
   ```
   NFTContract.Approve({
     Spender: Bob,
     Symbol: "SYMBOL",
     TokenId: 1,
     Amount: 1
   })
   ```
   State: `AllowanceMap[tokenHash][Alice][Bob] = 1`

2. **Alice makes Bob an operator** (by mistake or misunderstanding):
   ```
   NFTContract.ApproveProtocol({
     Operator: Bob,
     Symbol: "SYMBOL",
     Approved: true
   })
   ```
   State: `OperatorMap["SYMBOL"][Alice]` contains Bob

3. **Bob transfers 1 unit as operator**:
   ```
   NFTContract.TransferFrom({
     From: Alice,
     To: Bob,
     Symbol: "SYMBOL",
     TokenId: 1,
     Amount: 1
   })
   ```
   - Check: `isOperator = true` → allowance check skipped
   - Result: Transfer succeeds, Alice balance: 2→1, Bob balance: 0→1
   - **Critical**: `AllowanceMap[tokenHash][Alice][Bob]` still = 1 (unchanged)

4. **Alice revokes Bob's operator status** (thinking Bob only has 1 unit allowance left):
   ```
   NFTContract.ApproveProtocol({
     Operator: Bob,
     Symbol: "SYMBOL",
     Approved: false
   })
   ```
   State: Bob removed from `OperatorMap["SYMBOL"][Alice]`

5. **Bob transfers 1 more unit using allowance**:
   ```
   NFTContract.TransferFrom({
     From: Alice,
     To: Bob,
     Symbol: "SYMBOL",
     TokenId: 1,
     Amount: 1
   })
   ```
   - Check: `isOperator = false` → enters allowance check
   - Check: `allowance (1) >= amount (1)` → passes
   - Result: Transfer succeeds, Alice balance: 1→0, Bob balance: 1→2
   - `AllowanceMap[tokenHash][Alice][Bob] = 0`

**Expected Result**: Bob should only transfer 1 unit total (the approved amount)

**Actual Result**: Bob transferred 2 units total (1 via operator, 1 via allowance)

**Success Condition**: Bob's final balance is 2 units despite Alice only explicitly approving transfer of 1 unit via `Approve` method.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L238-254)
```csharp
    public override Empty ApproveProtocol(ApproveProtocolInput input)
    {
        Assert(State.NftProtocolMap[input.Symbol] != null, $"Protocol {input.Symbol} not exists.");
        var operatorList = State.OperatorMap[input.Symbol][Context.Sender] ?? new AddressList();
        switch (input.Approved)
        {
            case true when !operatorList.Value.Contains(input.Operator):
                operatorList.Value.Add(input.Operator);
                break;
            case false when operatorList.Value.Contains(input.Operator):
                operatorList.Value.Remove(input.Operator);
                break;
        }

        State.OperatorMap[input.Symbol][Context.Sender] = operatorList;
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L26-30)
```csharp
    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L42-45)
```csharp
    /// <summary>
    ///     Symbol (Protocol) -> Owner Address -> Operator Address List
    /// </summary>
    public MappedState<string, Address, AddressList> OperatorMap { get; set; }
```
