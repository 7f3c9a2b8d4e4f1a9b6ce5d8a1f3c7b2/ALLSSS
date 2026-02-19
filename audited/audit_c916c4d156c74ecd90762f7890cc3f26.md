### Title
Scheme ID Collision Enables Denial of Service on Profit Scheme Creation

### Summary
The `GenerateSchemeId()` function generates scheme IDs using only the scheme count per manager without including the manager's address in the hash. This causes different managers with the same scheme count to generate identical scheme IDs, allowing attackers to front-run and deny service to any user attempting to create profit schemes.

### Finding Description

The vulnerability exists in the `GenerateSchemeId()` function where scheme IDs are generated without including the manager address: [1](#0-0) 

When a token is not provided, the function generates the ID as `Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false))` where `createdSchemeCount` is retrieved from `State.ManagingSchemeIds[manager]?.SchemeIds.Count ?? 0`. The manager address is determined but **never included** in the ID generation, only the count is used.

In `CreateScheme()`, the generated ID is checked for uniqueness: [2](#0-1) 

**Root Cause:** The hash generation omits the manager address, meaning:
- Manager A creating their 1st scheme generates: `Hash(ProfitContract, 0)`
- Manager B creating their 1st scheme generates: `Hash(ProfitContract, 0)` 
- **Result:** Identical scheme IDs causing collision

Other contracts properly avoid this. For example, the Election contract includes the candidate pubkey: [3](#0-2) 

Similarly, TokenHolder includes both scheme manager and sender addresses: [4](#0-3) 

### Impact Explanation

**Operational Impact - Complete DoS:**
- Any attacker can permanently prevent any target user from creating profit schemes
- Once an attacker creates their Nth scheme, no other user can create their Nth scheme
- This breaks the core functionality of the Profit contract
- Affects all users attempting to create schemes without providing a custom token parameter

**Who is Affected:**
- All users who call `CreateScheme` without providing the optional `token` field
- Protocol contracts (Treasury, TokenHolder, etc.) that rely on creating profit schemes

**Severity Justification:**
Medium severity because while it's a complete DoS of scheme creation functionality, the mitigation exists (users can provide a token parameter), though this is not documented or enforced. The attack is trivial to execute with predictable outcomes. [5](#0-4) 

### Likelihood Explanation

**Attack Complexity:** Very Low
- Attacker monitors pending transactions or predicts when a victim will create a scheme
- Attacker front-runs by creating their own scheme at the same count
- No special permissions or resources required beyond gas fees

**Attacker Capabilities:**
- Read on-chain state to determine any manager's current scheme count via `GetManagingSchemeIds`
- Submit transactions to create schemes
- Standard front-running via higher gas price or MEV

**Feasibility:** Highly Practical
- The count is publicly readable on-chain
- Transaction ordering is controllable via gas price
- Attack succeeds immediately with first successful collision

**Detection/Constraints:**
- Attack is easily detectable on-chain but unstoppable once executed
- No rate limiting or uniqueness enforcement exists beyond the existence check
- Economic cost is minimal (only gas fees)

### Recommendation

**Fix 1: Include Manager Address in ID Generation (Recommended)**

Modify `GenerateSchemeId()` to include the manager address in the hash:

```csharp
private Hash GenerateSchemeId(CreateSchemeInput createSchemeInput)
{
    var manager = createSchemeInput.Manager ?? Context.Sender;
    if (createSchemeInput.Token != null)
        return Context.GenerateId(Context.Self, createSchemeInput.Token);
    var createdSchemeCount = State.ManagingSchemeIds[manager]?.SchemeIds.Count ?? 0;
    return Context.GenerateId(Context.Self, 
        ByteArrayHelper.ConcatArrays(manager.ToByteArray(), createdSchemeCount.ToBytes(false)));
}
```

**Fix 2: Enforce Token Parameter (Alternative)**

Require the token parameter to be provided:
```csharp
Assert(createSchemeInput.Token != null, "Token parameter required for unique scheme ID generation.");
```

**Test Cases to Add:**
1. Test that two different managers can create schemes with the same count
2. Test that scheme IDs are unique across all managers
3. Regression test: Verify no collision occurs when multiple managers create schemes simultaneously

### Proof of Concept

**Initial State:**
- Manager A (address 0xAAA) has created 0 schemes
- Manager B (address 0xBBB) has created 0 schemes

**Attack Sequence:**

1. **Attacker monitors** that Manager B will create their first scheme
2. **Attacker (Manager A) calls** `CreateScheme({})` with no token parameter
   - ID generated: `Hash(ProfitContract, 0)` 
   - Scheme stored at this ID with Manager A as owner
   - `State.ManagingSchemeIds[0xAAA].Count` = 1
3. **Victim (Manager B) calls** `CreateScheme({})` with no token parameter
   - ID generated: `Hash(ProfitContract, 0)` (same as step 2!)
   - Assertion fails: `Assert(State.SchemeInfos[schemeId] == null, "Already exists.")`
   - Transaction reverts
4. **Result:** Manager B cannot create any scheme with count=0

**Expected vs Actual:**
- **Expected:** Each manager should be able to create schemes independently
- **Actual:** Collision prevents victim from creating schemes, causing DoS

**Success Condition:** Manager B's `CreateScheme` transaction reverts with "Already exists" error despite them never having created a scheme before.

**Notes:**

The vulnerability is exacerbated by the fact that the `token` parameter workaround is not enforced or well-documented. Most users following the test examples would not provide this parameter and would be vulnerable to this DoS attack. The proto definition mentions the token field at line 132 as "Use to generate scheme id" but this critical security implication is not highlighted.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-60)
```csharp
        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
        State.SchemeInfos[schemeId] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L964-971)
```csharp
    private Hash GenerateSchemeId(CreateSchemeInput createSchemeInput)
    {
        var manager = createSchemeInput.Manager ?? Context.Sender;
        if (createSchemeInput.Token != null)
            return Context.GenerateId(Context.Self, createSchemeInput.Token);
        var createdSchemeCount = State.ManagingSchemeIds[manager]?.SchemeIds.Count ?? 0;
        return Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false));
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L407-411)
```csharp
        var candidateVotesCount =
            State.CandidateVotes[voteMinerInput.CandidatePubkey]?.ObtainedActiveVotedVotesAmount ?? 0;
        return Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(voteMinerInput.CandidatePubkey.GetBytes(),
                candidateVotesCount.ToBytes(false)));
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L157-158)
```csharp
        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
```

**File:** protobuf/profit_contract.proto (L131-132)
```text
    // Use to generate scheme id.
    aelf.Hash token = 6;
```
