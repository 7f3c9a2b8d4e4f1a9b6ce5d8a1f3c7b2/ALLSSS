### Title
Caller-Dependent Virtual Address Computation in GetLockedAmount View Method

### Summary
The `GetVirtualAddressForLocking` and `GetLockedAmount` view methods use `Context.Sender` in their virtual address computation, causing these methods to return different results depending on who calls them. This breaks the fundamental expectation that view methods return consistent, caller-independent data, making it impossible for external contracts or users to reliably query locked token amounts.

### Finding Description

The vulnerability exists in the `GetVirtualAddressForLocking` method which computes a virtual address by hashing `Context.Sender`, the target address, and lock ID together. [1](#0-0) 

The `GetLockedAmount` method uses this virtual address to query the balance of locked tokens. [2](#0-1) 

The root cause is that when tokens are locked, the `Lock` method computes the virtual address using the **locking contract's address** as `Context.Sender`. [3](#0-2) 

Similarly, the `Unlock` method uses the same formula to retrieve tokens from the virtual address. [4](#0-3) 

**Why protections fail:**
There are no protections because this is a fundamental design flaw. The view method's virtual address computation includes `Context.Sender`, which varies based on the caller. When Contract A locks tokens for a user, the virtual address is `Hash(ContractA + User + LockId)`. However, when Contract B or any other caller queries `GetLockedAmount` for the same user and lock ID, it computes `Hash(ContractB + User + LockId)`, resulting in a completely different virtual address and returning zero balance even though tokens are locked.

### Impact Explanation

**Operational Impact on Token Locking System:**

1. **Incorrect Balance Reporting**: External contracts and users receive zero or incorrect locked amounts when querying `GetLockedAmount`, even when tokens are actually locked. Only the original locking contract gets the correct result.

2. **Broken Composability**: Integration contracts cannot reliably verify locked token amounts. For example, if an Election contract locks tokens and a Governance contract needs to verify the lock status, the Governance contract will receive incorrect data.

3. **Integration Failures**: Systems that rely on querying locked amounts will make incorrect decisions based on false data. This could lead to:
   - Allowing operations that should be blocked due to locked tokens
   - Preventing operations that should be allowed because the query returns zero
   - Accounting discrepancies in dependent systems

4. **Protocol Trust Issues**: The view method violates the fundamental contract of read-only queries - that they return consistent, factual state data regardless of who queries them. This undermines trust in the entire token locking mechanism.

The documentation describes `GetLockedAmount` as returning "the amount of tokens currently locked by an address" with no mention of caller dependency. [5](#0-4) 

### Likelihood Explanation

**Likelihood: HIGH**

1. **Reachable Entry Point**: `GetLockedAmount` and `GetVirtualAddressForLocking` are public view methods accessible to any caller - contracts or users. [6](#0-5) 

2. **Automatic Occurrence**: The issue triggers automatically whenever any caller except the original locking contract queries locked amounts. No attack or special conditions required - it's the normal behavior of the code.

3. **Real-World Usage**: The TokenHolder contract demonstrates production usage where contracts need to query locked amounts. [7](#0-6) 

4. **No Detection**: Callers have no way to know they're receiving incorrect data. The method returns successfully with a plausible (but wrong) value rather than failing.

5. **Widespread Impact**: Any integration that needs to verify locked token amounts is affected, including cross-contract queries, UI displays, and external verification systems.

### Recommendation

**Code-Level Mitigation:**

1. **Option A - Add Locker Parameter**: Modify `GetVirtualAddressForLocking` to accept the locker contract address as an explicit input parameter instead of using `Context.Sender`:

```csharp
public override Address GetVirtualAddressForLocking(GetVirtualAddressForLockingInput input)
{
    // input should include: Address, LockId, AND LockerAddress
    var fromVirtualAddress = HashHelper.ComputeFrom(input.LockerAddress.Value
        .Concat(input.Address.Value)
        .Concat(input.LockId.Value).ToArray());
    var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
    return virtualAddress;
}
```

2. **Option B - Store Mapping**: During `Lock` operations, store a mapping of `(address, lockId) -> (virtualAddress, lockerContract)` and query from this mapping in view methods:

```csharp
// In Lock method, add:
State.LockRecords[input.Address][input.LockId] = new LockRecord 
{
    VirtualAddress = virtualAddress,
    LockerContract = Context.Sender
};

// In GetLockedAmount:
var lockRecord = State.LockRecords[input.Address][input.LockId];
Assert(lockRecord != null, "Lock not found");
return GetBalance(lockRecord.VirtualAddress, input.Symbol);
```

**Invariant Checks:**
- Add assertion that view methods must not use `Context.Sender` in ways that affect returned data
- Add integration tests verifying that different callers receive identical results from view methods

**Test Cases:**
- Test that Contract A locks tokens, then Contract B queries and receives the correct locked amount
- Test that user queries match contract queries for the same lock
- Test that the same query from different addresses returns identical results

### Proof of Concept

**Initial State:**
- Token "ELF" exists in the system
- User Alice has address `0x123...`
- BasicFunctionContract has address `0xAAA...`
- ElectionContract has address `0xBBB...`
- Lock ID = `Hash("TestLock")`

**Transaction Steps:**

1. **BasicFunctionContract locks 1000 ELF for Alice:**
   - BasicFunctionContract calls `TokenContract.Lock(Address=Alice, Symbol="ELF", Amount=1000, LockId=TestLock)`
   - Virtual address computed: `Hash(0xAAA... + 0x123... + TestLock) = 0xVirt1...`
   - 1000 ELF transferred from Alice to 0xVirt1...
   - Result: SUCCESS, tokens locked

2. **BasicFunctionContract queries locked amount:**
   - BasicFunctionContract calls `TokenContract.GetLockedAmount(Address=Alice, Symbol="ELF", LockId=TestLock)`
   - Virtual address computed: `Hash(0xAAA... + 0x123... + TestLock) = 0xVirt1...` (SAME)
   - Balance queried at 0xVirt1...
   - **Result: 1000 ELF (CORRECT)**

3. **ElectionContract queries same locked amount:**
   - ElectionContract calls `TokenContract.GetLockedAmount(Address=Alice, Symbol="ELF", LockId=TestLock)`
   - Virtual address computed: `Hash(0xBBB... + 0x123... + TestLock) = 0xVirt2...` (DIFFERENT!)
   - Balance queried at 0xVirt2...
   - **Result: 0 ELF (INCORRECT - should be 1000)**

4. **User Alice queries her own locked amount:**
   - Alice calls `TokenContract.GetLockedAmount(Address=Alice, Symbol="ELF", LockId=TestLock)`
   - Virtual address computed: `Hash(0x123... + 0x123... + TestLock) = 0xVirt3...` (ALSO DIFFERENT!)
   - Balance queried at 0xVirt3...
   - **Result: 0 ELF (INCORRECT - should be 1000)**

**Expected vs Actual Result:**
- **Expected**: All three queries return 1000 ELF because that's the actual locked amount
- **Actual**: Only the original locking contract (BasicFunctionContract) gets 1000 ELF; all other callers get 0 ELF

**Success Condition:**
The vulnerability is proven when the same query parameters `(Alice, "ELF", TestLock)` return different locked amounts depending on which contract/address makes the query, demonstrating that the view method produces caller-dependent results instead of consistent data.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L101-116)
```csharp
    public override GetLockedAmountOutput GetLockedAmount(GetLockedAmountInput input)
    {
        Assert(input.LockId != null, "Lock id cannot be null.");
        var virtualAddress = GetVirtualAddressForLocking(new GetVirtualAddressForLockingInput
        {
            Address = input.Address,
            LockId = input.LockId
        });
        return new GetLockedAmountOutput
        {
            Symbol = input.Symbol,
            Address = input.Address,
            LockId = input.LockId,
            Amount = GetBalance(virtualAddress, input.Symbol)
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L118-124)
```csharp
    public override Address GetVirtualAddressForLocking(GetVirtualAddressForLockingInput input)
    {
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        return virtualAddress;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L208-212)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L234-242)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        Context.SendVirtualInline(fromVirtualAddress, Context.Self, nameof(Transfer), new TransferInput
        {
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
```

**File:** docs/resources/smart-contract-apis/multi-token.md (L636-647)
```markdown
This view method returns the amount of tokens currently locked by an address.

Input:
- **address** the address.
- **symbol** the token.
- **lock_id** the lock id.

Output:
- **address** the address.
- **symbol** the token.
- **lock_id** the lock id.
- **amount** the amount currently locked by the specified address.
```

**File:** protobuf/token_contract_impl.proto (L148-151)
```text
    // Compute the virtual address for locking.
    rpc GetVirtualAddressForLocking (GetVirtualAddressForLockingInput) returns (aelf.Address) {
        option (aelf.is_view) = true;
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L220-225)
```csharp
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
```
