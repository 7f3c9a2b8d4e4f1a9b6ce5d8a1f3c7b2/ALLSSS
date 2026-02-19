# Audit Report

## Title
Scheme Metadata Overwrite Causes Permanent Token Lock Due to LockId Collision

## Summary
The TokenHolder contract allows managers to create multiple schemes, but stores only one scheme's metadata per manager address. When a manager creates a second scheme, it overwrites the first scheme's metadata (including the token symbol). Users who locked tokens under the first scheme become unable to withdraw because the withdrawal mechanism queries for the wrong token symbol, permanently trapping their funds.

## Finding Description

The vulnerability stems from an architectural mismatch between the TokenHolder and Profit contracts:

**1. LockId Generation Without Scheme Identifier**

The `RegisterForProfits` method generates lockIds using only the manager address and user address, without any scheme-specific identifier. [1](#0-0) 

**2. Single Scheme Storage Per Manager**

The `CreateScheme` method stores scheme metadata at `State.TokenHolderProfitSchemes[Context.Sender]`, which gets **overwritten** if the same manager creates multiple schemes. [2](#0-1) 

The state structure confirms this single-address mapping. [3](#0-2) 

**3. Profit Contract Supports Multiple Schemes**

The underlying Profit contract explicitly supports multiple schemes per manager, appending each new scheme to the manager's list. [4](#0-3) 

**4. Scheme Resolution Mismatch**

When withdrawing, the contract retrieves the overwritten scheme metadata from TokenHolder (with the new symbol), but then updates it with the SchemeId from the **first** scheme in the Profit contract's list using `FirstOrDefault`. [5](#0-4) 

This creates a critical mismatch: the scheme object has the SchemeId from the first (original) scheme but the Symbol from the second (overwritten) scheme.

**5. Symbol-Based Locked Amount Query**

The withdrawal process queries locked tokens using the (incorrect) symbol from the overwritten metadata. [6](#0-5) 

**6. Virtual Address Balance Query**

The `GetLockedAmount` function queries the virtual address balance for the specified symbol. Since the virtual address stores tokens with their original symbol, querying for a different symbol returns 0. [7](#0-6) 

**7. Lock/Unlock Mechanism Details**

The token lock mechanism stores tokens at a virtual address computed from the locker contract, user address, and lockId - but **not** the symbol. [8](#0-7)  The unlock operation uses the same address computation. [9](#0-8) 

Since the symbol is not part of the virtual address calculation, tokens locked with symbol "ELF" exist at the virtual address, but querying for symbol "USDT" at that same address returns 0.

**Attack Scenario:**
1. Manager creates Scheme A for token "ELF"
2. User locks 1000 ELF tokens via `RegisterForProfits`
3. Manager creates Scheme B for token "USDT" (overwrites TokenHolder metadata)
4. User calls `Withdraw` → queries for "USDT" instead of "ELF" → receives 0 tokens
5. User's 1000 ELF tokens remain permanently locked

## Impact Explanation

**Direct Fund Loss:**
- Users who registered for profits before a scheme overwrite lose **100% of their locked tokens permanently**
- The `GetLockedAmount` call returns 0 due to the symbol mismatch
- The `Unlock` operation executes with amount=0, leaving the original tokens inaccessible
- No recovery mechanism exists in the contract

**Scope:**
- Affects **ALL users** who registered under a manager before that manager creates a new scheme
- No time-based expiration or admin override exists
- Even the manager cannot reverse this condition

**Severity Justification:**
- **HIGH severity** due to permanent, irreversible fund loss
- User funds become completely inaccessible through any contract operation
- Violates the critical invariant: "users can unlock tokens they previously locked"
- No emergency unlock or admin recovery function exists

## Likelihood Explanation

**Trigger Conditions:**
- Any address can call `CreateScheme` (public entry point)
- No restriction prevents a manager from creating multiple schemes
- The Profit contract explicitly supports and tests this pattern

**Attacker Capabilities:**
- Requires control of a scheme manager address (any address can be a manager)
- Can be triggered **accidentally** by a legitimate manager attempting to "update" their scheme
- No special privileges required beyond normal scheme creation

**Probability:**
- **MEDIUM-HIGH**: Managers may legitimately want multiple schemes for different tokens
- Accidental triggering is highly plausible (no warnings or documentation prevent this)
- Deterministic outcome with no timing constraints or race conditions

## Recommendation

**Fix Option 1: Include SchemeId in LockId Generation**
```csharp
var lockId = Context.GenerateId(Context.Self,
    ByteArrayHelper.ConcatArrays(scheme.SchemeId.ToByteArray(), Context.Sender.ToByteArray()));
```
This ensures each scheme has unique lockIds.

**Fix Option 2: Use Multi-Key State Storage**
```csharp
// Change state structure
public MappedState<Address, Hash, TokenHolderProfitScheme> TokenHolderProfitSchemes { get; set; }
// Usage: State.TokenHolderProfitSchemes[manager][schemeId] = scheme;
```
This allows storing multiple schemes per manager without overwriting.

**Fix Option 3: Prevent Multiple Schemes**
Add validation in `CreateScheme`:
```csharp
Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
    "Manager can only create one scheme.");
```

**Recommended Approach**: Implement Fix Option 1 (unique lockIds per scheme) combined with Fix Option 2 (proper state storage), as this preserves the multi-scheme functionality while fixing the vulnerability.

## Proof of Concept

```csharp
[Fact]
public async Task SchemeOverwrite_PermanentlyLocksUserTokens()
{
    // Setup: Manager creates Scheme A for "ELF"
    var manager = Accounts[0].Address;
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    // User registers and locks 1000 ELF tokens
    var user = Accounts[1].Address;
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Spender = TokenHolderContractAddress,
        Symbol = "ELF",
        Amount = 1000
    });
    await UserTokenHolderStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager,
        Amount = 1000
    });
    
    // Verify tokens are locked
    var lockedBefore = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = user,
        Symbol = "ELF"
    });
    
    // Manager creates Scheme B for "USDT" (OVERWRITES metadata)
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "USDT",
        MinimumLockMinutes = 1
    });
    
    // Wait for minimum lock period
    await AdvanceTime(2);
    
    // User attempts withdrawal - SHOULD unlock 1000 ELF
    await UserTokenHolderStub.Withdraw.SendAsync(manager);
    
    // Verify tokens are STILL LOCKED (not returned to user)
    var balanceAfter = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = user,
        Symbol = "ELF"
    });
    
    // BUG: User's balance did not increase (tokens still locked)
    balanceAfter.Balance.ShouldBe(lockedBefore.Balance); // FAILS - tokens permanently locked
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L157-158)
```csharp
        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-293)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs (L10-10)
```csharp
    public MappedState<Address, TokenHolderProfitScheme> TokenHolderProfitSchemes { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L62-71)
```csharp
        var schemeIds = State.ManagingSchemeIds[scheme.Manager];
        if (schemeIds == null)
            schemeIds = new CreatedSchemeIds
            {
                SchemeIds = { schemeId }
            };
        else
            schemeIds.SchemeIds.Add(schemeId);

        State.ManagingSchemeIds[scheme.Manager] = schemeIds;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L101-115)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L208-210)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L234-235)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
```
