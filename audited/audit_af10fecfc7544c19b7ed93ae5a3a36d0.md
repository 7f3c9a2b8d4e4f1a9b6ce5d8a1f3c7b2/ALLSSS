### Title
Cross-Scheme State Confusion Due to One-to-One Mapping Limitation in TokenHolder Contract

### Summary
The TokenHolder contract enforces a one-to-one relationship between manager addresses and schemes through `TokenHolderProfitSchemes` mapping, while the underlying Profit contract supports multiple schemes per manager. When a user calls `CreateScheme` multiple times, the second call overwrites the first scheme's metadata but creates a new scheme in the Profit contract, leading to cross-scheme state confusion where operations use metadata from one scheme but the SchemeId from another.

### Finding Description

The vulnerability exists in the scheme storage architecture of the TokenHolder contract: [1](#0-0) 

This storage structure only allows one scheme per address. However, `CreateScheme` creates a new scheme in the Profit contract every time it's called: [2](#0-1) 

And then overwrites the previous TokenHolder storage entry: [3](#0-2) 

The Profit contract explicitly supports multiple schemes per manager, as evidenced by maintaining a list: [4](#0-3) [5](#0-4) 

When `GetValidScheme` is called and the SchemeId is null, `UpdateTokenHolderProfitScheme` retrieves only the FIRST scheme from the manager's list: [6](#0-5) 

This creates inconsistent state where the TokenHolder scheme contains metadata (symbol, minimum_lock_minutes, auto_distribute_threshold) from the second scheme creation, but the SchemeId and Period from the first scheme.

### Impact Explanation

**Direct Fund Impact:**
1. Users who call `CreateScheme` twice will lock the wrong token type. For example, if Scheme A expects "ELF" but the stored metadata says "USDT", `RegisterForProfits` will attempt to lock USDT tokens for a scheme that distributes ELF profits. [7](#0-6) 

2. Users cannot receive profits due to token type mismatch between locked tokens and distributed profits.

3. Wrong lock duration is enforced - if Scheme A requires 100 minutes but stored metadata says 200 minutes, users are forced to lock longer than the actual scheme requires: [8](#0-7) 

**Operational Impact:**
- The first scheme created becomes orphaned and permanently inaccessible through TokenHolder contract methods, as all operations will reference the wrong scheme.
- Beneficiaries added to the mixed scheme configuration will not function correctly.
- Distribution operations will fail or produce incorrect results due to metadata mismatch.

### Likelihood Explanation

**High Likelihood:**
1. The entry point `CreateScheme` is a public method with no access restrictions preventing multiple calls by the same address.

2. There is no check to prevent calling `CreateScheme` multiple times: [9](#0-8) 

3. The Profit contract is designed to support multiple schemes per manager, suggesting this is an intended use case that TokenHolder should support but doesn't.

4. Users may legitimately want to create multiple schemes for different token types or configurations, or may accidentally call `CreateScheme` twice.

5. No warning or error is thrown during the second `CreateScheme` call, making this issue easy to trigger unknowingly.

### Recommendation

**Fix 1: Prevent Multiple Scheme Creation**
Add a check in `CreateScheme` to prevent overwriting existing schemes:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    var existingScheme = State.TokenHolderProfitSchemes[Context.Sender];
    Assert(existingScheme == null || existingScheme.SchemeId == null, 
           "Scheme already exists for this address. Cannot create multiple schemes.");
    // ... rest of implementation
}
```

**Fix 2: Support Multiple Schemes (More Complex)**
Refactor the storage structure to support multiple schemes per address using a nested mapping:
```csharp
public MappedState<Address, Hash, TokenHolderProfitScheme> TokenHolderProfitSchemes { get; set; }
```
This would require updating all methods to accept a SchemeId parameter.

**Fix 3: Clear Previous Scheme**
Before creating a new scheme, ensure the previous scheme is properly cleaned up, removing all beneficiaries and preventing further operations on the old scheme.

### Proof of Concept

**Initial State:**
- User has 1000 ELF and 1000 USDT tokens
- User has approval set for TokenHolder contract

**Step 1:** User creates first scheme
```
CreateScheme({
    Symbol: "ELF",
    MinimumLockMinutes: 100,
    AutoDistributeThreshold: {}
})
```
Result: Profit Scheme A created, TokenHolderProfitSchemes[User] = {symbol: "ELF", minLockMinutes: 100, schemeId: null}

**Step 2:** User creates second scheme
```
CreateScheme({
    Symbol: "USDT", 
    MinimumLockMinutes: 200,
    AutoDistributeThreshold: {}
})
```
Result: Profit Scheme B created, TokenHolderProfitSchemes[User] = {symbol: "USDT", minLockMinutes: 200, schemeId: null}

**Step 3:** User tries to register for profits
```
RegisterForProfits({
    SchemeManager: User,
    Amount: 100
})
```
Expected: Should lock USDT tokens according to Scheme B configuration
Actual: 
- GetValidScheme calls UpdateTokenHolderProfitScheme
- Retrieves Scheme A's ID (FirstOrDefault)
- Uses USDT symbol from stored metadata
- Attempts to lock 100 USDT tokens
- Adds beneficiary to Scheme A (which distributes ELF, not USDT)
- User's 100 USDT tokens are locked but cannot receive ELF profits from Scheme A

**Step 4:** Verify inconsistent state
```
GetScheme(User)
```
Returns: {symbol: "USDT", minLockMinutes: 200, schemeId: SchemeA, period: SchemeA.period}

**Success Condition:** The scheme configuration is inconsistent - USDT metadata with ELF scheme, causing profit distribution to fail.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs (L10-10)
```csharp
    public MappedState<Address, TokenHolderProfitScheme> TokenHolderProfitSchemes { get; set; }
```

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-177)
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

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L19-40)
```csharp
    public async Task ProfitContract_CreateManyProfitItems_Test()
    {
        const int createTimes = 5;

        var creator = Creators[0];
        var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);

        for (var i = 0; i < createTimes; i++)
        {
            var executionResult = await creator.CreateScheme.SendAsync(new CreateSchemeInput
            {
            });
            executionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        }

        var createdSchemeIds = await creator.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
        {
            Manager = creatorAddress
        });

        createdSchemeIds.SchemeIds.Count.ShouldBe(createTimes);
    }
```
