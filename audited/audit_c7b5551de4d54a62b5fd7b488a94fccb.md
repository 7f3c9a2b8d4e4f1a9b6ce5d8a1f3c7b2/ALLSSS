### Title
Unbounded Scheme Creation Leading to State Bloat and DoS in TokenHolder Contract

### Summary
The `CreateScheme` function in TokenHolderContract allows any caller to repeatedly create unlimited profit schemes without checking if a scheme already exists. Each call creates a new `Scheme` object in the underlying ProfitContract, causing unbounded state storage growth and orphaning previous schemes. This enables a state bloat attack that can degrade node performance and contract operations.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The `CreateScheme` method lacks any validation to check if `State.TokenHolderProfitSchemes[Context.Sender]` already contains a scheme before creating a new one. Each invocation:

1. Calls `State.ProfitContract.CreateScheme.Send()` which creates a **new** Scheme object in the ProfitContract [2](#0-1) 

2. Overwrites the reference in `State.TokenHolderProfitSchemes[Context.Sender]` with the new scheme [3](#0-2) 

**Why Protections Fail:**

The ProfitContract generates unique scheme IDs based on the count of existing schemes: [4](#0-3) 

Since no `Token` value is provided by TokenHolderContract, the scheme ID is generated as `Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false))` where `createdSchemeCount` increments with each call. This ensures each call creates a **distinct** scheme rather than updating an existing one.

Each created scheme is stored permanently: [5](#0-4) 

The ProfitContract stores each scheme in `State.SchemeInfos[schemeId]` and appends the scheme ID to `State.ManagingSchemeIds[manager].SchemeIds`, causing unbounded array growth.

### Impact Explanation

**Concrete Harm:**

1. **State Database Bloat:** Each scheme creates:
   - A `Scheme` object (minimum ~150-200 bytes) containing virtual address, manager, scheme ID, and multiple fields [6](#0-5) 
   
   - An entry in the growing `ManagingSchemeIds[attacker].SchemeIds` array [7](#0-6) 

2. **Orphaned Schemes:** TokenHolder only tracks the most recent scheme. Previous schemes become inaccessible through the TokenHolder interface but continue consuming storage in the ProfitContract.

3. **DoS of Query Operations:** The `GetManagingSchemeIds` query returns increasingly large arrays as schemes accumulate, degrading node performance and potentially causing transaction timeouts.

4. **User Impact:** Users who registered for profits in a previous scheme lose access when `CreateScheme` is called again, as the TokenHolder reference is overwritten.

**Severity Justification:** Medium - While transaction fees provide some economic barrier, the lack of any hard limit or duplicate check allows determined attackers to cause significant operational degradation through state bloat.

### Likelihood Explanation

**Attacker Capabilities:**
- No special permissions required
- Any address can call `CreateScheme`
- No authorization check exists [8](#0-7) 

**Attack Complexity:** Low - requires only repeated calls to a single public function.

**Feasibility Conditions:**
- Transaction fees (if configured via ACS1) provide the primary cost barrier
- Block gas limits constrain schemes per block but not total accumulation
- Attack can be executed over multiple blocks to bypass per-block limits

**Economic Rationality:** 
The attack cost depends on configured method fees. Test evidence shows the Profit contract allows multiple scheme creation by design: [9](#0-8) 

This test creates 5 schemes successfully, demonstrating the pattern is executable. An attacker could scale this to hundreds or thousands of schemes depending on fee economics.

**Probability:** Medium-High - Simple execution path, but requires sustained transaction fee expenditure.

### Recommendation

**Code-Level Mitigation:**

Add a duplicate scheme check in `CreateScheme` before creating a new scheme:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
           "Scheme already exists for this address.");
    
    // ... existing code
}
```

This follows the validation pattern already used in `RegisterForProfits`: [10](#0-9) 

**Alternative Approach:** Implement an explicit `UpdateScheme` method for modifying existing schemes rather than creating new ones.

**Invariant Check:** Ensure `State.TokenHolderProfitSchemes[address]` contains at most one scheme per address.

**Test Cases:**
- Test that calling `CreateScheme` twice with the same sender reverts with "Scheme already exists"
- Test that `GetManagingSchemeIds` for a given manager does not grow unboundedly
- Verify state storage does not accumulate orphaned schemes

### Proof of Concept

**Initial State:**
- Attacker has sufficient tokens to pay transaction fees
- No existing scheme for attacker address

**Attack Steps:**

1. Attacker calls `TokenHolderContract.CreateScheme({Symbol: "ELF", MinimumLockMinutes: 1})`
   - Creates Profit scheme #0
   - Stores reference in `TokenHolderProfitSchemes[attacker]`

2. Attacker calls `TokenHolderContract.CreateScheme({Symbol: "ELF", MinimumLockMinutes: 1})` again
   - Creates Profit scheme #1 (new scheme ID generated)
   - Overwrites `TokenHolderProfitSchemes[attacker]` with new reference
   - Scheme #0 becomes orphaned but remains in `State.SchemeInfos` and `State.ManagingSchemeIds[attacker]`

3. Repeat step 2 N times
   - Creates N total Profit schemes
   - `State.ManagingSchemeIds[attacker].SchemeIds` grows to length N
   - `State.SchemeInfos` contains N separate Scheme objects
   - TokenHolder only references the last scheme

**Expected Result:** Second call should revert with "Scheme already exists"

**Actual Result:** Each call succeeds, creating new schemes indefinitely and causing state bloat

**Success Condition:** Query `GetManagingSchemeIds(attacker)` returns array of length N, confirming N schemes were created and stored permanently in the ProfitContract state.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L151-151)
```csharp
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L59-71)
```csharp
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
        State.SchemeInfos[schemeId] = scheme;

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

**File:** protobuf/profit_contract.proto (L135-160)
```text
message Scheme {
    // The virtual address of the scheme.
    aelf.Address virtual_address = 1;
    // The total weight of the scheme.
    int64 total_shares = 2;
    // The manager of the scheme.
    aelf.Address manager = 3;
    // The current period.
    int64 current_period = 4;
    // Sub schemes information.
    repeated SchemeBeneficiaryShare sub_schemes = 5;
    // Whether you can directly remove the beneficiary.
    bool can_remove_beneficiary_directly = 6;
    // Period of profit distribution.
    int64 profit_receiving_due_period_count = 7;
    // Whether all the schemes balance will be distributed during distribution each period.
    bool is_release_all_balance_every_time_by_default = 8;
    // The is of the scheme.
    aelf.Hash scheme_id = 9;
    // Delay distribute period.
    int32 delay_distribute_period_count = 10;
    // Record the scheme's current total share for deferred distribution of benefits, period -> total shares.
    map<int64, int64> cached_delay_total_shares = 11;
    // The received token symbols.
    repeated string received_token_symbols = 12;
}
```

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L15-15)
```csharp
    public MappedState<Address, CreatedSchemeIds> ManagingSchemeIds { get; set; }
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
