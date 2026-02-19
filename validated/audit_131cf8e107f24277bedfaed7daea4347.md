# Audit Report

## Title
Unbounded State Bloat via Unlimited Profit Scheme Creation in TokenHolderContract

## Summary
The `CreateScheme()` function in TokenHolderContract allows any user to create unlimited profit schemes without authorization or duplicate checks. Each invocation creates a new permanent scheme in ProfitContract while only the latest is tracked in TokenHolderContract, resulting in orphaned schemes that consume blockchain storage indefinitely.

## Finding Description

The vulnerability exists in the interaction between TokenHolderContract and ProfitContract during scheme creation:

**Unrestricted Entry Point:**
The `CreateScheme()` function is publicly accessible with no authorization validation. [1](#0-0) 

**Storage Overwrite in TokenHolderContract:**
Each call overwrites the single scheme slot per address in `State.TokenHolderProfitSchemes[Context.Sender]`. [2](#0-1) 

The state mapping confirms only one scheme is stored per address. [3](#0-2) 

**Unbounded Accumulation in ProfitContract:**
Each `CreateScheme` call creates a new unique scheme because the schemeId is generated based on an incrementing counter. [4](#0-3) 

The scheme is stored permanently and added to the manager's list without bounds. [5](#0-4) 

The duplicate check only prevents identical schemeIds, not multiple schemes per manager. [6](#0-5) 

**Orphaned Scheme Access:**
When TokenHolderContract attempts to retrieve schemes, it uses `FirstOrDefault()` which only accesses the first scheme created. [7](#0-6) 

This means all subsequent schemes become permanently orphaned—stored in ProfitContract state but inaccessible through TokenHolderContract.

**No Cleanup Mechanism:**
No `RemoveScheme` function exists in ProfitContract, making all created schemes permanent. The contract only provides `ResetManager` which transfers ownership without removing schemes. [8](#0-7) 

## Impact Explanation

This vulnerability enables unbounded state bloat with permanent impact:

**Direct State Impact:**
- Each scheme consumes significant storage including virtual addresses, manager addresses, scheme IDs, maps, and repeated fields as defined in the Scheme message. [9](#0-8) 
- An attacker can create thousands of schemes from a single address at minimal cost
- All schemes persist permanently in `State.SchemeInfos` with no removal mechanism [10](#0-9) 

**Blockchain-Wide Consequences:**
- Unbounded growth of ProfitContract state
- Increased node synchronization time as state database expands
- Degraded query performance for scheme lookups
- All validators must store and maintain the bloated state permanently

**Economic Viability:**
The attack cost is only transaction fees with no token locks, burns, or stakes required, making it economically feasible to inflict disproportionate permanent storage costs on the network.

## Likelihood Explanation

**Execution Complexity:** Trivial - simply call `CreateScheme()` repeatedly with any parameters.

**Attacker Prerequisites:** None - no special permissions, token holdings, or approvals required. The function is publicly accessible. [11](#0-10) 

**Attack Barriers:** None - no rate limiting, no duplicate prevention in TokenHolderContract, no validation that a scheme already exists.

**Detection/Mitigation:** The attack is visible on-chain but cannot be prevented without protocol changes, and damage is irreversible once schemes are created.

## Recommendation

Implement duplicate prevention in TokenHolderContract:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add duplicate check
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
        "Scheme already exists for this address.");
    
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

Additionally, consider implementing a `RemoveScheme` function in ProfitContract to allow cleanup of unused schemes.

## Proof of Concept

```csharp
// Test demonstrating unbounded scheme creation
[Fact]
public async Task StateBloat_UnlimitedSchemeCreation()
{
    var attacker = Accounts[1].Address;
    
    // Attacker creates multiple schemes from same address
    for (int i = 0; i < 100; i++)
    {
        var result = await TokenHolderContractStub.CreateScheme.SendAsync(
            new CreateTokenHolderProfitSchemeInput
            {
                Symbol = "ELF",
                MinimumLockMinutes = 100
            });
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    }
    
    // Verify: TokenHolderContract only tracks 1 scheme
    var trackedScheme = await TokenHolderContractStub.GetScheme.CallAsync(attacker);
    trackedScheme.ShouldNotBeNull();
    
    // Verify: ProfitContract accumulated 100 schemes
    var managingSchemes = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = attacker });
    managingSchemes.SchemeIds.Count.ShouldBe(100); // State bloat confirmed
    
    // All schemes except first are orphaned and permanent
}
```

**Notes:**
This vulnerability breaks the state integrity invariant by allowing unbounded permanent storage growth at minimal cost. The attack requires no special privileges and causes irreversible damage to the blockchain state that affects all network participants.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-25)
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-71)
```csharp
        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L723-743)
```csharp
    public override Empty ResetManager(ResetManagerInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");

        // Transfer managing scheme id.
        var oldManagerSchemeIds = State.ManagingSchemeIds[scheme.Manager];
        oldManagerSchemeIds.SchemeIds.Remove(input.SchemeId);
        State.ManagingSchemeIds[scheme.Manager] = oldManagerSchemeIds;
        var newManagerSchemeIds = State.ManagingSchemeIds[input.NewManager] ?? new CreatedSchemeIds();
        newManagerSchemeIds.SchemeIds.Add(input.SchemeId);
        State.ManagingSchemeIds[input.NewManager] = newManagerSchemeIds;

        scheme.Manager = input.NewManager;
        State.SchemeInfos[input.SchemeId] = scheme;
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L9-9)
```csharp
    public MappedState<Hash, Scheme> SchemeInfos { get; set; }
```

**File:** protobuf/token_holder_contract.proto (L19-21)
```text
    // Create a scheme for distributing bonus.
    rpc CreateScheme (CreateTokenHolderProfitSchemeInput) returns (google.protobuf.Empty) {
    }
```
