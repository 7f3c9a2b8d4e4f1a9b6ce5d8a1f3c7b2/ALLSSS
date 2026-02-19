### Title
Parliament Contract Address Caching Vulnerability Causes Permanent DoS of Critical Consensus Configuration Functions

### Summary
The `RequiredMaximumMinersCountControllerSet()` function caches an empty Address when the Parliament contract is not yet deployed, and never attempts to retrieve the correct address again. This causes permanent failure of all four functions that depend on it: `SetMaximumMinersCount`, `ChangeMaximumMinersCountController`, `SetMinerIncreaseInterval`, and `GetMaximumMinersCountController`, rendering critical consensus configuration mechanisms unusable even after Parliament is properly deployed.

### Finding Description

The vulnerability exists in the lazy initialization pattern for Parliament contract address resolution. [1](#0-0) 

When `RequiredMaximumMinersCountControllerSet()` is called for the first time, it checks if the controller is already set (line 33), and if not, calls `EnsureParliamentContractAddressSet()` at line 34. [2](#0-1) 

The critical flaw occurs in the following sequence:

1. `EnsureParliamentContractAddressSet()` checks if `State.ParliamentContract.Value == null`
2. If null, it calls `Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName)`
3. When Parliament is not deployed, this returns `new Address()` (empty Address, not null) [3](#0-2) 
4. The empty Address is stored in `State.ParliamentContract.Value`
5. On subsequent calls, the null check `if (State.ParliamentContract.Value == null)` evaluates to FALSE because an empty Address object exists
6. The code never attempts to retrieve the correct address again, even after Parliament is deployed

At line 38, when `State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())` is executed, it attempts to call a method on the empty contract address. [4](#0-3) 

This creates a transaction with a null/empty `To` address, which fails execution and throws a `ContractCallException`. [5](#0-4) 

All four public functions that call `RequiredMaximumMinersCountControllerSet` are affected:
- `SetMaximumMinersCount` (line 16)
- `ChangeMaximumMinersCountController` (line 47) 
- `SetMinerIncreaseInterval` (line 58)
- `GetMaximumMinersCountController` (line 68)

### Impact Explanation

This vulnerability causes a permanent Denial of Service (DoS) of critical consensus configuration mechanisms:

1. **SetMaximumMinersCount**: Controls the maximum number of miners allowed in the consensus system, critical for network scaling and security
2. **ChangeMaximumMinersCountController**: Manages governance authority over miner count configuration
3. **SetMinerIncreaseInterval**: Controls the rate at which new miners can be added to the network
4. **GetMaximumMinersCountController**: Prevents querying of controller information, blocking governance transparency

Once the empty Address is cached, these functions remain permanently unusable, requiring a contract upgrade or manual state intervention to fix. This affects the entire network's ability to adjust consensus parameters, which is critical for:
- Network growth and miner expansion
- Governance-driven consensus adjustments  
- Emergency response to consensus issues

The severity is **High** because:
- Multiple critical functions are simultaneously disabled
- The issue persists indefinitely once triggered
- Consensus parameter management is essential for network operation
- Recovery requires exceptional intervention (contract upgrade)

### Likelihood Explanation

The likelihood is **Medium to High** in the following realistic scenarios:

1. **Incorrect Deployment Order**: If AEDPoS contract is deployed before Parliament contract, or if contracts are deployed in parallel without proper sequencing. While test environments show the correct order [6](#0-5) , production deployments may deviate from this pattern.

2. **Chain Initialization Race Conditions**: During rapid chain initialization, if any of the affected functions are called before Parliament contract registration completes in the Genesis contract's name mapping.

3. **Development and Test Environments**: Incomplete environment setup where Parliament is not deployed, causing persistent failures that may propagate to staging or production.

4. **Chain Fork or Upgrade Scenarios**: If contract addresses change during chain forks or upgrades and the Parliament address becomes invalid.

The vulnerability does not require attacker capabilities - it is triggered by configuration/timing issues during normal operation. The preconditions (Parliament not deployed when functions are first called) are feasible in real-world deployment scenarios. The same vulnerability pattern exists in other system contracts [7](#0-6) , indicating a systemic issue.

### Recommendation

Implement validation and retry logic for contract address resolution:

**1. Add Address Validation in `EnsureParliamentContractAddressSet()`:**
```csharp
private void EnsureParliamentContractAddressSet()
{
    if (State.ParliamentContract.Value == null || State.ParliamentContract.Value.Value.IsEmpty)
    {
        var address = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
        Assert(address != null && !address.Value.IsNullOrEmpty(), 
            "Parliament contract not deployed or not registered.");
        State.ParliamentContract.Value = address;
    }
}
```

**2. Add Explicit Check in `RequiredMaximumMinersCountControllerSet()`:**
```csharp
private void RequiredMaximumMinersCountControllerSet()
{
    if (State.MaximumMinersCountController.Value != null) return;
    EnsureParliamentContractAddressSet();
    
    Assert(State.ParliamentContract.Value != null && !State.ParliamentContract.Value.Value.IsNullOrEmpty(),
        "Parliament contract address not available.");
    
    var defaultAuthority = new AuthorityInfo
    {
        OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
        ContractAddress = State.ParliamentContract.Value
    };
    
    State.MaximumMinersCountController.Value = defaultAuthority;
}
```

**3. Add Test Cases:**
- Test calling affected functions when Parliament is not deployed
- Test calling affected functions before Parliament registration
- Test recovery after Parliament is deployed
- Verify proper error messages guide operators to the root cause

**4. Apply Same Fix to All System Contracts:**
Apply the same validation pattern to Genesis contract and any other contracts using similar lazy initialization for cross-contract references.

### Proof of Concept

**Initial State:**
- Genesis contract deployed and initialized
- AEDPoS contract deployed and initialized
- Parliament contract NOT deployed (or not yet registered in Genesis name mapping)

**Exploitation Steps:**

1. Call `GetMaximumMinersCountController()` (view function, easiest to test):
   - Function calls `RequiredMaximumMinersCountControllerSet()` at line 68
   - `State.MaximumMinersCountController.Value` is null, so continues
   - Calls `EnsureParliamentContractAddressSet()`
   - `State.ParliamentContract.Value` is null, so retrieves address
   - `GetContractAddressByName` returns empty Address (Parliament not deployed)
   - `State.ParliamentContract.Value` set to empty Address
   - Attempts `State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())`
   - **Result**: Transaction fails with `ContractCallException` - "Invalid contract address" or similar error

2. Deploy Parliament contract properly

3. Call `GetMaximumMinersCountController()` again:
   - Function calls `RequiredMaximumMinersCountControllerSet()`
   - `State.MaximumMinersCountController.Value` is still null
   - Calls `EnsureParliamentContractAddressSet()`
   - `State.ParliamentContract.Value` is NOT null (it's the cached empty Address)
   - Does NOT retrieve new address
   - Attempts call with cached empty Address
   - **Result**: Transaction STILL fails with `ContractCallException`

**Expected Result:** Functions should fail gracefully with clear error messages, or retry address resolution.

**Actual Result:** Functions fail with `ContractCallException` and remain permanently broken due to cached empty Address, even after Parliament is properly deployed.

**Success Condition for Attack:** Any call to the four affected functions before Parliament deployment causes permanent DoS of those functions until contract upgrade.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L31-43)
```csharp
    private void RequiredMaximumMinersCountControllerSet()
    {
        if (State.MaximumMinersCountController.Value != null) return;
        EnsureParliamentContractAddressSet();

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MaximumMinersCountController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L154-159)
```csharp
    private void EnsureParliamentContractAddressSet()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    }
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractTest.cs (L56-57)
```csharp
            (await DefaultTester.GetContractAddressByName.CallAsync(HashHelper.ComputeFrom("Random"))).ShouldBe(
                new Address());
```

**File:** src/AElf.Sdk.CSharp/State/MethodReference.cs (L23-26)
```csharp
    public TOutput Call(TInput input)
    {
        return _parent.Context.Call<TOutput>(_parent.Value, _name, input);
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L199-226)
```csharp
    public T Call<T>(Address fromAddress, Address toAddress, string methodName, ByteString args)
        where T : IMessage<T>, new()
    {
        var trace = AsyncHelper.RunSync(async () =>
        {
            var chainContext = new ChainContext
            {
                BlockHash = TransactionContext.PreviousBlockHash,
                BlockHeight = TransactionContext.BlockHeight - 1,
                StateCache = CachedStateProvider.Cache
            };

            var tx = new Transaction
            {
                From = fromAddress,
                To = toAddress,
                MethodName = methodName,
                Params = args
            };
            return await _transactionReadOnlyExecutionService.ExecuteAsync(chainContext, tx, CurrentBlockTime);
        });

        if (!trace.IsSuccessful()) throw new ContractCallException(trace.Error);

        var obj = new T();
        obj.MergeFrom(trace.ReturnValue);
        return obj;
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTestBase.cs (L58-96)
```csharp
    protected void InitializeContracts()
    {
        //get basic stub
        BasicContractStub =
            GetContractZeroTester(DefaultSenderKeyPair);

        //deploy Parliament contract
        ParliamentContractAddress = AsyncHelper.RunSync(() =>
            DeploySystemSmartContract(
                KernelConstants.CodeCoverageRunnerCategory,
                ParliamentCode,
                ParliamentSmartContractAddressNameProvider.Name,
                DefaultSenderKeyPair
            ));
        ParliamentContractStub = GetParliamentContractTester(DefaultSenderKeyPair);
        AsyncHelper.RunSync(() => ParliamentContractStub.Initialize.SendAsync(new InitializeInput
        {
            ProposerAuthorityRequired = false,
            PrivilegedProposer = DefaultSender
        }));

        ConsensusContractAddress = AsyncHelper.RunSync(() => DeploySystemSmartContract(
            KernelConstants.CodeCoverageRunnerCategory,
            DPoSConsensusCode,
            ConsensusSmartContractAddressNameProvider.Name,
            DefaultSenderKeyPair));
        ConsensusContractStub = GetConsensusContractTester(DefaultSenderKeyPair);
        AsyncHelper.RunSync(async () => await InitializeConsensusAsync());
        
        //deploy token contract
        TokenContractAddress = AsyncHelper.RunSync(() =>
            DeploySystemSmartContract(
                KernelConstants.CodeCoverageRunnerCategory,
                TokenContractCode,
                TokenSmartContractAddressNameProvider.Name,
                DefaultSenderKeyPair));
        TokenContractStub = GetTokenContractTester(DefaultSenderKeyPair);
        AsyncHelper.RunSync(async () => await InitializeTokenAsync());
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L163-168)
```csharp
    private void RequireParliamentContractAddressSet()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    }
```
