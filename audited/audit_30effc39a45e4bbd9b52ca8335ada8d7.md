### Title
Missing Defensive Check for Parliament Contract Existence in MaximumMinersCount Controller Initialization

### Summary
The `RequiredMaximumMinersCountControllerSet()` function lacks a defensive null check before calling the Parliament contract, unlike the correct pattern implemented in other system contracts. While contract initialization itself succeeds, any subsequent call to maximum miners count governance methods will fail unexpectedly if Parliament is not deployed or initialized, causing operational disruption.

### Finding Description

The `RequiredMaximumMinersCountControllerSet()` function calls Parliament's `GetDefaultOrganizationAddress` without verifying the contract exists: [1](#0-0) 

The function calls `EnsureParliamentContractAddressSet()` which uses `Context.GetContractAddressByName()`: [2](#0-1) 

When Parliament doesn't exist, `GetContractAddressByName` returns null from the genesis contract: [3](#0-2) 

This causes `State.ParliamentContract.Value` to be null, then line 38 attempts to call `GetDefaultOrganizationAddress` on this null reference, resulting in a contract call failure.

In contrast, the MultiToken contract implements the correct defensive pattern with an explicit null check and explanatory comment: [4](#0-3) 

Note the critical difference at line 101: `if (State.ParliamentContract.Value != null)` with the comment "Parliament Auth Contract maybe not deployed."

The vulnerable function is called by four public methods that will all fail if Parliament doesn't exist: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

**Important Note:** The contract's `InitialAElfConsensusContract` initialization method does NOT call `RequiredMaximumMinersCountControllerSet()`, so initialization itself succeeds: [9](#0-8) 

The failure occurs only when the governance methods are called post-initialization.

### Impact Explanation

**Operational Impact - Medium Severity:**

1. **Governance Method Failures**: All maximum miners count governance operations become inoperative if called before Parliament deployment, including:
   - Querying the controller (view method accessible to any caller)
   - Setting maximum miners count
   - Changing the controller
   - Setting miner increase interval

2. **Ecosystem Disruption**: External systems depending on these methods (chain explorers, wallets, monitoring tools, governance UIs) will encounter unexpected failures when querying `GetMaximumMinersCountController()`.

3. **Migration/Deployment Issues**: In migration scenarios or custom chain deployments where contracts are deployed in non-standard order, these methods become unusable until Parliament is deployed and initialized, blocking governance operations related to miner count management.

4. **No Direct Fund Loss**: While governance operations fail, this does not directly result in token theft, minting, or consensus disruption. The consensus contract continues operating with its default `MaximumMinersCount` value of `int.MaxValue`.

### Likelihood Explanation

**Likelihood: Low to Medium**

**Preconditions:**
1. AEDPoS consensus contract deployed on a chain
2. Parliament contract either not deployed yet OR deployed but not initialized
3. Any caller invokes one of the affected methods

**Realistic Scenarios:**
1. **Migration/Upgrade Paths**: When upgrading or migrating contracts, if consensus is deployed/updated before Parliament is ready
2. **Custom Chain Deployments**: Non-standard deployment orders in private or test chains
3. **Partial Contract Set Deployments**: Side chains or specialized chains that deploy only a subset of system contracts
4. **Development/Testing Environments**: Test scenarios with incomplete contract initialization sequences

**Attacker Capabilities:**
- No special privileges required for `GetMaximumMinersCountController()` (public view method)
- Governance methods require appropriate authorization but will fail before authorization checks complete

**Execution Practicality:**
- Simple to trigger: just call any of the four affected methods
- No complex setup or state manipulation needed
- Deterministic failure when preconditions met

**Detection:**
- Failures are immediately visible in transaction results
- Error messages indicate contract call failures

**Production Likelihood:**
- Low in standard mainnet deployment (Parliament always deployed before Consensus)
- Higher in migration scenarios (as indicated by [Migration] tag in the question)
- The explicit defensive check in other contracts indicates this is a known concern

### Recommendation

Implement the same defensive pattern used in MultiToken and other system contracts:

```csharp
private void RequiredMaximumMinersCountControllerSet()
{
    if (State.MaximumMinersCountController.Value != null) return;
    
    EnsureParliamentContractAddressSet();

    var defaultAuthority = new AuthorityInfo();

    // Parliament Auth Contract maybe not deployed.
    if (State.ParliamentContract.Value != null)
    {
        defaultAuthority.OwnerAddress = 
            State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
        defaultAuthority.ContractAddress = State.ParliamentContract.Value;
    }

    State.MaximumMinersCountController.Value = defaultAuthority;
}
```

**Specific Changes:**
1. Add null check: `if (State.ParliamentContract.Value != null)` before calling `GetDefaultOrganizationAddress`
2. Initialize `AuthorityInfo` as empty object first
3. Only populate owner address and contract address if Parliament exists
4. Set the controller state regardless (with empty authority if Parliament doesn't exist)

**Additional Considerations:**
- Add validation in methods that use the controller to handle empty `OwnerAddress` gracefully
- Consider adding explicit error messages when Parliament is not available
- Add integration tests covering deployment ordering scenarios

**Test Cases:**
1. Call `GetMaximumMinersCountController()` before Parliament deployment → should return empty authority without error
2. Call `SetMaximumMinersCount()` before Parliament deployment → should fail with clear authorization error, not contract call error
3. Deploy Parliament after Consensus → next call to affected methods should initialize controller correctly

### Proof of Concept

**Initial State:**
1. Deploy Genesis contract (BasicContractZero)
2. Deploy AEDPoS Consensus contract
3. Call `InitialAElfConsensusContract` and `FirstRound` → **succeeds**
4. Parliament contract NOT deployed yet

**Exploitation Steps:**

Step 1: Call `GetMaximumMinersCountController()` (public view method)
```
Transaction to: AEDPoSContract
Method: GetMaximumMinersCountController
Params: Empty
```

Step 2: Execution trace:
- `GetMaximumMinersCountController()` called at line 66
- Calls `RequiredMaximumMinersCountControllerSet()` at line 68
- `State.MaximumMinersCountController.Value` is null, continues
- Calls `EnsureParliamentContractAddressSet()` at line 34
- `Context.GetContractAddressByName(ParliamentContractSystemName)` returns null (Parliament not deployed)
- `State.ParliamentContract.Value` set to null at line 157
- Returns to line 38: attempts `State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())`
- **Contract call fails** - attempting to call method on null contract address

**Expected Result:** Should return authority info (possibly empty) without error

**Actual Result:** Transaction fails with contract call error (contract not found or invalid address)

**Success Condition for Exploit:** Transaction fails instead of returning gracefully, confirming the missing defensive check causes operational disruption in migration/deployment scenarios where Parliament doesn't exist yet.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L45-54)
```csharp
    public override Empty ChangeMaximumMinersCountController(AuthorityInfo input)
    {
        RequiredMaximumMinersCountControllerSet();
        AssertSenderAddressWith(State.MaximumMinersCountController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MaximumMinersCountController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L56-64)
```csharp
    public override Empty SetMinerIncreaseInterval(Int64Value input)
    {
        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set miner increase interval.");
        Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
        State.MinerIncreaseInterval.Value = input.Value;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L66-70)
```csharp
    public override AuthorityInfo GetMaximumMinersCountController(Empty input)
    {
        RequiredMaximumMinersCountControllerSet();
        return State.MaximumMinersCountController.Value;
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L40-44)
```csharp
    public override Address GetContractAddressByName(Hash input)
    {
        var address = State.NameAddressMapping[input];
        return address;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L91-109)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo();

        // Parliament Auth Contract maybe not deployed.
        if (State.ParliamentContract.Value != null)
        {
            defaultAuthority.OwnerAddress =
                State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
            defaultAuthority.ContractAddress = State.ParliamentContract.Value;
        }

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L22-61)
```csharp
    public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
    {
        Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;

        State.PeriodSeconds.Value = input.IsTermStayOne
            ? int.MaxValue
            : input.PeriodSeconds;

        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;

        Context.LogDebug(() => $"There are {State.PeriodSeconds.Value} seconds per period.");

        if (input.IsSideChain) InitialProfitSchemeForSideChain(input.PeriodSeconds);

        if (input.IsTermStayOne || input.IsSideChain)
        {
            State.IsMainChain.Value = false;
            return new Empty();
        }

        State.IsMainChain.Value = true;

        State.ElectionContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        State.TreasuryContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        State.MaximumMinersCount.Value = int.MaxValue;

        if (State.TreasuryContract.Value != null)
            State.TreasuryContract.UpdateMiningReward.Send(new Int64Value
            {
                Value = AEDPoSContractConstants.InitialMiningRewardPerBlock
            });

        return new Empty();
    }
```
