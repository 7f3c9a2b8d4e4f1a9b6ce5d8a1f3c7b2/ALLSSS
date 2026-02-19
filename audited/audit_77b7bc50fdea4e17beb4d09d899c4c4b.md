### Title
Main Chain Consensus Corruption Due to Missing IsMainChain Initialization Check in FirstRound

### Summary
The `FirstRound` method lacks validation that `InitialAElfConsensusContract` was called first to set `State.IsMainChain.Value`. If `FirstRound` is invoked directly during genesis initialization, `State.IsMainChain.Value` defaults to `false`, causing main chain nodes to execute side chain logic, disable evil miner detection, skip election contract updates, and break the miner election process from round 2 onwards.

### Finding Description

The vulnerability exists due to insufficient initialization ordering checks in the consensus contract.

**Root Cause:**

The `FirstRound` method only validates that `State.CurrentRoundNumber.Value == 0` but does not check `State.Initialized.Value`, which is set by `InitialAElfConsensusContract`. [1](#0-0) 

In contrast, `InitialAElfConsensusContract` properly checks both conditions and sets the initialization flag: [2](#0-1) 

The critical `State.IsMainChain.Value` is only set within `InitialAElfConsensusContract`: [3](#0-2) 

**State Type Behavior:**

`State.IsMainChain` is a `BoolState`, which wraps non-nullable `bool`: [4](#0-3) 

When uninitialized, `SingletonState<bool>.Value` returns `default(bool)` = `false` (not null, not exception): [5](#0-4) [6](#0-5) 

**Affected Code Paths:**

When `State.IsMainChain.Value` incorrectly returns `false` (should be `true` for main chain):

1. **Side Chain Dividend Release Executed** - From round 2+, main chain nodes call side chain-specific `Release()`: [7](#0-6) [8](#0-7) 

2. **Miner Count Updates Skipped** - Election Contract never receives miner count updates: [9](#0-8) 

3. **Evil Miner Detection Disabled** - Malicious miners evade detection: [10](#0-9) 

4. **Miner Election Broken** - Victory queries fail, preventing proper miner rotation: [11](#0-10) 

5. **Candidate Updates Skipped** - Election Contract loses miner performance data: [12](#0-11) 

6. **Election Countdown Broken** - Returns 0 instead of proper countdown: [13](#0-12) 

### Impact Explanation

**Consensus Integrity Compromise:**
- Main chain behaves as side chain, executing dividend distribution logic intended only for side chains
- Evil miner detection is completely disabled, allowing malicious validators to avoid penalties
- Miner election process becomes non-functional as Election Contract never receives current miner lists or performance data

**Governance Breakdown:**
- Election Contract cannot maintain accurate validator set due to missing updates
- Term transitions fail because victory queries return no candidates
- The chain cannot replace underperforming or malicious miners

**Irreversible State Corruption:**
Once `FirstRound` executes without proper `State.IsMainChain` initialization, the incorrect value persists permanently (genesis block state cannot be modified). The chain launches with fundamentally broken consensus and governance from round 2 onwards.

**Severity Justification:**
This is HIGH severity because it violates the critical invariant "Correct round transitions and miner schedule integrity" and causes "Operational Impact: DoS of consensus flows." The entire validator election and accountability system becomes permanently non-functional.

### Likelihood Explanation

**Reachable Entry Point:**
Both `InitialAElfConsensusContract` and `FirstRound` are public methods intended for genesis block initialization. The expected sequence is shown in test infrastructure: [14](#0-13) 

**Feasibility:**
- During chain deployment, if the genesis transaction list is incorrectly ordered or `InitialAElfConsensusContract` is omitted
- No contract-level enforcement prevents calling `FirstRound` first
- Chain operators may not be aware of the strict ordering requirement since `FirstRound` has its own "Already initialized" check that appears sufficient

**Attack Complexity:**
This is not an intentional exploit but a configuration error during chain deployment. However, the contract should be resilient to initialization ordering mistakes.

**Detection:**
The issue manifests immediately from round 2 but may not be obvious:
- Side chain `Release()` returns early if `TokenHolderContract` is null (line 104 of SideChainDividendsPool)
- Missing election updates may be attributed to other issues
- The chain appears to function until miner election attempts occur

**Probability:**
MEDIUM-LOW in production (genesis scripts typically follow documented order) but HIGH impact if it occurs. The lack of contract-level validation makes this a dangerous footgun.

### Recommendation

**Immediate Fix:**
Add initialization check to `FirstRound`:

```csharp
public override Empty FirstRound(Round input)
{
    /* Basic checks. */
    Assert(State.CurrentRoundNumber.Value == 0, "Already initialized.");
    Assert(State.Initialized.Value, "Must call InitialAElfConsensusContract first.");
    
    /* Initial settings. */
    // ... rest of method
}
```

**Location to modify:** [1](#0-0) 

**Alternative Defense-in-Depth:**
Add assertions in `ProcessConsensusInformation` and other critical paths:

```csharp
private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
{
    EnsureTransactionOnlyExecutedOnceInOneBlock();
    Assert(State.Initialized.Value, "Consensus contract not properly initialized.");
    // ... rest of method
}
```

**Test Cases:**
1. Verify `FirstRound` reverts if called before `InitialAElfConsensusContract`
2. Verify main chain correctly sets `State.IsMainChain.Value = true` and executes election logic
3. Verify side chain correctly sets `State.IsMainChain.Value = false` and executes dividend logic
4. Integration test confirming proper initialization sequence in genesis block

### Proof of Concept

**Initial State:**
- Fresh chain deployment
- Genesis block generation in progress
- No prior state exists

**Exploit Steps:**

1. **Skip `InitialAElfConsensusContract`** - Genesis transaction list omits or misorients initialization call

2. **Call `FirstRound` directly:**
   - Passes check: `State.CurrentRoundNumber.Value == 0` ✓
   - Sets `CurrentRoundNumber = 1`
   - `State.IsMainChain.Value` remains uninitialized → defaults to `false`

3. **Execute consensus in Round 1:**
   - Condition at line 83: `!false && (1 > 1)` = `true && false` = `false`
   - No immediate issue visible

4. **Transition to Round 2 via `NextRound`:**
   - Round 2 begins

5. **Execute `UpdateValue` in Round 2:**
   - ProcessConsensusInformation called
   - Line 83: `!State.IsMainChain.Value && currentRound.RoundNumber > 1`
   - Evaluates: `!false && (2 > 1)` = `true && true` = `true`
   - **Side chain `Release()` executed on main chain** ✗

6. **Round transition via `ProcessNextRound`:**
   - Line 126: `if (State.IsMainChain.Value)` evaluates to `false`
   - **Miner count update skipped** ✗
   - Line 139: `if (State.IsMainChain.Value && ...)` evaluates to `false`  
   - **Evil miner detection skipped** ✗

7. **Term transition attempts:**
   - Calls `TryToGetVictories` for new miner list
   - Line 268: `if (!State.IsMainChain.Value)` evaluates to `true`
   - Returns `false`, no victories retrieved
   - **Miner election fails** ✗

**Expected Result:**
Main chain properly initialized with election integration, evil miner detection, and no side chain logic.

**Actual Result:**  
Main chain permanently corrupted: executes side chain dividend logic, has disabled accountability mechanisms, and cannot perform validator elections.

**Success Condition:**
Chain remains operational in round 1 but exhibits broken consensus behavior from round 2+ that cannot be remediated without full chain redeployment.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L22-25)
```csharp
    public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
    {
        Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L37-43)
```csharp
        if (input.IsTermStayOne || input.IsSideChain)
        {
            State.IsMainChain.Value = false;
            return new Empty();
        }

        State.IsMainChain.Value = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L74-77)
```csharp
    public override Empty FirstRound(Round input)
    {
        /* Basic checks. */
        Assert(State.CurrentRoundNumber.Value == 0, "Already initialized.");
```

**File:** src/AElf.Sdk.CSharp/State/SingletonState_Aliases.cs (L7-10)
```csharp
/// </summary>
public class BoolState : SingletonState<bool>
{
}
```

**File:** src/AElf.Sdk.CSharp/State/SingletonState.cs (L20-34)
```csharp
    public TEntity Value
    {
        get
        {
            if (!Loaded) Load();

            return _value;
        }
        set
        {
            if (!Loaded) Load();

            _value = value;
        }
    }
```

**File:** src/AElf.Sdk.CSharp/State/SingletonState.cs (L54-60)
```csharp
    private void Load()
    {
        var bytes = Provider.Get(Path);
        _originalValue = SerializationHelper.Deserialize<TEntity>(bytes);
        _value = SerializationHelper.Deserialize<TEntity>(bytes);
        Loaded = true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L83-83)
```csharp
        if (!State.IsMainChain.Value && currentRound.RoundNumber > 1) Release();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L126-136)
```csharp
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L102-122)
```csharp
    public void Release()
    {
        if (State.TokenHolderContract.Value == null) return;
        var scheme = State.TokenHolderContract.GetScheme.Call(Context.Self);
        var isTimeToRelease =
            (Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.PeriodSeconds.Value) > scheme.Period - 1;
        Context.LogDebug(() => "ReleaseSideChainDividendsPool Information:\n" +
                               $"CurrentBlockTime: {Context.CurrentBlockTime}\n" +
                               $"BlockChainStartTime: {State.BlockchainStartTimestamp.Value}\n" +
                               $"PeriodSeconds: {State.PeriodSeconds.Value}\n" +
                               $"Scheme Period: {scheme.Period}");
        if (isTimeToRelease)
        {
            Context.LogDebug(() => "Ready to release side chain dividends pool.");
            State.TokenHolderContract.DistributeProfits.Send(new DistributeProfitsInput
            {
                SchemeManager = Context.Self
            });
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L367-379)
```csharp
    private void UpdateCandidateInformation(string candidatePublicKey, long recentlyProducedBlocks,
        long recentlyMissedTimeSlots, bool isEvilNode = false)
    {
        if (!State.IsMainChain.Value) return;

        State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
        {
            Pubkey = candidatePublicKey,
            RecentlyProducedBlocks = recentlyProducedBlocks,
            RecentlyMissedTimeSlots = recentlyMissedTimeSlots,
            IsEvilNode = isEvilNode
        });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L413-416)
```csharp
    public override Int64Value GetNextElectCountDown(Empty input)
    {
        if (!State.IsMainChain.Value) return new Int64Value();

```

**File:** src/AElf.ContractTestKit.AEDPoSExtension/BlockMiningService.cs (L253-280)
```csharp
    private async Task InitialConsensus(DateTime currentBlockTime)
    {
        // InitialAElfConsensusContract
        {
            var executionResult = await _contractStubs.First().InitialAElfConsensusContract.SendAsync(
                new InitialAElfConsensusContractInput
                {
                    MinerIncreaseInterval = AEDPoSExtensionConstants.MinerIncreaseInterval,
                    PeriodSeconds = AEDPoSExtensionConstants.PeriodSeconds,
                    IsSideChain = _chainTypeProvider.IsSideChain
                });
            if (executionResult.TransactionResult.Status != TransactionResultStatus.Mined)
                throw new InitializationFailedException("Failed to execute InitialAElfConsensusContract.",
                    executionResult.TransactionResult.Error);
        }

        var initialMinerList = new MinerList
        {
            Pubkeys = { MissionedECKeyPairs.InitialKeyPairs.Select(p => ByteString.CopyFrom(p.PublicKey)) }
        };
        _currentRound =
            initialMinerList.GenerateFirstRoundOfNewTerm(AEDPoSExtensionConstants.MiningInterval,
                currentBlockTime);
        _testDataProvider.SetBlockTime(currentBlockTime.ToTimestamp());

        // FirstRound
        {
            var executionResult = await _contractStubs.First().FirstRound.SendAsync(_currentRound);
```
