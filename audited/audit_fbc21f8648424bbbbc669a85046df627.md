### Title
Missing Interface Validation on ElectionContract Reference Enables Consensus Halt via Non-Compliant Contract

### Summary
The AEDPoS consensus contract does not validate that the ElectionContract implements required methods before invoking them. If a non-compliant contract is deployed at the ElectionContract system address, critical consensus operations will fail with unhandled exceptions during term transitions and round generation, causing complete consensus halt.

### Finding Description

The ElectionContract reference is initialized via `Context.GetContractAddressByName()` without any validation of interface compliance: [1](#0-0) 

During consensus operations, two critical methods are invoked on this reference without exception handling:

1. **GetVictories** - Called during term transitions to elect new miners: [2](#0-1) 

This method is invoked in the term transition path: [3](#0-2) 

2. **GetMinerReplacementInformation** - Called during round generation to detect evil miners: [4](#0-3) 

Both use the `.Call()` method which throws `ContractCallException` if the target method doesn't exist or fails: [5](#0-4) 

The method `TryToGetVictories` is misleadingly named - it does not handle exceptions and will propagate failures upward, despite having a fallback mechanism that only activates when the call succeeds but returns empty results.

**Note**: `GetCandidateInformation()` mentioned in the audit question is NOT called by consensus contract in production code, only in tests.

### Impact Explanation

A non-compliant ElectionContract would cause:

1. **Complete Consensus Halt on Term Transition**: When `GetConsensusBlockExtraData` is called with `NextTerm` behavior, `GetVictories` invocation fails, throwing unhandled exception. The blockchain cannot elect new miners and term transition fails completely.

2. **Consensus Halt on Round Generation**: When `GenerateNextRoundInformation` is called during same-term block production, `GetMinerReplacementInformation` invocation fails, preventing any new blocks from being produced.

3. **Network-Wide Impact**: All nodes attempting consensus operations encounter the same failure, resulting in synchronized network halt requiring manual intervention and contract redeployment.

The severity is **HIGH** because consensus is the most critical blockchain operation - its failure renders the entire network inoperable.

### Likelihood Explanation

**Preconditions Required**:
- Genesis contract misconfiguration mapping ElectionContractSystemName to wrong address, OR
- Governance-controlled upgrade deploying non-compliant Election contract version, OR
- Deployment error placing incorrect contract at system address

**Complexity**: LOW - No exploitation steps needed, failure occurs automatically during normal consensus operations once misconfigured.

**Attacker Capabilities**: Requires either:
- Control over genesis configuration (deployment-time attack)
- Governance compromise to force malicious upgrade (runtime attack)
- Exploitation of deployment process vulnerabilities

**Feasibility**: MEDIUM-LOW in properly configured production environment with governance oversight, but MEDIUM-HIGH during deployment/migration phases or in chains with weak governance.

**Detection**: Immediate and obvious - consensus halts completely, logged in transaction traces.

Overall likelihood: **MEDIUM-LOW** for established chains with strong governance, but **MEDIUM** considering deployment errors and configuration mistakes that occur in real blockchain systems.

### Recommendation

**Immediate Mitigation**:

1. Add interface validation during ElectionContract initialization:

```csharp
// In InitialAElfConsensusContract or EnsureElectionContractAddressSet
State.ElectionContract.Value = 
    Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);

// Validate required methods exist by making safe test calls
try {
    var testVictories = State.ElectionContract.GetVictories.Call(new Empty());
    var testInfo = State.ElectionContract.GetMinerReplacementInformation.Call(
        new GetMinerReplacementInformationInput { CurrentMinerList = {} });
} catch {
    Assert(false, "ElectionContract does not implement required interface");
}
```

2. Add exception handling around critical calls:

```csharp
private bool TryToGetVictories(out MinerList victories)
{
    if (!State.IsMainChain.Value) {
        victories = null;
        return false;
    }
    
    try {
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        victories = new MinerList { Pubkeys = { victoriesPublicKeys.Value } };
        return victories.Pubkeys.Any();
    } catch (ContractCallException ex) {
        Context.LogDebug(() => $"Failed to get victories: {ex.Message}");
        victories = null;
        return false;
    }
}
```

3. Add validation tests verifying ElectionContract interface compliance before deployment.

### Proof of Concept

**Scenario**: Governance deploys non-compliant Election contract

**Initial State**:
- Blockchain operational with compliant Election contract
- Governance proposal to upgrade Election contract passes
- New contract deployed missing `GetVictories` method

**Exploitation Steps**:

1. Governance executes contract upgrade, setting ElectionContract system name to point to non-compliant contract
2. Blockchain continues operating until next term transition
3. Miner attempts to produce NextTerm block by calling `GetConsensusBlockExtraData` with `AElfConsensusBehaviour.NextTerm`
4. Execution path: `GetConsensusExtraDataForNextTerm` → `GenerateFirstRoundOfNextTerm` → `TryToGetVictories` → `State.ElectionContract.GetVictories.Call(new Empty())`
5. Call fails with `ContractCallException: Method GetVictories not found`
6. Exception propagates unhandled through consensus stack
7. Block production fails, transaction reverted
8. All nodes encounter same failure, consensus halts network-wide

**Expected Result**: Fallback to current miners or graceful degradation

**Actual Result**: Unhandled exception, consensus halt, network inoperable

**Success Condition**: Network requires emergency intervention, contract rollback, or manual repair to resume operation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L45-46)
```csharp
        State.ElectionContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-210)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
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
