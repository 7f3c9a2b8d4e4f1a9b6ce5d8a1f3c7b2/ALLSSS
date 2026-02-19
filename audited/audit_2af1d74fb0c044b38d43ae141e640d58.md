### Title
Null Reference Exception in ValidateConsensusAfterExecution on Side Chains During Miner List Updates

### Summary
The `ValidateConsensusAfterExecution()` method unconditionally calls `State.ElectionContract.GetNewestPubkey.Call()` to validate miner replacements, but on side chains the `ElectionContract` reference is never initialized and remains null. When side chains receive miner list updates from the main chain and validate blocks created before the update, this causes a `NullReferenceException` that crashes consensus validation and can halt the side chain.

### Finding Description

The root cause is in the `ValidateConsensusAfterExecution()` method which validates miner replacements without checking if the ElectionContract reference is available: [1](#0-0) 

This code path is reached when round hashes differ between the block header and current state, indicating potential miner replacements: [2](#0-1) 

On side chains, the `ElectionContract` reference is never initialized because the initialization returns early for side chains: [3](#0-2) 

Side chains receive miner list updates from the main chain via cross-chain synchronization: [4](#0-3) 

When a side chain validates a block that was created before a miner list update but is being validated after the update, the round hashes will differ. The validation logic identifies miners in the header that are not in the current state as "replaced miners" and attempts to call `GetNewestPubkey` on the null `ElectionContract` reference, causing a `NullReferenceException`.

The cross-contract call infrastructure throws exceptions rather than returning null: [5](#0-4) 

However, calling a method on a null reference occurs before reaching the call infrastructure.

### Impact Explanation

**Operational Impact - DoS of Side Chain Consensus:**
- Side chain block validation fails with an unhandled exception when validating blocks during miner list transitions
- This prevents the side chain from processing blocks and reaching consensus
- Side chain operation is halted until manual intervention or a hotfix is deployed
- All transactions on the affected side chain are blocked

**Affected Parties:**
- Side chain operators and validators
- Users and applications relying on the side chain
- Cross-chain operations involving the affected side chain

**Severity Justification:**
This is a Medium severity issue because:
- It causes complete side chain operational failure (DoS)
- It occurs during legitimate operational scenarios (miner list updates)
- It requires no attacker action - it's a consensus logic bug
- Recovery requires contract upgrade or chain restart

### Likelihood Explanation

**Reachable Entry Point:**
The `ValidateConsensusAfterExecution()` method is a core ACS4 consensus interface method called during block validation for every block: [6](#0-5) 

**Feasible Preconditions:**
- Side chain is running normally
- Main chain updates the miner list (happens during normal consensus operation)
- Side chain receives and applies the miner list update
- A block created before the update is validated after the update (common during block propagation/validation)

**Execution Practicality:**
This scenario occurs naturally during normal side chain operation without any attacker involvement. Side chains synchronize miner lists from the main chain as part of their standard consensus mechanism.

**Probability Assessment:**
HIGH - This will occur on every side chain whenever the main chain miner list changes and blocks from before the change are validated. Miner list changes happen regularly on the main chain during term transitions and miner replacements.

### Recommendation

Add a main chain check before attempting to validate miner replacements in `ValidateConsensusAfterExecution()`:

```csharp
var newMiners = stateMiners.Except(headerMiners).ToList();

// Only validate miner replacements on main chain where ElectionContract is available
if (State.IsMainChain.Value)
{
    var officialNewestMiners = replacedMiners.Select(miner =>
            State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
        .ToList();

    Assert(
        newMiners.Count == officialNewestMiners.Count &&
        newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
        "Incorrect replacement information.");
}
```

**Additional Mitigation:**
For side chains, miner list updates come from the main chain and are already validated there. Side chains should not re-validate miner replacements using the Election contract. Instead, they should trust the miner list received from the main chain via cross-chain synchronization.

**Test Cases:**
1. Test ValidateConsensusAfterExecution on a side chain after a miner list update
2. Test block validation with old miner list against new state on side chain
3. Verify that main chain miner replacement validation still works correctly

### Proof of Concept

**Initial State:**
1. Deploy and initialize a side chain with initial miner list [A, B, C]
2. Side chain is operational and producing blocks

**Exploitation Steps:**
1. Main chain updates miner list to [A, B, D] (replacing C with D)
2. Side chain receives miner list update via `UpdateInformationFromCrossChain`
3. Side chain state now has miner list [A, B, D]
4. A block arrives for validation that was created when miner list was still [A, B, C]
5. Block header contains round information with miners [A, B, C]
6. ValidateConsensusAfterExecution is called:
   - Round hash comparison fails (line 100-101) because miners differ
   - replacedMiners = [C] (miner in header but not in state)
   - newMiners = [D] (miner in state but not in header)
   - Code attempts: `State.ElectionContract.GetNewestPubkey.Call(...)` (line 117)
   - `State.ElectionContract` is null on side chains
   - **NullReferenceException is thrown**

**Expected Result:**
Validation should succeed or fail gracefully based on side chain-appropriate logic

**Actual Result:**
Unhandled NullReferenceException crashes the validation process, preventing block acceptance and halting consensus

**Success Condition:**
The side chain validation process throws a NullReferenceException when attempting to validate a block with an old miner list after a miner list update has been applied to the state.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-84)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L115-118)
```csharp
                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L37-46)
```csharp
        if (input.IsTermStayOne || input.IsSideChain)
        {
            State.IsMainChain.Value = false;
            return new Empty();
        }

        State.IsMainChain.Value = true;

        State.ElectionContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-294)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L221-225)
```csharp
        if (!trace.IsSuccessful()) throw new ContractCallException(trace.Error);

        var obj = new T();
        obj.MergeFrom(trace.ReturnValue);
        return obj;
```
