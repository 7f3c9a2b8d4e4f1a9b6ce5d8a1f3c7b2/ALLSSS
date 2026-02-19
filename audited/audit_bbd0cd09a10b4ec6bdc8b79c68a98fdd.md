### Title
Side Chain Validator Set Permanently Locked Without Cross-Chain Synchronization Alternative

### Summary
Side chains in AElf rely exclusively on cross-chain synchronization (`UpdateInformationFromCrossChain`) to update their validator sets and have no alternative governance mechanism. If the cross-chain synchronization mechanism fails (e.g., indexing fee depletion, side chain termination, cross-chain contract failure, or main chain unavailability), the side chain becomes permanently controlled by its current validators with no recovery path, even through unanimous governance proposals.

### Finding Description

**Root Cause:**

Side chains never use the `NextTerm` behavior for validator updates. The `SideChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` method always returns `NextRound` instead of `NextTerm`: [1](#0-0) 

The only mechanism for side chain validator updates is through cross-chain synchronization. The `UpdateInformationFromCrossChain` method updates `State.MainChainCurrentMinerList.Value` with validators from the main chain: [2](#0-1) 

This updated miner list is then used in `GenerateNextRoundInformation` when it detects the miner list has changed: [3](#0-2) 

**Why Protections Fail:**

1. **SetMinerList is private** - No direct public method exists to update the validator set: [4](#0-3) 

2. **NextTerm falls back to current validators on side chains** - Even if `NextTerm` is called manually, `GenerateFirstRoundOfNextTerm` calls `TryToGetVictories` which returns false for side chains: [5](#0-4) 

This causes it to fall back to reusing the current round's miners: [6](#0-5) 

3. **Cross-chain synchronization can fail** - Multiple realistic scenarios prevent `UpdateInformationFromCrossChain` from being called, including when the side chain status becomes `IndexingFeeDebt` or `Terminated`, which blocks all cross-chain indexing.

### Impact Explanation

**Concrete Impact:**
- Side chains lose the ability to add or remove validators permanently
- Current validators maintain perpetual control over the chain
- No governance mechanism (Parliament, Association, or Referendum) can change the validator set
- The side chain becomes centralized and controlled by whoever holds the initial validator keys
- Complete loss of decentralization and censorship resistance

**Who is Affected:**
- All side chain users and applications
- Token holders on the side chain
- Projects building on the side chain infrastructure
- Main chain reputation as a secure multi-chain platform

**Severity Justification:**
This is CRITICAL because:
1. It results in permanent, irrecoverable validator control
2. No governance action can fix it after cross-chain sync fails
3. Multiple realistic failure scenarios exist
4. Fundamentally compromises the security model of the side chain

### Likelihood Explanation

**Realistic Failure Scenarios:**

1. **Indexing Fee Depletion**: Side chains must pay fees for cross-chain indexing. If the fee balance is depleted, the side chain enters `IndexingFeeDebt` status, blocking all cross-chain updates.

2. **Side Chain Termination**: Governance can terminate a side chain, setting its status to `Terminated`, which prevents further cross-chain synchronization.

3. **Cross-Chain Contract Bugs**: Any bug in the cross-chain contract could prevent `UpdateInformationFromCrossChain` from being called.

4. **Main Chain Unavailability**: If the main chain stops producing blocks or validator information, side chains cannot receive updates.

5. **Network Partition**: Extended network partitions between main and side chains prevent synchronization.

**Feasibility:**
- No attacker action required - these are operational failures
- Some scenarios (fee depletion, termination) are by design
- Others (bugs, network issues) are realistic operational risks
- Once any scenario occurs, recovery is impossible

**Detection/Operational Constraints:**
The issue would be immediately obvious when validators need to be changed but cannot be, but by that time it's too late - there's no recovery mechanism.

### Recommendation

**Code-Level Mitigation:**

1. **Add governance-controlled validator update method** for side chains:
```
public override Empty SetValidatorsViaGovernance(SetValidatorsInput input)
{
    Assert(!State.IsMainChain.Value, "Only for side chains");
    RequireValidatorUpdateController();
    Assert(Context.Sender == State.ValidatorUpdateController.Value.OwnerAddress, 
           "No permission");
    
    var minerList = new MinerList { Pubkeys = { input.Pubkeys } };
    var termNumber = State.CurrentTermNumber.Value.Add(1);
    SetMinerList(minerList, termNumber, true);
    
    // Force term transition with new validators
    var nextRound = minerList.GenerateFirstRoundOfNewTerm(
        State.MiningInterval.Value, 
        Context.CurrentBlockTime, 
        GetCurrentRoundInformation(new Empty()));
    
    State.CurrentTermNumber.Value = termNumber;
    AddRoundInformation(nextRound);
    
    return new Empty();
}
```

2. **Add controller setup in initialization**:
Set `State.ValidatorUpdateController.Value` to Parliament or Association contract during side chain initialization.

3. **Add emergency NextTerm override** for side chains:
Modify `SideChainConsensusBehaviourProvider` to support NextTerm when a governance flag is set.

**Invariant Checks:**
- Side chains must always have at least one mechanism to update validators beyond cross-chain sync
- Validator update controller must be set during initialization
- Test that validator updates work even when cross-chain sync fails

**Test Cases:**
- Test validator update through governance when `UpdateInformationFromCrossChain` is blocked
- Test recovery from IndexingFeeDebt status with validator changes
- Test emergency validator rotation during network partition
- Verify that malicious validators cannot prevent governance-controlled updates

### Proof of Concept

**Initial State:**
1. Side chain initialized with 3 initial validators (V1, V2, V3)
2. Side chain synchronized with main chain
3. Cross-chain contract functioning normally

**Exploitation Steps:**

1. Side chain enters `IndexingFeeDebt` status (runs out of indexing fees)
   - Cross-chain indexing blocked
   - `UpdateInformationFromCrossChain` can no longer be called

2. Main chain validators change (new election cycle completes)
   - Main chain now has validators (V4, V5, V6)
   - Side chain still has (V1, V2, V3)

3. Side chain attempts validator update through governance:
   - Parliament proposal created to update validators
   - Proposal approved by current validators (V1, V2, V3)
   - Proposal executed: **FAILS** - no method to update validator set exists

4. Side chain attempts manual `NextTerm`:
   - Current validator calls `NextTerm` method
   - `GenerateFirstRoundOfNextTerm` called
   - `TryToGetVictories` returns false (side chain has no election)
   - Falls back to current miners (V1, V2, V3)
   - **Result**: Same validators, no update

**Expected vs Actual Result:**

**Expected**: Side chain can update its validator set through governance proposals when cross-chain sync fails.

**Actual**: Side chain is permanently stuck with validators (V1, V2, V3). No governance action can change this. The side chain is permanently controlled by whoever holds the V1, V2, V3 validator keys, even if those keys are compromised or the validators become malicious.

**Success Condition for Attack:**
The vulnerability is successfully exploited when any scenario prevents cross-chain synchronization and the side chain cannot update its validators through any alternative mechanism, resulting in permanent validator control.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L20-23)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-64)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L234-242)
```csharp
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-295)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```
