# Audit Report

## Title
Side Chain NextRound Can Accept BlockchainAge = 0 for RoundNumber > 1 Due to Missing Field Initialization

## Summary
On side chains, when the main chain miner list changes during round transition, the consensus contract generates a new Round without setting the `BlockchainAge` field, causing it to default to 0. This violates the critical invariant that blockchain age must monotonically increase with each round, creating inconsistent consensus state.

## Finding Description

The vulnerability exists in the side chain consensus round generation flow with multiple components working together to create the issue:

**Missing BlockchainAge Initialization in Side Chain Path:**

When running on a side chain and the main chain miner list has changed, the `GenerateNextRoundInformation` method takes a special branch that calls `GenerateFirstRoundOfNewTerm` but fails to set the `BlockchainAge` field before returning. [1](#0-0) 

This code path:
1. Detects the side chain condition and miner list change
2. Calls `GenerateFirstRoundOfNewTerm` to create the new round
3. Sets only `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber`
4. Returns immediately without setting `BlockchainAge`

**GenerateFirstRoundOfNewTerm Doesn't Set BlockchainAge:**

The `GenerateFirstRoundOfNewTerm` method creates a new Round and initializes various fields but explicitly does not set `BlockchainAge`. [2](#0-1) 

**Protobuf Default Value:**

The `blockchain_age` field in the protobuf definition defaults to 0 when not explicitly set. [3](#0-2) 

**Contrast with Normal Path:**

In the normal round generation path, `BlockchainAge` is properly calculated based on the elapsed time since blockchain start. [4](#0-3) 

**Contrast with Main Chain New Term:**

Even when generating a first round of a new term on the main chain, `BlockchainAge` is explicitly set. [5](#0-4) 

**Unvalidated Copy in NextRoundInput.Create():**

The `Create()` method directly copies `BlockchainAge` from the input Round without any validation. [6](#0-5) 

**No Validation in ProcessNextRound:**

The `ProcessNextRound` method accepts the Round and stores it without validating that `BlockchainAge` is appropriate for the `RoundNumber`. [7](#0-6) 

**No Validation Providers Check BlockchainAge:**

None of the validation providers used during `ValidateBeforeExecution` check the `BlockchainAge` field, including `RoundTerminateValidationProvider` which validates NextRound behavior. [8](#0-7) 

The validation only checks round number increment and that InValues are null, but does not validate `BlockchainAge`.

## Impact Explanation

**Consensus Invariant Violation:**
- Breaks the fundamental invariant that `BlockchainAge` must monotonically increase with each round
- According to the protobuf definition, `BlockchainAge` represents "the time from chain start to current round (seconds)"
- Creates inconsistent state where a side chain at round N+1 has blockchain age of 0, while round N had a non-zero value
- Violates the documented semantics of the field

**Side Chain Specific Impact:**
- Affects all side chains that synchronize with main chain miner list changes via cross-chain consensus
- The issue only manifests when `IsMainChainMinerListChanged()` returns true, which happens during normal main chain miner elections and term changes

**Limited Direct Impact:**
- Does NOT directly lead to fund theft or loss
- Does NOT break the core mining schedule or block production
- Consensus continues to function despite the incorrect state
- Could affect monitoring/analysis systems that rely on blockchain age metrics
- May impact future features that depend on accurate blockchain age tracking

**Severity Assessment:**
Medium severity because:
- It violates a critical consensus invariant documented in the protocol
- Occurs during normal operations without special conditions
- Undermines consensus correctness and state consistency
- However, does not have immediate financial impact or break core consensus functionality

## Likelihood Explanation

**Entry Point:**
The vulnerability is triggered through the standard consensus flow when miners produce blocks. The entry point is `GetConsensusExtraDataForNextRound` which calls `GenerateNextRoundInformation`. [9](#0-8) 

**Preconditions:**
1. Chain must be a side chain (`!IsMainChain`)
2. Main chain miner list must change between rounds
3. A miner produces a block triggering NextRound behavior

**Feasibility:**
- Side chains are a standard feature in AElf architecture - this is core functionality, not an edge case
- Main chain miner list changes occur during normal operations:
  - Elections when new validators are elected
  - Term changes when consensus moves to next term  
  - Miner replacements when miners are replaced
- No attacker capabilities required beyond being a legitimate miner on the side chain
- The code path is deterministic and will trigger whenever the conditions are met

**Attack Complexity:**
- Low complexity - occurs automatically during normal consensus operations
- No special manipulation required
- Not dependent on timing or race conditions
- Simply requires waiting for a main chain miner list change while running on a side chain

**Detection:**
- Easy to detect by monitoring Round state and checking if `BlockchainAge` decreases or stays zero across rounds
- Can be verified by querying `GetCurrentRoundInformation()` and checking the `BlockchainAge` field
- However, may go unnoticed if not explicitly monitored since consensus continues to function

**Probability:**
Medium-High probability of occurring on active side chains that experience main chain miner list changes, which happen regularly in production environments.

## Recommendation

Add `BlockchainAge` initialization in the side chain specific path. In `GenerateNextRoundInformation` method in `AEDPoSContract_ViewMethods.cs`, after line 293, add:

```csharp
nextRound.BlockchainAge = GetBlockchainAge();
```

The fixed code should look like:

```csharp
if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
{
    nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
        currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
    nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
    nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
    nextRound.BlockchainAge = GetBlockchainAge();  // ADD THIS LINE
    return;
}
```

This ensures the `BlockchainAge` is properly calculated and set even in the side chain miner list change path, maintaining the invariant that blockchain age increases monotonically with each round.

Optionally, add validation in `NextRoundInput.Create()` or the validation providers to assert that `BlockchainAge > 0` when `RoundNumber > 1` as a defense-in-depth measure.

## Proof of Concept

A proof of concept would involve:

1. Deploy a side chain with the AEDPoS consensus contract
2. Wait for the side chain to progress past round 1 (so that normal BlockchainAge is non-zero)
3. Trigger a main chain miner list change via cross-chain consensus (UpdateInformationFromCrossChain)
4. Have a miner produce the next block which triggers NextRound
5. Query GetCurrentRoundInformation() and observe that:
   - RoundNumber has incremented (e.g., from round 5 to round 6)
   - BlockchainAge is 0 instead of the expected increasing value
   - This violates the invariant that BlockchainAge should monotonically increase

The test would verify that in the returned Round object, `RoundNumber > 1` but `BlockchainAge == 0`, demonstrating the invariant violation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L247-247)
```csharp
        newRound.BlockchainAge = GetBlockchainAge();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L12-44)
```csharp
    internal Round GenerateFirstRoundOfNewTerm(int miningInterval,
        Timestamp currentBlockTime, long currentRoundNumber = 0, long currentTermNumber = 0)
    {
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();

        var round = new Round();

        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
        }

        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;

        return round;
```

**File:** protobuf/aedpos_contract.proto (L250-251)
```text
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L23-23)
```csharp
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L14-14)
```csharp
            BlockchainAge = round.BlockchainAge,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
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
        }

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

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```
