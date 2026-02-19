### Title
Consensus Chain Halt via Empty Miner List in Round Submission

### Summary
A malicious or compromised miner can craft and submit a NextRoundInput with an empty RealTimeMinersInformation dictionary that bypasses all validation checks and gets persisted to contract state. Once stored, this empty round causes TryToGetCurrentRoundInformation to fail, which prevents all miners from obtaining valid consensus commands, resulting in complete chain halt and permanent DoS of the consensus mechanism.

### Finding Description

The vulnerability exists in the round submission and validation flow with the following key components:

**Vulnerable Function**: The `GetExtraBlockMiningTime()` method calls `Last()` on an ordered collection that will throw `InvalidOperationException` if `RealTimeMinersInformation` is empty. [1](#0-0) 

**Root Cause - Insufficient Validation**: The validation providers used during consensus transaction validation do not explicitly check that RealTimeMinersInformation is non-empty:

1. `NextRoundMiningOrderValidationProvider` validates by checking if distinct count of miners with `FinalOrderOfNextRound > 0` equals miners with `OutValue != null`. For an empty collection, both counts are 0, so the validation passes (0 == 0). [2](#0-1) 

2. `RoundTerminateValidationProvider` checks if any miner has non-null InValue using `Any()`. For an empty collection, `Any()` returns false, which causes the validation to succeed (the ternary returns success when Any is false). [3](#0-2) 

**Persistence Path**: Once validation passes, `ProcessNextRound` converts the input to a Round object and persists it via `AddRoundInformation` without any additional checks on miner count. [4](#0-3) 

**Critical DoS Mechanism**: The most severe impact occurs because an empty Round has `RoundId == 0` (calculated as sum of empty ExpectedMiningTime values). The `IsEmpty` property returns true when `RoundId == 0`, causing `TryToGetCurrentRoundInformation` to return false. [5](#0-4) 

This causes `GetConsensusCommand` to immediately return `InvalidConsensusCommand` for ALL miners attempting to produce blocks: [6](#0-5) 

### Impact Explanation

**Severity**: CRITICAL - Complete chain halt

**Concrete Impact**:
- **Consensus Breakdown**: All miners receive `InvalidConsensusCommand` when attempting to mine, preventing any new blocks from being produced
- **Permanent DoS**: The chain cannot recover without manual intervention or chain rollback, as the empty round is persisted in state
- **Protocol-wide Halt**: Affects all transactions, token transfers, governance actions, and cross-chain operations
- **Economic Damage**: Complete loss of chain liveness, potential loss of user funds stuck in pending transactions, destruction of chain credibility

**Who is Affected**:
- All network participants lose ability to transact
- All miners lose block rewards indefinitely
- DApp users cannot access their applications
- The entire AElf ecosystem is halted

This is a CRITICAL vulnerability despite requiring a compromised miner because consensus is the foundation of blockchain operation, and its complete failure represents total protocol breakdown.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Must be an authorized miner in the current or previous round (validated by PreCheck) [7](#0-6) 

**Attack Complexity**: LOW
- Requires crafting a single malicious NextRoundInput message with empty RealTimeMinersInformation
- No complex transaction sequencing or state manipulation needed
- Single transaction execution achieves complete chain halt

**Feasibility Conditions**:
- Attacker controls at least one miner node (through compromise, malicious miner, or key theft)
- Standard transaction submission capabilities
- No special timing requirements

**Detection Constraints**:
- The malicious transaction appears similar to legitimate round transitions
- Validation passes, so no obvious red flags before execution
- Chain halt is immediate and obvious post-execution, but damage is already done

**Probability Assessment**: MEDIUM
- Requires miner compromise (not trivial but realistic threat model)
- Attack is straightforward once access obtained
- High impact makes this an attractive target for sophisticated attackers
- No economic cost to attacker beyond obtaining miner status

### Recommendation

**Immediate Fix**: Add explicit validation in round processing to reject rounds with empty miner lists:

1. In `ProcessNextRound`, add validation before persisting:
```csharp
var nextRound = input.ToRound();
Assert(nextRound.RealTimeMinersInformation.Count > 0, "Round must contain at least one miner.");
``` [8](#0-7) 

2. Add similar check in `ProcessNextTerm`: [9](#0-8) 

3. Add validation in `FirstRound` method: [10](#0-9) 

**Defense-in-Depth**: 
- Enhance `NextRoundMiningOrderValidationProvider` to explicitly check miner count > 0
- Add monitoring/alerting for round transitions with unusual miner counts
- Consider adding minimum miner threshold based on network parameters

**Test Cases**:
- Unit test attempting NextRound submission with empty RealTimeMinersInformation (should fail with assertion)
- Integration test verifying chain continues operating after malicious submission is rejected
- Regression test ensuring legitimate single-miner scenarios (if supported) still work

### Proof of Concept

**Initial State**:
- Chain is operational with multiple active miners
- Attacker controls one authorized miner node
- Current round has N miners (N >= 1)

**Attack Sequence**:

1. Attacker crafts malicious NextRoundInput:
   - RoundNumber = CurrentRoundNumber + 1
   - TermNumber = CurrentTermNumber (unchanged)
   - RealTimeMinersInformation = {} (empty dictionary)
   - All other fields set to plausible values
   - Valid RandomNumber for VRF verification

2. Attacker submits transaction calling `NextRound(malicious_input)` from their authorized miner account

3. Transaction execution flow:
   - `ProcessConsensusInformation` invoked [11](#0-10) 
   
   - PreCheck validates attacker is in current round miner list: PASSES
   - `ValidateBeforeExecution` called with validation providers
   - `NextRoundMiningOrderValidationProvider`: distinctCount = 0, OutValue count = 0, check passes (0 == 0)
   - `RoundTerminateValidationProvider`: Any(m => m.InValue != null) on empty = false, validation succeeds
   - `ProcessNextRound` called
   - `AddRoundInformation(nextRound)` persists empty round to `State.Rounds[roundNumber]` [12](#0-11) 

4. Chain halt manifestation:
   - Next miner attempts to produce block
   - Calls `GetConsensusCommand` via ACS4 interface
   - `TryToGetCurrentRoundInformation` retrieves empty round, calculates RoundId = 0, returns false
   - Returns `InvalidConsensusCommand`
   - Miner cannot produce block

5. Cascading failure:
   - All subsequent miners receive `InvalidConsensusCommand`
   - No blocks can be produced
   - Chain is permanently halted

**Expected Result**: Transaction should be rejected with validation failure

**Actual Result**: Transaction succeeds, empty round is persisted, chain halts permanently

**Success Condition**: After attack, `GetConsensusCommand` returns `InvalidConsensusCommand` for all miners, confirming complete consensus DoS.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L15-26)
```csharp
    public long RoundId
    {
        get
        {
            if (RealTimeMinersInformation.Values.All(bpInfo => bpInfo.ExpectedMiningTime != null))
                return RealTimeMinersInformation.Values.Select(bpInfo => bpInfo.ExpectedMiningTime.Seconds).Sum();

            return RoundIdForValidation;
        }
    }

    public bool IsEmpty => RoundId == 0;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-28)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-165)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-28)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L74-78)
```csharp
    public override Empty FirstRound(Round input)
    {
        /* Basic checks. */
        Assert(State.CurrentRoundNumber.Value == 0, "Already initialized.");

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```
