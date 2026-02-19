### Title
Side Chain Consensus Deadlock: Infinite NextRound Loop Without Recovery Mechanism

### Summary
Side chains can become permanently stuck when NextRound transactions fail, as the `SideChainConsensusBehaviourProvider` unconditionally returns `NextRound` behavior with no recovery path. If the current round state contains corrupted data (e.g., invalid `FinalOrderOfNextRound` values) that causes NextRound validation to fail, every subsequent block attempt will generate identical failing NextRound transactions from the unchanged round state, resulting in permanent chain halt with no recovery mechanism.

### Finding Description

The vulnerability exists in the consensus command generation flow for side chains: [1](#0-0) 

Unlike the main chain implementation which has conditional logic to return either `NextRound` or `NextTerm`: [2](#0-1) 

The side chain provider unconditionally returns `NextRound`, creating a single point of failure with no alternative path.

**Execution Flow:**

1. When a miner requests consensus behavior, the base provider calls `GetConsensusBehaviourToTerminateCurrentRound()`: [3](#0-2) 

2. This triggers next round generation using the current round state: [4](#0-3) 

3. The next round generation copies `FinalOrderOfNextRound` values from the current round: [5](#0-4) 

4. A NextRound transaction is generated: [6](#0-5) 

5. The transaction undergoes validation including mining order validation: [7](#0-6) 

6. If validation fails or execution fails, the round number is never updated: [8](#0-7) 

**Root Cause:**

When a NextRound transaction fails (validation or execution failure), the state remains unchanged. On the next block attempt:
- `GetCurrentRoundInformation()` returns the **same** round state
- `GetConsensusBehaviour()` again calls `GetConsensusBehaviourToTerminateCurrentRound()` which **always** returns `NextRound`
- `GenerateNextRoundInformation()` generates next round from the **same** (potentially corrupted) current round state
- The **same** corrupted `FinalOrderOfNextRound` values are used
- The NextRound transaction fails again with the **same** error

**Why Existing Protections Fail:**

1. No recovery mechanism exists (grep search for "RecoverFromFailedRound", "ForceNextRound", "AdminNextRound" returned zero results)
2. PreCheck failure doesn't help - it allows transaction to succeed without updating state: [9](#0-8) 

3. No timeout or circuit breaker logic
4. Side chains cannot switch to NextTerm behavior as an alternative path
5. The transaction-once-per-block check prevents duplicate execution but doesn't prevent retry in next block: [10](#0-9) 

### Impact Explanation

**Concrete Harm:**
- **Permanent Chain Halt**: Once trapped in the loop, the side chain cannot produce any new blocks or advance rounds
- **Complete Service Disruption**: All transactions, cross-chain operations, and token transfers on the side chain become impossible
- **No Self-Recovery**: Without external intervention to fix the corrupted state, the chain remains permanently stuck
- **Cascading Effects**: Parent-child chain communication breaks, cross-chain asset bridges fail, dependent applications become unavailable

**Who Is Affected:**
- All side chain users lose access to their assets and services
- Cross-chain applications depending on the side chain fail
- Main chain operations waiting for side chain confirmations are blocked

**Severity Justification - HIGH:**
This is a permanent denial-of-service condition with no recovery mechanism. Unlike temporary network issues or transient failures, this represents a fundamental flaw in the consensus state machine that can render an entire side chain permanently inoperable. The impact is total chain failure, not partial degradation.

### Likelihood Explanation

**Attack Complexity:**
No attacker is required - this is a systemic design flaw that can be triggered by any state corruption.

**Feasible Preconditions:**
Round state corruption leading to invalid `FinalOrderOfNextRound` values can occur through:
1. Software bugs during UpdateValue processing
2. Race conditions in concurrent state updates
3. Failed miner replacements leaving inconsistent state
4. Secret sharing failures corrupting signature data
5. Edge cases in order conflict resolution

**Execution Practicality:**
Once the condition is triggered, the loop is deterministic and self-perpetuating:
- Every miner will independently arrive at the same failing NextRound transaction
- No manual intervention by miners can break the loop
- The failure reproduces identically on every block attempt

**Detection/Operational Constraints:**
- The stuck state is immediately visible (no new blocks produced)
- However, fixing it requires either:
  - Hard fork to correct state
  - Chain rollback to before corruption
  - Contract upgrade to add recovery mechanism
- None of these are quick or easy operational responses

**Probability Reasoning:**
While state corruption may be rare under normal operation, the complete lack of recovery mechanism means that ANY instance of corruption leading to invalid NextRound data results in permanent chain halt. The probability is non-zero and the consequence is catastrophic.

### Recommendation

**Code-Level Mitigation:**

1. **Add Conditional Logic to SideChainConsensusBehaviourProvider:**
   Implement failure detection and alternative behavior similar to main chain's approach. Add checks for repeated NextRound failures and provide escape mechanisms.

2. **Implement Round Advancement Timeout:**
   Add state tracking for consecutive NextRound failures. After N failed attempts (e.g., 5), allow an emergency round advancement that:
   - Uses fallback values for corrupted `FinalOrderOfNextRound` (e.g., sequential ordering)
   - Logs the recovery event for investigation
   - Marks the round as recovered for audit trail

3. **Add Administrative Recovery Function:**
   Implement a privileged method (callable only by contract owner/governance) to force round advancement:
   ```
   public override Empty ForceNextRound(ForceNextRoundInput input)
   {
       Assert(IsControllerAddress(), "No permission");
       // Validate admin-provided next round data
       // Bypass normal generation, use admin data
       // Update round state
   }
   ```

4. **Enhance Validation with Recovery Path:**
   In `NextRoundMiningOrderValidationProvider`, detect repeated validation failures and allow degraded-mode validation that accepts imperfect but functional round data.

**Invariant Checks to Add:**

1. Track consecutive NextRound failures in state
2. Assert that failure count doesn't exceed threshold
3. Verify FinalOrderOfNextRound values are valid before generating NextRound
4. Add pre-validation in `GenerateNextRoundInformation()` to detect corrupt state early

**Test Cases to Prevent Regression:**

1. Test NextRound with intentionally corrupted FinalOrderOfNextRound values
2. Verify recovery mechanism activates after N failures
3. Test administrative override function with various corruption scenarios
4. Verify that fallback ordering logic produces valid rounds
5. Test cross-miner consistency when using fallback mechanisms

### Proof of Concept

**Required Initial State:**
1. Side chain running with multiple miners
2. Current round N with corrupted `FinalOrderOfNextRound` values (e.g., duplicate orders or values outside valid range)
3. All miners have passed their time slots, triggering round termination

**Transaction Steps:**

1. **Block Height H**: Miner A's time slot ends, calls `GetConsensusCommand()`
   - Returns `NextRound` behavior
   - Generates NextRound transaction with corrupted order data
   - Transaction validation fails: "Invalid FinalOrderOfNextRound"
   - Round stays at N

2. **Block Height H+1**: Miner B attempts next block
   - Calls `GetConsensusCommand()` with round still at N
   - Returns `NextRound` behavior again (unconditional)
   - Generates **identical** NextRound transaction (same source data)
   - Transaction validation fails with **same error**
   - Round stays at N

3. **Block Height H+2**: Miner C attempts next block
   - Same process repeats
   - Same failure occurs
   - Round stays at N

4. **Block Height H+3...∞**: 
   - Loop continues indefinitely
   - No block is successfully produced
   - Chain is permanently stuck at round N

**Expected vs Actual Result:**
- **Expected**: After NextRound fails, miners should have alternative paths (use fallback ordering, call recovery function, etc.) or validation should succeed with repaired data
- **Actual**: All miners endlessly generate identical failing NextRound transactions with no escape mechanism

**Success Condition for Exploit:**
The side chain stops producing blocks permanently. Checking `GetCurrentRoundNumber()` shows the same value indefinitely despite block production attempts.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L16-23)
```csharp
        /// <summary>
        ///     Simply return NEXT_ROUND for side chain.
        /// </summary>
        /// <returns></returns>
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-83)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L164-171)
```csharp
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L312-331)
```csharp
    ///     The transaction can still executed successfully if the pre-check failed,
    ///     though doing nothing about updating state.
    /// </summary>
    /// <returns></returns>
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```
