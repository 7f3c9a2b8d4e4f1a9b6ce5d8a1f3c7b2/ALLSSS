# Audit Report

## Title
Missing Timing Validation Allows Any Miner to Trigger Premature Term Changes

## Summary
The AEDPoS consensus contract's `NextTerm()` method allows any current or previous miner to prematurely trigger term transitions by bypassing timing validation. While timing consensus logic exists in `NeedToChangeTerm()`, it is only used for command generation, not transaction validation, enabling miners to change terms without meeting the configured `periodSeconds` threshold or two-thirds miner consensus requirement.

## Finding Description

The vulnerability stems from an architectural separation between consensus command suggestion and transaction validation enforcement.

**Public Entry Point:**
The `NextTerm()` method is publicly accessible via RPC [1](#0-0)  and processes term changes through `ProcessConsensusInformation()` [2](#0-1) .

**Insufficient Authorization:**
The `PreCheck()` method only verifies that the transaction sender is in the current or previous miner list, without validating timing requirements [3](#0-2) .

**State Updates Without Timing Validation:**
The `ProcessNextTerm()` method updates term and round numbers using `TryToUpdateTermNumber()` and `TryToUpdateRoundNumber()` [4](#0-3) , which only validate sequential increments (current + 1) [5](#0-4) .

**Timing Validation Exists But Not Enforced:**
The `NeedToChangeTerm()` method implements proper timing validation, checking if at least `MinersCountOfConsent` (two-thirds + 1) miners have ActualMiningTimes meeting the period threshold [6](#0-5) . The consensus threshold is calculated as `RealTimeMinersInformation.Count * 2 / 3 + 1` [7](#0-6) .

However, this method is ONLY called during command generation to suggest behavior [8](#0-7) , not during transaction validation.

**Incomplete Transaction Validation:**
The `ValidateBeforeExecution()` method for NextTerm behavior only adds `RoundTerminateValidationProvider` [9](#0-8) , which validates sequential increments but NOT timing requirements [10](#0-9) .

**Exploit Path:**
1. Malicious miner constructs `NextTermInput` with `term_number = current + 1` and `round_number = current + 1`
2. Calls public `NextTerm()` method
3. Passes `PreCheck()` (is in current/previous miner list)
4. Passes validation (sequential increments are correct)
5. `ProcessNextTerm()` executes, triggering term/round updates, miner list changes, treasury releases, and election snapshots [11](#0-10) 

## Impact Explanation

**Consensus Integrity Breach (CRITICAL):**
The `MinersCountOfConsent` two-thirds requirement exists to ensure broad miner agreement before major state transitions. Bypassing this requirement allows contentious term changes without proper consensus, violating the fundamental consensus guarantee that term changes require supermajority agreement.

**Governance Schedule Disruption (CRITICAL):**
Terms are designed to change at fixed intervals defined by `periodSeconds` (default 604800 seconds = 7 days). Premature term changes break the predictable governance model, undermining the election system's timing guarantees and voter expectations.

**Economic Manipulation (HIGH):**
Premature term transitions cause unauthorized treasury releases [12](#0-11) , redistribution of mining rewards to new miners before the scheduled time, and disruption of reward expectations for current miners.

**Election Integrity Violation (HIGH):**
The election system assumes predictable term timing for fair campaigns and voting periods. Arbitrary timing manipulation allows exploitation of temporary vote fluctuations and premature election snapshot creation [13](#0-12) .

## Likelihood Explanation

**Attacker Capabilities: ANY MINER**
Any active miner in the current or previous round can execute this attack via the public `NextTerm()` RPC method. No special privileges beyond normal block production rights are required.

**Attack Complexity: LOW**
The attacker simply constructs a `NextTermInput` message with sequentially incremented values and calls `NextTerm()`. No complex timing coordination, cryptographic operations, or multi-step interactions are needed.

**Feasibility Conditions: ALWAYS MET**
The only precondition is being in the current or previous miner list, which is the normal state for active miners. The attack can be executed during any block production opportunity.

**Economic Incentives: STRONG**
Miners have multiple incentives to manipulate term timing: optimizing their own reward periods, benefiting preferred election candidates, or disrupting competitors' mining terms. The competitive nature of elections creates strategic value in timing control.

**Detection: POST-FACTO ONLY**
While the premature term change is visible on-chain, detection occurs after execution. The state transition is irreversible, and other nodes accept the block as valid since all implemented validation checks pass.

## Recommendation

Add timing validation to transaction validation by modifying `ValidateBeforeExecution()` to include a timing validation provider for NextTerm behavior:

1. Create a new `TermTimingValidationProvider` that calls `NeedToChangeTerm()` with the current blockchain start timestamp, term number, and period seconds
2. Add this provider to the validation chain for `AElfConsensusBehaviour.NextTerm` cases
3. Reject NextTerm transactions if `NeedToChangeTerm()` returns false

This ensures the two-thirds consensus and timing requirements are enforced during transaction validation, not just command generation.

## Proof of Concept

A valid PoC would require:
1. Setting up an AElf test network with multiple miners
2. Waiting until a point before `periodSeconds` has elapsed
3. Constructing a `NextTermInput` with `term_number = current + 1` and `round_number = current + 1`
4. Calling `NextTerm()` from a miner account
5. Observing successful term change despite timing requirements not being met
6. Verifying that `NeedToChangeTerm()` would return false but validation still passes

The test would demonstrate that timing validation exists but is not enforced during transaction execution.

### Citations

**File:** protobuf/aedpos_contract.proto (L37-39)
```text
    // Update consensus information, create a new term.
    rpc NextTerm (NextTermInput) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L98-105)
```csharp
    private bool TryToUpdateTermNumber(long termNumber)
    {
        var oldTermNumber = State.CurrentTermNumber.Value;
        if (termNumber != 1 && oldTermNumber + 1 != termNumber) return false;

        State.CurrentTermNumber.Value = termNumber;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-174)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-218)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```
