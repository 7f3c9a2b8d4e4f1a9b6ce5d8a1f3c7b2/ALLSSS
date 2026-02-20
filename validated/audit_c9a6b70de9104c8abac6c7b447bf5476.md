# Audit Report

## Title
Missing Term Duration Validation Allows Premature Term Transitions

## Summary
The consensus validation logic for `NextTerm` transactions only verifies structural correctness (round and term number increments) without enforcing the critical temporal constraint that terms must last for `periodSeconds` duration. A malicious miner can force premature term transitions by bypassing honest node behavior logic, enabling manipulation of mining rewards, treasury releases, and election snapshots.

## Finding Description

The AEDPoS consensus mechanism has two separate code paths for term transitions: behavior determination (used by honest nodes to decide when to change terms) and validation (used to verify blocks from all nodes). These paths have a critical mismatch in their enforcement of time constraints.

**Behavior Determination (Honest Nodes Only):**

The `MainChainConsensusBehaviourProvider` uses `NeedToChangeTerm()` to decide whether to return `NextRound` or `NextTerm` behavior [1](#0-0) . The `NeedToChangeTerm()` method properly validates that at least 2/3 of miners have `ActualMiningTimes` indicating sufficient elapsed time [2](#0-1) , comparing elapsed time against `periodSeconds` [3](#0-2) .

**Validation (All Nodes):**

However, the validation pipeline uses a completely different logic path. When a `NextTerm` block is validated via `ValidateBeforeExecution()`, only the `RoundTerminateValidationProvider` is added to the validation pipeline [4](#0-3) . The `ValidationForNextTerm()` method only checks that round number increments by 1 and term number increments by 1 [5](#0-4)  - **no time constraint validation occurs**.

**Attack Execution:**

1. A malicious miner modifies their node to bypass `NeedToChangeTerm()` and always return `NextTerm` behavior
2. During their scheduled time slot, they call the public `NextTerm()` method [6](#0-5) 
3. The `PreCheck()` only verifies the sender is in the current or previous miner list [7](#0-6) 
4. The malicious block passes all validation checks despite the premature term transition
5. Other honest nodes accept and build upon this invalid state

## Impact Explanation

This vulnerability breaks a fundamental consensus invariant that terms must last for `periodSeconds` duration (typically 7 days). The premature term transition triggers multiple critical state changes with network-wide economic impact:

**Mining Reward Manipulation:** The `ProcessNextTerm()` method calls `DonateMiningReward()` which calculates and distributes mining rewards based on blocks produced in the "completed" term [8](#0-7) . Premature term changes result in incorrect reward calculations and distributions to miners [9](#0-8) .

**Treasury Release Manipulation:** Term changes trigger `Treasury.Release()` with the current period number [10](#0-9) , releasing treasury funds prematurely and disrupting the intended economic distribution schedule.

**Election Snapshot Timing:** Election snapshots are taken at term boundaries via `TakeSnapshot()` [11](#0-10) , which determines the next set of miners. Premature snapshots apply election results before the intended time.

**Miner List Updates:** The new miner list from election results is applied immediately [12](#0-11) , disrupting the consensus schedule and potentially removing honest miners prematurely.

**Impact Severity: HIGH** - Affects consensus integrity, economic incentives network-wide, and can be exploited deterministically by any single miner.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a current miner (in the active miner list)
- Must control their node software to modify consensus behavior logic
- No additional economic resources, stake, or collusion with other miners required

**Attack Complexity:**

The attack is straightforward to execute:
1. Modify `GetConsensusBehaviourToTerminateCurrentRound()` to always return `NextTerm`, OR
2. Modify `NeedToChangeTerm()` to always return `true`
3. Wait for the miner's scheduled time slot
4. Generate and broadcast a `NextTerm` consensus transaction with properly structured input (round number + 1, term number + 1)
5. The transaction passes validation since only structural checks are performed

**Feasibility:**

Every miner has a guaranteed time slot in the block production rotation. The validation pipeline provides no defense against this attack - the `TimeSlotValidationProvider` only checks that the miner is producing within their assigned time slot [13](#0-12) , not that sufficient time has passed for a term change.

**Detection:**

While the attack is detectable by monitoring term change timing against expected `periodSeconds`, once a malicious block is validated and added to the chain, the state corruption is permanent. Other honest miners will build upon the invalid chain state, and the incorrect reward distributions, treasury releases, and election results cannot be reversed.

**Likelihood: HIGH** - Any miner can execute this attack deterministically during their time slot with trivial node modifications.

## Recommendation

Add temporal validation to `RoundTerminateValidationProvider.ValidationForNextTerm()` that enforces the term duration requirement. The validation should mirror the logic in `NeedToChangeTerm()`:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Validate term number increment
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // ADD: Validate sufficient time has elapsed for term change
    var blockchainStartTimestamp = State.BlockchainStartTimestamp.Value;
    var periodSeconds = State.PeriodSeconds.Value;
    if (!validationContext.BaseRound.NeedToChangeTerm(blockchainStartTimestamp, 
        validationContext.CurrentTermNumber, periodSeconds))
    {
        return new ValidationResult { Message = "Insufficient time elapsed for term change." };
    }

    return new ValidationResult { Success = true };
}
```

This ensures that the same time constraint logic used by honest nodes for behavior determination is also enforced during validation of all blocks.

## Proof of Concept

While a full integration test would require a complete AElf testnet setup, the vulnerability can be demonstrated by examining the validation pipeline:

1. Create a `NextTermInput` with:
   - Round number = current round + 1
   - Term number = current term + 1
   - All structural requirements met (proper miner information, etc.)

2. Call `NextTerm(input)` from a miner's account immediately after the current term starts (before `periodSeconds` has elapsed)

3. Observe that:
   - `PreCheck()` passes (miner is in miner list)
   - `ValidateBeforeExecution()` only adds `RoundTerminateValidationProvider`
   - `ValidationForNextTerm()` only checks structural correctness
   - No time validation occurs
   - Block is accepted and term changes prematurely

The core issue is the missing time check in the validation path, which can be verified by code inspection of the files cited above.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-203)
```csharp
        if (DonateMiningReward(previousRound))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L205-208)
```csharp
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```
