# Audit Report

## Title
Missing NeedToChangeTerm Validation Allows Premature Term Termination in AEDPoS Consensus

## Summary
The AEDPoS consensus contract's `NextTerm` method lacks time-based validation during transaction execution, allowing any active miner to prematurely terminate a consensus term by directly invoking `NextTerm` even when the protocol's time threshold requirements are not met. This bypasses the intended `NeedToChangeTerm` check that should enforce two-thirds miner consensus on term changes based on elapsed blockchain time.

## Finding Description

The vulnerability exists in the separation between consensus behavior selection and transaction execution validation.

**Normal Flow**: During block production, the `MainChainConsensusBehaviourProvider` determines whether to use `NextRound` or `NextTerm` by calling `NeedToChangeTerm`, which verifies that at least two-thirds of miners' latest mining times indicate the time threshold has been reached [1](#0-0) . The `NeedToChangeTerm` method checks if sufficient miners agree based on blockchain age [2](#0-1)  using a two-thirds threshold [3](#0-2) .

**Vulnerability**: The `NextTerm` method is publicly accessible [4](#0-3) , allowing any miner to call it directly via transaction. During execution, `ProcessConsensusInformation` only performs basic checks [5](#0-4) :

1. The `PreCheck` method only verifies the caller is in the current or previous miner list [6](#0-5) 
2. For `NextTerm` behavior, validation only adds `RoundTerminateValidationProvider` [7](#0-6) 
3. `RoundTerminateValidationProvider` only validates structural correctness: round number increments by 1, term number increments by 1, and InValues are null [8](#0-7) 

**Critically**, there is NO re-validation of the `NeedToChangeTerm` condition during transaction execution. The `TryToUpdateTermNumber` method only checks that term number increments by 1 [9](#0-8) , with no time-based validation.

A malicious miner can construct a valid `NextTermInput` with `term number = current + 1` and `round number = current + 1`, and call `NextTerm` directly. The transaction will pass all validations and execute `ProcessNextTerm` [10](#0-9) , which:
- Updates term and round numbers
- Resets miner statistics (missed time slots, produced blocks to zero)
- Updates the miner list
- Donates mining rewards to treasury
- Triggers treasury release for the wrong period
- Takes an election snapshot prematurely

## Impact Explanation

This vulnerability has **HIGH** severity impact across multiple protocol subsystems:

1. **Consensus Integrity Breach**: The fundamental invariant that terms change only when time thresholds are met and two-thirds of miners agree is violated, undermining the protocol's time-based consensus security model.

2. **Economic Disruption**: Mining rewards are donated and treasury releases are triggered at incorrect times [11](#0-10) , causing fund distributions to occur out of sync with the intended economic schedule.

3. **Governance Manipulation**: Election snapshots are captured prematurely [12](#0-11) , potentially affecting validator selection and voting power calculations for subsequent terms.

4. **Miner Schedule Disruption**: The miner list is updated before the intended rotation time [13](#0-12) , disrupting block production schedules and potentially enabling colluding miners to extend their control.

5. **Statistical Manipulation**: Performance metrics are reset early [14](#0-13) , potentially masking poor miner performance or manipulating reputation-based mechanisms.

## Likelihood Explanation

The vulnerability has **HIGH** likelihood of exploitation:

**Attacker Profile**: Any miner in the current or previous miner list can execute this attack, which represents a significant portion of network participants in a decentralized consensus system.

**Technical Complexity**: **LOW** - The attacker only needs to:
1. Construct a `NextTermInput` with `TermNumber = current + 1` and `RoundNumber = current + 1`
2. Submit a transaction calling the public `NextTerm` method
3. Provide a valid random number proof (which they can generate as an active miner)

**Preconditions**: Minimal - The attacker must be an active or recently active miner (realistic in any functional consensus network), with no additional privileges required.

**Economic Incentives**: Strong motivation exists for attackers to:
- Gain extended mining time if they're in the next term's miner list
- Disrupt competitors by resetting their performance statistics
- Manipulate treasury release timing for financial advantage  
- Influence governance outcomes through premature election snapshots

**Detection vs Prevention**: While premature term changes are visible on-chain, the attack could occur during low-monitoring periods and may not be immediately reversible, causing lasting damage to consensus integrity.

## Recommendation

Add time-based validation during transaction execution by re-checking the `NeedToChangeTerm` condition in the validation flow:

1. Create a new validation provider `TermChangeTimeValidationProvider` that verifies the time threshold has been reached
2. Add this provider to the validation list for `NextTerm` behavior alongside `RoundTerminateValidationProvider`
3. The provider should call `NeedToChangeTerm` with current blockchain start timestamp, term number, and period seconds
4. Reject the transaction if `NeedToChangeTerm` returns false

Alternatively, modify `RoundTerminateValidationProvider.ValidationForNextTerm` to include the time-based check by accessing blockchain state to verify the time conditions are met before allowing term transitions.

This ensures the critical invariant that terms only change when the protocol's time-based consensus rules are satisfied is enforced at the transaction execution layer, not just during off-chain consensus command generation.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploy the AEDPoS consensus contract on a test network with multiple miners
2. Query current term number and round number from contract state
3. As an active miner, construct a `NextTermInput` with:
   - `TermNumber = current_term + 1`
   - `RoundNumber = current_round + 1`  
   - Valid random number proof
   - Appropriate round structure (InValues null, miner information populated)
4. Call `NextTerm` method directly via transaction **before** the time threshold would normally trigger term change
5. Observe that:
   - Transaction succeeds despite `NeedToChangeTerm` condition not being met
   - Term number is incremented prematurely
   - Miner statistics are reset
   - Treasury operations execute at wrong time
   - Election snapshot is captured prematurely

The test should verify that a direct `NextTerm` call succeeds even when the elapsed time since blockchain start is insufficient for the configured period, violating the two-thirds miner time-based consensus requirement that should gate term transitions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-35)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-28)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
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

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
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

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
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
