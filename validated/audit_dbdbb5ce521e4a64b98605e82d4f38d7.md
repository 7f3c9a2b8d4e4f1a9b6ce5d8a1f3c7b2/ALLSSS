# Audit Report

## Title
Insufficient Validation in SetMinerIncreaseInterval Allows Negative Values Leading to Complete Consensus Halt

## Summary
The `SetMinerIncreaseInterval()` function lacks lower bound validation, allowing negative values for `MinerIncreaseInterval`. This causes the miner count calculation to return large negative values, which propagate through the consensus system. The negative count causes LINQ's `.Take()` operation to return an empty miner list, resulting in a consensus round with zero miners and permanent blockchain halt.

## Finding Description

**Root Cause - Missing Validation:**

The `SetMinerIncreaseInterval()` function only validates that the new value does not exceed the current value, but fails to enforce a positive lower bound. [1](#0-0) 

This contrasts with `SetMaximumMinersCount()` which explicitly validates positive values. [2](#0-1) 

**Negative Value Calculation:**

When `GetMinersCount(Round)` executes with a negative `MinerIncreaseInterval`, it performs integer division with a negative divisor in the calculation formula. [3](#0-2) 

With `MinerIncreaseInterval = -1` and blockchain age of 100,000 seconds, the calculation becomes: `17 + (100000 / -1) * 2 = 17 - 200000 = -199,983`.

**Propagation to Election Contract:**

The negative miner count is sent to the Election contract via `UpdateMinersCount`. [4](#0-3) 

The Election contract stores this value without validation. [5](#0-4) 

**Critical LINQ Behavior Exploitation:**

When `GetVictories()` attempts to select miners, it uses LINQ's `.Take()` with the stored negative count. [6](#0-5) 

In C#, LINQ's `.Take(n)` with negative `n` returns an empty sequence, producing a `MinerList` with zero miners.

**Consensus Termination:**

The empty miner list is used to generate the next consensus round. [7](#0-6) 

With `sortedMiners.Count = 0`, the for loop never executes, creating a `Round` object with no miners in `RealTimeMinersInformation`. This round is then used in term transition. [8](#0-7) 

Since no miners exist in the round, no blocks can be produced, causing permanent consensus halt.

## Impact Explanation

**Complete Network Failure:**
The vulnerability causes total blockchain shutdown. With zero miners in the consensus round, block production permanently halts. All network participants (validators, users, dApps) are immediately affected.

**Unrecoverable State:**
Even governance cannot fix this through normal channels since executing governance proposals requires consensus. The system enters a deadlock requiring emergency node-level intervention or chain restart.

**Network-Wide Denial of Service:**
All blockchain operations cease: token transfers, smart contract executions, cross-chain messages, and governance actions become impossible. The impact manifests at the next term transition (typically hours after the parameter is set).

This represents a complete violation of the consensus protocol's fundamental invariant that the miner set must always contain at least one active miner.

## Likelihood Explanation

**Privilege Requirements:**
The function requires `MaximumMinersCountController` authority (default: Parliament's default organization). While this is a privileged role, the vulnerability represents a code defect - a validation gap that allows invalid state.

**Direct Invariant Break:**
This is a directly reachable invariant break where a single authorized call to `SetMinerIncreaseInterval(-1)` deterministically breaks the fundamental invariant that miner count must be positive. The validation gap represents mis-scoped privileges: Parliament should configure valid parameters, not break consensus.

**Code Defect Evidence:**
The codebase shows inconsistent validation - `SetMaximumMinersCount` validates `> 0`, but `SetMinerIncreaseInterval` only validates `<= current value`. This is a clear implementation defect, not a trust model issue.

**Execution Simplicity:**
Once authorization is obtained, exploitation requires only a single function call. The negative value persists in state and triggers failure at the next term transition.

## Recommendation

Add positive value validation to `SetMinerIncreaseInterval()`:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value > 0, "Miner increase interval must be positive.");
    Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
    State.MinerIncreaseInterval.Value = input.Value;
    return new Empty();
}
```

Additionally, add validation in `UpdateMinersCount()`:

```csharp
public override Empty UpdateMinersCount(UpdateMinersCountInput input)
{
    Assert(
        Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
        "Only consensus contract can update miners count.");
    Assert(input.MinersCount > 0, "Miners count must be positive.");
    State.MinersCount.Value = input.MinersCount;
    SyncSubsidyInfoAfterReduceMiner();
    return new Empty();
}
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Call `SetMinerIncreaseInterval` with value `-1` using Parliament authority
2. Advance blockchain time by a sufficient period
3. Trigger a term transition
4. Observe that `GetVictories()` returns an empty miner list
5. Verify that the generated round has zero miners in `RealTimeMinersInformation`
6. Confirm that no further blocks can be produced

The vulnerability manifests when the negative `MinerIncreaseInterval` is used in the division operation during miner count calculation, producing a large negative result that cascades through the system.

## Notes

This vulnerability demonstrates a critical validation gap in consensus parameter management. While Parliament is a trusted role, the missing validation allows accidental (or malicious) consensus breakage through a single parameter update. The inconsistency with other parameter validations (e.g., `SetMaximumMinersCount` validates `> 0`) indicates this is a code defect rather than an intentional trust assumption. The catastrophic and unrecoverable impact justifies treating this as a high-severity directly reachable invariant break despite the privilege requirement.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L56-64)
```csharp
    public override Empty SetMinerIncreaseInterval(Int64Value input)
    {
        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set miner increase interval.");
        Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
        State.MinerIncreaseInterval.Value = input.Value;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-61)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L149-160)
```csharp
    public override Empty UpdateMinersCount(UpdateMinersCountInput input)
    {
        Context.LogDebug(() =>
            $"Consensus Contract Address: {Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName)}");
        Context.LogDebug(() => $"Sender Address: {Context.Sender}");
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
            "Only consensus contract can update miners count.");
        State.MinersCount.Value = input.MinersCount;
        SyncSubsidyInfoAfterReduceMiner();
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-84)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L12-45)
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
    }
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
