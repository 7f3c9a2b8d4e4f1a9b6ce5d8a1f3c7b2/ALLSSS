### Title
Consensus Integrity: ActualMiningTime Injection Allows Miners to Manipulate Term Changes

### Summary
The `ProcessUpdateValue` function directly assigns `updateValueInput.ActualMiningTime` from transaction input without validation against the block header's consensus extra data. While `Signature`, `OutValue`, and `SupposedOrderOfNextRound` are validated via post-execution hash comparison, `ActualMiningTimes` are explicitly excluded from this validation, allowing malicious miners to inject arbitrary timestamps that can manipulate term changes and consensus timing.

### Finding Description

In `ProcessUpdateValue`, the function directly assigns input values without validation: [1](#0-0) 

The validation architecture has three stages:

1. **Pre-execution validation** (`ValidateBeforeExecution`) validates the block header's consensus extra data, which contains the Round information with `ActualMiningTime` set to `Context.CurrentBlockTime`: [2](#0-1) 

2. **Execution** processes the `UpdateValueInput` from the transaction, which may contain different values than the header.

3. **Post-execution validation** (`ValidateAfterExecution`) compares Round hashes, but explicitly excludes `ActualMiningTimes` from the hash calculation: [3](#0-2) 

The critical issue is at line 193 where `ActualMiningTimes.Clear()` removes these values from hash computation, meaning the post-execution hash comparison cannot detect if the transaction's `ActualMiningTime` differs from the header's value.

In contrast, `Signature`, `OutValue`, and `SupposedOrderOfNextRound` are **not** cleared and thus **are** validated via the hash comparison in `ValidateAfterExecution`: [4](#0-3) 

### Impact Explanation

The injected `ActualMiningTime` directly impacts the `NeedToChangeTerm` function, which determines when term changes occur: [5](#0-4) 

A malicious miner can:

1. **Trigger premature term changes** by injecting future timestamps that cross term boundaries, causing:
   - Unscheduled Treasury releases (losing time-locked funds control)
   - Premature Election snapshots (affecting voting power calculations)
   - Unexpected miner list updates (disrupting consensus stability)

2. **Delay term changes** by injecting past timestamps, preventing:
   - Treasury releases when expected
   - Timely election snapshots
   - Proper term transitions

3. **Corrupt consensus timing data**, as `ActualMiningTimes` represents the historical record of when blocks were actually produced, affecting round timing calculations and block production schedules.

Term changes trigger critical economic operations: [6](#0-5) 

**Severity**: High - Consensus integrity violation with direct economic impact on Treasury releases and election mechanics.

### Likelihood Explanation

**Attacker capabilities required:**
- Must be an active block-producing miner in the current miner list
- Must modify node software to inject different `ActualMiningTime` in `UpdateValueInput` transaction versus block header extra data
- Entry point is the public `UpdateValue` method

**Attack complexity:** Medium
- Requires custom node software modification
- The separation between header generation (`GetConsensusExtraData`) and transaction generation (`GenerateConsensusTransactions`) allows independent manipulation: [7](#0-6) 

**Feasibility:** High
- No cryptographic or economic barriers prevent this attack
- Validation mechanisms do not cross-check transaction input against header data for `ActualMiningTime`
- Attack is repeatable across multiple blocks by the same miner

**Detection:** Difficult - validators cannot detect the discrepancy without external time synchronization checks, as the blockchain only validates internal consistency via hash comparison which excludes `ActualMiningTimes`.

### Recommendation

**Immediate fix:** Add validation in `ProcessUpdateValue` to enforce that `ActualMiningTime` matches the block timestamp:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    
    // CRITICAL: Validate ActualMiningTime against Context.CurrentBlockTime
    Assert(updateValueInput.ActualMiningTime == Context.CurrentBlockTime,
        "ActualMiningTime must equal current block time.");
    
    minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
    // ... rest of function
}
```

**Alternative fix:** Include `ActualMiningTimes` in the post-execution hash validation by removing line 193 from `GetCheckableRound`, though this may require adjusting other validation logic.

**Test cases:**
1. Attempt to submit `UpdateValueInput` with `ActualMiningTime` ≠ `Context.CurrentBlockTime` → should fail
2. Verify term change timing cannot be manipulated by timestamp injection
3. Ensure legitimate tiny blocks with valid timestamps still process correctly

### Proof of Concept

**Initial state:**
- Miner M is in active miner list for current round
- Current term should change after 7 more seconds (based on `periodSeconds`)

**Attack sequence:**
1. Miner M modifies node software to intercept transaction generation
2. Block header extra data generated with valid `ActualMiningTime = Context.CurrentBlockTime` (T1)
3. UpdateValue transaction crafted with `ActualMiningTime = T1 + 8 seconds` (crossing term boundary)
4. Block submitted with inconsistent data

**Expected result:** Validation should fail due to timestamp mismatch

**Actual result:** 
- `ValidateBeforeExecution`: PASS (validates header with T1)
- `UpdateValue` executes: Stores T1 + 8 seconds to state
- `ValidateAfterExecution`: PASS (ActualMiningTimes excluded from hash at line 193)
- `NeedToChangeTerm` triggered prematurely: Term changes immediately instead of after 7 seconds
- Treasury release and Election snapshot occur ahead of schedule

**Success condition:** Premature term change confirmed by observing Treasury release and miner list update before expected time, demonstrating consensus timing manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-218)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-248)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-102)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L35-50)
```csharp
        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
            PreviousInValue = minerInRound.PreviousInValue ?? Hash.Empty,
            RoundId = RoundIdForValidation,
            ProducedBlocks = minerInRound.ProducedBlocks,
            ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
            TuneOrderInformation = { tuneOrderInformation },
            EncryptedPieces = { minerInRound.EncryptedPieces },
            DecryptedPieces = { decryptedPreviousInValues },
            MinersPreviousInValues = { minersPreviousInValues },
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
            RandomNumber = randomNumber
        };
```
