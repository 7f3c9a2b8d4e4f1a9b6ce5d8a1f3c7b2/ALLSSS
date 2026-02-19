### Title
Missing Miner List Validation in NextTerm Allows Malicious Miner to Monopolize Block Production

### Summary
The `NextTerm` function accepts an arbitrary miner list in `NextTermInput` without validating it against the Election Contract's `GetVictories()` result. A malicious miner can submit a term transition with only themselves in `RealTimeMinersInformation`, reducing the count to 1, which bypasses the continuous blocks validation and enables unlimited block production and transaction censorship.

### Finding Description

The vulnerability exists in the term transition validation and processing flow:

**Validation Gap**: The `ValidationForNextTerm` method only validates round/term number increments and null InValues, but does NOT validate that the provided miner list matches the elected miners from the Election Contract. [1](#0-0) 

**Unvalidated Processing**: The `ProcessNextTerm` method extracts the miner list directly from the input and calls `SetMinerList` without any validation against `GetVictories()`. [2](#0-1) 

**SetMinerList Accepts Without Validation**: The `SetMinerList` method only checks if the miner list was already set for the term, but performs no validation of the miner list content or legitimacy. [3](#0-2) 

**Continuous Blocks Bypass**: When `RealTimeMinersInformation.Count == 1`, the continuous blocks validation is completely bypassed, allowing unlimited consecutive block production. [4](#0-3) 

**Attack Path**: A current miner can call `NextTerm` (authorized by `PreCheck`) with a fabricated `NextTermInput` containing only their own pubkey in `RealTimeMinersInformation`. The system accepts this fraudulent miner list, establishing them as the sole miner for the entire term. [5](#0-4) 

### Impact Explanation

**Consensus Integrity Violation**: The attacker gains complete control over block production for an entire term, violating the fundamental security assumption that consensus requires multiple independent validators.

**Transaction Censorship**: With sole mining authority, the attacker can permanently censor any transactions, including:
- Governance proposals attempting to fix the issue
- Election votes that could change the miner set
- Any user transactions the attacker wishes to block

**Economic Damage**: The attacker captures 100% of mining rewards for the term while legitimate miners receive nothing, directly stealing value from other validators.

**Exclusion of Legitimate Miners**: All honestly elected miners are removed from the consensus process and cannot produce blocks or earn rewards, despite having been legitimately elected through the voting process.

**Permanent Until Next Term**: This attack persists until the next term transition, which the attacker controls. They can repeatedly submit fraudulent `NextTerm` transactions to maintain their monopoly indefinitely.

### Likelihood Explanation

**Reachable Entry Point**: Any current miner can call the public `NextTerm` method during term transition windows. [6](#0-5) 

**Feasible Preconditions**: 
- Attacker must be one of the current miners (realistic for any compromised or malicious validator)
- Attack executes during the natural term transition timing
- No special privileges beyond normal miner status required

**Low Attack Complexity**: 
1. Wait for term transition condition
2. Submit `NextTerm` transaction with modified `NextTermInput` containing only attacker's pubkey
3. System accepts due to missing validation
4. Attacker becomes sole miner

**No Detection Mechanisms**: The validation logic has no checks to detect or prevent this attack. Honest nodes will accept the malicious block as valid since it passes all implemented validation checks.

**Economic Rationality**: The attack cost is minimal (one transaction), while the benefit is capturing 100% of mining rewards and complete network control.

### Recommendation

**Add Miner List Validation**: Implement validation in `ValidationForNextTerm` or `ProcessNextTerm` to verify the provided miner list matches the Election Contract's current election results:

```csharp
// In ProcessNextTerm or new validation provider
if (State.IsMainChain.Value && State.ElectionContract.Value != null)
{
    var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
    var providedMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    var expectedMiners = expectedVictories.Value.Select(v => v.ToHex()).OrderBy(k => k).ToList();
    
    Assert(providedMiners.SequenceEqual(expectedMiners), 
        "Provided miner list does not match election results");
}
```

**Add Cross-Check in SetMinerList**: Validate against `GetVictories()` before accepting any miner list update: [7](#0-6) 

**Test Cases**: Add tests that verify:
1. NextTerm with incorrect miner list is rejected
2. NextTerm with subset of elected miners is rejected  
3. NextTerm with additional non-elected miners is rejected
4. Only NextTerm matching exact GetVictories() result is accepted

### Proof of Concept

**Initial State**:
- Current term has 5 legitimately elected miners: [M1, M2, M3, M4, M5]
- Attacker controls M1
- Election Contract has new election results ready for next term

**Attack Sequence**:

1. **Term Transition Time Reached**: System signals it's time for NextTerm based on blockchain age

2. **Attacker Generates Fraudulent NextTermInput**:
   - Call `GenerateFirstRoundOfNextTerm` locally with modified logic
   - Create `NextTermInput` with `RealTimeMinersInformation` containing only M1's pubkey
   - Set proper term/round numbers (current + 1)
   - Set all InValues to null

3. **Submit NextTerm Transaction**:
   - M1 calls `NextTerm(fraudulentInput)`
   - `PreCheck` passes: M1 is in current miner list
   - `ValidateBeforeExecution` passes: `RoundTerminateValidationProvider` only checks term/round numbers
   - `ProcessNextTerm` executes: extracts miner list from input without validation
   - New round stored with `RealTimeMinersInformation.Count = 1`

4. **Exploit Continuous Blocks Bypass**:
   - For all subsequent blocks in the new term
   - `ContinuousBlocksValidationProvider` checks: `Count != 1` evaluates to false
   - Validation bypassed, M1 can produce unlimited consecutive blocks
   - M1 censors any transactions attempting to fix the issue

**Expected Result**: NextTerm should be rejected due to miner list mismatch with Election Contract

**Actual Result**: NextTerm accepted, M1 becomes sole miner, can produce unlimited blocks and censor all transactions

**Success Condition**: After attack, `State.CurrentRoundInformation.RealTimeMinersInformation.Count == 1` and attacker produces 100+ consecutive blocks without validation failure

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-190)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-24)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
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
