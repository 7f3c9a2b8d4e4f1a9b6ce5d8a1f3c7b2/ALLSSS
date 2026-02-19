### Title
Missing LIB Round Number Validation Allows Consensus State Corruption in NextTerm/NextRound Operations

### Summary
The AEDPoS consensus contract fails to validate that `ConfirmedIrreversibleBlockRoundNumber` is less than the current `RoundNumber` when processing `NextTerm` and `NextRound` operations. A malicious miner can inject a round where the Last Irreversible Block (LIB) round number exceeds or equals the current round number, creating a logical impossibility that corrupts consensus state permanently.

### Finding Description

The vulnerability exists in the validation flow for consensus round transitions. When a miner produces a block triggering a `NextTerm` or `NextRound`, they provide round information including `ConfirmedIrreversibleBlockRoundNumber` and `RoundNumber`.

**Root Cause:**

The validation logic only applies `LibInformationValidationProvider` to `UpdateValue` behavior, not to `NextRound` or `NextTerm` behaviors: [1](#0-0) 

The `LibInformationValidationProvider` only checks that LIB information doesn't go backwards, but never validates that `ConfirmedIrreversibleBlockRoundNumber < RoundNumber`: [2](#0-1) 

For `NextTerm`, only `RoundTerminateValidationProvider` is used, which validates round number, term number, and inValues, but not LIB constraints: [3](#0-2) 

**Attack Path:**

1. Malicious miner is scheduled to produce a block for `NextTerm` or `NextRound`
2. Miner crafts a malicious input with:
   - `RoundNumber = currentRound.RoundNumber + 1` (valid)
   - `ConfirmedIrreversibleBlockRoundNumber >= RoundNumber` (malicious)
3. Validation passes because LIB constraints are not checked
4. `ProcessNextTerm` or `ProcessNextRound` stores the corrupted round via `AddRoundInformation` [4](#0-3) 

5. The corrupted state persists because future rounds copy these values: [5](#0-4) 

### Impact Explanation

**Consensus State Corruption:**
The blockchain's consensus state will contain an impossible condition where the confirmed irreversible block's round number is greater than or equal to the current round number. This violates the fundamental invariant that LIB always lags behind the current round.

**Persistent Corruption:**
Once injected, the corrupted values propagate to all subsequent rounds since `GenerateNextRoundInformation` copies these values without validation. The corruption becomes permanent in the consensus state.

**Mining Status Miscalculation:**
The `BlockchainMiningStatusEvaluator` uses these values to determine mining health status: [6](#0-5) [7](#0-6) 

With corrupted LIB round numbers, the status evaluation logic fails, potentially causing incorrect restrictions on block production or failure to detect actual mining abnormalities.

**Cross-Chain Impact:**
LIB information is critical for cross-chain operations. Corrupted LIB round numbers could affect side-chain synchronization and cross-chain transaction verification that depend on consensus finality.

**Severity:** HIGH - Corrupts critical consensus invariants with permanent, system-wide effects.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires being an active miner in the current miner list
- Must wait for their scheduled time slot to produce a `NextTerm` or `NextRound` block
- No additional privileges beyond standard miner permissions required

**Attack Complexity:**
- Low complexity: Simply craft a malicious `NextTermInput` or `NextRoundInput` with invalid LIB values
- The attack is a single transaction during the attacker's mining turn
- No need to coordinate with other miners or exploit timing windows

**Feasibility:**
- Execution is straightforward given miner status
- No economic cost beyond normal mining operations
- Attack succeeds immediately upon block acceptance
- Detection is difficult as the corruption doesn't cause immediate failures

**Probability:** MEDIUM-HIGH
While requiring miner status limits the attacker pool, miners regularly produce NextTerm and NextRound blocks, providing frequent opportunities. A compromised or malicious miner can execute this attack with certainty during their turn.

### Recommendation

**Immediate Fix:**
Add `LibInformationValidationProvider` to both `NextRound` and `NextTerm` validation chains:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

**Enhanced Validation:**
Extend `LibInformationValidationProvider` to explicitly validate the critical invariant:

```csharp
// Add to LibInformationValidationProvider.ValidateHeaderInformation()
if (providedRound.ConfirmedIrreversibleBlockRoundNumber >= providedRound.RoundNumber)
{
    validationResult.Message = "LIB round number cannot be >= current round number.";
    return validationResult;
}
```

**Test Cases:**
1. Attempt `NextTerm` with `ConfirmedIrreversibleBlockRoundNumber == RoundNumber` → Should FAIL
2. Attempt `NextTerm` with `ConfirmedIrreversibleBlockRoundNumber > RoundNumber` → Should FAIL
3. Attempt `NextRound` with invalid LIB values → Should FAIL
4. Verify legitimate transitions with valid LIB values → Should SUCCEED

### Proof of Concept

**Initial State:**
- Current round: `RoundNumber = 100`, `TermNumber = 5`, `ConfirmedIrreversibleBlockRoundNumber = 98`
- Attacker is a valid miner in the miner list

**Attack Steps:**

1. Wait for turn to produce NextTerm block
2. Craft malicious `NextTermInput`:
   ```
   RoundNumber: 101 (valid increment)
   TermNumber: 6 (valid increment)
   ConfirmedIrreversibleBlockRoundNumber: 101 (MALICIOUS - equals RoundNumber)
   ConfirmedIrreversibleBlockHeight: <any valid height>
   [other required fields populated correctly]
   ```

3. Submit transaction: `NextTerm(maliciousInput)`

4. Block is validated via `ValidateBeforeExecution`:
   - `RoundTerminateValidationProvider` checks pass (round/term numbers are correct)
   - `LibInformationValidationProvider` NOT executed for NextTerm
   - Validation succeeds ✓

5. `ProcessNextTerm` executes and stores corrupted round via `AddRoundInformation`

**Expected vs Actual Result:**

**Expected:** Transaction should FAIL with "Invalid LIB round number" error

**Actual:** Transaction SUCCEEDS, consensus state now has:
- `RoundNumber = 101`
- `ConfirmedIrreversibleBlockRoundNumber = 101` (INVALID - should be < 101)

**Success Condition:**
Query `GetCurrentRoundInformation()` and observe `ConfirmedIrreversibleBlockRoundNumber >= RoundNumber`, proving the logical invariant violation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-92)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L35-37)
```csharp
        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L119-129)
```csharp
        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
        }
```
