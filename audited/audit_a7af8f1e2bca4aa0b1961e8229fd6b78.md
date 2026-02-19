### Title
NextTerm Miner List Injection - Arbitrary Consensus Takeover via Unvalidated RealTimeMinersInformation Keys

### Summary
The `ProcessNextTerm` function extracts miner public keys directly from `NextTermInput.RealTimeMinersInformation` without validating them against the Election Contract's `GetVictories` result. A malicious current-term miner can modify the consensus extra data in their NextTerm block to inject arbitrary miner keys, completely bypassing the election system and taking over the consensus mechanism.

### Finding Description

**Root Cause:**

The vulnerability exists in the NextTerm execution flow where miner keys from the consensus block header are blindly accepted without cross-validation against the Election Contract. [1](#0-0) 

The `ToRound()` function simply copies `RealTimeMinersInformation` without validation. [2](#0-1) 

In `ProcessNextTerm`, at lines 163 and 188-190, the function extracts miner keys directly from the converted Round object and passes them to `SetMinerList` with no verification against the Election Contract's authorized miner list. [3](#0-2) 

`SetMinerList` only validates whether the miner list for this term was previously set (`minerListFromState == null`). It performs NO validation of:
- Key validity or format
- Correspondence with Election Contract victories
- Miner authorization or eligibility

**Validation Gaps:** [4](#0-3) 

The pre-execution validation for NextTerm only checks round number and term number increments. No miner key validation occurs. [5](#0-4) 

The validation system for NextTerm behavior adds only `RoundTerminateValidationProvider`, which lacks any Election Contract cross-reference.

**Correct vs. Exploitable Flow:**

The intended design calls `TryToGetVictories` to retrieve legitimate miners from the Election Contract when generating consensus extra data: [6](#0-5) 

However, this is only executed during consensus extra data GENERATION (by the block producer), not during VALIDATION (by all nodes). A malicious miner can:
1. Receive correct data from their local contract call
2. Modify the `RealTimeMinersInformation` dictionary before inserting it into the block header
3. Produce and sign the block with tampered miner keys [7](#0-6) 

When other nodes execute the block, `GenerateConsensusTransactions` creates the NextTerm transaction from the (tampered) header data, and `ProcessNextTerm` blindly accepts these keys.

### Impact Explanation

**Consensus Integrity Compromise:**
- Complete takeover of the block producer selection mechanism
- Attacker can make themselves and accomplices the exclusive miner set indefinitely
- Legitimate election winners are bypassed entirely
- All consensus security guarantees are voided

**Affected Parties:**
- All token holders whose votes are nullified
- Legitimate election winners who are excluded from consensus
- The entire network security model collapses
- DApp users relying on consensus integrity

**Severity Justification:**
This is a CRITICAL consensus-layer vulnerability that completely undermines the delegated proof-of-stake election system. The attacker gains permanent control over block production, enabling secondary attacks like:
- Censoring transactions from competitors
- Manipulating treasury distributions
- Double-spending through chain reorganization control
- Governance attack via controlling proposal execution timing

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a current-term miner (to produce NextTerm block during their time slot)
- Requires no special privileges beyond normal mining rights
- Can execute during any term transition

**Attack Complexity:**
- LOW - Only requires modifying consensus header data before block production
- No complex cryptographic operations or timing races needed
- Single block production achieves full compromise

**Feasibility Conditions:**
- Any current miner can execute during their NextTerm block slot
- Term transitions occur regularly (every period_seconds, typically 7 days on mainchain)
- High-value target with frequent opportunity windows

**Detection Constraints:**
- Post-execution validation compares header vs. state that was just updated FROM the header (circular validation) [8](#0-7) 

The hash comparison at lines 100-101 will match because state was updated from the malicious header, making the after-execution validation ineffective.

- Off-chain monitoring could detect mismatch between Election Contract state and actual miner list, but by then the malicious list is already set and accepted by all nodes

**Probability Assessment:**
HIGH - Any miner with basic technical capability can execute this attack during their designated NextTerm block production slot. The regular occurrence of term transitions provides multiple opportunities.

### Recommendation

**Immediate Mitigation:**

Add Election Contract cross-validation in `ProcessNextTerm` before calling `SetMinerList`:

```csharp
// After line 163 in ProcessNextTerm
var nextRound = input.ToRound();

// ADD VALIDATION HERE:
if (State.IsMainChain.Value)
{
    var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
    var expectedKeys = new HashSet<string>(expectedVictories.Value.Select(pk => pk.ToHex()));
    var providedKeys = new HashSet<string>(nextRound.RealTimeMinersInformation.Keys);
    
    Assert(
        expectedKeys.SetEquals(providedKeys),
        $"Miner list mismatch. Expected: {string.Join(",", expectedKeys.OrderBy(x => x))}, " +
        $"Provided: {string.Join(",", providedKeys.OrderBy(x => x))}"
    );
}
```

**Alternative Enhancement:**

Strengthen pre-execution validation by adding miner list verification to `RoundTerminateValidationProvider`:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;
    
    // Existing term number check...
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // ADD: Validate miner list against Election Contract
    if (validationContext.IsMainChain)
    {
        var victories = GetElectionVictories(); // Call Election Contract
        var expectedKeys = victories.Value.Select(pk => pk.ToHex()).OrderBy(x => x).ToList();
        var providedKeys = extraData.Round.RealTimeMinersInformation.Keys.OrderBy(x => x).ToList();
        
        if (!expectedKeys.SequenceEqual(providedKeys))
            return new ValidationResult { 
                Message = "NextTerm miner list does not match Election Contract victories" 
            };
    }
    
    return new ValidationResult { Success = true };
}
```

**Test Cases Required:**
1. NextTerm with tampered miner list should fail validation
2. NextTerm with correctly ordered but wrong miners should fail
3. NextTerm with additional unauthorized miners should fail  
4. NextTerm with missing legitimate miners should fail
5. Valid NextTerm with exact Election Contract matches should succeed

### Proof of Concept

**Initial State:**
- Current term T with legitimate miners M1, M2, M3
- Election Contract has determined winners for term T+1: W1, W2, W3
- Attacker is M1 (current legitimate miner)

**Attack Sequence:**

1. **M1's NextTerm Block Slot Arrives:**
   - M1 calls `GetConsensusCommand` → receives `AElfConsensusBehaviour.NextTerm`
   - M1 calls `GetConsensusExtraData` with NextTerm trigger
   - Contract returns consensus header with legitimate winners {W1, W2, W3}

2. **M1 Tampers with Consensus Extra Data:**
   ```
   Original: RealTimeMinersInformation.Keys = {W1, W2, W3}
   Modified: RealTimeMinersInformation.Keys = {M1, Accomplice1, Accomplice2}
   ```
   - M1 modifies the Round object's RealTimeMinersInformation dictionary
   - M1 produces block with tampered header and signs it

3. **Honest Nodes Validate Block:**
   - `ValidateConsensusBeforeExecution` runs `RoundTerminateValidationProvider`
   - Checks: round_number = current + 1 ✓, term_number = current + 1 ✓, InValues = null ✓
   - **NO check against Election Contract** → Validation PASSES

4. **Block Execution:**
   - `GenerateConsensusTransactions` creates NextTermInput from tampered header
   - `ProcessNextTerm(NextTermInput)` executes
   - Line 163: `nextRound.RealTimeMinersInformation.Keys` = {M1, Accomplice1, Accomplice2}
   - Line 190: `SetMinerList` called with attacker-controlled list
   - `SetMinerList` checks only `State.MinerListMap[T+1] == null` ✓ → SUCCEEDS
   - State now has: `MinerListMap[T+1]` = {M1, Accomplice1, Accomplice2}

5. **Post-Execution Validation:**
   - `ValidateConsensusAfterExecution` compares header.Round vs. currentRound
   - Both contain {M1, Accomplice1, Accomplice2} because state was just updated → PASSES

**Expected Result:**
NextTerm block should be REJECTED with "Miner list does not match Election Contract"

**Actual Result:**
NextTerm block is ACCEPTED, attacker-controlled miner list becomes official for term T+1

**Success Condition:**
```
assert State.MinerListMap[T+1].Pubkeys == {M1, Accomplice1, Accomplice2}
assert ElectionContract.GetVictories() == {W1, W2, W3}
// Mismatch proves bypass of election system
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-257)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }

        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;

        newRound.BlockchainAge = GetBlockchainAge();

        if (newRound.RealTimeMinersInformation.ContainsKey(senderPubkey))
            newRound.RealTimeMinersInformation[senderPubkey].ProducedBlocks = 1;
        else
            UpdateCandidateInformation(senderPubkey, 1, 0);

        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;

        return newRound;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
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
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L172-179)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
```
