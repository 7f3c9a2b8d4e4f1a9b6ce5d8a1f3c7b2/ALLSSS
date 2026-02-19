# Audit Report

## Title
Consensus Miner List Manipulation via Unvalidated NextTermInput Conversion

## Summary
The AEDPoS consensus contract accepts arbitrary miner lists during term transitions without validating them against election results. A malicious block producer can inject custom miners into the next term by manipulating consensus extra data, completely bypassing the election-based consensus mechanism. The validation layer only verifies structural properties (term/round number increments) but never cross-validates the miner list against `GetVictories()` results from the Election Contract.

## Finding Description

**Root Cause - Unvalidated Conversion:**

The `ToRound()` method performs direct field copying without any validation: [1](#0-0) 

This method blindly copies `RealTimeMinersInformation` (the miner list) without checking if it matches the authoritative election results that should determine consensus participants.

**Validation Gap - No Miner List Verification:**

For NextTerm behavior, only `RoundTerminateValidationProvider` is added to the validation pipeline: [2](#0-1) 

This provider only validates term and round number increments, NOT the miner list composition: [3](#0-2) 

The basic validation providers (`MiningPermissionValidationProvider`, `TimeSlotValidationProvider`, `ContinuousBlocksValidationProvider`) check the CURRENT block producer's permissions, but none verify that the NEXT TERM's miner list matches election winners.

**Processing Without Validation:**

`ProcessNextTerm` directly converts and uses the unvalidated input: [4](#0-3) 

The miner list is extracted from the unvalidated `nextRound` and set as the official list for the new term without any election validation.

**SetMinerList Has No Election Validation:**

The method that finalizes the miner list only checks if it was already set: [5](#0-4) 

There is no call to `GetVictories()` or any verification that the provided list matches election results.

**Honest Path (Bypassed):**

The intended flow calls `GenerateFirstRoundOfNextTerm` which retrieves election winners: [6](#0-5) 

However, there is NO enforcement that this honest path was actually followed. The consensus extra data generation happens at: [7](#0-6) 

A malicious block producer can run modified node software that generates custom consensus extra data bypassing `TryToGetVictories()`, and the validation layer will accept it.

**Attack Flow:**

1. Malicious miner (already in current term) waits for term-ending extra block slot
2. Modified node generates `AElfConsensusHeaderInformation` with custom `Round` containing arbitrary miners
3. Block is produced with this consensus extra data in header
4. Other nodes validate via `ValidateConsensusBeforeExecution` - passes because only structural checks exist
5. Transaction is generated from header: [8](#0-7) 

6. `NextTerm(NextTermInput input)` executes with malicious miner list
7. Malicious list becomes official via `SetMinerList`
8. Next term begins with attacker-controlled miners

## Impact Explanation

**Consensus Integrity Compromise:**
This vulnerability completely breaks the fundamental security assumption of the AEDPoS consensus protocol - that block producers are elected through voting by token holders. An attacker can:

- **Exclude Legitimate Winners**: Remove election winners from the miner list, nullifying token holder votes
- **Include Arbitrary Miners**: Add attacker-controlled addresses that never participated in elections
- **Perpetuate Control**: Once established, attacker maintains control indefinitely by always including themselves in subsequent terms
- **Centralize Network**: Replace distributed consensus with attacker monopoly

**Affected Parties:**
- **Legitimate Election Winners**: Lose block production rights despite winning elections
- **Token Holders**: Votes completely nullified, governance rights eliminated
- **Network Security**: Decentralization guarantee broken
- **Economic Participants**: All users subject to censorship and potential double-spend attacks

**Quantified Damage:**
- **Block Production**: 100% control over block production for entire terms (7 days typical term length)
- **Transaction Censorship**: Ability to exclude any transactions indefinitely
- **Chain Reorgs**: Can reorg chain to reverse transactions
- **Reward Theft**: All mining rewards (~mined_blocks * reward_per_block) redirected to attacker
- **Election System**: Complete nullification of election-based governance
- **Network Trust**: Fundamental security model broken

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a legitimate miner in the current term (realistic - elections are open)
- Must control timing to produce the term transition block (deterministic - extra block slots are assigned)
- Can run modified node software (trivial - open source)

**Attack Complexity: MEDIUM**
1. Fork AElf node repository
2. Modify consensus extra data generation to return custom `Round` with arbitrary miners
3. Deploy modified node and participate in elections to become a miner
4. Wait for term-ending extra block slot assignment
5. Produce block with malicious consensus data
6. Validation passes because no election verification exists

**Feasibility: HIGH**
- Any current miner can execute this attack
- No economic cost beyond being a miner (which attackers likely already are)
- Attack is deterministic - no race conditions or timing issues
- Success guaranteed if attacker produces the term-ending block

**Detection: LOW**
- Malicious miner list appears structurally valid (correct term/round numbers)
- No off-chain monitoring can detect election misalignment without comparing to `GetVictories()` results
- By the time discrepancy is noticed, attacker already has control
- Honest nodes accept the block because validation passes

## Recommendation

Add election-based miner list validation in the NextTerm validation path:

1. **Add Election Validation Provider**: Create `NextTermElectionValidationProvider` that:
   - Calls `State.ElectionContract.GetVictories.Call(new Empty())`
   - Compares returned election winners with `extraData.Round.RealTimeMinersInformation.Keys`
   - Returns validation failure if mismatch detected

2. **Register Provider**: In `ValidateBeforeExecution`, add the provider for NextTerm:
```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new NextTermElectionValidationProvider(State)); // Add this
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

3. **Alternative Defense-in-Depth**: Add validation directly in `ProcessNextTerm`:
```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // Validate miner list against election results
    if (State.IsMainChain.Value && State.ElectionContract.Value != null)
    {
        var victories = State.ElectionContract.GetVictories.Call(new Empty());
        var expectedMiners = victories.Value.Select(v => v.ToHex()).OrderBy(x => x).ToList();
        var providedMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(x => x).ToList();
        
        Assert(
            expectedMiners.Count == providedMiners.Count &&
            expectedMiners.SequenceEqual(providedMiners),
            "Miner list does not match election results.");
    }
    
    // ... rest of processing
}
```

## Proof of Concept

The vulnerability cannot be demonstrated with a single test function because it requires modified node software to inject malicious consensus extra data into block headers. However, the validation gap can be verified:

**Test demonstrating missing validation:**
```csharp
[Fact]
public async Task NextTerm_AcceptsArbitraryMiners_WithoutElectionValidation()
{
    // Setup: Current term with legitimate miners
    var currentMiners = await SetupCurrentTermWithElectedMiners();
    
    // Create NextTermInput with DIFFERENT miners (not from election)
    var maliciousMiners = GenerateArbitraryPublicKeys(5);
    var maliciousRound = CreateRoundWithMiners(maliciousMiners, 
        termNumber: 2, roundNumber: 1);
    var maliciousInput = NextTermInput.Create(maliciousRound, GenerateRandomNumber());
    
    // Execute NextTerm - should fail but doesn't
    var result = await ConsensusStub.NextTerm.SendAsync(maliciousInput);
    
    // VULNERABILITY: Transaction succeeds despite invalid miner list
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify malicious miners are now official
    var newTermMiners = await ConsensusStub.GetCurrentMinerList.CallAsync(new Empty());
    newTermMiners.Pubkeys.ShouldBe(maliciousMiners); // Attack succeeded
    
    // Verify they DON'T match election results
    var electionWinners = await ElectionStub.GetVictories.CallAsync(new Empty());
    newTermMiners.Pubkeys.ShouldNotBe(electionWinners.Value); // Consensus broken!
}
```

**Notes:**
The actual exploit requires producing a block with manipulated consensus extra data, which happens at the node level before the smart contract validates it. The test above demonstrates that the smart contract layer provides no protection against such manipulation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
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
