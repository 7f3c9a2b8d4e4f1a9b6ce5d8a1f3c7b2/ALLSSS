### Title
Missing LIB Height Validation in NextTerm Consensus Behavior Enables Consensus DoS Attack

### Summary
A malicious miner can inject a negative `ConfirmedIrreversibleBlockHeight` value during term transitions due to missing `LibInformationValidationProvider` validation for `NextTerm` behavior. This causes the blockchain to immediately enter Severe mining status, reducing block production to 1 block per round and effectively DoS'ing the consensus mechanism.

### Finding Description

**Root Cause:**

The `NextTermInput.Create()` method directly copies `ConfirmedIrreversibleBlockHeight` from the provided Round parameter without any validation: [1](#0-0) 

The `ConfirmedIrreversibleBlockHeight` field is defined as `int64` in the protobuf schema, allowing negative values: [2](#0-1) 

**Missing Validation:**

In `ValidateBeforeExecution`, the `LibInformationValidationProvider` (which validates LIB height monotonicity) is **only** applied to `UpdateValue` behavior, NOT to `NextTerm`: [3](#0-2) 

For `NextTerm` behavior, only `RoundTerminateValidationProvider` is applied, which validates term/round numbers but NOT LIB heights: [4](#0-3) 

**Attack Execution Path:**

1. A malicious miner generates consensus extra data for `NextTerm` with manipulated Round containing negative `ConfirmedIrreversibleBlockHeight` (e.g., -1,000,000) and `ConfirmedIrreversibleBlockRoundNumber` (e.g., -100)

2. The consensus extra data passes validation since `LibInformationValidationProvider` is not applied

3. The `NextTerm` method calls `ProcessConsensusInformation` → `ProcessNextTerm`: [5](#0-4) 

4. `ProcessNextTerm` converts the input to Round and stores it via `AddRoundInformation` without validation: [6](#0-5) 

5. The malicious values are persisted in state: [7](#0-6) 

### Impact Explanation

**Consensus DoS Attack:**

Once the negative `ConfirmedIrreversibleBlockHeight` is stored, subsequent calls to `GetMaximumBlocksCount()` read this malicious value: [8](#0-7) 

The `BlockchainMiningStatusEvaluator` uses `libRoundNumber` (now negative) in status calculation. With `libRoundNumber = -100` and `currentRoundNumber = 100` (example):

- Line 127 check: `100 >= -100 + 8` evaluates to `100 >= -92` = TRUE
- Blockchain enters **Severe** status [9](#0-8) 

In Severe status, mining is restricted to **1 block per round**: [10](#0-9) 

**Concrete Harm:**
- **Operational Impact**: Blockchain throughput reduced to ~1 block per round (severe performance degradation)
- **Network DoS**: `IrreversibleBlockHeightUnacceptable` events fired continuously
- **Consensus Integrity**: Chain appears in abnormal state despite being functional
- **Recovery**: Requires majority miner coordination to transition to next term with valid values

**Affected Parties:** All network participants experience degraded performance until next term transition.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a current miner (in the active miner list)
- Can generate and broadcast consensus blocks

**Attack Complexity:** Low
- Attacker modifies consensus extra data generation during term transition
- Single malicious block during term transition achieves persistent DoS
- No complex state manipulation or timing requirements needed

**Feasibility Conditions:**
- Attack window: Any term transition (occurs regularly based on term configuration)
- Detection: Post-exploit via monitoring mining status, but no pre-validation
- The comment in code references a non-existent `ConstrainedAEDPoSTransactionValidationProvider`: [11](#0-10) 

This suggests the protection was intended but never implemented.

**Economic Rationality:**
- Attack cost: Normal block production cost (attacker is already a miner)
- Attack benefit: Severe network disruption, competitive advantage if attacker operates alternative infrastructure
- Low cost, high impact = economically rational for adversarial miners

**Probability Assessment:** HIGH - The attack requires only miner privileges (which multiple parties have), has simple execution, and guaranteed impact.

### Recommendation

**Immediate Fix:**

Add `LibInformationValidationProvider` to the validation providers for `NextTerm` behavior in `AEDPoSContract_Validation.cs`:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
``` [12](#0-11) 

**Additional Hardening:**

Add explicit validation in `NextTermInput.Create()` to reject invalid LIB values:

```csharp
public static NextTermInput Create(Round round, ByteString randomNumber)
{
    Assert(round.ConfirmedIrreversibleBlockHeight >= 0, 
           "Invalid ConfirmedIrreversibleBlockHeight");
    Assert(round.ConfirmedIrreversibleBlockRoundNumber >= 0, 
           "Invalid ConfirmedIrreversibleBlockRoundNumber");
    // ... rest of method
}
```

**Test Cases:**

1. Test `NextTerm` validation rejects Round with negative `ConfirmedIrreversibleBlockHeight`
2. Test `NextTerm` validation rejects Round with `ConfirmedIrreversibleBlockHeight` lower than current round
3. Test `GetMaximumBlocksCount` behavior with edge case LIB values (0, negative, very large)

### Proof of Concept

**Initial State:**
- Blockchain at height 100,000, current term number 10, round number 500
- Current round has `ConfirmedIrreversibleBlockHeight = 99,000` and `ConfirmedIrreversibleBlockRoundNumber = 495`
- Attacker is a current miner in the active miner list

**Attack Steps:**

1. **Attacker waits for term transition trigger**
   - Normal consensus determines term should transition from term 10 to term 11

2. **Attacker generates malicious consensus extra data**
   - Calls `GetConsensusExtraDataForNextTerm` to generate base Round
   - Modifies the generated Round in consensus extra data:
     - `ConfirmedIrreversibleBlockHeight = -1,000,000`
     - `ConfirmedIrreversibleBlockRoundNumber = -100`
     - Other fields (term number, round number, miner list) remain valid

3. **Attacker proposes block with malicious consensus data**
   - Block includes proper `NextTerm` transaction generated from consensus extra data
   - Block signature is valid (attacker is legitimate miner)

4. **Block validation occurs:**
   - `ValidateBeforeExecution` is called with consensus extra data
   - Only `RoundTerminateValidationProvider` runs (validates term 11 = term 10 + 1 ✓)
   - `LibInformationValidationProvider` NOT applied for NextTerm
   - Validation PASSES ✗ (vulnerability exploited)

5. **Block execution stores malicious values:**
   - `NextTerm` → `ProcessNextTerm` → `AddRoundInformation`
   - State now contains: current round with `ConfirmedIrreversibleBlockHeight = -1,000,000`

6. **Subsequent blocks trigger DoS:**
   - Any miner calls `GetMaximumBlocksCount`
   - Reads `libRoundNumber = -100`, `currentRoundNumber = 501`
   - Check: `501 >= -100 + 8` → `501 >= -92` → TRUE
   - Returns `BlockchainMiningStatus.Severe`
   - Mining restricted to 1 block per round
   - `IrreversibleBlockHeightUnacceptable` event fired

**Expected vs Actual Result:**
- **Expected**: Validation rejects negative LIB height, attacker's block is invalid
- **Actual**: Validation passes, malicious values stored, consensus enters Severe DoS state

**Success Condition:** 
Network mining throughput drops to ~1 block per round, persisting until next term transition with valid values. Observable via monitoring `GetMaximumBlocksCount()` return value (1 instead of normal 8) and `IrreversibleBlockHeightUnacceptable` events.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** protobuf/aedpos_contract.proto (L256-257)
```text
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L322-325)
```csharp

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-106)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L24-28)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L57-67)
```csharp
        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```
