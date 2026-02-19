### Title
Missing LIB Height Validation During NextTerm Transition Enables Chain Reorganization

### Summary
The AEDPoS consensus contract lacks validation to prevent Last Irreversible Block (LIB) height rollback during term transitions. While `UpdateValue` operations validate that LIB height never decreases, `NextTerm` operations do not perform this critical check. A malicious miner scheduled to produce the NextTerm block can include stale consensus data with a lower LIB height, effectively un-finalizing previously confirmed blocks and breaking the blockchain's finality guarantees.

### Finding Description

**Code Locations:**

The vulnerability exists in the interaction between multiple files:

1. **LIB Height Preservation Without Validation**: In `GenerateFirstRoundOfNextTerm()`, the function directly copies the LIB height from the current round to the new term's first round without any validation. [1](#0-0) 

2. **Missing Validation for NextTerm**: The validation logic explicitly includes `LibInformationValidationProvider` for `UpdateValue` behavior to prevent LIB rollback. [2](#0-1) 

However, for `NextTerm` behavior, only `RoundTerminateValidationProvider` is used, with no LIB validation: [3](#0-2) 

3. **LIB Validation Logic**: The `LibInformationValidationProvider` checks that provided LIB heights do not decrease from the base round, but this protection is not applied to NextTerm: [4](#0-3) 

4. **No Validation in ProcessNextTerm**: The `ProcessNextTerm` method processes the input without validating that the LIB height has not decreased: [5](#0-4) 

5. **UpdateValue Correctly Updates LIB**: For comparison, `ProcessUpdateValue` correctly calculates and validates LIB increases: [6](#0-5) 

**Root Cause:**

The core issue is an inconsistent application of LIB validation. While the system correctly prevents LIB rollback during normal block production (`UpdateValue`), it fails to apply the same validation during term transitions (`NextTerm`). This creates a window where a malicious or compromised miner can inject stale consensus data.

**Execution Flow:**

1. Node calls `GetConsensusExtraData` to generate consensus data for a NextTerm block: [7](#0-6) 

2. This calls `GetConsensusExtraDataForNextTerm` which invokes `GenerateFirstRoundOfNextTerm`: [8](#0-7) 

3. The function reads current round from state and copies its LIB height: [9](#0-8) 

4. Validation occurs via `ValidateConsensusBeforeExecution`, but NextTerm lacks LIB validation.

5. The transaction is generated and executed: [10](#0-9) 

### Impact Explanation

**Critical Blockchain Integrity Violation:**

This vulnerability directly violates the fundamental security property of blockchain finality. The impact includes:

1. **Finality Breach**: Previously irreversible blocks can become reversible, breaking the core guarantee that confirmed transactions are permanent.

2. **Double-Spending Risk**: If blocks are un-finalized, transactions within those blocks can potentially be reorganized, enabling double-spending attacks where users spend the same tokens twice.

3. **Cross-Chain Security**: The LIB height is used for cross-chain operations. Rolling back LIB could affect parent-side chain synchronization and cross-chain asset transfers.

4. **Economic Damage**: Users and exchanges rely on finality for large-value transactions. A finality breach could result in significant financial losses and loss of confidence in the blockchain.

5. **Systemic Risk**: If LIB can be arbitrarily rolled back by 10-20 blocks during each term transition, the blockchain's security model is fundamentally compromised.

**Affected Parties:**
- All blockchain users who rely on transaction finality
- Exchanges and payment processors
- Cross-chain bridge operators
- DApp developers and users

**Severity Justification**: CRITICAL - This breaks a core blockchain security invariant and can lead to direct financial loss through double-spending.

### Likelihood Explanation

**Attacker Capabilities Required:**

1. **Miner Status**: Attacker must be a valid miner in the current round scheduled to produce the NextTerm block. This is achievable through:
   - Running for election and obtaining votes
   - Compromising an existing miner's node

2. **Technical Capability**: Attacker needs to:
   - Call `GetConsensusExtraData` (a view method callable at any time) to obtain consensus data when LIB is at a desired lower value
   - Cache this data or modify node software to use stale data
   - Include the stale data when producing their NextTerm block

**Attack Complexity**: MODERATE

- The exploit requires the attacker to be scheduled for a term transition block (occurs periodically)
- `GetConsensusExtraData` is a view method with no restrictions on when it can be called
- No cryptographic or complex technical requirements beyond being a miner

**Feasibility Conditions:**

1. **Timing Window**: Term transitions occur at predictable intervals (every period), providing regular exploitation opportunities.

2. **Race Condition Alternative**: Even without malicious intent, a legitimate race condition could occur where:
   - Node generates consensus data at time T1 with LIB = X
   - Other miners update LIB to Y > X before the block is produced
   - The block with stale LIB = X is still accepted

3. **No Detection**: The validation system has no mechanism to detect or prevent this, as the check is completely absent.

**Probability Assessment**: HIGH

Given that:
- Term transitions occur regularly
- Any miner in the rotation will eventually be scheduled for a NextTerm block
- The attack is technically simple (no complex exploit chain required)
- There is zero validation preventing it

The probability of exploitation is high, either through malicious action or accidental race conditions.

### Recommendation

**Immediate Fix:**

Add `LibInformationValidationProvider` to the NextTerm validation providers in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

Location to modify: [3](#0-2) 

**Additional Hardening:**

Add explicit validation in `ProcessNextTerm` to double-check LIB invariant:

```csharp
// Before line 196, add:
if (TryToGetCurrentRoundInformation(out var currentStateRound))
{
    Assert(
        nextRound.ConfirmedIrreversibleBlockHeight >= currentStateRound.ConfirmedIrreversibleBlockHeight,
        "LIB height cannot decrease during term transition."
    );
    Assert(
        nextRound.ConfirmedIrreversibleBlockRoundNumber >= currentStateRound.ConfirmedIrreversibleBlockRoundNumber,
        "LIB round number cannot decrease during term transition."
    );
}
```

Location to modify: [5](#0-4) 

**Test Cases:**

1. Verify NextTerm blocks with LIB lower than current state are rejected
2. Verify NextTerm blocks with equal or higher LIB are accepted
3. Test race condition scenario where LIB increases between consensus data generation and block production
4. Verify NextRound also has proper LIB validation (same vulnerability pattern)

### Proof of Concept

**Initial State:**
- Current block height: 1000
- Current term: 5
- Current round: 150
- Current LIB height: 950
- Attacker is miner M scheduled to produce block 1021 (NextTerm block for term 6)

**Attack Sequence:**

1. **At Block 1000**: Attacker calls `GetConsensusExtraData` with NextTerm behavior
   - Returns consensus data with `ConfirmedIrreversibleBlockHeight = 950`
   - Attacker stores this data

2. **Blocks 1001-1020**: Honest miners produce blocks with UpdateValue
   - LIB progressively increases: 951, 952, ..., 970
   - Current state now has `ConfirmedIrreversibleBlockHeight = 970`

3. **At Block 1021**: Attacker produces NextTerm block
   - Includes cached consensus data from step 1 with LIB = 950
   - Block passes `ValidateConsensusBeforeExecution`:
     - `RoundTerminateValidationProvider` checks term/round numbers ✓
     - No `LibInformationValidationProvider` for NextTerm ✗
   - Block is accepted

4. **Execution of Block 1021**: `ProcessNextTerm` runs
   - Creates new term with `ConfirmedIrreversibleBlockHeight = 950`
   - Writes this to state via `AddRoundInformation`
   - No validation that 950 < 970 (current LIB before this block)

**Expected vs Actual Result:**

- **Expected**: Block should be rejected due to LIB rollback from 970 to 950
- **Actual**: Block is accepted, LIB rolls back to 950

**Success Condition:**

After block 1021, query `GetCurrentRoundInformation().ConfirmedIrreversibleBlockHeight` returns 950 instead of 970, demonstrating that 20 previously finalized blocks are now un-finalized, enabling potential chain reorganization.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-246)
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

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-210)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
```
