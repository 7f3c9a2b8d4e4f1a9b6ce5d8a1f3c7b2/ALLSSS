### Title
Missing LIB Height Validation in NextTerm Allows Irreversible Block Rollback

### Summary
The NextTerm consensus behavior does not validate that the provided Round's ConfirmedIrreversibleBlockHeight is not lower than the current Last Irreversible Block (LIB) height. A miner can produce a NextTerm block based on outdated state, causing the LIB to roll backward and enabling chain reorganization attacks on previously irreversible blocks.

### Finding Description

The vulnerability exists in the validation and processing flow of the NextTerm consensus behavior:

**1. Missing Validation Check:**

When NextTerm behavior is validated, the LibInformationValidationProvider is NOT added to the validation pipeline: [1](#0-0) 

In contrast, UpdateValue behavior DOES include this validator: [2](#0-1) 

The LibInformationValidationProvider checks that ConfirmedIrreversibleBlockHeight does not decrease: [3](#0-2) 

**2. Round Generation from Potentially Outdated State:**

When a miner generates NextTerm consensus data, the Round is created by copying LIB from their local state: [4](#0-3) [5](#0-4) 

**3. Unchecked Storage of Outdated LIB:**

When ProcessNextTerm executes, it converts the NextTermInput to a Round and stores it directly: [6](#0-5) [7](#0-6) 

The AddRoundInformation function stores the round without validating LIB: [8](#0-7) 

**4. NextTermInput.Create() Lacks Validation:**

The Create() function simply copies all fields including ConfirmedIrreversibleBlockHeight without any validation: [9](#0-8) 

### Impact Explanation

**Consensus Integrity Violation:**
- The Last Irreversible Block height can move backwards, violating the fundamental blockchain invariant that finalized blocks must remain irreversible
- Blocks that were previously marked as irreversible become reversible again
- Enables chain reorganization attacks on hundreds or thousands of blocks

**Cross-Chain Security Breach:**
- Cross-chain bridges and side chains rely on LIB for finality guarantees
- A rolled-back LIB could allow manipulation of cross-chain messages and merkle proofs
- Assets could be double-spent across chains

**Economic Impact:**
- Transactions in previously irreversible blocks can be reverted
- Double-spend attacks become possible
- Smart contract state that depended on finalized blocks becomes unreliable

**Affected Parties:**
- All network participants relying on block finality
- Cross-chain protocols and bridges
- DApps and users with transactions in affected blocks

This is a **CRITICAL** severity issue as it undermines the core consensus guarantee of irreversibility.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a valid miner in the current or previous miner set (required to produce NextTerm blocks)
- Must have the ability to control their local node state or experience network delays [10](#0-9) 

**Attack Complexity: LOW**
1. Attacker waits to be scheduled for NextTerm block production
2. Deliberately delays syncing recent UpdateValue blocks OR exploits natural network delays
3. Generates NextTerm with outdated LIB from their stale state
4. Block passes validation (no LIB check for NextTerm)
5. LIB rolls back upon execution

**Feasibility Conditions:**
- Natural occurrence: Network partitions or delays during term transitions
- Malicious exploitation: Miner intentionally uses outdated state
- No additional privileges needed beyond being a miner

**Detection Constraints:**
- Difficult to distinguish from legitimate network delays
- Could be attributed to "synchronization issues"
- May not be immediately obvious until chain reorganization is attempted

**Probability: MEDIUM-HIGH**
- Miners produce NextTerm blocks regularly (every term transition)
- Network conditions naturally create state inconsistencies
- Attack can be disguised as network issues

### Recommendation

**Immediate Fix:**

Add LibInformationValidationProvider to the NextTerm validation pipeline: [1](#0-0) 

Modify the validation to include:
```
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

**Additional Safety Check:**

Add explicit validation in ProcessNextTerm before storing the round: [6](#0-5) 

Insert check:
```
var nextRound = input.ToRound();
Assert(TryToGetCurrentRoundInformation(out var currentRound), "Failed to get current round");
Assert(nextRound.ConfirmedIrreversibleBlockHeight >= currentRound.ConfirmedIrreversibleBlockHeight, 
    "LIB cannot move backwards");
```

**Test Cases:**

1. Test that NextTerm with lower LIB than current state is rejected
2. Test that NextTerm with equal LIB is accepted
3. Test that NextTerm with higher LIB is accepted
4. Test concurrent NextTerm and UpdateValue scenarios

### Proof of Concept

**Initial State:**
- Block height: 10,000
- Current LIB (in state): 9,800
- Current term: 100
- Current round: 1,000
- Miner M is scheduled to produce NextTerm block

**Attack Sequence:**

1. **Setup Outdated State:**
   - Miner M stops syncing after block 9,900
   - Network continues, UpdateValue blocks increase LIB to 9,950 by block 10,100
   - Other nodes have LIB = 9,950
   - Miner M still has LIB = 9,800

2. **Generate Malicious NextTerm:**
   - At block 10,101, it's time for NextTerm
   - Miner M calls GetConsensusExtraData for NextTerm behavior
   - GenerateFirstRoundOfNextTerm reads from M's local state with LIB = 9,800
   - NextTermInput.Create() copies ConfirmedIrreversibleBlockHeight = 9,800
   - M produces block with this NextTerm

3. **Validation Passes:**
   - Other nodes receive M's block
   - ValidateBeforeExecution checks:
     * Round number: 1,000 + 1 = 1,001 ✓
     * Term number: 100 + 1 = 101 ✓
     * LibInformationValidationProvider: NOT CALLED ✓
   - Validation succeeds

4. **LIB Rollback Occurs:**
   - ProcessNextTerm executes
   - Stores round 1,001 with ConfirmedIrreversibleBlockHeight = 9,800
   - State.Rounds[1,001].ConfirmedIrreversibleBlockHeight = 9,800
   - Current round becomes 1,001

5. **Exploitation:**
   - LIB has rolled back from 9,950 → 9,800
   - Blocks 9,801-9,950 (150 blocks) are no longer irreversible
   - Attacker can attempt chain reorganization on these blocks
   - Double-spend attacks, transaction censorship now possible

**Expected Result:** Validation should reject the block due to LIB moving backwards

**Actual Result:** Block is accepted and LIB moves backwards, enabling chain reorganization

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L51-52)
```csharp
        round.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        round.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-163)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L196-196)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-22)
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
```
