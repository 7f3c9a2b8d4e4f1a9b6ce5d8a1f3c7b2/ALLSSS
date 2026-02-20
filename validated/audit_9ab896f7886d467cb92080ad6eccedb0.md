# Audit Report

## Title
NextTerm Validation Bypass Allows Outdated Miner Keys After Replacement

## Summary
The `ValidateConsensusAfterExecution` function contains a critical logic flaw for NextTerm blocks. It validates miner replacements only when round hashes differ, but NextTerm execution unconditionally sets state from header input, causing hashes to always match. This circular validation bypasses the `GetNewestPubkey` replacement check, allowing blocks with replaced (potentially compromised) miner public keys to be accepted.

## Finding Description

The vulnerability exists in the post-execution validation logic where the replacement check is conditional on hash mismatches. [1](#0-0) 

The validation assumes matching hashes guarantee miner list validity. However, for NextTerm blocks, `ProcessNextTerm` unconditionally sets the current round state from the input without validating the miner list against current election results. [2](#0-1) 

The state update occurs via `AddRoundInformation` which directly writes the input round to state storage. [3](#0-2) 

The NextTerm input is generated at block creation time by calling `GenerateFirstRoundOfNextTerm`, which queries `GetVictories` from the Election contract to obtain the current elected miner list. [4](#0-3) 

This creates a time-of-check to time-of-use vulnerability where:
1. Block generation (time T1): Calls `GetVictories()` returning `[A, B, C]`
2. Between generation and validation: `ReplaceCandidatePubkey(A → A')` executes
3. Block validation (time T2): State already matches header, no replacement validation occurs

**Why existing protections fail:**

Pre-execution validation for NextTerm only validates round termination logic, not miner list composition. [5](#0-4) 

The `RoundTerminateValidationProvider` confirms this - it only checks round number and term number correctness, with no miner list validation. [6](#0-5) 

When a candidate is replaced via `ReplaceCandidatePubkey`, the consensus contract's `RecordCandidateReplacement` is notified, but it only updates the **current round** information, not future rounds in pending blocks. [7](#0-6) 

The Election contract's replacement tracking updates the mapping to track the newest pubkey. [8](#0-7) 

## Impact Explanation

**Consensus Security Breach:** This vulnerability directly violates the critical invariant that replaced miners must be immediately removed from block production eligibility. When a candidate's key is replaced (typically due to key compromise or security concerns), the old key should be banned and unable to participate in consensus.

**Specific Attack Consequences:**
- A compromised or malicious miner whose key was replaced can continue producing blocks in the entire new term
- The legitimate replacement miner (new key holder) is denied their rightful block production slot
- Network security is degraded as compromised keys maintain consensus power
- Block production rewards are misdirected to the old (potentially compromised) key holder

**Affected Parties:**
- Network consensus integrity
- Legitimate miners with replacement keys who lose rewards and participation rights
- Token holders who face increased security risk from compromised validators

This is **High severity** because it allows continued participation of potentially compromised validator keys in consensus, directly undermining the blockchain's security model.

## Likelihood Explanation

**Realistic Attack Scenario:**
1. Miner produces NextTerm block at height N (calls `GetVictories()` → `[A, B, C]`)
2. Block N propagates through network with delays
3. Before Block N executes on all nodes, `ReplaceCandidatePubkey(A → A')` transaction executes in Block M < N
4. Block N arrives for validation after replacement
5. Validation: `ProcessNextTerm` sets state to `[A, B, C]` from header
6. `ValidateConsensusAfterExecution` compares header `[A, B, C]` with state `[A, B, C]` (just set) → hashes match
7. Replacement check skipped, block accepted
8. New term begins with compromised miner A instead of legitimate A'

**Feasibility Factors:**
- **Network delays**: Normal blockchain network latency can cause blocks to arrive out of generation order
- **Chain reorganizations**: Fork resolution can cause blocks to be re-validated in different state contexts
- **No special privileges required**: Uses legitimate protocol operations (key replacement + block propagation)
- **Window of opportunity**: Any time between NextTerm block generation and execution

The replacement function is part of normal protocol operations for legitimate security maintenance. [9](#0-8) 

**Attack Complexity:** Medium - requires timing coordination between block propagation and replacement transaction, but exploits inherent network conditions.

## Recommendation

Add explicit miner list validation during pre-execution validation for NextTerm blocks by validating each miner against `GetNewestPubkey`:

```csharp
// In RoundTerminateValidationProvider.ValidationForNextTerm
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Validate term number
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // ADD THIS: Validate miner list against replacements
    var headerMiners = extraData.Round.RealTimeMinersInformation.Keys.ToList();
    foreach (var miner in headerMiners)
    {
        var newestPubkey = State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value;
        if (newestPubkey != miner)
            return new ValidationResult { Message = $"Miner {miner} has been replaced by {newestPubkey}." };
    }
    
    return new ValidationResult { Success = true };
}
```

Alternatively, modify post-execution validation to check replacements independently of hash comparison for NextTerm blocks.

## Proof of Concept

Cannot provide executable PoC without full AElf test infrastructure, but the attack flow is:

1. Setup: Deploy contracts with miners [A, B, C] in current term
2. Generate NextTerm block with miner list [A, B, C] obtained from `GetVictories()`
3. Execute `ReplaceCandidatePubkey(A → A')` before block validation
4. Validate the NextTerm block:
   - Pre-execution: Passes (only checks round/term numbers)
   - Execution: `ProcessNextTerm` writes [A, B, C] to state
   - Post-execution: Hash comparison matches, replacement check bypassed
5. Observe: Block accepted with old miner A, new term starts with compromised key

**Notes**

The vulnerability stems from a fundamental design flaw where post-execution validation relies on state that was just set from the header being validated, creating a circular validation loop. The fix requires either pre-execution miner list validation or independent replacement checking that doesn't rely on hash comparison.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-124)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-232)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-146)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L280-291)
```csharp
    private void PerformReplacement(string oldPubkey, string newPubkey)
    {
        State.CandidateReplacementMap[newPubkey] = oldPubkey;

        // Initial pubkey is:
        // - miner pubkey of the first round (aka. Initial Miner), or
        // - the pubkey announced election

        var initialPubkey = State.InitialPubkeyMap[oldPubkey] ?? oldPubkey;
        State.InitialPubkeyMap[newPubkey] = initialPubkey;

        State.InitialToNewestPubkeyMap[initialPubkey] = newPubkey;
```
